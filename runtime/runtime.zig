const std = @import("std");

// ── SpinLock ───────────────────────────────────────────────────────────────
pub const SpinLock = struct {
    locked: bool = false,

    pub fn lock(self: *SpinLock) void {
        while (@cmpxchgWeak(bool, &self.locked, false, true, .acquire, .monotonic) != null) {
            std.Thread.yield() catch {};
        }
    }

    pub fn tryLock(self: *SpinLock) bool {
        return @cmpxchgWeak(bool, &self.locked, false, true, .acquire, .monotonic) == null;
    }

    pub fn unlock(self: *SpinLock) void {
        @atomicStore(bool, &self.locked, false, .release);
    }
};

// ── Object Model & Header ──────────────────────────────────────────────────
pub const ObjectHeader = struct {
    class_ptr: usize,
    monitor: usize, // Bit 0: fat-lock flag. Bits 1-31: thin-lock Thread ID. Bits 32-63: recursion count.
};

pub const ClassMetadata = struct {
    name: []const u8,
    instance_size: usize,
    vtable: []const usize,
};

// ── Cheney Semi-Space Copying GC ────────────────────────────────────────────
pub const GC = struct {
    space_size: usize,
    from_space: []u8,
    to_space: []u8,
    bump_ptr: usize,
    allocator: std.mem.Allocator,

    pub fn init(allocator: std.mem.Allocator, space_size: usize) !GC {
        const from = try allocator.alloc(u8, space_size);
        const to = try allocator.alloc(u8, space_size);
        return GC{
            .space_size = space_size,
            .from_space = from,
            .to_space = to,
            .bump_ptr = @intFromPtr(from.ptr),
            .allocator = allocator,
        };
    }

    pub fn deinit(self: *GC) void {
        self.allocator.free(self.from_space);
        self.allocator.free(self.to_space);
    }

    pub fn alloc(self: *GC, class_ptr: usize, size: usize) !*anyopaque {
        const aligned_size = std.mem.alignForward(usize, size, 8);
        const total_size = aligned_size + @sizeOf(ObjectHeader);

        const limit = @intFromPtr(self.from_space.ptr) + self.space_size;
        if (self.bump_ptr + total_size > limit) {
            try self.collect();
            if (self.bump_ptr + total_size > limit) {
                return error.OutOfMemory;
            }
        }

        const ptr = @as(*ObjectHeader, @ptrFromInt(self.bump_ptr));
        self.bump_ptr += total_size;

        ptr.class_ptr = class_ptr;
        ptr.monitor = 0;

        const obj_ptr = @intFromPtr(ptr) + @sizeOf(ObjectHeader);
        @memset(@as([*]u8, @ptrFromInt(obj_ptr))[0..aligned_size], 0);

        return @ptrFromInt(obj_ptr);
    }

    pub fn collect(self: *GC) !void {
        // Swap spaces
        const temp = self.from_space;
        self.from_space = self.to_space;
        self.to_space = temp;

        const to_start = @intFromPtr(self.from_space.ptr);
        self.bump_ptr = to_start;
    }
};

// Global GC instance
pub var global_gc: ?GC = null;

pub fn initRuntime(allocator: std.mem.Allocator, gc_size: usize) !void {
    global_gc = try GC.init(allocator, gc_size);
    try global_pool.init(allocator, 4); // Initialize with 4 worker threads
}

pub fn deinitRuntime() void {
    if (global_gc) |*gc| gc.deinit();
    global_pool.deinit();
}

pub fn gcAlloc(class_ptr: usize, size: usize) callconv(.c) *anyopaque {
    if (global_gc) |*gc| {
        return gc.alloc(class_ptr, size) catch @panic("GC Allocation OOM");
    }
    @panic("Runtime not initialized");
}

// ── Thin-Lock Synchronization ───────────────────────────────────────────────
pub fn monitorEnter(obj: *anyopaque) callconv(.c) void {
    const header = @as(*ObjectHeader, @ptrFromInt(@intFromPtr(obj) - @sizeOf(ObjectHeader)));
    const thread_id = @as(usize, @intCast(std.Thread.getCurrentId()));

    while (true) {
        const current = @atomicLoad(usize, &header.monitor, .acquire);
        if (current == 0) {
            // Unlocked: attempt CAS to acquire thin lock
            if (@cmpxchgWeak(usize, &header.monitor, 0, thread_id << 1, .release, .monotonic) == null) {
                return;
            }
        } else if ((current >> 1) == thread_id) {
            // Reentrant lock
            const new_val = current + (1 << 32);
            @atomicStore(usize, &header.monitor, new_val, .release);
            return;
        } else {
            // Contested lock: spin-wait or yield thread
            std.Thread.yield() catch {};
        }
    }
}

pub fn monitorExit(obj: *anyopaque) callconv(.c) void {
    const header = @as(*ObjectHeader, @ptrFromInt(@intFromPtr(obj) - @sizeOf(ObjectHeader)));
    const thread_id = @as(usize, @intCast(std.Thread.getCurrentId()));

    const current = @atomicLoad(usize, &header.monitor, .acquire);
    if ((current >> 1) == thread_id) {
        const recursion = current >> 32;
        if (recursion > 0) {
            @atomicStore(usize, &header.monitor, current - (1 << 32), .release);
        } else {
            @atomicStore(usize, &header.monitor, 0, .release);
        }
    }
}

// ── Concurrency & Atomic Operations ──────────────────────────────────────────
pub fn atomicCAS(addr: *i32, expected: i32, new_val: i32) callconv(.c) bool {
    return @cmpxchgStrong(i32, addr, expected, new_val, .seq_cst, .seq_cst) == null;
}

pub fn memoryBarrier() callconv(.c) void {
    asm volatile ("mfence");
}

// ── Work-Stealing Parallelism Thread Pool ────────────────────────────────────
pub const Task = struct {
    run: *const fn (?*anyopaque) callconv(.c) void,
    arg: ?*anyopaque,
};

pub const Worker = struct {
    thread: std.Thread,
    queue: std.ArrayList(Task),
    mutex: SpinLock,
    pool: *ThreadPool,
    id: usize,

    pub fn init(pool: *ThreadPool, id: usize, allocator: std.mem.Allocator) !*Worker {
        const w = try allocator.create(Worker);
        w.* = .{
            .thread = undefined,
            .queue = std.ArrayList(Task).empty,
            .mutex = .{},
            .pool = pool,
            .id = id,
        };
        return w;
    }

    pub fn start(self: *Worker) !void {
        self.thread = try std.Thread.spawn(.{}, workerRun, .{self});
    }

    pub fn deinit(self: *Worker, allocator: std.mem.Allocator) void {
        self.queue.deinit(allocator);
        allocator.destroy(self);
    }
};

pub const ThreadPool = struct {
    workers: []*Worker,
    allocator: std.mem.Allocator,
    running: bool,
    mutex: SpinLock,

    pub fn init(self: *ThreadPool, allocator: std.mem.Allocator, num_workers: usize) !void {
        self.allocator = allocator;
        self.running = true;
        self.workers = try allocator.alloc(*Worker, num_workers);
        for (0..num_workers) |i| {
            self.workers[i] = try Worker.init(self, i, allocator);
        }
        for (0..num_workers) |i| {
            try self.workers[i].start();
        }
    }

    pub fn deinit(self: *ThreadPool) void {
        self.running = false;
        for (self.workers) |w| {
            w.thread.join();
            w.deinit(self.allocator);
        }
        self.allocator.free(self.workers);
    }

    pub fn submit(self: *ThreadPool, task: Task) !void {
        const w = self.workers[0];
        w.mutex.lock();
        defer w.mutex.unlock();
        try w.queue.append(self.allocator, task);
    }
};

fn workerRun(worker: *Worker) void {
    const pool = worker.pool;
    while (pool.running) {
        var task: ?Task = null;

        worker.mutex.lock();
        if (worker.queue.items.len > 0) {
            task = worker.queue.items[worker.queue.items.len - 1];
            worker.queue.items.len -= 1;
        }
        worker.mutex.unlock();

        if (task == null) {
            for (pool.workers) |other| {
                if (other.id == worker.id) continue;
                if (other.mutex.tryLock()) {
                    if (other.queue.items.len > 0) {
                        task = other.queue.items[other.queue.items.len - 1];
                        other.queue.items.len -= 1;
                    }
                    other.mutex.unlock();
                }
                if (task != null) break;
            }
        }

        if (task) |t| {
            t.run(t.arg);
        } else {
            std.Thread.yield() catch {};
        }
    }
}

pub var global_pool: ThreadPool = undefined;
