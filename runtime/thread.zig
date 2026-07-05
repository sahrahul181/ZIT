const std = @import("std");
const gc = @import("gc");
const chase_lev = @import("chase_lev");

extern "kernel32" fn CreateFiber(dwStackSize: usize, lpStartAddress: *const fn (?*anyopaque) callconv(.c) void, lpParameter: ?*anyopaque) callconv(.c) ?*anyopaque;
extern "kernel32" fn ConvertThreadToFiber(lpParameter: ?*anyopaque) callconv(.c) ?*anyopaque;
extern "kernel32" fn SwitchToFiber(lpFiber: *anyopaque) callconv(.c) void;
extern "kernel32" fn DeleteFiber(lpFiber: *anyopaque) callconv(.c) void;

// ── Virtual Thread State ───────────────────────────────────────────────────────

pub const FiberState = enum(u8) {
    created,
    runnable,
    running,
    parked,
    terminated,
};

pub const ThreadLocalStorage = struct {
    exception: usize = 0,   // pending Throwable reference (0 = none)
    result:    u64   = 0,   // return value from native call
    allocator: gc.immix.allocator.MutatorAllocator = undefined, // Lock-free Immix allocation
    jmp_env:   [32]u64 = [_]u64{0} ** 32, // saved jump buffer for JIT exception recovery
    has_jmp_env: bool = false,
};

// ── JavaThread (Virtual Fiber) ────────────────────────────────────────────────
pub const JavaThread = struct {
    id: usize,
    java_thread_obj: u64 = 0,
    state: std.atomic.Value(FiberState),
    tls: ThreadLocalStorage,
    
    // Fiber context (stack and registers for context switching)
    fiber_handle: ?*anyopaque = null,
    
    // Virtual thread entry point
    entry: *const fn (*JavaThread) callconv(.c) void,
    
    pub fn init(allocator: std.mem.Allocator, id: usize, entry: *const fn (*JavaThread) callconv(.c) void) !*JavaThread {
        const jt = try allocator.create(JavaThread);
        jt.* = .{
            .id = id,
            .state = std.atomic.Value(FiberState).init(.created),
            .tls = .{ .allocator = gc.immix.allocator.MutatorAllocator.init(dummyBlockSupplier) },
            .entry = entry,
        };
        jt.fiber_handle = CreateFiber(16 * 1024 * 1024, fiberEntry, jt);
        if (jt.fiber_handle == null) @panic("Failed to create Fiber for JavaThread");
        return jt;
    }

    pub fn start(self: *JavaThread) void {
        self.state.store(.runnable, .release);
        if (global_worker_pool) |pool| {
            pool.submit(self) catch @panic("Failed to submit JavaThread to pool");
        } else {
            @panic("Cannot start JavaThread before WorkerPool is initialized");
        }
    }

    pub fn join(self: *JavaThread) void {
        while (self.state.load(.acquire) != .terminated) {
            std.Thread.yield() catch {};
        }
    }

    pub fn yield(self: *JavaThread) void {
        self.state.store(.runnable, .release);
        std.Thread.yield() catch {};
    }

    pub fn park(self: *JavaThread) void {
        self.state.store(.parked, .release);
        while (self.state.load(.acquire) == .parked) {
            std.Thread.yield() catch {};
        }
    }


    pub fn unpark(self: *JavaThread) void {
        if (self.state.cmpxchgStrong(.parked, .runnable, .release, .monotonic) == null) {
            if (global_worker_pool) |pool| {
                pool.submit(self) catch @panic("Failed to submit unparked JavaThread");
            }
        }
    }

    pub fn deinit(self: *JavaThread, allocator: std.mem.Allocator) void {
        allocator.destroy(self);
    }
};


fn dummyBlockSupplier() ?*gc.immix.layout.Block {
    return null;
}

// ── OS Worker Thread (M:N Scheduler) ──────────────────────────────────────────
pub const Worker = struct {
    id: usize,
    thread: std.Thread,
    primary_fiber: ?*anyopaque = null,
    last_fiber: ?*JavaThread = null,
    deque: chase_lev.Deque,
    pool: *WorkerPool,
    allocator: std.mem.Allocator,

    pub fn init(pool: *WorkerPool, id: usize, allocator: std.mem.Allocator) !*Worker {
        const w = try allocator.create(Worker);
        w.* = .{
            .id = id,
            .thread = undefined,
            .deque = try chase_lev.Deque.init(allocator, 8), // 2^8 = 256 initial tasks
            .pool = pool,
            .allocator = allocator,
        };
        return w;
    }

    pub fn deinit(self: *Worker) void {
        self.deque.deinit();
        self.allocator.destroy(self);
    }
};

const Spinlock = struct {
    state: std.atomic.Value(bool) = std.atomic.Value(bool).init(false),
    
    pub fn lock(self: *Spinlock) void {
        while (self.state.swap(true, .acquire)) {
            std.atomic.spinLoopHint();
        }
    }
    
    pub fn unlock(self: *Spinlock) void {
        self.state.store(false, .release);
    }
};

// ── Global Worker Pool ────────────────────────────────────────────────────────
pub const WorkerPool = struct {
    workers: []*Worker,
    allocator: std.mem.Allocator,
    running: std.atomic.Value(bool),
    global_queue: std.ArrayList(chase_lev.Task),
    global_mutex: Spinlock,

    pub fn init(allocator: std.mem.Allocator, num_workers: usize) !*WorkerPool {
        const p = try allocator.create(WorkerPool);
        p.allocator = allocator;
        p.running = std.atomic.Value(bool).init(true);
        p.global_queue = .empty;
        p.global_mutex = .{};
        p.workers = try allocator.alloc(*Worker, num_workers);
        
        for (0..num_workers) |i| {
            p.workers[i] = try Worker.init(p, i, allocator);
        }
        
        for (0..num_workers) |i| {
            p.workers[i].thread = try std.Thread.spawn(.{}, workerLoop, .{p.workers[i]});
        }
        return p;
    }

    pub fn deinit(self: *WorkerPool) void {
        self.running.store(false, .release);
        for (self.workers) |w| {
            w.thread.join();
            w.deinit();
        }
        self.global_queue.deinit(self.allocator);
        self.allocator.free(self.workers);
        self.allocator.destroy(self);
    }

    pub fn submit(self: *WorkerPool, fiber: *JavaThread) !void {
        self.global_mutex.lock();
        defer self.global_mutex.unlock();
        try self.global_queue.append(self.allocator, .{
            .run = @ptrCast(fiber.entry),
            .arg = fiber,
        });
    }
};

// Simple OS thread ID maps to prevent TLS corruption issues in Fiber contexts on Windows.
var active_threads: [128]struct { os_id: std.Thread.Id, thread: ?*JavaThread } = undefined;
var active_threads_len: usize = 0;
var active_workers: [128]struct { os_id: std.Thread.Id, worker: *Worker } = undefined;
var active_workers_len: usize = 0;
var thread_map_mutex: Spinlock = .{};

pub fn registerThread(jt: ?*JavaThread) void {
    thread_map_mutex.lock();
    defer thread_map_mutex.unlock();
    const tid = std.Thread.getCurrentId();
    for (active_threads[0..active_threads_len]) |*t| {
        if (t.os_id == tid) {
            t.thread = jt;
            return;
        }
    }
    if (active_threads_len < 128) {
        active_threads[active_threads_len] = .{ .os_id = tid, .thread = jt };
        active_threads_len += 1;
    }
}

pub fn registerWorker(w: *Worker) void {
    thread_map_mutex.lock();
    defer thread_map_mutex.unlock();
    const tid = std.Thread.getCurrentId();
    for (active_workers[0..active_workers_len]) |*wk| {
        if (wk.os_id == tid) {
            wk.worker = w;
            return;
        }
    }
    if (active_workers_len < 128) {
        active_workers[active_workers_len] = .{ .os_id = tid, .worker = w };
        active_workers_len += 1;
    }
}

pub fn getCurrent() ?*JavaThread {
    thread_map_mutex.lock();
    defer thread_map_mutex.unlock();
    const tid = std.Thread.getCurrentId();
    for (active_threads[0..active_threads_len]) |t| {
        if (t.os_id == tid) return t.thread;
    }
    return null;
}

pub fn getCurrentWorker() ?*Worker {
    thread_map_mutex.lock();
    defer thread_map_mutex.unlock();
    const tid = std.Thread.getCurrentId();
    for (active_workers[0..active_workers_len]) |w| {
        if (w.os_id == tid) return w.worker;
    }
    return null;
}


fn fiberEntry(lpParameter: ?*anyopaque) callconv(.c) void {
    const fiber = @as(*JavaThread, @ptrCast(@alignCast(lpParameter.?)));
    fiber.state.store(.running, .release);
    registerThread(fiber);

    // Call the actual java thread code
    fiber.entry(fiber);

    // Terminate
    fiber.state.store(.terminated, .release);
    const w = getCurrentWorker() orelse @panic("JavaThread finished without a worker");
    // Clear registration
    registerThread(null);
    SwitchToFiber(w.primary_fiber.?);
}

fn workerLoop(worker: *Worker) void {
    worker.primary_fiber = ConvertThreadToFiber(null);
    if (worker.primary_fiber == null) @panic("Failed to convert OS thread to fiber");
    
    registerWorker(worker);
    const pool = worker.pool;

    while (pool.running.load(.acquire)) {
        if (worker.last_fiber) |lf| {
            if (lf.state.load(.acquire) == .terminated) {
                DeleteFiber(lf.fiber_handle.?);
            }
            worker.last_fiber = null;
        }
        
        var task = worker.deque.pop();
        
        // If our deque is empty, work-steal from others!
        if (task == null) {
            pool.global_mutex.lock();
            if (pool.global_queue.items.len > 0) {
                // Pop the FIRST item for fairness (FIFO) or LAST for LIFO. Let's use orderedRemove for FIFO.
                task = pool.global_queue.orderedRemove(0);
            }
            pool.global_mutex.unlock();
            
            if (task == null) {
                for (pool.workers) |other| {
                    if (other.id == worker.id) continue;
                    if (other.deque.steal()) |stolen| {
                        task = stolen;
                        break;
                    }
                }
            }
        }

        if (task) |t| {
            if (t.arg) |arg| {
                const fiber = @as(*JavaThread, @ptrCast(@alignCast(arg)));
                registerThread(fiber);
                worker.last_fiber = fiber;
                SwitchToFiber(fiber.fiber_handle.?);
            }
        } else {
            // Spin loop backoff when starving
            std.Thread.yield() catch {};
        }
    }
}


// ── Thread Subsystem ──────────────────────────────────────────────────────────
pub var global_worker_pool: ?*WorkerPool = null;

pub fn initThreadSubsystem(allocator: std.mem.Allocator) !void {
    const num_cores = std.Thread.getCpuCount() catch 4;
    global_worker_pool = try WorkerPool.init(allocator, num_cores);
}

pub fn deinitThreadSubsystem() void {
    if (global_worker_pool) |pool| {
        pool.deinit();
        global_worker_pool = null;
    }
}
