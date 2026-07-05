const std = @import("std");

// ── SpinLock ───────────────────────────────────────────────────────────────
pub const SpinLock = struct {
    locked: bool = false,

    pub fn lock(self: *SpinLock) void {
        var backoff: u32 = 0;
        while (@cmpxchgWeak(bool, &self.locked, false, true, .acquire, .monotonic) != null) {
            std.atomic.spinLoopHint();
            backoff += 1;
            if (backoff > 1000) {
                std.Thread.yield() catch {};
                backoff = 0;
            }
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

const layout = @import("gc").immix.layout;
pub const sync = @import("sync");
pub const thread = @import("thread");
pub const chase_lev = @import("chase_lev");
pub const MutatorAllocator = @import("gc").immix.allocator.MutatorAllocator;
const Block = layout.Block;

pub const ImmixGC = struct {
    allocator: std.mem.Allocator,
    // Note: A true production GC manages OS mmap pages globally.
    // For now, we will simulate a global pool by tracking active blocks.

    pub fn init(allocator: std.mem.Allocator) !ImmixGC {
        return .{
            .allocator = allocator,
        };
    }

    pub fn deinit(self: *ImmixGC) void {
        _ = self;
    }

    pub fn requestBlock(self: *ImmixGC) !*Block {
        // Allocate a new block from the OS (via Zig allocator).
        // MUST be BLOCK_SIZE-aligned so that Block.lineIndex() (which uses
        // `address & (BLOCK_SIZE-1)`) and Block.fromAddress() produce correct
        // results.  Plain malloc() gives only 16-byte alignment, which breaks
        // the hole-scan math and causes intermittent "Object too large for Immix
        // block" panics when two threads race to fill their TLABs.
        const mem = try self.allocator.alignedAlloc(u8, .fromByteUnits(layout.BLOCK_SIZE), layout.BLOCK_SIZE);
        const block = @as(*Block, @ptrCast(@alignCast(mem.ptr)));
        block.* = Block.init();
        return block;
    }
};

// Global Immix Coordinator
pub var global_gc: ?ImmixGC = null;
pub var global_io: std.Io = undefined;

pub fn initRuntime(allocator: std.mem.Allocator, gc_size: usize) !void {
    _ = gc_size; // Not used in dynamic Immix yet
    global_gc = try ImmixGC.init(allocator);
    try thread.initThreadSubsystem(allocator);
}

pub fn deinitRuntime() void {
    if (global_gc) |*gc| gc.deinit();
    thread.deinitThreadSubsystem();
}

pub fn gcAlloc(class_ptr: usize, size: usize) callconv(.c) *anyopaque {
    const current_thread = thread.getCurrent() orelse @panic("gcAlloc called without thread context");

    if (global_gc) |*gc| {
        // Total size = ObjectHeader (16) + aligned instance size
        const aligned_size = std.mem.alignForward(usize, size, 8);
        const total_size = aligned_size + 16;

        // Large-object space: objects that don't fit within an Immix block's
        // bump region are allocated directly from the OS allocator instead of
        // panicking. (These are leaked for now — there is no GC sweep yet, same
        // as Immix blocks.) The threshold is a conservative half-block.
        if (total_size > layout.BLOCK_SIZE / 2) {
            const mem = gc.allocator.alignedAlloc(u8, .@"16", total_size) catch @panic("OOM: large object");
            const obj_ptr_int = @intFromPtr(mem.ptr);
            const hdr = @as(*ObjectHeader, @ptrFromInt(obj_ptr_int));
            hdr.class_ptr = class_ptr;
            hdr.monitor = 0;
            const obj_ptr = obj_ptr_int + 16;
            @memset(@as([*]u8, @ptrFromInt(obj_ptr))[0..aligned_size], 0);
            return @ptrFromInt(obj_ptr);
        }

        var ptr = current_thread.tls.allocator.alloc(total_size);
        if (ptr == null) {
            // TLAB exhausted, request a new block from the global coordinator
            const new_block = gc.requestBlock() catch @panic("OOM: Failed to allocate Immix Block");
            current_thread.tls.allocator.setBlock(new_block);
            ptr = current_thread.tls.allocator.alloc(total_size);
            if (ptr == null) @panic("Object too large for Immix block");
        }

        // Initialize header
        const obj_ptr_int = @intFromPtr(ptr.?);
        const hdr = @as(*ObjectHeader, @ptrFromInt(obj_ptr_int));
        hdr.class_ptr = class_ptr;
        hdr.monitor = 0;

        // Zero body
        const obj_ptr = obj_ptr_int + 16;
        @memset(@as([*]u8, @ptrFromInt(obj_ptr))[0..aligned_size], 0);

        return @ptrFromInt(obj_ptr);
    }
    @panic("Runtime not initialized");
}

// ── Wait/Notify Queues ────────────────────────────────────────────────────────
pub var wait_queues: ?std.AutoHashMap(usize, std.ArrayList(*thread.JavaThread)) = null;
pub var wait_queue_mutex: SpinLock = .{};

// ── Thin-Lock Synchronization ───────────────────────────────────────────────
pub fn monitorEnter(obj: *anyopaque) callconv(.c) void {
    if (@intFromPtr(obj) == 0) return; // tolerate null lock object (no-op)
    const header = @as(*ObjectHeader, @ptrFromInt(@intFromPtr(obj) - @sizeOf(ObjectHeader)));
    const current = thread.getCurrent() orelse @panic("monitorEnter outside JavaThread");
    const thread_id = current.id;

    while (true) {
        const current_val = @atomicLoad(usize, &header.monitor, .acquire);
        if (current_val == 0) {
            // Unlocked: attempt CAS to acquire thin lock
            if (@cmpxchgWeak(usize, &header.monitor, 0, thread_id << 1, .release, .monotonic) == null) {
                return;
            }
        } else if ((current_val >> 1) == thread_id) {
            // Reentrant lock
            const new_val = current_val + (1 << 32);
            @atomicStore(usize, &header.monitor, new_val, .release);
            return;
        } else {
            // Contested lock: spin-wait or yield thread
            current.yield();
        }
    }
}

pub fn monitorExit(obj: *anyopaque) callconv(.c) void {
    if (@intFromPtr(obj) == 0) return; // tolerate null (matches monitorEnter behaviour)
    const header = @as(*ObjectHeader, @ptrFromInt(@intFromPtr(obj) - @sizeOf(ObjectHeader)));
    const current = thread.getCurrent() orelse @panic("monitorExit outside JavaThread");
    const thread_id = current.id;

    const current_val = @atomicLoad(usize, &header.monitor, .acquire);
    if ((current_val >> 1) == thread_id) {
        const recursion = current_val >> 32;
        if (recursion > 0) {
            @atomicStore(usize, &header.monitor, current_val - (1 << 32), .release);
        } else {
            @atomicStore(usize, &header.monitor, 0, .release);
        }
    } else {
        @panic("IllegalMonitorStateException");
    }
}

pub fn monitorWait(obj: *anyopaque) callconv(.c) void {
    const header = @as(*ObjectHeader, @ptrFromInt(@intFromPtr(obj) - @sizeOf(ObjectHeader)));
    const current = thread.getCurrent() orelse @panic("monitorWait outside JavaThread");
    const thread_id = current.id;
    const obj_ptr = @intFromPtr(obj);

    const current_val = @atomicLoad(usize, &header.monitor, .acquire);
    if ((current_val >> 1) != thread_id) {
        @panic("IllegalMonitorStateException: wait called without monitor");
    }

    // Add to wait queue
    wait_queue_mutex.lock();
    if (wait_queues == null) {
        wait_queues = std.AutoHashMap(usize, std.ArrayList(*thread.JavaThread)).init(global_gc.?.allocator);
    }
    const gop = wait_queues.?.getOrPut(obj_ptr) catch @panic("OOM in wait queue");
    if (!gop.found_existing) {
        gop.value_ptr.* = std.ArrayList(*thread.JavaThread).empty;
    }
    gop.value_ptr.append(global_gc.?.allocator, current) catch @panic("OOM in wait queue");
    wait_queue_mutex.unlock();

    // Release lock completely (record recursion count)
    const recursion = current_val >> 32;
    @atomicStore(usize, &header.monitor, 0, .release);

    // Park fiber
    current.park();

    // Re-acquire lock
    monitorEnter(obj);

    // Restore recursion
    if (recursion > 0) {
        const new_val = @atomicLoad(usize, &header.monitor, .acquire) + (recursion << 32);
        @atomicStore(usize, &header.monitor, new_val, .release);
    }
}

pub fn monitorNotify(obj: *anyopaque) callconv(.c) void {
    const header = @as(*ObjectHeader, @ptrFromInt(@intFromPtr(obj) - @sizeOf(ObjectHeader)));
    const current = thread.getCurrent() orelse return;
    const thread_id = current.id;
    const obj_ptr = @intFromPtr(obj);

    const current_val = @atomicLoad(usize, &header.monitor, .acquire);
    if ((current_val >> 1) != thread_id) {
        @panic("IllegalMonitorStateException: notify called without monitor");
    }

    wait_queue_mutex.lock();
    defer wait_queue_mutex.unlock();
    if (wait_queues) |*wq| {
        if (wq.getPtr(obj_ptr)) |list| {
            if (list.items.len > 0) {
                const target = list.orderedRemove(0);
                target.unpark();
            }
        }
    }
}

pub fn monitorNotifyAll(obj: *anyopaque) callconv(.c) void {
    const header = @as(*ObjectHeader, @ptrFromInt(@intFromPtr(obj) - @sizeOf(ObjectHeader)));
    const current = thread.getCurrent() orelse return;
    const thread_id = current.id;
    const obj_ptr = @intFromPtr(obj);

    const current_val = @atomicLoad(usize, &header.monitor, .acquire);
    if ((current_val >> 1) != thread_id) {
        @panic("IllegalMonitorStateException: notifyAll called without monitor");
    }

    wait_queue_mutex.lock();
    defer wait_queue_mutex.unlock();
    if (wait_queues) |*wq| {
        if (wq.getPtr(obj_ptr)) |list| {
            for (list.items) |target| {
                target.unpark();
            }
            list.clearRetainingCapacity();
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

const JitStringLayout = extern struct { value: [*]const u8, length: i32 };

/// JIT helper: build a heap String object from a (value pointer, length) pair,
/// matching the interpreter's const_string handling. The emitter resolves the
/// string-pool entry at compile time (the bytes live in the stable DEX buffer)
/// and passes value_ptr/length as immediates. Passing the raw pool index instead
/// would look like a misaligned object pointer to consumers.
pub fn gcNewString(value_ptr: usize, length: i32) callconv(.c) usize {
    const obj = gcAlloc(0, 24);
    const slay = @as(*JitStringLayout, @ptrCast(@alignCast(obj)));
    slay.value = @ptrFromInt(value_ptr);
    slay.length = length;
    return @intFromPtr(obj);
}

/// JIT helper: allocate an array of `count` elements with the given element size
/// (elem_size: 1=byte/bool, 2=short/char, 4=int/float, 8=long/double/ref).
/// Returns pointer to the array body (first field is i32 length).
pub fn gcAllocArray(count: i64, elem_size: usize) callconv(.c) usize {
    if (count < 0) return 0;
    const byte_count = @as(usize, @intCast(count)) * elem_size + 8; // 4-byte len + 4 pad
    const raw = gcAlloc(0, byte_count);
    const ptr = @intFromPtr(raw);
    @as(*i32, @ptrFromInt(ptr)).* = @intCast(count);
    return ptr;
}

/// JIT helper: allocate an instance of the given class (size in bytes, excl header).
pub fn gcAllocObj(class_ptr: usize, size: usize) callconv(.c) usize {
    const raw = gcAlloc(class_ptr, size);
    return @intFromPtr(raw);
}

/// JIT helper: check if object is instance of class. (Currently minimal check)
pub fn gcInstanceOf(obj_ptr: usize, type_idx: u32) callconv(.c) i32 {
    if (obj_ptr == 0) return 0;
    _ = type_idx;
    // For a real implementation, we would look up type_idx in native.global_dex
    // and compare it to the class_ptr of the object.
    // For now, return 1 to mimic interpreter behavior.
    return 1;
}

/// JIT helper: fill array with data payload.
pub fn gcFillArrayData(array_ptr: usize, data_ptr: usize, elements: u32, width: u32) callconv(.c) void {
    if (array_ptr == 0 or data_ptr == 0) return;
    const array_body = @as([*]u8, @ptrFromInt(array_ptr));
    // Array body starts with 4-byte length. Elements start at offset 8 (after 4 bytes padding).
    const dest = array_body[8..];
    const src = @as([*]const u8, @ptrFromInt(data_ptr))[0 .. elements * width];
    @memcpy(dest[0..src.len], src);
}

/// JIT helper: move exception from TLS
pub fn gcGetAndClearException() callconv(.c) usize {
    const th = thread.getCurrent();
    if (th) |t| {
        const ex = t.tls.exception;
        t.tls.exception = 0;
        return ex;
    }
    return 0;
}
/// C guard helper — calls longjmp back into jit_guarded_call if a guard is active.
extern fn jit_longjmp_if_guarded() callconv(.c) void;

pub fn throwIndexOutOfBounds(index: i64, length: i64) callconv(.c) noreturn {
    std.debug.print("ArrayIndexOutOfBoundsException: Index {d} out of bounds for length {d}\n", .{ index, length });
    // If the interpreter set up a setjmp guard (via jit_guarded_call), unwind to it.
    jit_longjmp_if_guarded(); // never returns when a guard is active
    std.process.exit(1);
}

pub fn throwNullPointerException() callconv(.c) noreturn {
    std.debug.print("NullPointerException\n", .{});
    jit_longjmp_if_guarded();
    std.process.exit(1);
}
