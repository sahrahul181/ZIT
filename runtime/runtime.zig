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
        // Allocate a new block from the OS (via Zig allocator)
        const mem = try self.allocator.alloc(u8, layout.BLOCK_SIZE);
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
    const th = thread.current_thread;
    if (th) |t| {
        const ex = t.tls.exception;
        t.tls.exception = 0;
        return ex;
    }
    return 0;
}

