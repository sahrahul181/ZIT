const std = @import("std");

var memory_barrier_dummy: u8 = 0;
pub inline fn seqCstFence() void {
    _ = @atomicRmw(u8, &memory_barrier_dummy, .Xchg, 0, .seq_cst);
}

pub const Task = struct {
    run: *const fn (?*anyopaque) callconv(.c) void,
    arg: ?*anyopaque,
};

pub const CircularArray = struct {
    log_size: u8,
    tasks: []Task,
    allocator: std.mem.Allocator,

    pub fn init(allocator: std.mem.Allocator, log_size: u8) !*CircularArray {
        const size = @as(usize, 1) << @as(u6, @intCast(log_size));
        const tasks = try allocator.alloc(Task, size);
        const self = try allocator.create(CircularArray);
        self.* = .{ .log_size = log_size, .tasks = tasks, .allocator = allocator };
        return self;
    }

    pub fn deinit(self: *CircularArray) void {
        self.allocator.free(self.tasks);
        self.allocator.destroy(self);
    }

    pub fn get(self: *CircularArray, idx: i64) Task {
        const mask = (@as(usize, 1) << @as(u6, @intCast(self.log_size))) - 1;
        const uidx: u64 = @bitCast(idx);
        return self.tasks[@as(usize, @intCast(uidx & mask))];
    }

    pub fn put(self: *CircularArray, idx: i64, task: Task) void {
        const mask = (@as(usize, 1) << @as(u6, @intCast(self.log_size))) - 1;
        const uidx: u64 = @bitCast(idx);
        self.tasks[@as(usize, @intCast(uidx & mask))] = task;
    }

    pub fn resize(self: *CircularArray, b: i64, t: i64) !*CircularArray {
        const new_ca = try CircularArray.init(self.allocator, self.log_size + 1);
        var i = t;
        while (i < b) : (i += 1) {
            new_ca.put(i, self.get(i));
        }
        return new_ca;
    }
};

pub const Deque = struct {
    top: i64 = 0,
    bottom: i64 = 0,
    active_array: *CircularArray,
    allocator: std.mem.Allocator,

    pub fn init(allocator: std.mem.Allocator, initial_log_size: u8) !Deque {
        return .{
            .active_array = try CircularArray.init(allocator, initial_log_size),
            .allocator = allocator,
        };
    }

    pub fn deinit(self: *Deque) void {
        self.active_array.deinit();
    }

    pub fn push(self: *Deque, task: Task) !void {
        const b = @atomicLoad(i64, &self.bottom, .monotonic);
        const t = @atomicLoad(i64, &self.top, .acquire);
        var a = @atomicLoad(*CircularArray, &self.active_array, .monotonic);

        const size = b - t;
        const capacity = @as(i64, 1) << @as(u6, @intCast(a.log_size));
        
        if (size >= capacity - 1) {
            a = try a.resize(b, t);
            @atomicStore(*CircularArray, &self.active_array, a, .release);
        }

        a.put(b, task);
        @atomicStore(i64, &self.bottom, b + 1, .release);
    }

    pub fn pop(self: *Deque) ?Task {
        const b = @atomicLoad(i64, &self.bottom, .monotonic) - 1;
        @atomicStore(i64, &self.bottom, b, .monotonic);
        seqCstFence();

        const t = @atomicLoad(i64, &self.top, .monotonic);
        if (t <= b) {
            // Non-empty
            const a = @atomicLoad(*CircularArray, &self.active_array, .monotonic);
            const task = a.get(b);
            if (t != b) {
                // More than one item
                return task;
            }
            // Exactly one item, might conflict with steal
            if (@cmpxchgStrong(i64, &self.top, t, t + 1, .seq_cst, .monotonic) == null) {
                @atomicStore(i64, &self.bottom, t + 1, .monotonic);
                return task;
            } else {
                @atomicStore(i64, &self.bottom, t + 1, .monotonic);
                return null; // Lost the race to steal
            }
        } else {
            // Empty
            @atomicStore(i64, &self.bottom, t, .monotonic);
            return null;
        }
    }

    pub fn steal(self: *Deque) ?Task {
        while (true) {
            const t = @atomicLoad(i64, &self.top, .acquire);
            seqCstFence();
            const b = @atomicLoad(i64, &self.bottom, .acquire);

            if (t < b) {
                const a = @atomicLoad(*CircularArray, &self.active_array, .acquire);
                const task = a.get(t);
                if (@cmpxchgStrong(i64, &self.top, t, t + 1, .seq_cst, .monotonic) == null) {
                    return task;
                }
                // CAS failed, try again
            } else {
                return null; // Empty
            }
        }
    }
};
