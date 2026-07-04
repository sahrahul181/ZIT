const std = @import("std");
const runtime = @import("../runtime/runtime.zig");

pub const ParallelLoopTask = struct {
    run: *const fn (i32) callconv(.c) void,
    index: i32,
};

fn runParallelTask(arg: ?*anyopaque) callconv(.c) void {
    if (arg) |a| {
        const loop_task = @as(*const ParallelLoopTask, @ptrCast(a));
        loop_task.run(loop_task.index);
    }
}

pub fn parallelForEach(start: i32, end: i32, run: *const fn (i32) callconv(.c) void) callconv(.c) void {
    if (start >= end) return;
    const count = end - start;
    const allocator = std.heap.page_allocator;
    
    var tasks = allocator.alloc(ParallelLoopTask, @intCast(count)) catch return;
    defer allocator.free(tasks);
    
    for (0..@intCast(count)) |i| {
        tasks[i] = .{
            .run = run,
            .index = start + @as(i32, @intCast(i)),
        };
        runtime.global_pool.submit(.{
            .run = runParallelTask,
            .arg = &tasks[i],
        }) catch {};
    }
    
    std.Thread.yield() catch {};
}
