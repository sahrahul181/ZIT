const std = @import("std");
const registry = @import("../../registry.zig");
const runtime = @import("runtime");

fn currentTimeMillis(args: [*]const u64, _: usize) callconv(.c) u64 {
    _ = args;
    return @intCast(std.Io.Timestamp.now(runtime.global_io, .real).toMilliseconds());
}

fn nanoTime(args: [*]const u64, _: usize) callconv(.c) u64 {
    _ = args;
    return @bitCast(@as(i64, @intCast(std.Io.Timestamp.now(runtime.global_io, .awake).toNanoseconds())));
}

pub const class_def = registry.NativeClassDef{
    .name = "java/lang/System",
    .super_name = "java/lang/Object",
    .instance_size = 16,
    .methods = &.{
        .{ .name = "currentTimeMillis", .signature = "J", .is_static = true, .func_ptr = &currentTimeMillis },
        .{ .name = "nanoTime", .signature = "J", .is_static = true, .func_ptr = &nanoTime },
    },
    .static_fields = &.{
        .{ .name = "out", .signature = "Ljava/io/PrintStream;" },
    },
};
