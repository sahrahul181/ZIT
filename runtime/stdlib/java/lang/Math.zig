const std = @import("std");
const registry = @import("../../registry.zig");

fn absInt(args: [*]const u64, _: usize) callconv(.c) u64 {
    const v: i32 = @bitCast(@as(u32, @truncate(args[0])));
    return @bitCast(@as(i64, @abs(v)));
}

fn absLong(args: [*]const u64, _: usize) callconv(.c) u64 {
    const v: i64 = @bitCast(args[0]);
    return @bitCast(@abs(v));
}

fn sqrtDouble(args: [*]const u64, _: usize) callconv(.c) u64 {
    const v: f64 = @bitCast(args[0]);
    return @bitCast(std.math.sqrt(v));
}

fn minInt(args: [*]const u64, _: usize) callconv(.c) u64 {
    const a: i32 = @bitCast(@as(u32, @truncate(args[0])));
    const b: i32 = @bitCast(@as(u32, @truncate(args[1])));
    return @bitCast(@as(i64, @min(a, b)));
}

fn maxInt(args: [*]const u64, _: usize) callconv(.c) u64 {
    const a: i32 = @bitCast(@as(u32, @truncate(args[0])));
    const b: i32 = @bitCast(@as(u32, @truncate(args[1])));
    return @bitCast(@as(i64, @max(a, b)));
}

pub const class_def = registry.NativeClassDef{
    .name = "java/lang/Math",
    .super_name = "java/lang/Object",
    .instance_size = 16,
    .methods = &.{
        .{ .name = "abs", .signature = "II", .is_static = true, .func_ptr = &absInt },
        .{ .name = "abs", .signature = "JJ", .is_static = true, .func_ptr = &absLong },
        .{ .name = "sqrt", .signature = "DD", .is_static = true, .func_ptr = &sqrtDouble },
        .{ .name = "min", .signature = "III", .is_static = true, .func_ptr = &minInt },
        .{ .name = "max", .signature = "III", .is_static = true, .func_ptr = &maxInt },
    },
};
