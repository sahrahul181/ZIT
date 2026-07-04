const std = @import("std");
const registry = @import("../../registry.zig");
const StringLayout = struct {
    value: [*]const u8,
    length: i32,
};

fn parseInt(args: [*]const u64, _: usize) callconv(.c) u64 {
    const str_obj = args[0];
    if (str_obj == 0) return 0;
    const layout = @as(*align(4) const StringLayout, @ptrFromInt(str_obj));
    const slice = layout.value[0..@intCast(layout.length)];
    const val = std.fmt.parseInt(i32, slice, 10) catch |err| {
        std.debug.print("parseInt failed for '{s}' (len={d}) with error: {s}\n", .{ slice, slice.len, @errorName(err) });
        return 0;
    };
    return @bitCast(@as(i64, val));
}

fn valueOf(args: [*]const u64, _: usize) callconv(.c) u64 {
    const val = @as(i32, @bitCast(@as(u32, @truncate(args[0]))));
    const runtime = @import("runtime");
    const obj = runtime.gcAlloc(0, 24);
    @as(*i32, @ptrCast(@alignCast(obj))).* = val;
    return @intFromPtr(obj);
}

pub const class_def = registry.NativeClassDef{
    .name = "java/lang/Integer",
    .super_name = "java/lang/Object",
    .instance_size = 16,
    .methods = &.{
        .{ .name = "parseInt", .signature = "IL", .is_static = true, .func_ptr = &parseInt },
        .{ .name = "valueOf", .signature = "LI", .is_static = true, .func_ptr = &valueOf },
    },
};
