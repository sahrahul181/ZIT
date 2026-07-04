const registry = @import("../../registry.zig");

fn valueOf(args: [*]const u64, _: usize) callconv(.c) u64 {
    const val = @as(f64, @bitCast(args[0]));
    const runtime = @import("runtime");
    const obj = runtime.gcAlloc(0, 24);
    @as(*f64, @ptrCast(@alignCast(obj))).* = val;
    return @intFromPtr(obj);
}

pub const class_def = registry.NativeClassDef{
    .name = "java/lang/Double",
    .super_name = "java/lang/Object",
    .instance_size = 16,
    .methods = &.{
        .{ .name = "valueOf", .signature = "LD", .is_static = true, .func_ptr = &valueOf },
    },
};
