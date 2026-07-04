const registry = @import("../../registry.zig");

pub const class_def = registry.NativeClassDef{
    .name = "java/lang/String",
    .super_name = "java/lang/Object",
    .instance_size = 24,
    .methods = &.{
        .{ .name = "length", .signature = "I", .is_static = false, .func_ptr = null },
        .{ .name = "charAt", .signature = "CI", .is_static = false, .func_ptr = null },
        .{ .name = "equals", .signature = "ZL", .is_static = false, .func_ptr = null },
    },
};
