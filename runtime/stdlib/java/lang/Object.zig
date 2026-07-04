const registry = @import("../../registry.zig");

pub const class_def = registry.NativeClassDef{
    .name = "java/lang/Object",
    .super_name = null,
    .instance_size = 16,
    .methods = &.{
        .{ .name = "<init>", .signature = "V", .is_static = false, .func_ptr = null },
        .{ .name = "hashCode", .signature = "I", .is_static = false, .func_ptr = null },
        .{ .name = "equals", .signature = "ZL", .is_static = false, .func_ptr = null },
    },
};
