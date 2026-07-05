const std = @import("std");

pub const NativeMethodDef = struct {
    name: []const u8,
    signature: []const u8,
    is_static: bool,
    func_ptr: ?*const anyopaque,
};

pub const NativeFieldDef = struct {
    name: []const u8,
    signature: []const u8,
};

pub const NativeClassDef = struct {
    name: []const u8,
    super_name: ?[]const u8 = "java/lang/Object",
    instance_size: u32 = 16,
    methods: []const NativeMethodDef = &.{},
    static_fields: []const NativeFieldDef = &.{},
};

pub const stdlib_classes = [_]NativeClassDef{
    @import("java/lang/Object.zig").class_def,
    @import("java/lang/String.zig").class_def,
    @import("java/lang/System.zig").class_def,
    @import("java/lang/Math.zig").class_def,
    @import("java/lang/Integer.zig").class_def,
    @import("java/lang/Double.zig").class_def,
    @import("java/lang/Thread.zig").class_def,
    @import("java/lang/StringBuilder.zig").class_def,
    @import("java/io/PrintStream.zig").class_def,
};
