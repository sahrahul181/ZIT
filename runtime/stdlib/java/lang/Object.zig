const registry = @import("../../registry.zig");
const runtime = @import("runtime");

fn hashCode(args: [*]const u64, n_args: usize) callconv(.c) u64 {
    _ = n_args;
    // For identity hashcode, we can just cast the pointer to a 32-bit int
    const ptr = args[0];
    return @truncate(ptr);
}

fn equals(args: [*]const u64, n_args: usize) callconv(.c) u64 {
    _ = n_args;
    return if (args[0] == args[1]) 1 else 0;
}

fn clone(args: [*]const u64, n_args: usize) callconv(.c) u64 {
    _ = n_args;
    const ptr = args[0];
    if (ptr == 0) return 0;
    
    const obj = @as(*anyopaque, @ptrFromInt(ptr));
    const header = @as(*runtime.ObjectHeader, @ptrFromInt(ptr - 16));
    
    if (header.class_ptr == 0) {
        @panic("CloneNotSupportedException: Cannot clone arrays yet");
    }
    
    const class_loader = @import("class_loader");
    const cd = @as(*const class_loader.ClassData, @ptrFromInt(header.class_ptr));
    const size = cd.instance_size;
    
    const new_obj = runtime.gcAlloc(header.class_ptr, size);
    
    // Copy memory (shallow copy)
    @import("std").mem.copyForwards(u8, @as([*]u8, @ptrCast(new_obj))[0..size], @as([*]const u8, @ptrCast(obj))[0..size]);
    
    return @intFromPtr(new_obj);
}

fn notify(args: [*]const u64, n_args: usize) callconv(.c) u64 {
    _ = n_args;
    const ptr = args[0];
    runtime.monitorNotify(@ptrFromInt(ptr));
    return 0;
}

fn notifyAll(args: [*]const u64, n_args: usize) callconv(.c) u64 {
    _ = n_args;
    const ptr = args[0];
    runtime.monitorNotifyAll(@ptrFromInt(ptr));
    return 0;
}

fn wait(args: [*]const u64, n_args: usize) callconv(.c) u64 {
    _ = n_args;
    const ptr = args[0];
    runtime.monitorWait(@ptrFromInt(ptr));
    return 0;
}

pub const class_def = registry.NativeClassDef{
    .name = "java/lang/Object",
    .super_name = null,
    .instance_size = 16, // monitor + class_ptr
    .methods = &.{
        .{ .name = "<init>", .signature = "V", .is_static = false, .func_ptr = null },
        .{ .name = "hashCode", .signature = "I", .is_static = false, .func_ptr = hashCode },
        .{ .name = "equals", .signature = "ZL", .is_static = false, .func_ptr = equals },
        .{ .name = "clone", .signature = "L", .is_static = false, .func_ptr = clone },
        .{ .name = "notify", .signature = "V", .is_static = false, .func_ptr = notify },
        .{ .name = "notifyAll", .signature = "V", .is_static = false, .func_ptr = notifyAll },
        .{ .name = "wait", .signature = "V", .is_static = false, .func_ptr = wait },
    },
};
