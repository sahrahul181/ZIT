const std = @import("std");
const registry = @import("../../registry.zig");
const runtime = @import("runtime");

const StringLayout = struct {
    value: [*]const u8,
    length: i32,
};

const StringBuilderLayout = struct {
    length: i32,
    data: [4096]u8,
};

fn init(args: [*]const u64, _: usize) callconv(.c) u64 {
    const this = args[0];
    if (this == 0) return 0;
    const layout = @as(*align(4) StringBuilderLayout, @ptrFromInt(this));
    layout.length = 0;
    return this;
}

fn appendString(args: [*]const u64, _: usize) callconv(.c) u64 {
    const this = args[0];
    const str = args[1];
    if (this == 0) return this;
    const layout = @as(*align(4) StringBuilderLayout, @ptrFromInt(this));
    if (str != 0) {
        const str_layout = @as(*align(4) const StringLayout, @ptrFromInt(str));
        const len = str_layout.length;
        if (len > 0) {
            const copy_len = @min(@as(usize, @intCast(len)), layout.data.len - @as(usize, @intCast(layout.length)));
            if (copy_len > 0) {
                @memcpy(layout.data[@intCast(layout.length)..][0..copy_len], str_layout.value[0..copy_len]);
                layout.length += @intCast(copy_len);
            }
        }
    }
    return this;
}

fn appendInt(args: [*]const u64, _: usize) callconv(.c) u64 {
    const this = args[0];
    const val = @as(i32, @bitCast(@as(u32, @truncate(args[1]))));
    if (this == 0) return this;
    const layout = @as(*align(4) StringBuilderLayout, @ptrFromInt(this));
    
    var buf: [32]u8 = undefined;
    const str = std.fmt.bufPrint(&buf, "{d}", .{val}) catch return this;
    const copy_len = @min(str.len, layout.data.len - @as(usize, @intCast(layout.length)));
    if (copy_len > 0) {
        @memcpy(layout.data[@intCast(layout.length)..][0..copy_len], str[0..copy_len]);
        layout.length += @intCast(copy_len);
    }
    return this;
}

fn toString(args: [*]const u64, _: usize) callconv(.c) u64 {
    const this = args[0];
    if (this == 0) return 0;
    const layout = @as(*align(4) StringBuilderLayout, @ptrFromInt(this));
    
    const len = @as(usize, @intCast(layout.length));
    if (len == 0) {
        const str_obj = runtime.gcAlloc(0, 24);
        const str_layout = @as(*align(4) StringLayout, @ptrCast(@alignCast(str_obj)));
        str_layout.value = "";
        str_layout.length = 0;
        return @intFromPtr(str_obj);
    }
    
    // Allocate bytes in GC for the string content
    const bytes = runtime.gcAlloc(0, len);
    @memcpy(@as([*]u8, @ptrCast(bytes))[0..len], layout.data[0..len]);
    
    const str_obj = runtime.gcAlloc(0, 24);
    const str_layout = @as(*align(4) StringLayout, @ptrCast(@alignCast(str_obj)));
    str_layout.value = @ptrCast(bytes);
    str_layout.length = @intCast(len);
    return @intFromPtr(str_obj);
}

pub const class_def = registry.NativeClassDef{
    .name = "java/lang/StringBuilder",
    .super_name = "java/lang/Object",
    .instance_size = @sizeOf(StringBuilderLayout),
    .methods = &.{
        .{ .name = "<init>", .signature = "V", .is_static = false, .func_ptr = &init },
        .{ .name = "append", .signature = "LL", .is_static = false, .func_ptr = &appendString },
        .{ .name = "append", .signature = "LI", .is_static = false, .func_ptr = &appendInt },
        .{ .name = "toString", .signature = "L", .is_static = false, .func_ptr = &toString },
    },
};
