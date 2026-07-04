const std = @import("std");

pub const StringLayout = struct {
    value: [*]const u8,
    length: i32,
};

pub fn length(str: ?*anyopaque) callconv(.c) i32 {
    if (str) |s| {
        const layout = @as(*const StringLayout, @ptrCast(s));
        return layout.length;
    }
    return 0;
}

pub fn charAt(str: ?*anyopaque, index: i32) callconv(.c) u8 {
    if (str) |s| {
        const layout = @as(*const StringLayout, @ptrCast(s));
        if (index >= 0 and index < layout.length) {
            return layout.value[@intCast(index)];
        }
    }
    return 0;
}
