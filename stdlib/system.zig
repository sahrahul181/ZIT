const std = @import("std");
const string = @import("string.zig");

pub fn print(str: ?*anyopaque) callconv(.c) void {
    if (str) |s| {
        const layout = @as(*const string.StringLayout, @ptrCast(s));
        const slice = layout.value[0..@intCast(layout.length)];
        std.io.getStdOut().writer().writeAll(slice) catch {};
    }
}

pub fn println(str: ?*anyopaque) callconv(.c) void {
    print(str);
    std.io.getStdOut().writer().writeAll("\n") catch {};
}
