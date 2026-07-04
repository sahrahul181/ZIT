const std = @import("std");

pub fn hashCode(obj: *anyopaque) callconv(.c) i32 {
    return @intCast(@intFromPtr(obj) & 0x7FFFFFFF);
}

pub fn equals(obj1: ?*anyopaque, obj2: ?*anyopaque) callconv(.c) bool {
    return obj1 == obj2;
}
