const std = @import("std");
const registry = @import("../../registry.zig");

extern fn printf(format: [*]const u8, ...) callconv(.c) c_int;
extern fn fflush(stream: ?*anyopaque) callconv(.c) c_int;

/// Flush libc stdio buffers. Print methods below intentionally do NOT flush on
/// every call (that was a per-call `write()` syscall storm); the VM flushes once
/// at shutdown, and callers that interleave with other output can flush here.
pub fn flushStdout() void {
    _ = fflush(null);
}

const StringLayout = struct {
    value: [*]const u8,
    length: i32,
};

fn println(args: [*]const u64, _: usize) callconv(.c) u64 {
    const str_obj = args[1];
    if (str_obj == 0) {
        _ = printf("null\n");
        return 0;
    }
    const layout = @as(*align(4) const StringLayout, @ptrFromInt(str_obj));
    _ = printf("%.*s\n", @as(c_int, @intCast(layout.length)), layout.value);
    return 0;
}

fn printlnInt(args: [*]const u64, _: usize) callconv(.c) u64 {
    const val = @as(i32, @bitCast(@as(u32, @truncate(args[1]))));
    _ = printf("%d\n", @as(c_int, val));
    return 0;
}

fn printlnLong(args: [*]const u64, _: usize) callconv(.c) u64 {
    const val = @as(i64, @bitCast(args[1]));
    _ = printf("%lld\n", @as(c_longlong, val));
    return 0;
}


fn print(args: [*]const u64, _: usize) callconv(.c) u64 {
    const str_obj = args[1];
    if (str_obj == 0) {
        _ = printf("null");
        return 0;
    }
    const layout = @as(*align(4) const StringLayout, @ptrFromInt(str_obj));
    _ = printf("%.*s", @as(c_int, @intCast(layout.length)), layout.value);
    return 0;
}

fn printf_native(args: [*]const u64, _: usize) callconv(.c) u64 {
    const fmt_obj = args[1];
    if (fmt_obj == 0) return 0;
    const fmt_layout = @as(*align(4) const StringLayout, @ptrFromInt(fmt_obj));
    const fmt_slice = fmt_layout.value[0..@intCast(fmt_layout.length)];
    const has_array = args[2] != 0;
    const arr_ptr = if (has_array) @as([*]const u32, @ptrFromInt(args[2] + 4)) else undefined;
    const arr_len = if (has_array) @as(*const i32, @ptrCast(@alignCast(@as(*anyopaque, @ptrFromInt(args[2]))))).* else 0;
    
    const getArgValue = struct {
        fn run(idx: usize, ap: [*]const u32, has_ap: bool, al: i32, raw_args: [*]const u64) u64 {
            if (!has_ap) return raw_args[idx];
            if (@as(i32, @intCast(idx - 2)) < al) {
                const ap64 = @as([*]align(4) const u64, @ptrCast(@alignCast(ap)));
                return ap64[idx - 2];
            }
            return 0;
        }
    }.run;

    var i: usize = 0;
    var arg_idx: usize = 2;
    var start_txt: usize = 0;
    while (i < fmt_slice.len) {
        const char = fmt_slice[i];
        if (char == '%') {
            if (i > start_txt) {
                _ = printf("%.*s", @as(c_int, @intCast(i - start_txt)), fmt_slice[start_txt..].ptr);
            }
            var j = i + 1;
            var width: ?usize = null;
            var precision: ?usize = null;
            var has_precision = false;

            while (j < fmt_slice.len) {
                const fmt_char = fmt_slice[j];
                if (fmt_char >= '0' and fmt_char <= '9') {
                    if (has_precision) {
                        precision = (precision orelse 0) * 10 + (fmt_char - '0');
                    } else {
                        width = (width orelse 0) * 10 + (fmt_char - '0');
                    }
                    j += 1;
                } else if (fmt_char == '.') {
                    has_precision = true;
                    j += 1;
                } else {
                    break;
                }
            }

            if (j < fmt_slice.len) {
                const conv = fmt_slice[j];
                if (conv == 'd') {
                    const obj_addr = getArgValue(arg_idx, arr_ptr, has_array, arr_len, args);
                    const val = if (obj_addr != 0) @as(*align(4) const i32, @ptrFromInt(obj_addr)).* else 0;
                    _ = printf("%d", @as(c_int, val));
                    arg_idx += 1;
                } else if (conv == 's') {
                    const obj_addr = getArgValue(arg_idx, arr_ptr, has_array, arr_len, args);
                    if (obj_addr == 0) {
                        _ = printf("null");
                    } else {
                        const layout = @as(*const StringLayout, @ptrFromInt(obj_addr));
                        _ = printf("%.*s", @as(c_int, @intCast(layout.length)), layout.value);
                    }
                    arg_idx += 1;
                } else if (conv == 'f') {
                    const obj_addr = getArgValue(arg_idx, arr_ptr, has_array, arr_len, args);
                    const val = if (obj_addr != 0) @as(*align(4) const f64, @ptrFromInt(obj_addr)).* else 0.0;
                    if (has_precision) {
                        var fmt_buf: [32]u8 = undefined;
                        const fmt_str = std.fmt.bufPrint(&fmt_buf, "%.{d}f", .{precision orelse 6}) catch "%.6f";
                        var c_fmt: [33]u8 = undefined;
                        @memcpy(c_fmt[0..fmt_str.len], fmt_str);
                        c_fmt[fmt_str.len] = 0;
                        _ = printf(c_fmt[0..].ptr, val);
                    } else {
                        _ = printf("%f", val);
                    }
                    arg_idx += 1;
                } else if (conv == 'n') {
                    _ = printf("\n");
                } else if (conv == '%') {
                    _ = printf("%%");
                }
                i = j;
            }
            start_txt = i + 1;
        }
        i += 1;
    }
    
    if (i > start_txt) {
        _ = printf("%.*s", @as(c_int, @intCast(i - start_txt)), fmt_slice[start_txt..].ptr);
    }
    return 0;
}

pub const class_def = registry.NativeClassDef{
    .name = "java/io/PrintStream",
    .super_name = "java/lang/Object",
    .instance_size = 16,
    .methods = &.{
        .{ .name = "print", .signature = "VL", .is_static = false, .func_ptr = &print },
        .{ .name = "println", .signature = "VL", .is_static = false, .func_ptr = &println },
        .{ .name = "println", .signature = "VI", .is_static = false, .func_ptr = &printlnInt },
        .{ .name = "println", .signature = "VJ", .is_static = false, .func_ptr = &printlnLong },
        .{ .name = "printf", .signature = "LLL", .is_static = false, .func_ptr = &printf_native },
    },
};
