const std = @import("std");
const registry = @import("../../registry.zig");
const runtime = @import("runtime");

var next_thread_id: std.atomic.Value(usize) = std.atomic.Value(usize).init(1);

fn init(args: [*]const u64, _: usize) callconv(.c) u64 {
    const this = args[0];
    const target = args[1];
    @as(*u64, @ptrFromInt(this + 8)).* = target;
    return 0;
}

fn start(args: [*]const u64, _: usize) callconv(.c) u64 {
    const th_obj_ptr = args[0];
    const native = @import("../../../native.zig");
    const allocator = native.global_native_registry.?.allocator;
    const thread_mod = @import("thread");

    const run_trampoline = struct {
        fn run(thread: *@import("thread").JavaThread) callconv(.c) void {
            const target = @as(*const u64, @ptrFromInt(thread.java_thread_obj + 8)).*;
            if (target == 0) return;
            
            const obj = @as(*const @import("runtime").ObjectHeader, @ptrFromInt(@as(usize, target) - 16));
            const cd = @as(*const @import("class_loader").ClassData, @ptrFromInt(obj.class_ptr));
            const run_m = cd.findMethod("run", "V") orelse return;
            const nat = @import("../../../native.zig");
            const interpreter = @import("interpreter");
            
            var interp = interpreter.Interpreter.init(
                nat.global_native_registry.?.allocator,
                nat.global_registry.?,
                nat.global_dex.?,
            );
            interp.native_lookup_fn = nat.lookupNativeMethod;
            const val_args = [_]u64{ target };
            _ = interp.invoke(run_m, &val_args) catch |err| {
                std.debug.print("Thread {d} exited with error: {s}\n", .{ thread.id, @errorName(err) });
            };
        }
    }.run;

    const tid = next_thread_id.fetchAdd(1, .monotonic);
    const jt = thread_mod.JavaThread.init(allocator, tid, run_trampoline) catch {
        std.debug.panic("OutOfMemory during Thread.start", .{});
    };
    jt.java_thread_obj = th_obj_ptr;

    const jt_field_ptr = @as(*usize, @ptrFromInt(th_obj_ptr));
    jt_field_ptr.* = @intFromPtr(jt);

    jt.start();
    return 0;
}

fn join(args: [*]const u64, _: usize) callconv(.c) u64 {
    const th_obj_ptr = args[0];
    const jt_field_ptr = @as(*usize, @ptrFromInt(th_obj_ptr));
    if (jt_field_ptr.* != 0) {
        const thread_mod = @import("thread");
        const jt = @as(*thread_mod.JavaThread, @ptrFromInt(jt_field_ptr.*));
        jt.join();
    }
    return 0;
}

fn sleep(args: [*]const u64, _: usize) callconv(.c) u64 {
    const ms = args[0];
    runtime.global_io.sleep(.fromMilliseconds(@as(i64, @intCast(ms))), .awake) catch {};
    const sp_page = @import("safepoint").safepoint_page;
    _ = sp_page.*;
    return 0;
}

pub const class_def = registry.NativeClassDef{
    .name = "java/lang/Thread",
    .super_name = "java/lang/Object",
    .instance_size = 32,
    .methods = &.{
        .{ .name = "<init>", .signature = "VL", .is_static = false, .func_ptr = &init },
        .{ .name = "start", .signature = "V", .is_static = false, .func_ptr = &start },
        .{ .name = "join", .signature = "V", .is_static = false, .func_ptr = &join },
        .{ .name = "sleep", .signature = "VJ", .is_static = true, .func_ptr = &sleep },
        .{ .name = "run", .signature = "V", .is_static = false, .func_ptr = null },
    },
};
