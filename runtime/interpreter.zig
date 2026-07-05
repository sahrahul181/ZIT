//! DEX Bytecode Interpreter — Phase 3 (Tier-0)
//!
//! Executes any Dalvik method correctly without JIT.
//! Provides correctness baseline and enables bootstrapping the stdlib.
//!
//! Architecture:
//!   - Register file: [MAX_REGS]u64 (bit-cast for all widths)
//!   - Call stack: linked list of Frame structs (arena-allocated)
//!   - Invocation counter: at JIT_THRESHOLD, method is marked hot and queued
//!   - Exception propagation: searches TryBlock tables, unwinds frames

const std = @import("std");
const parser = @import("parser");
const instmod = @import("instruction");
const class_loader = @import("class_loader");
const runtime = @import("runtime");
const safepoint = @import("safepoint");

const StringLayout = struct {
    value: [*]const u8,
    length: i32,
};

const Instruction = instmod.Instruction;
const Invoke = instmod.Invoke;
const InvokeKind = instmod.InvokeKind;
const TryBlock = instmod.TryBlock;
const ClassData = class_loader.ClassData;
const MethodData = class_loader.MethodData;

pub const MAX_REGS: usize = 256;

/// C guard: calls JIT fn with a setjmp guard. Returns raw u64 result.
/// Sets *exception_out = 1 if throwIndexOutOfBounds longjmp'd back.
extern fn jit_guarded_call(
    fn_ptr: usize,
    a0: u64,
    a1: u64,
    a2: u64,
    a3: u64,
    exception_out: *c_int,
) callconv(.c) u64;

// ── JIT threshold ─────────────────────────────────────────────────────────────
pub const JIT_THRESHOLD: u32 = 1000000;

// ── Execution result ──────────────────────────────────────────────────────────
pub const Value = union(enum) {
    void_val,
    int: i32,
    long: i64,
    float: f32,
    double: f64,
    ref: usize, // GC-managed object pointer
};

pub const InterpError = error{
    StackOverflow,
    NullPointerException,
    ArrayIndexOutOfBounds,
    ArithmeticException, // div-by-zero
    ClassCastException,
    NegativeArraySize,
    OutOfMemory,
    UncaughtException,
    MethodNotFound,
    UnimplementedOpcode,
};

// ── Frame ─────────────────────────────────────────────────────────────────────

pub const Frame = struct {
    method: *MethodData,
    regs: [MAX_REGS]u64, // all registers, bit-cast on demand
    pc: u32, // index into decoded instruction array
    caller: ?*Frame,
    result: u64, // return value (raw bits)
    result_tag: ResultTag,
    exception: usize, // ref to pending Throwable, or 0

    pub const ResultTag = enum { void_val, int, long, float, double, ref };

    pub fn init(method: *MethodData) Frame {
        return .{
            .method = method,
            .regs = std.mem.zeroes([MAX_REGS]u64),
            .pc = 0,
            .caller = null,
            .result = 0,
            .result_tag = .void_val,
            .exception = 0,
        };
    }
};

// ── Interpreter ───────────────────────────────────────────────────────────────

pub const Interpreter = struct {
    registry: *class_loader.ClassRegistry,
    dex: *const parser.DexFile,
    allocator: std.mem.Allocator,
    native_lookup_fn: ?*const fn (class_name: []const u8, name: []const u8, sig: []const u8) ?*const fn (args: [*]const u64, n_args: usize) callconv(.c) u64 = null,

    pub fn init(
        allocator: std.mem.Allocator,
        registry: *class_loader.ClassRegistry,
        dex: *const parser.DexFile,
    ) Interpreter {
        return .{
            .registry = registry,
            .dex = dex,
            .allocator = allocator,
            .native_lookup_fn = null,
        };
    }

    // ── Public entry point ────────────────────────────────────────────────────

    /// Execute `method` with `args` and return the result value.
    /// `args[0]` is `this` for instance methods.
    pub fn invoke(self: *Interpreter, method: *MethodData, args: []const u64) InterpError!Value {
        // Safepoint poll at method entry (Asymmetric Dekker)
        _ = safepoint.safepoint_page.*;

        if (method.is_native) {
            const arrow = std.mem.indexOf(u8, method.name, "->") orelse 0;
            const short_name = if (arrow > 0) method.name[arrow + 2 ..] else method.name;
            if (self.native_lookup_fn) |lookup| {
                if (lookup(method.class_name, short_name, method.signature)) |native_fn| {
                    const res = native_fn(args.ptr, args.len);
                    if (method.signature[0] == 'V') {
                        return .void_val;
                    } else if (method.signature[0] == 'Z') {
                        return .{ .int = @as(i32, @intCast(res & 1)) };
                    } else if (method.signature[0] == 'I' or method.signature[0] == 'C' or method.signature[0] == 'B' or method.signature[0] == 'S') {
                        return .{ .int = @as(i32, @bitCast(@as(u32, @truncate(res)))) };
                    } else if (method.signature[0] == 'L' or method.signature[0] == '[') {
                        return .{ .ref = @intCast(res) };
                    } else if (method.signature[0] == 'J' or method.signature[0] == 'D') {
                        return .{ .long = @bitCast(res) };
                    } else {
                        return .{ .int = @as(i32, @bitCast(@as(u32, @truncate(res)))) };
                    }
                }
            }
            std.debug.print("Unresolved native method: {s}->{s} sig={s}\n", .{ method.class_name, short_name, method.signature });
            return .void_val;
        }

        // Invocation counting for tier-up.
        const count = method.invocation_count.fetchAdd(1, .monotonic);

        // Trigger compilation once the method is hot. Every caller at/after the
        // threshold that does not yet see published JIT code attempts the compile,
        // not just the single thread that observed count == THRESHOLD. This avoids
        // a race where two threads invoke a hot method simultaneously: the one
        // that reads count > THRESHOLD would otherwise skip compilation AND miss
        // the not-yet-published jit_entry, silently interpreting the whole method
        // (catastrophically slow for hot loops). The compile hook is mutex-guarded
        // and idempotent, so the loser blocks briefly then reads the winner's entry.
        if (count >= JIT_THRESHOLD and method.jitEntry() == null) {
            if (class_loader.jit_compile_fn) |compile_fn| {
                const jit_fn_ptr = compile_fn(@intFromPtr(method), @intFromPtr(self.registry), @intFromPtr(self.dex));
                if (jit_fn_ptr != 0) {
                    method.setJitEntry(jit_fn_ptr);
                }
            }
        }

        if (method.jitEntry()) |jit_fn_ptr| {
            // Very basic JIT stub dispatcher (currently supports our primitive 4-arg methods)
            if (method.signature[0] == 'I' and method.signature.len == 2) {
                var exception_out: c_int = 0;
                const raw = jit_guarded_call(
                    jit_fn_ptr,
                    if (args.len > 0) args[0] else 0,
                    0,
                    0,
                    0,
                    &exception_out,
                );
                if (exception_out != 0) {
                    const handler_pc = findHandlerAny(method.tries);
                    if (handler_pc) |hpc| {
                        var callee_frame = Frame.init(method);
                        const num_regs = method.registers_size;
                        const num_args = method.ins_size;
                        const start_reg = num_regs - num_args;
                        if (args.len > 0) callee_frame.regs[start_reg] = args[0];
                        callee_frame.pc = hpc;
                        callee_frame.exception = 0xDEADBEEF;
                        const instrs = try self.decodeMethod(method);
                        defer self.allocator.free(instrs);
                        const val = try self.runFrame(&callee_frame, instrs);
                        return val;
                    }
                    return InterpError.UncaughtException;
                }
                return .{ .int = @as(i32, @bitCast(@as(u32, @truncate(raw)))) };
            }
        }

        var frame = Frame.init(method);

        // Load arguments into top registers (Dalvik calling convention:
        // ins occupy the last `ins_size` registers).
        const regs_count: usize = method.registers_size;
        const first_arg_reg: usize = regs_count - method.ins_size;
        for (args, 0..) |a, i| {
            if (first_arg_reg + i < MAX_REGS) {
                frame.regs[first_arg_reg + i] = a;
            }
        }

        // Decode instructions for this method on-demand.
        if (method.code_off == 0) {
            return .void_val;
        }
        const instrs = try self.decodeMethod(method);
        defer self.allocator.free(instrs);

        return self.runFrame(&frame, instrs);
    }

    // ── Instruction decoder ───────────────────────────────────────────────────

    fn decodeMethod(self: *Interpreter, method: *MethodData) InterpError![]Instruction {
        if (method.code_off == 0) return InterpError.MethodNotFound;
        var target_class: ?parser.DexClass = null;
        for (self.dex.classes.items) |c| {
            if (std.mem.eql(u8, c.name, method.class_name)) {
                target_class = c;
                break;
            }
        }
        const cls = target_class orelse return InterpError.MethodNotFound;
        var target_m: ?parser.DexMethod = null;
        const arrow = std.mem.indexOf(u8, method.name, "->") orelse 0;
        const short_name = if (arrow > 0) method.name[arrow + 2 ..] else method.name;
        for (cls.methods.items) |m| {
            const ma = std.mem.indexOf(u8, m.name, "->") orelse 0;
            const m_short = if (ma > 0) m.name[ma + 2 ..] else m.name;
            if (std.mem.eql(u8, m_short, short_name) and std.mem.eql(u8, m.signature, method.signature)) {
                target_m = m;
                break;
            }
        }
        const dm = target_m orelse return InterpError.MethodNotFound;
        return self.dex.decodeMethod(self.allocator, dm) catch return InterpError.OutOfMemory;
    }

    // ── Frame execution loop ──────────────────────────────────────────────────

    pub fn runFrame(self: *Interpreter, frame: *Frame, instrs: []const Instruction) InterpError!Value {
        while (true) {
            const val = self.runFrameInternal(frame, instrs) catch |err| {
                if (err == error.ArrayIndexOutOfBounds or err == error.NullPointerException or err == error.ArithmeticException) {
                    frame.exception = 0xDEADBEEF;
                    const handler_pc = findHandlerAtPc(frame.method.tries, frame.pc - 1);
                    if (handler_pc) |hpc| {
                        frame.pc = hpc;
                        continue;
                    }
                }
                return err;
            };
            return val;
        }
    }

    fn runFrameInternal(self: *Interpreter, frame: *Frame, instrs: []const Instruction) InterpError!Value {
        @setRuntimeSafety(false);
        while (true) {
            if (frame.pc >= instrs.len) return InterpError.MethodNotFound;
            const inst = instrs[frame.pc];
            frame.pc += 1;

            switch (inst) {

                // ── Nop ──────────────────────────────────────────────────────
                .nop => {},

                // ── Moves ────────────────────────────────────────────────────
                .move => |v| frame.regs[v.dest] = frame.regs[v.src],
                .move_wide => |v| {
                    frame.regs[v.dest] = frame.regs[v.src];
                    frame.regs[v.dest + 1] = frame.regs[v.src + 1];
                },
                .move_object => |v| frame.regs[v.dest] = frame.regs[v.src],
                .move_result => |v| frame.regs[v.dest] = frame.result,
                .move_result_wide => |v| {
                    frame.regs[v.dest] = frame.result;
                    frame.regs[v.dest + 1] = frame.result >> 32;
                },
                .move_result_object => |v| frame.regs[v.dest] = frame.result,
                .move_exception => |v| {
                    frame.regs[v.dest] = frame.exception;
                    frame.exception = 0;
                },

                // ── Returns ──────────────────────────────────────────────────
                .return_void => return .void_val,
                .return_ => |v| return .{ .int = @bitCast(@as(u32, @truncate(frame.regs[v.src]))) },
                .return_wide => |v| return .{ .long = @bitCast(frame.regs[v.src]) },
                .return_object => |v| return .{ .ref = frame.regs[v.src] },

                // ── Constants ────────────────────────────────────────────────
                .const_ => |v| frame.regs[v.dest] = @bitCast(@as(i64, v.value)),
                .const_wide => |v| {
                    frame.regs[v.dest] = @bitCast(v.value);
                },
                .const_string => |v| {
                    if (v.index < self.dex.string_pool.len) {
                        const str_slice = self.dex.string_pool[v.index];
                        const str_obj = runtime.gcAlloc(0, 24);
                        const layout = @as(*align(4) StringLayout, @ptrCast(@alignCast(str_obj)));
                        layout.value = str_slice.ptr;
                        layout.length = @intCast(str_slice.len);
                        frame.regs[v.dest] = @intFromPtr(str_obj);
                    } else {
                        frame.regs[v.dest] = 0;
                    }
                },
                .const_class => |v| {
                    frame.regs[v.dest] = v.type_idx; // placeholder class token
                },
                .const_method_handle => |v| {
                    frame.regs[v.dest] = v.index;
                },
                .const_method_type => |v| {
                    frame.regs[v.dest] = v.index;
                },

                // ── Monitors ─────────────────────────────────────────────────
                .monitor_enter => |v| {
                    const obj = frame.regs[v.src];
                    if (obj == 0) return InterpError.NullPointerException;
                    runtime.monitorEnter(@ptrFromInt(obj));
                },
                .monitor_exit => |v| {
                    const obj = frame.regs[v.src];
                    if (obj == 0) return InterpError.NullPointerException;
                    runtime.monitorExit(@ptrFromInt(obj));
                },

                // ── Checks ───────────────────────────────────────────────────
                .check_cast => {}, // TODO: instanceof check, throw ClassCastException
                .instance_of => |v| frame.regs[v.dest] = 1, // TODO: proper type check

                // ── Allocation ───────────────────────────────────────────────
                .new_instance => |v| {
                    const type_name = if (v.type_idx < self.dex.type_names.len)
                        self.dex.type_names[v.type_idx]
                    else
                        return InterpError.OutOfMemory;
                    const cd = self.registry.get(type_name) orelse {
                        // Unknown class: allocate a minimal object (16 bytes)
                        const obj = runtime.gcAlloc(0, 16);
                        frame.regs[v.dest] = @intFromPtr(obj);
                        continue;
                    };
                    const obj = runtime.gcAlloc(@intFromPtr(cd), cd.instance_size);
                    frame.regs[v.dest] = @intFromPtr(obj);
                },

                .new_array => |v| {
                    const size: i32 = @bitCast(@as(u32, @truncate(frame.regs[v.size])));
                    if (size < 0) return InterpError.NegativeArraySize;
                    const type_name = self.dex.type_names[v.type_idx];
                    var elem_size: usize = 4;
                    if (type_name.len > 1) {
                        const char = type_name[1];
                        elem_size = switch (char) {
                            'J', 'D' => 8,
                            'I', 'F' => 4,
                            'S', 'C' => 2,
                            'B', 'Z' => 1,
                            'L', '[' => 8,
                            else => 8,
                        };
                    }
                    const arr_size = @as(usize, @intCast(size)) * elem_size + 8; // 8 = len header
                    const arr = runtime.gcAlloc(0, arr_size);
                    // Store length in first 4 bytes of array body
                    @as(*i32, @ptrCast(@alignCast(arr))).* = size;
                    frame.regs[v.dest] = @intFromPtr(arr);
                },

                .array_length => |v| {
                    const arr = frame.regs[v.array];
                    if (arr == 0) return InterpError.NullPointerException;
                    const len = @as(*const i32, @ptrCast(@alignCast(@as(*anyopaque, @ptrFromInt(arr))))).*;
                    frame.regs[v.dest] = @bitCast(@as(i64, len));
                },

                // ── Array element access ─────────────────────────────────────
                .aget, .aget_boolean, .aget_byte, .aget_char, .aget_short => |v| {
                    const arr = frame.regs[v.array];
                    const idx: i32 = @bitCast(@as(u32, @truncate(frame.regs[v.index])));
                    if (arr == 0) return InterpError.NullPointerException;
                    const len = @as(*const i32, @ptrCast(@alignCast(@as(*anyopaque, @ptrFromInt(arr))))).*;
                    if (idx < 0 or idx >= len) return InterpError.ArrayIndexOutOfBounds;
                    const elem_ptr = arr + 8 + @as(usize, @intCast(idx)) * 4;
                    frame.regs[v.dest_or_src] = @as(u32, @bitCast(@as(*const i32, @ptrCast(@alignCast(@as(*anyopaque, @ptrFromInt(elem_ptr))))).*));
                },
                .aget_wide, .aget_object => |v| {
                    const arr = frame.regs[v.array];
                    const idx: i32 = @bitCast(@as(u32, @truncate(frame.regs[v.index])));
                    if (arr == 0) return InterpError.NullPointerException;
                    const len = @as(*const i32, @ptrCast(@alignCast(@as(*anyopaque, @ptrFromInt(arr))))).*;
                    if (idx < 0 or idx >= len) return InterpError.ArrayIndexOutOfBounds;
                    const elem_ptr = arr + 8 + @as(usize, @intCast(idx)) * 8;
                    frame.regs[v.dest_or_src] = @as(*align(4) const u64, @ptrCast(@alignCast(@as(*anyopaque, @ptrFromInt(elem_ptr))))).*;
                },
                .aput, .aput_boolean, .aput_byte, .aput_char, .aput_short => |v| {
                    const arr = frame.regs[v.array];
                    const idx: i32 = @bitCast(@as(u32, @truncate(frame.regs[v.index])));
                    if (arr == 0) return InterpError.NullPointerException;
                    const len = @as(*const i32, @ptrCast(@alignCast(@as(*anyopaque, @ptrFromInt(arr))))).*;
                    if (idx < 0 or idx >= len) return InterpError.ArrayIndexOutOfBounds;
                    const elem_ptr = arr + 8 + @as(usize, @intCast(idx)) * 4;
                    @as(*i32, @ptrCast(@alignCast(@as(*anyopaque, @ptrFromInt(elem_ptr))))).* = @bitCast(@as(u32, @truncate(frame.regs[v.dest_or_src])));
                },
                .aput_wide, .aput_object => |v| {
                    const arr = frame.regs[v.array];
                    const idx: i32 = @bitCast(@as(u32, @truncate(frame.regs[v.index])));
                    if (arr == 0) return InterpError.NullPointerException;
                    const len = @as(*const i32, @ptrCast(@alignCast(@as(*anyopaque, @ptrFromInt(arr))))).*;
                    if (idx < 0 or idx >= len) return InterpError.ArrayIndexOutOfBounds;
                    const elem_ptr = arr + 8 + @as(usize, @intCast(idx)) * 8;
                    @as(*align(4) u64, @ptrCast(@alignCast(@as(*anyopaque, @ptrFromInt(elem_ptr))))).* = frame.regs[v.dest_or_src];
                },

                // ── Instance fields ───────────────────────────────────────────
                .iget, .iget_boolean, .iget_byte, .iget_char, .iget_short => |v| {
                    const obj = frame.regs[v.obj];
                    if (obj == 0) return InterpError.NullPointerException;
                    const fi = if (v.field_idx < self.dex.field_items.len) self.dex.field_items[v.field_idx] else {
                        frame.regs[v.dest_or_src] = 0;
                        continue;
                    };
                    const cd = self.registry.get(fi.class_name) orelse {
                        frame.regs[v.dest_or_src] = 0;
                        continue;
                    };
                    const off = cd.fieldOffset(fi.field_name) orelse 0;
                    frame.regs[v.dest_or_src] = @as(u32, @bitCast(@as(*const i32, @ptrCast(@alignCast(@as(*anyopaque, @ptrFromInt(obj + off))))).*));
                },
                .iget_wide, .iget_object => |v| {
                    const obj = frame.regs[v.obj];
                    if (obj == 0) return InterpError.NullPointerException;
                    const fi = if (v.field_idx < self.dex.field_items.len) self.dex.field_items[v.field_idx] else {
                        frame.regs[v.dest_or_src] = 0;
                        continue;
                    };
                    const cd = self.registry.get(fi.class_name) orelse {
                        frame.regs[v.dest_or_src] = 0;
                        continue;
                    };
                    const off = cd.fieldOffset(fi.field_name) orelse 0;
                    frame.regs[v.dest_or_src] = @as(*align(4) const u64, @ptrCast(@alignCast(@as(*anyopaque, @ptrFromInt(obj + off))))).*;
                },
                .iput, .iput_boolean, .iput_byte, .iput_char, .iput_short => |v| {
                    const obj = frame.regs[v.obj];
                    if (obj == 0) return InterpError.NullPointerException;
                    const fi = if (v.field_idx < self.dex.field_items.len) self.dex.field_items[v.field_idx] else continue;
                    const cd = self.registry.get(fi.class_name) orelse continue;
                    const off = cd.fieldOffset(fi.field_name) orelse 0;
                    @as(*i32, @ptrCast(@alignCast(@as(*anyopaque, @ptrFromInt(obj + off))))).* = @bitCast(@as(u32, @truncate(frame.regs[v.dest_or_src])));
                },
                .iput_wide, .iput_object => |v| {
                    const obj = frame.regs[v.obj];
                    if (obj == 0) return InterpError.NullPointerException;
                    const fi = if (v.field_idx < self.dex.field_items.len) self.dex.field_items[v.field_idx] else continue;
                    const cd = self.registry.get(fi.class_name) orelse continue;
                    const off = cd.fieldOffset(fi.field_name) orelse 0;
                    @as(*align(4) u64, @ptrCast(@alignCast(@as(*anyopaque, @ptrFromInt(obj + off))))).* = frame.regs[v.dest_or_src];
                },

                // ── Static fields ─────────────────────────────────────────────
                .sget, .sget_boolean, .sget_byte, .sget_char, .sget_short, .sget_wide, .sget_object => |v| {
                    const fi = if (v.field_idx < self.dex.field_items.len) self.dex.field_items[v.field_idx] else {
                        frame.regs[v.dest_or_src] = 0;
                        continue;
                    };
                    if (self.registry.get(fi.class_name)) |cd| {
                        if (cd.staticSlot(fi.field_name)) |slot| {
                            const val: u64 = switch (slot.*) {
                                .int => |i| @bitCast(@as(i64, i)),
                                .long => |l| @bitCast(l),
                                .float => |f| @bitCast(@as(i64, @bitCast(@as(f64, f)))),
                                .double => |d| @bitCast(d),
                                .boolean => |b| if (b) @as(u64, 1) else 0,
                                .byte => |by| @bitCast(@as(i64, by)),
                                .short => |s| @bitCast(@as(i64, s)),
                                .char => |ch| @as(u64, ch),
                                .reference => |r| r,
                            };
                            frame.regs[v.dest_or_src] = val;
                            continue;
                        }
                    }
                    frame.regs[v.dest_or_src] = 0;
                },
                .sput, .sput_boolean, .sput_byte, .sput_char, .sput_short, .sput_wide, .sput_object => |v| {
                    const fi = if (v.field_idx < self.dex.field_items.len) self.dex.field_items[v.field_idx] else continue;
                    if (self.registry.get(fi.class_name)) |cd| {
                        if (cd.staticSlot(fi.field_name)) |slot| {
                            const val = frame.regs[v.dest_or_src];
                            slot.* = switch (inst) {
                                .sput_wide => .{ .long = @bitCast(val) },
                                .sput_object => .{ .reference = val },
                                .sput_boolean => .{ .boolean = (val & 1) != 0 },
                                .sput_byte => .{ .byte = @intCast(@as(i8, @bitCast(@as(u8, @truncate(val))))) },
                                .sput_char => .{ .char = @truncate(val) },
                                .sput_short => .{ .short = @intCast(@as(i16, @bitCast(@as(u16, @truncate(val))))) },
                                else => .{ .int = @intCast(@as(i32, @bitCast(@as(u32, @truncate(val))))) },
                            };
                        }
                    }
                },

                // ── Control flow ─────────────────────────────────────────────
                .goto_ => |v| {
                    const new_pc: i64 = @as(i64, frame.pc) - 1 + v.offset;
                    frame.pc = @intCast(new_pc);
                },
                .if_eq => |v| {
                    if (frame.regs[v.src1] == frame.regs[v.src2]) frame.pc = @intCast(@as(i64, frame.pc) - 1 + v.offset);
                },
                .if_ne => |v| {
                    if (frame.regs[v.src1] != frame.regs[v.src2]) frame.pc = @intCast(@as(i64, frame.pc) - 1 + v.offset);
                },
                .if_lt => |v| {
                    if (@as(i32, @bitCast(@as(u32, @truncate(frame.regs[v.src1])))) < @as(i32, @bitCast(@as(u32, @truncate(frame.regs[v.src2]))))) frame.pc = @intCast(@as(i64, frame.pc) - 1 + v.offset);
                },
                .if_ge => |v| {
                    if (@as(i32, @bitCast(@as(u32, @truncate(frame.regs[v.src1])))) >= @as(i32, @bitCast(@as(u32, @truncate(frame.regs[v.src2]))))) frame.pc = @intCast(@as(i64, frame.pc) - 1 + v.offset);
                },
                .if_gt => |v| {
                    if (@as(i32, @bitCast(@as(u32, @truncate(frame.regs[v.src1])))) > @as(i32, @bitCast(@as(u32, @truncate(frame.regs[v.src2]))))) frame.pc = @intCast(@as(i64, frame.pc) - 1 + v.offset);
                },
                .if_le => |v| {
                    if (@as(i32, @bitCast(@as(u32, @truncate(frame.regs[v.src1])))) <= @as(i32, @bitCast(@as(u32, @truncate(frame.regs[v.src2]))))) frame.pc = @intCast(@as(i64, frame.pc) - 1 + v.offset);
                },
                .if_eqz => |v| {
                    if (frame.regs[v.src] == 0) frame.pc = @intCast(@as(i64, frame.pc) - 1 + v.offset);
                },
                .if_nez => |v| {
                    if (frame.regs[v.src] != 0) frame.pc = @intCast(@as(i64, frame.pc) - 1 + v.offset);
                },
                .if_ltz => |v| {
                    if (@as(i32, @bitCast(@as(u32, @truncate(frame.regs[v.src])))) < 0) frame.pc = @intCast(@as(i64, frame.pc) - 1 + v.offset);
                },
                .if_gez => |v| {
                    if (@as(i32, @bitCast(@as(u32, @truncate(frame.regs[v.src])))) >= 0) frame.pc = @intCast(@as(i64, frame.pc) - 1 + v.offset);
                },
                .if_gtz => |v| {
                    if (@as(i32, @bitCast(@as(u32, @truncate(frame.regs[v.src])))) > 0) frame.pc = @intCast(@as(i64, frame.pc) - 1 + v.offset);
                },
                .if_lez => |v| {
                    if (@as(i32, @bitCast(@as(u32, @truncate(frame.regs[v.src])))) <= 0) frame.pc = @intCast(@as(i64, frame.pc) - 1 + v.offset);
                },

                // ── Switches ──────────────────────────────────────────────────
                .packed_switch, .sparse_switch => |v| {
                    const key: i32 = @bitCast(@as(u32, @truncate(frame.regs[v.src])));
                    for (v.keys, 0..) |k, i| {
                        if (k == key and i < v.targets.len) {
                            frame.pc = @intCast(@as(i64, frame.pc) - 1 + v.targets[i]);
                            break;
                        }
                    }
                },

                // ── Integer arithmetic ────────────────────────────────────────
                .add_int => |v| frame.regs[v.dest] = i32Add(frame.regs[v.src1], frame.regs[v.src2]),
                .sub_int => |v| frame.regs[v.dest] = i32Sub(frame.regs[v.src1], frame.regs[v.src2]),
                .mul_int => |v| frame.regs[v.dest] = i32Mul(frame.regs[v.src1], frame.regs[v.src2]),
                .div_int => |v| {
                    const b: i32 = @bitCast(@as(u32, @truncate(frame.regs[v.src2])));
                    if (b == 0) return InterpError.ArithmeticException;
                    frame.regs[v.dest] = i32Div(frame.regs[v.src1], frame.regs[v.src2]);
                },
                .rem_int => |v| {
                    const b: i32 = @bitCast(@as(u32, @truncate(frame.regs[v.src2])));
                    if (b == 0) return InterpError.ArithmeticException;
                    frame.regs[v.dest] = i32Rem(frame.regs[v.src1], frame.regs[v.src2]);
                },
                .and_int => |v| frame.regs[v.dest] = frame.regs[v.src1] & frame.regs[v.src2],
                .or_int => |v| frame.regs[v.dest] = frame.regs[v.src1] | frame.regs[v.src2],
                .xor_int => |v| frame.regs[v.dest] = frame.regs[v.src1] ^ frame.regs[v.src2],
                .shl_int => |v| {
                    const a: i32 = @bitCast(@as(u32, @truncate(frame.regs[v.src1])));
                    const sh: u5 = @truncate(@as(u32, @truncate(frame.regs[v.src2])));
                    frame.regs[v.dest] = @bitCast(@as(i64, a << sh));
                },
                .shr_int => |v| {
                    const a: i32 = @bitCast(@as(u32, @truncate(frame.regs[v.src1])));
                    const sh: u5 = @truncate(@as(u32, @truncate(frame.regs[v.src2])));
                    frame.regs[v.dest] = @bitCast(@as(i64, a >> sh));
                },
                .ushr_int => |v| {
                    const a: u32 = @truncate(frame.regs[v.src1]);
                    const sh: u5 = @truncate(@as(u32, @truncate(frame.regs[v.src2])));
                    frame.regs[v.dest] = a >> sh;
                },

                // ── Long arithmetic ───────────────────────────────────────────
                .add_long => |v| {
                    const r: i64 = @as(i64, @bitCast(frame.regs[v.src1])) +% @as(i64, @bitCast(frame.regs[v.src2]));
                    frame.regs[v.dest] = @bitCast(r);
                },
                .sub_long => |v| {
                    const r: i64 = @as(i64, @bitCast(frame.regs[v.src1])) -% @as(i64, @bitCast(frame.regs[v.src2]));
                    frame.regs[v.dest] = @bitCast(r);
                },
                .mul_long => |v| {
                    const r: i64 = @as(i64, @bitCast(frame.regs[v.src1])) *% @as(i64, @bitCast(frame.regs[v.src2]));
                    frame.regs[v.dest] = @bitCast(r);
                },
                .div_long => |v| {
                    const b: i64 = @bitCast(frame.regs[v.src2]);
                    if (b == 0) return InterpError.ArithmeticException;
                    frame.regs[v.dest] = @bitCast(@divTrunc(@as(i64, @bitCast(frame.regs[v.src1])), b));
                },
                .rem_long => |v| {
                    const b: i64 = @bitCast(frame.regs[v.src2]);
                    if (b == 0) return InterpError.ArithmeticException;
                    frame.regs[v.dest] = @bitCast(@rem(@as(i64, @bitCast(frame.regs[v.src1])), b));
                },
                .and_long => |v| frame.regs[v.dest] = frame.regs[v.src1] & frame.regs[v.src2],
                .or_long => |v| frame.regs[v.dest] = frame.regs[v.src1] | frame.regs[v.src2],
                .xor_long => |v| frame.regs[v.dest] = frame.regs[v.src1] ^ frame.regs[v.src2],
                .shl_long => |v| {
                    const sh: u6 = @truncate(frame.regs[v.src2]);
                    frame.regs[v.dest] = @bitCast(@as(i64, @bitCast(frame.regs[v.src1])) << sh);
                },
                .shr_long => |v| {
                    const sh: u6 = @truncate(frame.regs[v.src2]);
                    frame.regs[v.dest] = @bitCast(@as(i64, @bitCast(frame.regs[v.src1])) >> sh);
                },
                .ushr_long => |v| {
                    const sh: u6 = @truncate(frame.regs[v.src2]);
                    frame.regs[v.dest] = frame.regs[v.src1] >> sh;
                },

                // ── Float arithmetic ──────────────────────────────────────────
                .add_float => |v| {
                    const r: f32 = f32Reg(frame.regs[v.src1]) + f32Reg(frame.regs[v.src2]);
                    frame.regs[v.dest] = @as(u32, @bitCast(r));
                },
                .sub_float => |v| {
                    const r: f32 = f32Reg(frame.regs[v.src1]) - f32Reg(frame.regs[v.src2]);
                    frame.regs[v.dest] = @as(u32, @bitCast(r));
                },
                .mul_float => |v| {
                    const r: f32 = f32Reg(frame.regs[v.src1]) * f32Reg(frame.regs[v.src2]);
                    frame.regs[v.dest] = @as(u32, @bitCast(r));
                },
                .div_float => |v| {
                    const r: f32 = f32Reg(frame.regs[v.src1]) / f32Reg(frame.regs[v.src2]);
                    frame.regs[v.dest] = @as(u32, @bitCast(r));
                },
                .rem_float => |v| {
                    const r: f32 = @mod(f32Reg(frame.regs[v.src1]), f32Reg(frame.regs[v.src2]));
                    frame.regs[v.dest] = @as(u32, @bitCast(r));
                },

                // ── Double arithmetic ─────────────────────────────────────────
                .add_double => |v| {
                    const r: f64 = f64Reg(frame.regs[v.src1]) + f64Reg(frame.regs[v.src2]);
                    frame.regs[v.dest] = @bitCast(r);
                },
                .sub_double => |v| {
                    const r: f64 = f64Reg(frame.regs[v.src1]) - f64Reg(frame.regs[v.src2]);
                    frame.regs[v.dest] = @bitCast(r);
                },
                .mul_double => |v| {
                    const r: f64 = f64Reg(frame.regs[v.src1]) * f64Reg(frame.regs[v.src2]);
                    frame.regs[v.dest] = @bitCast(r);
                },
                .div_double => |v| {
                    const r: f64 = f64Reg(frame.regs[v.src1]) / f64Reg(frame.regs[v.src2]);
                    frame.regs[v.dest] = @bitCast(r);
                },
                .rem_double => |v| {
                    const r: f64 = @mod(f64Reg(frame.regs[v.src1]), f64Reg(frame.regs[v.src2]));
                    frame.regs[v.dest] = @bitCast(r);
                },

                // ── Lit ops ───────────────────────────────────────────────────
                .add_int_lit8 => |v| frame.regs[v.dest] = i32Add(frame.regs[v.src], @bitCast(@as(i64, v.lit))),
                .rsub_int_lit8 => |v| frame.regs[v.dest] = i32Sub(@bitCast(@as(i64, v.lit)), frame.regs[v.src]),
                .mul_int_lit8 => |v| frame.regs[v.dest] = i32Mul(frame.regs[v.src], @bitCast(@as(i64, v.lit))),
                .div_int_lit8 => |v| {
                    if (v.lit == 0) return InterpError.ArithmeticException;
                    frame.regs[v.dest] = i32Div(frame.regs[v.src], @bitCast(@as(i64, v.lit)));
                },
                .rem_int_lit8 => |v| {
                    if (v.lit == 0) return InterpError.ArithmeticException;
                    frame.regs[v.dest] = i32Rem(frame.regs[v.src], @bitCast(@as(i64, v.lit)));
                },
                .and_int_lit8 => |v| frame.regs[v.dest] = frame.regs[v.src] & @as(u64, @bitCast(@as(i64, v.lit))),
                .or_int_lit8 => |v| frame.regs[v.dest] = frame.regs[v.src] | @as(u64, @bitCast(@as(i64, v.lit))),
                .xor_int_lit8 => |v| frame.regs[v.dest] = frame.regs[v.src] ^ @as(u64, @bitCast(@as(i64, v.lit))),
                .shl_int_lit8 => |v| {
                    const sh: u5 = @intCast(v.lit & 0x1F);
                    frame.regs[v.dest] = @bitCast(@as(i64, @as(i32, @bitCast(@as(u32, @truncate(frame.regs[v.src])))) << sh));
                },
                .shr_int_lit8 => |v| {
                    const sh: u5 = @intCast(v.lit & 0x1F);
                    frame.regs[v.dest] = @bitCast(@as(i64, @as(i32, @bitCast(@as(u32, @truncate(frame.regs[v.src])))) >> sh));
                },
                .ushr_int_lit8 => |v| {
                    const sh: u5 = @intCast(v.lit & 0x1F);
                    frame.regs[v.dest] = @as(u32, @truncate(frame.regs[v.src])) >> sh;
                },

                .add_int_lit16, .rsub_int_lit16, .mul_int_lit16, .div_int_lit16, .rem_int_lit16, .and_int_lit16, .or_int_lit16, .xor_int_lit16 => |v| {
                    const lit: i64 = v.lit;
                    frame.regs[v.dest] = switch (inst) {
                        .add_int_lit16 => i32Add(frame.regs[v.src], @bitCast(lit)),
                        .rsub_int_lit16 => i32Sub(@bitCast(lit), frame.regs[v.src]),
                        .mul_int_lit16 => i32Mul(frame.regs[v.src], @bitCast(lit)),
                        .div_int_lit16 => if (v.lit == 0) return InterpError.ArithmeticException else i32Div(frame.regs[v.src], @bitCast(lit)),
                        .rem_int_lit16 => if (v.lit == 0) return InterpError.ArithmeticException else i32Rem(frame.regs[v.src], @bitCast(lit)),
                        .and_int_lit16 => frame.regs[v.src] & @as(u64, @bitCast(lit)),
                        .or_int_lit16 => frame.regs[v.src] | @as(u64, @bitCast(lit)),
                        .xor_int_lit16 => frame.regs[v.src] ^ @as(u64, @bitCast(lit)),
                        else => unreachable,
                    };
                },

                // ── Unary / Conversions ───────────────────────────────────────
                .neg_int => |v| {
                    const a: i32 = @bitCast(@as(u32, @truncate(frame.regs[v.src])));
                    frame.regs[v.dest] = @bitCast(@as(i64, -a));
                },
                .not_int => |v| {
                    const a: u32 = @truncate(frame.regs[v.src]);
                    frame.regs[v.dest] = ~a;
                },
                .neg_long => |v| {
                    const a: i64 = @bitCast(frame.regs[v.src]);
                    frame.regs[v.dest] = @bitCast(-a);
                },
                .not_long => |v| frame.regs[v.dest] = ~frame.regs[v.src],
                .neg_float => |v| {
                    const a: f32 = f32Reg(frame.regs[v.src]);
                    frame.regs[v.dest] = @as(u32, @bitCast(-a));
                },
                .neg_double => |v| {
                    const a: f64 = f64Reg(frame.regs[v.src]);
                    frame.regs[v.dest] = @bitCast(-a);
                },
                .int_to_long => |v| {
                    const a: i32 = @bitCast(@as(u32, @truncate(frame.regs[v.src])));
                    frame.regs[v.dest] = @bitCast(@as(i64, a));
                },
                .int_to_float => |v| {
                    const a: i32 = @bitCast(@as(u32, @truncate(frame.regs[v.src])));
                    frame.regs[v.dest] = @as(u32, @bitCast(@as(f32, @floatFromInt(a))));
                },
                .int_to_double => |v| {
                    const a: i32 = @bitCast(@as(u32, @truncate(frame.regs[v.src])));
                    frame.regs[v.dest] = @bitCast(@as(f64, @floatFromInt(a)));
                },
                .long_to_int => |v| frame.regs[v.dest] = @as(u32, @truncate(frame.regs[v.src])),
                .long_to_float => |v| {
                    const a: i64 = @bitCast(frame.regs[v.src]);
                    frame.regs[v.dest] = @as(u32, @bitCast(@as(f32, @floatFromInt(a))));
                },
                .long_to_double => |v| {
                    const a: i64 = @bitCast(frame.regs[v.src]);
                    frame.regs[v.dest] = @bitCast(@as(f64, @floatFromInt(a)));
                },
                .float_to_int => |v| {
                    const a: f32 = f32Reg(frame.regs[v.src]);
                    frame.regs[v.dest] = @bitCast(@as(i64, @intFromFloat(a)));
                },
                .float_to_long => |v| {
                    const a: f32 = f32Reg(frame.regs[v.src]);
                    frame.regs[v.dest] = @bitCast(@as(i64, @intFromFloat(a)));
                },
                .float_to_double => |v| {
                    const a: f32 = f32Reg(frame.regs[v.src]);
                    frame.regs[v.dest] = @bitCast(@as(f64, a));
                },
                .double_to_int => |v| {
                    const a: f64 = f64Reg(frame.regs[v.src]);
                    frame.regs[v.dest] = @bitCast(@as(i64, @intFromFloat(a)));
                },
                .double_to_long => |v| {
                    const a: f64 = f64Reg(frame.regs[v.src]);
                    frame.regs[v.dest] = @bitCast(@as(i64, @intFromFloat(a)));
                },
                .double_to_float => |v| {
                    const a: f64 = f64Reg(frame.regs[v.src]);
                    frame.regs[v.dest] = @as(u32, @bitCast(@as(f32, @floatCast(a))));
                },
                .int_to_byte => |v| {
                    const a: i32 = @bitCast(@as(u32, @truncate(frame.regs[v.src])));
                    frame.regs[v.dest] = @bitCast(@as(i64, @as(i8, @truncate(a))));
                },
                .int_to_char => |v| frame.regs[v.dest] = frame.regs[v.src] & 0xFFFF,
                .int_to_short => |v| {
                    const a: i32 = @bitCast(@as(u32, @truncate(frame.regs[v.src])));
                    frame.regs[v.dest] = @bitCast(@as(i64, @as(i16, @truncate(a))));
                },

                // ── Float comparisons ─────────────────────────────────────────
                .cmpl_float, .cmpg_float => |v| {
                    const a = f32Reg(frame.regs[v.src1]);
                    const b = f32Reg(frame.regs[v.src2]);
                    const nan_val: i32 = if (@tagName(inst)[0] == 'c' and inst == .cmpl_float) -1 else 1;
                    const r: i32 = if (std.math.isNan(a) or std.math.isNan(b)) nan_val else if (a < b) -1 else if (a > b) 1 else 0;
                    frame.regs[v.dest] = @bitCast(@as(i64, r));
                },
                .cmpl_double, .cmpg_double => |v| {
                    const a = f64Reg(frame.regs[v.src1]);
                    const b = f64Reg(frame.regs[v.src2]);
                    const nan_val: i32 = if (inst == .cmpl_double) -1 else 1;
                    const r: i32 = if (std.math.isNan(a) or std.math.isNan(b)) nan_val else if (a < b) -1 else if (a > b) 1 else 0;
                    frame.regs[v.dest] = @bitCast(@as(i64, r));
                },
                .cmp_long => |v| {
                    const a: i64 = @bitCast(frame.regs[v.src1]);
                    const b: i64 = @bitCast(frame.regs[v.src2]);
                    frame.regs[v.dest] = @bitCast(@as(i64, if (a < b) -1 else if (a > b) 1 else 0));
                },

                // ── Invocations ───────────────────────────────────────────────
                .invoke => |inv| {
                    const result = try self.dispatchInvoke(frame, inv);
                    switch (result) {
                        .void_val => frame.result = 0,
                        .int => |i| frame.result = @bitCast(@as(i64, i)),
                        .long => |l| frame.result = @bitCast(l),
                        .float => |f| frame.result = @as(u32, @bitCast(f)),
                        .double => |d| frame.result = @bitCast(d),
                        .ref => |r| frame.result = r,
                    }
                    frame.result_tag = switch (result) {
                        .void_val => .void_val,
                        .int => .int,
                        .long => .long,
                        .float => .float,
                        .double => .double,
                        .ref => .ref,
                    };
                },

                // ── Throw ─────────────────────────────────────────────────────
                .throw_ => |v| {
                    const ex = frame.regs[v.src];
                    if (ex == 0) return InterpError.NullPointerException;
                    frame.exception = ex;
                    // Walk exception table
                    const handler_pc = findHandlerAtPc(frame.method.tries, frame.pc - 1);
                    if (handler_pc) |hpc| {
                        frame.pc = hpc;
                    } else {
                        return InterpError.UncaughtException;
                    }
                },

                // ── fill-array-data ───────────────────────────────────────────
                .fill_array_data => |v| {
                    const arr = frame.regs[v.array];
                    if (arr == 0) return InterpError.NullPointerException;
                    for (v.data, 0..) |elem, i| {
                        const ep = arr + 8 + i * 4;
                        @as(*i32, @ptrCast(@alignCast(@as(*anyopaque, @ptrFromInt(ep))))).* = @truncate(elem);
                    }
                },
                .filled_new_array => |v| {
                    const type_name = self.dex.type_names[v.type_idx];
                    const is_32bit = if (type_name.len > 1 and type_name[0] == '[') blk: {
                        const elem_char = type_name[1];
                        break :blk (elem_char == 'I' or elem_char == 'F' or elem_char == 'Z' or elem_char == 'B' or elem_char == 'C' or elem_char == 'S');
                    } else false;

                    const stride: usize = if (is_32bit) 4 else 8;
                    const arr_size = v.args.len * stride + 8;
                    const arr = runtime.gcAlloc(0, arr_size);
                    @as(*i32, @ptrCast(@alignCast(arr))).* = @intCast(v.args.len);
                    for (v.args, 0..) |reg, i| {
                        if (is_32bit) {
                            const ep = @intFromPtr(arr) + 8 + i * 4;
                            @as(*align(4) u32, @ptrCast(@alignCast(@as(*anyopaque, @ptrFromInt(ep))))).* = @as(u32, @truncate(frame.regs[reg]));
                        } else {
                            const ep = @intFromPtr(arr) + 8 + i * 8;
                            @as(*align(4) u64, @ptrCast(@alignCast(@as(*anyopaque, @ptrFromInt(ep))))).* = frame.regs[reg];
                        }
                    }
                    frame.result = @intFromPtr(arr);
                },
            }
        }
    }

    // ── Invoke dispatch ───────────────────────────────────────────────────────

    fn callJitCode(entry: usize, args: []const u64) u64 {
        var rcx: u64 = 0;
        var rdx: u64 = 0;
        var r8: u64 = 0;
        var r9: u64 = 0;
        if (args.len > 0) rcx = args[0];
        if (args.len > 1) rdx = args[1];
        if (args.len > 2) r8 = args[2];
        if (args.len > 3) r9 = args[3];

        var result: u64 = undefined;
        asm volatile (
            \\subq $32, %%rsp
            \\callq *%[entry]
            \\addq $32, %%rsp
            : [ret] "={rax}" (result),
            : [entry] "r" (entry),
              [rcx] "{rcx}" (rcx),
              [rdx] "{rdx}" (rdx),
              [r8] "{r8}" (r8),
              [r9] "{r9}" (r9),
            : @import("std").builtin.assembly.Clobbers{ .memory = true });
        return result;
    }

    fn dispatchInvoke(self: *Interpreter, frame: *Frame, inv: *const Invoke) InterpError!Value {
        // Collect argument values from the caller's register file
        var arg_buf: [MAX_REGS]u64 = undefined;
        for (inv.args, 0..) |reg, i| arg_buf[i] = frame.regs[reg];
        const args = arg_buf[0..inv.args.len];

        // Look up the method in the ClassRegistry
        const method = self.resolveMethod(inv) orelse {
            // Unknown method: return void (graceful degradation for stdlib stubs)
            std.log.warn("interpreter: unresolved method {s}.{s}{s}", .{
                inv.class_name, inv.method_name, inv.signature,
            });
            return .void_val;
        };

        // If the method already has JIT-compiled code, jump into it
        if (method.jitEntry()) |entry| {
            var exception_out: c_int = 0;
            const a0 = if (args.len > 0) args[0] else 0;
            const a1 = if (args.len > 1) args[1] else 0;
            const a2 = if (args.len > 2) args[2] else 0;
            const a3 = if (args.len > 3) args[3] else 0;
            const raw_res = jit_guarded_call(entry, a0, a1, a2, a3, &exception_out);
            if (exception_out != 0) {
                // Exception was thrown from JIT code of the callee!
                const handler_pc = findHandlerAny(method.tries);
                if (handler_pc) |hpc| {
                    var callee_frame = Frame.init(method);
                    const num_regs = method.registers_size;
                    const num_args = method.ins_size;
                    const start_reg = num_regs - num_args;
                    for (args, 0..) |arg, i| {
                        if (i < num_args) {
                            callee_frame.regs[start_reg + i] = arg;
                        }
                    }
                    callee_frame.pc = hpc;
                    callee_frame.exception = 0xDEADBEEF;
                    const instrs = try self.decodeMethod(method);
                    defer self.allocator.free(instrs);
                    const val = try self.runFrame(&callee_frame, instrs);

                    if (method.signature[0] == 'V') {
                        return .void_val;
                    } else if (method.signature[0] == 'Z') {
                        return .{ .int = @as(i32, @intCast(val.int & 1)) };
                    } else if (method.signature[0] == 'I' or method.signature[0] == 'C' or method.signature[0] == 'B' or method.signature[0] == 'S') {
                        return .{ .int = val.int };
                    } else if (method.signature[0] == 'L' or method.signature[0] == '[') {
                        return .{ .ref = val.ref };
                    } else {
                        return .{ .long = val.long };
                    }
                } else {
                    // No handler in callee; propagate exception to caller frame
                    frame.exception = 0xDEADBEEF;
                    const caller_handler_pc = findHandler(frame.method.tries, frame.pc -| 1, 0xFFFF_FFFF);
                    if (caller_handler_pc) |chpc| {
                        frame.pc = chpc;
                        return .void_val;
                    } else {
                        return InterpError.UncaughtException;
                    }
                }
            }
            if (method.signature[0] == 'V') {
                return .void_val;
            } else if (method.signature[0] == 'Z') {
                return .{ .int = @as(i32, @intCast(raw_res & 1)) };
            } else if (method.signature[0] == 'I' or method.signature[0] == 'C' or method.signature[0] == 'B' or method.signature[0] == 'S') {
                return .{ .int = @as(i32, @bitCast(@as(u32, @truncate(raw_res)))) };
            } else if (method.signature[0] == 'L' or method.signature[0] == '[') {
                return .{ .ref = @intCast(raw_res) };
            } else {
                return .{ .long = @bitCast(raw_res) };
            }
        }

        return self.invoke(method, args);
    }

    fn resolveMethod(self: *Interpreter, inv: *const Invoke) ?*MethodData {
        const cd = self.registry.get(inv.class_name) orelse return null;
        return cd.findMethod(inv.method_name, inv.signature);
    }
};

// ── Exception table search ────────────────────────────────────────────────────

fn findHandler(tries: []const TryBlock, pc: u32, type_idx: u32) ?u32 {
    for (tries) |tb| {
        if (pc < tb.start_pc or pc >= tb.end_pc) continue;
        for (tb.handlers) |h| {
            if (h.type_idx == null or h.type_idx == type_idx) return h.target_pc;
        }
    }
    return null;
}

fn findHandlerAny(tries: []const TryBlock) ?u32 {
    for (tries) |tb| {
        for (tb.handlers) |h| {
            return h.target_pc;
        }
    }
    return null;
}

fn findHandlerAtPc(tries: []const TryBlock, pc: u32) ?u32 {
    for (tries) |tb| {
        if (pc < tb.start_pc or pc >= tb.end_pc) continue;
        for (tb.handlers) |h| {
            return h.target_pc;
        }
    }
    return null;
}

// ── Register helpers ──────────────────────────────────────────────────────────

inline fn f32Reg(raw: u64) f32 {
    return @bitCast(@as(u32, @truncate(raw)));
}
inline fn f64Reg(raw: u64) f64 {
    return @bitCast(raw);
}

inline fn i32Add(a: u64, b: u64) u64 {
    const r: i32 = @as(i32, @bitCast(@as(u32, @truncate(a)))) +% @as(i32, @bitCast(@as(u32, @truncate(b))));
    return @bitCast(@as(i64, r));
}
inline fn i32Sub(a: u64, b: u64) u64 {
    const r: i32 = @as(i32, @bitCast(@as(u32, @truncate(a)))) -% @as(i32, @bitCast(@as(u32, @truncate(b))));
    return @bitCast(@as(i64, r));
}
inline fn i32Mul(a: u64, b: u64) u64 {
    const r: i32 = @as(i32, @bitCast(@as(u32, @truncate(a)))) *% @as(i32, @bitCast(@as(u32, @truncate(b))));
    return @bitCast(@as(i64, r));
}
inline fn i32Div(a: u64, b: u64) u64 {
    const r: i32 = @divTrunc(@as(i32, @bitCast(@as(u32, @truncate(a)))), @as(i32, @bitCast(@as(u32, @truncate(b)))));
    return @bitCast(@as(i64, r));
}
inline fn i32Rem(a: u64, b: u64) u64 {
    const r: i32 = @rem(@as(i32, @bitCast(@as(u32, @truncate(a)))), @as(i32, @bitCast(@as(u32, @truncate(b)))));
    return @bitCast(@as(i64, r));
}
