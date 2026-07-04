const std = @import("std");
const instmod = @import("instruction");
const ir = @import("ir");
const cfgmod = @import("cfg");

// Helper to quickly create an unversioned SSA variable
inline fn ssa(reg: u16) ir.SSAVar {
    return .{ .reg = reg, .version = 0 };
}

/// Translates raw Dalvik instructions into the 3-Address Code IR.
/// Populates the `instructions` array for every block in the CFG.
pub fn translateCFG(
    allocator: std.mem.Allocator,
    cfg: *cfgmod.CFG,
    dalvik_insts: []const instmod.Instruction,
) !void {
    // We need a quick way to resolve Dalvik branch offsets to Block IDs.
    // We can reuse the `start_to_id` map concept from the CFG builder.
    var start_to_id = std.AutoHashMap(usize, usize).init(allocator);
    defer start_to_id.deinit();
    for (cfg.blocks.items) |b| try start_to_id.put(b.start_idx, b.id);

    const resolveBlockId = struct {
        fn f(map: *std.AutoHashMap(usize, usize), base: usize, offset: i32) usize {
            const target_idx: usize = @intCast(@as(i64, @intCast(base)) + offset);
            return map.get(target_idx) orelse unreachable; // CFG builder already validated these
        }
    }.f;

    for (cfg.blocks.items) |*block| {
        // Initialize the IR instructions list for this block
        block.instructions = std.ArrayListUnmanaged(ir.IRInst).empty;

        for (block.start_idx..block.end_idx + 1) |inst_idx| {
            const d_inst = dalvik_insts[inst_idx];

            const ir_inst: ?ir.IRInst = switch (d_inst) {
                // --- Base & Moves ---
                .nop => null,
                .move => |v| .{ .move = .{ .dest = ssa(v.dest), .src = ssa(v.src) } },
                .move_wide => |v| .{ .move = .{ .dest = ssa(v.dest), .src = ssa(v.src) } },
                .move_object => |v| .{ .move = .{ .dest = ssa(v.dest), .src = ssa(v.src) } },
                
                .move_result => |v| blk: {
                    if (block.instructions.items.len > 0) {
                        var last_inst = &block.instructions.items[block.instructions.items.len - 1];
                        if (last_inst.* == .invoke) {
                            last_inst.invoke.dest = ssa(v.dest);
                            break :blk null;
                        }
                    }
                    break :blk .{ .move = .{ .dest = ssa(v.dest), .src = ssa(0) } };
                },
                .move_result_wide => |v| blk: {
                    if (block.instructions.items.len > 0) {
                        var last_inst = &block.instructions.items[block.instructions.items.len - 1];
                        if (last_inst.* == .invoke) {
                            last_inst.invoke.dest = ssa(v.dest);
                            break :blk null;
                        }
                    }
                    break :blk .{ .move = .{ .dest = ssa(v.dest), .src = ssa(0) } };
                },
                .move_result_object => |v| blk: {
                    if (block.instructions.items.len > 0) {
                        var last_inst = &block.instructions.items[block.instructions.items.len - 1];
                        if (last_inst.* == .invoke) {
                            last_inst.invoke.dest = ssa(v.dest);
                            break :blk null;
                        }
                    }
                    break :blk .{ .move = .{ .dest = ssa(v.dest), .src = ssa(0) } };
                },
                .move_exception => |v| .{ .move = .{ .dest = ssa(v.dest), .src = ssa(0) } },

                // --- Returns ---
                .return_void => .{ .ret = .{ .src = null } },
                .return_ => |v| .{ .ret = .{ .src = ssa(v.src) } },
                .return_wide => |v| .{ .ret = .{ .src = ssa(v.src) } },
                .return_object => |v| .{ .ret = .{ .src = ssa(v.src) } },

                // --- Constants ---
                .const_ => |v| .{ .const_int = .{ .dest = ssa(v.dest), .val = v.value } },
                .const_wide => |v| .{ .const_wide = .{ .dest = ssa(v.dest), .val = v.value } },
                .const_string => |v| .{ .const_string = .{ .dest = ssa(v.dest), .str_idx = v.index } },
                .const_class => |v| .{ .const_class = .{ .dest = ssa(v.dest), .type_idx = v.type_idx } },
                .const_method_handle => |v| .{ .const_int = .{ .dest = ssa(v.dest), .val = @intCast(v.index) } },
                .const_method_type => |v| .{ .const_int = .{ .dest = ssa(v.dest), .val = @intCast(v.index) } },

                // --- Monitors ---
                .monitor_enter, .monitor_exit => null,

                // --- Checks & Casts ---
                .check_cast => |v| .{ .move = .{ .dest = ssa(v.src), .src = ssa(v.src) } },
                .instance_of => |v| .{ .const_int = .{ .dest = ssa(v.dest), .val = 1 } },

                // --- Allocation & Arrays ---
                .array_length => |v| .{ .move = .{ .dest = ssa(v.dest), .src = ssa(v.array) } },
                .new_instance => |v| .{ .new_instance = .{ .dest = ssa(v.dest), .type_idx = v.type_idx } },
                .new_array => |v| .{ .new_array = .{ .dest = ssa(v.dest), .size = ssa(v.size), .type_idx = v.type_idx } },
                .filled_new_array => |v| .{ .new_instance = .{ .dest = ssa(0), .type_idx = v.type_idx } },
                .fill_array_data => null,

                // --- Exceptions ---
                .throw_ => |v| .{ .throw_op = .{ .src = ssa(v.src) } },

                // --- Control Flow ---
                .goto_ => |v| .{ .goto = .{ .target_block_id = resolveBlockId(&start_to_id, inst_idx, v.offset) } },
                .packed_switch, .sparse_switch => |v| blk: {
                    var targets = try allocator.alloc(usize, v.targets.len);
                    for (v.targets, 0..) |offset, i| {
                        targets[i] = resolveBlockId(&start_to_id, inst_idx, offset);
                    }
                    break :blk .{
                        .switch_op = .{
                            .src = ssa(v.src),
                            .keys = v.keys,
                            .target_block_ids = targets,
                        },
                    };
                },

                // --- Comparisons ---
                .cmpl_float, .cmpg_float, .cmpl_double, .cmpg_double, .cmp_long => |v| .{
                    .sub_int = .{ .dest = ssa(v.dest), .left = ssa(v.src1), .right = ssa(v.src2) }
                },

                // --- Conditional Branches ---
                .if_eq => |v| .{ .if_eq = .{ .left = ssa(v.src1), .right = ssa(v.src2), .target_block_id = resolveBlockId(&start_to_id, inst_idx, v.offset) } },
                .if_ne => |v| .{ .if_ne = .{ .left = ssa(v.src1), .right = ssa(v.src2), .target_block_id = resolveBlockId(&start_to_id, inst_idx, v.offset) } },
                .if_ge => |v| .{ .if_ge = .{ .left = ssa(v.src1), .right = ssa(v.src2), .target_block_id = resolveBlockId(&start_to_id, inst_idx, v.offset) } },
                .if_gt => |v| .{ .if_gt = .{ .left = ssa(v.src1), .right = ssa(v.src2), .target_block_id = resolveBlockId(&start_to_id, inst_idx, v.offset) } },
                .if_lt => |v| .{ .if_lt = .{ .left = ssa(v.src1), .right = ssa(v.src2), .target_block_id = resolveBlockId(&start_to_id, inst_idx, v.offset) } },
                .if_le => |v| .{ .if_le = .{ .left = ssa(v.src1), .right = ssa(v.src2), .target_block_id = resolveBlockId(&start_to_id, inst_idx, v.offset) } },

                .if_eqz => |v| .{ .if_eqz = .{ .src = ssa(v.src), .target_block_id = resolveBlockId(&start_to_id, inst_idx, v.offset) } },
                .if_nez => |v| .{ .if_nez = .{ .src = ssa(v.src), .target_block_id = resolveBlockId(&start_to_id, inst_idx, v.offset) } },
                .if_ltz => |v| .{ .if_ltz = .{ .src = ssa(v.src), .target_block_id = resolveBlockId(&start_to_id, inst_idx, v.offset) } },
                .if_gez => |v| .{ .if_gez = .{ .src = ssa(v.src), .target_block_id = resolveBlockId(&start_to_id, inst_idx, v.offset) } },
                .if_gtz => |v| .{ .if_gtz = .{ .src = ssa(v.src), .target_block_id = resolveBlockId(&start_to_id, inst_idx, v.offset) } },
                .if_lez => |v| .{ .if_lez = .{ .src = ssa(v.src), .target_block_id = resolveBlockId(&start_to_id, inst_idx, v.offset) } },

                // --- Array Access (aget/aput) ---
                .aget, .aget_wide, .aget_object, .aget_boolean, .aget_byte, .aget_char, .aget_short => |v| .{
                    .aget = .{ .dest_or_src = ssa(v.dest_or_src), .array = ssa(v.array), .index = ssa(v.index) }
                },
                .aput, .aput_wide, .aput_object, .aput_boolean, .aput_byte, .aput_char, .aput_short => |v| .{
                    .aput = .{ .dest_or_src = ssa(v.dest_or_src), .array = ssa(v.array), .index = ssa(v.index) }
                },

                // --- Instance Fields (iget/iput) ---
                .iget, .iget_wide, .iget_object, .iget_boolean, .iget_byte, .iget_char, .iget_short => |v| .{
                    .iget = .{ .dest_or_src = ssa(v.dest_or_src), .obj = ssa(v.obj), .field_idx = v.field_idx }
                },
                .iput, .iput_wide, .iput_object, .iput_boolean, .iput_byte, .iput_char, .iput_short => |v| .{
                    .iput = .{ .dest_or_src = ssa(v.dest_or_src), .obj = ssa(v.obj), .field_idx = v.field_idx }
                },

                // --- Static Fields (sget/sput) ---
                .sget, .sget_wide, .sget_object, .sget_boolean, .sget_byte, .sget_char, .sget_short => |v| .{
                    .sget = .{ .dest_or_src = ssa(v.dest_or_src), .field_idx = v.field_idx }
                },
                .sput, .sput_wide, .sput_object, .sput_boolean, .sput_byte, .sput_char, .sput_short => |v| .{
                    .sput = .{ .dest_or_src = ssa(v.dest_or_src), .field_idx = v.field_idx }
                },

                // --- Invocation ---
                .invoke => |v| blk: {
                    var ir_args = try allocator.alloc(ir.SSAVar, v.args.len);
                    for (v.args, 0..) |arg_reg, i| {
                        ir_args[i] = ssa(arg_reg);
                    }
                    break :blk .{
                        .invoke = .{
                            .dest = null,
                            .method_idx = 0,
                            .is_static = (v.kind == .static),
                            .args = ir_args,
                        },
                    };
                },

                // --- Unary Math & Conversions ---
                .neg_int, .not_int, .neg_long, .not_long, .neg_float, .neg_double,
                .int_to_long, .int_to_float, .int_to_double,
                .long_to_int, .long_to_float, .long_to_double,
                .float_to_int, .float_to_long, .float_to_double,
                .double_to_int, .double_to_long, .double_to_float,
                .int_to_byte, .int_to_char, .int_to_short => |v| .{
                    .move = .{ .dest = ssa(v.dest), .src = ssa(v.src) }
                },

                // --- Binary Math ---
                .add_int => |v| .{ .add_int = .{ .dest = ssa(v.dest), .left = ssa(v.src1), .right = ssa(v.src2) } },
                .sub_int => |v| .{ .sub_int = .{ .dest = ssa(v.dest), .left = ssa(v.src1), .right = ssa(v.src2) } },
                .mul_int => |v| .{ .mul_int = .{ .dest = ssa(v.dest), .left = ssa(v.src1), .right = ssa(v.src2) } },
                .div_int => |v| .{ .div_int = .{ .dest = ssa(v.dest), .left = ssa(v.src1), .right = ssa(v.src2) } },
                .rem_int => |v| .{ .rem_int = .{ .dest = ssa(v.dest), .left = ssa(v.src1), .right = ssa(v.src2) } },
                .and_int => |v| .{ .and_int = .{ .dest = ssa(v.dest), .left = ssa(v.src1), .right = ssa(v.src2) } },
                .or_int => |v| .{ .or_int = .{ .dest = ssa(v.dest), .left = ssa(v.src1), .right = ssa(v.src2) } },
                .xor_int => |v| .{ .xor_int = .{ .dest = ssa(v.dest), .left = ssa(v.src1), .right = ssa(v.src2) } },
                .shl_int => |v| .{ .shl_int = .{ .dest = ssa(v.dest), .left = ssa(v.src1), .right = ssa(v.src2) } },
                .shr_int => |v| .{ .shr_int = .{ .dest = ssa(v.dest), .left = ssa(v.src1), .right = ssa(v.src2) } },
                .ushr_int => |v| .{ .ushr_int = .{ .dest = ssa(v.dest), .left = ssa(v.src1), .right = ssa(v.src2) } },

                .add_long => |v| .{ .add_wide = .{ .dest = ssa(v.dest), .left = ssa(v.src1), .right = ssa(v.src2) } },
                .sub_long => |v| .{ .sub_wide = .{ .dest = ssa(v.dest), .left = ssa(v.src1), .right = ssa(v.src2) } },
                .mul_long => |v| .{ .mul_wide = .{ .dest = ssa(v.dest), .left = ssa(v.src1), .right = ssa(v.src2) } },
                .div_long => |v| .{ .div_wide = .{ .dest = ssa(v.dest), .left = ssa(v.src1), .right = ssa(v.src2) } },
                .rem_long, .and_long, .or_long, .xor_long, .shl_long, .shr_long, .ushr_long => |v| .{
                    .add_wide = .{ .dest = ssa(v.dest), .left = ssa(v.src1), .right = ssa(v.src2) }
                },

                .add_float => |v| .{ .add_float = .{ .dest = ssa(v.dest), .left = ssa(v.src1), .right = ssa(v.src2) } },
                .sub_float => |v| .{ .sub_float = .{ .dest = ssa(v.dest), .left = ssa(v.src1), .right = ssa(v.src2) } },
                .mul_float => |v| .{ .mul_float = .{ .dest = ssa(v.dest), .left = ssa(v.src1), .right = ssa(v.src2) } },
                .div_float => |v| .{ .div_float = .{ .dest = ssa(v.dest), .left = ssa(v.src1), .right = ssa(v.src2) } },
                .rem_float => |v| .{ .div_float = .{ .dest = ssa(v.dest), .left = ssa(v.src1), .right = ssa(v.src2) } },

                .add_double => |v| .{ .add_wide = .{ .dest = ssa(v.dest), .left = ssa(v.src1), .right = ssa(v.src2) } },
                .sub_double => |v| .{ .sub_wide = .{ .dest = ssa(v.dest), .left = ssa(v.src1), .right = ssa(v.src2) } },
                .mul_double => |v| .{ .mul_wide = .{ .dest = ssa(v.dest), .left = ssa(v.src1), .right = ssa(v.src2) } },
                .div_double => |v| .{ .div_wide = .{ .dest = ssa(v.dest), .left = ssa(v.src1), .right = ssa(v.src2) } },
                .rem_double => |v| .{ .div_wide = .{ .dest = ssa(v.dest), .left = ssa(v.src1), .right = ssa(v.src2) } },

                // --- Literal Math ---
                .add_int_lit16 => |v| .{ .add_lit = .{ .dest = ssa(v.dest), .src = ssa(v.src), .lit = v.lit } },
                .add_int_lit8 => |v| .{ .add_lit = .{ .dest = ssa(v.dest), .src = ssa(v.src), .lit = v.lit } },
                .rsub_int_lit16 => |v| .{ .sub_lit = .{ .dest = ssa(v.dest), .src = ssa(v.src), .lit = v.lit } },
                .rsub_int_lit8 => |v| .{ .sub_lit = .{ .dest = ssa(v.dest), .src = ssa(v.src), .lit = v.lit } },
                .mul_int_lit16 => |v| .{ .mul_lit = .{ .dest = ssa(v.dest), .src = ssa(v.src), .lit = v.lit } },
                .mul_int_lit8 => |v| .{ .mul_lit = .{ .dest = ssa(v.dest), .src = ssa(v.src), .lit = v.lit } },
                .div_int_lit16 => |v| .{ .div_lit = .{ .dest = ssa(v.dest), .src = ssa(v.src), .lit = v.lit } },
                .div_int_lit8 => |v| .{ .div_lit = .{ .dest = ssa(v.dest), .src = ssa(v.src), .lit = v.lit } },
                .rem_int_lit16 => |v| .{ .rem_lit = .{ .dest = ssa(v.dest), .src = ssa(v.src), .lit = v.lit } },
                .rem_int_lit8 => |v| .{ .rem_lit = .{ .dest = ssa(v.dest), .src = ssa(v.src), .lit = v.lit } },
                .and_int_lit16 => |v| .{ .and_lit = .{ .dest = ssa(v.dest), .src = ssa(v.src), .lit = v.lit } },
                .and_int_lit8 => |v| .{ .and_lit = .{ .dest = ssa(v.dest), .src = ssa(v.src), .lit = v.lit } },
                .or_int_lit16 => |v| .{ .or_lit = .{ .dest = ssa(v.dest), .src = ssa(v.src), .lit = v.lit } },
                .or_int_lit8 => |v| .{ .or_lit = .{ .dest = ssa(v.dest), .src = ssa(v.src), .lit = v.lit } },
                .xor_int_lit16 => |v| .{ .xor_lit = .{ .dest = ssa(v.dest), .src = ssa(v.src), .lit = v.lit } },
                .xor_int_lit8 => |v| .{ .xor_lit = .{ .dest = ssa(v.dest), .src = ssa(v.src), .lit = v.lit } },
                .shl_int_lit8 => |v| .{ .shl_lit = .{ .dest = ssa(v.dest), .src = ssa(v.src), .lit = v.lit } },
                .shr_int_lit8 => |v| .{ .shr_lit = .{ .dest = ssa(v.dest), .src = ssa(v.src), .lit = v.lit } },
                .ushr_int_lit8 => |v| .{ .ushr_lit = .{ .dest = ssa(v.dest), .src = ssa(v.src), .lit = v.lit } },
            };

            if (ir_inst) |inst| {
                try block.instructions.append(allocator, inst);
            }
        }
    }
}

test "translateCFG: basic moves, constants, and return" {
    const a = std.testing.allocator;

    // Dalvik instructions
    const insns = [_]instmod.Instruction{
        .{ .const_ = .{ .dest = 0, .value = 42 } },
        .{ .move = .{ .dest = 1, .src = 0 } },
        .return_void,
    };

    var cfg = try cfgmod.buildCFG(a, &insns);
    defer cfg.deinit();

    try translateCFG(a, &cfg, &insns);

    try std.testing.expectEqual(@as(usize, 1), cfg.blocks.items.len);
    const insts = cfg.blocks.items[0].instructions.items;
    try std.testing.expectEqual(@as(usize, 3), insts.len);

    // Verify first inst (const)
    try std.testing.expect(insts[0] == .const_int);
    try std.testing.expectEqual(@as(u16, 0), insts[0].const_int.dest.reg);
    try std.testing.expectEqual(@as(i32, 42), insts[0].const_int.val);

    // Verify second inst (move)
    try std.testing.expect(insts[1] == .move);
    try std.testing.expectEqual(@as(u16, 1), insts[1].move.dest.reg);
    try std.testing.expectEqual(@as(u16, 0), insts[1].move.src.reg);

    // Verify third inst (ret void)
    try std.testing.expect(insts[2] == .ret);
    try std.testing.expect(insts[2].ret.src == null);
}

test "translateCFG: conditional branch and back-link move_result" {
    const a = std.testing.allocator;

    const invoke_obj = try a.create(instmod.Invoke);
    defer a.destroy(invoke_obj);
    invoke_obj.* = .{
        .class_name = "",
        .method_name = "",
        .signature = "",
        .args = &[_]u16{0},
        .dest = null,
        .kind = .static,
    };

    const insns = [_]instmod.Instruction{
        .{ .if_eqz = .{ .src = 0, .offset = 3 } }, // 0: branch to 3 (return_void)
        .{ .invoke = invoke_obj }, // 1: call method
        .{ .move_result = .{ .dest = 1 } }, // 2: catch output in v1
        .return_void, // 3: return
    };

    var cfg = try cfgmod.buildCFG(a, &insns);
    defer cfg.deinit();

    try translateCFG(a, &cfg, &insns);

    // Block 0: starts at idx 0 (if_eqz), ends at idx 0
    const block0_insts = cfg.blocks.items[0].instructions.items;
    try std.testing.expectEqual(@as(usize, 1), block0_insts.len);
    try std.testing.expect(block0_insts[0] == .if_eqz);
    try std.testing.expectEqual(@as(u16, 0), block0_insts[0].if_eqz.src.reg);

    // Block 1: starts at idx 1 (invoke), ends at idx 2 (move_result is merged into invoke)
    const block1_insts = cfg.blocks.items[1].instructions.items;
    try std.testing.expectEqual(@as(usize, 1), block1_insts.len);
    try std.testing.expect(block1_insts[0] == .invoke);
    try std.testing.expect(block1_insts[0].invoke.dest != null);
    try std.testing.expectEqual(@as(u16, 1), block1_insts[0].invoke.dest.?.reg);
}

test "translateCFG: moves, constants, and monitors" {
    const a = std.testing.allocator;
    const insns = [_]instmod.Instruction{
        .{ .move_wide = .{ .dest = 0, .src = 1 } },
        .{ .move_object = .{ .dest = 2, .src = 3 } },
        .{ .move_exception = .{ .dest = 4 } },
        .{ .const_wide = .{ .value = 100, .dest = 5 } },
        .{ .const_string = .{ .index = 10, .dest = 6 } },
        .{ .const_class = .{ .type_idx = 20, .dest = 7 } },
        .{ .const_method_handle = .{ .index = 30, .dest = 8 } },
        .{ .const_method_type = .{ .index = 40, .dest = 9 } },
        .{ .monitor_enter = .{ .src = 10 } },
        .{ .monitor_exit = .{ .src = 10 } },
        .return_void,
    };
    var cfg = try cfgmod.buildCFG(a, &insns);
    defer cfg.deinit();
    try translateCFG(a, &cfg, &insns);

    const insts = cfg.blocks.items[0].instructions.items;
    // Monitor enter/exit are skipped, so 11 - 2 = 9 instructions
    try std.testing.expectEqual(@as(usize, 9), insts.len);
    try std.testing.expect(insts[0] == .move);
    try std.testing.expect(insts[1] == .move);
    try std.testing.expect(insts[2] == .move);
    try std.testing.expect(insts[3] == .const_wide);
    try std.testing.expect(insts[4] == .const_string);
    try std.testing.expect(insts[5] == .const_class);
    try std.testing.expect(insts[6] == .const_int);
    try std.testing.expect(insts[7] == .const_int);
    try std.testing.expect(insts[8] == .ret);
}

test "translateCFG: checks, casts, allocations, and exceptions" {
    const a = std.testing.allocator;
    const insns = [_]instmod.Instruction{
        .{ .check_cast = .{ .type_idx = 1, .src = 2 } },
        .{ .instance_of = .{ .type_idx = 2, .dest = 3, .src = 4 } },
        .{ .array_length = .{ .dest = 5, .array = 6 } },
        .{ .new_instance = .{ .type_idx = 3, .dest = 7 } },
        .{ .new_array = .{ .type_idx = 4, .dest = 8, .size = 9 } },
        .{ .filled_new_array = .{ .args = &.{}, .type_idx = 5 } },
        .{ .fill_array_data = .{ .payload_offset = 0, .array = 10 } },
        .{ .throw_ = .{ .src = 11 } },
    };
    var cfg = try cfgmod.buildCFG(a, &insns);
    defer cfg.deinit();
    try translateCFG(a, &cfg, &insns);

    const insts = cfg.blocks.items[0].instructions.items;
    // fill_array_data is skipped, so 8 - 1 = 7 instructions
    try std.testing.expectEqual(@as(usize, 7), insts.len);
    try std.testing.expect(insts[0] == .move);
    try std.testing.expect(insts[1] == .const_int);
    try std.testing.expect(insts[2] == .move);
    try std.testing.expect(insts[3] == .new_instance);
    try std.testing.expect(insts[4] == .new_array);
    try std.testing.expect(insts[5] == .new_instance);
    try std.testing.expect(insts[6] == .throw_op);
}

test "translateCFG: switches and comparisons" {
    const a = std.testing.allocator;
    const insns = [_]instmod.Instruction{
        .{ .cmpl_float = .{ .dest = 0, .src1 = 1, .src2 = 2 } },
        .{ .cmpg_float = .{ .dest = 3, .src1 = 4, .src2 = 5 } },
        .{ .cmpl_double = .{ .dest = 6, .src1 = 7, .src2 = 8 } },
        .{ .cmpg_double = .{ .dest = 9, .src1 = 10, .src2 = 11 } },
        .{ .cmp_long = .{ .dest = 12, .src1 = 13, .src2 = 14 } },
        .{ .packed_switch = .{ .payload_offset = 0, .src = 15, .keys = &.{1}, .targets = &.{1} } },
        .return_void,
    };
    var cfg = try cfgmod.buildCFG(a, &insns);
    defer cfg.deinit();
    try translateCFG(a, &cfg, &insns);

    const block0 = cfg.blocks.items[0].instructions.items;
    try std.testing.expectEqual(@as(usize, 6), block0.len);
    try std.testing.expect(block0[0] == .sub_int);
    try std.testing.expect(block0[1] == .sub_int);
    try std.testing.expect(block0[2] == .sub_int);
    try std.testing.expect(block0[3] == .sub_int);
    try std.testing.expect(block0[4] == .sub_int);
    try std.testing.expect(block0[5] == .switch_op);

    const block1 = cfg.blocks.items[1].instructions.items;
    try std.testing.expectEqual(@as(usize, 1), block1.len);
    try std.testing.expect(block1[0] == .ret);
}

test "translateCFG: conditional branches" {
    const a = std.testing.allocator;
    const insns = [_]instmod.Instruction{
        .{ .if_lt = .{ .offset = 7, .src1 = 0, .src2 = 1 } },
        .{ .if_le = .{ .offset = 6, .src1 = 2, .src2 = 3 } },
        .{ .if_nez = .{ .offset = 5, .src = 4 } },
        .{ .if_ltz = .{ .offset = 4, .src = 5 } },
        .{ .if_gez = .{ .offset = 3, .src = 6 } },
        .{ .if_gtz = .{ .offset = 2, .src = 7 } },
        .{ .if_lez = .{ .offset = 1, .src = 8 } },
        .return_void,
    };
    var cfg = try cfgmod.buildCFG(a, &insns);
    defer cfg.deinit();
    try translateCFG(a, &cfg, &insns);

    try std.testing.expectEqual(@as(usize, 8), cfg.blocks.items.len);
    try std.testing.expect(cfg.blocks.items[0].instructions.items[0] == .if_lt);
    try std.testing.expect(cfg.blocks.items[1].instructions.items[0] == .if_le);
    try std.testing.expect(cfg.blocks.items[2].instructions.items[0] == .if_nez);
    try std.testing.expect(cfg.blocks.items[3].instructions.items[0] == .if_ltz);
    try std.testing.expect(cfg.blocks.items[4].instructions.items[0] == .if_gez);
    try std.testing.expect(cfg.blocks.items[5].instructions.items[0] == .if_gtz);
    try std.testing.expect(cfg.blocks.items[6].instructions.items[0] == .if_lez);
}

test "translateCFG: field and array accesses" {
    const a = std.testing.allocator;
    const insns = [_]instmod.Instruction{
        .{ .aget_wide = .{ .dest_or_src = 0, .array = 1, .index = 2 } },
        .{ .aput_object = .{ .dest_or_src = 3, .array = 4, .index = 5 } },
        .{ .iget_boolean = .{ .field_idx = 10, .dest_or_src = 6, .obj = 7 } },
        .{ .iput_byte = .{ .field_idx = 11, .dest_or_src = 8, .obj = 9 } },
        .{ .sget_char = .{ .field_idx = 12, .dest_or_src = 10 } },
        .{ .sput_short = .{ .field_idx = 13, .dest_or_src = 11 } },
        .return_void,
    };
    var cfg = try cfgmod.buildCFG(a, &insns);
    defer cfg.deinit();
    try translateCFG(a, &cfg, &insns);

    const insts = cfg.blocks.items[0].instructions.items;
    try std.testing.expectEqual(@as(usize, 7), insts.len);
    try std.testing.expect(insts[0] == .aget);
    try std.testing.expect(insts[1] == .aput);
    try std.testing.expect(insts[2] == .iget);
    try std.testing.expect(insts[3] == .iput);
    try std.testing.expect(insts[4] == .sget);
    try std.testing.expect(insts[5] == .sput);
}

test "translateCFG: unary math and conversions" {
    const a = std.testing.allocator;
    const insns = [_]instmod.Instruction{
        .{ .neg_int = .{ .dest = 0, .src = 1 } },
        .{ .not_int = .{ .dest = 2, .src = 3 } },
        .{ .long_to_int = .{ .dest = 4, .src = 5 } },
        .{ .float_to_double = .{ .dest = 6, .src = 7 } },
        .return_void,
    };
    var cfg = try cfgmod.buildCFG(a, &insns);
    defer cfg.deinit();
    try translateCFG(a, &cfg, &insns);

    const insts = cfg.blocks.items[0].instructions.items;
    try std.testing.expectEqual(@as(usize, 5), insts.len);
    try std.testing.expect(insts[0] == .move);
    try std.testing.expect(insts[1] == .move);
    try std.testing.expect(insts[2] == .move);
    try std.testing.expect(insts[3] == .move);
}

test "translateCFG: binary math register and literals" {
    const a = std.testing.allocator;
    const insns = [_]instmod.Instruction{
        .{ .rem_int = .{ .dest = 0, .src1 = 1, .src2 = 2 } },
        .{ .shl_int = .{ .dest = 3, .src1 = 4, .src2 = 5 } },
        .{ .sub_long = .{ .dest = 6, .src1 = 7, .src2 = 8 } },
        .{ .rem_long = .{ .dest = 9, .src1 = 10, .src2 = 11 } },
        .{ .mul_float = .{ .dest = 12, .src1 = 13, .src2 = 14 } },
        .{ .rem_double = .{ .dest = 15, .src1 = 16, .src2 = 17 } },
        .{ .rsub_int_lit16 = .{ .dest = 18, .src = 19, .lit = 10 } },
        .{ .xor_int_lit8 = .{ .dest = 20, .src = 21, .lit = 5 } },
        .return_void,
    };
    var cfg = try cfgmod.buildCFG(a, &insns);
    defer cfg.deinit();
    try translateCFG(a, &cfg, &insns);

    const insts = cfg.blocks.items[0].instructions.items;
    try std.testing.expectEqual(@as(usize, 9), insts.len);
    try std.testing.expect(insts[0] == .rem_int);
    try std.testing.expect(insts[1] == .shl_int);
    try std.testing.expect(insts[2] == .sub_wide);
    try std.testing.expect(insts[3] == .add_wide);
    try std.testing.expect(insts[4] == .mul_float);
    try std.testing.expect(insts[5] == .div_wide);
    try std.testing.expect(insts[6] == .sub_lit);
    try std.testing.expect(insts[7] == .xor_lit);
}
