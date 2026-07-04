const std = @import("std");
const ir = @import("ir");
const cfgmod = @import("cfg");

/// Phase 1 of the Back-End: Out-of-SSA Translation.
/// Replaces all Phi nodes with explicit `move` instructions in the predecessor blocks.
fn maxVersion(cfg: *cfgmod.CFG, reg: u16) u32 {
    var max: u32 = 0;
    for (cfg.blocks.items) |block| {
        for (block.phi_functions.items) |phi| {
            if (phi.original_reg == reg) {
                if (phi.ssa_version) |v| {
                    if (v > max) max = v;
                }
            }
        }
        for (block.instructions.items) |inst| {
            const dest: ?ir.SSAVar = switch (inst) {
                .move => |v| v.dest,
                .const_int => |v| v.dest,
                .const_wide => |v| v.dest,
                .const_string => |v| v.dest,
                .const_class => |v| v.dest,
                .add_int, .sub_int, .mul_int, .div_int, .rem_int, .and_int, .or_int, .xor_int, .shl_int, .shr_int, .ushr_int, .add_float, .sub_float, .mul_float, .div_float, .add_wide, .sub_wide, .mul_wide, .div_wide => |v| v.dest,
                .add_lit, .sub_lit, .mul_lit, .div_lit, .rem_lit, .and_lit, .or_lit, .xor_lit, .shl_lit, .shr_lit, .ushr_lit => |v| v.dest,
                .new_instance => |v| v.dest,
                .new_array => |v| v.dest,
                .iget => |v| v.dest_or_src,
                .sget => |v| v.dest_or_src,
                .aget => |v| v.dest_or_src,
                .phi => |v| v.dest,
                .invoke => |v| if (v.dest) |d| d else null,
                else => null,
            };
            if (dest) |d| {
                if (d.reg == reg and d.version > max) {
                    max = d.version;
                }
            }
        }
    }
    return max;
}

const Move = struct {
    dest: ir.SSAVar,
    src: ir.SSAVar,
};

fn resolveParallelCopies(allocator: std.mem.Allocator, cfg: *cfgmod.CFG, raw_moves: []const Move) ![]const ir.IRInst {
    var moves = std.ArrayList(Move).empty;
    defer moves.deinit(allocator);

    // 1. Filter out self-moves (Optimization 1)
    for (raw_moves) |m| {
        if (m.dest.reg == m.src.reg and m.dest.version == m.src.version) {
            continue;
        }
        try moves.append(allocator, m);
    }

    var emitted = std.ArrayList(ir.IRInst).empty;
    errdefer {
        for (emitted.items) |inst| {
            if (inst == .phi) allocator.free(inst.phi.args);
        }
        emitted.deinit(allocator);
    }

    // 2. Topological sort with cycle breaking (Optimization 2 & Swap Resolution)
    while (moves.items.len > 0) {
        var found_independent = false;
        
        for (moves.items, 0..) |m, idx| {
            var is_source_of_other = false;
            for (moves.items) |other| {
                if (other.src.reg == m.dest.reg and other.src.version == m.dest.version) {
                    is_source_of_other = true;
                    break;
                }
            }

            if (!is_source_of_other) {
                try emitted.append(allocator, .{ .move = .{ .dest = m.dest, .src = m.src } });
                _ = moves.orderedRemove(idx);
                found_independent = true;
                break;
            }
        }

        if (!found_independent) {
            const m = moves.items[0];
            const max_ver = maxVersion(cfg, m.src.reg);
            const temp_var = ir.SSAVar{ .reg = m.src.reg, .version = max_ver + 1 };

            try emitted.append(allocator, .{ .move = .{ .dest = temp_var, .src = m.src } });

            for (moves.items) |*other| {
                if (other.src.reg == m.src.reg and other.src.version == m.src.version) {
                    other.src = temp_var;
                }
            }
        }
    }

    return emitted.toOwnedSlice(allocator);
}

/// Phase 1 of the Back-End: Out-of-SSA Translation.
/// Replaces all Phi nodes with explicit `move` instructions in the predecessor blocks.
pub fn eliminatePhis(allocator: std.mem.Allocator, cfg: *cfgmod.CFG) !void {
    // Map: Predecessor Block ID -> List of raw Move configurations
    var moves_to_insert = std.AutoHashMap(usize, std.ArrayList(Move)).init(allocator);
    defer {
        var it = moves_to_insert.iterator();
        while (it.next()) |entry| {
            entry.value_ptr.deinit(allocator);
        }
        moves_to_insert.deinit();
    }

    // Step 1: Scan for Phi functions and queue up the raw moves
    for (cfg.blocks.items) |*block| {
        var non_phi_insts = std.ArrayList(ir.IRInst).empty;

        for (block.instructions.items) |inst| {
            if (inst == .phi) {
                const dest_var = inst.phi.dest;

                for (inst.phi.args) |arg| {
                    const raw_move = Move{ .dest = dest_var, .src = arg.val };

                    var entry = try moves_to_insert.getOrPut(arg.pred_block_id);
                    if (!entry.found_existing) {
                        entry.value_ptr.* = std.ArrayList(Move).empty;
                    }
                    try entry.value_ptr.append(allocator, raw_move);
                }
            } else {
                try non_phi_insts.append(allocator, inst);
            }
        }

        for (block.instructions.items) |inst| {
            if (inst == .phi) {
                allocator.free(inst.phi.args);
            }
        }
        block.instructions.deinit(allocator);
        block.instructions = non_phi_insts;
    }

    // Step 2: Resolve parallel copy cycles and insert the optimized move sequences
    var it = moves_to_insert.iterator();
    while (it.next()) |entry| {
        const pred_id = entry.key_ptr.*;
        const raw_moves = entry.value_ptr.*;
        var pred_block = &cfg.blocks.items[pred_id];

        const resolved_moves = try resolveParallelCopies(allocator, cfg, raw_moves.items);
        defer allocator.free(resolved_moves);

        var insert_idx = pred_block.instructions.items.len;

        if (insert_idx > 0) {
            const last_inst = pred_block.instructions.items[insert_idx - 1];
            const is_terminal = switch (last_inst) {
                .goto, .if_eq, .if_ne, .if_lt, .if_ge, .if_gt, .if_le, .if_eqz, .if_nez, .if_ltz, .if_gez, .if_gtz, .if_lez, .switch_op, .ret, .throw_op => true,
                else => false,
            };

            if (is_terminal) {
                insert_idx -= 1;
            }
        }

        try pred_block.instructions.insertSlice(allocator, insert_idx, resolved_moves);
    }
}

test "eliminatePhis: out-of-ssa translation" {
    const a = std.testing.allocator;
    const instmod = @import("instruction");
    const translate = @import("translate");

    const insns = [_]instmod.Instruction{
        .{ .const_ = .{ .value = 10, .dest = 0 } }, // Block 0
        .{ .if_gtz = .{ .offset = 3, .src = 0 } }, // if v0 > 0 goto Block 2 (offset 3 to index 5)
        .{ .const_ = .{ .value = 20, .dest = 1 } }, // Block 1
        .{ .goto_ = .{ .offset = 1 } }, // goto Block 2
        .{ .return_ = .{ .src = 2 } }, // Block 2
    };

    var cfg = try cfgmod.buildCFG(a, &insns);
    defer cfg.deinit();

    try cfg.computePredecessors();
    try cfg.computeDominators();
    try cfg.computeDominatorChildren();
    try cfg.computeDominanceFrontiers();

    try translate.translateCFG(a, &cfg, &insns);

    var def_map = std.AutoHashMap(u16, std.ArrayList(usize)).init(a);
    defer {
        var it = def_map.iterator();
        while (it.next()) |entry| entry.value_ptr.deinit(a);
        def_map.deinit();
    }

    for (cfg.blocks.items) |block| {
        for (block.instructions.items) |inst| {
            const dest_reg: ?u16 = switch (inst) {
                .phi => |v| v.dest.reg,
                .move => |v| v.dest.reg,
                .const_int => |v| v.dest.reg,
                .const_wide => |v| v.dest.reg,
                .const_string => |v| v.dest.reg,
                .const_class => |v| v.dest.reg,
                .add_int,
                .sub_int,
                .mul_int,
                .div_int,
                .rem_int,
                .and_int,
                .or_int,
                .xor_int,
                .shl_int,
                .shr_int,
                .ushr_int,
                .add_float,
                .sub_float,
                .mul_float,
                .div_float,
                .add_wide,
                .sub_wide,
                .mul_wide,
                .div_wide,
                => |v| v.dest.reg,
                .add_lit,
                .sub_lit,
                .mul_lit,
                .div_lit,
                .rem_lit,
                .and_lit,
                .or_lit,
                .xor_lit,
                .shl_lit,
                .shr_lit,
                .ushr_lit,
                => |v| v.dest.reg,
                .new_instance => |v| v.dest.reg,
                .new_array => |v| v.dest.reg,
                .iget => |v| v.dest_or_src.reg,
                .sget => |v| v.dest_or_src.reg,
                .aget => |v| v.dest_or_src.reg,
                .invoke => |v| if (v.dest) |d| d.reg else null,
                else => null,
            };

            if (dest_reg) |reg| {
                var res = try def_map.getOrPut(reg);
                if (!res.found_existing) {
                    res.value_ptr.* = .empty;
                }
                var contains = false;
                for (res.value_ptr.items) |b_id| {
                    if (b_id == block.id) {
                        contains = true;
                        break;
                    }
                }
                if (!contains) {
                    try res.value_ptr.append(a, block.id);
                }
            }
        }
    }

    try cfg.insertPhiFunctions(def_map);
    try cfg.renameVariables(10);

    for (cfg.blocks.items[2].instructions.items) |inst| {
        if (inst == .phi) {
            a.free(inst.phi.args);
        }
    }
    cfg.blocks.items[2].instructions.clearRetainingCapacity();

    const phi_args = try a.alloc(ir.PhiArg, 2);
    phi_args[0] = .{ .pred_block_id = 0, .val = .{ .reg = 0, .version = 1 } };
    phi_args[1] = .{ .pred_block_id = 1, .val = .{ .reg = 1, .version = 1 } };

    try cfg.blocks.items[2].instructions.append(a, .{ .phi = .{ .dest = .{ .reg = 2, .version = 1 }, .args = phi_args } });
    try cfg.blocks.items[2].instructions.append(a, .{ .ret = .{ .src = .{ .reg = 2, .version = 1 } } });

    try eliminatePhis(a, &cfg);

    for (cfg.blocks.items[2].instructions.items) |inst| {
        try std.testing.expect(inst != .phi);
    }

    const b0_insts = cfg.blocks.items[0].instructions.items;
    var found_b0_move = false;
    for (b0_insts) |inst| {
        if (inst == .move) {
            try std.testing.expectEqual(@as(u16, 2), inst.move.dest.reg);
            try std.testing.expectEqual(@as(u16, 0), inst.move.src.reg);
            found_b0_move = true;
        }
    }
    try std.testing.expect(found_b0_move);

    const b1_insts = cfg.blocks.items[1].instructions.items;
    var found_b1_move = false;
    for (b1_insts) |inst| {
        if (inst == .move) {
            try std.testing.expectEqual(@as(u16, 2), inst.move.dest.reg);
            try std.testing.expectEqual(@as(u16, 1), inst.move.src.reg);
            found_b1_move = true;
        }
    }
    try std.testing.expect(found_b1_move);
}

test "eliminatePhis: parallel copy and swap cycle resolution" {
    const a = std.testing.allocator;
    const instmod = @import("instruction");
    const translate = @import("translate");

    const insns = [_]instmod.Instruction{
        .{ .const_ = .{ .value = 10, .dest = 0 } },  // Block 0
        .{ .const_ = .{ .value = 20, .dest = 1 } },
        .{ .goto_ = .{ .offset = 1 } },
        .{ .return_ = .{ .src = 0 } },               // Block 1
    };

    var cfg = try cfgmod.buildCFG(a, &insns);
    defer cfg.deinit();

    try cfg.computePredecessors();
    try cfg.computeDominators();
    try cfg.computeDominatorChildren();
    try cfg.computeDominanceFrontiers();

    try translate.translateCFG(a, &cfg, &insns);

    var def_map = std.AutoHashMap(u16, std.ArrayList(usize)).init(a);
    defer {
        var it = def_map.iterator();
        while (it.next()) |entry| entry.value_ptr.deinit(a);
        def_map.deinit();
    }

    for (cfg.blocks.items) |block| {
        for (block.instructions.items) |inst| {
            const dest_reg: ?u16 = switch (inst) {
                .phi => |v| v.dest.reg,
                .move => |v| v.dest.reg,
                .const_int => |v| v.dest.reg,
                .const_wide => |v| v.dest.reg,
                .const_string => |v| v.dest.reg,
                .const_class => |v| v.dest.reg,
                .add_int, .sub_int, .mul_int, .div_int, .rem_int,
                .and_int, .or_int, .xor_int, .shl_int, .shr_int, .ushr_int,
                .add_float, .sub_float, .mul_float, .div_float,
                .add_wide, .sub_wide, .mul_wide, .div_wide,
                => |v| v.dest.reg,
                .add_lit, .sub_lit, .mul_lit, .div_lit, .rem_lit,
                .and_lit, .or_lit, .xor_lit, .shl_lit, .shr_lit, .ushr_lit,
                => |v| v.dest.reg,
                .new_instance => |v| v.dest.reg,
                .new_array => |v| v.dest.reg,
                .iget => |v| v.dest_or_src.reg,
                .sget => |v| v.dest_or_src.reg,
                .aget => |v| v.dest_or_src.reg,
                .invoke => |v| if (v.dest) |d| d.reg else null,
                else => null,
            };

            if (dest_reg) |reg| {
                var res = try def_map.getOrPut(reg);
                if (!res.found_existing) {
                    res.value_ptr.* = .empty;
                }
                var contains = false;
                for (res.value_ptr.items) |b_id| {
                    if (b_id == block.id) {
                        contains = true;
                        break;
                    }
                }
                if (!contains) {
                    try res.value_ptr.append(a, block.id);
                }
            }
        }
    }

    try cfg.insertPhiFunctions(def_map);
    try cfg.renameVariables(10);

    cfg.blocks.items[1].instructions.clearRetainingCapacity();

    const phi0_args = try a.alloc(ir.PhiArg, 1);
    phi0_args[0] = .{ .pred_block_id = 0, .val = .{ .reg = 1, .version = 1 } };
    try cfg.blocks.items[1].instructions.append(a, .{ .phi = .{ .dest = .{ .reg = 0, .version = 2 }, .args = phi0_args } });

    const phi1_args = try a.alloc(ir.PhiArg, 1);
    phi1_args[0] = .{ .pred_block_id = 0, .val = .{ .reg = 0, .version = 1 } };
    try cfg.blocks.items[1].instructions.append(a, .{ .phi = .{ .dest = .{ .reg = 1, .version = 2 }, .args = phi1_args } });

    try cfg.blocks.items[1].instructions.append(a, .{ .ret = .{ .src = .{ .reg = 0, .version = 2 } } });

    try eliminatePhis(a, &cfg);

    const b0_insts = cfg.blocks.items[0].instructions.items;

    var move_count: usize = 0;
    for (b0_insts) |inst| {
        if (inst == .move) {
            move_count += 1;
        }
    }
    try std.testing.expectEqual(@as(usize, 2), move_count);

    // Now test the cycle-breaking logic directly:
    var raw_moves = [_]Move{
        .{ .dest = .{ .reg = 0, .version = 1 }, .src = .{ .reg = 1, .version = 1 } },
        .{ .dest = .{ .reg = 1, .version = 1 }, .src = .{ .reg = 0, .version = 1 } },
    };
    const resolved = try resolveParallelCopies(a, &cfg, &raw_moves);
    defer a.free(resolved);

    try std.testing.expectEqual(@as(usize, 3), resolved.len);
    var found_temp = false;
    for (resolved) |inst| {
        if (inst == .move and inst.move.dest.version > 1) {
            found_temp = true;
        }
    }
    try std.testing.expect(found_temp);
}
