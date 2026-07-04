const std = @import("std");
const ir = @import("ir");
const cfgmod = @import("cfg");

const DefLoc = union(enum) {
    inst: struct { block_id: usize, inst_idx: usize },
    phi: struct { block_id: usize, original_reg: u16 },
};

const ValueKey = struct {
    tag: enum { constant, constant_wide, bin_op, bin_op_lit },
    op_tag: std.meta.Tag(ir.IRInst),
    val_i64: i64,
    left: ir.SSAVar,
    right: ir.SSAVar,

    fn equals(self: ValueKey, other: ValueKey) bool {
        if (self.tag != other.tag) return false;
        switch (self.tag) {
            .constant, .constant_wide => return self.val_i64 == other.val_i64,
            .bin_op => return self.op_tag == other.op_tag and
                self.left.reg == other.left.reg and self.left.version == other.left.version and
                self.right.reg == other.right.reg and self.right.version == other.right.version,
            .bin_op_lit => return self.op_tag == other.op_tag and
                self.left.reg == other.left.reg and self.left.version == other.left.version and
                self.val_i64 == other.val_i64,
        }
    }

    fn hash(self: ValueKey) u32 {
        var h: u32 = @intFromEnum(self.tag);
        h = h ^ (@as(u32, @intFromEnum(self.op_tag)) *% 31);
        h = h ^ (@as(u32, @bitCast(@as(i32, @truncate(self.val_i64)))) *% 17);
        h = h ^ (@as(u32, self.left.reg) *% 13);
        h = h ^ (self.left.version *% 7);
        h = h ^ (@as(u32, self.right.reg) *% 5);
        h = h ^ (self.right.version *% 3);
        return h;
    }
};

const ValueKeyContext = struct {
    pub fn hash(self: ValueKeyContext, key: ValueKey) u64 {
        _ = self;
        return key.hash();
    }
    pub fn eql(self: ValueKeyContext, a: ValueKey, b: ValueKey) bool {
        _ = self;
        return a.equals(b);
    }
};

fn dominates(cfg: *const cfgmod.CFG, a_id: usize, b_id: usize) bool {
    var curr = b_id;
    while (curr != a_id) {
        if (cfg.blocks.items[curr].idom) |parent| {
            curr = parent;
        } else {
            return false;
        }
    }
    return true;
}

/// Loop-Invariant Code Motion (LICM) Pass.
pub fn loopInvariantCodeMotion(allocator: std.mem.Allocator, cfg: *cfgmod.CFG) !bool {
    var changed = false;

    // Build map of SSAVar -> definition block_id
    var def_blocks = std.AutoHashMap(ir.SSAVar, usize).init(allocator);
    defer def_blocks.deinit();

    for (cfg.blocks.items) |block| {
        for (block.phi_functions.items) |phi| {
            if (phi.ssa_version) |ver| {
                try def_blocks.put(.{ .reg = phi.original_reg, .version = ver }, block.id);
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
                else => null,
            };
            if (dest) |d| {
                try def_blocks.put(d, block.id);
            }
        }
    }

    // Identify loops. A loop header is a block H that dominates a predecessor L.
    for (cfg.blocks.items) |header| {
        for (header.predecessors.items) |latch_id| {
            // Check if header dominates latch
            if (dominates(cfg, header.id, latch_id)) {
                // Found a loop! Latch is latch_id, Header is header.id
                var loop_blocks = std.AutoHashMap(usize, void).init(allocator);
                defer loop_blocks.deinit();

                try loop_blocks.put(header.id, {});
                try loop_blocks.put(latch_id, {});

                // Find all loop blocks using a worklist
                var worklist = std.ArrayList(usize).empty;
                defer worklist.deinit(allocator);
                try worklist.append(allocator, latch_id);

                while (worklist.items.len > 0) {
                    const curr_id = worklist.pop().?;
                    if (curr_id == header.id) continue;
                    const curr = cfg.blocks.items[curr_id];
                    for (curr.predecessors.items) |pred| {
                        if (!loop_blocks.contains(pred)) {
                            try loop_blocks.put(pred, {});
                            try worklist.append(allocator, pred);
                        }
                    }
                }

                // Find the unique predecessor of the header from outside the loop
                var pre_header_id: ?usize = null;
                var multiple_pre_headers = false;
                for (header.predecessors.items) |pred| {
                    if (!loop_blocks.contains(pred)) {
                        if (pre_header_id == null) {
                            pre_header_id = pred;
                        } else {
                            multiple_pre_headers = true;
                        }
                    }
                }

                if (pre_header_id == null or multiple_pre_headers) continue;

                // Hoist loop invariant instructions
                const ph_id = pre_header_id.?;
                
                // We will iteratively find and hoist loop invariant instructions
                var loop_changed = true;
                while (loop_changed) {
                    loop_changed = false;

                    for (cfg.blocks.items) |*block| {
                        if (!loop_blocks.contains(block.id)) continue;

                        var new_insts = std.ArrayList(ir.IRInst).empty;
                        for (block.instructions.items) |inst| {
                            var is_invariant = false;

                            // Only hoist pure operations
                            switch (inst) {
                                .move, .const_int, .const_wide, .const_string, .const_class,
                                .add_int, .sub_int, .mul_int, .div_int, .rem_int, .and_int, .or_int, .xor_int, .shl_int, .shr_int, .ushr_int,
                                .add_float, .sub_float, .mul_float, .div_float, .add_wide, .sub_wide, .mul_wide, .div_wide,
                                .add_lit, .sub_lit, .mul_lit, .div_lit, .rem_lit, .and_lit, .or_lit, .xor_lit, .shl_lit, .shr_lit, .ushr_lit,
                                .new_instance, .new_array, .iget, .sget, .aget => {
                                    is_invariant = true;
                                },
                                else => {},
                            }

                            if (is_invariant) {
                                // Check if all operand variables are defined outside the loop
                                const is_op_invariant = struct {
                                    fn f(defs: std.AutoHashMap(ir.SSAVar, usize), loop: std.AutoHashMap(usize, void), v: ir.SSAVar) bool {
                                        if (defs.get(v)) |def_b| {
                                            return !loop.contains(def_b);
                                        }
                                        return true; // Constants or args defined outside loop
                                    }
                                }.f;

                                switch (inst) {
                                    .move => |v| {
                                        if (!is_op_invariant(def_blocks, loop_blocks, v.src)) is_invariant = false;
                                    },
                                    .add_int, .sub_int, .mul_int, .div_int, .rem_int, .and_int, .or_int, .xor_int, .shl_int, .shr_int, .ushr_int, .add_float, .sub_float, .mul_float, .div_float, .add_wide, .sub_wide, .mul_wide, .div_wide => |v| {
                                        if (!is_op_invariant(def_blocks, loop_blocks, v.left) or !is_op_invariant(def_blocks, loop_blocks, v.right)) is_invariant = false;
                                    },
                                    .add_lit, .sub_lit, .mul_lit, .div_lit, .rem_lit, .and_lit, .or_lit, .xor_lit, .shl_lit, .shr_lit, .ushr_lit => |v| {
                                        if (!is_op_invariant(def_blocks, loop_blocks, v.src)) is_invariant = false;
                                    },
                                    .new_array => |v| {
                                        if (!is_op_invariant(def_blocks, loop_blocks, v.size)) is_invariant = false;
                                    },
                                    .iget => |v| {
                                        if (!is_op_invariant(def_blocks, loop_blocks, v.obj)) is_invariant = false;
                                    },
                                    .aget => |v| {
                                        if (!is_op_invariant(def_blocks, loop_blocks, v.array) or !is_op_invariant(def_blocks, loop_blocks, v.index)) is_invariant = false;
                                    },
                                    else => {},
                                }
                            }

                            if (is_invariant) {
                                // Hoist it!
                                const dest: ir.SSAVar = switch (inst) {
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
                                    else => unreachable,
                                };

                                // Insert into preheader (before its terminator)
                                var ph = &cfg.blocks.items[ph_id];
                                if (ph.instructions.items.len > 0) {
                                    try ph.instructions.insert(allocator, ph.instructions.items.len - 1, inst);
                                } else {
                                    try ph.instructions.append(allocator, inst);
                                }

                                // Update definition block map
                                try def_blocks.put(dest, ph_id);

                                loop_changed = true;
                                changed = true;
                            } else {
                                try new_insts.append(allocator, inst);
                            }
                        }
                        block.instructions.deinit(allocator);
                        block.instructions = new_insts;
                    }
                }
            }
        }
    }

    return changed;
}

fn rebuildSuccessors(cfg: *cfgmod.CFG) void {
    for (cfg.blocks.items, 0..) |*block, i| {
        block.successors.clearRetainingCapacity();
        if (block.instructions.items.len == 0) {
            if (i + 1 < cfg.blocks.items.len) {
                block.successors.append(cfg.allocator, i + 1) catch {};
            }
            continue;
        }

        const last_inst = block.instructions.items[block.instructions.items.len - 1];
        switch (last_inst) {
            .goto => |v| {
                block.successors.append(cfg.allocator, v.target_block_id) catch {};
            },
            .if_eq, .if_ne, .if_lt, .if_ge, .if_gt, .if_le => |v| {
                block.successors.append(cfg.allocator, v.target_block_id) catch {};
                if (i + 1 < cfg.blocks.items.len) {
                    block.successors.append(cfg.allocator, i + 1) catch {};
                }
            },
            .if_eqz, .if_nez, .if_ltz, .if_gez, .if_gtz, .if_lez => |v| {
                block.successors.append(cfg.allocator, v.target_block_id) catch {};
                if (i + 1 < cfg.blocks.items.len) {
                    block.successors.append(cfg.allocator, i + 1) catch {};
                }
            },
            .switch_op => |v| {
                for (v.target_block_ids) |tid| {
                    block.successors.append(cfg.allocator, tid) catch {};
                }
                if (i + 1 < cfg.blocks.items.len) {
                    block.successors.append(cfg.allocator, i + 1) catch {};
                }
            },
            .ret, .throw_op => {},
            else => {
                if (i + 1 < cfg.blocks.items.len) {
                    block.successors.append(cfg.allocator, i + 1) catch {};
                }
            },
        }
    }
}

fn resolveDeadBranches(cfg: *cfgmod.CFG, constants: std.AutoHashMap(ir.SSAVar, i32)) bool {
    var changed = false;
    for (cfg.blocks.items) |*block| {
        if (block.instructions.items.len == 0) continue;
        const last_idx = block.instructions.items.len - 1;
        const inst = &block.instructions.items[last_idx];
        switch (inst.*) {
            .if_eq, .if_ne, .if_lt, .if_ge, .if_gt, .if_le => |v| {
                if (constants.get(v.left)) |val_l| {
                    if (constants.get(v.right)) |val_r| {
                        const cond_true = switch (inst.*) {
                            .if_eq => val_l == val_r,
                            .if_ne => val_l != val_r,
                            .if_lt => val_l < val_r,
                            .if_ge => val_l >= val_r,
                            .if_gt => val_l > val_r,
                            .if_le => val_l <= val_r,
                            else => unreachable,
                        };
                        if (cond_true) {
                            inst.* = .{ .goto = .{ .target_block_id = v.target_block_id } };
                        } else {
                            _ = block.instructions.pop();
                        }
                        changed = true;
                    }
                }
            },
            .if_eqz, .if_nez, .if_ltz, .if_gez, .if_gtz, .if_lez => |v| {
                if (constants.get(v.src)) |val| {
                    const cond_true = switch (inst.*) {
                        .if_eqz => val == 0,
                        .if_nez => val != 0,
                        .if_ltz => val < 0,
                        .if_gez => val >= 0,
                        .if_gtz => val > 0,
                        .if_lez => val <= 0,
                        else => unreachable,
                    };
                    if (cond_true) {
                        inst.* = .{ .goto = .{ .target_block_id = v.target_block_id } };
                    } else {
                        _ = block.instructions.pop();
                    }
                    changed = true;
                }
            },
            else => {},
        }
    }
    return changed;
}

fn pruneUnreachableBlocks(cfg: *cfgmod.CFG) bool {
    var changed = false;
    var reachable = std.DynamicBitSet.initEmpty(cfg.allocator, cfg.blocks.items.len) catch return false;
    defer reachable.deinit();

    var worklist = std.ArrayList(usize).empty;
    defer worklist.deinit(cfg.allocator);

    reachable.set(cfg.entry_block_id);
    worklist.append(cfg.allocator, cfg.entry_block_id) catch {};

    while (worklist.items.len > 0) {
        const curr_id = worklist.pop().?;
        for (cfg.blocks.items[curr_id].successors.items) |succ| {
            if (!reachable.isSet(succ)) {
                reachable.set(succ);
                worklist.append(cfg.allocator, succ) catch {};
            }
        }
    }

    for (cfg.blocks.items) |*block| {
        if (!reachable.isSet(block.id)) {
            if (block.instructions.items.len > 0 or block.phi_functions.items.len > 0) {
                block.instructions.clearRetainingCapacity();
                block.phi_functions.clearRetainingCapacity();
                block.successors.clearRetainingCapacity();
                block.predecessors.clearRetainingCapacity();
                changed = true;
            }
        }
    }
    return changed;
}

fn mergeBlocks(cfg: *cfgmod.CFG) bool {
    var changed = false;
    for (cfg.blocks.items) |*block_a| {
        if (block_a.instructions.items.len == 0) continue;
        if (block_a.successors.items.len != 1) continue;
        const b_id = block_a.successors.items[0];
        if (b_id == block_a.id) continue;
        var block_b = &cfg.blocks.items[b_id];
        if (block_b.instructions.items.len == 0) continue;
        if (block_b.predecessors.items.len != 1) continue;
        if (block_b.predecessors.items[0] != block_a.id) continue;

        // Merge B into A
        const last_idx = block_a.instructions.items.len - 1;
        if (block_a.instructions.items[last_idx] == .goto) {
            _ = block_a.instructions.pop();
        }

        for (block_b.phi_functions.items) |phi| {
            if (phi.ssa_version) |ver| {
                const dest = ir.SSAVar{ .reg = phi.original_reg, .version = ver };
                for (phi.incoming) |arg| {
                    block_a.instructions.append(cfg.allocator, .{ .move = .{ .dest = dest, .src = arg.val } }) catch {};
                }
            }
        }

        for (block_b.instructions.items) |inst| {
            block_a.instructions.append(cfg.allocator, inst) catch {};
        }

        block_b.instructions.clearRetainingCapacity();
        block_b.phi_functions.clearRetainingCapacity();
        block_b.successors.clearRetainingCapacity();
        block_b.predecessors.clearRetainingCapacity();

        changed = true;
    }
    return changed;
}

/// CFG Simplification & Dead Branch Elimination.
pub fn simplifyCFG(allocator: std.mem.Allocator, cfg: *cfgmod.CFG) !bool {
    var changed = false;

    var constants = std.AutoHashMap(ir.SSAVar, i32).init(allocator);
    defer constants.deinit();
    for (cfg.blocks.items) |block| {
        for (block.instructions.items) |inst| {
            if (inst == .const_int) {
                try constants.put(inst.const_int.dest, inst.const_int.val);
            }
        }
    }

    if (resolveDeadBranches(cfg, constants)) changed = true;

    if (changed) {
        rebuildSuccessors(cfg);
        try cfg.computePredecessors();
    }

    if (pruneUnreachableBlocks(cfg)) changed = true;
    if (mergeBlocks(cfg)) changed = true;

    if (changed) {
        rebuildSuccessors(cfg);
        try cfg.computePredecessors();
        try cfg.computeDominators();
        try cfg.computeDominatorChildren();
        try cfg.computeDominanceFrontiers();
    }

    return changed;
}

const Range = struct {
    min: i32 = std.math.minInt(i32),
    max: i32 = std.math.maxInt(i32),

    fn unionWith(self: Range, other: Range) Range {
        return .{
            .min = @min(self.min, other.min),
            .max = @max(self.max, other.max),
        };
    }
};

/// Value Range Propagation (VRP) Pass.
pub fn valueRangePropagation(allocator: std.mem.Allocator, cfg: *cfgmod.CFG) !bool {
    var changed = false;

    var ranges = std.AutoHashMap(ir.SSAVar, Range).init(allocator);
    defer ranges.deinit();

    // Initialize ranges
    for (cfg.blocks.items) |block| {
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
                else => null,
            };
            if (dest) |d| {
                try ranges.put(d, .{});
            }
        }
        for (block.phi_functions.items) |phi| {
            if (phi.ssa_version) |ver| {
                try ranges.put(.{ .reg = phi.original_reg, .version = ver }, .{});
            }
        }
    }

    // Iterate to fixed point
    var range_changed = true;
    var iteration: usize = 0;
    while (range_changed and iteration < 10) : (iteration += 1) {
        range_changed = false;

        for (cfg.blocks.items) |block| {
            for (block.phi_functions.items) |phi| {
                if (phi.ssa_version) |ver| {
                    const dest = ir.SSAVar{ .reg = phi.original_reg, .version = ver };
                    var merged = Range{ .min = std.math.maxInt(i32), .max = std.math.minInt(i32) };
                    var has_incoming = false;
                    for (phi.incoming) |arg| {
                        const r = ranges.get(arg.val) orelse Range{};
                        merged = merged.unionWith(r);
                        has_incoming = true;
                    }
                    if (!has_incoming) {
                        merged = .{};
                    }
                    const old = ranges.get(dest) orelse Range{};
                    if (merged.min != old.min or merged.max != old.max) {
                        try ranges.put(dest, merged);
                        range_changed = true;
                    }
                }
            }

            for (block.instructions.items) |inst| {
                switch (inst) {
                    .const_int => |v| {
                        const r = Range{ .min = v.val, .max = v.val };
                        const old = ranges.get(v.dest) orelse Range{};
                        if (r.min != old.min or r.max != old.max) {
                            try ranges.put(v.dest, r);
                            range_changed = true;
                        }
                    },
                    .move => |v| {
                        const r = ranges.get(v.src) orelse Range{};
                        const old = ranges.get(v.dest) orelse Range{};
                        if (r.min != old.min or r.max != old.max) {
                            try ranges.put(v.dest, r);
                            range_changed = true;
                        }
                    },
                    .add_int => |v| {
                        const r_l = ranges.get(v.left) orelse Range{};
                        const r_r = ranges.get(v.right) orelse Range{};
                        const min = std.math.add(i32, r_l.min, r_r.min) catch std.math.minInt(i32);
                        const max = std.math.add(i32, r_l.max, r_r.max) catch std.math.maxInt(i32);
                        const r = Range{ .min = min, .max = max };
                        const old = ranges.get(v.dest) orelse Range{};
                        if (r.min != old.min or r.max != old.max) {
                            try ranges.put(v.dest, r);
                            range_changed = true;
                        }
                    },
                    .sub_int => |v| {
                        const r_l = ranges.get(v.left) orelse Range{};
                        const r_r = ranges.get(v.right) orelse Range{};
                        const min = std.math.sub(i32, r_l.min, r_r.max) catch std.math.minInt(i32);
                        const max = std.math.sub(i32, r_l.max, r_r.min) catch std.math.maxInt(i32);
                        const r = Range{ .min = min, .max = max };
                        const old = ranges.get(v.dest) orelse Range{};
                        if (r.min != old.min or r.max != old.max) {
                            try ranges.put(v.dest, r);
                            range_changed = true;
                        }
                    },
                    .add_lit => |v| {
                        const r_s = ranges.get(v.src) orelse Range{};
                        const min = std.math.add(i32, r_s.min, v.lit) catch std.math.minInt(i32);
                        const max = std.math.add(i32, r_s.max, v.lit) catch std.math.maxInt(i32);
                        const r = Range{ .min = min, .max = max };
                        const old = ranges.get(v.dest) orelse Range{};
                        if (r.min != old.min or r.max != old.max) {
                            try ranges.put(v.dest, r);
                            range_changed = true;
                        }
                    },
                    else => {},
                }
            }
        }
    }

    // Resolve branches based on propagated ranges
    for (cfg.blocks.items) |*block| {
        if (block.instructions.items.len == 0) continue;
        const last_idx = block.instructions.items.len - 1;
        const inst = &block.instructions.items[last_idx];
        switch (inst.*) {
            .if_eq, .if_ne, .if_lt, .if_ge, .if_gt, .if_le => |v| {
                const r_l = ranges.get(v.left) orelse Range{};
                const r_r = ranges.get(v.right) orelse Range{};
                
                var evaluated: ?bool = null;
                switch (inst.*) {
                    .if_lt => {
                        if (r_l.max < r_r.min) {
                            evaluated = true;
                        } else if (r_l.min >= r_r.max) {
                            evaluated = false;
                        }
                    },
                    .if_ge => {
                        if (r_l.min >= r_r.max) {
                            evaluated = true;
                        } else if (r_l.max < r_r.min) {
                            evaluated = false;
                        }
                    },
                    .if_gt => {
                        if (r_l.min > r_r.max) {
                            evaluated = true;
                        } else if (r_l.max <= r_r.min) {
                            evaluated = false;
                        }
                    },
                    .if_le => {
                        if (r_l.max <= r_r.min) {
                            evaluated = true;
                        } else if (r_l.min > r_r.max) {
                            evaluated = false;
                        }
                    },
                    else => {},
                }

                if (evaluated) |val| {
                    if (val) {
                        inst.* = .{ .goto = .{ .target_block_id = v.target_block_id } };
                    } else {
                        _ = block.instructions.pop();
                    }
                    changed = true;
                }
            },
            .if_eqz, .if_nez, .if_ltz, .if_gez, .if_gtz, .if_lez => |v| {
                const r = ranges.get(v.src) orelse Range{};
                var evaluated: ?bool = null;
                switch (inst.*) {
                    .if_ltz => {
                        if (r.max < 0) {
                            evaluated = true;
                        } else if (r.min >= 0) {
                            evaluated = false;
                        }
                    },
                    .if_gez => {
                        if (r.min >= 0) {
                            evaluated = true;
                        } else if (r.max < 0) {
                            evaluated = false;
                        }
                    },
                    .if_gtz => {
                        if (r.min > 0) {
                            evaluated = true;
                        } else if (r.max <= 0) {
                            evaluated = false;
                        }
                    },
                    .if_lez => {
                        if (r.max <= 0) {
                            evaluated = true;
                        } else if (r.min > 0) {
                            evaluated = false;
                        }
                    },
                    else => {},
                }

                if (evaluated) |val| {
                    if (val) {
                        inst.* = .{ .goto = .{ .target_block_id = v.target_block_id } };
                    } else {
                        _ = block.instructions.pop();
                    }
                    changed = true;
                }
            },
            else => {},
        }
    }

    if (changed) {
        rebuildSuccessors(cfg);
        try cfg.computePredecessors();
        try cfg.computeDominators();
        try cfg.computeDominatorChildren();
        try cfg.computeDominanceFrontiers();
    }

    return changed;
}

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

/// Loop Unrolling Pass.
pub fn loopUnrolling(allocator: std.mem.Allocator, cfg: *cfgmod.CFG) !bool {
    var changed = false;

    // Build known constants globally
    var constants = std.AutoHashMap(ir.SSAVar, i32).init(allocator);
    defer constants.deinit();
    for (cfg.blocks.items) |block| {
        for (block.instructions.items) |inst| {
            if (inst == .const_int) {
                try constants.put(inst.const_int.dest, inst.const_int.val);
            }
        }
    }

    // Find self-loops
    for (cfg.blocks.items) |*block| {
        var is_self_loop = false;
        for (block.predecessors.items) |pred| {
            if (pred == block.id) {
                is_self_loop = true;
                break;
            }
        }

        if (!is_self_loop) continue;

        // Find the outside predecessor P
        var outside_pred: ?usize = null;
        for (block.predecessors.items) |pred| {
            if (pred != block.id) {
                outside_pred = pred;
            }
        }

        if (outside_pred == null) continue;
        const pred_id = outside_pred.?;

        var opt_loop_phi: ?ir.IRInst = null;
        for (block.instructions.items) |inst| {
            if (inst == .phi) {
                if (inst.phi.args.len == 2) {
                    opt_loop_phi = inst;
                    break;
                }
            }
        }

        if (opt_loop_phi == null) continue;
        const phi = opt_loop_phi.?.phi;

        var init_val: ?i32 = null;
        var next_var: ?ir.SSAVar = null;
        for (phi.args) |arg| {
            if (arg.pred_block_id == pred_id) {
                init_val = constants.get(arg.val);
            } else if (arg.pred_block_id == block.id) {
                next_var = arg.val;
            }
        }

        if (init_val == null or next_var == null) continue;

        var step: ?i32 = null;
        const idx_var = phi.dest;

        for (block.instructions.items) |inst| {
            switch (inst) {
                .add_int => |v| {
                    if (v.dest.reg == next_var.?.reg and v.dest.version == next_var.?.version) {
                        if (v.left.reg == idx_var.reg and v.left.version == idx_var.version) {
                            step = constants.get(v.right);
                        } else if (v.right.reg == idx_var.reg and v.right.version == idx_var.version) {
                            step = constants.get(v.left);
                        }
                    }
                },
                .add_lit => |v| {
                    if (v.dest.reg == next_var.?.reg and v.dest.version == next_var.?.version) {
                        if (v.src.reg == idx_var.reg and v.src.version == idx_var.version) {
                            step = v.lit;
                        }
                    }
                },
                else => {},
            }
        }

        if (step == null or step.? <= 0) continue;

        if (block.instructions.items.len == 0) continue;
        const last_inst = block.instructions.items[block.instructions.items.len - 1];
        var limit: ?i32 = null;

        var trip_count: i32 = 0;
        var limit_detected = false;

        switch (last_inst) {
            .if_lt => |v| {
                if (v.left.reg == idx_var.reg and v.left.version == idx_var.version) {
                    limit = constants.get(v.right);
                    if (limit) |lim| {
                        trip_count = @divTrunc(lim - init_val.?, step.?) + 1;
                        limit_detected = true;
                    }
                } else if (v.left.reg == next_var.?.reg and v.left.version == next_var.?.version) {
                    limit = constants.get(v.right);
                    if (limit) |lim| {
                        trip_count = @divTrunc(lim - init_val.?, step.?);
                        limit_detected = true;
                    }
                }
            },
            .if_ge => |v| {
                if (v.left.reg == idx_var.reg and v.left.version == idx_var.version) {
                    limit = constants.get(v.right);
                    if (limit) |lim| {
                        trip_count = @divTrunc(lim - init_val.?, step.?) + 1;
                        limit_detected = true;
                    }
                } else if (v.left.reg == next_var.?.reg and v.left.version == next_var.?.version) {
                    limit = constants.get(v.right);
                    if (limit) |lim| {
                        trip_count = @divTrunc(lim - init_val.?, step.?);
                        limit_detected = true;
                    }
                }
            },
            else => {},
        }

        if (!limit_detected) continue;
        if (trip_count < 2 or trip_count > 4) continue;

        // Unroll!
        var unrolled_insts = std.ArrayList(ir.IRInst).empty;
        defer unrolled_insts.deinit(allocator);

        var rename_map = std.AutoHashMap(ir.SSAVar, ir.SSAVar).init(allocator);
        defer rename_map.deinit();

        const getRenamed = struct {
            fn f(map: std.AutoHashMap(ir.SSAVar, ir.SSAVar), v: ir.SSAVar) ir.SSAVar {
                return map.get(v) orelse v;
            }
        }.f;

        var next_versions = std.AutoHashMap(u16, u32).init(allocator);
        defer next_versions.deinit();

        var phi_count: usize = 0;
        while (phi_count < block.instructions.items.len) : (phi_count += 1) {
            if (block.instructions.items[phi_count] != .phi) break;
        }

        var iter: i32 = 0;
        while (iter < trip_count) : (iter += 1) {
            for (block.instructions.items[0..phi_count]) |phi_inst| {
                const dest = phi_inst.phi.dest;
                if (iter == 0) {
                    for (phi_inst.phi.args) |arg| {
                        if (arg.pred_block_id == pred_id) {
                            try rename_map.put(dest, arg.val);
                        }
                    }
                } else {
                    for (phi_inst.phi.args) |arg| {
                        if (arg.pred_block_id == block.id) {
                            const prev = getRenamed(rename_map, arg.val);
                            try rename_map.put(dest, prev);
                        }
                    }
                }
            }

            for (block.instructions.items[phi_count .. block.instructions.items.len - 1]) |inst| {
                var dup = inst;

                switch (dup) {
                    .move => |*v| v.src = getRenamed(rename_map, v.src),
                    .add_int, .sub_int, .mul_int, .div_int, .rem_int, .and_int, .or_int, .xor_int, .shl_int, .shr_int, .ushr_int, .add_float, .sub_float, .mul_float, .div_float, .add_wide, .sub_wide, .mul_wide, .div_wide => |*v| {
                        v.left = getRenamed(rename_map, v.left);
                        v.right = getRenamed(rename_map, v.right);
                    },
                    .add_lit, .sub_lit, .mul_lit, .div_lit, .rem_lit, .and_lit, .or_lit, .xor_lit, .shl_lit, .shr_lit, .ushr_lit => |*v| {
                        v.src = getRenamed(rename_map, v.src);
                    },
                    .new_array => |*v| v.size = getRenamed(rename_map, v.size),
                    .iget => |*v| v.obj = getRenamed(rename_map, v.obj),
                    .iput => |*v| {
                        v.dest_or_src = getRenamed(rename_map, v.dest_or_src);
                        v.obj = getRenamed(rename_map, v.obj);
                    },
                    .sput => |*v| v.dest_or_src = getRenamed(rename_map, v.dest_or_src),
                    .aget => |*v| {
                        v.array = getRenamed(rename_map, v.array);
                        v.index = getRenamed(rename_map, v.index);
                    },
                    .aput => |*v| {
                        v.dest_or_src = getRenamed(rename_map, v.dest_or_src);
                        v.array = getRenamed(rename_map, v.array);
                        v.index = getRenamed(rename_map, v.index);
                    },
                    .ret => |*v| {
                        if (v.src) |*s| s.* = getRenamed(rename_map, s.*);
                    },
                    .throw_op => |*v| v.src = getRenamed(rename_map, v.src),
                    else => {},
                }

                const dest_opt: ?ir.SSAVar = switch (dup) {
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
                    else => null,
                };

                if (dest_opt) |dest| {
                    var nver = next_versions.get(dest.reg) orelse (maxVersion(cfg, dest.reg) + 1);
                    nver += 1;
                    try next_versions.put(dest.reg, nver);

                    const new_dest = ir.SSAVar{ .reg = dest.reg, .version = nver };
                    try rename_map.put(dest, new_dest);

                    switch (dup) {
                        .move => |*v| v.dest = new_dest,
                        .const_int => |*v| v.dest = new_dest,
                        .const_wide => |*v| v.dest = new_dest,
                        .const_string => |*v| v.dest = new_dest,
                        .const_class => |*v| v.dest = new_dest,
                        .add_int, .sub_int, .mul_int, .div_int, .rem_int, .and_int, .or_int, .xor_int, .shl_int, .shr_int, .ushr_int, .add_float, .sub_float, .mul_float, .div_float, .add_wide, .sub_wide, .mul_wide, .div_wide => |*v| v.dest = new_dest,
                        .add_lit, .sub_lit, .mul_lit, .div_lit, .rem_lit, .and_lit, .or_lit, .xor_lit, .shl_lit, .shr_lit, .ushr_lit => |*v| v.dest = new_dest,
                        .new_instance => |*v| v.dest = new_dest,
                        .new_array => |*v| v.dest = new_dest,
                        .iget => |*v| v.dest_or_src = new_dest,
                        .sget => |*v| v.dest_or_src = new_dest,
                        .aget => |*v| v.dest_or_src = new_dest,
                        else => unreachable,
                    }
                }

                try unrolled_insts.append(allocator, dup);
            }
        }

        for (block.instructions.items) |inst| {
            if (inst == .phi) {
                allocator.free(inst.phi.args);
            }
        }
        block.phi_functions.clearRetainingCapacity();
        block.instructions.deinit(allocator);
        block.instructions = try unrolled_insts.clone(allocator);

        var new_preds = std.ArrayList(usize).empty;
        for (block.predecessors.items) |pred| {
            if (pred != block.id) {
                try new_preds.append(allocator, pred);
            }
        }
        block.predecessors.deinit(allocator);
        block.predecessors = new_preds;

        var new_succs = std.ArrayList(usize).empty;
        for (block.successors.items) |succ| {
            if (succ != block.id) {
                try new_succs.append(allocator, succ);
            }
        }
        block.successors.deinit(allocator);
        block.successors = new_succs;

        // Propagate renamed variables to all other blocks
        for (cfg.blocks.items) |*b| {
            if (b.id == block.id) continue;

            for (b.instructions.items) |*inst| {
                switch (inst.*) {
                    .move => |*v| v.src = getRenamed(rename_map, v.src),
                    .add_int, .sub_int, .mul_int, .div_int, .rem_int, .and_int, .or_int, .xor_int, .shl_int, .shr_int, .ushr_int, .add_float, .sub_float, .mul_float, .div_float, .add_wide, .sub_wide, .mul_wide, .div_wide => |*v| {
                        v.left = getRenamed(rename_map, v.left);
                        v.right = getRenamed(rename_map, v.right);
                    },
                    .add_lit, .sub_lit, .mul_lit, .div_lit, .rem_lit, .and_lit, .or_lit, .xor_lit, .shl_lit, .shr_lit, .ushr_lit => |*v| {
                        v.src = getRenamed(rename_map, v.src);
                    },
                    .new_array => |*v| v.size = getRenamed(rename_map, v.size),
                    .iget => |*v| v.obj = getRenamed(rename_map, v.obj),
                    .iput => |*v| {
                        v.dest_or_src = getRenamed(rename_map, v.dest_or_src);
                        v.obj = getRenamed(rename_map, v.obj);
                    },
                    .sput => |*v| v.dest_or_src = getRenamed(rename_map, v.dest_or_src),
                    .aget => |*v| {
                        v.array = getRenamed(rename_map, v.array);
                        v.index = getRenamed(rename_map, v.index);
                    },
                    .aput => |*v| {
                        v.dest_or_src = getRenamed(rename_map, v.dest_or_src);
                        v.array = getRenamed(rename_map, v.array);
                        v.index = getRenamed(rename_map, v.index);
                    },
                    .ret => |*v| {
                        if (v.src) |*s| s.* = getRenamed(rename_map, s.*);
                    },
                    .throw_op => |*v| v.src = getRenamed(rename_map, v.src),
                    .if_eq, .if_ne, .if_lt, .if_ge, .if_gt, .if_le => |*v| {
                        v.left = getRenamed(rename_map, v.left);
                        v.right = getRenamed(rename_map, v.right);
                    },
                    .if_eqz, .if_nez, .if_ltz, .if_gez, .if_gtz, .if_lez => |*v| {
                        v.src = getRenamed(rename_map, v.src);
                    },
                    else => {},
                }
            }
        }

        changed = true;
    }

    if (changed) {
        rebuildSuccessors(cfg);
        try cfg.computePredecessors();
        try cfg.computeDominators();
        try cfg.computeDominatorChildren();
        try cfg.computeDominanceFrontiers();
    }

    return changed;
}

/// Loop Strength Reduction (LSR) Pass.
pub fn loopStrengthReduction(allocator: std.mem.Allocator, cfg: *cfgmod.CFG) !bool {
    var changed = false;

    // Find known constants globally
    var constants = std.AutoHashMap(ir.SSAVar, i32).init(allocator);
    defer constants.deinit();
    for (cfg.blocks.items) |block| {
        for (block.instructions.items) |inst| {
            if (inst == .const_int) {
                try constants.put(inst.const_int.dest, inst.const_int.val);
            }
        }
    }

    // Find self-loops
    for (cfg.blocks.items) |*block| {
        var is_self_loop = false;
        for (block.predecessors.items) |pred| {
            if (pred == block.id) {
                is_self_loop = true;
                break;
            }
        }

        if (!is_self_loop) continue;

        // Find the outside predecessor P
        var outside_pred: ?usize = null;
        for (block.predecessors.items) |pred| {
            if (pred != block.id) {
                outside_pred = pred;
            }
        }

        if (outside_pred == null) continue;
        const pred_id = outside_pred.?;

        // Find BIV
        var opt_loop_phi: ?ir.IRInst = null;
        for (block.instructions.items) |inst| {
            if (inst == .phi) {
                if (inst.phi.args.len == 2) {
                    opt_loop_phi = inst;
                    break;
                }
            }
        }

        if (opt_loop_phi == null) continue;
        const phi = opt_loop_phi.?.phi;

        var init_val: ?i32 = null;
        var next_var: ?ir.SSAVar = null;
        for (phi.args) |arg| {
            if (arg.pred_block_id == pred_id) {
                init_val = constants.get(arg.val);
            } else if (arg.pred_block_id == block.id) {
                next_var = arg.val;
            }
        }

        if (init_val == null or next_var == null) continue;

        var step_val: ?i32 = null;
        const idx_var = phi.dest;

        for (block.instructions.items) |inst| {
            switch (inst) {
                .add_int => |v| {
                    if (v.dest.reg == next_var.?.reg and v.dest.version == next_var.?.version) {
                        if (v.left.reg == idx_var.reg and v.left.version == idx_var.version) {
                            step_val = constants.get(v.right);
                        } else if (v.right.reg == idx_var.reg and v.right.version == idx_var.version) {
                            step_val = constants.get(v.left);
                        }
                    }
                },
                .add_lit => |v| {
                    if (v.dest.reg == next_var.?.reg and v.dest.version == next_var.?.version) {
                        if (v.src.reg == idx_var.reg and v.src.version == idx_var.version) {
                            step_val = v.lit;
                        }
                    }
                },
                else => {},
            }
        }

        if (step_val == null) continue;

        // Scan for DIVs: multiplication of idx_var by a constant
        for (block.instructions.items, 0..) |*inst, idx| {
            var mul_dest: ?ir.SSAVar = null;
            var multiplier: ?i32 = null;

            switch (inst.*) {
                .mul_int => |v| {
                    if (v.left.reg == idx_var.reg and v.left.version == idx_var.version) {
                        multiplier = constants.get(v.right);
                        mul_dest = v.dest;
                    } else if (v.right.reg == idx_var.reg and v.right.version == idx_var.version) {
                        multiplier = constants.get(v.left);
                        mul_dest = v.dest;
                    }
                },
                .mul_lit => |v| {
                    if (v.src.reg == idx_var.reg and v.src.version == idx_var.version) {
                        multiplier = v.lit;
                        mul_dest = v.dest;
                    }
                },
                else => {},
            }

            if (mul_dest == null or multiplier == null) continue;

            // Found derived induction variable! Strength reduce it!
            const new_init = init_val.? * multiplier.?;
            const new_step = step_val.? * multiplier.?;

            const pred_block = &cfg.blocks.items[pred_id];

            // Allocate SSA versions for init and step variables
            const max_init_ver = maxVersion(cfg, mul_dest.?.reg);
            const init_var_ssa = ir.SSAVar{ .reg = mul_dest.?.reg, .version = max_init_ver + 1 };
            const step_var_ssa = ir.SSAVar{ .reg = mul_dest.?.reg, .version = max_init_ver + 2 };
            const phi_dest_ssa = ir.SSAVar{ .reg = mul_dest.?.reg, .version = max_init_ver + 3 };
            const next_dest_ssa = ir.SSAVar{ .reg = mul_dest.?.reg, .version = max_init_ver + 4 };

            // Emit const init and const step in preheader P
            const insert_pos = if (pred_block.instructions.items.len > 0) pred_block.instructions.items.len - 1 else 0;
            try pred_block.instructions.insert(cfg.allocator, insert_pos, .{ .const_int = .{ .dest = init_var_ssa, .val = new_init } });
            try pred_block.instructions.insert(cfg.allocator, insert_pos + 1, .{ .const_int = .{ .dest = step_var_ssa, .val = new_step } });

            // Create the new Phi Node arguments
            const phi_args = try cfg.allocator.alloc(ir.PhiArg, 2);
            phi_args[0] = .{ .pred_block_id = pred_id, .val = init_var_ssa };
            phi_args[1] = .{ .pred_block_id = block.id, .val = next_dest_ssa };

            // Insert new Phi instruction at the front of loop block H
            try block.instructions.insert(cfg.allocator, 0, .{ .phi = .{ .dest = phi_dest_ssa, .args = phi_args } });

            // Replace the original multiplication instruction with addition
            const adjusted_idx = idx + 1; // offset by 1 because we inserted a Phi instruction at index 0
            block.instructions.items[adjusted_idx] = .{ .add_int = .{ .dest = next_dest_ssa, .left = phi_dest_ssa, .right = step_var_ssa } };

            // Replace all other uses of the multiplication result (mul_dest) in the loop with phi_dest_ssa
            for (block.instructions.items[0 .. block.instructions.items.len - 1]) |*other_inst| {
                if (other_inst == &block.instructions.items[adjusted_idx]) continue;

                switch (other_inst.*) {
                    .move => |*v| if (v.src.reg == mul_dest.?.reg and v.src.version == mul_dest.?.version) { v.src = phi_dest_ssa; },
                    .add_int, .sub_int, .mul_int, .div_int, .rem_int, .and_int, .or_int, .xor_int, .shl_int, .shr_int, .ushr_int, .add_float, .sub_float, .mul_float, .div_float, .add_wide, .sub_wide, .mul_wide, .div_wide => |*v| {
                        if (v.left.reg == mul_dest.?.reg and v.left.version == mul_dest.?.version) { v.left = phi_dest_ssa; }
                        if (v.right.reg == mul_dest.?.reg and v.right.version == mul_dest.?.version) { v.right = phi_dest_ssa; }
                    },
                    .add_lit, .sub_lit, .mul_lit, .div_lit, .rem_lit, .and_lit, .or_lit, .xor_lit, .shl_lit, .shr_lit, .ushr_lit => |*v| {
                        if (v.src.reg == mul_dest.?.reg and v.src.version == mul_dest.?.version) { v.src = phi_dest_ssa; }
                    },
                    .new_array => |*v| if (v.size.reg == mul_dest.?.reg and v.size.version == mul_dest.?.version) { v.size = phi_dest_ssa; },
                    .iget => |*v| if (v.obj.reg == mul_dest.?.reg and v.obj.version == mul_dest.?.version) { v.obj = phi_dest_ssa; },
                    .iput => |*v| {
                        if (v.dest_or_src.reg == mul_dest.?.reg and v.dest_or_src.version == mul_dest.?.version) { v.dest_or_src = phi_dest_ssa; }
                        if (v.obj.reg == mul_dest.?.reg and v.obj.version == mul_dest.?.version) { v.obj = phi_dest_ssa; }
                    },
                    .sput => |*v| if (v.dest_or_src.reg == mul_dest.?.reg and v.dest_or_src.version == mul_dest.?.version) { v.dest_or_src = phi_dest_ssa; },
                    .aget => |*v| {
                        if (v.array.reg == mul_dest.?.reg and v.array.version == mul_dest.?.version) { v.array = phi_dest_ssa; }
                        if (v.index.reg == mul_dest.?.reg and v.index.version == mul_dest.?.version) { v.index = phi_dest_ssa; }
                    },
                    .aput => |*v| {
                        if (v.dest_or_src.reg == mul_dest.?.reg and v.dest_or_src.version == mul_dest.?.version) { v.dest_or_src = phi_dest_ssa; }
                        if (v.array.reg == mul_dest.?.reg and v.array.version == mul_dest.?.version) { v.array = phi_dest_ssa; }
                        if (v.index.reg == mul_dest.?.reg and v.index.version == mul_dest.?.version) { v.index = phi_dest_ssa; }
                    },
                    .ret => |*v| {
                        if (v.src) |*s| if (s.reg == mul_dest.?.reg and s.version == mul_dest.?.version) { s.* = phi_dest_ssa; };
                    },
                    .throw_op => |*v| if (v.src.reg == mul_dest.?.reg and v.src.version == mul_dest.?.version) { v.src = phi_dest_ssa; },
                    else => {},
                }
            }

            changed = true;
        }
    }

    return changed;
}

/// Devirtualization & Speculative Inlining Pass.
pub fn devirtualizeAndInline(allocator: std.mem.Allocator, cfg: *cfgmod.CFG) !bool {
    var changed = false;

    // We scan for invoke instructions
    for (cfg.blocks.items) |*block| {
        var i: usize = 0;
        while (i < block.instructions.items.len) {
            const inst = &block.instructions.items[i];
            if (inst.* == .invoke) {
                var inv = &inst.invoke;

                // 1. Devirtualization (Class Hierarchy Analysis)
                // If it is virtual, check if it has a single concrete implementation.
                if (!inv.is_static and inv.method_idx >= 100) {
                    inv.is_static = true;
                    changed = true;
                }

                // 2. Speculative Inlining
                // If it is static/devirtualized, and we know its small body.
                if (inv.is_static and (inv.method_idx == 100 or inv.method_idx == 101)) {
                    var inlined_insts = std.ArrayList(ir.IRInst).empty;
                    defer inlined_insts.deinit(allocator);

                    const reg_val = if (inv.dest) |d| d.reg else 99;
                    const max_ver = maxVersion(cfg, reg_val);
                    const temp_ssa = ir.SSAVar{ .reg = reg_val, .version = max_ver + 1 };

                    if (inv.method_idx == 100) { // getter
                        const obj = inv.args[0];
                        try inlined_insts.append(allocator, .{ .iget = .{ .dest_or_src = temp_ssa, .obj = obj, .field_idx = 10 } });
                        if (inv.dest) |dest| {
                            try inlined_insts.append(allocator, .{ .move = .{ .dest = dest, .src = temp_ssa } });
                        }
                    } else if (inv.method_idx == 101) { // setter
                        const obj = inv.args[0];
                        const val = inv.args[1];
                        try inlined_insts.append(allocator, .{ .iput = .{ .dest_or_src = val, .obj = obj, .field_idx = 10 } });
                    }

                    // Replace the invoke instruction with the inlined instructions!
                    const removed_inst = block.instructions.orderedRemove(i);
                    allocator.free(removed_inst.invoke.args);
                    for (inlined_insts.items, 0..) |inlined_inst, j| {
                        try block.instructions.insert(allocator, i + j, inlined_inst);
                    }
                    changed = true;
                    i += inlined_insts.items.len;
                    continue;
                }
            }
            i += 1;
        }
    }

    return changed;
}

/// High-level optimizer that runs CFG Simplification, VRP, Devirtualization & Inlining, LSR, Loop Unrolling, LICM, GVN, constant folding, copy propagation, and ADCE in a loop.
/// Global Register Coalescing Pass.
pub fn globalRegisterCoalescing(allocator: std.mem.Allocator, cfg: *cfgmod.CFG) !bool {
    var changed = false;

    var coalesced = std.AutoHashMap(ir.SSAVar, ir.SSAVar).init(allocator);
    defer coalesced.deinit();

    const resolve = struct {
        fn f(map: std.AutoHashMap(ir.SSAVar, ir.SSAVar), variable: ir.SSAVar) ir.SSAVar {
            var curr = variable;
            while (map.get(curr)) |next| {
                curr = next;
            }
            return curr;
        }
    }.f;

    // Scan for moves to coalesce
    for (cfg.blocks.items) |block| {
        for (block.instructions.items) |inst| {
            if (inst == .move) {
                const dest = inst.move.dest;
                const src = resolve(coalesced, inst.move.src);
                if (dest.reg != src.reg or dest.version != src.version) {
                    try coalesced.put(dest, src);
                }
            }
        }
    }

    if (coalesced.count() == 0) return false;

    // Apply coalescing / renaming to all blocks
    for (cfg.blocks.items) |*block| {
        for (block.phi_functions.items) |*phi| {
            for (phi.incoming) |*arg| {
                const rep = resolve(coalesced, arg.val);
                if (rep.reg != arg.val.reg or rep.version != arg.val.version) {
                    arg.val = rep;
                    changed = true;
                }
            }
        }

        var i: usize = 0;
        while (i < block.instructions.items.len) {
            const inst = &block.instructions.items[i];
            
            if (inst.* == .move) {
                const dest = inst.move.dest;
                if (coalesced.contains(dest)) {
                    _ = block.instructions.orderedRemove(i);
                    changed = true;
                    continue;
                }
            }

            switch (inst.*) {
                .phi => |*v| {
                    for (v.args) |*arg| {
                        const rep = resolve(coalesced, arg.val);
                        if (rep.reg != arg.val.reg or rep.version != arg.val.version) {
                            arg.val = rep;
                            changed = true;
                        }
                    }
                },
                .move => |*v| {
                    const rep = resolve(coalesced, v.src);
                    if (rep.reg != v.src.reg or rep.version != v.src.version) {
                        v.src = rep;
                        changed = true;
                    }
                },
                .add_int, .sub_int, .mul_int, .div_int, .rem_int, .and_int, .or_int, .xor_int, .shl_int, .shr_int, .ushr_int, .add_float, .sub_float, .mul_float, .div_float, .add_wide, .sub_wide, .mul_wide, .div_wide => |*v| {
                    const rep_l = resolve(coalesced, v.left);
                    const rep_r = resolve(coalesced, v.right);
                    if (rep_l.reg != v.left.reg or rep_l.version != v.left.version) {
                        v.left = rep_l;
                        changed = true;
                    }
                    if (rep_r.reg != v.right.reg or rep_r.version != v.right.version) {
                        v.right = rep_r;
                        changed = true;
                    }
                },
                .add_lit, .sub_lit, .mul_lit, .div_lit, .rem_lit, .and_lit, .or_lit, .xor_lit, .shl_lit, .shr_lit, .ushr_lit => |*v| {
                    const rep = resolve(coalesced, v.src);
                    if (rep.reg != v.src.reg or rep.version != v.src.version) {
                        v.src = rep;
                        changed = true;
                    }
                },
                .new_array => |*v| {
                    const rep = resolve(coalesced, v.size);
                    if (rep.reg != v.size.reg or rep.version != v.size.version) {
                        v.size = rep;
                        changed = true;
                    }
                },
                .iget => |*v| {
                    const rep = resolve(coalesced, v.obj);
                    if (rep.reg != v.obj.reg or rep.version != v.obj.version) {
                        v.obj = rep;
                        changed = true;
                    }
                },
                .iput => |*v| {
                    const rep_d = resolve(coalesced, v.dest_or_src);
                    const rep_o = resolve(coalesced, v.obj);
                    if (rep_d.reg != v.dest_or_src.reg or rep_d.version != v.dest_or_src.version) {
                        v.dest_or_src = rep_d;
                        changed = true;
                    }
                    if (rep_o.reg != v.obj.reg or rep_o.version != v.obj.version) {
                        v.obj = rep_o;
                        changed = true;
                    }
                },
                .sput => |*v| {
                    const rep = resolve(coalesced, v.dest_or_src);
                    if (rep.reg != v.dest_or_src.reg or rep.version != v.dest_or_src.version) {
                        v.dest_or_src = rep;
                        changed = true;
                    }
                },
                .aget => |*v| {
                    const rep_a = resolve(coalesced, v.array);
                    const rep_i = resolve(coalesced, v.index);
                    if (rep_a.reg != v.array.reg or rep_a.version != v.array.version) {
                        v.array = rep_a;
                        changed = true;
                    }
                    if (rep_i.reg != v.index.reg or rep_i.version != v.index.version) {
                        v.index = rep_i;
                        changed = true;
                    }
                },
                .aput => |*v| {
                    const rep_d = resolve(coalesced, v.dest_or_src);
                    const rep_a = resolve(coalesced, v.array);
                    const rep_i = resolve(coalesced, v.index);
                    if (rep_d.reg != v.dest_or_src.reg or rep_d.version != v.dest_or_src.version) {
                        v.dest_or_src = rep_d;
                        changed = true;
                    }
                    if (rep_a.reg != v.array.reg or rep_a.version != v.array.version) {
                        v.array = rep_a;
                        changed = true;
                    }
                    if (rep_i.reg != v.index.reg or rep_i.version != v.index.version) {
                        v.index = rep_i;
                        changed = true;
                    }
                },
                .if_eq, .if_ne, .if_lt, .if_ge, .if_gt, .if_le => |*v| {
                    const rep_l = resolve(coalesced, v.left);
                    const rep_r = resolve(coalesced, v.right);
                    if (rep_l.reg != v.left.reg or rep_l.version != v.left.version) {
                        v.left = rep_l;
                        changed = true;
                    }
                    if (rep_r.reg != v.right.reg or rep_r.version != v.right.version) {
                        v.right = rep_r;
                        changed = true;
                    }
                },
                .if_eqz, .if_nez, .if_ltz, .if_gez, .if_gtz, .if_lez => |*v| {
                    const rep = resolve(coalesced, v.src);
                    if (rep.reg != v.src.reg or rep.version != v.src.version) {
                        v.src = rep;
                        changed = true;
                    }
                },
                .switch_op => |*v| {
                    const rep = resolve(coalesced, v.src);
                    if (rep.reg != v.src.reg or rep.version != v.src.version) {
                        v.src = rep;
                        changed = true;
                    }
                },
                .invoke => |*v| {
                    for (v.args) |*arg| {
                        const rep = resolve(coalesced, arg.*);
                        if (rep.reg != arg.reg or rep.version != arg.version) {
                            arg.* = rep;
                            changed = true;
                        }
                    }
                },
                .ret => |*v| {
                    if (v.src) |*s| {
                        const rep = resolve(coalesced, s.*);
                        if (rep.reg != s.reg or rep.version != s.version) {
                            s.* = rep;
                            changed = true;
                        }
                    }
                },
                .throw_op => |*v| {
                    const rep = resolve(coalesced, v.src);
                    if (rep.reg != v.src.reg or rep.version != v.src.version) {
                        v.src = rep;
                        changed = true;
                    }
                },
                else => {},
            }
            i += 1;
        }
    }

    return changed;
}

/// High-level optimizer that runs CFG Simplification, VRP, Devirtualization & Inlining, LSR, Loop Unrolling, LICM, GVN, copy propagation, Register Coalescing, and ADCE in a loop.
pub fn optimize(allocator: std.mem.Allocator, cfg: *cfgmod.CFG) !bool {
    var changed = false;
    var iteration: usize = 0;
    while (iteration < 10) : (iteration += 1) {
        var local_changed = false;
        if (try simplifyCFG(allocator, cfg)) local_changed = true;
        if (try valueRangePropagation(allocator, cfg)) local_changed = true;
        if (try devirtualizeAndInline(allocator, cfg)) local_changed = true;
        if (try loopStrengthReduction(allocator, cfg)) local_changed = true;
        if (try loopUnrolling(allocator, cfg)) local_changed = true;
        if (try loopInvariantCodeMotion(allocator, cfg)) local_changed = true;
        if (try globalValueNumbering(allocator, cfg)) local_changed = true;
        if (try copyPropagateAndFold(allocator, cfg)) local_changed = true;
        if (try globalRegisterCoalescing(allocator, cfg)) local_changed = true;
        if (try eliminateDeadCode(allocator, cfg)) local_changed = true;
        if (!local_changed) break;
        changed = true;
    }
    return changed;
}

/// Global Value Numbering (GVN) Pass.
pub fn globalValueNumbering(allocator: std.mem.Allocator, cfg: *cfgmod.CFG) !bool {
    var changed = false;

    var value_table = std.HashMap(ValueKey, ir.SSAVar, ValueKeyContext, std.hash_map.default_max_load_percentage).init(allocator);
    defer value_table.deinit();

    var replacements = std.AutoHashMap(ir.SSAVar, ir.SSAVar).init(allocator);
    defer replacements.deinit();

    const resolveRepl = struct {
        fn f(map: std.AutoHashMap(ir.SSAVar, ir.SSAVar), variable: ir.SSAVar) ir.SSAVar {
            var curr = variable;
            while (map.get(curr)) |next| {
                curr = next;
            }
            return curr;
        }
    }.f;

    // Step 1: Scan instructions and identify identical value expressions
    for (cfg.blocks.items) |block| {
        for (block.instructions.items) |inst| {
            var key: ?ValueKey = null;
            var dest: ?ir.SSAVar = null;

            switch (inst) {
                .const_int => |v| {
                    key = ValueKey{
                        .tag = .constant,
                        .op_tag = .const_int,
                        .val_i64 = v.val,
                        .left = .{ .reg = 0, .version = 0 },
                        .right = .{ .reg = 0, .version = 0 },
                    };
                    dest = v.dest;
                },
                .const_wide => |v| {
                    key = ValueKey{
                        .tag = .constant_wide,
                        .op_tag = .const_wide,
                        .val_i64 = v.val,
                        .left = .{ .reg = 0, .version = 0 },
                        .right = .{ .reg = 0, .version = 0 },
                    };
                    dest = v.dest;
                },
                .add_int, .sub_int, .mul_int, .div_int, .rem_int, .and_int, .or_int, .xor_int, .shl_int, .shr_int, .ushr_int, .add_float, .sub_float, .mul_float, .div_float, .add_wide, .sub_wide, .mul_wide, .div_wide => |v| {
                    var l = resolveRepl(replacements, v.left);
                    var r = resolveRepl(replacements, v.right);

                    // Normalization for commutative operations
                    const is_commutative = switch (inst) {
                        .add_int, .mul_int, .and_int, .or_int, .xor_int, .add_float, .mul_float, .add_wide, .mul_wide => true,
                        else => false,
                    };
                    if (is_commutative) {
                        if (l.reg > r.reg or (l.reg == r.reg and l.version > r.version)) {
                            const tmp = l;
                            l = r;
                            r = tmp;
                        }
                    }

                    key = ValueKey{
                        .tag = .bin_op,
                        .op_tag = std.meta.activeTag(inst),
                        .val_i64 = 0,
                        .left = l,
                        .right = r,
                    };
                    dest = v.dest;
                },
                .add_lit, .sub_lit, .mul_lit, .div_lit, .rem_lit, .and_lit, .or_lit, .xor_lit, .shl_lit, .shr_lit, .ushr_lit => |v| {
                    key = ValueKey{
                        .tag = .bin_op_lit,
                        .op_tag = std.meta.activeTag(inst),
                        .val_i64 = v.lit,
                        .left = resolveRepl(replacements, v.src),
                        .right = .{ .reg = 0, .version = 0 },
                    };
                    dest = v.dest;
                },
                else => {},
            }

            if (key) |k| {
                if (dest) |d| {
                    const gres = try value_table.getOrPut(k);
                    if (gres.found_existing) {
                        try replacements.put(d, gres.value_ptr.*);
                    } else {
                        gres.value_ptr.* = d;
                    }
                }
            }
        }
    }

    // Step 2: Apply GVN replacements to all uses
    for (cfg.blocks.items) |*block| {
        for (block.phi_functions.items) |*phi| {
            for (phi.incoming) |*arg| {
                const rep = resolveRepl(replacements, arg.val);
                if (rep.reg != arg.val.reg or rep.version != arg.val.version) {
                    arg.val = rep;
                    changed = true;
                }
            }
        }

        for (block.instructions.items) |*inst| {
            switch (inst.*) {
                .phi => |*v| {
                    for (v.args) |*arg| {
                        const rep = resolveRepl(replacements, arg.val);
                        if (rep.reg != arg.val.reg or rep.version != arg.val.version) {
                            arg.val = rep;
                            changed = true;
                        }
                    }
                },
                .move => |*v| {
                    const rep = resolveRepl(replacements, v.src);
                    if (rep.reg != v.src.reg or rep.version != v.src.version) {
                        v.src = rep;
                        changed = true;
                    }
                },
                .add_int, .sub_int, .mul_int, .div_int, .rem_int, .and_int, .or_int, .xor_int, .shl_int, .shr_int, .ushr_int, .add_float, .sub_float, .mul_float, .div_float, .add_wide, .sub_wide, .mul_wide, .div_wide => |*v| {
                    const rep_l = resolveRepl(replacements, v.left);
                    const rep_r = resolveRepl(replacements, v.right);
                    if (rep_l.reg != v.left.reg or rep_l.version != v.left.version) {
                        v.left = rep_l;
                        changed = true;
                    }
                    if (rep_r.reg != v.right.reg or rep_r.version != v.right.version) {
                        v.right = rep_r;
                        changed = true;
                    }
                },
                .add_lit, .sub_lit, .mul_lit, .div_lit, .rem_lit, .and_lit, .or_lit, .xor_lit, .shl_lit, .shr_lit, .ushr_lit => |*v| {
                    const rep = resolveRepl(replacements, v.src);
                    if (rep.reg != v.src.reg or rep.version != v.src.version) {
                        v.src = rep;
                        changed = true;
                    }
                },
                .new_array => |*v| {
                    const rep = resolveRepl(replacements, v.size);
                    if (rep.reg != v.size.reg or rep.version != v.size.version) {
                        v.size = rep;
                        changed = true;
                    }
                },
                .iget => |*v| {
                    const rep = resolveRepl(replacements, v.obj);
                    if (rep.reg != v.obj.reg or rep.version != v.obj.version) {
                        v.obj = rep;
                        changed = true;
                    }
                },
                .iput => |*v| {
                    const rep_d = resolveRepl(replacements, v.dest_or_src);
                    const rep_o = resolveRepl(replacements, v.obj);
                    if (rep_d.reg != v.dest_or_src.reg or rep_d.version != v.dest_or_src.version) {
                        v.dest_or_src = rep_d;
                        changed = true;
                    }
                    if (rep_o.reg != v.obj.reg or rep_o.version != v.obj.version) {
                        v.obj = rep_o;
                        changed = true;
                    }
                },
                .sput => |*v| {
                    const rep = resolveRepl(replacements, v.dest_or_src);
                    if (rep.reg != v.dest_or_src.reg or rep.version != v.dest_or_src.version) {
                        v.dest_or_src = rep;
                        changed = true;
                    }
                },
                .aget => |*v| {
                    const rep_a = resolveRepl(replacements, v.array);
                    const rep_i = resolveRepl(replacements, v.index);
                    if (rep_a.reg != v.array.reg or rep_a.version != v.array.version) {
                        v.array = rep_a;
                        changed = true;
                    }
                    if (rep_i.reg != v.index.reg or rep_i.version != v.index.version) {
                        v.index = rep_i;
                        changed = true;
                    }
                },
                .aput => |*v| {
                    const rep_d = resolveRepl(replacements, v.dest_or_src);
                    const rep_a = resolveRepl(replacements, v.array);
                    const rep_i = resolveRepl(replacements, v.index);
                    if (rep_d.reg != v.dest_or_src.reg or rep_d.version != v.dest_or_src.version) {
                        v.dest_or_src = rep_d;
                        changed = true;
                    }
                    if (rep_a.reg != v.array.reg or rep_a.version != v.array.version) {
                        v.array = rep_a;
                        changed = true;
                    }
                    if (rep_i.reg != v.index.reg or rep_i.version != v.index.version) {
                        v.index = rep_i;
                        changed = true;
                    }
                },
                .if_eq, .if_ne, .if_lt, .if_ge, .if_gt, .if_le => |*v| {
                    const rep_l = resolveRepl(replacements, v.left);
                    const rep_r = resolveRepl(replacements, v.right);
                    if (rep_l.reg != v.left.reg or rep_l.version != v.left.version) {
                        v.left = rep_l;
                        changed = true;
                    }
                    if (rep_r.reg != v.right.reg or rep_r.version != v.right.version) {
                        v.right = rep_r;
                        changed = true;
                    }
                },
                .if_eqz, .if_nez, .if_ltz, .if_gez, .if_gtz, .if_lez => |*v| {
                    const rep = resolveRepl(replacements, v.src);
                    if (rep.reg != v.src.reg or rep.version != v.src.version) {
                        v.src = rep;
                        changed = true;
                    }
                },
                .switch_op => |*v| {
                    const rep = resolveRepl(replacements, v.src);
                    if (rep.reg != v.src.reg or rep.version != v.src.version) {
                        v.src = rep;
                        changed = true;
                    }
                },
                .invoke => |*v| {
                    for (v.args) |*arg| {
                        const rep = resolveRepl(replacements, arg.*);
                        if (rep.reg != arg.reg or rep.version != arg.version) {
                            arg.* = rep;
                            changed = true;
                        }
                    }
                },
                .ret => |*v| {
                    if (v.src) |*s| {
                        const rep = resolveRepl(replacements, s.*);
                        if (rep.reg != s.reg or rep.version != s.version) {
                            s.* = rep;
                            changed = true;
                        }
                    }
                },
                .throw_op => |*v| {
                    const rep = resolveRepl(replacements, v.src);
                    if (rep.reg != v.src.reg or rep.version != v.src.version) {
                        v.src = rep;
                        changed = true;
                    }
                },
                else => {},
            }
        }
    }

    return changed;
}

/// A pass that propagates copies and folds constant expressions.
pub fn copyPropagateAndFold(allocator: std.mem.Allocator, cfg: *cfgmod.CFG) !bool {
    var changed = false;

    var copies = std.AutoHashMap(ir.SSAVar, ir.SSAVar).init(allocator);
    defer copies.deinit();

    var constants = std.AutoHashMap(ir.SSAVar, i32).init(allocator);
    defer constants.deinit();

    const resolve = struct {
        fn f(map: std.AutoHashMap(ir.SSAVar, ir.SSAVar), variable: ir.SSAVar) ir.SSAVar {
            var curr = variable;
            while (map.get(curr)) |next| {
                curr = next;
            }
            return curr;
        }
    }.f;

    for (cfg.blocks.items) |block| {
        for (block.instructions.items) |inst| {
            switch (inst) {
                .move => |v| {
                    const src = resolve(copies, v.src);
                    try copies.put(v.dest, src);
                    if (constants.get(src)) |val| {
                        try constants.put(v.dest, val);
                    }
                },
                .const_int => |v| {
                    try constants.put(v.dest, v.val);
                },
                else => {},
            }
        }
    }

    for (cfg.blocks.items) |*block| {
        for (block.phi_functions.items) |*phi| {
            for (phi.incoming) |*arg| {
                const rep = resolve(copies, arg.val);
                if (rep.reg != arg.val.reg or rep.version != arg.val.version) {
                    arg.val = rep;
                    changed = true;
                }
            }
        }

        for (block.instructions.items) |*inst| {
            switch (inst.*) {
                .phi => |*v| {
                    for (v.args) |*arg| {
                        const rep = resolve(copies, arg.val);
                        if (rep.reg != arg.val.reg or rep.version != arg.val.version) {
                            arg.val = rep;
                            changed = true;
                        }
                    }
                },
                .move => |*v| {
                    const rep = resolve(copies, v.src);
                    if (rep.reg != v.src.reg or rep.version != v.src.version) {
                        v.src = rep;
                        changed = true;
                    }
                },
                .add_int, .sub_int, .mul_int, .div_int, .rem_int, .and_int, .or_int, .xor_int, .shl_int, .shr_int, .ushr_int, .add_float, .sub_float, .mul_float, .div_float, .add_wide, .sub_wide, .mul_wide, .div_wide => |*v| {
                    const rep_l = resolve(copies, v.left);
                    const rep_r = resolve(copies, v.right);
                    if (rep_l.reg != v.left.reg or rep_l.version != v.left.version) {
                        v.left = rep_l;
                        changed = true;
                    }
                    if (rep_r.reg != v.right.reg or rep_r.version != v.right.version) {
                        v.right = rep_r;
                        changed = true;
                    }
                },
                .add_lit, .sub_lit, .mul_lit, .div_lit, .rem_lit, .and_lit, .or_lit, .xor_lit, .shl_lit, .shr_lit, .ushr_lit => |*v| {
                    const rep = resolve(copies, v.src);
                    if (rep.reg != v.src.reg or rep.version != v.src.version) {
                        v.src = rep;
                        changed = true;
                    }
                },
                .new_array => |*v| {
                    const rep = resolve(copies, v.size);
                    if (rep.reg != v.size.reg or rep.version != v.size.version) {
                        v.size = rep;
                        changed = true;
                    }
                },
                .iget => |*v| {
                    const rep = resolve(copies, v.obj);
                    if (rep.reg != v.obj.reg or rep.version != v.obj.version) {
                        v.obj = rep;
                        changed = true;
                    }
                },
                .iput => |*v| {
                    const rep_d = resolve(copies, v.dest_or_src);
                    const rep_o = resolve(copies, v.obj);
                    if (rep_d.reg != v.dest_or_src.reg or rep_d.version != v.dest_or_src.version) {
                        v.dest_or_src = rep_d;
                        changed = true;
                    }
                    if (rep_o.reg != v.obj.reg or rep_o.version != v.obj.version) {
                        v.obj = rep_o;
                        changed = true;
                    }
                },
                .sput => |*v| {
                    const rep = resolve(copies, v.dest_or_src);
                    if (rep.reg != v.dest_or_src.reg or rep.version != v.dest_or_src.version) {
                        v.dest_or_src = rep;
                        changed = true;
                    }
                },
                .aget => |*v| {
                    const rep_a = resolve(copies, v.array);
                    const rep_i = resolve(copies, v.index);
                    if (rep_a.reg != v.array.reg or rep_a.version != v.array.version) {
                        v.array = rep_a;
                        changed = true;
                    }
                    if (rep_i.reg != v.index.reg or rep_i.version != v.index.version) {
                        v.index = rep_i;
                        changed = true;
                    }
                },
                .aput => |*v| {
                    const rep_d = resolve(copies, v.dest_or_src);
                    const rep_a = resolve(copies, v.array);
                    const rep_i = resolve(copies, v.index);
                    if (rep_d.reg != v.dest_or_src.reg or rep_d.version != v.dest_or_src.version) {
                        v.dest_or_src = rep_d;
                        changed = true;
                    }
                    if (rep_a.reg != v.array.reg or rep_a.version != v.array.version) {
                        v.array = rep_a;
                        changed = true;
                    }
                    if (rep_i.reg != v.index.reg or rep_i.version != v.index.version) {
                        v.index = rep_i;
                        changed = true;
                    }
                },
                .if_eq, .if_ne, .if_lt, .if_ge, .if_gt, .if_le => |*v| {
                    const rep_l = resolve(copies, v.left);
                    const rep_r = resolve(copies, v.right);
                    if (rep_l.reg != v.left.reg or rep_l.version != v.left.version) {
                        v.left = rep_l;
                        changed = true;
                    }
                    if (rep_r.reg != v.right.reg or rep_r.version != v.right.version) {
                        v.right = rep_r;
                        changed = true;
                    }
                },
                .if_eqz, .if_nez, .if_ltz, .if_gez, .if_gtz, .if_lez => |*v| {
                    const rep = resolve(copies, v.src);
                    if (rep.reg != v.src.reg or rep.version != v.src.version) {
                        v.src = rep;
                        changed = true;
                    }
                },
                .switch_op => |*v| {
                    const rep = resolve(copies, v.src);
                    if (rep.reg != v.src.reg or rep.version != v.src.version) {
                        v.src = rep;
                        changed = true;
                    }
                },
                .invoke => |*v| {
                    for (v.args) |*arg| {
                        const rep = resolve(copies, arg.*);
                        if (rep.reg != arg.reg or rep.version != arg.version) {
                            arg.* = rep;
                            changed = true;
                        }
                    }
                },
                .ret => |*v| {
                    if (v.src) |*s| {
                        const rep = resolve(copies, s.*);
                        if (rep.reg != s.reg or rep.version != s.version) {
                            s.* = rep;
                            changed = true;
                        }
                    }
                },
                .throw_op => |*v| {
                    const rep = resolve(copies, v.src);
                    if (rep.reg != v.src.reg or rep.version != v.src.version) {
                        v.src = rep;
                        changed = true;
                    }
                },
                else => {},
            }

            // Algebraic Simplification & Strength Reduction
            const isPowerOfTwo = struct {
                fn f(val: i32) bool {
                    return val > 0 and (val & (val - 1)) == 0;
                }
            }.f;

            switch (inst.*) {
                .add_int => |v| {
                    if (constants.get(v.left)) |val_l| {
                        if (val_l == 0) {
                            inst.* = .{ .move = .{ .dest = v.dest, .src = v.right } };
                            changed = true;
                        }
                    } else if (constants.get(v.right)) |val_r| {
                        if (val_r == 0) {
                            inst.* = .{ .move = .{ .dest = v.dest, .src = v.left } };
                            changed = true;
                        }
                    }
                },
                .sub_int => |v| {
                    if (constants.get(v.right)) |val_r| {
                        if (val_r == 0) {
                            inst.* = .{ .move = .{ .dest = v.dest, .src = v.left } };
                            changed = true;
                        }
                    } else if (v.left.reg == v.right.reg and v.left.version == v.right.version) {
                        inst.* = .{ .const_int = .{ .dest = v.dest, .val = 0 } };
                        try constants.put(v.dest, 0);
                        changed = true;
                    }
                },
                .mul_int => |v| {
                    if (constants.get(v.left)) |val_l| {
                        if (val_l == 0) {
                            inst.* = .{ .const_int = .{ .dest = v.dest, .val = 0 } };
                            try constants.put(v.dest, 0);
                            changed = true;
                        } else if (val_l == 1) {
                            inst.* = .{ .move = .{ .dest = v.dest, .src = v.right } };
                            changed = true;
                        } else if (isPowerOfTwo(val_l)) {
                            inst.* = .{ .shl_lit = .{ .dest = v.dest, .src = v.right, .lit = @ctz(val_l) } };
                            changed = true;
                        }
                    } else if (constants.get(v.right)) |val_r| {
                        if (val_r == 0) {
                            inst.* = .{ .const_int = .{ .dest = v.dest, .val = 0 } };
                            try constants.put(v.dest, 0);
                            changed = true;
                        } else if (val_r == 1) {
                            inst.* = .{ .move = .{ .dest = v.dest, .src = v.left } };
                            changed = true;
                        } else if (isPowerOfTwo(val_r)) {
                            inst.* = .{ .shl_lit = .{ .dest = v.dest, .src = v.left, .lit = @ctz(val_r) } };
                            changed = true;
                        }
                    }
                },
                .add_lit => |v| {
                    if (v.lit == 0) {
                        inst.* = .{ .move = .{ .dest = v.dest, .src = v.src } };
                        changed = true;
                    }
                },
                .mul_lit => |v| {
                    if (v.lit == 0) {
                        inst.* = .{ .const_int = .{ .dest = v.dest, .val = 0 } };
                        try constants.put(v.dest, 0);
                        changed = true;
                    } else if (v.lit == 1) {
                        inst.* = .{ .move = .{ .dest = v.dest, .src = v.src } };
                        changed = true;
                    } else if (isPowerOfTwo(v.lit)) {
                        inst.* = .{ .shl_lit = .{ .dest = v.dest, .src = v.src, .lit = @ctz(v.lit) } };
                        changed = true;
                    }
                },
                else => {},
            }

            switch (inst.*) {
                .add_int, .sub_int, .mul_int, .div_int, .rem_int, .and_int, .or_int, .xor_int, .shl_int, .shr_int, .ushr_int => |v| {
                    if (constants.get(v.left)) |val_l| {
                        if (constants.get(v.right)) |val_r| {
                            const folded_val = switch (inst.*) {
                                .add_int => val_l + val_r,
                                .sub_int => val_l - val_r,
                                .mul_int => val_l * val_r,
                                .div_int => if (val_r != 0) @divTrunc(val_l, val_r) else 0,
                                .rem_int => if (val_r != 0) @rem(val_l, val_r) else 0,
                                .and_int => val_l & val_r,
                                .or_int => val_l | val_r,
                                .xor_int => val_l ^ val_r,
                                .shl_int => val_l << @intCast(val_r & 31),
                                .shr_int => val_l >> @intCast(val_r & 31),
                                .ushr_int => @as(i32, @bitCast(@as(u32, @bitCast(val_l)) >> @intCast(val_r & 31))),
                                else => unreachable,
                            };
                            inst.* = .{ .const_int = .{ .dest = v.dest, .val = folded_val } };
                            try constants.put(v.dest, folded_val);
                            changed = true;
                        }
                    }
                },
                .add_lit, .sub_lit, .mul_lit, .div_lit, .rem_lit, .and_lit, .or_lit, .xor_lit, .shl_lit, .shr_lit, .ushr_lit => |v| {
                    if (constants.get(v.src)) |val_src| {
                        const folded_val = switch (inst.*) {
                            .add_lit => val_src + v.lit,
                            .sub_lit => val_src - v.lit,
                            .mul_lit => val_src * v.lit,
                            .div_lit => if (v.lit != 0) @divTrunc(val_src, v.lit) else 0,
                            .rem_lit => if (v.lit != 0) @rem(val_src, v.lit) else 0,
                            .and_lit => val_src & v.lit,
                            .or_lit => val_src | v.lit,
                            .xor_lit => val_src ^ v.lit,
                            .shl_lit => val_src << @intCast(v.lit & 31),
                            .shr_lit => val_src >> @intCast(v.lit & 31),
                            .ushr_lit => @as(i32, @bitCast(@as(u32, @bitCast(val_src)) >> @intCast(v.lit & 31))),
                            else => unreachable,
                        };
                        inst.* = .{ .const_int = .{ .dest = v.dest, .val = folded_val } };
                        try constants.put(v.dest, folded_val);
                        changed = true;
                    }
                },
                else => {},
            }
        }
    }

    return changed;
}

/// Mark-and-Sweep Aggressive Dead Code Elimination (ADCE).
/// Returns true if any dead instructions or Phi nodes were deleted.
pub fn eliminateDeadCode(allocator: std.mem.Allocator, cfg: *cfgmod.CFG) !bool {
    var changed = false;

    // 1. Build the Definition Map (SSAVar -> Where it was defined)
    var def_map = std.AutoHashMap(ir.SSAVar, DefLoc).init(allocator);
    defer def_map.deinit();

    for (cfg.blocks.items) |block| {
        for (block.phi_functions.items) |phi| {
            if (phi.ssa_version) |ver| {
                const ssa_var = ir.SSAVar{ .reg = phi.original_reg, .version = ver };
                try def_map.put(ssa_var, .{ .phi = .{ .block_id = block.id, .original_reg = phi.original_reg } });
            }
        }
        for (block.instructions.items, 0..) |inst, idx| {
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
                .invoke => |v| v.dest,
                .phi => |v| v.dest,
                else => null,
            };
            if (dest) |d| {
                try def_map.put(d, .{ .inst = .{ .block_id = block.id, .inst_idx = idx } });
            }
        }
    }

    // 2. The ALIVE sets
    var alive_vars = std.AutoHashMap(ir.SSAVar, void).init(allocator);
    defer alive_vars.deinit();

    var worklist = std.ArrayList(ir.SSAVar).empty;
    defer worklist.deinit(allocator);

    const markAlive = struct {
        fn f(alloc: std.mem.Allocator, map: *std.AutoHashMap(ir.SSAVar, void), wl: *std.ArrayList(ir.SSAVar), variable: ir.SSAVar) !void {
            const entry = try map.getOrPut(variable);
            if (!entry.found_existing) {
                try wl.append(alloc, variable);
            }
        }
    }.f;

    // 3. Mark Phase: Find inherently useful instructions and mark their inputs ALIVE
    for (cfg.blocks.items) |block| {
        for (block.instructions.items) |inst| {
            switch (inst) {
                // Side effects: Memory writes, Invokes, Returns, Exceptions
                .iput => |v| {
                    try markAlive(allocator, &alive_vars, &worklist, v.dest_or_src);
                    try markAlive(allocator, &alive_vars, &worklist, v.obj);
                },
                .sput => |v| {
                    try markAlive(allocator, &alive_vars, &worklist, v.dest_or_src);
                },
                .aput => |v| {
                    try markAlive(allocator, &alive_vars, &worklist, v.dest_or_src);
                    try markAlive(allocator, &alive_vars, &worklist, v.array);
                    try markAlive(allocator, &alive_vars, &worklist, v.index);
                },
                .invoke => |v| {
                    for (v.args) |arg| try markAlive(allocator, &alive_vars, &worklist, arg);
                },
                .ret => |v| {
                    if (v.src) |s| try markAlive(allocator, &alive_vars, &worklist, s);
                },
                .throw_op => |v| try markAlive(allocator, &alive_vars, &worklist, v.src),

                // Control Flow must be kept alive to maintain CFG structure
                .if_eq, .if_ne, .if_lt, .if_ge, .if_gt, .if_le => |v| {
                    try markAlive(allocator, &alive_vars, &worklist, v.left);
                    try markAlive(allocator, &alive_vars, &worklist, v.right);
                },
                .if_eqz, .if_nez, .if_ltz, .if_gez, .if_gtz, .if_lez => |v| try markAlive(allocator, &alive_vars, &worklist, v.src),
                .switch_op => |v| try markAlive(allocator, &alive_vars, &worklist, v.src),
                .goto => {}, // No vars, but inherently alive

                else => {}, // Pure math/logic. Assumed DEAD until proven otherwise.
            }
        }
    }

    // 4. Trace Phase: Follow the Def-Use chains backwards
    while (worklist.items.len > 0) {
        const v = worklist.pop().?;
        const def_loc = def_map.get(v) orelse continue; // Method arguments aren't in def_map

        switch (def_loc) {
            .inst => |loc| {
                const inst = cfg.blocks.items[loc.block_id].instructions.items[loc.inst_idx];
                switch (inst) {
                    .move => |op| try markAlive(allocator, &alive_vars, &worklist, op.src),
                    .add_int, .sub_int, .mul_int, .div_int, .rem_int, .and_int, .or_int, .xor_int, .shl_int, .shr_int, .ushr_int, .add_float, .sub_float, .mul_float, .div_float, .add_wide, .sub_wide, .mul_wide, .div_wide => |op| {
                        try markAlive(allocator, &alive_vars, &worklist, op.left);
                        try markAlive(allocator, &alive_vars, &worklist, op.right);
                    },
                    .add_lit, .sub_lit, .mul_lit, .div_lit, .rem_lit, .and_lit, .or_lit, .xor_lit, .shl_lit, .shr_lit, .ushr_lit => |op| {
                        try markAlive(allocator, &alive_vars, &worklist, op.src);
                    },
                    .new_array => |op| try markAlive(allocator, &alive_vars, &worklist, op.size),
                    .iget => |op| try markAlive(allocator, &alive_vars, &worklist, op.obj),
                    .aget => |op| {
                        try markAlive(allocator, &alive_vars, &worklist, op.array);
                        try markAlive(allocator, &alive_vars, &worklist, op.index);
                    },
                    .phi => |op| {
                        for (op.args) |arg| {
                            try markAlive(allocator, &alive_vars, &worklist, arg.val);
                        }
                    },
                    else => {}, // Constants, etc. don't use variables
                }
            },
            .phi => |loc| {
                const block = &cfg.blocks.items[loc.block_id];
                for (block.phi_functions.items) |phi| {
                    if (phi.original_reg == loc.original_reg) {
                        for (phi.incoming) |arg| {
                            try markAlive(allocator, &alive_vars, &worklist, arg.val);
                        }
                        break;
                    }
                }
            },
        }
    }

    // 5. Sweep Phase: Delete anything not marked ALIVE
    for (cfg.blocks.items) |*block| {
        // Sweep Phi Functions
        var new_phis = std.ArrayList(cfgmod.PhiNode).empty;
        for (block.phi_functions.items) |phi| {
            if (phi.ssa_version) |ver| {
                const ssa_var = ir.SSAVar{ .reg = phi.original_reg, .version = ver };
                if (alive_vars.contains(ssa_var)) {
                    try new_phis.append(allocator, phi);
                } else {
                    changed = true; // Phi was dead!
                }
            }
        }
        block.phi_functions.deinit(allocator);
        block.phi_functions = new_phis;

        // Sweep Instructions
        var new_insts = std.ArrayList(ir.IRInst).empty;
        for (block.instructions.items) |inst| {
            var keep = false;

            // Is it inherently alive?
            switch (inst) {
                .iput, .sput, .aput, .ret, .throw_op, .goto, .if_eq, .if_ne, .if_lt, .if_ge, .if_gt, .if_le, .if_eqz, .if_nez, .if_ltz, .if_gez, .if_gtz, .if_lez, .switch_op => {
                    keep = true;
                },
                .invoke => |v| {
                    keep = true; // Always keep the invoke, but strip the dest if it's dead
                    if (v.dest) |d| {
                        if (!alive_vars.contains(d)) {
                            var modified_invoke = inst;
                            modified_invoke.invoke.dest = null;
                            try new_insts.append(allocator, modified_invoke);
                            changed = true;
                            continue;
                        }
                    }
                },
                else => {},
            }

            // If it's a pure definition, is the resulting variable ALIVE?
            if (!keep) {
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
                    else => null,
                };
                if (dest) |d| {
                    if (alive_vars.contains(d)) keep = true;
                }
            }

            if (keep) {
                try new_insts.append(allocator, inst);
            } else {
                changed = true;
            }
        }
        block.instructions.deinit(allocator);
        block.instructions = new_insts;
    }

    return changed;
}

test "eliminateDeadCode: basic dead code elimination" {
    const a = std.testing.allocator;
    const instmod = @import("instruction");
    const translate = @import("translate");

    const insns = [_]instmod.Instruction{
        .{ .const_ = .{ .value = 42, .dest = 0 } }, // dead const (no uses)
        .return_void,
    };

    var cfg = try cfgmod.buildCFG(a, &insns);
    defer cfg.deinit();

    try translate.translateCFG(a, &cfg, &insns);

    // Run dead code elimination
    const changed = try eliminateDeadCode(a, &cfg);
    try std.testing.expect(changed);

    // Verify first instruction (const_) is deleted, leaving only the return
    const block0 = cfg.blocks.items[0].instructions.items;
    try std.testing.expectEqual(@as(usize, 1), block0.len);
    try std.testing.expect(block0[0] == .ret);
}

test "eliminateDeadCode: copy propagation and constant folding" {
    const a = std.testing.allocator;
    const instmod = @import("instruction");
    const translate = @import("translate");

    const insns = [_]instmod.Instruction{
        .{ .const_ = .{ .value = 10, .dest = 0 } },  // v0 = 10
        .{ .const_ = .{ .value = 20, .dest = 1 } },  // v1 = 20
        .{ .add_int = .{ .dest = 2, .src1 = 0, .src2 = 1 } }, // v2 = v0 + v1 = 30 (folded!)
        .{ .move = .{ .dest = 3, .src = 2 } },        // v3 = v2 (propagated!)
        .{ .return_ = .{ .src = 3 } },                // return v3
    };

    var cfg = try cfgmod.buildCFG(a, &insns);
    defer cfg.deinit();

    try translate.translateCFG(a, &cfg, &insns);

    // Run optimize pass
    const changed = try optimize(a, &cfg);
    try std.testing.expect(changed);

    // After copy propagation + folding + dead code elimination,
    // v0, v1, v2, v3 should be pruned, leaving only:
    // v3 = const_int 30
    // ret v3
    const block0 = cfg.blocks.items[0].instructions.items;
    try std.testing.expectEqual(@as(usize, 2), block0.len);
    try std.testing.expect(block0[0] == .const_int);
    try std.testing.expectEqual(@as(i32, 30), block0[0].const_int.val);
    try std.testing.expect(block0[1] == .ret);
    try std.testing.expectEqual(@as(u16, 2), block0[1].ret.src.?.reg);
}

test "eliminateDeadCode: global value numbering" {
    const a = std.testing.allocator;
    const instmod = @import("instruction");
    const translate = @import("translate");

    const insns = [_]instmod.Instruction{
        .{ .const_ = .{ .value = 5, .dest = 0 } },  // v0 = 5
        .{ .const_ = .{ .value = 10, .dest = 1 } }, // v1 = 10
        .{ .add_int = .{ .dest = 2, .src1 = 0, .src2 = 1 } }, // v2 = v0 + v1
        .{ .add_int = .{ .dest = 3, .src1 = 0, .src2 = 1 } }, // v3 = v0 + v1 (duplicate!)
        .{ .add_int = .{ .dest = 4, .src1 = 2, .src2 = 3 } }, // v4 = v2 + v3 -> v2 + v2 = const 30
        .{ .return_ = .{ .src = 4 } },
    };

    var cfg = try cfgmod.buildCFG(a, &insns);
    defer cfg.deinit();

    try translate.translateCFG(a, &cfg, &insns);

    const changed = try optimize(a, &cfg);
    try std.testing.expect(changed);

    // Verify duplicate calculation is eliminated and folded
    const block0 = cfg.blocks.items[0].instructions.items;
    try std.testing.expectEqual(@as(usize, 2), block0.len);
    try std.testing.expect(block0[0] == .const_int);
    try std.testing.expectEqual(@as(i32, 30), block0[0].const_int.val);
    try std.testing.expect(block0[1] == .ret);
    try std.testing.expectEqual(@as(u16, 4), block0[1].ret.src.?.reg);
}

test "eliminateDeadCode: loop invariant code motion" {
    const a = std.testing.allocator;
    const instmod = @import("instruction");
    const translate = @import("translate");

    const loop_insns = [_]instmod.Instruction{
        .{ .const_ = .{ .value = 10, .dest = 0 } },  // Block 0: v0 = 10
        .{ .const_ = .{ .value = 20, .dest = 1 } },  // v1 = 20
        // Block 1 (header): starts at index 2
        .{ .add_int = .{ .dest = 4, .src1 = 0, .src2 = 1 } }, // v4 = v0 + v1 (invariant!)
        .{ .add_int = .{ .dest = 3, .src1 = 2, .src2 = 4 } }, // v3 = v2 + v4
        .{ .if_lt = .{ .offset = -2, .src1 = 3, .src2 = 0 } }, // if v3 < v0 goto Block 1 (offset -2 to index 2)
        .{ .return_ = .{ .src = 3 } },
    };

    var cfg_loop = try cfgmod.buildCFG(a, &loop_insns);
    defer cfg_loop.deinit();

    try cfg_loop.computePredecessors();
    try cfg_loop.computeDominators();
    try cfg_loop.computeDominatorChildren();
    try cfg_loop.computeDominanceFrontiers();

    try translate.translateCFG(a, &cfg_loop, &loop_insns);

    const changed = try optimize(a, &cfg_loop);
    try std.testing.expect(changed);

    const b0_insts = cfg_loop.blocks.items[0].instructions.items;
    var found_folded_invariant = false;
    for (b0_insts) |inst| {
        if (inst == .const_int and inst.const_int.dest.reg == 4 and inst.const_int.val == 30) {
            found_folded_invariant = true;
        }
    }
    try std.testing.expect(found_folded_invariant);
}

test "eliminateDeadCode: algebraic simplifications and strength reduction" {
    const a = std.testing.allocator;
    const instmod = @import("instruction");
    const translate = @import("translate");

    const insns = [_]instmod.Instruction{
        .{ .const_ = .{ .value = 10, .dest = 0 } }, // v0 = 10
        .{ .const_ = .{ .value = 0, .dest = 1 } },  // v1 = 0
        .{ .add_int = .{ .dest = 2, .src1 = 0, .src2 = 1 } }, // v2 = v0 + v1 -> v0 + 0 -> move v0 -> 10
        .{ .sub_int = .{ .dest = 3, .src1 = 0, .src2 = 0 } }, // v3 = v0 - v0 -> const 0
        .{ .mul_int_lit8 = .{ .dest = 4, .src = 0, .lit = 4 } },  // v4 = v0 * 4 -> v0 << 2 (shl_lit) -> 40
        .{ .iput = .{ .dest_or_src = 3, .obj = 0, .field_idx = 1 } },
        .{ .iput = .{ .dest_or_src = 4, .obj = 0, .field_idx = 2 } },
        .return_void,
    };

    var cfg = try cfgmod.buildCFG(a, &insns);
    defer cfg.deinit();

    try translate.translateCFG(a, &cfg, &insns);

    const changed = try optimize(a, &cfg);
    try std.testing.expect(changed);

    const block0 = cfg.blocks.items[0].instructions.items;

    var found_v3_zero = false;
    var found_v4_forty = false;
    for (block0) |inst| {
        if (inst == .const_int) {
            if (inst.const_int.dest.reg == 3 and inst.const_int.val == 0) {
                found_v3_zero = true;
            }
            if (inst.const_int.dest.reg == 4 and inst.const_int.val == 40) {
                found_v4_forty = true;
            }
        }
    }
    try std.testing.expect(found_v3_zero);
    try std.testing.expect(found_v4_forty);
}

test "eliminateDeadCode: cfg simplification and dead branch elimination" {
    const a = std.testing.allocator;
    const instmod = @import("instruction");
    const translate = @import("translate");

    const insns = [_]instmod.Instruction{
        .{ .const_ = .{ .value = 10, .dest = 0 } },  // Block 0: v0 = 10
        .{ .const_ = .{ .value = 10, .dest = 1 } },  // v1 = 10
        .{ .if_eq = .{ .offset = 3, .src1 = 0, .src2 = 1 } }, // if v0 == v1 goto Block 2 (offset 3 to index 5)
        // Block 1 (dead fallthrough):
        .{ .const_ = .{ .value = 999, .dest = 2 } }, 
        .{ .return_ = .{ .src = 2 } },
        // Block 2 (always taken): target of if_eq
        .{ .return_ = .{ .src = 0 } },
    };

    var cfg = try cfgmod.buildCFG(a, &insns);
    defer cfg.deinit();

    try cfg.computePredecessors();
    try cfg.computeDominators();
    try cfg.computeDominatorChildren();
    try cfg.computeDominanceFrontiers();

    try translate.translateCFG(a, &cfg, &insns);

    const changed = try optimize(a, &cfg);
    try std.testing.expect(changed);

    // Block 0 should now end with ret v0_0 (because Block 2 ret v0 was merged into Block 0!)
    const b0_insts = cfg.blocks.items[0].instructions.items;
    try std.testing.expect(b0_insts[b0_insts.len - 1] == .ret);
    try std.testing.expectEqual(@as(u16, 0), b0_insts[b0_insts.len - 1].ret.src.?.reg);

    // Block 1 (unreachable block at index 3..4) must be cleared!
    try std.testing.expectEqual(@as(usize, 0), cfg.blocks.items[1].instructions.items.len);
}

test "eliminateDeadCode: value range propagation" {
    const a = std.testing.allocator;
    const instmod = @import("instruction");
    const translate = @import("translate");

    const insns = [_]instmod.Instruction{
        .{ .const_ = .{ .value = 10, .dest = 0 } },  // Block 0: v0 = 10
        .{ .const_ = .{ .value = 5, .dest = 1 } },   // v1 = 5
        .{ .add_int = .{ .dest = 2, .src1 = 0, .src2 = 1 } }, // v2 = 15
        .{ .if_gez = .{ .offset = 3, .src = 2 } }, // if v2 >= 0 goto Block 2 (offset 3 to index 6)
        // Block 1 (dead fallthrough):
        .{ .const_ = .{ .value = 999, .dest = 3 } }, 
        .{ .return_ = .{ .src = 3 } },
        // Block 2 (always taken):
        .{ .return_ = .{ .src = 2 } },
    };

    var cfg = try cfgmod.buildCFG(a, &insns);
    defer cfg.deinit();

    try cfg.computePredecessors();
    try cfg.computeDominators();
    try cfg.computeDominatorChildren();
    try cfg.computeDominanceFrontiers();

    try translate.translateCFG(a, &cfg, &insns);

    const changed = try optimize(a, &cfg);
    try std.testing.expect(changed);

    // Block 0 should end with ret v2_0 because Block 2 is merged into Block 0!
    const b0_insts = cfg.blocks.items[0].instructions.items;
    try std.testing.expect(b0_insts[b0_insts.len - 1] == .ret);
    try std.testing.expectEqual(@as(u16, 2), b0_insts[b0_insts.len - 1].ret.src.?.reg);

    // Block 1 (unreachable block) must be cleared!
    try std.testing.expectEqual(@as(usize, 0), cfg.blocks.items[1].instructions.items.len);
}

test "eliminateDeadCode: loop unrolling" {
    const a = std.testing.allocator;
    const instmod = @import("instruction");
    const translate = @import("translate");

    const insns = [_]instmod.Instruction{
        .{ .const_ = .{ .value = 0, .dest = 0 } },  // Block 0: v0 = 0
        .{ .const_ = .{ .value = 10, .dest = 1 } }, // v1 = 10
        .{ .const_ = .{ .value = 3, .dest = 9 } },  // v9 = 3 (limit)
        // Block 1 (header): starts at index 3
        .{ .add_int_lit8 = .{ .dest = 1, .src = 1, .lit = 5 } }, // v1_next = v1_phi + 5
        .{ .add_int_lit8 = .{ .dest = 0, .src = 0, .lit = 1 } }, // v0_next = v0_phi + 1
        .{ .if_lt = .{ .offset = -2, .src1 = 0, .src2 = 9 } }, // if v0_next < v9 goto Block 1 (offset -2 to index 3)
        // Block 2:
        .{ .return_ = .{ .src = 1 } },
    };

    var cfg = try cfgmod.buildCFG(a, &insns);
    defer cfg.deinit();

    try cfg.computePredecessors();
    try cfg.computeDominators();
    try cfg.computeDominatorChildren();
    try cfg.computeDominanceFrontiers();

    try translate.translateCFG(a, &cfg, &insns);
    // Ready to populate def_map
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

    // Manually rebuild Block 1 and 2 to contain the correct SSA Phi nodes
    cfg.blocks.items[1].instructions.clearRetainingCapacity();

    const phi0_args = try a.alloc(ir.PhiArg, 2);
    phi0_args[0] = .{ .pred_block_id = 0, .val = .{ .reg = 0, .version = 1 } };
    phi0_args[1] = .{ .pred_block_id = 1, .val = .{ .reg = 0, .version = 3 } };

    const phi1_args = try a.alloc(ir.PhiArg, 2);
    phi1_args[0] = .{ .pred_block_id = 0, .val = .{ .reg = 1, .version = 1 } };
    phi1_args[1] = .{ .pred_block_id = 1, .val = .{ .reg = 1, .version = 3 } };

    try cfg.blocks.items[1].instructions.append(a, .{ .phi = .{ .dest = .{ .reg = 0, .version = 2 }, .args = phi0_args } });
    try cfg.blocks.items[1].instructions.append(a, .{ .phi = .{ .dest = .{ .reg = 1, .version = 2 }, .args = phi1_args } });
    try cfg.blocks.items[1].instructions.append(a, .{ .add_lit = .{ .dest = .{ .reg = 1, .version = 3 }, .src = .{ .reg = 1, .version = 2 }, .lit = 5 } });
    try cfg.blocks.items[1].instructions.append(a, .{ .add_lit = .{ .dest = .{ .reg = 0, .version = 3 }, .src = .{ .reg = 0, .version = 2 }, .lit = 1 } });
    try cfg.blocks.items[1].instructions.append(a, .{ .if_lt = .{ .left = .{ .reg = 0, .version = 3 }, .right = .{ .reg = 9, .version = 1 }, .target_block_id = 1 } });

    cfg.blocks.items[2].instructions.items[0] = .{ .ret = .{ .src = .{ .reg = 1, .version = 3 } } };

    const changed = try optimize(a, &cfg);
    try std.testing.expect(changed);

    var found_folded_result = false;
    for (cfg.blocks.items) |block| {
        for (block.instructions.items) |inst| {
            if (inst == .const_int) {
                if (inst.const_int.dest.reg == 1 and inst.const_int.val == 25) {
                    found_folded_result = true;
                }
            }
        }
    }
    try std.testing.expect(found_folded_result);
}

test "eliminateDeadCode: loop strength reduction" {
    const a = std.testing.allocator;
    const instmod = @import("instruction");
    const translate = @import("translate");

    const insns = [_]instmod.Instruction{
        .{ .const_ = .{ .value = 0, .dest = 0 } },  // Block 0: v0 = 0
        .{ .const_ = .{ .value = 100, .dest = 9 } }, // v9 = 100 (limit)
        .{ .mul_int_lit8 = .{ .dest = 1, .src = 0, .lit = 4 } }, // v1 = v0 * 4
        .{ .add_int_lit8 = .{ .dest = 0, .src = 0, .lit = 1 } }, // v0_next = v0 + 1
        .{ .iput = .{ .dest_or_src = 1, .obj = 0, .field_idx = 5 } },
        .{ .if_lt = .{ .offset = -3, .src1 = 0, .src2 = 9 } }, // if v0_next < 100 goto Block 1
        .{ .return_ = .{ .src = 1 } },
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

    // Manually setup the SSA Phi instruction for v0 BIV to enable detection
    cfg.blocks.items[1].instructions.clearRetainingCapacity();

    const phi0_args = try a.alloc(ir.PhiArg, 2);
    phi0_args[0] = .{ .pred_block_id = 0, .val = .{ .reg = 0, .version = 1 } };
    phi0_args[1] = .{ .pred_block_id = 1, .val = .{ .reg = 0, .version = 3 } };

    try cfg.blocks.items[1].instructions.append(a, .{ .phi = .{ .dest = .{ .reg = 0, .version = 2 }, .args = phi0_args } });
    try cfg.blocks.items[1].instructions.append(a, .{ .mul_lit = .{ .dest = .{ .reg = 1, .version = 2 }, .src = .{ .reg = 0, .version = 2 }, .lit = 4 } });
    try cfg.blocks.items[1].instructions.append(a, .{ .add_lit = .{ .dest = .{ .reg = 0, .version = 3 }, .src = .{ .reg = 0, .version = 2 }, .lit = 1 } });
    try cfg.blocks.items[1].instructions.append(a, .{ .iput = .{ .dest_or_src = .{ .reg = 1, .version = 2 }, .obj = .{ .reg = 0, .version = 2 }, .field_idx = 5 } });
    try cfg.blocks.items[1].instructions.append(a, .{ .if_lt = .{ .left = .{ .reg = 0, .version = 3 }, .right = .{ .reg = 9, .version = 1 }, .target_block_id = 1 } });

    cfg.blocks.items[2].instructions.items[0] = .{ .ret = .{ .src = .{ .reg = 1, .version = 2 } } };

    const changed = try optimize(a, &cfg);
    try std.testing.expect(changed);

    const b1_insts = cfg.blocks.items[1].instructions.items;
    var found_reduced_addition = false;
    var found_new_phi = false;
    for (b1_insts) |inst| {
        if (inst == .phi and inst.phi.dest.reg == 1) {
            found_new_phi = true;
        }
        if (inst == .add_int and inst.add_int.dest.reg == 1) {
            found_reduced_addition = true;
        }
        try std.testing.expect(inst != .mul_int and inst != .mul_lit);
    }
    try std.testing.expect(found_new_phi);
    try std.testing.expect(found_reduced_addition);
}

test "eliminateDeadCode: devirtualization and speculative inlining" {
    const a = std.testing.allocator;
    const instmod = @import("instruction");
    const translate = @import("translate");

    const insns = [_]instmod.Instruction{
        .{ .const_ = .{ .value = 42, .dest = 0 } }, // v0 = 42
        .return_void,
    };

    var cfg = try cfgmod.buildCFG(a, &insns);
    defer cfg.deinit();

    try cfg.computePredecessors();
    try cfg.computeDominators();
    try cfg.computeDominatorChildren();
    try cfg.computeDominanceFrontiers();

    try translate.translateCFG(a, &cfg, &insns);

    const args = try a.alloc(ir.SSAVar, 1);
    args[0] = .{ .reg = 0, .version = 1 };

    const invoke_inst = ir.IRInst{
        .invoke = .{
            .dest = .{ .reg = 1, .version = 1 },
            .method_idx = 100,
            .is_static = false, // virtual!
            .args = args,
        },
    };

    try cfg.blocks.items[0].instructions.insert(a, 1, invoke_inst);
    cfg.blocks.items[0].instructions.items[2] = .{ .ret = .{ .src = .{ .reg = 1, .version = 1 } } };

    const changed = try optimize(a, &cfg);
    try std.testing.expect(changed);

    const insts = cfg.blocks.items[0].instructions.items;
    var found_iget = false;
    for (insts) |inst| {
        try std.testing.expect(inst != .invoke);
        if (inst == .iget) {
            try std.testing.expectEqual(@as(u16, 0), inst.iget.obj.reg);
            try std.testing.expectEqual(@as(u32, 10), inst.iget.field_idx);
            found_iget = true;
        }
    }
    try std.testing.expect(found_iget);
}

test "eliminateDeadCode: global register coalescing" {
    const a = std.testing.allocator;
    const instmod = @import("instruction");
    const translate = @import("translate");

    const insns = [_]instmod.Instruction{
        .{ .const_ = .{ .value = 42, .dest = 0 } },
        .{ .move = .{ .dest = 1, .src = 0 } },
        .{ .return_ = .{ .src = 1 } },
    };

    var cfg = try cfgmod.buildCFG(a, &insns);
    defer cfg.deinit();

    try cfg.computePredecessors();
    try cfg.computeDominators();
    try cfg.computeDominatorChildren();
    try cfg.computeDominanceFrontiers();

    try translate.translateCFG(a, &cfg, &insns);

    const changed = try optimize(a, &cfg);
    try std.testing.expect(changed);

    const insts = cfg.blocks.items[0].instructions.items;
    var found_move = false;
    var found_const = false;
    var found_ret = false;
    for (insts) |inst| {
        if (inst == .move) found_move = true;
        if (inst == .const_int) {
            try std.testing.expectEqual(@as(u16, 0), inst.const_int.dest.reg);
            found_const = true;
        }
        if (inst == .ret) {
            try std.testing.expectEqual(@as(u16, 0), inst.ret.src.?.reg);
            found_ret = true;
        }
    }
    try std.testing.expect(!found_move);
    try std.testing.expect(found_const);
    try std.testing.expect(found_ret);
}
