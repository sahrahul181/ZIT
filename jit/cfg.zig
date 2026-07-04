const std = @import("std");
const instmod = @import("instruction");
const Instruction = instmod.Instruction;
const ir = @import("ir");

pub const PhiNode = struct {
    original_reg: u16,
    ssa_version: ?u32 = null,
    incoming: []ir.PhiArg,
};

/// A Basic Block represents a straight-line sequence of instructions
/// with no branches in except to the entry, and no branches out except at the exit.
pub const BasicBlock = struct {
    id: usize,
    /// Index into the original instructions slice where this block starts
    start_idx: usize,
    /// Index into the original instructions slice where this block ends (inclusive)
    end_idx: usize,
    /// List of block IDs that can execute immediately after this one
    successors: std.ArrayList(usize),
    /// List of block IDs that branch directly into this block
    predecessors: std.ArrayList(usize),
    /// The ID of the block that immediately dominates this one
    idom: ?usize,
    /// The set of block IDs where this block's dominance ends
    dominance_frontier: std.ArrayList(usize),
    /// Tracks which original registers have a Phi function at the start of this block
    phi_functions: std.ArrayList(PhiNode),
    /// Blocks that are immediately dominated by this block
    dom_children: std.ArrayList(usize),
    /// Instructions in 3-Address Code IR form (populated by translateCFG)
    instructions: std.ArrayList(ir.IRInst),

    pub fn getPhi(self: *BasicBlock, reg: u16) ?*PhiNode {
        for (self.phi_functions.items) |*phi| {
            if (phi.original_reg == reg) return phi;
        }
        return null;
    }

    pub fn getPhiConst(self: *const BasicBlock, reg: u16) ?*const PhiNode {
        for (self.phi_functions.items) |*phi| {
            if (phi.original_reg == reg) return phi;
        }
        return null;
    }

    pub fn putPhi(self: *BasicBlock, allocator: std.mem.Allocator, phi: PhiNode) !void {
        if (self.getPhi(phi.original_reg)) |existing| {
            existing.* = phi;
            return;
        }
        try self.phi_functions.append(allocator, phi);
    }
};

pub const CFG = struct {
    blocks: std.ArrayList(BasicBlock),
    allocator: std.mem.Allocator,
    /// ID of the entry block (always 0 for DEX methods)
    entry_block_id: usize = 0,

    pub fn deinit(self: *CFG) void {
        for (self.blocks.items) |*block| {
            block.successors.deinit(self.allocator);
            block.predecessors.deinit(self.allocator);
            block.dominance_frontier.deinit(self.allocator);
            
            for (block.phi_functions.items) |phi| {
                self.allocator.free(phi.incoming);
            }
            block.phi_functions.deinit(self.allocator);
            
            block.dom_children.deinit(self.allocator);
            for (block.instructions.items) |inst| {
                switch (inst) {
                    .invoke => |v| self.allocator.free(v.args),
                    .phi => |v| self.allocator.free(v.args),
                    .switch_op => |v| self.allocator.free(v.target_block_ids),
                    else => {},
                }
            }
            block.instructions.deinit(self.allocator);
        }
        self.blocks.deinit(self.allocator);
    }
    /// Step 1: Backfill predecessors based on successors
    pub fn computePredecessors(self: *CFG) !void {
        // Clear any existing predecessors if this is re-run
        for (self.blocks.items) |*b| {
            b.predecessors.clearRetainingCapacity();
        }

        for (self.blocks.items) |*block| {
            for (block.successors.items) |succ_id| {
                // Add the current block as a predecessor to its successor
                try self.blocks.items[succ_id].predecessors.append(self.allocator, block.id);
            }
        }
    }

    /// Step 2: Calculate the Immediate Dominator (IDom) for every block.
    pub fn computeDominators(self: *CFG) !void {
        const num_blocks = self.blocks.items.len;
        if (num_blocks == 0) return;

        // doms[i] will be a bitset representing all blocks that dominate block i
        var doms = try self.allocator.alloc(std.DynamicBitSetUnmanaged, num_blocks);
        defer {
            for (doms) |*ds| ds.deinit(self.allocator);
            self.allocator.free(doms);
        }

        // Initialize bitsets
        for (0..num_blocks) |i| {
            doms[i] = try std.DynamicBitSetUnmanaged.initEmpty(self.allocator, num_blocks);
            if (i == self.entry_block_id) {
                // The entry node only dominates itself
                doms[i].set(i);
            } else {
                // All other nodes initially are dominated by everything
                doms[i].setRangeValue(.{ .start = 0, .end = num_blocks }, true);
            }
        }

        // Iterative data-flow algorithm
        var changed = true;
        while (changed) {
            changed = false;
            for (0..num_blocks) |i| {
                if (i == self.entry_block_id) continue;

                var new_dom = try std.DynamicBitSetUnmanaged.initEmpty(self.allocator, num_blocks);
                defer new_dom.deinit(self.allocator);
                new_dom.setRangeValue(.{ .start = 0, .end = num_blocks }, true);

                const preds = self.blocks.items[i].predecessors.items;
                if (preds.len == 0) {
                    new_dom.setRangeValue(.{ .start = 0, .end = num_blocks }, false);
                } else {
                    for (preds) |pred_id| {
                        // Intersection: new_dom = new_dom AND doms[pred]
                        new_dom.setIntersection(doms[pred_id]);
                    }
                }

                // A block always dominates itself
                new_dom.set(i);

                // Check if the dominator set for this block changed
                var differs = false;
                var iter = new_dom.iterator(.{});
                while (iter.next()) |bit| {
                    if (!doms[i].isSet(bit)) differs = true;
                }
                var old_iter = doms[i].iterator(.{});
                while (old_iter.next()) |bit| {
                    if (!new_dom.isSet(bit)) differs = true;
                }

                if (differs) {
                    doms[i].deinit(self.allocator);
                    doms[i] = try new_dom.clone(self.allocator);
                    changed = true;
                }
            }
        }

        // Extract the Immediate Dominator (IDom)
        // IDom is the dominator that is "closest" to the block
        for (0..num_blocks) |i| {
            if (i == self.entry_block_id) {
                self.blocks.items[i].idom = null;
                continue;
            }

            var idom_candidate: ?usize = null;
            var iter = doms[i].iterator(.{});

            while (iter.next()) |dom_id| {
                if (dom_id == i) continue; // Cannot immediately dominate itself

                if (idom_candidate == null) {
                    idom_candidate = dom_id;
                    continue;
                }

                // If dom_id is dominated by our current candidate, it is closer
                if (doms[dom_id].isSet(idom_candidate.?)) {
                    idom_candidate = dom_id;
                }
            }
            self.blocks.items[i].idom = idom_candidate;
        }
    }
    pub fn computeDominatorChildren(self: *CFG) !void {
        for (self.blocks.items) |*b| b.dom_children.clearRetainingCapacity();

        for (self.blocks.items) |b| {
            if (b.idom) |parent_id| {
                try self.blocks.items[parent_id].dom_children.append(self.allocator, b.id);
            }
        }
    }
    /// Step 3: Calculate the Dominance Frontier for every block.
    /// A block's dominance frontier is the set of nodes where its dominance ends.
    pub fn computeDominanceFrontiers(self: *CFG) !void {
        // Clear previous runs
        for (self.blocks.items) |*b| {
            b.dominance_frontier.clearRetainingCapacity();
        }

        // We care about "join points" — blocks with multiple predecessors
        // or the entry block if it has a back-edge.
        for (self.blocks.items) |*b| {
            const preds = b.predecessors.items;
            const is_join = preds.len >= 2 or (b.id == self.entry_block_id and preds.len >= 1);
            if (is_join) {
                const b_idom = b.idom;

                // For each predecessor, walk up the dominator tree until we hit b's IDom or b itself
                for (preds) |pred_id| {
                    var runner: ?usize = pred_id;

                    while (runner != null and runner.? != b_idom and runner.? != b.id) {
                        const runner_id = runner.?;

                        // Add 'b' to the runner's dominance frontier
                        // (Checking for duplicates first, as multiple preds might share a dominator path)
                        var already_exists = false;
                        for (self.blocks.items[runner_id].dominance_frontier.items) |existing| {
                            if (existing == b.id) {
                                already_exists = true;
                                break;
                            }
                        }

                        if (!already_exists) {
                            try self.blocks.items[runner_id].dominance_frontier.append(self.allocator, b.id);
                        }

                        // Move up the tree
                        runner = self.blocks.items[runner_id].idom;
                    }
                }
            }
        }
    }
    pub fn insertPhiFunctions(self: *CFG, def_map: std.AutoHashMap(u16, std.ArrayList(usize))) !void {
        // Track which blocks have already had a phi inserted for a specific register
        var has_phi = try std.DynamicBitSetUnmanaged.initEmpty(self.allocator, self.blocks.items.len);
        defer has_phi.deinit(self.allocator);

        // Track which blocks have already been added to our processing worklist
        var added_to_worklist = try std.DynamicBitSetUnmanaged.initEmpty(self.allocator, self.blocks.items.len);
        defer added_to_worklist.deinit(self.allocator);

        var worklist = std.ArrayList(usize).empty;
        defer worklist.deinit(self.allocator);

        var it = def_map.iterator();
        while (it.next()) |entry| {
            const reg = entry.key_ptr.*;
            const definers = entry.value_ptr.*.items;

            // Reset our tracking sets for this specific register
            has_phi.setRangeValue(.{ .start = 0, .end = self.blocks.items.len }, false);
            added_to_worklist.setRangeValue(.{ .start = 0, .end = self.blocks.items.len }, false);
            worklist.clearRetainingCapacity();

            // Initialize the worklist with every block that natively defines this register
            for (definers) |def_block_id| {
                added_to_worklist.set(def_block_id);
                try worklist.append(self.allocator, def_block_id);
            }

            // Iterated Dominance Frontier algorithm
            while (worklist.items.len > 0) {
                const b_id = worklist.pop().?;
                const b = &self.blocks.items[b_id];

                // For every block 'd' in the dominance frontier of 'b'
                for (b.dominance_frontier.items) |d_id| {
                    if (!has_phi.isSet(d_id)) {
                        // Insert the Phi function!
                        var d_block = &self.blocks.items[d_id];
                        const incoming = try self.allocator.alloc(ir.PhiArg, d_block.predecessors.items.len);
                        for (incoming, 0..) |*arg, i| {
                            arg.* = .{
                                .pred_block_id = d_block.predecessors.items[i],
                                .val = .{ .reg = reg, .version = 0 },
                            };
                        }
                        try d_block.putPhi(self.allocator, .{
                            .original_reg = reg,
                            .incoming = incoming,
                        });
                        has_phi.set(d_id);

                        // A phi function is a NEW definition.
                        // We must add 'd' to the worklist to check its frontier.
                        if (!added_to_worklist.isSet(d_id)) {
                            added_to_worklist.set(d_id);
                            try worklist.append(self.allocator, d_id);
                        }
                    }
                }
            }
        }
    }
    /// Phase 2 of SSA: Rename variables top-down across the dominator tree.
    pub fn renameVariables(self: *CFG, total_virtual_registers: usize) !void {
        // Track the highest version number issued for each original register
        const counters = try self.allocator.alloc(u32, total_virtual_registers);
        @memset(counters, 0);
        defer self.allocator.free(counters);

        // Track the "current active" version of each original register
        var stacks = try self.allocator.alloc(std.ArrayList(u32), total_virtual_registers);
        for (0..total_virtual_registers) |i| {
            stacks[i] = .empty;
            // Push version 0 as the uninitialized default
            try stacks[i].append(self.allocator, 0);
        }
        defer {
            for (stacks) |*s| s.deinit(self.allocator);
            self.allocator.free(stacks);
        }

        // Kick off the recursive renaming starting at the entry block
        try self.renameBlock(self.entry_block_id, counters, stacks);

        // Prepend phi IR instructions
        for (self.blocks.items) |*block| {
            const num_phis = block.phi_functions.items.len;
            if (num_phis == 0) continue;

            var new_insts = std.ArrayList(ir.IRInst).empty;
            errdefer new_insts.deinit(self.allocator);
            try new_insts.ensureTotalCapacity(self.allocator, num_phis + block.instructions.items.len);

            for (block.phi_functions.items) |phi_node| {
                const reg = phi_node.original_reg;

                const args = try self.allocator.alloc(ir.PhiArg, phi_node.incoming.len);
                @memcpy(args, phi_node.incoming);

                try new_insts.append(self.allocator, .{
                    .phi = .{
                        .dest = .{ .reg = reg, .version = phi_node.ssa_version.? },
                        .args = args,
                    },
                });
            }

            try new_insts.appendSlice(self.allocator, block.instructions.items);
            block.instructions.deinit(self.allocator);
            block.instructions = new_insts;
        }
    }

    fn renameBlock(self: *CFG, block_id: usize, counters: []u32, stacks: []std.ArrayList(u32)) !void {
        const block = &self.blocks.items[block_id];

        // 1. Rename Phi function definitions first
        for (block.phi_functions.items) |*phi_node| {
            const reg = phi_node.original_reg;

            // Generate a fresh version for this register
            counters[@as(usize, reg)] += 1;
            const new_version = counters[@as(usize, reg)];

            // Push it to the stack to make it the active version
            try stacks[@as(usize, reg)].append(self.allocator, new_version);

            // Record it in the phi node (e.g., v0_3 = Phi(...))
            phi_node.ssa_version = new_version;
        }

        // 2. Iterate through normal instructions in this block
        var defs = std.ArrayList(u16).empty;
        defer defs.deinit(self.allocator);

        const renameUse = struct {
            fn f(st: []const std.ArrayList(u32), variable: *ir.SSAVar) void {
                variable.version = st[@as(usize, variable.reg)].items[st[@as(usize, variable.reg)].items.len - 1];
            }
        }.f;

        const renameDef = struct {
            fn f(alloc: std.mem.Allocator, cnt: []u32, st: []std.ArrayList(u32), variable: *ir.SSAVar, dl: *std.ArrayList(u16)) !void {
                const reg = variable.reg;
                cnt[@as(usize, reg)] += 1;
                const new_version = cnt[@as(usize, reg)];
                try st[@as(usize, reg)].append(alloc, new_version);
                variable.version = new_version;
                try dl.append(alloc, reg);
            }
        }.f;

        for (block.instructions.items) |*inst| {
            switch (inst.*) {
                .phi => unreachable,

                // Moves
                .move => |*v| {
                    renameUse(stacks, &v.src);
                    try renameDef(self.allocator, counters, stacks, &v.dest, &defs);
                },

                // Constants
                .const_int => |*v| {
                    try renameDef(self.allocator, counters, stacks, &v.dest, &defs);
                },
                .const_wide => |*v| {
                    try renameDef(self.allocator, counters, stacks, &v.dest, &defs);
                },
                .const_string => |*v| {
                    try renameDef(self.allocator, counters, stacks, &v.dest, &defs);
                },
                .const_class => |*v| {
                    try renameDef(self.allocator, counters, stacks, &v.dest, &defs);
                },

                // Binary Math
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
                .add_long,
                .sub_long,
                .mul_long,
                .div_long,
                .rem_long,
                .and_long,
                .or_long,
                .xor_long,
                .shl_long,
                .shr_long,
                .ushr_long,
                .add_float,
                .sub_float,
                .mul_float,
                .div_float,
                .rem_float,
                .add_wide,
                .sub_wide,
                .mul_wide,
                .div_wide,
                .rem_wide,
                => |*v| {
                    renameUse(stacks, &v.left);
                    renameUse(stacks, &v.right);
                    try renameDef(self.allocator, counters, stacks, &v.dest, &defs);
                },

                // Unary math & conversions
                .un_op => |*v| {
                    renameUse(stacks, &v.src);
                    try renameDef(self.allocator, counters, stacks, &v.dest, &defs);
                },

                // Three-way comparisons
                .cmp_op => |*v| {
                    renameUse(stacks, &v.left);
                    renameUse(stacks, &v.right);
                    try renameDef(self.allocator, counters, stacks, &v.dest, &defs);
                },

                // Literal Math
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
                => |*v| {
                    renameUse(stacks, &v.src);
                    try renameDef(self.allocator, counters, stacks, &v.dest, &defs);
                },

                // Object & Array Allocation
                .new_instance => |*v| {
                    try renameDef(self.allocator, counters, stacks, &v.dest, &defs);
                },
                .new_array => |*v| {
                    renameUse(stacks, &v.size);
                    try renameDef(self.allocator, counters, stacks, &v.dest, &defs);
                },

                // Memory Access
                .iget => |*v| {
                    renameUse(stacks, &v.obj);
                    try renameDef(self.allocator, counters, stacks, &v.dest_or_src, &defs);
                },
                .iput => |*v| {
                    renameUse(stacks, &v.obj);
                    renameUse(stacks, &v.dest_or_src);
                },
                .sget => |*v| {
                    try renameDef(self.allocator, counters, stacks, &v.dest_or_src, &defs);
                },
                .sput => |*v| {
                    renameUse(stacks, &v.dest_or_src);
                },
                .aget => |*v| {
                    renameUse(stacks, &v.array);
                    renameUse(stacks, &v.index);
                    try renameDef(self.allocator, counters, stacks, &v.dest_or_src, &defs);
                },
                .aput => |*v| {
                    renameUse(stacks, &v.array);
                    renameUse(stacks, &v.index);
                    renameUse(stacks, &v.dest_or_src);
                },

                // Control Flow
                .goto => {},
                .if_eq,
                .if_ne,
                .if_lt,
                .if_ge,
                .if_gt,
                .if_le,
                => |*v| {
                    renameUse(stacks, &v.left);
                    renameUse(stacks, &v.right);
                },
                .if_eqz,
                .if_nez,
                .if_ltz,
                .if_gez,
                .if_gtz,
                .if_lez,
                => |*v| {
                    renameUse(stacks, &v.src);
                },
                .switch_op => |*v| {
                    renameUse(stacks, &v.src);
                },

                // Functions
                .invoke => |*v| {
                    for (v.args) |*arg| {
                        renameUse(stacks, arg);
                    }
                    if (v.dest) |*d| {
                        try renameDef(self.allocator, counters, stacks, d, &defs);
                    }
                },
                .monitor_enter => |*v| {
                    renameUse(stacks, &v.src);
                },
                .monitor_exit => |*v| {
                    renameUse(stacks, &v.src);
                },
                .ret => |*v| {
                    if (v.src) |*s| {
                        renameUse(stacks, s);
                    }
                },
                .throw_op => |*v| {
                    renameUse(stacks, &v.src);
                },
            }
        }

        // 3. Fill in Phi function arguments for our Successors
        for (block.successors.items) |succ_id| {
            const succ_block = &self.blocks.items[succ_id];
            for (succ_block.phi_functions.items) |*phi_node| {
                const reg = phi_node.original_reg;
                const current_active_version = stacks[@as(usize, reg)].items[stacks[@as(usize, reg)].items.len - 1];

                for (phi_node.incoming) |*arg| {
                    if (arg.pred_block_id == block_id) {
                        arg.val.version = current_active_version;
                        break;
                    }
                }
            }
        }

        // 4. Recurse down the dominator tree
        for (block.dom_children.items) |child_id| {
            try self.renameBlock(child_id, counters, stacks);
        }

        // 5. Cleanup (Pop the stacks)
        for (block.phi_functions.items) |phi_node| {
            _ = stacks[@as(usize, phi_node.original_reg)].pop();
        }

        while (defs.items.len > 0) {
            const reg = defs.pop().?;
            _ = stacks[@as(usize, reg)].pop();
        }
    }
};

pub const CfgError = error{
    /// A branch/switch offset points outside the instruction slice, or a jump
    /// target does not land on a block leader. Indicates malformed bytecode.
    BadBranchTarget,
    OutOfMemory,
};

/// Resolves `base + offset` to an in-range instruction index, or errors.
fn resolveTarget(base: usize, offset: i32, len: usize) CfgError!usize {
    const t = @as(i64, @intCast(base)) + offset;
    if (t < 0 or t >= @as(i64, @intCast(len))) return error.BadBranchTarget;
    return @intCast(t);
}

/// Builds a Control Flow Graph from a linear slice of instructions.
pub fn buildCFG(allocator: std.mem.Allocator, instructions: []const Instruction) CfgError!CFG {
    return buildCFGWithTries(allocator, instructions, &.{});
}

pub fn buildCFGWithTries(
    allocator: std.mem.Allocator,
    instructions: []const Instruction,
    tries: []const instmod.TryBlock,
) CfgError!CFG {
    var leaders = std.AutoHashMap(usize, void).init(allocator);
    defer leaders.deinit();

    // --- STEP 1: Identify all Block Leaders ---
    // Rule 1: The first instruction is always a leader.
    if (instructions.len > 0) try leaders.put(0, {});

    for (instructions, 0..) |inst, i| {
        const is_last = i == instructions.len - 1;

        if (inst.branchOffset()) |offset| {
            // Rule 2: The target of any jump/branch is a leader.
            try leaders.put(try resolveTarget(i, offset, instructions.len), {});

            // Rule 3: The instruction immediately following a branch is a leader.
            if (!is_last) try leaders.put(i + 1, {});
        } else {
            switch (inst) {
                .packed_switch => |sw| {
                    for (sw.targets) |offset| {
                        try leaders.put(try resolveTarget(i, offset, instructions.len), {});
                    }
                    if (!is_last) try leaders.put(i + 1, {});
                },
                .sparse_switch => |sw| {
                    for (sw.targets) |offset| {
                        try leaders.put(try resolveTarget(i, offset, instructions.len), {});
                    }
                    if (!is_last) try leaders.put(i + 1, {});
                },
                .return_void, .return_, .return_wide, .return_object, .throw_ => {
                    // Instruction following a return/throw is a leader (even if it's dead code)
                    if (!is_last) try leaders.put(i + 1, {});
                },
                else => {}, // Normal sequential instruction
            }
        }
    }

    // Rule 4: Every catch handler target is a leader.
    for (tries) |t| {
        for (t.handlers) |h| {
            try leaders.put(h.target_pc, {});
            if (h.target_pc + 1 < instructions.len) {
                try leaders.put(h.target_pc + 1, {});
            }
        }
        if (t.start_pc < instructions.len) try leaders.put(t.start_pc, {});
        if (t.end_pc < instructions.len) try leaders.put(t.end_pc, {});
    }

    // --- STEP 2: Sort Leaders to Define Block Boundaries ---
    var leader_list = std.ArrayList(usize).empty;
    defer leader_list.deinit(allocator);

    var it = leaders.keyIterator();
    while (it.next()) |key| {
        try leader_list.append(allocator, key.*);
    }
    std.mem.sort(usize, leader_list.items, {}, std.sort.asc(usize));

    // --- STEP 3: Create the Blocks ---
    var cfg = CFG{
        .blocks = std.ArrayList(BasicBlock).empty,
        .allocator = allocator,
    };
    errdefer cfg.deinit();

    for (leader_list.items, 0..) |start_idx, block_id| {
        const end_idx = if (block_id + 1 < leader_list.items.len)
            leader_list.items[block_id + 1] - 1
        else
            instructions.len - 1;

        try cfg.blocks.append(allocator, .{
            .id = block_id,
            .start_idx = start_idx,
            .end_idx = end_idx,
            .successors = std.ArrayList(usize).empty,
            .predecessors = std.ArrayList(usize).empty,
            .idom = null,
            .dominance_frontier = std.ArrayList(usize).empty,
            .phi_functions = .empty,
            .dom_children = std.ArrayList(usize).empty,
            .instructions = std.ArrayList(ir.IRInst).empty,
        });
    }

    // Map each block's start index to its ID, for O(1) target → block lookup
    var start_to_id = std.AutoHashMap(usize, usize).init(allocator);
    defer start_to_id.deinit();
    for (cfg.blocks.items) |b| try start_to_id.put(b.start_idx, b.id);

    // Resolves a jump target index to the ID of the block it starts.
    const targetBlockId = struct {
        fn f(map: *const std.AutoHashMap(usize, usize), base: usize, offset: i32, len: usize) CfgError!usize {
            const idx = try resolveTarget(base, offset, len);
            return map.get(idx) orelse error.BadBranchTarget;
        }
    }.f;

    // --- STEP 4: Link the Edges (Successors) ---
    const n = instructions.len;
    for (cfg.blocks.items) |*block| {
        const last_inst = instructions[block.end_idx];
        const is_last_block = block.id == cfg.blocks.items.len - 1;

        switch (last_inst) {
            .goto_ => |v| {
                try block.successors.append(allocator, try targetBlockId(&start_to_id, block.end_idx, v.offset, n));
            },
            .return_void, .return_, .return_wide, .return_object, .throw_ => {
                // Returns and exceptions are exit points; they have zero successors in this CFG
            },
            .packed_switch => |sw| {
                for (sw.targets) |offset| {
                    try block.successors.append(allocator, try targetBlockId(&start_to_id, block.end_idx, offset, n));
                }
                if (!is_last_block) try block.successors.append(allocator, block.id + 1); // Fallthrough
            },
            .sparse_switch => |sw| {
                for (sw.targets) |offset| {
                    try block.successors.append(allocator, try targetBlockId(&start_to_id, block.end_idx, offset, n));
                }
                if (!is_last_block) try block.successors.append(allocator, block.id + 1); // Fallthrough
            },
            else => {
                if (last_inst.branchOffset()) |offset| {
                    try block.successors.append(allocator, try targetBlockId(&start_to_id, block.end_idx, offset, n));
                }

                if (!is_last_block) {
                    try block.successors.append(allocator, block.id + 1);
                }
            },
        }

        // Add exceptional successor edges if this block overlaps with any TryBlock
        for (tries) |t| {
            if (block.start_idx < t.end_pc and block.end_idx >= t.start_pc) {
                for (t.handlers) |h| {
                    const catch_block_id = start_to_id.get(h.target_pc) orelse continue;
                    var already_present = false;
                    for (block.successors.items) |succ| {
                        if (succ == catch_block_id) {
                            already_present = true;
                            break;
                        }
                    }
                    if (!already_present) {
                        try block.successors.append(allocator, catch_block_id);
                    }
                }
            }
        }
    }

    return cfg;
}

// ── Tests ────────────────────────────────────────────────────────────────────

test "linear block: no branches → single block, no successors" {
    const a = std.testing.allocator;
    const insns = [_]Instruction{
        .{ .const_ = .{ .dest = 0, .value = 1 } },
        .{ .add_int = .{ .dest = 0, .src1 = 0, .src2 = 0 } },
        .return_void,
    };
    var cfg = try buildCFG(a, &insns);
    defer cfg.deinit();
    try std.testing.expectEqual(@as(usize, 1), cfg.blocks.items.len);
    try std.testing.expectEqual(@as(usize, 0), cfg.blocks.items[0].successors.items.len);
}

test "conditional branch: splits into blocks with two successors" {
    const a = std.testing.allocator;
    // 0: if_eqz v0, +2   (target = idx 2)
    // 1: return_void      (fallthrough)
    // 2: return_void      (branch target)
    const insns = [_]Instruction{
        .{ .if_eqz = .{ .src = 0, .offset = 2 } },
        .return_void,
        .return_void,
    };
    var cfg = try buildCFG(a, &insns);
    defer cfg.deinit();
    // Leaders: 0 (first), 2 (target), 1 (after branch) → 3 blocks.
    try std.testing.expectEqual(@as(usize, 3), cfg.blocks.items.len);
    // Block 0 ends in if_eqz → fallthrough (block 1) + branch target (block 2).
    const succ = cfg.blocks.items[0].successors.items;
    try std.testing.expectEqual(@as(usize, 2), succ.len);
}

test "goto back-edge (loop) resolves to earlier block" {
    const a = std.testing.allocator;
    // 0: add_int          (loop body / target)
    // 1: goto -1          (back to idx 0)
    const insns = [_]Instruction{
        .{ .add_int = .{ .dest = 0, .src1 = 0, .src2 = 0 } },
        .{ .goto_ = .{ .offset = -1 } },
    };
    var cfg = try buildCFG(a, &insns);
    defer cfg.deinit();
    // The goto block's sole successor is the block starting at idx 0.
    const last = &cfg.blocks.items[cfg.blocks.items.len - 1];
    try std.testing.expectEqual(@as(usize, 1), last.successors.items.len);
    try std.testing.expectEqual(cfg.blocks.items[0].id, last.successors.items[0]);
}

test "out-of-range branch target errors instead of panicking" {
    const a = std.testing.allocator;
    const insns = [_]Instruction{
        .{ .goto_ = .{ .offset = 100 } }, // way past the end
    };
    try std.testing.expectError(error.BadBranchTarget, buildCFG(a, &insns));
}

// ── Predecessor Tests ─────────────────────────────────────────────────────────

test "computePredecessors: linear chain" {
    // 0: const
    // 1: goto +1  (target = idx 2, a leader)
    // 2: return_void
    // Blocks: 0=[0..0], 1=[1..1], 2=[2..2]
    // Edges: 0->1 (fallthrough after goto? no — goto has no fallthrough)
    //        0: goto to block 2, so only edge 0->2
    //        Actually 1 is dead code but still a leader.
    // Simpler: use a conditional branch.
    //
    // 0: if_eqz v0, +2  → fallthrough block 1, branch target block 2
    // 1: return_void
    // 2: return_void
    const a = std.testing.allocator;
    const insns = [_]Instruction{
        .{ .if_eqz = .{ .src = 0, .offset = 2 } },
        .return_void,
        .return_void,
    };
    var cfg = try buildCFG(a, &insns);
    defer cfg.deinit();
    try cfg.computePredecessors();

    // Block 0 is the entry — it has no predecessors
    try std.testing.expectEqual(@as(usize, 0), cfg.blocks.items[0].predecessors.items.len);

    // Block 1 (fallthrough of block 0) has exactly block 0 as predecessor
    try std.testing.expectEqual(@as(usize, 1), cfg.blocks.items[1].predecessors.items.len);
    try std.testing.expectEqual(@as(usize, 0), cfg.blocks.items[1].predecessors.items[0]);

    // Block 2 (branch target of block 0) has exactly block 0 as predecessor
    try std.testing.expectEqual(@as(usize, 1), cfg.blocks.items[2].predecessors.items.len);
    try std.testing.expectEqual(@as(usize, 0), cfg.blocks.items[2].predecessors.items[0]);
}

test "computePredecessors: loop back-edge" {
    // A loop with a conditional exit:
    //   0: if_eqz v0, +2  → fallthrough block1(idx1), branch block2(idx2)
    //   1: goto -1         → back-edge to block0(idx0)
    //   2: return_void     → exit
    //
    // Leaders: {0, 1(after branch), 2(branch target)}
    // Blocks: 0=[0..0], 1=[1..1], 2=[2..2]
    // Edges: 0→1 (fallthrough), 0→2 (branch), 1→0 (back-edge)
    const a = std.testing.allocator;
    const insns = [_]Instruction{
        .{ .if_eqz = .{ .src = 0, .offset = 2 } }, // idx 0
        .{ .goto_ = .{ .offset = -1 } }, // idx 1: back to idx 0
        .return_void, // idx 2: exit
    };
    var cfg = try buildCFG(a, &insns);
    defer cfg.deinit();
    try cfg.computePredecessors();

    try std.testing.expectEqual(@as(usize, 3), cfg.blocks.items.len);

    // Block 0 (entry): predecessor = block 1 (back-edge)
    const preds0 = cfg.blocks.items[0].predecessors.items;
    try std.testing.expectEqual(@as(usize, 1), preds0.len);
    try std.testing.expectEqual(@as(usize, 1), preds0[0]); // block 1 → block 0

    // Block 1 (loop body): predecessor = block 0
    const preds1 = cfg.blocks.items[1].predecessors.items;
    try std.testing.expectEqual(@as(usize, 1), preds1.len);
    try std.testing.expectEqual(@as(usize, 0), preds1[0]); // block 0 → block 1

    // Block 2 (exit): predecessor = block 0
    const preds2 = cfg.blocks.items[2].predecessors.items;
    try std.testing.expectEqual(@as(usize, 1), preds2.len);
    try std.testing.expectEqual(@as(usize, 0), preds2[0]); // block 0 → block 2
}

test "computePredecessors: idempotent on re-run" {
    // Calling computePredecessors twice should yield the same result.
    const a = std.testing.allocator;
    const insns = [_]Instruction{
        .{ .if_eqz = .{ .src = 0, .offset = 2 } },
        .return_void,
        .return_void,
    };
    var cfg = try buildCFG(a, &insns);
    defer cfg.deinit();
    try cfg.computePredecessors();
    try cfg.computePredecessors(); // second call should not duplicate entries

    // Block 1 should still have exactly one predecessor (block 0), not two
    try std.testing.expectEqual(@as(usize, 1), cfg.blocks.items[1].predecessors.items.len);
    try std.testing.expectEqual(@as(usize, 1), cfg.blocks.items[2].predecessors.items.len);
}

// ── Dominator Tests ───────────────────────────────────────────────────────────

test "computeDominators: single block" {
    // A single-block function: entry has no idom.
    const a = std.testing.allocator;
    const insns = [_]Instruction{.return_void};
    var cfg = try buildCFG(a, &insns);
    defer cfg.deinit();
    try cfg.computePredecessors();
    try cfg.computeDominators();

    try std.testing.expectEqual(@as(?usize, null), cfg.blocks.items[0].idom);
}

test "computeDominators: linear three-block chain" {
    // 0: if_eqz → block 1 or block 2
    // 1: return_void
    // 2: return_void
    // Dominators: 0 dom {0,1,2}, idom(1)=0, idom(2)=0
    const a = std.testing.allocator;
    const insns = [_]Instruction{
        .{ .if_eqz = .{ .src = 0, .offset = 2 } },
        .return_void,
        .return_void,
    };
    var cfg = try buildCFG(a, &insns);
    defer cfg.deinit();
    try cfg.computePredecessors();
    try cfg.computeDominators();

    // Entry block has no idom
    try std.testing.expectEqual(@as(?usize, null), cfg.blocks.items[0].idom);
    // Block 1 (fallthrough) is immediately dominated by block 0
    try std.testing.expectEqual(@as(?usize, 0), cfg.blocks.items[1].idom);
    // Block 2 (branch target) is immediately dominated by block 0
    try std.testing.expectEqual(@as(?usize, 0), cfg.blocks.items[2].idom);
}

test "computeDominators: diamond CFG" {
    // Classic diamond pattern:
    //       0 (if-branch)
    //      / \
    //     1   2
    //      \ /
    //       3 (join)
    //
    // Instructions:
    //   0: if_eqz v0, +3   (branch to idx 3, fallthrough to idx 1)
    //   1: nop
    //   2: goto +1          (jump to idx 3)
    //   3: return_void
    //
    // Leaders: 0, 1, 3 (target of branch), 3 (target of goto)
    // Actually: 0 (first), 1 (after branch), 3 (branch target), 3 (goto target = same)
    // Leaders: {0, 1, 3} → blocks 0=[0..0], 1=[1..2], 2=[3..3]
    //
    // Simpler diamond with 4 blocks:
    //   0: if_eqz v0, +2   → block1=fallthrough(idx1), block2=branch(idx2)
    //   1: goto +2          → block3(idx3)
    //   2: nop              → fallthrough to block3
    //   3: return_void
    //
    // Leaders: 0, 1(after branch), 2(branch target), 3(goto target=idx3), 3(after nop)
    // Leaders: {0,1,2,3} → 4 blocks
    //   Block 0: [0..0], successors: 1 (fallthrough), 2 (branch target idx2=block2)
    //   Block 1: [1..1], successors: 3 (goto idx3=block3)
    //   Block 2: [2..2], successors: 3 (fallthrough)
    //   Block 3: [3..3], successors: none
    //
    // idom: 1→0, 2→0, 3→0 (0 dominates everything in a diamond)
    const a = std.testing.allocator;
    const insns = [_]Instruction{
        .{ .if_eqz = .{ .src = 0, .offset = 2 } }, // idx 0
        .{ .goto_ = .{ .offset = 2 } }, // idx 1: jump to idx 3
        .{ .nop = {} }, // idx 2
        .return_void, // idx 3
    };
    var cfg = try buildCFG(a, &insns);
    defer cfg.deinit();
    try cfg.computePredecessors();
    try cfg.computeDominators();

    // 4 blocks expected
    try std.testing.expectEqual(@as(usize, 4), cfg.blocks.items.len);

    // Entry dominates everything — no idom for entry
    try std.testing.expectEqual(@as(?usize, null), cfg.blocks.items[0].idom);
    // Blocks 1, 2, 3 are all immediately dominated by block 0
    try std.testing.expectEqual(@as(?usize, 0), cfg.blocks.items[1].idom);
    try std.testing.expectEqual(@as(?usize, 0), cfg.blocks.items[2].idom);
    try std.testing.expectEqual(@as(?usize, 0), cfg.blocks.items[3].idom);
}

test "computeDominators: loop — back edge does not break dominator calc" {
    // A conditional loop:
    //   0: if_eqz v0, +2  → block1(fallthrough) or block2(branch, exit)
    //   1: goto -1         → back to block0
    //   2: return_void
    //
    // idom(1) = 0, idom(2) = 0 (block 0 is the only entry to both)
    const a = std.testing.allocator;
    const insns = [_]Instruction{
        .{ .if_eqz = .{ .src = 0, .offset = 2 } },
        .{ .goto_ = .{ .offset = -1 } },
        .return_void,
    };
    var cfg = try buildCFG(a, &insns);
    defer cfg.deinit();
    try cfg.computePredecessors();
    try cfg.computeDominators();

    try std.testing.expectEqual(@as(usize, 3), cfg.blocks.items.len);
    try std.testing.expectEqual(@as(?usize, null), cfg.blocks.items[0].idom); // entry
    try std.testing.expectEqual(@as(?usize, 0), cfg.blocks.items[1].idom); // loop body
    try std.testing.expectEqual(@as(?usize, 0), cfg.blocks.items[2].idom); // exit
}

test "computeDominanceFrontiers: diamond CFG" {
    // Diamond pattern:
    //   0: if_eqz v0, +2  → block1(fallthrough) or block2(branch)
    //   1: goto +2         → block3(idx3)
    //   2: nop             → block3(idx3)
    //   3: return_void
    //
    // Dominance:
    //   0 dominates {0, 1, 2, 3}
    //   1 dominates {1}
    //   2 dominates {2}
    //   3 dominates {3}
    //
    // Dominance Frontiers:
    //   DF(0) = {} (dominates everything)
    //   DF(1) = {3}
    //   DF(2) = {3}
    //   DF(3) = {}
    const a = std.testing.allocator;
    const insns = [_]Instruction{
        .{ .if_eqz = .{ .src = 0, .offset = 2 } }, // idx 0
        .{ .goto_ = .{ .offset = 2 } }, // idx 1
        .{ .nop = {} }, // idx 2
        .return_void, // idx 3
    };
    var cfg = try buildCFG(a, &insns);
    defer cfg.deinit();
    try cfg.computePredecessors();
    try cfg.computeDominators();
    try cfg.computeDominanceFrontiers();

    // Check block 1's DF
    const df1 = cfg.blocks.items[1].dominance_frontier.items;
    try std.testing.expectEqual(@as(usize, 1), df1.len);
    try std.testing.expectEqual(@as(usize, 3), df1[0]);

    // Check block 2's DF
    const df2 = cfg.blocks.items[2].dominance_frontier.items;
    try std.testing.expectEqual(@as(usize, 1), df2.len);
    try std.testing.expectEqual(@as(usize, 3), df2[0]);

    // Check block 0 and 3's DF (should be empty)
    try std.testing.expectEqual(@as(usize, 0), cfg.blocks.items[0].dominance_frontier.items.len);
    try std.testing.expectEqual(@as(usize, 0), cfg.blocks.items[3].dominance_frontier.items.len);
}

test "computeDominanceFrontiers: loop CFG" {
    // A conditional loop:
    //   0: if_eqz v0, +2  → block1(fallthrough, loop body) or block2(branch, exit)
    //   1: goto -1         → back to block0
    //   2: return_void
    //
    // Dominance:
    //   0 dominates {0, 1, 2}
    //   1 dominates {1}
    //   2 dominates {2}
    //
    // Dominance Frontiers:
    //   DF(0) = {}
    //   DF(1) = {0}
    //   DF(2) = {}
    const a = std.testing.allocator;
    const insns = [_]Instruction{
        .{ .if_eqz = .{ .src = 0, .offset = 2 } },
        .{ .goto_ = .{ .offset = -1 } },
        .return_void,
    };
    var cfg = try buildCFG(a, &insns);
    defer cfg.deinit();
    try cfg.computePredecessors();
    try cfg.computeDominators();
    try cfg.computeDominanceFrontiers();

    // Check block 1's DF (should contain block 0)
    const df1 = cfg.blocks.items[1].dominance_frontier.items;
    try std.testing.expectEqual(@as(usize, 1), df1.len);
    try std.testing.expectEqual(@as(usize, 0), df1[0]);

    // Check block 0 and 2's DF (should be empty)
    try std.testing.expectEqual(@as(usize, 0), cfg.blocks.items[0].dominance_frontier.items.len);
    try std.testing.expectEqual(@as(usize, 0), cfg.blocks.items[2].dominance_frontier.items.len);
}

test "insertPhiFunctions: diamond CFG" {
    const a = std.testing.allocator;
    const insns = [_]Instruction{
        .{ .if_eqz = .{ .src = 0, .offset = 2 } }, // idx 0
        .{ .goto_ = .{ .offset = 2 } }, // idx 1
        .{ .nop = {} }, // idx 2
        .return_void, // idx 3
    };
    var cfg = try buildCFG(a, &insns);
    defer cfg.deinit();
    try cfg.computePredecessors();
    try cfg.computeDominators();
    try cfg.computeDominanceFrontiers();

    // Map register v0 definition in block 1
    var def_map = std.AutoHashMap(u16, std.ArrayList(usize)).init(a);
    defer {
        var it = def_map.iterator();
        while (it.next()) |entry| {
            var val = entry.value_ptr.*;
            val.deinit(a);
        }
        def_map.deinit();
    }

    var defs0 = std.ArrayList(usize).empty;
    try defs0.append(a, 1); // v0 defined in block 1
    try def_map.put(0, defs0);

    try cfg.insertPhiFunctions(def_map);

    // Block 3 is in DF(1), so it should have a phi function for v0
    const phi = cfg.blocks.items[3].getPhiConst(0);
    try std.testing.expect(phi != null);
    try std.testing.expectEqual(@as(u16, 0), phi.?.original_reg);

    // Block 1 and 2 should not have a phi function for v0
    try std.testing.expect(cfg.blocks.items[1].getPhiConst(0) == null);
    try std.testing.expect(cfg.blocks.items[2].getPhiConst(0) == null);
}

test "cfg: rename variables and SSA generation with long arithmetic ops" {
    const a = std.testing.allocator;

    var cfg = CFG{
        .blocks = std.ArrayList(BasicBlock).empty,
        .allocator = a,
    };
    defer cfg.deinit();

    var block = BasicBlock{
        .id = 0,
        .start_idx = 0,
        .end_idx = 3,
        .successors = std.ArrayList(usize).empty,
        .predecessors = std.ArrayList(usize).empty,
        .dominance_frontier = std.ArrayList(usize).empty,
        .dom_children = std.ArrayList(usize).empty,
        .idom = null,
        .phi_functions = std.ArrayList(PhiNode).empty,
        .instructions = std.ArrayList(ir.IRInst).empty,
    };
    try block.instructions.append(a, .{ .const_wide = .{ .dest = .{ .reg = 0, .version = 0 }, .val = 10 } });
    try block.instructions.append(a, .{ .const_wide = .{ .dest = .{ .reg = 2, .version = 0 }, .val = 20 } });
    try block.instructions.append(a, .{ .add_long = .{ .dest = .{ .reg = 4, .version = 0 }, .left = .{ .reg = 0, .version = 0 }, .right = .{ .reg = 2, .version = 0 } } });
    try block.instructions.append(a, .{ .ret = .{ .src = .{ .reg = 4, .version = 0 } } });
    try cfg.blocks.append(a, block);

    try cfg.renameVariables(6);

    const insts = cfg.blocks.items[0].instructions.items;
    const add_inst = insts[2].add_long;
    try std.testing.expectEqual(@as(u16, 0), add_inst.left.reg);
    try std.testing.expect(add_inst.left.version > 0);
    try std.testing.expectEqual(@as(u16, 2), add_inst.right.reg);
    try std.testing.expect(add_inst.right.version > 0);
    try std.testing.expectEqual(@as(u16, 4), add_inst.dest.reg);
    try std.testing.expect(add_inst.dest.version > 0);
}

test "buildCFGWithTries: try/catch exceptional edges linked correctly" {
    const a = std.testing.allocator;

    const insns = [_]Instruction{
        .{ .const_ = .{ .dest = 0, .value = 1 } },
        .{ .div_int = .{ .dest = 1, .src1 = 0, .src2 = 0 } },
        .{ .return_ = .{ .src = 1 } },
        .{ .const_ = .{ .dest = 1, .value = 99 } },
        .{ .return_ = .{ .src = 1 } },
    };

    const handler = instmod.CatchHandler{
        .type_idx = 1,
        .target_pc = 3,
    };
    const try_block = instmod.TryBlock{
        .start_pc = 1,
        .end_pc = 2,
        .handlers = &[_]instmod.CatchHandler{handler},
    };

    var cfg = try buildCFGWithTries(a, &insns, &[_]instmod.TryBlock{try_block});
    defer cfg.deinit();

    try cfg.computePredecessors();

    var try_block_id: ?usize = null;
    var catch_block_id: ?usize = null;

    for (cfg.blocks.items) |block| {
        if (block.start_idx <= 1 and block.end_idx >= 1) {
            try_block_id = block.id;
        }
        if (block.start_idx <= 3 and block.end_idx >= 3) {
            catch_block_id = block.id;
        }
    }

    try std.testing.expect(try_block_id != null);
    try std.testing.expect(catch_block_id != null);

    var found_succ = false;
    for (cfg.blocks.items[try_block_id.?].successors.items) |succ| {
        if (succ == catch_block_id.?) {
            found_succ = true;
            break;
        }
    }
    try std.testing.expect(found_succ);

    var found_pred = false;
    for (cfg.blocks.items[catch_block_id.?].predecessors.items) |pred| {
        if (pred == try_block_id.?) {
            found_pred = true;
            break;
        }
    }
    try std.testing.expect(found_pred);
}
