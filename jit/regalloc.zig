const std = @import("std");
const ir = @import("ir");
const x86 = @import("x86");
const cfgmod = @import("cfg");

pub const RegClass = enum { gpr, xmm };

pub const LiveInterval = struct {
    vreg: ir.SSAVar,
    start: usize,
    end: usize,
    reg: ?x86.PhysicalReg = null,
    stack_offset: ?i32 = null,
    hint_vreg: ?ir.SSAVar = null,
    class: RegClass = .gpr,
    live_across_call: bool = false,
};

inline fn isCalleeSaved(reg: x86.PhysicalReg) bool {
    return switch (reg) {
        .rbx, .rsi, .rdi, .r12, .r13, .r14, .r15 => true,
        else => false,
    };
}

/// Comparator to sort intervals by start position.
fn compareIntervals(context: void, a: LiveInterval, b: LiveInterval) bool {
    _ = context;
    if (a.start == b.start) {
        return a.end < b.end;
    }
    return a.start < b.start;
}

/// Comparator to sort active intervals by end position.
fn compareActive(context: void, a: *const LiveInterval, b: *const LiveInterval) bool {
    _ = context;
    return a.end < b.end;
}

pub fn allocateRegisters(allocator: std.mem.Allocator, program: *x86.MachineProgram, cfg_opt: ?*cfgmod.CFG, registers_size: u16, ins_size: u16) !void {
    // 0. Prepend parameter mov instructions to the entry block to load parameters from RCX, RDX, R8, R9.
    if (ins_size > 0 and program.blocks.items.len > 0) {
        const first_block = &program.blocks.items[0];
        const arg_regs = [_]x86.PhysicalReg{ .rcx, .rdx, .r8, .r9 };
        var i: u16 = 0;
        while (i < ins_size and i < 4) : (i += 1) {
            const param_reg = registers_size - ins_size + i;
            const v = ir.SSAVar{ .reg = param_reg, .version = 0 };
            try first_block.instructions.insert(allocator, i, .{ .mov = .{
                .dest = .{ .vreg = v },
                .src = .{ .reg = arg_regs[i] },
            } });
        }
    }

    // 1. Gather all virtual registers and compute their live intervals.
    // Map from ir.SSAVar -> LiveInterval.
    var interval_map = std.AutoHashMap(ir.SSAVar, LiveInterval).init(allocator);
    defer interval_map.deinit();

    var call_indices = std.ArrayList(usize).empty;
    defer call_indices.deinit(allocator);

    var global_inst_idx: usize = 0;

    for (program.blocks.items) |block| {
        for (block.instructions.items) |inst| {
            // Helper closure/logic to update interval for a read or write
            const helper = struct {
                fn process(map: *std.AutoHashMap(ir.SSAVar, LiveInterval), op: x86.Operand, idx: usize, is_def: bool, class: RegClass) !void {
                    switch (op) {
                        .vreg => |v| {
                            if (map.getPtr(v)) |interval| {
                                if (idx > interval.end) {
                                    interval.end = idx;
                                }
                                if (idx < interval.start) {
                                    interval.start = idx;
                                }
                                if (class == .xmm) {
                                    interval.class = .xmm;
                                }
                            } else {
                                try map.put(v, .{
                                    .vreg = v,
                                    .start = idx,
                                    .end = idx,
                                    .class = class,
                                });
                            }
                            _ = is_def;
                        },
                        .mem => |m| {
                            switch (m.base) {
                                .vreg => |bv| try process(map, .{ .vreg = bv }, idx, false, .gpr),
                                else => {},
                            }
                            if (m.index) |idx_op| {
                                switch (idx_op) {
                                    .vreg => |iv| try process(map, .{ .vreg = iv }, idx, false, .gpr),
                                    else => {},
                                }
                            }
                        },
                        else => {},
                    }
                }
            };

            // Inspect all operands for this instruction to compute intervals.
            switch (inst) {
                .mov => |v| {
                    try helper.process(&interval_map, v.dest, global_inst_idx, true, .gpr);
                    try helper.process(&interval_map, v.src, global_inst_idx, false, .gpr);

                    // Set hint if both are virtual registers to allow coalescing.
                    if (v.dest == .vreg and v.src == .vreg) {
                        const d = v.dest.vreg;
                        const s = v.src.vreg;
                        if (interval_map.getPtr(d)) |interval_d| {
                            interval_d.hint_vreg = s;
                        }
                        if (interval_map.getPtr(s)) |interval_s| {
                            interval_s.hint_vreg = d;
                        }
                    }
                },
                .add => |v| {
                    try helper.process(&interval_map, v.dest, global_inst_idx, true, .gpr);
                    try helper.process(&interval_map, v.src, global_inst_idx, false, .gpr);
                },
                .sub => |v| {
                    try helper.process(&interval_map, v.dest, global_inst_idx, true, .gpr);
                    try helper.process(&interval_map, v.src, global_inst_idx, false, .gpr);
                },
                .imul => |v| {
                    try helper.process(&interval_map, v.dest, global_inst_idx, true, .gpr);
                    try helper.process(&interval_map, v.src, global_inst_idx, false, .gpr);
                },
                .and_op => |v| {
                    try helper.process(&interval_map, v.dest, global_inst_idx, true, .gpr);
                    try helper.process(&interval_map, v.src, global_inst_idx, false, .gpr);
                },
                .or_op => |v| {
                    try helper.process(&interval_map, v.dest, global_inst_idx, true, .gpr);
                    try helper.process(&interval_map, v.src, global_inst_idx, false, .gpr);
                },
                .xor_op => |v| {
                    try helper.process(&interval_map, v.dest, global_inst_idx, true, .gpr);
                    try helper.process(&interval_map, v.src, global_inst_idx, false, .gpr);
                },
                .shl => |v| {
                    try helper.process(&interval_map, v.dest, global_inst_idx, true, .gpr);
                    try helper.process(&interval_map, v.src, global_inst_idx, false, .gpr);
                },
                .shr => |v| {
                    try helper.process(&interval_map, v.dest, global_inst_idx, true, .gpr);
                    try helper.process(&interval_map, v.src, global_inst_idx, false, .gpr);
                },
                .ushr => |v| {
                    try helper.process(&interval_map, v.dest, global_inst_idx, true, .gpr);
                    try helper.process(&interval_map, v.src, global_inst_idx, false, .gpr);
                },

                // SSE Single Precision float instructions
                .addss => |v| {
                    try helper.process(&interval_map, v.dest, global_inst_idx, true, .xmm);
                    try helper.process(&interval_map, v.src, global_inst_idx, false, .xmm);
                },
                .subss => |v| {
                    try helper.process(&interval_map, v.dest, global_inst_idx, true, .xmm);
                    try helper.process(&interval_map, v.src, global_inst_idx, false, .xmm);
                },
                .mulss => |v| {
                    try helper.process(&interval_map, v.dest, global_inst_idx, true, .xmm);
                    try helper.process(&interval_map, v.src, global_inst_idx, false, .xmm);
                },
                .divss => |v| {
                    try helper.process(&interval_map, v.dest, global_inst_idx, true, .xmm);
                    try helper.process(&interval_map, v.src, global_inst_idx, false, .xmm);
                },
                .movss => |v| {
                    try helper.process(&interval_map, v.dest, global_inst_idx, true, .xmm);
                    try helper.process(&interval_map, v.src, global_inst_idx, false, .xmm);
                    if (v.dest == .vreg and v.src == .vreg) {
                        const d = v.dest.vreg;
                        const s = v.src.vreg;
                        if (interval_map.getPtr(d)) |interval_d| interval_d.hint_vreg = s;
                        if (interval_map.getPtr(s)) |interval_s| interval_s.hint_vreg = d;
                    }
                },

                // SSE Double Precision float instructions
                .addsd => |v| {
                    try helper.process(&interval_map, v.dest, global_inst_idx, true, .xmm);
                    try helper.process(&interval_map, v.src, global_inst_idx, false, .xmm);
                },
                .subsd => |v| {
                    try helper.process(&interval_map, v.dest, global_inst_idx, true, .xmm);
                    try helper.process(&interval_map, v.src, global_inst_idx, false, .xmm);
                },
                .mulsd => |v| {
                    try helper.process(&interval_map, v.dest, global_inst_idx, true, .xmm);
                    try helper.process(&interval_map, v.src, global_inst_idx, false, .xmm);
                },
                .divsd => |v| {
                    try helper.process(&interval_map, v.dest, global_inst_idx, true, .xmm);
                    try helper.process(&interval_map, v.src, global_inst_idx, false, .xmm);
                },
                .movsd => |v| {
                    try helper.process(&interval_map, v.dest, global_inst_idx, true, .xmm);
                    try helper.process(&interval_map, v.src, global_inst_idx, false, .xmm);
                    if (v.dest == .vreg and v.src == .vreg) {
                        const d = v.dest.vreg;
                        const s = v.src.vreg;
                        if (interval_map.getPtr(d)) |interval_d| interval_d.hint_vreg = s;
                        if (interval_map.getPtr(s)) |interval_s| interval_s.hint_vreg = d;
                    }
                },
                .idiv, .irem => {
                    // Split the capture to avoid union capture mismatch
                    const dest = switch (inst) {
                        .idiv => |d| d.dest,
                        .irem => |r| r.dest,
                        else => unreachable,
                    };
                    const rem = switch (inst) {
                        .idiv => |d| d.rem,
                        .irem => |r| r.rem,
                        else => unreachable,
                    };
                    const src = switch (inst) {
                        .idiv => |d| d.src,
                        .irem => |r| r.src,
                        else => unreachable,
                    };
                    try helper.process(&interval_map, dest, global_inst_idx, true, .gpr);
                    try helper.process(&interval_map, rem, global_inst_idx, true, .gpr);
                    try helper.process(&interval_map, src, global_inst_idx, false, .gpr);
                },
                .neg => |v| {
                    try helper.process(&interval_map, v.dest, global_inst_idx, true, .gpr);
                },
                .cmp => |v| {
                    try helper.process(&interval_map, v.left, global_inst_idx, false, .gpr);
                    try helper.process(&interval_map, v.right, global_inst_idx, false, .gpr);
                },
                .test_op => |v| {
                    try helper.process(&interval_map, v.left, global_inst_idx, false, .gpr);
                    try helper.process(&interval_map, v.right, global_inst_idx, false, .gpr);
                },
                .switch_stub => |v| {
                    try helper.process(&interval_map, v.src, global_inst_idx, false, .gpr);
                },
                .call => |v| {
                    if (v.dest) |d| {
                        try helper.process(&interval_map, d, global_inst_idx, true, .gpr); // Object references are GPR
                    }
                    try call_indices.append(allocator, global_inst_idx);
                },
                .alloc_obj => |v| {
                    try helper.process(&interval_map, v.dest, global_inst_idx, true, .gpr);
                },
                .alloc_arr => |v| {
                    try helper.process(&interval_map, v.dest, global_inst_idx, true, .gpr);
                    try helper.process(&interval_map, v.size, global_inst_idx, false, .gpr);
                },
                .field_load => |v| {
                    try helper.process(&interval_map, v.dest, global_inst_idx, true, .gpr);
                    if (v.obj) |o| try helper.process(&interval_map, o, global_inst_idx, false, .gpr);
                },
                .field_store => |v| {
                    try helper.process(&interval_map, v.src, global_inst_idx, false, .gpr);
                    if (v.obj) |o| try helper.process(&interval_map, o, global_inst_idx, false, .gpr);
                },
                .arr_load => |v| {
                    try helper.process(&interval_map, v.dest, global_inst_idx, true, .gpr);
                    try helper.process(&interval_map, v.array, global_inst_idx, false, .gpr);
                    try helper.process(&interval_map, v.index, global_inst_idx, false, .gpr);
                },
                .arr_store => |v| {
                    try helper.process(&interval_map, v.src, global_inst_idx, false, .gpr);
                    try helper.process(&interval_map, v.array, global_inst_idx, false, .gpr);
                    try helper.process(&interval_map, v.index, global_inst_idx, false, .gpr);
                },
                .ret => |v| {
                    if (v) |op| try helper.process(&interval_map, op, global_inst_idx, false, .gpr);
                },
                .throw_stub => |v| {
                    try helper.process(&interval_map, v.src, global_inst_idx, false, .gpr);
                },
                .jmp, .je, .jne, .jl, .jle, .jg, .jge, .jz, .jnz => {},
            }
            global_inst_idx += 1;
        }
    }

    if (cfg_opt) |cfg| {
        // Run backward liveness analysis to correctly extend intervals across loop boundaries.
        var max_block_id: usize = 0;
        for (cfg.blocks.items) |b| {
            if (b.id > max_block_id) max_block_id = b.id;
        }
        
        const BlockLiveness = struct {
            def: std.AutoHashMap(ir.SSAVar, void),
            use: std.AutoHashMap(ir.SSAVar, void),
            live_in: std.AutoHashMap(ir.SSAVar, void),
            live_out: std.AutoHashMap(ir.SSAVar, void),
        };

        const liveness_table = try allocator.alloc(BlockLiveness, max_block_id + 1);
        defer allocator.free(liveness_table);
        for (liveness_table) |*l| {
            l.* = .{
                .def = std.AutoHashMap(ir.SSAVar, void).init(allocator),
                .use = std.AutoHashMap(ir.SSAVar, void).init(allocator),
                .live_in = std.AutoHashMap(ir.SSAVar, void).init(allocator),
                .live_out = std.AutoHashMap(ir.SSAVar, void).init(allocator),
            };
        }
        defer {
            for (liveness_table) |*l| {
                l.def.deinit();
                l.use.deinit();
                l.live_in.deinit();
                l.live_out.deinit();
            }
        }

        const block_start_idx = try allocator.alloc(usize, max_block_id + 1);
        const block_end_idx = try allocator.alloc(usize, max_block_id + 1);
        defer allocator.free(block_start_idx);
        defer allocator.free(block_end_idx);

        var temp_idx: usize = 0;
        for (program.blocks.items) |mblock| {
            block_start_idx[mblock.id] = temp_idx;
            const l = &liveness_table[mblock.id];

            const collectDefsAndUses = struct {
                fn run(bl: *BlockLiveness, op: x86.Operand, is_def: bool) !void {
                    switch (op) {
                        .vreg => |v| {
                            if (is_def) {
                                try bl.def.put(v, {});
                            } else {
                                if (!bl.def.contains(v)) {
                                    try bl.use.put(v, {});
                                }
                            }
                        },
                        .mem => |m| {
                            switch (m.base) {
                                .vreg => |bv| try run(bl, .{ .vreg = bv }, false),
                                else => {},
                            }
                            if (m.index) |idx| {
                                switch (idx) {
                                    .vreg => |iv| try run(bl, .{ .vreg = iv }, false),
                                    else => {},
                                }
                            }
                        },
                        else => {},
                    }
                }
            }.run;

            for (mblock.instructions.items) |inst| {
                switch (inst) {
                    .mov => |v| {
                        try collectDefsAndUses(l, v.src, false);
                        try collectDefsAndUses(l, v.dest, true);
                    },
                    .movss => |v| {
                        try collectDefsAndUses(l, v.src, false);
                        try collectDefsAndUses(l, v.dest, true);
                    },
                    .movsd => |v| {
                        try collectDefsAndUses(l, v.src, false);
                        try collectDefsAndUses(l, v.dest, true);
                    },
                    .add => |v| {
                        try collectDefsAndUses(l, v.src, false);
                        try collectDefsAndUses(l, v.dest, false);
                        try collectDefsAndUses(l, v.dest, true);
                    },
                    .sub => |v| {
                        try collectDefsAndUses(l, v.src, false);
                        try collectDefsAndUses(l, v.dest, false);
                        try collectDefsAndUses(l, v.dest, true);
                    },
                    .imul => |v| {
                        try collectDefsAndUses(l, v.src, false);
                        try collectDefsAndUses(l, v.dest, false);
                        try collectDefsAndUses(l, v.dest, true);
                    },
                    .and_op => |v| {
                        try collectDefsAndUses(l, v.src, false);
                        try collectDefsAndUses(l, v.dest, false);
                        try collectDefsAndUses(l, v.dest, true);
                    },
                    .or_op => |v| {
                        try collectDefsAndUses(l, v.src, false);
                        try collectDefsAndUses(l, v.dest, false);
                        try collectDefsAndUses(l, v.dest, true);
                    },
                    .xor_op => |v| {
                        try collectDefsAndUses(l, v.src, false);
                        try collectDefsAndUses(l, v.dest, false);
                        try collectDefsAndUses(l, v.dest, true);
                    },
                    .shl => |v| {
                        try collectDefsAndUses(l, v.src, false);
                        try collectDefsAndUses(l, v.dest, false);
                        try collectDefsAndUses(l, v.dest, true);
                    },
                    .shr => |v| {
                        try collectDefsAndUses(l, v.src, false);
                        try collectDefsAndUses(l, v.dest, false);
                        try collectDefsAndUses(l, v.dest, true);
                    },
                    .ushr => |v| {
                        try collectDefsAndUses(l, v.src, false);
                        try collectDefsAndUses(l, v.dest, false);
                        try collectDefsAndUses(l, v.dest, true);
                    },
                    .addss => |v| {
                        try collectDefsAndUses(l, v.src, false);
                        try collectDefsAndUses(l, v.dest, false);
                        try collectDefsAndUses(l, v.dest, true);
                    },
                    .subss => |v| {
                        try collectDefsAndUses(l, v.src, false);
                        try collectDefsAndUses(l, v.dest, false);
                        try collectDefsAndUses(l, v.dest, true);
                    },
                    .mulss => |v| {
                        try collectDefsAndUses(l, v.src, false);
                        try collectDefsAndUses(l, v.dest, false);
                        try collectDefsAndUses(l, v.dest, true);
                    },
                    .divss => |v| {
                        try collectDefsAndUses(l, v.src, false);
                        try collectDefsAndUses(l, v.dest, false);
                        try collectDefsAndUses(l, v.dest, true);
                    },
                    .addsd => |v| {
                        try collectDefsAndUses(l, v.src, false);
                        try collectDefsAndUses(l, v.dest, false);
                        try collectDefsAndUses(l, v.dest, true);
                    },
                    .subsd => |v| {
                        try collectDefsAndUses(l, v.src, false);
                        try collectDefsAndUses(l, v.dest, false);
                        try collectDefsAndUses(l, v.dest, true);
                    },
                    .mulsd => |v| {
                        try collectDefsAndUses(l, v.src, false);
                        try collectDefsAndUses(l, v.dest, false);
                        try collectDefsAndUses(l, v.dest, true);
                    },
                    .divsd => |v| {
                        try collectDefsAndUses(l, v.src, false);
                        try collectDefsAndUses(l, v.dest, false);
                        try collectDefsAndUses(l, v.dest, true);
                    },
                    .neg => |v| {
                        try collectDefsAndUses(l, v.dest, false);
                        try collectDefsAndUses(l, v.dest, true);
                    },
                    .idiv => |v| {
                        try collectDefsAndUses(l, v.src, false);
                        try collectDefsAndUses(l, v.dest, false);
                        try collectDefsAndUses(l, v.dest, true);
                        try collectDefsAndUses(l, v.rem, true);
                    },
                    .irem => |v| {
                        try collectDefsAndUses(l, v.src, false);
                        try collectDefsAndUses(l, v.dest, false);
                        try collectDefsAndUses(l, v.dest, true);
                        try collectDefsAndUses(l, v.rem, true);
                    },
                    .cmp => |v| {
                        try collectDefsAndUses(l, v.left, false);
                        try collectDefsAndUses(l, v.right, false);
                    },
                    .test_op => |v| {
                        try collectDefsAndUses(l, v.left, false);
                        try collectDefsAndUses(l, v.right, false);
                    },
                    .ret => |v| {
                        if (v) |op| try collectDefsAndUses(l, op, false);
                    },
                    else => {},
                }
                temp_idx += 1;
            }
            block_end_idx[mblock.id] = temp_idx - 1;
        }

        var liveness_changed = true;
        while (liveness_changed) {
            liveness_changed = false;
            
            var b_idx = cfg.blocks.items.len;
            while (b_idx > 0) {
                b_idx -= 1;
                const b = cfg.blocks.items[b_idx];
                const l = &liveness_table[b.id];
                
                for (b.successors.items) |succ_id| {
                    const succ_l = &liveness_table[succ_id];
                    var succ_it = succ_l.live_in.keyIterator();
                    while (succ_it.next()) |var_ptr| {
                        const variable = var_ptr.*;
                        const res = try l.live_out.getOrPut(variable);
                        if (!res.found_existing) {
                            liveness_changed = true;
                        }
                    }
                }
                
                var use_it = l.use.keyIterator();
                while (use_it.next()) |var_ptr| {
                    const variable = var_ptr.*;
                    const res = try l.live_in.getOrPut(variable);
                    if (!res.found_existing) {
                        liveness_changed = true;
                    }
                }
                var out_it = l.live_out.keyIterator();
                while (out_it.next()) |var_ptr| {
                    const variable = var_ptr.*;
                    if (!l.def.contains(variable)) {
                        const res = try l.live_in.getOrPut(variable);
                        if (!res.found_existing) {
                            liveness_changed = true;
                        }
                    }
                }
            }
        }

        // Extend intervals based on live_in and live_out of blocks.
        for (liveness_table, 0..) |l, b_id| {
            var in_it = l.live_in.keyIterator();
            while (in_it.next()) |var_ptr| {
                const variable = var_ptr.*;
                if (interval_map.getPtr(variable)) |interval| {
                    interval.start = @min(interval.start, block_start_idx[b_id]);
                }
            }
            var out_it = l.live_out.keyIterator();
            while (out_it.next()) |var_ptr| {
                const variable = var_ptr.*;
                if (interval_map.getPtr(variable)) |interval| {
                    interval.end = @max(interval.end, block_end_idx[b_id]);
                }
            }
        }
    }

    // Convert hash map values to a flat slice of intervals and sort them.
    var intervals = std.ArrayList(LiveInterval).empty;
    defer intervals.deinit(allocator);

    var val_it = interval_map.valueIterator();
    while (val_it.next()) |val| {
        var interval = val.*;
        for (call_indices.items) |call_idx| {
            if (call_idx > interval.start and call_idx < interval.end) {
                interval.live_across_call = true;
                break;
            }
        }
        try intervals.append(allocator, interval);
    }
    std.mem.sort(LiveInterval, intervals.items, {}, compareIntervals);

    // List of allocatable GPR registers.
    // Excluding RAX and RDX to prevent collision/clobbering by IDIV/IREM easily.
    const gpr_registers = [_]x86.PhysicalReg{
        .rbx, .rcx, .rsi, .rdi, .r8, .r9, .r10, .r11, .r12, .r13, .r14, .r15
    };

    // List of SSE XMM registers.
    const xmm_registers = [_]x86.PhysicalReg{
        .xmm0, .xmm1, .xmm2, .xmm3, .xmm4, .xmm5, .xmm6, .xmm7,
        .xmm8, .xmm9, .xmm10, .xmm11, .xmm12, .xmm13, .xmm14, .xmm15
    };

    var free_gprs = std.ArrayList(x86.PhysicalReg).empty;
    defer free_gprs.deinit(allocator);
    try free_gprs.appendSlice(allocator, &gpr_registers);

    var free_xmms = std.ArrayList(x86.PhysicalReg).empty;
    defer free_xmms.deinit(allocator);
    try free_xmms.appendSlice(allocator, &xmm_registers);

    var active = std.ArrayList(*LiveInterval).empty;
    defer active.deinit(allocator);

    var next_stack_offset: i32 = 8;
    var allocation_results = std.AutoHashMap(ir.SSAVar, LiveInterval).init(allocator);
    defer allocation_results.deinit();

    for (intervals.items) |*interval| {
        // Expire old intervals
        var active_idx: usize = 0;
        while (active_idx < active.items.len) {
            const act = active.items[active_idx];
            if (act.end < interval.start) {
                // Free reg to correct pool
                if (act.reg) |r| {
                    if (act.class == .xmm) {
                        try free_xmms.append(allocator, r);
                    } else {
                        try free_gprs.append(allocator, r);
                    }
                }
                _ = active.orderedRemove(active_idx);
            } else {
                active_idx += 1;
            }
        }

        const pool = if (interval.class == .xmm) &free_xmms else &free_gprs;

        if (pool.items.len > 0) {
            // Allocate register: check if we can reuse the hint register.
            var selected_reg: ?x86.PhysicalReg = null;
            if (interval.hint_vreg) |hint_v| {
                if (allocation_results.get(hint_v)) |hint_res| {
                    if (hint_res.reg) |hr| {
                        // Check if the hinted register is actually currently free in this pool
                        for (pool.items, 0..) |fr, fri| {
                            if (fr == hr) {
                                selected_reg = pool.orderedRemove(fri);
                                break;
                            }
                        }
                    }
                }
            }

            const reg = selected_reg orelse blk: {
                if (interval.class == .gpr) {
                    var found_idx: ?usize = null;
                    for (pool.items, 0..) |fr, fri| {
                        const is_callee = isCalleeSaved(fr);
                        if (interval.live_across_call == is_callee) {
                            found_idx = fri;
                            break;
                        }
                    }
                    if (found_idx) |fi| {
                        break :blk pool.orderedRemove(fi);
                    }
                }
                break :blk pool.pop();
            };
            interval.reg = reg;
            try active.append(allocator, interval);
            std.mem.sort(*LiveInterval, active.items, {}, compareActive);
        } else {
            // Spill: Find the active interval of the SAME class that ends furthest
            var victim_idx: ?usize = null;
            var max_end: usize = 0;
            for (active.items, 0..) |act, acti| {
                if (act.class == interval.class and act.end > max_end) {
                    max_end = act.end;
                    victim_idx = acti;
                }
            }

            if (victim_idx != null and max_end > interval.end) {
                const victim = active.items[victim_idx.?];
                interval.reg = victim.reg;
                victim.reg = null;
                victim.stack_offset = next_stack_offset;
                next_stack_offset += 8;
                active.items[victim_idx.?] = interval;
                std.mem.sort(*LiveInterval, active.items, {}, compareActive);
            } else {
                // Spill current interval
                interval.stack_offset = next_stack_offset;
                next_stack_offset += 8;
            }
        }

        try allocation_results.put(interval.vreg, interval.*);
    }

    // Now rewrite all instructions in the program using the allocation results.
    for (program.blocks.items) |*block| {
        var rewritten_insts = std.ArrayList(x86.Inst).empty;
        errdefer rewritten_insts.deinit(allocator);

        for (block.instructions.items) |inst| {
            const rewriteOp = struct {
                fn run(results: *const std.AutoHashMap(ir.SSAVar, LiveInterval), op: x86.Operand) x86.Operand {
                    switch (op) {
                        .vreg => |v| {
                            if (results.get(v)) |alloc_res| {
                                if (alloc_res.reg) |r| {
                                    return .{ .reg = r };
                                } else if (alloc_res.stack_offset) |offset| {
                                    return .{ .stack = offset };
                                }
                            }
                            return op;
                        },
                        .mem => |m| {
                            var new_base = m.base;
                            switch (m.base) {
                                .vreg => |bv| {
                                    const rw = run(results, .{ .vreg = bv });
                                    switch (rw) {
                                        .reg => |r| new_base = .{ .reg = r },
                                        .stack => |s| new_base = .{ .stack = s },
                                        else => {},
                                    }
                                },
                                else => {},
                            }
                            var new_index = m.index;
                            if (m.index) |idx| {
                                switch (idx) {
                                    .vreg => |iv| {
                                        const rw = run(results, .{ .vreg = iv });
                                        switch (rw) {
                                            .reg => |r| new_index = .{ .reg = r },
                                            .stack => |s| new_index = .{ .stack = s },
                                            else => {},
                                        }
                                    },
                                    else => {},
                                }
                            }
                            return .{ .mem = .{
                                .base = new_base,
                                .index = new_index,
                                .scale = m.scale,
                                .disp = m.disp,
                            } };
                        },
                        else => return op,
                    }
                }
            };

            var new_inst = inst;

            switch (new_inst) {
                .mov => |*v| {
                    v.dest = rewriteOp.run(&allocation_results, v.dest);
                    v.src = rewriteOp.run(&allocation_results, v.src);
                },
                .add => |*v| {
                    v.dest = rewriteOp.run(&allocation_results, v.dest);
                    v.src = rewriteOp.run(&allocation_results, v.src);
                },
                .sub => |*v| {
                    v.dest = rewriteOp.run(&allocation_results, v.dest);
                    v.src = rewriteOp.run(&allocation_results, v.src);
                },
                .imul => |*v| {
                    v.dest = rewriteOp.run(&allocation_results, v.dest);
                    v.src = rewriteOp.run(&allocation_results, v.src);
                },
                .and_op => |*v| {
                    v.dest = rewriteOp.run(&allocation_results, v.dest);
                    v.src = rewriteOp.run(&allocation_results, v.src);
                },
                .or_op => |*v| {
                    v.dest = rewriteOp.run(&allocation_results, v.dest);
                    v.src = rewriteOp.run(&allocation_results, v.src);
                },
                .xor_op => |*v| {
                    v.dest = rewriteOp.run(&allocation_results, v.dest);
                    v.src = rewriteOp.run(&allocation_results, v.src);
                },
                .shl => |*v| {
                    v.dest = rewriteOp.run(&allocation_results, v.dest);
                    v.src = rewriteOp.run(&allocation_results, v.src);
                },
                .shr => |*v| {
                    v.dest = rewriteOp.run(&allocation_results, v.dest);
                    v.src = rewriteOp.run(&allocation_results, v.src);
                },
                .ushr => |*v| {
                    v.dest = rewriteOp.run(&allocation_results, v.dest);
                    v.src = rewriteOp.run(&allocation_results, v.src);
                },
                .addss => |*v| {
                    v.dest = rewriteOp.run(&allocation_results, v.dest);
                    v.src = rewriteOp.run(&allocation_results, v.src);
                },
                .subss => |*v| {
                    v.dest = rewriteOp.run(&allocation_results, v.dest);
                    v.src = rewriteOp.run(&allocation_results, v.src);
                },
                .mulss => |*v| {
                    v.dest = rewriteOp.run(&allocation_results, v.dest);
                    v.src = rewriteOp.run(&allocation_results, v.src);
                },
                .divss => |*v| {
                    v.dest = rewriteOp.run(&allocation_results, v.dest);
                    v.src = rewriteOp.run(&allocation_results, v.src);
                },
                .movss => |*v| {
                    v.dest = rewriteOp.run(&allocation_results, v.dest);
                    v.src = rewriteOp.run(&allocation_results, v.src);
                },
                .addsd => |*v| {
                    v.dest = rewriteOp.run(&allocation_results, v.dest);
                    v.src = rewriteOp.run(&allocation_results, v.src);
                },
                .subsd => |*v| {
                    v.dest = rewriteOp.run(&allocation_results, v.dest);
                    v.src = rewriteOp.run(&allocation_results, v.src);
                },
                .mulsd => |*v| {
                    v.dest = rewriteOp.run(&allocation_results, v.dest);
                    v.src = rewriteOp.run(&allocation_results, v.src);
                },
                .divsd => |*v| {
                    v.dest = rewriteOp.run(&allocation_results, v.dest);
                    v.src = rewriteOp.run(&allocation_results, v.src);
                },
                .movsd => |*v| {
                    v.dest = rewriteOp.run(&allocation_results, v.dest);
                    v.src = rewriteOp.run(&allocation_results, v.src);
                },
                .idiv => |*v| {
                    v.dest = rewriteOp.run(&allocation_results, v.dest);
                    v.rem = rewriteOp.run(&allocation_results, v.rem);
                    v.src = rewriteOp.run(&allocation_results, v.src);
                },
                .irem => |*v| {
                    v.dest = rewriteOp.run(&allocation_results, v.dest);
                    v.rem = rewriteOp.run(&allocation_results, v.rem);
                    v.src = rewriteOp.run(&allocation_results, v.src);
                },
                .neg => |*v| {
                    v.dest = rewriteOp.run(&allocation_results, v.dest);
                },
                .cmp => |*v| {
                    v.left = rewriteOp.run(&allocation_results, v.left);
                    v.right = rewriteOp.run(&allocation_results, v.right);
                },
                .test_op => |*v| {
                    v.left = rewriteOp.run(&allocation_results, v.left);
                    v.right = rewriteOp.run(&allocation_results, v.right);
                },
                .switch_stub => |*v| {
                    v.src = rewriteOp.run(&allocation_results, v.src);
                },
                .call => |*v| {
                    if (v.dest) |*d| {
                        d.* = rewriteOp.run(&allocation_results, d.*);
                    }
                },
                .alloc_obj => |*v| {
                    v.dest = rewriteOp.run(&allocation_results, v.dest);
                },
                .alloc_arr => |*v| {
                    v.dest = rewriteOp.run(&allocation_results, v.dest);
                    v.size = rewriteOp.run(&allocation_results, v.size);
                },
                .field_load => |*v| {
                    v.dest = rewriteOp.run(&allocation_results, v.dest);
                    if (v.obj) |*o| o.* = rewriteOp.run(&allocation_results, o.*);
                },
                .field_store => |*v| {
                    v.src = rewriteOp.run(&allocation_results, v.src);
                    if (v.obj) |*o| o.* = rewriteOp.run(&allocation_results, o.*);
                },
                .arr_load => |*v| {
                    v.dest = rewriteOp.run(&allocation_results, v.dest);
                    v.array = rewriteOp.run(&allocation_results, v.array);
                    v.index = rewriteOp.run(&allocation_results, v.index);
                },
                .arr_store => |*v| {
                    v.src = rewriteOp.run(&allocation_results, v.src);
                    v.array = rewriteOp.run(&allocation_results, v.array);
                    v.index = rewriteOp.run(&allocation_results, v.index);
                },
                .ret => |*v| {
                    if (v.*) |*op| {
                        op.* = rewriteOp.run(&allocation_results, op.*);
                    }
                },
                .throw_stub => |*v| {
                    v.src = rewriteOp.run(&allocation_results, v.src);
                },
                .jmp, .je, .jne, .jl, .jle, .jg, .jge, .jz, .jnz => {},
            }

            // Correctness check: x86 does not support operating directly stack-to-stack
            // e.g., MOV [rbp-8], [rbp-16]. We resolve this by inserting a temporary scratch
            // using RAX (which is excluded from GPR pool).
            switch (new_inst) {
                .mov => |v| {
                    if (v.dest == .stack and v.src == .stack) {
                        try rewritten_insts.append(allocator, .{ .mov = .{ .dest = .{ .reg = .rax }, .src = v.src } });
                        try rewritten_insts.append(allocator, .{ .mov = .{ .dest = v.dest, .src = .{ .reg = .rax } } });
                        continue;
                    }
                },
                .add => |v| {
                    if (v.dest == .stack and v.src == .stack) {
                        try rewritten_insts.append(allocator, .{ .mov = .{ .dest = .{ .reg = .rax }, .src = v.dest } });
                        try rewritten_insts.append(allocator, .{ .add = .{ .dest = .{ .reg = .rax }, .src = v.src } });
                        try rewritten_insts.append(allocator, .{ .mov = .{ .dest = v.dest, .src = .{ .reg = .rax } } });
                        continue;
                    }
                },
                .sub => |v| {
                    if (v.dest == .stack and v.src == .stack) {
                        try rewritten_insts.append(allocator, .{ .mov = .{ .dest = .{ .reg = .rax }, .src = v.dest } });
                        try rewritten_insts.append(allocator, .{ .sub = .{ .dest = .{ .reg = .rax }, .src = v.src } });
                        try rewritten_insts.append(allocator, .{ .mov = .{ .dest = v.dest, .src = .{ .reg = .rax } } });
                        continue;
                    }
                },
                else => {},
            }

            // Physical dead self-move elimination post-register allocation
            // e.g. MOV %rcx, %rcx -> skip it!
            const is_physical_self_mov = switch (new_inst) {
                .mov => |v| switch (v.dest) {
                    .reg => |d| switch (v.src) {
                        .reg => |s| d == s,
                        else => false,
                    },
                    else => false,
                },
                else => false,
            };

            if (is_physical_self_mov) {
                continue;
            }

            try rewritten_insts.append(allocator, new_inst);
        }

        block.instructions.deinit(allocator);
        block.instructions = rewritten_insts;
    }
}

// ── Unit Tests ──────────────────────────────────────────────────────────────

test "regalloc: basic linear scan" {
    const a = std.testing.allocator;

    var prog = x86.MachineProgram{
        .blocks = std.ArrayList(x86.MachineBlock).empty,
        .allocator = a,
    };
    defer prog.deinit();

    var mblock = x86.MachineBlock{
        .id = 0,
        .instructions = std.ArrayList(x86.Inst).empty,
    };

    const v0 = ir.SSAVar{ .reg = 0, .version = 1 };
    const v1 = ir.SSAVar{ .reg = 1, .version = 1 };

    // MOV v0_1, #10
    try mblock.instructions.append(a, .{ .mov = .{ .dest = .{ .vreg = v0 }, .src = .{ .imm = 10 } } });
    // MOV v1_1, #20
    try mblock.instructions.append(a, .{ .mov = .{ .dest = .{ .vreg = v1 }, .src = .{ .imm = 20 } } });
    // ADD v0_1, v1_1
    try mblock.instructions.append(a, .{ .add = .{ .dest = .{ .vreg = v0 }, .src = .{ .vreg = v1 } } });
    // RET v0_1
    try mblock.instructions.append(a, .{ .ret = .{ .vreg = v0 } });

    try prog.blocks.append(a, mblock);

    try allocateRegisters(a, &prog, null, 0, 0);

    const insts = prog.blocks.items[0].instructions.items;
    try std.testing.expect(insts[0].mov.dest == .reg);
    try std.testing.expect(insts[1].mov.dest == .reg);
    try std.testing.expect(insts[2].add.dest == .reg);
    try std.testing.expect(insts[2].add.src == .reg);
    try std.testing.expect(insts[3].ret.? == .reg);
}

test "regalloc: float register allocation" {
    const a = std.testing.allocator;

    var prog = x86.MachineProgram{
        .blocks = std.ArrayList(x86.MachineBlock).empty,
        .allocator = a,
    };
    defer prog.deinit();

    var mblock = x86.MachineBlock{
        .id = 0,
        .instructions = std.ArrayList(x86.Inst).empty,
    };

    const v0 = ir.SSAVar{ .reg = 0, .version = 1 };
    const v1 = ir.SSAVar{ .reg = 1, .version = 1 };

    // MOVSS v0_1, v1_1
    try mblock.instructions.append(a, .{ .movss = .{ .dest = .{ .vreg = v0 }, .src = .{ .vreg = v1 } } });
    // ADDSS v0_1, v1_1
    try mblock.instructions.append(a, .{ .addss = .{ .dest = .{ .vreg = v0 }, .src = .{ .vreg = v1 } } });

    try prog.blocks.append(a, mblock);

    try allocateRegisters(a, &prog, null, 0, 0);

    const insts = prog.blocks.items[0].instructions.items;
    // Verify that the float variables are allocated to XMM registers!
    try std.testing.expect(insts[0].movss.dest == .reg);
    try std.testing.expect(insts[0].movss.src == .reg);
    
    // Check they belong to the XMM register class (starts with xmm0 name or equivalent)
    const dest_name = insts[0].movss.dest.reg.name();
    const src_name = insts[0].movss.src.reg.name();
    try std.testing.expect(std.mem.startsWith(u8, dest_name, "xmm"));
    try std.testing.expect(std.mem.startsWith(u8, src_name, "xmm"));
}

test "regalloc: SIB array indexing rewrite" {
    const a = std.testing.allocator;

    var prog = x86.MachineProgram{
        .blocks = std.ArrayList(x86.MachineBlock).empty,
        .allocator = a,
    };
    defer prog.deinit();

    var mblock = x86.MachineBlock{
        .id = 0,
        .instructions = std.ArrayList(x86.Inst).empty,
    };

    const v_array = ir.SSAVar{ .reg = 0, .version = 1 };
    const v_index = ir.SSAVar{ .reg = 1, .version = 1 };
    const v_dest  = ir.SSAVar{ .reg = 2, .version = 1 };

    // MOV v_dest, [v_array + v_index * 4 + 16]
    const mem_op = x86.Operand{ .mem = .{
        .base = .{ .vreg = v_array },
        .index = .{ .vreg = v_index },
        .scale = 4,
        .disp = 16,
    } };
    try mblock.instructions.append(a, .{ .mov = .{ .dest = .{ .vreg = v_dest }, .src = mem_op } });

    try prog.blocks.append(a, mblock);

    try allocateRegisters(a, &prog, null, 0, 0);

    const insts = prog.blocks.items[0].instructions.items;
    try std.testing.expect(insts[0].mov.dest == .reg);
    try std.testing.expect(insts[0].mov.src == .mem);
    
    // Verify that the memory operand's base and index have been rewritten to physical GPR registers
    const rewritten_mem = insts[0].mov.src.mem;
    try std.testing.expect(rewritten_mem.base == .reg);
    try std.testing.expect(rewritten_mem.index.? == .reg);
    
    // GPRs should not be XMM
    try std.testing.expect(!std.mem.startsWith(u8, rewritten_mem.base.reg.name(), "xmm"));
    try std.testing.expect(!std.mem.startsWith(u8, rewritten_mem.index.?.reg.name(), "xmm"));
}

test "regalloc: loop liveness analysis" {
    const a = std.testing.allocator;

    // Build a simple 2-block CFG with a loop:
    // Block 0:
    //   v0_1 = const 0 (defined)
    // Block 1 (loop header/latch):
    //   v0_2 = phi([bb0: v0_1], [bb1: v0_3])
    //   v0_3 = add v0_2, 1
    //   if v0_3 < 10 goto bb1
    
    var test_cfg = cfgmod.CFG{
        .blocks = std.ArrayList(cfgmod.BasicBlock).empty,
        .allocator = a,
    };
    defer test_cfg.deinit();

    var b0 = cfgmod.BasicBlock{
        .id = 0,
        .start_idx = 0,
        .end_idx = 0,
        .successors = std.ArrayList(usize).empty,
        .predecessors = std.ArrayList(usize).empty,
        .dominance_frontier = std.ArrayList(usize).empty,
        .dom_children = std.ArrayList(usize).empty,
        .idom = null,
        .phi_functions = std.ArrayList(cfgmod.PhiNode).empty,
        .instructions = std.ArrayList(ir.IRInst).empty,
    };
    const v0_1 = ir.SSAVar{ .reg = 0, .version = 1 };
    try b0.instructions.append(a, .{ .const_int = .{ .dest = v0_1, .val = 0 } });
    try b0.successors.append(a, 1);
    try test_cfg.blocks.append(a, b0);

    var b1 = cfgmod.BasicBlock{
        .id = 1,
        .start_idx = 1,
        .end_idx = 3,
        .successors = std.ArrayList(usize).empty,
        .predecessors = std.ArrayList(usize).empty,
        .dominance_frontier = std.ArrayList(usize).empty,
        .dom_children = std.ArrayList(usize).empty,
        .idom = null,
        .phi_functions = std.ArrayList(cfgmod.PhiNode).empty,
        .instructions = std.ArrayList(ir.IRInst).empty,
    };
    const v0_2 = ir.SSAVar{ .reg = 0, .version = 2 };
    const v0_3 = ir.SSAVar{ .reg = 0, .version = 3 };

    // phi
    var phi_args = try a.alloc(ir.PhiArg, 2);
    phi_args[0] = .{ .pred_block_id = 0, .val = v0_1 };
    phi_args[1] = .{ .pred_block_id = 1, .val = v0_3 };
    try b1.phi_functions.append(a, .{ .original_reg = 0, .ssa_version = 2, .incoming = phi_args });

    try b1.instructions.append(a, .{ .add_lit = .{ .dest = v0_3, .src = v0_2, .lit = 1 } });
    try b1.instructions.append(a, .{ .if_ltz = .{ .src = v0_3, .target_block_id = 1 } }); // branch back
    try b1.successors.append(a, 1);
    try b1.predecessors.append(a, 0);
    try b1.predecessors.append(a, 1);
    try test_cfg.blocks.append(a, b1);
    
    test_cfg.blocks.items[0].successors.items[0] = 1;

    var prog = x86.MachineProgram{
        .blocks = std.ArrayList(x86.MachineBlock).empty,
        .allocator = a,
    };
    defer prog.deinit();

    var mb0 = x86.MachineBlock{ .id = 0, .instructions = std.ArrayList(x86.Inst).empty };
    try mb0.instructions.append(a, .{ .mov = .{ .dest = .{ .vreg = v0_1 }, .src = .{ .imm = 0 } } });
    try prog.blocks.append(a, mb0);

    var mb1 = x86.MachineBlock{ .id = 1, .instructions = std.ArrayList(x86.Inst).empty };
    try mb1.instructions.append(a, .{ .mov = .{ .dest = .{ .vreg = v0_2 }, .src = .{ .vreg = v0_1 } } }); // simplified phi copy
    try mb1.instructions.append(a, .{ .add = .{ .dest = .{ .vreg = v0_3 }, .src = .{ .imm = 1 } } });
    try mb1.instructions.append(a, .{ .jl = 1 });
    try prog.blocks.append(a, mb1);

    // Test that variable v0_2 is live across the back-edge, so its interval doesn't terminate prematurely
    try allocateRegisters(a, &prog, &test_cfg, 2, 0);

    // Let's assert that the allocations succeeded and registers were assigned
    const mb1_insts = prog.blocks.items[1].instructions.items;
    try std.testing.expect(mb1_insts[0].mov.dest == .reg);
    try std.testing.expect(mb1_insts[0].mov.src == .reg);
}

