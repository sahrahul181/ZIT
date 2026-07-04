const std = @import("std");
const ir = @import("ir");
const x86 = @import("x86");

pub const LiveInterval = struct {
    vreg: ir.SSAVar,
    start: usize,
    end: usize,
    reg: ?x86.PhysicalReg = null,
    stack_offset: ?i32 = null,
    hint_vreg: ?ir.SSAVar = null,
};

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

pub fn allocateRegisters(allocator: std.mem.Allocator, program: *x86.MachineProgram) !void {
    // 1. Gather all virtual registers and compute their live intervals.
    // Map from ir.SSAVar -> LiveInterval.
    var interval_map = std.AutoHashMap(ir.SSAVar, LiveInterval).init(allocator);
    defer interval_map.deinit();

    var global_inst_idx: usize = 0;

    for (program.blocks.items) |block| {
        for (block.instructions.items) |inst| {
            // Helper closure/logic to update interval for a read or write
            const helper = struct {
                fn process(map: *std.AutoHashMap(ir.SSAVar, LiveInterval), op: x86.Operand, idx: usize, is_def: bool) !void {
                    switch (op) {
                        .vreg => |v| {
                            if (map.getPtr(v)) |interval| {
                                if (idx > interval.end) {
                                    interval.end = idx;
                                }
                                if (idx < interval.start) {
                                    interval.start = idx;
                                }
                            } else {
                                try map.put(v, .{
                                    .vreg = v,
                                    .start = idx,
                                    .end = idx,
                                });
                            }
                            _ = is_def;
                        },
                        else => {},
                    }
                }
            };

            // Inspect all operands for this instruction to compute intervals.
            switch (inst) {
                .mov => |v| {
                    try helper.process(&interval_map, v.dest, global_inst_idx, true);
                    try helper.process(&interval_map, v.src, global_inst_idx, false);

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
                    try helper.process(&interval_map, v.dest, global_inst_idx, true);
                    try helper.process(&interval_map, v.src, global_inst_idx, false);
                },
                .sub => |v| {
                    try helper.process(&interval_map, v.dest, global_inst_idx, true);
                    try helper.process(&interval_map, v.src, global_inst_idx, false);
                },
                .imul => |v| {
                    try helper.process(&interval_map, v.dest, global_inst_idx, true);
                    try helper.process(&interval_map, v.src, global_inst_idx, false);
                },
                .and_op => |v| {
                    try helper.process(&interval_map, v.dest, global_inst_idx, true);
                    try helper.process(&interval_map, v.src, global_inst_idx, false);
                },
                .or_op => |v| {
                    try helper.process(&interval_map, v.dest, global_inst_idx, true);
                    try helper.process(&interval_map, v.src, global_inst_idx, false);
                },
                .xor_op => |v| {
                    try helper.process(&interval_map, v.dest, global_inst_idx, true);
                    try helper.process(&interval_map, v.src, global_inst_idx, false);
                },
                .shl => |v| {
                    try helper.process(&interval_map, v.dest, global_inst_idx, true);
                    try helper.process(&interval_map, v.src, global_inst_idx, false);
                },
                .shr => |v| {
                    try helper.process(&interval_map, v.dest, global_inst_idx, true);
                    try helper.process(&interval_map, v.src, global_inst_idx, false);
                },
                .ushr => |v| {
                    try helper.process(&interval_map, v.dest, global_inst_idx, true);
                    try helper.process(&interval_map, v.src, global_inst_idx, false);
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
                    try helper.process(&interval_map, dest, global_inst_idx, true);
                    try helper.process(&interval_map, rem, global_inst_idx, true);
                    try helper.process(&interval_map, src, global_inst_idx, false);
                },
                .neg => |v| {
                    try helper.process(&interval_map, v.dest, global_inst_idx, true);
                },
                .cmp => |v| {
                    try helper.process(&interval_map, v.left, global_inst_idx, false);
                    try helper.process(&interval_map, v.right, global_inst_idx, false);
                },
                .test_op => |v| {
                    try helper.process(&interval_map, v.left, global_inst_idx, false);
                    try helper.process(&interval_map, v.right, global_inst_idx, false);
                },
                .switch_stub => |v| {
                    try helper.process(&interval_map, v.src, global_inst_idx, false);
                },
                .call => |v| {
                    if (v.dest) |d| {
                        try helper.process(&interval_map, d, global_inst_idx, true);
                    }
                },
                .alloc_obj => |v| {
                    try helper.process(&interval_map, v.dest, global_inst_idx, true);
                },
                .alloc_arr => |v| {
                    try helper.process(&interval_map, v.dest, global_inst_idx, true);
                    try helper.process(&interval_map, v.size, global_inst_idx, false);
                },
                .field_load => |v| {
                    try helper.process(&interval_map, v.dest, global_inst_idx, true);
                    if (v.obj) |o| try helper.process(&interval_map, o, global_inst_idx, false);
                },
                .field_store => |v| {
                    try helper.process(&interval_map, v.src, global_inst_idx, false);
                    if (v.obj) |o| try helper.process(&interval_map, o, global_inst_idx, false);
                },
                .arr_load => |v| {
                    try helper.process(&interval_map, v.dest, global_inst_idx, true);
                    try helper.process(&interval_map, v.array, global_inst_idx, false);
                    try helper.process(&interval_map, v.index, global_inst_idx, false);
                },
                .arr_store => |v| {
                    try helper.process(&interval_map, v.src, global_inst_idx, false);
                    try helper.process(&interval_map, v.array, global_inst_idx, false);
                    try helper.process(&interval_map, v.index, global_inst_idx, false);
                },
                .ret => |v| {
                    if (v) |op| try helper.process(&interval_map, op, global_inst_idx, false);
                },
                .throw_stub => |v| {
                    try helper.process(&interval_map, v.src, global_inst_idx, false);
                },
                .jmp, .je, .jne, .jl, .jle, .jg, .jge, .jz, .jnz => {},
            }
            global_inst_idx += 1;
        }
    }

    // Convert hash map values to a flat slice of intervals and sort them.
    var intervals = std.ArrayList(LiveInterval).empty;
    defer intervals.deinit(allocator);

    var val_it = interval_map.valueIterator();
    while (val_it.next()) |val| {
        try intervals.append(allocator, val.*);
    }
    std.mem.sort(LiveInterval, intervals.items, {}, compareIntervals);

    // List of allocatable registers.
    // Excluding RAX and RDX to prevent collision/clobbering by IDIV/IREM easily.
    const registers = [_]x86.PhysicalReg{
        .rbx, .rcx, .rsi, .rdi, .r8, .r9, .r10, .r11, .r12, .r13, .r14, .r15
    };

    var free_regs = std.ArrayList(x86.PhysicalReg).empty;
    defer free_regs.deinit(allocator);
    try free_regs.appendSlice(allocator, &registers);

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
                // Free reg
                if (act.reg) |r| {
                    try free_regs.append(allocator, r);
                }
                _ = active.orderedRemove(active_idx);
            } else {
                active_idx += 1;
            }
        }

        if (free_regs.items.len > 0) {
            // Allocate register: check if we can reuse the hint register.
            var selected_reg: ?x86.PhysicalReg = null;
            if (interval.hint_vreg) |hint_v| {
                if (allocation_results.get(hint_v)) |hint_res| {
                    if (hint_res.reg) |hr| {
                        // Check if the hinted register is actually currently free
                        for (free_regs.items, 0..) |fr, fri| {
                            if (fr == hr) {
                                selected_reg = free_regs.orderedRemove(fri);
                                break;
                            }
                        }
                    }
                }
            }

            const reg = selected_reg orelse free_regs.pop();
            interval.reg = reg;
            try active.append(allocator, interval);
            std.mem.sort(*LiveInterval, active.items, {}, compareActive);
        } else {
            // Spill: Spill the one in active list that ends furthest
            if (active.items.len > 0 and active.items[active.items.len - 1].end > interval.end) {
                const victim = active.items[active.items.len - 1];
                interval.reg = victim.reg;
                victim.reg = null;
                victim.stack_offset = next_stack_offset;
                next_stack_offset += 8;
                active.items[active.items.len - 1] = interval;
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

    try allocateRegisters(a, &prog);

    const insts = prog.blocks.items[0].instructions.items;
    try std.testing.expect(insts[0].mov.dest == .reg);
    try std.testing.expect(insts[1].mov.dest == .reg);
    try std.testing.expect(insts[2].add.dest == .reg);
    try std.testing.expect(insts[2].add.src == .reg);
    try std.testing.expect(insts[3].ret.? == .reg);
}
