const std = @import("std");
const ir = @import("ir");
const cfgmod = @import("cfg");
const x86 = @import("x86");

inline fn opReg(v: ir.SSAVar) x86.Operand  { return .{ .vreg = v }; }
inline fn opImm(val: i32) x86.Operand      { return .{ .imm = val }; }
inline fn opImm64(val: i64) x86.Operand    { return .{ .imm64 = val }; }

/// Lowers the de-SSA 3-Address IR into virtual x86-64 Machine Assembly.
/// Every IRInst variant is explicitly mapped; none are silently dropped.
pub fn lowerCFG(allocator: std.mem.Allocator, cfg: *cfgmod.CFG) !x86.MachineProgram {
    var program = x86.MachineProgram{
        .blocks = std.ArrayList(x86.MachineBlock).empty,
        .allocator = allocator,
    };
    errdefer program.deinit();

    for (cfg.blocks.items) |block| {
        var mi = std.ArrayList(x86.Inst).empty;
        errdefer mi.deinit(allocator);

        for (block.instructions.items) |inst| {
            switch (inst) {

                // ── Constants ─────────────────────────────────────────────
                .const_int => |v| {
                    try mi.append(allocator, .{ .mov = .{ .dest = opReg(v.dest), .src = opImm(v.val) } });
                },
                .const_wide => |v| {
                    // Treat as a 64-bit immediate; the RA pass will split if needed.
                    try mi.append(allocator, .{ .mov = .{ .dest = opReg(v.dest), .src = opImm64(v.val) } });
                },
                .const_string => |v| {
                    // Address of string literal resolved at link time → stub as imm 0
                    try mi.append(allocator, .{ .mov = .{ .dest = opReg(v.dest), .src = opImm(@intCast(v.str_idx)) } });
                },
                .const_class => |v| {
                    // Class object pointer resolved at link time → stub as imm
                    try mi.append(allocator, .{ .mov = .{ .dest = opReg(v.dest), .src = opImm(@intCast(v.type_idx)) } });
                },

                // ── Move ──────────────────────────────────────────────────
                .move => |v| {
                    try mi.append(allocator, .{ .mov = .{ .dest = opReg(v.dest), .src = opReg(v.src) } });
                },

                // ── Integer Binary (3-Address → 2-Address) ────────────────
                .add_int => |v| {
                    try mi.append(allocator, .{ .mov = .{ .dest = opReg(v.dest), .src = opReg(v.left) } });
                    try mi.append(allocator, .{ .add = .{ .dest = opReg(v.dest), .src = opReg(v.right) } });
                },
                .sub_int => |v| {
                    try mi.append(allocator, .{ .mov = .{ .dest = opReg(v.dest), .src = opReg(v.left) } });
                    try mi.append(allocator, .{ .sub = .{ .dest = opReg(v.dest), .src = opReg(v.right) } });
                },
                .mul_int => |v| {
                    try mi.append(allocator, .{ .mov = .{ .dest = opReg(v.dest), .src = opReg(v.left) } });
                    try mi.append(allocator, .{ .imul = .{ .dest = opReg(v.dest), .src = opReg(v.right) } });
                },
                .div_int => |v| {
                    // Quotient goes to dest; we allocate a scratch for the remainder
                    const rem_scratch = ir.SSAVar{ .reg = v.dest.reg, .version = v.dest.version +% 0x8000 };
                    try mi.append(allocator, .{ .mov  = .{ .dest = opReg(v.dest),     .src = opReg(v.left) } });
                    try mi.append(allocator, .{ .idiv = .{ .dest = opReg(v.dest), .rem = opReg(rem_scratch), .src = opReg(v.right) } });
                },
                .rem_int => |v| {
                    // Remainder goes to dest (maps to RDX after real IDIV)
                    const quot_scratch = ir.SSAVar{ .reg = v.dest.reg, .version = v.dest.version +% 0x8000 };
                    try mi.append(allocator, .{ .mov  = .{ .dest = opReg(quot_scratch), .src = opReg(v.left) } });
                    try mi.append(allocator, .{ .irem = .{ .dest = opReg(quot_scratch), .rem = opReg(v.dest), .src = opReg(v.right) } });
                },
                .and_int => |v| {
                    try mi.append(allocator, .{ .mov    = .{ .dest = opReg(v.dest), .src = opReg(v.left) } });
                    try mi.append(allocator, .{ .and_op = .{ .dest = opReg(v.dest), .src = opReg(v.right) } });
                },
                .or_int => |v| {
                    try mi.append(allocator, .{ .mov   = .{ .dest = opReg(v.dest), .src = opReg(v.left) } });
                    try mi.append(allocator, .{ .or_op = .{ .dest = opReg(v.dest), .src = opReg(v.right) } });
                },
                .xor_int => |v| {
                    try mi.append(allocator, .{ .mov    = .{ .dest = opReg(v.dest), .src = opReg(v.left) } });
                    try mi.append(allocator, .{ .xor_op = .{ .dest = opReg(v.dest), .src = opReg(v.right) } });
                },
                .shl_int => |v| {
                    try mi.append(allocator, .{ .mov = .{ .dest = opReg(v.dest), .src = opReg(v.left) } });
                    try mi.append(allocator, .{ .shl = .{ .dest = opReg(v.dest), .src = opReg(v.right) } });
                },
                .shr_int => |v| {
                    try mi.append(allocator, .{ .mov = .{ .dest = opReg(v.dest), .src = opReg(v.left) } });
                    try mi.append(allocator, .{ .shr = .{ .dest = opReg(v.dest), .src = opReg(v.right) } });
                },
                .ushr_int => |v| {
                    try mi.append(allocator, .{ .mov  = .{ .dest = opReg(v.dest), .src = opReg(v.left) } });
                    try mi.append(allocator, .{ .ushr = .{ .dest = opReg(v.dest), .src = opReg(v.right) } });
                },

                // ── Float & Wide Binary (same 2-address expansion as int) ─
                .add_float, .add_wide => |v| {
                    try mi.append(allocator, .{ .mov = .{ .dest = opReg(v.dest), .src = opReg(v.left) } });
                    try mi.append(allocator, .{ .add = .{ .dest = opReg(v.dest), .src = opReg(v.right) } });
                },
                .sub_float, .sub_wide => |v| {
                    try mi.append(allocator, .{ .mov = .{ .dest = opReg(v.dest), .src = opReg(v.left) } });
                    try mi.append(allocator, .{ .sub = .{ .dest = opReg(v.dest), .src = opReg(v.right) } });
                },
                .mul_float, .mul_wide => |v| {
                    try mi.append(allocator, .{ .mov  = .{ .dest = opReg(v.dest), .src = opReg(v.left) } });
                    try mi.append(allocator, .{ .imul = .{ .dest = opReg(v.dest), .src = opReg(v.right) } });
                },
                .div_float, .div_wide => |v| {
                    const rem_scratch = ir.SSAVar{ .reg = v.dest.reg, .version = v.dest.version +% 0x8000 };
                    try mi.append(allocator, .{ .mov  = .{ .dest = opReg(v.dest),     .src = opReg(v.left) } });
                    try mi.append(allocator, .{ .idiv = .{ .dest = opReg(v.dest), .rem = opReg(rem_scratch), .src = opReg(v.right) } });
                },

                // ── Literal Arithmetic ────────────────────────────────────
                .add_lit => |v| {
                    try mi.append(allocator, .{ .mov = .{ .dest = opReg(v.dest), .src = opReg(v.src) } });
                    try mi.append(allocator, .{ .add = .{ .dest = opReg(v.dest), .src = opImm(v.lit) } });
                },
                .sub_lit => |v| {
                    try mi.append(allocator, .{ .mov = .{ .dest = opReg(v.dest), .src = opReg(v.src) } });
                    try mi.append(allocator, .{ .sub = .{ .dest = opReg(v.dest), .src = opImm(v.lit) } });
                },
                .mul_lit => |v| {
                    try mi.append(allocator, .{ .mov  = .{ .dest = opReg(v.dest), .src = opReg(v.src) } });
                    try mi.append(allocator, .{ .imul = .{ .dest = opReg(v.dest), .src = opImm(v.lit) } });
                },
                .div_lit => |v| {
                    const rem_scratch = ir.SSAVar{ .reg = v.dest.reg, .version = v.dest.version +% 0x8000 };
                    try mi.append(allocator, .{ .mov  = .{ .dest = opReg(v.dest),     .src = opReg(v.src) } });
                    try mi.append(allocator, .{ .idiv = .{ .dest = opReg(v.dest), .rem = opReg(rem_scratch), .src = opImm(v.lit) } });
                },
                .rem_lit => |v| {
                    const quot_scratch = ir.SSAVar{ .reg = v.dest.reg, .version = v.dest.version +% 0x8000 };
                    try mi.append(allocator, .{ .mov  = .{ .dest = opReg(quot_scratch), .src = opReg(v.src) } });
                    try mi.append(allocator, .{ .irem = .{ .dest = opReg(quot_scratch), .rem = opReg(v.dest), .src = opImm(v.lit) } });
                },
                .and_lit => |v| {
                    try mi.append(allocator, .{ .mov    = .{ .dest = opReg(v.dest), .src = opReg(v.src) } });
                    try mi.append(allocator, .{ .and_op = .{ .dest = opReg(v.dest), .src = opImm(v.lit) } });
                },
                .or_lit => |v| {
                    try mi.append(allocator, .{ .mov   = .{ .dest = opReg(v.dest), .src = opReg(v.src) } });
                    try mi.append(allocator, .{ .or_op = .{ .dest = opReg(v.dest), .src = opImm(v.lit) } });
                },
                .xor_lit => |v| {
                    try mi.append(allocator, .{ .mov    = .{ .dest = opReg(v.dest), .src = opReg(v.src) } });
                    try mi.append(allocator, .{ .xor_op = .{ .dest = opReg(v.dest), .src = opImm(v.lit) } });
                },
                .shl_lit => |v| {
                    try mi.append(allocator, .{ .mov = .{ .dest = opReg(v.dest), .src = opReg(v.src) } });
                    try mi.append(allocator, .{ .shl = .{ .dest = opReg(v.dest), .src = opImm(v.lit) } });
                },
                .shr_lit => |v| {
                    try mi.append(allocator, .{ .mov = .{ .dest = opReg(v.dest), .src = opReg(v.src) } });
                    try mi.append(allocator, .{ .shr = .{ .dest = opReg(v.dest), .src = opImm(v.lit) } });
                },
                .ushr_lit => |v| {
                    try mi.append(allocator, .{ .mov  = .{ .dest = opReg(v.dest), .src = opReg(v.src) } });
                    try mi.append(allocator, .{ .ushr = .{ .dest = opReg(v.dest), .src = opImm(v.lit) } });
                },

                // ── Object & Array Allocation ─────────────────────────────
                .new_instance => |v| {
                    try mi.append(allocator, .{ .alloc_obj = .{ .dest = opReg(v.dest), .type_idx = v.type_idx } });
                },
                .new_array => |v| {
                    try mi.append(allocator, .{ .alloc_arr = .{ .dest = opReg(v.dest), .size = opReg(v.size), .type_idx = v.type_idx } });
                },

                // ── Field Access ──────────────────────────────────────────
                .iget => |v| {
                    try mi.append(allocator, .{ .field_load = .{ .dest = opReg(v.dest_or_src), .obj = opReg(v.obj), .field_idx = v.field_idx } });
                },
                .iput => |v| {
                    try mi.append(allocator, .{ .field_store = .{ .src = opReg(v.dest_or_src), .obj = opReg(v.obj), .field_idx = v.field_idx } });
                },
                .sget => |v| {
                    try mi.append(allocator, .{ .field_load = .{ .dest = opReg(v.dest_or_src), .obj = null, .field_idx = v.field_idx } });
                },
                .sput => |v| {
                    try mi.append(allocator, .{ .field_store = .{ .src = opReg(v.dest_or_src), .obj = null, .field_idx = v.field_idx } });
                },

                // ── Array Element Access ──────────────────────────────────
                .aget => |v| {
                    try mi.append(allocator, .{ .arr_load = .{ .dest = opReg(v.dest_or_src), .array = opReg(v.array), .index = opReg(v.index) } });
                },
                .aput => |v| {
                    try mi.append(allocator, .{ .arr_store = .{ .src = opReg(v.dest_or_src), .array = opReg(v.array), .index = opReg(v.index) } });
                },

                // ── Control Flow ──────────────────────────────────────────
                .goto => |v| {
                    try mi.append(allocator, .{ .jmp = v.target_block_id });
                },
                .if_eq => |v| {
                    try mi.append(allocator, .{ .cmp = .{ .left = opReg(v.left), .right = opReg(v.right) } });
                    try mi.append(allocator, .{ .je = v.target_block_id });
                },
                .if_ne => |v| {
                    try mi.append(allocator, .{ .cmp = .{ .left = opReg(v.left), .right = opReg(v.right) } });
                    try mi.append(allocator, .{ .jne = v.target_block_id });
                },
                .if_lt => |v| {
                    try mi.append(allocator, .{ .cmp = .{ .left = opReg(v.left), .right = opReg(v.right) } });
                    try mi.append(allocator, .{ .jl = v.target_block_id });
                },
                .if_ge => |v| {
                    try mi.append(allocator, .{ .cmp = .{ .left = opReg(v.left), .right = opReg(v.right) } });
                    try mi.append(allocator, .{ .jge = v.target_block_id });
                },
                .if_gt => |v| {
                    try mi.append(allocator, .{ .cmp = .{ .left = opReg(v.left), .right = opReg(v.right) } });
                    try mi.append(allocator, .{ .jg = v.target_block_id });
                },
                .if_le => |v| {
                    try mi.append(allocator, .{ .cmp = .{ .left = opReg(v.left), .right = opReg(v.right) } });
                    try mi.append(allocator, .{ .jle = v.target_block_id });
                },
                // Zero-comparisons use TEST reg, reg (sets ZF without modifying reg)
                .if_eqz => |v| {
                    try mi.append(allocator, .{ .test_op = .{ .left = opReg(v.src), .right = opReg(v.src) } });
                    try mi.append(allocator, .{ .jz = v.target_block_id });
                },
                .if_nez => |v| {
                    try mi.append(allocator, .{ .test_op = .{ .left = opReg(v.src), .right = opReg(v.src) } });
                    try mi.append(allocator, .{ .jnz = v.target_block_id });
                },
                .if_ltz => |v| {
                    try mi.append(allocator, .{ .cmp = .{ .left = opReg(v.src), .right = opImm(0) } });
                    try mi.append(allocator, .{ .jl = v.target_block_id });
                },
                .if_gez => |v| {
                    try mi.append(allocator, .{ .cmp = .{ .left = opReg(v.src), .right = opImm(0) } });
                    try mi.append(allocator, .{ .jge = v.target_block_id });
                },
                .if_gtz => |v| {
                    try mi.append(allocator, .{ .cmp = .{ .left = opReg(v.src), .right = opImm(0) } });
                    try mi.append(allocator, .{ .jg = v.target_block_id });
                },
                .if_lez => |v| {
                    try mi.append(allocator, .{ .cmp = .{ .left = opReg(v.src), .right = opImm(0) } });
                    try mi.append(allocator, .{ .jle = v.target_block_id });
                },

                // ── Switch ────────────────────────────────────────────────
                .switch_op => |v| {
                    try mi.append(allocator, .{ .switch_stub = .{ .src = opReg(v.src), .num_cases = v.keys.len } });
                },

                // ── Method calls ─────────────────────────────────────────
                .invoke => |v| {
                    const dest_op: ?x86.Operand = if (v.dest) |d| opReg(d) else null;
                    try mi.append(allocator, .{ .call = .{
                        .dest       = dest_op,
                        .method_idx = v.method_idx,
                        .is_static  = v.is_static,
                        .arg_count  = v.args.len,
                    } });
                },

                // ── Returns & Exceptions ──────────────────────────────────
                .ret => |v| {
                    if (v.src) |s| {
                        try mi.append(allocator, .{ .ret = opReg(s) });
                    } else {
                        try mi.append(allocator, .{ .ret = null });
                    }
                },
                .throw_op => |v| {
                    try mi.append(allocator, .{ .throw_stub = .{ .src = opReg(v.src) } });
                },

                // ── SSA-only — must be removed before lowering ────────────
                .phi => {
                    // Phi nodes must be eliminated by dessa.eliminatePhis before lowerCFG.
                    // Encountering one here is a compiler pipeline bug.
                    return error.UnexpectedPhiNode;
                },
            }
        }

        try program.blocks.append(allocator, .{
            .id           = block.id,
            .instructions = mi,
        });
    }

    return program;
}

// ── Tests ─────────────────────────────────────────────────────────────────────

test "lowerCFG: const + add_lit + ret" {
    const a = std.testing.allocator;

    var cfg = cfgmod.CFG{
        .blocks    = std.ArrayList(cfgmod.BasicBlock).empty,
        .entry_block_id = 0,
        .allocator = a,
    };
    defer cfg.deinit();

    var block = cfgmod.BasicBlock{
        .id = 0, .start_idx = 0, .end_idx = 2,
        .successors        = std.ArrayList(usize).empty,
        .predecessors      = std.ArrayList(usize).empty,
        .idom              = null,
        .dominance_frontier = std.ArrayList(usize).empty,
        .dom_children      = std.ArrayList(usize).empty,
        .phi_functions     = std.ArrayList(cfgmod.PhiNode).empty,
        .instructions      = std.ArrayList(ir.IRInst).empty,
    };

    const v0 = ir.SSAVar{ .reg = 0, .version = 1 };
    const v1 = ir.SSAVar{ .reg = 1, .version = 1 };
    try block.instructions.append(a, .{ .const_int = .{ .dest = v0, .val = 10 } });
    try block.instructions.append(a, .{ .add_lit   = .{ .dest = v1, .src = v0, .lit = 5 } });
    try block.instructions.append(a, .{ .ret = .{ .src = v1 } });
    try cfg.blocks.append(a, block);

    var prog = try lowerCFG(a, &cfg);
    defer prog.deinit();

    const insts = prog.blocks.items[0].instructions.items;
    // const_int  → 1 × MOV
    // add_lit    → 1 × MOV + 1 × ADD
    // ret        → 1 × RET
    // Total = 4
    try std.testing.expectEqual(@as(usize, 4), insts.len);
    try std.testing.expect(insts[0] == .mov);   // const_int → MOV v1, #10
    try std.testing.expect(insts[1] == .mov);   // add_lit:  MOV v2, v1
    try std.testing.expect(insts[2] == .add);   // add_lit:  ADD v2, #5
    try std.testing.expect(insts[3] == .ret);   // ret v2
}

test "lowerCFG: conditional branch if_lt" {
    const a = std.testing.allocator;

    var cfg = cfgmod.CFG{
        .blocks    = std.ArrayList(cfgmod.BasicBlock).empty,
        .entry_block_id = 0,
        .allocator = a,
    };
    defer cfg.deinit();

    var block = cfgmod.BasicBlock{
        .id = 0, .start_idx = 0, .end_idx = 1,
        .successors        = std.ArrayList(usize).empty,
        .predecessors      = std.ArrayList(usize).empty,
        .idom              = null,
        .dominance_frontier = std.ArrayList(usize).empty,
        .dom_children      = std.ArrayList(usize).empty,
        .phi_functions     = std.ArrayList(cfgmod.PhiNode).empty,
        .instructions      = std.ArrayList(ir.IRInst).empty,
    };

    const va = ir.SSAVar{ .reg = 0, .version = 1 };
    const vb = ir.SSAVar{ .reg = 1, .version = 1 };
    try block.instructions.append(a, .{ .if_lt = .{ .left = va, .right = vb, .target_block_id = 2 } });
    try cfg.blocks.append(a, block);

    var prog = try lowerCFG(a, &cfg);
    defer prog.deinit();

    const insts = prog.blocks.items[0].instructions.items;
    // if_lt → CMP + JL
    try std.testing.expectEqual(@as(usize, 2), insts.len);
    try std.testing.expect(insts[0] == .cmp);
    try std.testing.expect(insts[1] == .jl);
    try std.testing.expectEqual(@as(usize, 2), insts[1].jl);
}

test "lowerCFG: zero-comparison if_eqz" {
    const a = std.testing.allocator;

    var cfg = cfgmod.CFG{
        .blocks    = std.ArrayList(cfgmod.BasicBlock).empty,
        .entry_block_id = 0,
        .allocator = a,
    };
    defer cfg.deinit();

    var block = cfgmod.BasicBlock{
        .id = 0, .start_idx = 0, .end_idx = 0,
        .successors        = std.ArrayList(usize).empty,
        .predecessors      = std.ArrayList(usize).empty,
        .idom              = null,
        .dominance_frontier = std.ArrayList(usize).empty,
        .dom_children      = std.ArrayList(usize).empty,
        .phi_functions     = std.ArrayList(cfgmod.PhiNode).empty,
        .instructions      = std.ArrayList(ir.IRInst).empty,
    };

    const v0 = ir.SSAVar{ .reg = 0, .version = 1 };
    try block.instructions.append(a, .{ .if_eqz = .{ .src = v0, .target_block_id = 3 } });
    try cfg.blocks.append(a, block);

    var prog = try lowerCFG(a, &cfg);
    defer prog.deinit();

    const insts = prog.blocks.items[0].instructions.items;
    // if_eqz → TEST reg,reg + JZ
    try std.testing.expectEqual(@as(usize, 2), insts.len);
    try std.testing.expect(insts[0] == .test_op);
    try std.testing.expect(insts[1] == .jz);
}

test "lowerCFG: iget and iput field access" {
    const a = std.testing.allocator;

    var cfg = cfgmod.CFG{
        .blocks    = std.ArrayList(cfgmod.BasicBlock).empty,
        .entry_block_id = 0,
        .allocator = a,
    };
    defer cfg.deinit();

    var block = cfgmod.BasicBlock{
        .id = 0, .start_idx = 0, .end_idx = 1,
        .successors        = std.ArrayList(usize).empty,
        .predecessors      = std.ArrayList(usize).empty,
        .idom              = null,
        .dominance_frontier = std.ArrayList(usize).empty,
        .dom_children      = std.ArrayList(usize).empty,
        .phi_functions     = std.ArrayList(cfgmod.PhiNode).empty,
        .instructions      = std.ArrayList(ir.IRInst).empty,
    };

    const obj  = ir.SSAVar{ .reg = 0, .version = 1 };
    const dest = ir.SSAVar{ .reg = 1, .version = 1 };
    try block.instructions.append(a, .{ .iget = .{ .dest_or_src = dest, .obj = obj, .field_idx = 7 } });
    try block.instructions.append(a, .{ .iput = .{ .dest_or_src = dest, .obj = obj, .field_idx = 7 } });
    try cfg.blocks.append(a, block);

    var prog = try lowerCFG(a, &cfg);
    defer prog.deinit();

    const insts = prog.blocks.items[0].instructions.items;
    try std.testing.expectEqual(@as(usize, 2), insts.len);
    try std.testing.expect(insts[0] == .field_load);
    try std.testing.expect(insts[1] == .field_store);
    try std.testing.expectEqual(@as(u32, 7), insts[0].field_load.field_idx);
}

test "lowerCFG: invoke method call" {
    const a = std.testing.allocator;

    var cfg = cfgmod.CFG{
        .blocks    = std.ArrayList(cfgmod.BasicBlock).empty,
        .entry_block_id = 0,
        .allocator = a,
    };
    defer cfg.deinit();

    var block = cfgmod.BasicBlock{
        .id = 0, .start_idx = 0, .end_idx = 0,
        .successors        = std.ArrayList(usize).empty,
        .predecessors      = std.ArrayList(usize).empty,
        .idom              = null,
        .dominance_frontier = std.ArrayList(usize).empty,
        .dom_children      = std.ArrayList(usize).empty,
        .phi_functions     = std.ArrayList(cfgmod.PhiNode).empty,
        .instructions      = std.ArrayList(ir.IRInst).empty,
    };

    const arg0 = ir.SSAVar{ .reg = 0, .version = 1 };
    // cfg.deinit() will free v.args via allocator.free, so we must NOT defer a.free here.
    const args = try a.alloc(ir.SSAVar, 1);
    args[0] = arg0;

    const dest_v = ir.SSAVar{ .reg = 1, .version = 1 };
    try block.instructions.append(a, .{ .invoke = .{
        .dest       = dest_v,
        .method_idx = 42,
        .is_static  = true,
        .args       = args,
    } });
    try cfg.blocks.append(a, block);

    var prog = try lowerCFG(a, &cfg);
    defer prog.deinit();

    const insts = prog.blocks.items[0].instructions.items;
    try std.testing.expectEqual(@as(usize, 1), insts.len);
    try std.testing.expect(insts[0] == .call);
    try std.testing.expectEqual(@as(u32, 42), insts[0].call.method_idx);
    try std.testing.expectEqual(@as(usize, 1), insts[0].call.arg_count);
    try std.testing.expect(insts[0].call.dest != null);
}



