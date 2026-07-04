const std = @import("std");
const ir = @import("ir");
const cfgmod = @import("cfg");
const x86 = @import("x86");

inline fn opReg(v: ir.SSAVar) x86.Operand  { return .{ .vreg = v }; }
inline fn opImm(val: i32) x86.Operand      { return .{ .imm = val }; }
inline fn opImm64(val: i64) x86.Operand    { return .{ .imm64 = val }; }

/// True when two SSA variables refer to the same virtual register.
inline fn eqVar(a: ir.SSAVar, b: ir.SSAVar) bool {
    return a.reg == b.reg and a.version == b.version;
}

/// Post-lowering peephole: removes any `MOV x, x` (self-moves) that survived
/// coalescing.  Runs in O(n) per block.
fn removeDeadMovs(allocator: std.mem.Allocator, program: *x86.MachineProgram) !void {
    for (program.blocks.items) |*mblock| {
        var write: usize = 0;
        for (mblock.instructions.items) |inst| {
            const is_self_mov = switch (inst) {
                .mov => |v| switch (v.dest) {
                    .vreg => |d| switch (v.src) {
                        .vreg => |s| eqVar(d, s),
                        else  => false,
                    },
                    else => false,
                },
                else => false,
            };
            if (!is_self_mov) {
                mblock.instructions.items[write] = inst;
                write += 1;
            }
        }
        mblock.instructions.shrinkRetainingCapacity(write);
        _ = allocator; // used by future passes
    }
}

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

                // ── Integer Binary (3-Address → 2-Address with coalescing) ────
                //
                // For COMMUTATIVE ops (add, mul, and, or, xor):
                //   dest == left  → OP dest, right          (skip leading MOV)
                //   dest == right → OP dest, left           (commutative swap; also fixes clobber bug)
                //   otherwise     → MOV dest, left; OP dest, right
                //
                // For NON-COMMUTATIVE ops (sub, shl, shr, ushr):
                //   dest == left  → OP dest, right          (skip leading MOV)
                //   otherwise     → MOV dest, left; OP dest, right
                //   (dest == right is rare/impossible post-dessa for shifts; handled by general case)
                //
                // For SUB where dest == right:
                //   dest = left − right − where right IS dest. Emit: NEG dest; ADD dest, left
                //   because -(right) + left == left − right.

                .add_int => |v| {
                    if (eqVar(v.dest, v.left)) {
                        try mi.append(allocator, .{ .add = .{ .dest = opReg(v.dest), .src = opReg(v.right) } });
                    } else if (eqVar(v.dest, v.right)) {
                        try mi.append(allocator, .{ .add = .{ .dest = opReg(v.dest), .src = opReg(v.left) } });
                    } else {
                        try mi.append(allocator, .{ .mov = .{ .dest = opReg(v.dest), .src = opReg(v.left) } });
                        try mi.append(allocator, .{ .add = .{ .dest = opReg(v.dest), .src = opReg(v.right) } });
                    }
                },
                .sub_int => |v| {
                    if (eqVar(v.dest, v.left)) {
                        try mi.append(allocator, .{ .sub = .{ .dest = opReg(v.dest), .src = opReg(v.right) } });
                    } else if (eqVar(v.dest, v.right)) {
                        // dest = left - dest → NEG dest; ADD dest, left
                        try mi.append(allocator, .{ .neg = .{ .dest = opReg(v.dest) } });
                        try mi.append(allocator, .{ .add = .{ .dest = opReg(v.dest), .src = opReg(v.left) } });
                    } else {
                        try mi.append(allocator, .{ .mov = .{ .dest = opReg(v.dest), .src = opReg(v.left) } });
                        try mi.append(allocator, .{ .sub = .{ .dest = opReg(v.dest), .src = opReg(v.right) } });
                    }
                },
                .mul_int => |v| {
                    if (eqVar(v.dest, v.left)) {
                        try mi.append(allocator, .{ .imul = .{ .dest = opReg(v.dest), .src = opReg(v.right) } });
                    } else if (eqVar(v.dest, v.right)) {
                        try mi.append(allocator, .{ .imul = .{ .dest = opReg(v.dest), .src = opReg(v.left) } });
                    } else {
                        try mi.append(allocator, .{ .mov  = .{ .dest = opReg(v.dest), .src = opReg(v.left) } });
                        try mi.append(allocator, .{ .imul = .{ .dest = opReg(v.dest), .src = opReg(v.right) } });
                    }
                },
                .div_int => |v| {
                    const rem_scratch = ir.SSAVar{ .reg = v.dest.reg, .version = v.dest.version +% 0x8000 };
                    if (eqVar(v.dest, v.left)) {
                        try mi.append(allocator, .{ .idiv = .{ .dest = opReg(v.dest), .rem = opReg(rem_scratch), .src = opReg(v.right) } });
                    } else {
                        try mi.append(allocator, .{ .mov  = .{ .dest = opReg(v.dest), .src = opReg(v.left) } });
                        try mi.append(allocator, .{ .idiv = .{ .dest = opReg(v.dest), .rem = opReg(rem_scratch), .src = opReg(v.right) } });
                    }
                },
                .rem_int => |v| {
                    const quot_scratch = ir.SSAVar{ .reg = v.dest.reg, .version = v.dest.version +% 0x8000 };
                    try mi.append(allocator, .{ .mov  = .{ .dest = opReg(quot_scratch), .src = opReg(v.left) } });
                    try mi.append(allocator, .{ .irem = .{ .dest = opReg(quot_scratch), .rem = opReg(v.dest), .src = opReg(v.right) } });
                },
                .and_int => |v| {
                    if (eqVar(v.dest, v.left)) {
                        try mi.append(allocator, .{ .and_op = .{ .dest = opReg(v.dest), .src = opReg(v.right) } });
                    } else if (eqVar(v.dest, v.right)) {
                        try mi.append(allocator, .{ .and_op = .{ .dest = opReg(v.dest), .src = opReg(v.left) } });
                    } else {
                        try mi.append(allocator, .{ .mov    = .{ .dest = opReg(v.dest), .src = opReg(v.left) } });
                        try mi.append(allocator, .{ .and_op = .{ .dest = opReg(v.dest), .src = opReg(v.right) } });
                    }
                },
                .or_int => |v| {
                    if (eqVar(v.dest, v.left)) {
                        try mi.append(allocator, .{ .or_op = .{ .dest = opReg(v.dest), .src = opReg(v.right) } });
                    } else if (eqVar(v.dest, v.right)) {
                        try mi.append(allocator, .{ .or_op = .{ .dest = opReg(v.dest), .src = opReg(v.left) } });
                    } else {
                        try mi.append(allocator, .{ .mov   = .{ .dest = opReg(v.dest), .src = opReg(v.left) } });
                        try mi.append(allocator, .{ .or_op = .{ .dest = opReg(v.dest), .src = opReg(v.right) } });
                    }
                },
                .xor_int => |v| {
                    if (eqVar(v.dest, v.left)) {
                        try mi.append(allocator, .{ .xor_op = .{ .dest = opReg(v.dest), .src = opReg(v.right) } });
                    } else if (eqVar(v.dest, v.right)) {
                        try mi.append(allocator, .{ .xor_op = .{ .dest = opReg(v.dest), .src = opReg(v.left) } });
                    } else {
                        try mi.append(allocator, .{ .mov    = .{ .dest = opReg(v.dest), .src = opReg(v.left) } });
                        try mi.append(allocator, .{ .xor_op = .{ .dest = opReg(v.dest), .src = opReg(v.right) } });
                    }
                },
                .shl_int => |v| {
                    if (eqVar(v.dest, v.left)) {
                        try mi.append(allocator, .{ .shl = .{ .dest = opReg(v.dest), .src = opReg(v.right) } });
                    } else {
                        try mi.append(allocator, .{ .mov = .{ .dest = opReg(v.dest), .src = opReg(v.left) } });
                        try mi.append(allocator, .{ .shl = .{ .dest = opReg(v.dest), .src = opReg(v.right) } });
                    }
                },
                .shr_int => |v| {
                    if (eqVar(v.dest, v.left)) {
                        try mi.append(allocator, .{ .shr = .{ .dest = opReg(v.dest), .src = opReg(v.right) } });
                    } else {
                        try mi.append(allocator, .{ .mov = .{ .dest = opReg(v.dest), .src = opReg(v.left) } });
                        try mi.append(allocator, .{ .shr = .{ .dest = opReg(v.dest), .src = opReg(v.right) } });
                    }
                },
                .ushr_int => |v| {
                    if (eqVar(v.dest, v.left)) {
                        try mi.append(allocator, .{ .ushr = .{ .dest = opReg(v.dest), .src = opReg(v.right) } });
                    } else {
                        try mi.append(allocator, .{ .mov  = .{ .dest = opReg(v.dest), .src = opReg(v.left) } });
                        try mi.append(allocator, .{ .ushr = .{ .dest = opReg(v.dest), .src = opReg(v.right) } });
                    }
                },

                // ── Float & Wide Binary (Lowered to native SSE instructions) ──
                .add_float => |v| {
                    if (eqVar(v.dest, v.left)) {
                        try mi.append(allocator, .{ .addss = .{ .dest = opReg(v.dest), .src = opReg(v.right) } });
                    } else if (eqVar(v.dest, v.right)) {
                        try mi.append(allocator, .{ .addss = .{ .dest = opReg(v.dest), .src = opReg(v.left) } });
                    } else {
                        try mi.append(allocator, .{ .movss = .{ .dest = opReg(v.dest), .src = opReg(v.left) } });
                        try mi.append(allocator, .{ .addss = .{ .dest = opReg(v.dest), .src = opReg(v.right) } });
                    }
                },
                .add_long => |v| {
                    if (eqVar(v.dest, v.left)) {
                        try mi.append(allocator, .{ .add = .{ .dest = opReg(v.dest), .src = opReg(v.right) } });
                    } else if (eqVar(v.dest, v.right)) {
                        try mi.append(allocator, .{ .add = .{ .dest = opReg(v.dest), .src = opReg(v.left) } });
                    } else {
                        try mi.append(allocator, .{ .mov = .{ .dest = opReg(v.dest), .src = opReg(v.left) } });
                        try mi.append(allocator, .{ .add = .{ .dest = opReg(v.dest), .src = opReg(v.right) } });
                    }
                },
                .sub_long => |v| {
                    if (eqVar(v.dest, v.left)) {
                        try mi.append(allocator, .{ .sub = .{ .dest = opReg(v.dest), .src = opReg(v.right) } });
                    } else if (eqVar(v.dest, v.right)) {
                        try mi.append(allocator, .{ .neg = .{ .dest = opReg(v.dest) } });
                        try mi.append(allocator, .{ .add = .{ .dest = opReg(v.dest), .src = opReg(v.left) } });
                    } else {
                        try mi.append(allocator, .{ .mov = .{ .dest = opReg(v.dest), .src = opReg(v.left) } });
                        try mi.append(allocator, .{ .sub = .{ .dest = opReg(v.dest), .src = opReg(v.right) } });
                    }
                },
                .mul_long => |v| {
                    if (eqVar(v.dest, v.left)) {
                        try mi.append(allocator, .{ .imul = .{ .dest = opReg(v.dest), .src = opReg(v.right) } });
                    } else if (eqVar(v.dest, v.right)) {
                        try mi.append(allocator, .{ .imul = .{ .dest = opReg(v.dest), .src = opReg(v.left) } });
                    } else {
                        try mi.append(allocator, .{ .mov = .{ .dest = opReg(v.dest), .src = opReg(v.left) } });
                        try mi.append(allocator, .{ .imul = .{ .dest = opReg(v.dest), .src = opReg(v.right) } });
                    }
                },
                .div_long => |v| {
                    const rem_scratch = ir.SSAVar{ .reg = v.dest.reg, .version = v.dest.version +% 0x8000 };
                    if (!eqVar(v.dest, v.left)) try mi.append(allocator, .{ .mov = .{ .dest = opReg(v.dest), .src = opReg(v.left) } });
                    try mi.append(allocator, .{ .idiv = .{ .dest = opReg(v.dest), .rem = opReg(rem_scratch), .src = opReg(v.right) } });
                },
                .add_wide => |v| {
                    if (eqVar(v.dest, v.left)) {
                        try mi.append(allocator, .{ .addsd = .{ .dest = opReg(v.dest), .src = opReg(v.right) } });
                    } else if (eqVar(v.dest, v.right)) {
                        try mi.append(allocator, .{ .addsd = .{ .dest = opReg(v.dest), .src = opReg(v.left) } });
                    } else {
                        try mi.append(allocator, .{ .movsd = .{ .dest = opReg(v.dest), .src = opReg(v.left) } });
                        try mi.append(allocator, .{ .addsd = .{ .dest = opReg(v.dest), .src = opReg(v.right) } });
                    }
                },
                .sub_float => |v| {
                    if (eqVar(v.dest, v.left)) {
                        try mi.append(allocator, .{ .subss = .{ .dest = opReg(v.dest), .src = opReg(v.right) } });
                    } else {
                        try mi.append(allocator, .{ .movss = .{ .dest = opReg(v.dest), .src = opReg(v.left) } });
                        try mi.append(allocator, .{ .subss = .{ .dest = opReg(v.dest), .src = opReg(v.right) } });
                    }
                },
                .sub_wide => |v| {
                    if (eqVar(v.dest, v.left)) {
                        try mi.append(allocator, .{ .subsd = .{ .dest = opReg(v.dest), .src = opReg(v.right) } });
                    } else {
                        try mi.append(allocator, .{ .movsd = .{ .dest = opReg(v.dest), .src = opReg(v.left) } });
                        try mi.append(allocator, .{ .subsd = .{ .dest = opReg(v.dest), .src = opReg(v.right) } });
                    }
                },
                .mul_float => |v| {
                    if (eqVar(v.dest, v.left)) {
                        try mi.append(allocator, .{ .mulss = .{ .dest = opReg(v.dest), .src = opReg(v.right) } });
                    } else if (eqVar(v.dest, v.right)) {
                        try mi.append(allocator, .{ .mulss = .{ .dest = opReg(v.dest), .src = opReg(v.left) } });
                    } else {
                        try mi.append(allocator, .{ .movss = .{ .dest = opReg(v.dest), .src = opReg(v.left) } });
                        try mi.append(allocator, .{ .mulss = .{ .dest = opReg(v.dest), .src = opReg(v.right) } });
                    }
                },
                .mul_wide => |v| {
                    if (eqVar(v.dest, v.left)) {
                        try mi.append(allocator, .{ .mulsd = .{ .dest = opReg(v.dest), .src = opReg(v.right) } });
                    } else if (eqVar(v.dest, v.right)) {
                        try mi.append(allocator, .{ .mulsd = .{ .dest = opReg(v.dest), .src = opReg(v.left) } });
                    } else {
                        try mi.append(allocator, .{ .movsd = .{ .dest = opReg(v.dest), .src = opReg(v.left) } });
                        try mi.append(allocator, .{ .mulsd = .{ .dest = opReg(v.dest), .src = opReg(v.right) } });
                    }
                },
                .div_float => |v| {
                    if (eqVar(v.dest, v.left)) {
                        try mi.append(allocator, .{ .divss = .{ .dest = opReg(v.dest), .src = opReg(v.right) } });
                    } else {
                        try mi.append(allocator, .{ .movss = .{ .dest = opReg(v.dest), .src = opReg(v.left) } });
                        try mi.append(allocator, .{ .divss = .{ .dest = opReg(v.dest), .src = opReg(v.right) } });
                    }
                },
                .div_wide => |v| {
                    if (eqVar(v.dest, v.left)) {
                        try mi.append(allocator, .{ .divsd = .{ .dest = opReg(v.dest), .src = opReg(v.right) } });
                    } else {
                        try mi.append(allocator, .{ .movsd = .{ .dest = opReg(v.dest), .src = opReg(v.left) } });
                        try mi.append(allocator, .{ .divsd = .{ .dest = opReg(v.dest), .src = opReg(v.right) } });
                    }
                },

                // ── Literal Arithmetic (skip MOV when dest == src) ─────────
                .add_lit => |v| {
                    if (!eqVar(v.dest, v.src)) try mi.append(allocator, .{ .mov = .{ .dest = opReg(v.dest), .src = opReg(v.src) } });
                    try mi.append(allocator, .{ .add = .{ .dest = opReg(v.dest), .src = opImm(v.lit) } });
                },
                .sub_lit => |v| {
                    if (!eqVar(v.dest, v.src)) try mi.append(allocator, .{ .mov = .{ .dest = opReg(v.dest), .src = opReg(v.src) } });
                    try mi.append(allocator, .{ .sub = .{ .dest = opReg(v.dest), .src = opImm(v.lit) } });
                },
                .mul_lit => |v| {
                    if (!eqVar(v.dest, v.src)) try mi.append(allocator, .{ .mov = .{ .dest = opReg(v.dest), .src = opReg(v.src) } });
                    try mi.append(allocator, .{ .imul = .{ .dest = opReg(v.dest), .src = opImm(v.lit) } });
                },
                .div_lit => |v| {
                    const rem_scratch = ir.SSAVar{ .reg = v.dest.reg, .version = v.dest.version +% 0x8000 };
                    if (!eqVar(v.dest, v.src)) try mi.append(allocator, .{ .mov = .{ .dest = opReg(v.dest), .src = opReg(v.src) } });
                    try mi.append(allocator, .{ .idiv = .{ .dest = opReg(v.dest), .rem = opReg(rem_scratch), .src = opImm(v.lit) } });
                },
                .rem_lit => |v| {
                    const quot_scratch = ir.SSAVar{ .reg = v.dest.reg, .version = v.dest.version +% 0x8000 };
                    try mi.append(allocator, .{ .mov  = .{ .dest = opReg(quot_scratch), .src = opReg(v.src) } });
                    try mi.append(allocator, .{ .irem = .{ .dest = opReg(quot_scratch), .rem = opReg(v.dest), .src = opImm(v.lit) } });
                },
                .and_lit => |v| {
                    if (!eqVar(v.dest, v.src)) try mi.append(allocator, .{ .mov = .{ .dest = opReg(v.dest), .src = opReg(v.src) } });
                    try mi.append(allocator, .{ .and_op = .{ .dest = opReg(v.dest), .src = opImm(v.lit) } });
                },
                .or_lit => |v| {
                    if (!eqVar(v.dest, v.src)) try mi.append(allocator, .{ .mov = .{ .dest = opReg(v.dest), .src = opReg(v.src) } });
                    try mi.append(allocator, .{ .or_op = .{ .dest = opReg(v.dest), .src = opImm(v.lit) } });
                },
                .xor_lit => |v| {
                    if (!eqVar(v.dest, v.src)) try mi.append(allocator, .{ .mov = .{ .dest = opReg(v.dest), .src = opReg(v.src) } });
                    try mi.append(allocator, .{ .xor_op = .{ .dest = opReg(v.dest), .src = opImm(v.lit) } });
                },
                .shl_lit => |v| {
                    if (!eqVar(v.dest, v.src)) try mi.append(allocator, .{ .mov = .{ .dest = opReg(v.dest), .src = opReg(v.src) } });
                    try mi.append(allocator, .{ .shl = .{ .dest = opReg(v.dest), .src = opImm(v.lit) } });
                },
                .shr_lit => |v| {
                    if (!eqVar(v.dest, v.src)) try mi.append(allocator, .{ .mov = .{ .dest = opReg(v.dest), .src = opReg(v.src) } });
                    try mi.append(allocator, .{ .shr = .{ .dest = opReg(v.dest), .src = opImm(v.lit) } });
                },
                .ushr_lit => |v| {
                    if (!eqVar(v.dest, v.src)) try mi.append(allocator, .{ .mov = .{ .dest = opReg(v.dest), .src = opReg(v.src) } });
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

                // ── Array Element Access (Lowered to hardware SIB memory addressing) ──
                .aget => |v| {
                    const mem_op = x86.Operand{ .mem = .{
                        .base = .{ .vreg = v.array },
                        .index = .{ .vreg = v.index },
                        .scale = 4,
                        .disp = 16,
                    } };
                    try mi.append(allocator, .{ .mov = .{ .dest = opReg(v.dest_or_src), .src = mem_op } });
                },
                .aput => |v| {
                    const mem_op = x86.Operand{ .mem = .{
                        .base = .{ .vreg = v.array },
                        .index = .{ .vreg = v.index },
                        .scale = 4,
                        .disp = 16,
                    } };
                    try mi.append(allocator, .{ .mov = .{ .dest = mem_op, .src = opReg(v.dest_or_src) } });
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

    try removeDeadMovs(allocator, &program);
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

// ── Optimization tests ────────────────────────────────────────────────────────

test "opt: commutative coalescing - dest == right skips MOV and swaps operands" {
    // add_wide dest=v3_4, left=v1_1, right=v3_4
    // Before: MOV v3_4, v1_1; ADD v3_4, v3_4   ← WRONG (clobbers right)
    // After:  ADD v3_4, v1_1                    ← commutative swap, no MOV
    const a = std.testing.allocator;

    var cfg = cfgmod.CFG{ .blocks = std.ArrayList(cfgmod.BasicBlock).empty, .entry_block_id = 0, .allocator = a };
    defer cfg.deinit();

    var block = cfgmod.BasicBlock{
        .id = 0, .start_idx = 0, .end_idx = 0,
        .successors = std.ArrayList(usize).empty, .predecessors = std.ArrayList(usize).empty,
        .idom = null, .dominance_frontier = std.ArrayList(usize).empty,
        .dom_children = std.ArrayList(usize).empty, .phi_functions = std.ArrayList(cfgmod.PhiNode).empty,
        .instructions = std.ArrayList(ir.IRInst).empty,
    };

    const v1_1 = ir.SSAVar{ .reg = 1, .version = 1 };
    const v3_4 = ir.SSAVar{ .reg = 3, .version = 4 };
    // add_wide v3_4 = v1_1 + v3_4   (dest == right)
    try block.instructions.append(a, .{ .add_wide = .{ .dest = v3_4, .left = v1_1, .right = v3_4 } });
    try cfg.blocks.append(a, block);

    var prog = try lowerCFG(a, &cfg);
    defer prog.deinit();

    const insts = prog.blocks.items[0].instructions.items;
    // Should emit exactly 1 × ADDSD (no MOV)
    try std.testing.expectEqual(@as(usize, 1), insts.len);
    try std.testing.expect(insts[0] == .addsd);
    // The ADDSD should use v1_1 as src (commutative swap)
    try std.testing.expectEqual(v1_1.reg, insts[0].addsd.src.vreg.reg);
    try std.testing.expectEqual(v1_1.version, insts[0].addsd.src.vreg.version);
}

test "opt: commutative coalescing - dest == left skips MOV" {
    // add_int dest=v0, left=v0, right=v1 → ADD v0, v1 (no MOV)
    const a = std.testing.allocator;

    var cfg = cfgmod.CFG{ .blocks = std.ArrayList(cfgmod.BasicBlock).empty, .entry_block_id = 0, .allocator = a };
    defer cfg.deinit();

    var block = cfgmod.BasicBlock{
        .id = 0, .start_idx = 0, .end_idx = 0,
        .successors = std.ArrayList(usize).empty, .predecessors = std.ArrayList(usize).empty,
        .idom = null, .dominance_frontier = std.ArrayList(usize).empty,
        .dom_children = std.ArrayList(usize).empty, .phi_functions = std.ArrayList(cfgmod.PhiNode).empty,
        .instructions = std.ArrayList(ir.IRInst).empty,
    };

    const v0 = ir.SSAVar{ .reg = 0, .version = 1 };
    const v1 = ir.SSAVar{ .reg = 1, .version = 1 };
    try block.instructions.append(a, .{ .add_int = .{ .dest = v0, .left = v0, .right = v1 } });
    try cfg.blocks.append(a, block);

    var prog = try lowerCFG(a, &cfg);
    defer prog.deinit();

    const insts = prog.blocks.items[0].instructions.items;
    try std.testing.expectEqual(@as(usize, 1), insts.len);
    try std.testing.expect(insts[0] == .add);
    // src should be v1 (the right operand)
    try std.testing.expectEqual(v1.reg, insts[0].add.src.vreg.reg);
}

test "opt: literal coalescing - dest == src skips MOV" {
    // add_lit dest=v0, src=v0, lit=1 → ADD v0, #1 (no MOV)
    const a = std.testing.allocator;

    var cfg = cfgmod.CFG{ .blocks = std.ArrayList(cfgmod.BasicBlock).empty, .entry_block_id = 0, .allocator = a };
    defer cfg.deinit();

    var block = cfgmod.BasicBlock{
        .id = 0, .start_idx = 0, .end_idx = 0,
        .successors = std.ArrayList(usize).empty, .predecessors = std.ArrayList(usize).empty,
        .idom = null, .dominance_frontier = std.ArrayList(usize).empty,
        .dom_children = std.ArrayList(usize).empty, .phi_functions = std.ArrayList(cfgmod.PhiNode).empty,
        .instructions = std.ArrayList(ir.IRInst).empty,
    };

    const v0 = ir.SSAVar{ .reg = 0, .version = 4 };
    // add_lit v0_4 = v0_4 + 1   (dest == src — common in loop increments)
    try block.instructions.append(a, .{ .add_lit = .{ .dest = v0, .src = v0, .lit = 1 } });
    try cfg.blocks.append(a, block);

    var prog = try lowerCFG(a, &cfg);
    defer prog.deinit();

    const insts = prog.blocks.items[0].instructions.items;
    // Only 1 × ADD (no MOV, no dead self-MOV)
    try std.testing.expectEqual(@as(usize, 1), insts.len);
    try std.testing.expect(insts[0] == .add);
    try std.testing.expectEqual(@as(i32, 1), insts[0].add.src.imm);
}

test "opt: removeDeadMovs - self-moves from move instruction removed" {
    // move v0_1 = v0_1 → MOV v0_1, v0_1 → stripped by removeDeadMovs
    const a = std.testing.allocator;

    var cfg = cfgmod.CFG{ .blocks = std.ArrayList(cfgmod.BasicBlock).empty, .entry_block_id = 0, .allocator = a };
    defer cfg.deinit();

    var block = cfgmod.BasicBlock{
        .id = 0, .start_idx = 0, .end_idx = 0,
        .successors = std.ArrayList(usize).empty, .predecessors = std.ArrayList(usize).empty,
        .idom = null, .dominance_frontier = std.ArrayList(usize).empty,
        .dom_children = std.ArrayList(usize).empty, .phi_functions = std.ArrayList(cfgmod.PhiNode).empty,
        .instructions = std.ArrayList(ir.IRInst).empty,
    };

    const v0 = ir.SSAVar{ .reg = 0, .version = 1 };
    const v1 = ir.SSAVar{ .reg = 1, .version = 1 };
    try block.instructions.append(a, .{ .move = .{ .dest = v0, .src = v0 } }); // self-move → stripped
    try block.instructions.append(a, .{ .move = .{ .dest = v1, .src = v0 } }); // real move → kept
    try cfg.blocks.append(a, block);

    var prog = try lowerCFG(a, &cfg);
    defer prog.deinit();

    const insts = prog.blocks.items[0].instructions.items;
    try std.testing.expectEqual(@as(usize, 1), insts.len);
    try std.testing.expect(insts[0] == .mov);
    try std.testing.expectEqual(v0.reg, insts[0].mov.src.vreg.reg);
}

test "opt: sub dest==right emits NEG+ADD instead of clobbering MOV" {
    // sub_int dest=v1, left=v0, right=v1   (dest = v0 - v1, but dest IS v1)
    // Naive: MOV v1, v0; SUB v1, v1  ← wrong (v0-v0 = 0)
    // Opt:   NEG v1; ADD v1, v0      ← correct: -(v1) + v0 = v0 - v1
    const a = std.testing.allocator;

    var cfg = cfgmod.CFG{ .blocks = std.ArrayList(cfgmod.BasicBlock).empty, .entry_block_id = 0, .allocator = a };
    defer cfg.deinit();

    var block = cfgmod.BasicBlock{
        .id = 0, .start_idx = 0, .end_idx = 0,
        .successors = std.ArrayList(usize).empty, .predecessors = std.ArrayList(usize).empty,
        .idom = null, .dominance_frontier = std.ArrayList(usize).empty,
        .dom_children = std.ArrayList(usize).empty, .phi_functions = std.ArrayList(cfgmod.PhiNode).empty,
        .instructions = std.ArrayList(ir.IRInst).empty,
    };

    const v0 = ir.SSAVar{ .reg = 0, .version = 1 };
    const v1 = ir.SSAVar{ .reg = 1, .version = 1 };
    try block.instructions.append(a, .{ .sub_int = .{ .dest = v1, .left = v0, .right = v1 } });
    try cfg.blocks.append(a, block);

    var prog = try lowerCFG(a, &cfg);
    defer prog.deinit();

    const insts = prog.blocks.items[0].instructions.items;
    try std.testing.expectEqual(@as(usize, 2), insts.len);
    try std.testing.expect(insts[0] == .neg); // NEG v1
    try std.testing.expect(insts[1] == .add); // ADD v1, v0
    try std.testing.expectEqual(v0.reg, insts[1].add.src.vreg.reg);
}

test "lowerCFG: long math operations" {
    const a = std.testing.allocator;

    var cfg = cfgmod.CFG{ .blocks = std.ArrayList(cfgmod.BasicBlock).empty, .entry_block_id = 0, .allocator = a };
    defer cfg.deinit();

    var block = cfgmod.BasicBlock{
        .id = 0, .start_idx = 0, .end_idx = 0,
        .successors = std.ArrayList(usize).empty, .predecessors = std.ArrayList(usize).empty,
        .idom = null, .dominance_frontier = std.ArrayList(usize).empty,
        .dom_children = std.ArrayList(usize).empty, .phi_functions = std.ArrayList(cfgmod.PhiNode).empty,
        .instructions = std.ArrayList(ir.IRInst).empty,
    };

    const v0 = ir.SSAVar{ .reg = 0, .version = 1 };
    const v1 = ir.SSAVar{ .reg = 1, .version = 1 };
    const v2 = ir.SSAVar{ .reg = 2, .version = 1 };

    try block.instructions.append(a, .{ .add_long = .{ .dest = v2, .left = v0, .right = v1 } });
    try cfg.blocks.append(a, block);

    var prog = try lowerCFG(a, &cfg);
    defer prog.deinit();

    const insts = prog.blocks.items[0].instructions.items;
    
    // add_long lower should result in:
    //   MOV dest, left
    //   ADD dest, right
    try std.testing.expectEqual(@as(usize, 2), insts.len);
    try std.testing.expect(insts[0] == .mov);
    try std.testing.expect(insts[1] == .add);
    try std.testing.expectEqual(v2.reg, insts[0].mov.dest.vreg.reg);
    try std.testing.expectEqual(v0.reg, insts[0].mov.src.vreg.reg);
    try std.testing.expectEqual(v2.reg, insts[1].add.dest.vreg.reg);
    try std.testing.expectEqual(v1.reg, insts[1].add.src.vreg.reg);
}




