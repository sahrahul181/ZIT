const std = @import("std");
const ir = @import("ir");
const x86 = @import("x86");

pub const EmitterError = error{
    UnsupportedInstruction,
    UnsupportedOperandCombination,
};

fn regCode(reg: x86.PhysicalReg) u4 {
    return switch (reg) {
        .rax => 0,
        .rcx => 1,
        .rdx => 2,
        .rbx => 3,
        .rsi => 6,
        .rdi => 7,
        .r8 => 8,
        .r9 => 9,
        .r10 => 10,
        .r11 => 11,
        .r12 => 12,
        .r13 => 13,
        .r14 => 14,
        .r15 => 15,
        .xmm0 => 0,
        .xmm1 => 1,
        .xmm2 => 2,
        .xmm3 => 3,
        .xmm4 => 4,
        .xmm5 => 5,
        .xmm6 => 6,
        .xmm7 => 7,
        .xmm8 => 8,
        .xmm9 => 9,
        .xmm10 => 10,
        .xmm11 => 11,
        .xmm12 => 12,
        .xmm13 => 13,
        .xmm14 => 14,
        .xmm15 => 15,
    };
}

/// Helper to encode REX prefix byte.
fn makeRex(w: bool, reg: u4, rm: u4) u8 {
    var rex: u8 = 0x40;
    if (w) rex |= 0x08; // W bit (64-bit operand size)
    if (reg >= 8) rex |= 0x04; // R bit (registers 8-15)
    if (rm >= 8) rex |= 0x01; // B bit (registers 8-15)
    return rex;
}

/// Helper to encode ModR/M byte.
fn makeModRM(mod: u2, reg: u3, rm: u3) u8 {
    return (@as(u8, mod) << 6) | (@as(u8, reg) << 3) | rm;
}

/// A relocation entry for fixing up jump target offsets in the second pass.
const Relocation = struct {
    patch_offset: usize,
    target_block_id: usize,
    jump_type: enum { jmp, jcc },
};

/// Helper to scan all instructions and determine which callee-saved registers are used.
fn getUsedCalleeSavedRegs(allocator: std.mem.Allocator, program: *x86.MachineProgram) !std.ArrayList(x86.PhysicalReg) {
    var used = std.AutoHashMap(x86.PhysicalReg, void).init(allocator);
    defer used.deinit();
    
    for (program.blocks.items) |block| {
        for (block.instructions.items) |inst| {
            const checkOp = struct {
                fn run(u: *std.AutoHashMap(x86.PhysicalReg, void), op: x86.Operand) !void {
                    if (op == .reg) {
                        const r = op.reg;
                        const is_callee = switch (r) {
                            .rbx, .rsi, .rdi, .r12, .r13, .r14, .r15,
                            .xmm6, .xmm7, .xmm8, .xmm9, .xmm10, .xmm11, .xmm12, .xmm13, .xmm14, .xmm15 => true,
                            else => false,
                        };
                        if (is_callee) {
                            try u.put(r, {});
                        }
                    }
                }
            }.run;

            switch (inst) {
                .mov => |v| { try checkOp(&used, v.dest); try checkOp(&used, v.src); },
                .add => |v| { try checkOp(&used, v.dest); try checkOp(&used, v.src); },
                .sub => |v| { try checkOp(&used, v.dest); try checkOp(&used, v.src); },
                .imul => |v| { try checkOp(&used, v.dest); try checkOp(&used, v.src); },
                .idiv => |v| { try checkOp(&used, v.dest); try checkOp(&used, v.rem); try checkOp(&used, v.src); },
                .irem => |v| { try checkOp(&used, v.dest); try checkOp(&used, v.rem); try checkOp(&used, v.src); },
                .neg => |v| { try checkOp(&used, v.dest); },
                .and_op => |v| { try checkOp(&used, v.dest); try checkOp(&used, v.src); },
                .or_op => |v| { try checkOp(&used, v.dest); try checkOp(&used, v.src); },
                .xor_op => |v| { try checkOp(&used, v.dest); try checkOp(&used, v.src); },
                .shl => |v| { try checkOp(&used, v.dest); try checkOp(&used, v.src); },
                .shr => |v| { try checkOp(&used, v.dest); try checkOp(&used, v.src); },
                .ushr => |v| { try checkOp(&used, v.dest); try checkOp(&used, v.src); },
                .cmp => |v| { try checkOp(&used, v.left); try checkOp(&used, v.right); },
                .test_op => |v| { try checkOp(&used, v.left); try checkOp(&used, v.right); },
                .addss => |v| { try checkOp(&used, v.dest); try checkOp(&used, v.src); },
                .subss => |v| { try checkOp(&used, v.dest); try checkOp(&used, v.src); },
                .mulss => |v| { try checkOp(&used, v.dest); try checkOp(&used, v.src); },
                .divss => |v| { try checkOp(&used, v.dest); try checkOp(&used, v.src); },
                .movss => |v| { try checkOp(&used, v.dest); try checkOp(&used, v.src); },
                .addsd => |v| { try checkOp(&used, v.dest); try checkOp(&used, v.src); },
                .subsd => |v| { try checkOp(&used, v.dest); try checkOp(&used, v.src); },
                .mulsd => |v| { try checkOp(&used, v.dest); try checkOp(&used, v.src); },
                .divsd => |v| { try checkOp(&used, v.dest); try checkOp(&used, v.src); },
                .movsd => |v| { try checkOp(&used, v.dest); try checkOp(&used, v.src); },
                .ret => |v| { if (v) |op| try checkOp(&used, op); },
                .call => |v| { if (v.dest) |op| try checkOp(&used, op); },
                .not => |v| { try checkOp(&used, v.dest); },
                .negss => |v| { try checkOp(&used, v.dest); },
                .negsd => |v| { try checkOp(&used, v.dest); },
                .movsxd => |v| { try checkOp(&used, v.dest); try checkOp(&used, v.src); },
                .movsx8 => |v| { try checkOp(&used, v.dest); try checkOp(&used, v.src); },
                .movsx16 => |v| { try checkOp(&used, v.dest); try checkOp(&used, v.src); },
                .movzx16 => |v| { try checkOp(&used, v.dest); try checkOp(&used, v.src); },
                .cvtsi2ss => |v| { try checkOp(&used, v.dest); try checkOp(&used, v.src); },
                .cvtsi2sd => |v| { try checkOp(&used, v.dest); try checkOp(&used, v.src); },
                .cvttss2si => |v| { try checkOp(&used, v.dest); try checkOp(&used, v.src); },
                .cvttsd2si => |v| { try checkOp(&used, v.dest); try checkOp(&used, v.src); },
                .cvtss2sd => |v| { try checkOp(&used, v.dest); try checkOp(&used, v.src); },
                .cvtsd2ss => |v| { try checkOp(&used, v.dest); try checkOp(&used, v.src); },
                .frem32 => |v| { try checkOp(&used, v.dest); try checkOp(&used, v.src); },
                .frem64 => |v| { try checkOp(&used, v.dest); try checkOp(&used, v.src); },
                .cmp3 => |v| { try checkOp(&used, v.dest); try checkOp(&used, v.left); try checkOp(&used, v.right); },
                else => {},
            }
        }
    }

    var list = std.ArrayList(x86.PhysicalReg).empty;
    var it = used.keyIterator();
    while (it.next()) |r| {
        try list.append(allocator, r.*);
    }
    return list;
}

pub fn emitProgram(allocator: std.mem.Allocator, program: *x86.MachineProgram) ![]u8 {
    var raw_code = std.ArrayList(u8).empty;
    errdefer raw_code.deinit(allocator);

    var raw_relocations = std.ArrayList(Relocation).empty;
    defer raw_relocations.deinit(allocator);

    const CodeWriter = struct {
        buf: *std.ArrayList(u8),
        alloc: std.mem.Allocator,
        items: []u8 = &.{},

        fn updateItems(self: *@This()) void {
            self.items = self.buf.items;
        }
        fn append(self: *@This(), val: u8) !void {
            try self.buf.append(self.alloc, val);
            self.updateItems();
        }
        fn appendSlice(self: *@This(), slice: []const u8) !void {
            try self.buf.appendSlice(self.alloc, slice);
            self.updateItems();
        }
        fn toOwnedSlice(self: *@This()) ![]u8 {
            return self.buf.toOwnedSlice(self.alloc);
        }
    };

    const RelocWriter = struct {
        buf: *std.ArrayList(Relocation),
        alloc: std.mem.Allocator,
        items: []Relocation = &.{},

        fn updateItems(self: *@This()) void {
            self.items = self.buf.items;
        }
        fn append(self: *@This(), val: Relocation) !void {
            try self.buf.append(self.alloc, val);
            self.updateItems();
        }
    };

    const emitPush = struct {
        fn run(c: *CodeWriter, reg: x86.PhysicalReg) !void {
            const code_num = regCode(reg);
            if (code_num >= 8) {
                try c.append(0x41); // REX.B
                try c.append(0x50 + @as(u8, @truncate(code_num - 8)));
            } else {
                try c.append(0x50 + @as(u8, @truncate(code_num)));
            }
        }
    }.run;

    const emitPop = struct {
        fn run(c: *CodeWriter, reg: x86.PhysicalReg) !void {
            const code_num = regCode(reg);
            if (code_num >= 8) {
                try c.append(0x41); // REX.B
                try c.append(0x58 + @as(u8, @truncate(code_num - 8)));
            } else {
                try c.append(0x58 + @as(u8, @truncate(code_num)));
            }
        }
    }.run;

    const emitSubRsp = struct {
        fn run(c: *CodeWriter, val: i32) !void {
            if (val == 0) return;
            try c.append(0x48);
            if (val >= -128 and val <= 127) {
                try c.append(0x83);
                try c.append(0xEC);
                try c.append(@as(u8, @bitCast(@as(i8, @truncate(val)))));
            } else {
                try c.append(0x81);
                try c.append(0xEC);
                var bytes: [4]u8 = undefined;
                std.mem.writeInt(i32, &bytes, val, .little);
                try c.appendSlice(&bytes);
            }
        }
    }.run;

    const emitAddRsp = struct {
        fn run(c: *CodeWriter, val: i32) !void {
            if (val == 0) return;
            try c.append(0x48);
            if (val >= -128 and val <= 127) {
                try c.append(0x83);
                try c.append(0xC4);
                try c.append(@as(u8, @bitCast(@as(i8, @truncate(val)))));
            } else {
                try c.append(0x81);
                try c.append(0xC4);
                var bytes: [4]u8 = undefined;
                std.mem.writeInt(i32, &bytes, val, .little);
                try c.appendSlice(&bytes);
            }
        }
    }.run;

    const emitSaveXmm = struct {
        fn run(c: *CodeWriter, reg: x86.PhysicalReg, offset: i32) !void {
            const r = regCode(reg);
            const rex = makeRex(false, r, 4); // RSP is 4
            if (rex != 0x40) try c.append(rex);
            try c.append(0x0F);
            try c.append(0x11);
            if (offset >= -128 and offset <= 127) {
                try c.append(makeModRM(0b01, @as(u3, @truncate(r)), 4));
                try c.append(0x24);
                try c.append(@as(u8, @bitCast(@as(i8, @truncate(offset)))));
            } else {
                try c.append(makeModRM(0b10, @as(u3, @truncate(r)), 4));
                try c.append(0x24);
                var bytes: [4]u8 = undefined;
                std.mem.writeInt(i32, &bytes, offset, .little);
                try c.appendSlice(&bytes);
            }
        }
    }.run;

    const emitRestoreXmm = struct {
        fn run(c: *CodeWriter, reg: x86.PhysicalReg, offset: i32) !void {
            const r = regCode(reg);
            const rex = makeRex(false, r, 4);
            if (rex != 0x40) try c.append(rex);
            try c.append(0x0F);
            try c.append(0x10);
            if (offset >= -128 and offset <= 127) {
                try c.append(makeModRM(0b01, @as(u3, @truncate(r)), 4));
                try c.append(0x24);
                try c.append(@as(u8, @bitCast(@as(i8, @truncate(offset)))));
            } else {
                try c.append(makeModRM(0b10, @as(u3, @truncate(r)), 4));
                try c.append(0x24);
                var bytes: [4]u8 = undefined;
                std.mem.writeInt(i32, &bytes, offset, .little);
                try c.appendSlice(&bytes);
            }
        }
    }.run;

    // MOV r64, imm32 (sign-extended). Always 7 bytes (REX.W C7 /0 id) — the
    // fixed size matters for the hand-computed rel8 jumps in cmp3.
    const emitMovRegImm32 = struct {
        fn run(c: *CodeWriter, reg: x86.PhysicalReg, val: i32) !void {
            const d = regCode(reg);
            try c.append(makeRex(true, 0, d));
            try c.append(0xC7);
            try c.append(makeModRM(0b11, 0, @as(u3, @truncate(d))));
            var bytes: [4]u8 = undefined;
            std.mem.writeInt(i32, &bytes, val, .little);
            try c.appendSlice(&bytes);
        }
    }.run;

    var code = CodeWriter{ .buf = &raw_code, .alloc = allocator };
    code.updateItems();

    var relocations = RelocWriter{ .buf = &raw_relocations, .alloc = allocator };
    relocations.updateItems();

    // Map from block ID -> byte offset in final code buffer.
    var block_offsets = std.AutoHashMap(usize, usize).init(allocator);
    defer block_offsets.deinit();

    var callee_saved = try getUsedCalleeSavedRegs(allocator, program);
    defer callee_saved.deinit(allocator);

    var gpr_saved = std.ArrayList(x86.PhysicalReg).empty;
    defer gpr_saved.deinit(allocator);
    var xmm_saved = std.ArrayList(x86.PhysicalReg).empty;
    defer xmm_saved.deinit(allocator);

    for (callee_saved.items) |r| {
        if (std.mem.startsWith(u8, r.name(), "xmm")) {
            try xmm_saved.append(allocator, r);
        } else {
            try gpr_saved.append(allocator, r);
        }
    }
    
    // Establish RBP frame pointer
    try code.append(0x55); // push rbp
    try code.appendSlice(&[_]u8{ 0x48, 0x89, 0xE5 }); // mov rbp, rsp

    // Emit pushes for callee-saved GPRs
    for (gpr_saved.items) |r| {
        try emitPush(&code, r);
    }

    // Save callee-saved XMMs to stack
    const xmm_space = @as(i32, @intCast(xmm_saved.items.len)) * 16;
    if (xmm_space > 0) {
        try emitSubRsp(&code, xmm_space);
        for (xmm_saved.items, 0..) |r, idx| {
            try emitSaveXmm(&code, r, @as(i32, @intCast(idx)) * 16);
        }
    }

    // Pass 1: Emit instructions and record label offsets and relocation sites.
    for (program.blocks.items) |block| {
        try block_offsets.put(block.id, code.items.len);

        for (block.instructions.items) |inst| {
            switch (inst) {
                // ---- Data movement ----
                .mov => |v| {
                    if (v.dest == .reg and (v.src == .imm or v.src == .imm64)) {
                        if (std.mem.startsWith(u8, v.dest.reg.name(), "xmm")) {
                            // Can only load imm 0 to XMM using PXOR/XORPD
                            const val: i64 = switch (v.src) {
                                .imm => |imm| imm,
                                .imm64 => |imm| @as(i64, @bitCast(imm)),
                                else => return EmitterError.UnsupportedOperandCombination,
                            };
                            if (val == 0) {
                                const d = regCode(v.dest.reg);
                                const rex = makeRex(false, d, d);
                                try code.append(0x66);
                                if (rex != 0x40) try code.append(rex);
                                try code.append(0x0F);
                                try code.append(0x57); // XORPD
                                try code.append(makeModRM(0b11, @as(u3, @truncate(d)), @as(u3, @truncate(d))));
                            } else {
                                return EmitterError.UnsupportedOperandCombination;
                            }
                        } else {
                            // MOV r64, imm32/imm64
                            const d = regCode(v.dest.reg);
                            const rex = makeRex(true, 0, d);
                            try code.append(rex);
                            try code.append(0xB8 + @as(u8, @intCast(d & 7)));
                            // We support 64-bit constants here (imm64 or imm)
                            const val: u64 = switch (v.src) {
                                .imm => |imm| @as(u64, @bitCast(@as(i64, imm))),
                                .imm64 => |imm| @as(u64, @bitCast(imm)),
                                else => unreachable,
                            };
                            var bytes: [8]u8 = undefined;
                            std.mem.writeInt(u64, &bytes, val, .little);
                            try code.appendSlice(&bytes);
                        }
                    } else if (v.dest == .reg and v.src == .reg) {
                        const dest_xmm = std.mem.startsWith(u8, v.dest.reg.name(), "xmm");
                        const src_xmm = std.mem.startsWith(u8, v.src.reg.name(), "xmm");
                        if (dest_xmm and !src_xmm) {
                            // movq xmm, r64
                            const d = regCode(v.dest.reg);
                            const s = regCode(v.src.reg);
                            try code.append(0x66);
                            const rex = makeRex(true, d, s);
                            try code.append(rex);
                            try code.append(0x0F);
                            try code.append(0x6E);
                            try code.append(makeModRM(0b11, @as(u3, @truncate(d)), @as(u3, @truncate(s))));
                        } else if (!dest_xmm and src_xmm) {
                            // movq r64, xmm
                            const d = regCode(v.dest.reg);
                            const s = regCode(v.src.reg);
                            try code.append(0x66);
                            const rex = makeRex(true, s, d);
                            try code.append(rex);
                            try code.append(0x0F);
                            try code.append(0x7E);
                            try code.append(makeModRM(0b11, @as(u3, @truncate(s)), @as(u3, @truncate(d))));
                        } else if (dest_xmm and src_xmm) {
                            // movsd xmm, xmm
                            const d = regCode(v.dest.reg);
                            const s = regCode(v.src.reg);
                            try code.append(0xF2);
                            const rex = makeRex(false, d, s);
                            if (rex != 0x40) try code.append(rex);
                            try code.append(0x0F);
                            try code.append(0x10);
                            try code.append(makeModRM(0b11, @as(u3, @truncate(d)), @as(u3, @truncate(s))));
                        } else {
                            // MOV r64, r64
                            const d = regCode(v.dest.reg);
                            const s = regCode(v.src.reg);
                            const rex = makeRex(true, s, d);
                            try code.append(rex);
                            try code.append(0x89);
                            try code.append(makeModRM(0b11, @as(u3, @truncate(s)), @as(u3, @truncate(d))));
                        }
                    } else if (v.dest == .reg and v.src == .stack) {
                        // MOV r64, [rbp - offset]
                        const d = regCode(v.dest.reg);
                        const offset = v.src.stack;
                        const rex = makeRex(true, d, 5); // RBP is code 5
                        try code.append(rex);
                        try code.append(0x8B); // Load
                        // Use mod 01 for 8-bit sign-extended disp, mod 10 for 32-bit disp
                        if (offset >= -128 and offset <= 127) {
                            try code.append(makeModRM(0b01, @as(u3, @truncate(d)), 5));
                            try code.append(@as(u8, @bitCast(@as(i8, @truncate(-offset)))));
                        } else {
                            try code.append(makeModRM(0b10, @as(u3, @truncate(d)), 5));
                            var bytes: [4]u8 = undefined;
                            std.mem.writeInt(i32, &bytes, -offset, .little);
                            try code.appendSlice(&bytes);
                        }
                    } else if (v.dest == .stack and v.src == .reg) {
                        // MOV [rbp - offset], r64
                        const s = regCode(v.src.reg);
                        const offset = v.dest.stack;
                        const rex = makeRex(true, s, 5);
                        try code.append(rex);
                        try code.append(0x89); // Store
                        if (offset >= -128 and offset <= 127) {
                            try code.append(makeModRM(0b01, @as(u3, @truncate(s)), 5));
                            try code.append(@as(u8, @bitCast(@as(i8, @truncate(-offset)))));
                        } else {
                            try code.append(makeModRM(0b10, @as(u3, @truncate(s)), 5));
                            var bytes: [4]u8 = undefined;
                            std.mem.writeInt(i32, &bytes, -offset, .little);
                            try code.appendSlice(&bytes);
                        }
                    } else {
                        return EmitterError.UnsupportedOperandCombination;
                    }
                },

                // ---- Integer Arithmetic ----
                .add => |v| {
                    if (v.dest == .reg and v.src == .reg) {
                        const d = regCode(v.dest.reg);
                        const s = regCode(v.src.reg);
                        const rex = makeRex(true, s, d);
                        try code.append(rex);
                        try code.append(0x01);
                        try code.append(makeModRM(0b11, @as(u3, @truncate(s)), @as(u3, @truncate(d))));
                    } else if (v.dest == .reg and v.src == .imm) {
                        const d = regCode(v.dest.reg);
                        const val = v.src.imm;
                        const rex = makeRex(true, 0, d);
                        try code.append(rex);
                        if (val >= -128 and val <= 127) {
                            try code.append(0x83); // ADD r/m64, imm8
                            try code.append(makeModRM(0b11, 0, @as(u3, @truncate(d))));
                            try code.append(@as(u8, @bitCast(@as(i8, @truncate(val)))));
                        } else {
                            try code.append(0x81); // ADD r/m64, imm32
                            try code.append(makeModRM(0b11, 0, @as(u3, @truncate(d))));
                            var bytes: [4]u8 = undefined;
                            std.mem.writeInt(i32, &bytes, val, .little);
                            try code.appendSlice(&bytes);
                        }
                    } else {
                        return EmitterError.UnsupportedOperandCombination;
                    }
                },
                .sub => |v| {
                    if (v.dest == .reg and v.src == .reg) {
                        const d = regCode(v.dest.reg);
                        const s = regCode(v.src.reg);
                        const rex = makeRex(true, s, d);
                        try code.append(rex);
                        try code.append(0x29);
                        try code.append(makeModRM(0b11, @as(u3, @truncate(s)), @as(u3, @truncate(d))));
                    } else if (v.dest == .reg and v.src == .imm) {
                        const d = regCode(v.dest.reg);
                        const val = v.src.imm;
                        const rex = makeRex(true, 0, d);
                        try code.append(rex);
                        if (val >= -128 and val <= 127) {
                            try code.append(0x83);
                            try code.append(makeModRM(0b11, 5, @as(u3, @truncate(d)))); // SUB is /5
                            try code.append(@as(u8, @bitCast(@as(i8, @truncate(val)))));
                        } else {
                            try code.append(0x81);
                            try code.append(makeModRM(0b11, 5, @as(u3, @truncate(d))));
                            var bytes: [4]u8 = undefined;
                            std.mem.writeInt(i32, &bytes, val, .little);
                            try code.appendSlice(&bytes);
                        }
                    } else {
                        return EmitterError.UnsupportedOperandCombination;
                    }
                },
                .imul => |v| {
                    if (v.dest == .reg and v.src == .reg) {
                        // IMUL r64, r64 -> 0F AF /r
                        const d = regCode(v.dest.reg);
                        const s = regCode(v.src.reg);
                        const rex = makeRex(true, d, s);
                        try code.append(rex);
                        try code.append(0x0F);
                        try code.append(0xAF);
                        try code.append(makeModRM(0b11, @as(u3, @truncate(d)), @as(u3, @truncate(s))));
                    } else {
                        return EmitterError.UnsupportedOperandCombination;
                    }
                },
                .neg => |v| {
                    if (v.dest == .reg) {
                        // NEG r64 -> REX.W F7 /3
                        const d = regCode(v.dest.reg);
                        const rex = makeRex(true, 0, d);
                        try code.append(rex);
                        try code.append(0xF7);
                        try code.append(makeModRM(0b11, 3, @as(u3, @truncate(d))));
                    } else {
                        return EmitterError.UnsupportedOperandCombination;
                    }
                },
                .not => |v| {
                    if (v.dest == .reg) {
                        // NOT r64 -> REX.W F7 /2
                        const d = regCode(v.dest.reg);
                        try code.append(makeRex(true, 0, d));
                        try code.append(0xF7);
                        try code.append(makeModRM(0b11, 2, @as(u3, @truncate(d))));
                    } else {
                        return EmitterError.UnsupportedOperandCombination;
                    }
                },

                // ---- Sign/zero extensions ----
                .movsxd => |v| {
                    if (v.dest == .reg and v.src == .reg) {
                        // MOVSXD r64, r/m32 -> REX.W 63 /r
                        const d = regCode(v.dest.reg);
                        const s = regCode(v.src.reg);
                        try code.append(makeRex(true, d, s));
                        try code.append(0x63);
                        try code.append(makeModRM(0b11, @as(u3, @truncate(d)), @as(u3, @truncate(s))));
                    } else {
                        return EmitterError.UnsupportedOperandCombination;
                    }
                },
                .movsx8 => |v| {
                    if (v.dest == .reg and v.src == .reg) {
                        // MOVSX r64, r/m8 -> REX.W 0F BE /r
                        const d = regCode(v.dest.reg);
                        const s = regCode(v.src.reg);
                        try code.append(makeRex(true, d, s));
                        try code.append(0x0F);
                        try code.append(0xBE);
                        try code.append(makeModRM(0b11, @as(u3, @truncate(d)), @as(u3, @truncate(s))));
                    } else {
                        return EmitterError.UnsupportedOperandCombination;
                    }
                },
                .movsx16 => |v| {
                    if (v.dest == .reg and v.src == .reg) {
                        // MOVSX r64, r/m16 -> REX.W 0F BF /r
                        const d = regCode(v.dest.reg);
                        const s = regCode(v.src.reg);
                        try code.append(makeRex(true, d, s));
                        try code.append(0x0F);
                        try code.append(0xBF);
                        try code.append(makeModRM(0b11, @as(u3, @truncate(d)), @as(u3, @truncate(s))));
                    } else {
                        return EmitterError.UnsupportedOperandCombination;
                    }
                },
                .movzx16 => |v| {
                    if (v.dest == .reg and v.src == .reg) {
                        // MOVZX r64, r/m16 -> REX.W 0F B7 /r
                        const d = regCode(v.dest.reg);
                        const s = regCode(v.src.reg);
                        try code.append(makeRex(true, d, s));
                        try code.append(0x0F);
                        try code.append(0xB7);
                        try code.append(makeModRM(0b11, @as(u3, @truncate(d)), @as(u3, @truncate(s))));
                    } else {
                        return EmitterError.UnsupportedOperandCombination;
                    }
                },

                // ---- Int ↔ float conversions ----
                .cvtsi2ss, .cvtsi2sd, .cvttss2si, .cvttsd2si => {
                    const parts = switch (inst) {
                        .cvtsi2ss => .{ inst.cvtsi2ss.dest, inst.cvtsi2ss.src, @as(u8, 0xF3), @as(u8, 0x2A) },
                        .cvtsi2sd => .{ inst.cvtsi2sd.dest, inst.cvtsi2sd.src, @as(u8, 0xF2), @as(u8, 0x2A) },
                        .cvttss2si => .{ inst.cvttss2si.dest, inst.cvttss2si.src, @as(u8, 0xF3), @as(u8, 0x2C) },
                        .cvttsd2si => .{ inst.cvttsd2si.dest, inst.cvttsd2si.src, @as(u8, 0xF2), @as(u8, 0x2C) },
                        else => unreachable,
                    };
                    const dest_op = parts[0];
                    const src_op = parts[1];
                    if (dest_op == .reg and src_op == .reg) {
                        // prefix REX.W 0F 2A/2C /r (dest in reg field, src in rm)
                        const d = regCode(dest_op.reg);
                        const s = regCode(src_op.reg);
                        try code.append(parts[2]);
                        try code.append(makeRex(true, d, s));
                        try code.append(0x0F);
                        try code.append(parts[3]);
                        try code.append(makeModRM(0b11, @as(u3, @truncate(d)), @as(u3, @truncate(s))));
                    } else {
                        return EmitterError.UnsupportedOperandCombination;
                    }
                },
                .cvtss2sd, .cvtsd2ss => {
                    const parts = switch (inst) {
                        .cvtss2sd => .{ inst.cvtss2sd.dest, inst.cvtss2sd.src, @as(u8, 0xF3) },
                        .cvtsd2ss => .{ inst.cvtsd2ss.dest, inst.cvtsd2ss.src, @as(u8, 0xF2) },
                        else => unreachable,
                    };
                    const dest_op = parts[0];
                    const src_op = parts[1];
                    if (dest_op == .reg and src_op == .reg) {
                        // prefix 0F 5A /r
                        const d = regCode(dest_op.reg);
                        const s = regCode(src_op.reg);
                        try code.append(parts[2]);
                        const rex = makeRex(false, d, s);
                        if (rex != 0x40) try code.append(rex);
                        try code.append(0x0F);
                        try code.append(0x5A);
                        try code.append(makeModRM(0b11, @as(u3, @truncate(d)), @as(u3, @truncate(s))));
                    } else {
                        return EmitterError.UnsupportedOperandCombination;
                    }
                },

                // ---- SSE negation: flip the sign bit via XORPS/XORPD with a
                //      stack-materialized mask (no scratch register needed) ----
                .negss => |v| {
                    if (v.dest == .reg) {
                        const d = regCode(v.dest.reg);
                        try emitSubRsp(&code, 16);
                        // MOV dword [rsp], 0x80000000  -> C7 04 24 imm32
                        try code.appendSlice(&[_]u8{ 0xC7, 0x04, 0x24, 0x00, 0x00, 0x00, 0x80 });
                        // XORPS dest, [rsp] -> 0F 57 /r (mod=00, rm=100 + SIB rsp)
                        const rex = makeRex(false, d, 4);
                        if (rex != 0x40) try code.append(rex);
                        try code.append(0x0F);
                        try code.append(0x57);
                        try code.append(makeModRM(0b00, @as(u3, @truncate(d)), 4));
                        try code.append(0x24);
                        try emitAddRsp(&code, 16);
                    } else {
                        return EmitterError.UnsupportedOperandCombination;
                    }
                },
                .negsd => |v| {
                    if (v.dest == .reg) {
                        const d = regCode(v.dest.reg);
                        try emitSubRsp(&code, 16);
                        // MOV dword [rsp], 0        -> C7 04 24 imm32
                        try code.appendSlice(&[_]u8{ 0xC7, 0x04, 0x24, 0x00, 0x00, 0x00, 0x00 });
                        // MOV dword [rsp+4], 0x80000000 -> C7 44 24 04 imm32
                        try code.appendSlice(&[_]u8{ 0xC7, 0x44, 0x24, 0x04, 0x00, 0x00, 0x00, 0x80 });
                        // XORPD dest, [rsp] -> 66 0F 57 /r
                        try code.append(0x66);
                        const rex = makeRex(false, d, 4);
                        if (rex != 0x40) try code.append(rex);
                        try code.append(0x0F);
                        try code.append(0x57);
                        try code.append(makeModRM(0b00, @as(u3, @truncate(d)), 4));
                        try code.append(0x24);
                        try emitAddRsp(&code, 16);
                    } else {
                        return EmitterError.UnsupportedOperandCombination;
                    }
                },

                // ---- Three-way compare: dest = -1/0/1 (branchy but self-contained) ----
                .cmp3 => |v| {
                    if (v.dest != .reg or v.left != .reg or v.right != .reg)
                        return EmitterError.UnsupportedOperandCombination;
                    const dest_reg = v.dest.reg;
                    const l = regCode(v.left.reg);
                    const r = regCode(v.right.reg);

                    if (v.kind == .cmp_long) {
                        // mov dest, 0            (7 bytes, flags untouched)
                        // cmp left, right        (REX.W 3B /r, 3 bytes)
                        // je  end (+16)
                        // mov dest, 1            (7)
                        // jg  end (+7)
                        // mov dest, -1           (7)
                        try emitMovRegImm32(&code, dest_reg, 0);
                        try code.append(makeRex(true, l, r));
                        try code.append(0x3B);
                        try code.append(makeModRM(0b11, @as(u3, @truncate(l)), @as(u3, @truncate(r))));
                        try code.appendSlice(&[_]u8{ 0x74, 16 }); // JE rel8
                        try emitMovRegImm32(&code, dest_reg, 1);
                        try code.appendSlice(&[_]u8{ 0x7F, 7 }); // JG rel8
                        try emitMovRegImm32(&code, dest_reg, -1);
                    } else {
                        // Dalvik NaN bias: cmpl → -1 on NaN, cmpg → +1 on NaN.
                        // mov dest, bias
                        // ucomiss/ucomisd left, right   (unordered → ZF=PF=CF=1)
                        // jp  end (+25)   ; NaN → keep bias
                        // mov dest, 1
                        // ja  end (+16)   ; CF=0,ZF=0 → left > right
                        // mov dest, 0
                        // je  end (+7)    ; equal
                        // mov dest, -1    ; less
                        const bias: i32 = switch (v.kind) {
                            .cmpg_float, .cmpg_double => 1,
                            else => -1,
                        };
                        const is_double = v.kind == .cmpl_double or v.kind == .cmpg_double;
                        try emitMovRegImm32(&code, dest_reg, bias);
                        if (is_double) try code.append(0x66);
                        const rex = makeRex(false, l, r);
                        if (rex != 0x40) try code.append(rex);
                        try code.append(0x0F);
                        try code.append(0x2E); // UCOMISS/UCOMISD
                        try code.append(makeModRM(0b11, @as(u3, @truncate(l)), @as(u3, @truncate(r))));
                        try code.appendSlice(&[_]u8{ 0x7A, 25 }); // JP rel8
                        try emitMovRegImm32(&code, dest_reg, 1);
                        try code.appendSlice(&[_]u8{ 0x77, 16 }); // JA rel8
                        try emitMovRegImm32(&code, dest_reg, 0);
                        try code.appendSlice(&[_]u8{ 0x74, 7 }); // JE rel8
                        try emitMovRegImm32(&code, dest_reg, -1);
                    }
                },

                // ---- SSE Single-Precision Float ----
                .addss => |v| {
                    if (v.dest == .reg and v.src == .reg) {
                        const d = regCode(v.dest.reg);
                        const s = regCode(v.src.reg);
                        try code.append(0xF3); // prefix
                        const rex = makeRex(false, d, s);
                        if (rex != 0x40) try code.append(rex);
                        try code.append(0x0F);
                        try code.append(0x58);
                        try code.append(makeModRM(0b11, @as(u3, @truncate(d)), @as(u3, @truncate(s))));
                    } else {
                        return EmitterError.UnsupportedOperandCombination;
                    }
                },
                .subss => |v| {
                    if (v.dest == .reg and v.src == .reg) {
                        const d = regCode(v.dest.reg);
                        const s = regCode(v.src.reg);
                        try code.append(0xF3);
                        const rex = makeRex(false, d, s);
                        if (rex != 0x40) try code.append(rex);
                        try code.append(0x0F);
                        try code.append(0x5C);
                        try code.append(makeModRM(0b11, @as(u3, @truncate(d)), @as(u3, @truncate(s))));
                    } else {
                        return EmitterError.UnsupportedOperandCombination;
                    }
                },
                .mulss => |v| {
                    if (v.dest == .reg and v.src == .reg) {
                        const d = regCode(v.dest.reg);
                        const s = regCode(v.src.reg);
                        try code.append(0xF3);
                        const rex = makeRex(false, d, s);
                        if (rex != 0x40) try code.append(rex);
                        try code.append(0x0F);
                        try code.append(0x59);
                        try code.append(makeModRM(0b11, @as(u3, @truncate(d)), @as(u3, @truncate(s))));
                    } else {
                        return EmitterError.UnsupportedOperandCombination;
                    }
                },
                .divss => |v| {
                    if (v.dest == .reg and v.src == .reg) {
                        const d = regCode(v.dest.reg);
                        const s = regCode(v.src.reg);
                        try code.append(0xF3);
                        const rex = makeRex(false, d, s);
                        if (rex != 0x40) try code.append(rex);
                        try code.append(0x0F);
                        try code.append(0x5E);
                        try code.append(makeModRM(0b11, @as(u3, @truncate(d)), @as(u3, @truncate(s))));
                    } else {
                        return EmitterError.UnsupportedOperandCombination;
                    }
                },
                .movss => |v| {
                    if (v.dest == .reg and v.src == .reg) {
                        const d = regCode(v.dest.reg);
                        const s = regCode(v.src.reg);
                        try code.append(0xF3);
                        const rex = makeRex(false, d, s);
                        if (rex != 0x40) try code.append(rex);
                        try code.append(0x0F);
                        try code.append(0x10);
                        try code.append(makeModRM(0b11, @as(u3, @truncate(d)), @as(u3, @truncate(s))));
                    } else {
                        return EmitterError.UnsupportedOperandCombination;
                    }
                },

                // ---- SSE Double-Precision Float ----
                .addsd => |v| {
                    if (v.dest == .reg and v.src == .reg) {
                        const d = regCode(v.dest.reg);
                        const s = regCode(v.src.reg);
                        try code.append(0xF2);
                        const rex = makeRex(false, d, s);
                        if (rex != 0x40) try code.append(rex);
                        try code.append(0x0F);
                        try code.append(0x58);
                        try code.append(makeModRM(0b11, @as(u3, @truncate(d)), @as(u3, @truncate(s))));
                    } else {
                        return EmitterError.UnsupportedOperandCombination;
                    }
                },
                .subsd => |v| {
                    if (v.dest == .reg and v.src == .reg) {
                        const d = regCode(v.dest.reg);
                        const s = regCode(v.src.reg);
                        try code.append(0xF2);
                        const rex = makeRex(false, d, s);
                        if (rex != 0x40) try code.append(rex);
                        try code.append(0x0F);
                        try code.append(0x5C);
                        try code.append(makeModRM(0b11, @as(u3, @truncate(d)), @as(u3, @truncate(s))));
                    } else {
                        return EmitterError.UnsupportedOperandCombination;
                    }
                },
                .mulsd => |v| {
                    if (v.dest == .reg and v.src == .reg) {
                        const d = regCode(v.dest.reg);
                        const s = regCode(v.src.reg);
                        try code.append(0xF2);
                        const rex = makeRex(false, d, s);
                        if (rex != 0x40) try code.append(rex);
                        try code.append(0x0F);
                        try code.append(0x59);
                        try code.append(makeModRM(0b11, @as(u3, @truncate(d)), @as(u3, @truncate(s))));
                    } else {
                        return EmitterError.UnsupportedOperandCombination;
                    }
                },
                .divsd => |v| {
                    if (v.dest == .reg and v.src == .reg) {
                        const d = regCode(v.dest.reg);
                        const s = regCode(v.src.reg);
                        try code.append(0xF2);
                        const rex = makeRex(false, d, s);
                        if (rex != 0x40) try code.append(rex);
                        try code.append(0x0F);
                        try code.append(0x5E);
                        try code.append(makeModRM(0b11, @as(u3, @truncate(d)), @as(u3, @truncate(s))));
                    } else {
                        return EmitterError.UnsupportedOperandCombination;
                    }
                },
                .movsd => |v| {
                    if (v.dest == .reg and v.src == .reg) {
                        const d = regCode(v.dest.reg);
                        const s = regCode(v.src.reg);
                        try code.append(0xF2);
                        const rex = makeRex(false, d, s);
                        if (rex != 0x40) try code.append(rex);
                        try code.append(0x0F);
                        try code.append(0x10);
                        try code.append(makeModRM(0b11, @as(u3, @truncate(d)), @as(u3, @truncate(s))));
                    } else {
                        return EmitterError.UnsupportedOperandCombination;
                    }
                },

                // ---- Bitwise ----
                .xor_op => |v| {
                    if (v.dest == .reg and v.src == .reg) {
                        const d = regCode(v.dest.reg);
                        const s = regCode(v.src.reg);
                        const rex = makeRex(true, s, d);
                        try code.append(rex);
                        try code.append(0x31);
                        try code.append(makeModRM(0b11, @as(u3, @truncate(s)), @as(u3, @truncate(d))));
                    } else if (v.dest == .reg and v.src == .imm) {
                        const d = regCode(v.dest.reg);
                        const val = v.src.imm;
                        try code.append(makeRex(true, 0, d));
                        if (val >= -128 and val <= 127) {
                            try code.append(0x83);
                            try code.append(makeModRM(0b11, 6, @as(u3, @truncate(d))));
                            try code.append(@as(u8, @bitCast(@as(i8, @truncate(val)))));
                        } else {
                            try code.append(0x81);
                            try code.append(makeModRM(0b11, 6, @as(u3, @truncate(d))));
                            var bytes: [4]u8 = undefined;
                            std.mem.writeInt(i32, &bytes, val, .little);
                            try code.appendSlice(&bytes);
                        }
                    } else {
                        return EmitterError.UnsupportedOperandCombination;
                    }
                },

                // ---- Bitwise (AND / OR) ----
                .and_op => |v| {
                    if (v.dest == .reg and v.src == .reg) {
                        // AND r/m64, r64 -> REX.W 21 /r
                        const d = regCode(v.dest.reg);
                        const s = regCode(v.src.reg);
                        try code.append(makeRex(true, s, d));
                        try code.append(0x21);
                        try code.append(makeModRM(0b11, @as(u3, @truncate(s)), @as(u3, @truncate(d))));
                    } else if (v.dest == .reg and v.src == .imm) {
                        // AND r/m64, imm -> REX.W 83 /4 ib  or  81 /4 id
                        const d = regCode(v.dest.reg);
                        const val = v.src.imm;
                        try code.append(makeRex(true, 0, d));
                        if (val >= -128 and val <= 127) {
                            try code.append(0x83);
                            try code.append(makeModRM(0b11, 4, @as(u3, @truncate(d))));
                            try code.append(@as(u8, @bitCast(@as(i8, @truncate(val)))));
                        } else {
                            try code.append(0x81);
                            try code.append(makeModRM(0b11, 4, @as(u3, @truncate(d))));
                            var bytes: [4]u8 = undefined;
                            std.mem.writeInt(i32, &bytes, val, .little);
                            try code.appendSlice(&bytes);
                        }
                    } else {
                        return EmitterError.UnsupportedOperandCombination;
                    }
                },
                .or_op => |v| {
                    if (v.dest == .reg and v.src == .reg) {
                        // OR r/m64, r64 -> REX.W 09 /r
                        const d = regCode(v.dest.reg);
                        const s = regCode(v.src.reg);
                        try code.append(makeRex(true, s, d));
                        try code.append(0x09);
                        try code.append(makeModRM(0b11, @as(u3, @truncate(s)), @as(u3, @truncate(d))));
                    } else if (v.dest == .reg and v.src == .imm) {
                        // OR r/m64, imm -> REX.W 83 /1 ib  or  81 /1 id
                        const d = regCode(v.dest.reg);
                        const val = v.src.imm;
                        try code.append(makeRex(true, 0, d));
                        if (val >= -128 and val <= 127) {
                            try code.append(0x83);
                            try code.append(makeModRM(0b11, 1, @as(u3, @truncate(d))));
                            try code.append(@as(u8, @bitCast(@as(i8, @truncate(val)))));
                        } else {
                            try code.append(0x81);
                            try code.append(makeModRM(0b11, 1, @as(u3, @truncate(d))));
                            var bytes: [4]u8 = undefined;
                            std.mem.writeInt(i32, &bytes, val, .little);
                            try code.appendSlice(&bytes);
                        }
                    } else {
                        return EmitterError.UnsupportedOperandCombination;
                    }
                },


                // ---- Shifts ----
                // Immediate count → C1 /r ib.  Register count must be in CL → D3 /r,
                // so the register form materializes MOV rcx, count first.  The RA pass
                // keeps RCX out of the general pool via the shift-count reservation.
                .shl, .shr, .ushr => {
                    const parts = switch (inst) {
                        .shl => .{ inst.shl.dest, inst.shl.src, @as(u3, 4) },  // /4 SHL
                        .shr => .{ inst.shr.dest, inst.shr.src, @as(u3, 7) },  // /7 SAR
                        .ushr => .{ inst.ushr.dest, inst.ushr.src, @as(u3, 5) }, // /5 SHR
                        else => unreachable,
                    };
                    const dest_op = parts[0];
                    const src_op = parts[1];
                    const ext = parts[2];
                    if (dest_op != .reg) return EmitterError.UnsupportedOperandCombination;
                    const d = regCode(dest_op.reg);
                    if (src_op == .imm) {
                        try code.append(makeRex(true, 0, d));
                        try code.append(0xC1);
                        try code.append(makeModRM(0b11, ext, @as(u3, @truncate(d))));
                        try code.append(@as(u8, @truncate(@as(u32, @bitCast(src_op.imm)) & 0x3f)));
                    } else if (src_op == .reg) {
                        // Register shift count MUST be in CL. RCX may hold a live value
                        // (it's allocatable / the 1st param reg), so preserve it: push
                        // rcx; mov cl-worth via full RCX; shift; pop rcx.
                        const s = regCode(src_op.reg);
                        const dest_is_rcx = (d == 1);
                        const src_is_rcx = (s == 1);
                        if (!src_is_rcx) {
                            try code.append(0x51); // push rcx
                            // MOV rcx, src (REX.W 89 /r, src in reg field, rcx=1 rm)
                            try code.append(makeRex(true, s, 1));
                            try code.append(0x89);
                            try code.append(makeModRM(0b11, @as(u3, @truncate(s)), 1));
                        }
                        // If dest is RCX we just overwrote it via push/mov; but dest==rcx
                        // with a register count is contradictory (dest and count share a
                        // reg) — the RA hint avoids this; treat as unsupported to be safe.
                        if (dest_is_rcx and !src_is_rcx) return EmitterError.UnsupportedOperandCombination;
                        // shift dest by CL: REX.W D3 /ext
                        try code.append(makeRex(true, 0, d));
                        try code.append(0xD3);
                        try code.append(makeModRM(0b11, ext, @as(u3, @truncate(d))));
                        if (!src_is_rcx) {
                            try code.append(0x59); // pop rcx
                        }
                    } else {
                        return EmitterError.UnsupportedOperandCombination;
                    }
                },

                // ---- Integer division / remainder ----
                // x86 IDIV divides RDX:RAX by the operand: quotient→RAX, remainder→RDX.
                // The RA pass excludes RAX and RDX from the pool, so they are free scratch.
                // idiv {dest,rem,src}: dest holds dividend on entry, receives quotient.
                // irem {dest,rem,src}: dest holds dividend on entry, rem receives remainder.
                .idiv, .irem => {
                    const is_rem = inst == .irem;
                    const dest_op = if (is_rem) inst.irem.dest else inst.idiv.dest;
                    const src_op = if (is_rem) inst.irem.src else inst.idiv.src;
                    const rem_op = if (is_rem) inst.irem.rem else inst.idiv.rem;
                    if (dest_op != .reg) return EmitterError.UnsupportedOperandCombination;

                    // MOV rax, dividend(dest)
                    {
                        const s = regCode(dest_op.reg);
                        if (s != 0) {
                            try code.append(makeRex(true, s, 0));
                            try code.append(0x89);
                            try code.append(makeModRM(0b11, @as(u3, @truncate(s)), 0));
                        }
                    }
                    // CQO  (sign-extend RAX into RDX:RAX) -> REX.W 99
                    try code.append(0x48);
                    try code.append(0x99);
                    // IDIV divisor
                    if (src_op == .reg) {
                        // IDIV r/m64 -> REX.W F7 /7
                        const s = regCode(src_op.reg);
                        try code.append(makeRex(true, 0, s));
                        try code.append(0xF7);
                        try code.append(makeModRM(0b11, 7, @as(u3, @truncate(s))));
                    } else if (src_op == .imm) {
                        // No IDIV imm form. Materialize the divisor into RCX, preserving
                        // whatever RCX held (it is allocatable), then divide by it.
                        try code.append(0x51); // push rcx
                        try emitMovRegImm32(&code, .rcx, src_op.imm);
                        try code.append(makeRex(true, 0, 1)); // rcx=1
                        try code.append(0xF7);
                        try code.append(makeModRM(0b11, 7, 1));
                        // Result is already in RAX(quot)/RDX(rem); restore RCX after we
                        // move the result out below. Defer the pop by emitting it now is
                        // wrong (would clobber flags-free RAX? no—pop doesn't touch RAX/RDX).
                        try code.append(0x59); // pop rcx
                    } else {
                        return EmitterError.UnsupportedOperandCombination;
                    }
                    // Move result out of RAX (quotient) or RDX (remainder)
                    if (is_rem) {
                        if (rem_op != .reg) return EmitterError.UnsupportedOperandCombination;
                        const r = regCode(rem_op.reg);
                        if (r != 2) { // RDX is 2
                            try code.append(makeRex(true, 2, r));
                            try code.append(0x89);
                            try code.append(makeModRM(0b11, 2, @as(u3, @truncate(r))));
                        }
                    } else {
                        const r = regCode(dest_op.reg);
                        if (r != 0) {
                            try code.append(makeRex(true, 0, r));
                            try code.append(0x89);
                            try code.append(makeModRM(0b11, 0, @as(u3, @truncate(r))));
                        }
                    }
                },

                // ---- Float remainder: dest = dest - trunc(dest/src)*src via SSE ----
                // Uses XMM0 (kept out of the XMM pool) as scratch; no runtime call.
                .frem32, .frem64 => {
                    const is64 = inst == .frem64;
                    const dest_op = if (is64) inst.frem64.dest else inst.frem32.dest;
                    const src_op = if (is64) inst.frem64.src else inst.frem32.src;
                    if (dest_op != .reg or src_op != .reg) return EmitterError.UnsupportedOperandCombination;
                    const d = regCode(dest_op.reg);
                    const s = regCode(src_op.reg);
                    const pfx: u8 = if (is64) 0xF2 else 0xF3;
                    const scratch: u4 = 0; // xmm0

                    // Preserve XMM0 (allocatable / float-return reg) on the stack.
                    const xmm0_is_operand = (d == 0 or s == 0);
                    if (!xmm0_is_operand) {
                        try emitSubRsp(&code, 16);
                        // movsd [rsp], xmm0 -> F2 0F 11 /r (mod=00 rm=100 SIB rsp)
                        try code.append(0xF2);
                        try code.append(0x0F); try code.append(0x11);
                        try code.append(makeModRM(0b00, 0, 4));
                        try code.append(0x24);
                    }

                    // movaps/movsd xmm0, dest    (copy dividend)
                    try code.append(pfx);
                    { const rex = makeRex(false, scratch, d); if (rex != 0x40) try code.append(rex); }
                    try code.append(0x0F); try code.append(0x10);
                    try code.append(makeModRM(0b11, scratch, @as(u3, @truncate(d))));
                    // divss/divsd xmm0, src
                    try code.append(pfx);
                    { const rex = makeRex(false, scratch, s); if (rex != 0x40) try code.append(rex); }
                    try code.append(0x0F); try code.append(0x5E);
                    try code.append(makeModRM(0b11, scratch, @as(u3, @truncate(s))));
                    // roundss/roundsd xmm0, xmm0, 3 (truncate toward zero) -> 66 0F 3A 0A/0B /r ib
                    try code.append(0x66);
                    { const rex = makeRex(false, scratch, scratch); if (rex != 0x40) try code.append(rex); }
                    try code.append(0x0F); try code.append(0x3A);
                    try code.append(if (is64) @as(u8, 0x0B) else @as(u8, 0x0A));
                    try code.append(makeModRM(0b11, scratch, scratch));
                    try code.append(0x03); // round-toward-zero
                    // mulss/mulsd xmm0, src
                    try code.append(pfx);
                    { const rex = makeRex(false, scratch, s); if (rex != 0x40) try code.append(rex); }
                    try code.append(0x0F); try code.append(0x59);
                    try code.append(makeModRM(0b11, scratch, @as(u3, @truncate(s))));
                    // subss/subsd dest, xmm0    (dest -= trunc(dest/src)*src)
                    try code.append(pfx);
                    { const rex = makeRex(false, d, scratch); if (rex != 0x40) try code.append(rex); }
                    try code.append(0x0F); try code.append(0x5C);
                    try code.append(makeModRM(0b11, @as(u3, @truncate(d)), scratch));

                    if (!xmm0_is_operand) {
                        // movsd xmm0, [rsp] -> F2 0F 10 /r
                        try code.append(0xF2);
                        try code.append(0x0F); try code.append(0x10);
                        try code.append(makeModRM(0b00, 0, 4));
                        try code.append(0x24);
                        try emitAddRsp(&code, 16);
                    }
                },

                // ---- Comparison ----
                .cmp => |v| {
                    if (v.left == .reg and v.right == .reg) {
                        const l = regCode(v.left.reg);
                        const r = regCode(v.right.reg);
                        const rex = makeRex(true, r, l);
                        try code.append(rex);
                        try code.append(0x39);
                        try code.append(makeModRM(0b11, @as(u3, @truncate(r)), @as(u3, @truncate(l))));
                    } else if (v.left == .reg and v.right == .imm) {
                        // CMP r/m64, imm -> REX.W 83 /7 ib  or  81 /7 id
                        const l = regCode(v.left.reg);
                        const val = v.right.imm;
                        try code.append(makeRex(true, 0, l));
                        if (val >= -128 and val <= 127) {
                            try code.append(0x83);
                            try code.append(makeModRM(0b11, 7, @as(u3, @truncate(l))));
                            try code.append(@as(u8, @bitCast(@as(i8, @truncate(val)))));
                        } else {
                            try code.append(0x81);
                            try code.append(makeModRM(0b11, 7, @as(u3, @truncate(l))));
                            var bytes: [4]u8 = undefined;
                            std.mem.writeInt(i32, &bytes, val, .little);
                            try code.appendSlice(&bytes);
                        }
                    } else {
                        return EmitterError.UnsupportedOperandCombination;
                    }
                },
                // TEST r/m64, r64 -> REX.W 85 /r  (sets ZF/SF without writing)
                .test_op => |v| {
                    if (v.left == .reg and v.right == .reg) {
                        const l = regCode(v.left.reg);
                        const r = regCode(v.right.reg);
                        try code.append(makeRex(true, r, l));
                        try code.append(0x85);
                        try code.append(makeModRM(0b11, @as(u3, @truncate(r)), @as(u3, @truncate(l))));
                    } else {
                        return EmitterError.UnsupportedOperandCombination;
                    }
                },

                // ---- Switch: emit a compare/JE chain, one entry per key ----
                // Falls through past the chain when no key matches, which lands on the
                // block's default successor (the packed/sparse-switch fall-through).
                .switch_stub => |v| {
                    if (v.src != .reg) return EmitterError.UnsupportedOperandCombination;
                    const sreg = regCode(v.src.reg);
                    for (v.keys, 0..) |key, i| {
                        // CMP src, key  -> REX.W 83 /7 ib  or  81 /7 id
                        try code.append(makeRex(true, 0, sreg));
                        if (key >= -128 and key <= 127) {
                            try code.append(0x83);
                            try code.append(makeModRM(0b11, 7, @as(u3, @truncate(sreg))));
                            try code.append(@as(u8, @bitCast(@as(i8, @truncate(key)))));
                        } else {
                            try code.append(0x81);
                            try code.append(makeModRM(0b11, 7, @as(u3, @truncate(sreg))));
                            var bytes: [4]u8 = undefined;
                            std.mem.writeInt(i32, &bytes, key, .little);
                            try code.appendSlice(&bytes);
                        }
                        // JE target[i]  -> 0F 84 rel32 (patched in pass 2)
                        try code.append(0x0F);
                        try code.append(0x84);
                        try relocations.append(.{
                            .patch_offset = code.items.len,
                            .target_block_id = v.targets[i],
                            .jump_type = .jcc,
                        });
                        try code.appendSlice(&[_]u8{ 0, 0, 0, 0 });
                    }
                },

                // ---- Control Flow (Branches) ----
                .jmp => |v| {
                    try code.append(0xE9); // JMP rel32
                    try relocations.append(.{
                        .patch_offset = code.items.len,
                        .target_block_id = v,
                        .jump_type = .jmp,
                    });
                    try code.appendSlice(&[_]u8{ 0, 0, 0, 0 });
                },
                .je => |v| {
                    try code.append(0x0F); // Jcc rel32 (JE is 0F 84)
                    try code.append(0x84);
                    try relocations.append(.{
                        .patch_offset = code.items.len,
                        .target_block_id = v,
                        .jump_type = .jcc,
                    });
                    try code.appendSlice(&[_]u8{ 0, 0, 0, 0 });
                },
                .jne => |v| {
                    try code.append(0x0F); // JNE is 0F 85
                    try code.append(0x85);
                    try relocations.append(.{
                        .patch_offset = code.items.len,
                        .target_block_id = v,
                        .jump_type = .jcc,
                    });
                    try code.appendSlice(&[_]u8{ 0, 0, 0, 0 });
                },
                .jl => |v| {
                    try code.append(0x0F); // JL is 0F 8C
                    try code.append(0x8C);
                    try relocations.append(.{
                        .patch_offset = code.items.len,
                        .target_block_id = v,
                        .jump_type = .jcc,
                    });
                    try code.appendSlice(&[_]u8{ 0, 0, 0, 0 });
                },
                .jge => |v| {
                    try code.append(0x0F); // JGE is 0F 8D
                    try code.append(0x8D);
                    try relocations.append(.{
                        .patch_offset = code.items.len,
                        .target_block_id = v,
                        .jump_type = .jcc,
                    });
                    try code.appendSlice(&[_]u8{ 0, 0, 0, 0 });
                },
                .jg => |v| {
                    try code.append(0x0F); // JG is 0F 8F
                    try code.append(0x8F);
                    try relocations.append(.{
                        .patch_offset = code.items.len,
                        .target_block_id = v,
                        .jump_type = .jcc,
                    });
                    try code.appendSlice(&[_]u8{ 0, 0, 0, 0 });
                },
                .jle => |v| {
                    try code.append(0x0F); // JLE is 0F 8E
                    try code.append(0x8E);
                    try relocations.append(.{
                        .patch_offset = code.items.len,
                        .target_block_id = v,
                        .jump_type = .jcc,
                    });
                    try code.appendSlice(&[_]u8{ 0, 0, 0, 0 });
                },
                .jz => |v| {
                    try code.append(0x0F); // JZ == JE -> 0F 84
                    try code.append(0x84);
                    try relocations.append(.{
                        .patch_offset = code.items.len,
                        .target_block_id = v,
                        .jump_type = .jcc,
                    });
                    try code.appendSlice(&[_]u8{ 0, 0, 0, 0 });
                },
                .jnz => |v| {
                    try code.append(0x0F); // JNZ == JNE -> 0F 85
                    try code.append(0x85);
                    try relocations.append(.{
                        .patch_offset = code.items.len,
                        .target_block_id = v,
                        .jump_type = .jcc,
                    });
                    try code.appendSlice(&[_]u8{ 0, 0, 0, 0 });
                },

                // ---- Returns ----
                .ret => |v| {
                    if (v) |op| {
                        if (op == .reg) {
                            const is_xmm = std.mem.startsWith(u8, op.reg.name(), "xmm");
                            if (is_xmm) {
                                if (regCode(op.reg) != 0) { // XMM0 is 0
                                    const s = regCode(op.reg);
                                    try code.append(0xF3);
                                    const rex = makeRex(false, 0, s);
                                    if (rex != 0x40) try code.append(rex);
                                    try code.append(0x0F);
                                    try code.append(0x10);
                                    try code.append(makeModRM(0b11, 0, @as(u3, @truncate(s))));
                                }
                            } else {
                                if (regCode(op.reg) != 0) { // RAX is 0
                                    const s = regCode(op.reg);
                                    const rex = makeRex(true, s, 0); // RAX is 0
                                    try code.append(rex);
                                    try code.append(0x89);
                                    try code.append(makeModRM(0b11, @as(u3, @truncate(s)), 0));
                                }
                            }
                        }
                    }
                    // Restore callee-saved XMMs
                    if (xmm_space > 0) {
                        for (xmm_saved.items, 0..) |r, idx| {
                            try emitRestoreXmm(&code, r, @as(i32, @intCast(idx)) * 16);
                        }
                        try emitAddRsp(&code, xmm_space);
                    }

                    // Emit pops in reverse order for GPRs
                    var idx_saved = gpr_saved.items.len;
                    while (idx_saved > 0) {
                        idx_saved -= 1;
                        try emitPop(&code, gpr_saved.items[idx_saved]);
                    }

                    // Restore RBP frame pointer
                    try code.append(0x5D); // pop rbp
                    try code.append(0xC3); // RET
                },
                .call => |v| {
                    if (v.is_self_call) {
                        try code.append(0xE8);
                        const rel32 = -@as(i32, @intCast(code.items.len + 4));
                        var disp_bytes: [4]u8 = undefined;
                        std.mem.writeInt(i32, &disp_bytes, rel32, .little);
                        try code.appendSlice(&disp_bytes);
                    } else {
                        return EmitterError.UnsupportedInstruction;
                    }

                    if (v.dest) |dest| {
                        if (dest == .reg) {
                            const d = regCode(dest.reg);
                            if (d != 0) {
                                try code.append(makeRex(true, 0, d));
                                try code.append(0x89);
                                try code.append(makeModRM(0b11, 0, @as(u3, @truncate(d))));
                            }
                        } else if (dest == .stack) {
                            const offset = dest.stack;
                            try code.append(makeRex(true, 0, 5));
                            try code.append(0x89);
                            if (offset >= -128 and offset <= 127) {
                                try code.append(makeModRM(0b01, 0, 5));
                                try code.append(@as(u8, @bitCast(@as(i8, @truncate(-offset)))));
                            } else {
                                try code.append(makeModRM(0b10, 0, 5));
                                var offset_bytes: [4]u8 = undefined;
                                std.mem.writeInt(i32, &offset_bytes, -offset, .little);
                                try code.appendSlice(&offset_bytes);
                            }
                        }
                    }
                },

                else => return EmitterError.UnsupportedInstruction,
            }
        }
    }

    // Pass 2: Patch relative jump targets.
    for (relocations.items) |reloc| {
        const target_offset = block_offsets.get(reloc.target_block_id) orelse {
            return error.UnknownRelocationTargetBlock;
        };
        const end_offset = reloc.patch_offset + 4;
        const rel32 = @as(i32, @intCast(target_offset)) - @as(i32, @intCast(end_offset));
        
        var bytes: [4]u8 = undefined;
        std.mem.writeInt(i32, &bytes, rel32, .little);
        
        for (bytes, 0..) |b, i| {
            code.items[reloc.patch_offset + i] = b;
        }
    }

    return code.toOwnedSlice();
}

// ── Unit Tests ──────────────────────────────────────────────────────────────

test "emitter: basic arithmetic and moves to machine bytes" {
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

    // MOV RAX, 42
    try mblock.instructions.append(a, .{ .mov = .{ .dest = .{ .reg = .rax }, .src = .{ .imm = 42 } } });
    // ADD RAX, RBX
    try mblock.instructions.append(a, .{ .add = .{ .dest = .{ .reg = .rax }, .src = .{ .reg = .rbx } } });
    // RET
    try mblock.instructions.append(a, .{ .ret = null });

    try prog.blocks.append(a, mblock);

    const bytes = try emitProgram(a, &prog);
    defer a.free(bytes);

    // Expected machine bytes:
    // MOV RAX, 42  -> 48 B8 2A 00 00 00 00 00 00 00
    // ADD RAX, RBX -> 48 01 D8
    // RET          -> C3
    const expected = [_]u8{
        0x55,
        0x48, 0x89, 0xE5,
        0x53, // push rbx
        0x48, 0xB8, 0x2A, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
        0x48, 0x01, 0xD8,
        0x5B, // pop rbx
        0x5D,
        0xC3,
    };
    try std.testing.expectEqualSlices(u8, &expected, bytes);
}

test "emitter: callee-saved registers and register-8 immediate load encoding" {
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

    // MOV R8, 2
    try mblock.instructions.append(a, .{ .mov = .{ .dest = .{ .reg = .r8 }, .src = .{ .imm = 2 } } });
    // MOV R15, 10
    try mblock.instructions.append(a, .{ .mov = .{ .dest = .{ .reg = .r15 }, .src = .{ .imm = 10 } } });
    // RET
    try mblock.instructions.append(a, .{ .ret = null });

    try prog.blocks.append(a, mblock);

    const bytes = try emitProgram(a, &prog);
    defer a.free(bytes);

    // Expected:
    // push r15       -> 41 57
    // mov r8, 2      -> 49 B8 02 00 00 00 00 00 00 00
    // mov r15, 10    -> 49 BF 0A 00 00 00 00 00 00 00
    // pop r15        -> 41 5F
    // ret            -> C3
    const expected = [_]u8{
        0x55,
        0x48, 0x89, 0xE5,
        0x41, 0x57,
        0x49, 0xB8, 0x02, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
        0x49, 0xBF, 0x0A, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
        0x41, 0x5F,
        0x5D,
        0xC3,
    };
    try std.testing.expectEqualSlices(u8, &expected, bytes);
}

test "emitter: new ops (not, movsxd, shl, cmp3)" {
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

    // NOT RAX
    try mblock.instructions.append(a, .{ .not = .{ .dest = .{ .reg = .rax } } });
    // MOVSXD RAX, RBX
    try mblock.instructions.append(a, .{ .movsxd = .{ .dest = .{ .reg = .rax }, .src = .{ .reg = .rbx } } });
    // SHL RAX, 3
    try mblock.instructions.append(a, .{ .shl = .{ .dest = .{ .reg = .rax }, .src = .{ .imm = 3 } } });
    // CMP3 (cmp_long) RAX, RBX, RCX
    try mblock.instructions.append(a, .{ .cmp3 = .{ .kind = .cmp_long, .dest = .{ .reg = .rax }, .left = .{ .reg = .rbx }, .right = .{ .reg = .rcx } } });
    // RET
    try mblock.instructions.append(a, .{ .ret = null });

    try prog.blocks.append(a, mblock);

    const bytes = try emitProgram(a, &prog);
    defer a.free(bytes);

    try std.testing.expect(bytes.len > 0);
}
