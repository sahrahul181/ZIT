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
                    } else {
                        return EmitterError.UnsupportedOperandCombination;
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
                    } else {
                        return EmitterError.UnsupportedOperandCombination;
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
