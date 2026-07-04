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

    var code = CodeWriter{ .buf = &raw_code, .alloc = allocator };
    code.updateItems();

    var relocations = RelocWriter{ .buf = &raw_relocations, .alloc = allocator };
    relocations.updateItems();

    // Map from block ID -> byte offset in final code buffer.
    var block_offsets = std.AutoHashMap(usize, usize).init(allocator);
    defer block_offsets.deinit();

    // Pass 1: Emit instructions and record label offsets and relocation sites.
    for (program.blocks.items) |block| {
        try block_offsets.put(block.id, code.items.len);

        for (block.instructions.items) |inst| {
            switch (inst) {
                // ---- Data movement ----
                .mov => |v| {
                    if (v.dest == .reg and v.src == .imm) {
                        // MOV r64, imm32/imm64
                        const d = regCode(v.dest.reg);
                        const rex = makeRex(true, 0, d);
                        try code.append(rex);
                        try code.append(0xB8 + @as(u8, @truncate(d)));
                        // We support 64-bit constants here (imm64 or imm)
                        const val: u64 = switch (v.src) {
                            .imm => |imm| @as(u64, @bitCast(@as(i64, imm))),
                            .imm64 => |imm| @as(u64, @bitCast(imm)),
                            else => unreachable,
                        };
                        var bytes: [8]u8 = undefined;
                        std.mem.writeInt(u64, &bytes, val, .little);
                        try code.appendSlice(&bytes);
                    } else if (v.dest == .reg and v.src == .reg) {
                        // MOV r64, r64
                        const d = regCode(v.dest.reg);
                        const s = regCode(v.src.reg);
                        const rex = makeRex(true, s, d);
                        try code.append(rex);
                        try code.append(0x89);
                        try code.append(makeModRM(0b11, @as(u3, @truncate(s)), @as(u3, @truncate(d))));
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
                        if (op == .reg and regCode(op.reg) != 0) {
                            // If the return operand is not in RAX, MOV it to RAX!
                            const s = regCode(op.reg);
                            const rex = makeRex(true, s, 0); // RAX is 0
                            try code.append(rex);
                            try code.append(0x89);
                            try code.append(makeModRM(0b11, @as(u3, @truncate(s)), 0));
                        }
                    }
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
        0x48, 0xB8, 0x2A, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
        0x48, 0x01, 0xD8,
        0xC3,
    };
    try std.testing.expectEqualSlices(u8, &expected, bytes);
}
