const std = @import("std");
const ir = @import("ir");
const x86 = @import("x86");
const runtime = @import("runtime");

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

fn makeRexSib(w: bool, reg: u4, rm: u4, idx: u4) u8 {
    var rex: u8 = 0x40;
    if (w) rex |= 0x08; // W bit (64-bit operand size)
    if (reg >= 8) rex |= 0x04; // R bit (registers 8-15)
    if (idx >= 8) rex |= 0x02; // X bit (index 8-15)
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
                    switch (op) {
                        .reg => |r| {
                            const is_callee = switch (r) {
                                .rbx, .rsi, .rdi, .r12, .r13, .r14, .r15, .xmm6, .xmm7, .xmm8, .xmm9, .xmm10, .xmm11, .xmm12, .xmm13, .xmm14, .xmm15 => true,
                                else => false,
                            };
                            if (is_callee) {
                                try u.put(r, {});
                            }
                        },
                        .mem => |m| {
                            switch (m.base) {
                                .reg => |br| try run(u, .{ .reg = br }),
                                else => {},
                            }
                            if (m.index) |idx| {
                                switch (idx) {
                                    .reg => |irg| try run(u, .{ .reg = irg }),
                                    else => {},
                                }
                            }
                        },
                        else => {},
                    }
                }
            }.run;

            switch (inst) {
                .mov => |v| {
                    try checkOp(&used, v.dest);
                    try checkOp(&used, v.src);
                },
                .bounds_check => |v| {
                    try checkOp(&used, v.index);
                    try checkOp(&used, v.array);
                },
                .add => |v| {
                    try checkOp(&used, v.dest);
                    try checkOp(&used, v.src);
                },
                .sub => |v| {
                    try checkOp(&used, v.dest);
                    try checkOp(&used, v.src);
                },
                .imul => |v| {
                    try checkOp(&used, v.dest);
                    try checkOp(&used, v.src);
                },
                .idiv => |v| {
                    try checkOp(&used, v.dest);
                    try checkOp(&used, v.rem);
                    try checkOp(&used, v.src);
                },
                .irem => |v| {
                    try checkOp(&used, v.dest);
                    try checkOp(&used, v.rem);
                    try checkOp(&used, v.src);
                },
                .neg => |v| {
                    try checkOp(&used, v.dest);
                },
                .and_op => |v| {
                    try checkOp(&used, v.dest);
                    try checkOp(&used, v.src);
                },
                .or_op => |v| {
                    try checkOp(&used, v.dest);
                    try checkOp(&used, v.src);
                },
                .xor_op => |v| {
                    try checkOp(&used, v.dest);
                    try checkOp(&used, v.src);
                },
                .shl => |v| {
                    try checkOp(&used, v.dest);
                    try checkOp(&used, v.src);
                },
                .shr => |v| {
                    try checkOp(&used, v.dest);
                    try checkOp(&used, v.src);
                },
                .ushr => |v| {
                    try checkOp(&used, v.dest);
                    try checkOp(&used, v.src);
                },
                .cmp => |v| {
                    try checkOp(&used, v.left);
                    try checkOp(&used, v.right);
                },
                .test_op => |v| {
                    try checkOp(&used, v.left);
                    try checkOp(&used, v.right);
                },
                .addss => |v| {
                    try checkOp(&used, v.dest);
                    try checkOp(&used, v.src);
                },
                .subss => |v| {
                    try checkOp(&used, v.dest);
                    try checkOp(&used, v.src);
                },
                .mulss => |v| {
                    try checkOp(&used, v.dest);
                    try checkOp(&used, v.src);
                },
                .divss => |v| {
                    try checkOp(&used, v.dest);
                    try checkOp(&used, v.src);
                },
                .movss => |v| {
                    try checkOp(&used, v.dest);
                    try checkOp(&used, v.src);
                },
                .addsd => |v| {
                    try checkOp(&used, v.dest);
                    try checkOp(&used, v.src);
                },
                .subsd => |v| {
                    try checkOp(&used, v.dest);
                    try checkOp(&used, v.src);
                },
                .mulsd => |v| {
                    try checkOp(&used, v.dest);
                    try checkOp(&used, v.src);
                },
                .divsd => |v| {
                    try checkOp(&used, v.dest);
                    try checkOp(&used, v.src);
                },
                .movsd => |v| {
                    try checkOp(&used, v.dest);
                    try checkOp(&used, v.src);
                },
                .ret => |v| {
                    if (v) |op| try checkOp(&used, op);
                },
                .call => |v| {
                    if (v.dest) |op| try checkOp(&used, op);
                },
                .monitor_enter => |v| {
                    try checkOp(&used, v.src);
                },
                .monitor_exit => |v| {
                    try checkOp(&used, v.src);
                },
                .not => |v| {
                    try checkOp(&used, v.dest);
                },
                .negss => |v| {
                    try checkOp(&used, v.dest);
                },
                .negsd => |v| {
                    try checkOp(&used, v.dest);
                },
                .movsxd => |v| {
                    try checkOp(&used, v.dest);
                    try checkOp(&used, v.src);
                },
                .movsx8 => |v| {
                    try checkOp(&used, v.dest);
                    try checkOp(&used, v.src);
                },
                .movsx16 => |v| {
                    try checkOp(&used, v.dest);
                    try checkOp(&used, v.src);
                },
                .movzx16 => |v| {
                    try checkOp(&used, v.dest);
                    try checkOp(&used, v.src);
                },
                .cvtsi2ss => |v| {
                    try checkOp(&used, v.dest);
                    try checkOp(&used, v.src);
                },
                .cvtsi2sd => |v| {
                    try checkOp(&used, v.dest);
                    try checkOp(&used, v.src);
                },
                .cvttss2si => |v| {
                    try checkOp(&used, v.dest);
                    try checkOp(&used, v.src);
                },
                .cvttsd2si => |v| {
                    try checkOp(&used, v.dest);
                    try checkOp(&used, v.src);
                },
                .cvtss2sd => |v| {
                    try checkOp(&used, v.dest);
                    try checkOp(&used, v.src);
                },
                .cvtsd2ss => |v| {
                    try checkOp(&used, v.dest);
                    try checkOp(&used, v.src);
                },
                .frem32 => |v| {
                    try checkOp(&used, v.dest);
                    try checkOp(&used, v.src);
                },
                .frem64 => |v| {
                    try checkOp(&used, v.dest);
                    try checkOp(&used, v.src);
                },
                .cmp3 => |v| {
                    try checkOp(&used, v.dest);
                    try checkOp(&used, v.left);
                    try checkOp(&used, v.right);
                },
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

pub fn emitProgram(
    allocator: std.mem.Allocator,
    program: *x86.MachineProgram,
    registry: ?*@import("class_loader").ClassRegistry,
    dex: ?*const @import("parser").DexFile,
) ![]u8 {
    var raw_code = std.ArrayList(u8).empty;
    errdefer raw_code.deinit(allocator);

    var local_gc_builder = @import("gc_map").GcMapBuilder.init(allocator);
    defer local_gc_builder.deinit();

    var raw_relocations = std.ArrayList(Relocation).empty;
    defer raw_relocations.deinit(allocator);

    const LatePatchType = enum {
        class_ptr,
        target_ptr,
    };

    const LatePatch = struct {
        patch_type: LatePatchType,
        inst_offset: usize,
        next_inst_offset: usize,
        ic_index: usize,
    };

    var late_patches = std.ArrayList(LatePatch).empty;
    defer late_patches.deinit(allocator);

    var num_inline_caches: usize = 0;

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

    // MOV r64, imm32 (sign-extended). Always 7 bytes (REX.W C7 /0 id) â€” the
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

    const emitMemModRM = struct {
        fn run(c: *CodeWriter, reg_field: u3, mem: x86.MemoryAddress) !void {
            // Handle .stack base: treat as [rbp - offset] (no index, just disp)
            if (mem.base == .stack) {
                const stack_disp = -mem.base.stack + mem.disp;
                if (stack_disp >= -128 and stack_disp <= 127) {
                    try c.append(makeModRM(0b01, reg_field, 5)); // RBP = 5
                    try c.append(@as(u8, @bitCast(@as(i8, @truncate(stack_disp)))));
                } else {
                    try c.append(makeModRM(0b10, reg_field, 5));
                    var bytes: [4]u8 = undefined;
                    std.mem.writeInt(i32, &bytes, stack_disp, .little);
                    try c.appendSlice(&bytes);
                }
                return;
            }
            const base = regCode(mem.base.reg);
            if (mem.index == null) {
                if (base == 4) { // RSP/R12
                    if (mem.disp == 0) {
                        try c.append(makeModRM(0b00, reg_field, 4));
                        try c.append(0x24);
                    } else if (mem.disp >= -128 and mem.disp <= 127) {
                        try c.append(makeModRM(0b01, reg_field, 4));
                        try c.append(0x24);
                        try c.append(@as(u8, @bitCast(@as(i8, @truncate(mem.disp)))));
                    } else {
                        try c.append(makeModRM(0b10, reg_field, 4));
                        try c.append(0x24);
                        var bytes: [4]u8 = undefined;
                        std.mem.writeInt(i32, &bytes, mem.disp, .little);
                        try c.appendSlice(&bytes);
                    }
                    return;
                }

                if (mem.disp == 0 and base != 5) {
                    try c.append(makeModRM(0b00, reg_field, @as(u3, @truncate(base))));
                } else if (mem.disp >= -128 and mem.disp <= 127) {
                    try c.append(makeModRM(0b01, reg_field, @as(u3, @truncate(base))));
                    try c.append(@as(u8, @bitCast(@as(i8, @truncate(mem.disp)))));
                } else {
                    try c.append(makeModRM(0b10, reg_field, @as(u3, @truncate(base))));
                    var bytes: [4]u8 = undefined;
                    std.mem.writeInt(i32, &bytes, mem.disp, .little);
                    try c.appendSlice(&bytes);
                }
            } else {
                const idx_base = mem.index.?;
                const idx = if (idx_base == .reg) regCode(idx_base.reg) else 0;
                const scale_bits: u8 = switch (@as(u4, mem.scale)) {
                    1 => 0b00,
                    2 => 0b01,
                    4 => 0b10,
                    8 => 0b11,
                    else => unreachable,
                };
                const sib = (scale_bits << 6) | (@as(u8, @truncate(idx)) << 3) | @as(u8, @truncate(base));

                if (mem.disp == 0 and base != 5) {
                    try c.append(makeModRM(0b00, reg_field, 4));
                    try c.append(sib);
                } else if (mem.disp >= -128 and mem.disp <= 127) {
                    try c.append(makeModRM(0b01, reg_field, 4));
                    try c.append(sib);
                    try c.append(@as(u8, @bitCast(@as(i8, @truncate(mem.disp)))));
                } else {
                    try c.append(makeModRM(0b10, reg_field, 4));
                    try c.append(sib);
                    var bytes: [4]u8 = undefined;
                    std.mem.writeInt(i32, &bytes, mem.disp, .little);
                    try c.appendSlice(&bytes);
                }
            }
        }
    }.run;

    // The safepoint page is allocated once (during initSafepointSubsystem, before
    // any JIT compilation) and its address never changes — only its page
    // *protection* is toggled by the GC. So bake the page address in as an
    // immediate and poll it with a single dependent load, rather than chasing the
    // global pointer through two extra loads on every backward branch. This is a
    // hot-path optimization: the old 3-load poll roughly doubled tight-loop cost.
    const sp_page_addr: u64 = blk: {
        const sp = @import("safepoint");
        const p: usize = @intFromPtr(sp.safepoint_page);
        break :blk @intCast(p);
    };
    const emitSafepointCheck = struct {
        fn run(c: *CodeWriter, page_addr: u64) !void {
            if (page_addr == 0) {
                // Page not yet allocated at emit time (e.g. unit tests without the
                // safepoint subsystem): fall back to the pointer-chasing form so we
                // still poll the correct location once it is set.
                try c.appendSlice(&[_]u8{ 0x48, 0xB8 });
                var addr_bytes: [8]u8 = undefined;
                std.mem.writeInt(u64, &addr_bytes, @intFromPtr(&@import("safepoint").safepoint_page), .little);
                try c.appendSlice(&addr_bytes);
                try c.appendSlice(&[_]u8{ 0x48, 0x8B, 0x00 }); // MOV RAX, [RAX]
                try c.appendSlice(&[_]u8{ 0x8A, 0x00 });       // MOV AL, [RAX]
                return;
            }
            if (page_addr <= 0x7FFFFFFF) {
                // Fast path: 32-bit absolute addressing
                // CMP BYTE PTR [page_addr], 0
                try c.appendSlice(&[_]u8{ 0x80, 0x3C, 0x25 });
                var addr_bytes: [4]u8 = undefined;
                std.mem.writeInt(u32, &addr_bytes, @intCast(page_addr), .little);
                try c.appendSlice(&addr_bytes);
                try c.append(0x00);
                return;
            }
            // MOV RAX, page_addr (imm64)
            try c.appendSlice(&[_]u8{ 0x48, 0xB8 });
            var addr_bytes: [8]u8 = undefined;
            std.mem.writeInt(u64, &addr_bytes, page_addr, .little);
            try c.appendSlice(&addr_bytes);
            // MOV AL, [RAX] — the dummy page read; traps via VEH when the GC has
            // protected the page for a stop-the-world safepoint.
            try c.appendSlice(&[_]u8{ 0x8A, 0x00 });
        }
    }.run;

    var code = CodeWriter{ .buf = &raw_code, .alloc = allocator };
    code.updateItems();

    // safepoint_patch_offsets removed for Dekker safepoints

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

    // Allocate local variable space (aligned)
    const gpr_space = @as(i32, @intCast(gpr_saved.items.len)) * 8;
    const save_space = gpr_space + xmm_space;
    var local_space = program.stack_space - 8;
    if (local_space < 0) local_space = 0;
    if (@mod(save_space + local_space, 16) != 0) {
        local_space += 16 - @mod(save_space + local_space, 16);
    }
    if (local_space > 0) {
        try emitSubRsp(&code, local_space);
    }

    // Collect loop back-edges (target block id <= source block id) so we can poll
    // the GC safepoint only on *outer* loops. Polling every innermost iteration
    // roughly doubles tight-loop cost; an outer-loop poll still lets the GC stop
    // threads within a bounded window. A back-edge is "inner" (skip) when its loop
    // range is strictly contained in another back-edge's range.
    const BackEdge = struct { target: usize, source: usize };
    var back_edges = std.ArrayList(BackEdge).empty;
    defer back_edges.deinit(allocator);
    for (program.blocks.items) |block| {
        for (block.instructions.items) |inst| {
            const target: ?usize = switch (inst) {
                .jmp, .je, .jne, .jl, .jge, .jg, .jle, .jz, .jnz => |t| t,
                else => null,
            };
            if (target) |t| {
                if (t <= block.id) try back_edges.append(allocator, .{ .target = t, .source = block.id });
            }
        }
    }
    const shouldPoll = struct {
        fn f(edges: []const BackEdge, target: usize, source: usize) bool {
            // Poll unless some OTHER back-edge strictly contains this one's range
            // [target, source] (i.e. this is a nested/inner loop).
            for (edges) |e| {
                if (e.target == target and e.source == source) continue;
                if (e.target <= target and e.source >= source) return false;
            }
            return true;
        }
    }.f;

    // Pass 1: Emit instructions and record label offsets and relocation sites.
    for (program.blocks.items) |block| {
        try block_offsets.put(block.id, code.items.len);

        for (block.instructions.items) |inst| {
            // GC safepoint on outer-loop back-edges only (see back_edges above).
            if (dex != null) {
                const bt: ?usize = switch (inst) {
                    .jmp, .je, .jne, .jl, .jge, .jg, .jle, .jz, .jnz => |t| t,
                    else => null,
                };
                if (bt) |t| {
                    if (t <= block.id and shouldPoll(back_edges.items, t, block.id)) {
                        try emitSafepointCheck(&code, sp_page_addr);
                    }
                }
            }

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
                                // Non-zero immediate into XMM: load via integer register
                                // MOV r11, imm64; MOVQ xmm, r11
                                try code.appendSlice(&[_]u8{ 0x49, 0xBB });
                                var imm_bytes: [8]u8 = undefined;
                                const imm_v: i64 = switch (v.src) {
                                    .imm => |i| i,
                                    .imm64 => |i| @as(i64, @bitCast(i)),
                                    else => unreachable,
                                };
                                std.mem.writeInt(i64, &imm_bytes, imm_v, .little);
                                try code.appendSlice(&imm_bytes);
                                // MOVQ xmm, r11: 66 REX.W+R+B 0F 6E /r
                                const d = regCode(v.dest.reg);
                                try code.append(0x66);
                                try code.append(makeRex(true, d, 11)); // 11 = r11
                                try code.append(0x0F);
                                try code.append(0x6E);
                                try code.append(makeModRM(0b11, @as(u3, @truncate(d)), 3)); // r11 low3 = 3
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
                    } else if (v.dest == .reg and v.src == .mem) {
                        const d = regCode(v.dest.reg);
                        const b = if (v.src.mem.base == .reg) regCode(v.src.mem.base.reg) else 0;
                        const idx = if (v.src.mem.index) |i| (if (i == .reg) regCode(i.reg) else 0) else 0;
                        try code.append(makeRexSib(true, d, b, idx));
                        try code.append(0x8B); // Load
                        try emitMemModRM(&code, @as(u3, @truncate(d)), v.src.mem);
                    } else if (v.dest == .mem and v.src == .reg) {
                        const s = regCode(v.src.reg);
                        const b = if (v.dest.mem.base == .reg) regCode(v.dest.mem.base.reg) else 0;
                        const idx = if (v.dest.mem.index) |i| (if (i == .reg) regCode(i.reg) else 0) else 0;
                        try code.append(makeRexSib(true, s, b, idx));
                        try code.append(0x89); // Store
                        try emitMemModRM(&code, @as(u3, @truncate(s)), v.dest.mem);
                    } else if (v.dest == .stack and v.src == .imm) {
                        // MOV r11, imm64; MOV [rbp-offset], r11
                        const val = v.src.imm;
                        const offset = v.dest.stack;
                        try code.appendSlice(&[_]u8{ 0x49, 0xBB });
                        var imm_bytes: [8]u8 = undefined;
                        std.mem.writeInt(i64, &imm_bytes, val, .little);
                        try code.appendSlice(&imm_bytes);
                        try code.append(0x4C); // REX.W + REX.R (r11)
                        try code.append(0x89);
                        if (offset >= -128 and offset <= 127) {
                            try code.append(makeModRM(0b01, 3, 5));
                            try code.append(@as(u8, @bitCast(@as(i8, @truncate(-offset)))));
                        } else {
                            try code.append(makeModRM(0b10, 3, 5));
                            var bytes: [4]u8 = undefined;
                            std.mem.writeInt(i32, &bytes, -offset, .little);
                            try code.appendSlice(&bytes);
                        }
                    } else if (v.dest == .stack and v.src == .stack) {
                        // Load into r11, then store
                        const src_off = v.src.stack;
                        const dst_off = v.dest.stack;
                        try code.append(0x4C); // REX.W + REX.R (r11)
                        try code.append(0x8B);
                        if (src_off >= -128 and src_off <= 127) {
                            try code.append(makeModRM(0b01, 3, 5));
                            try code.append(@as(u8, @bitCast(@as(i8, @truncate(-src_off)))));
                        } else {
                            try code.append(makeModRM(0b10, 3, 5));
                            var bytes: [4]u8 = undefined;
                            std.mem.writeInt(i32, &bytes, -src_off, .little);
                            try code.appendSlice(&bytes);
                        }
                        try code.append(0x4C);
                        try code.append(0x89);
                        if (dst_off >= -128 and dst_off <= 127) {
                            try code.append(makeModRM(0b01, 3, 5));
                            try code.append(@as(u8, @bitCast(@as(i8, @truncate(-dst_off)))));
                        } else {
                            try code.append(makeModRM(0b10, 3, 5));
                            var bytes: [4]u8 = undefined;
                            std.mem.writeInt(i32, &bytes, -dst_off, .little);
                            try code.appendSlice(&bytes);
                        }
                    } else if (v.dest == .mem and v.src == .stack) {
                        // Load from stack into r11, then store to mem
                        const src_off = v.src.stack;
                        try code.append(0x4C); // REX.W + REX.R(r11)
                        try code.append(0x8B);
                        if (src_off >= -128 and src_off <= 127) {
                            try code.append(makeModRM(0b01, 3, 5));
                            try code.append(@as(u8, @bitCast(@as(i8, @truncate(-src_off)))));
                        } else {
                            try code.append(makeModRM(0b10, 3, 5));
                            var bytes: [4]u8 = undefined;
                            std.mem.writeInt(i32, &bytes, -src_off, .little);
                            try code.appendSlice(&bytes);
                        }
                        // MOV [mem], r11
                        const b = if (v.dest.mem.base == .reg) regCode(v.dest.mem.base.reg) else 0;
                        const idx = if (v.dest.mem.index) |i| (if (i == .reg) regCode(i.reg) else 0) else 0;
                        try code.append(makeRexSib(true, 11, b, idx));
                        try code.append(0x89);
                        try emitMemModRM(&code, 3, v.dest.mem); // r11 low3 = 3
                    } else if (v.dest == .stack and v.src == .mem) {
                        // Load from mem into r11, then store to stack
                        const d_off = v.dest.stack;
                        const b = if (v.src.mem.base == .reg) regCode(v.src.mem.base.reg) else 0;
                        const idx = if (v.src.mem.index) |i| (if (i == .reg) regCode(i.reg) else 0) else 0;
                        try code.append(makeRexSib(true, 11, b, idx));
                        try code.append(0x8B);
                        try emitMemModRM(&code, 3, v.src.mem); // r11 low3 = 3
                        // MOV [rbp - d_off], r11
                        try code.append(0x4C);
                        try code.append(0x89);
                        if (d_off >= -128 and d_off <= 127) {
                            try code.append(makeModRM(0b01, 3, 5));
                            try code.append(@as(u8, @bitCast(@as(i8, @truncate(-d_off)))));
                        } else {
                            try code.append(makeModRM(0b10, 3, 5));
                            var bytes: [4]u8 = undefined;
                            std.mem.writeInt(i32, &bytes, -d_off, .little);
                            try code.appendSlice(&bytes);
                        }
                    } else {
                        std.debug.print("mov: unsupported dest={s} src={s}\n", .{ @tagName(v.dest), @tagName(v.src) });
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
                    } else if (v.dest == .reg and v.src == .stack) {
                        // Load src from stack into tmp reg (r11), then SUB
                        const d = regCode(v.dest.reg);
                        const offset = v.src.stack;
                        // MOV r11, [rbp - offset]
                        try code.append(0x4C); // REX.W + REX.R (r11=reg field) + REX.B (rbp=5)
                        try code.append(0x8B);
                        if (offset >= -128 and offset <= 127) {
                            try code.append(makeModRM(0b01, 3, 5)); // r11 code = 3 in low3 bits
                            try code.append(@as(u8, @bitCast(@as(i8, @truncate(-offset)))));
                        } else {
                            try code.append(makeModRM(0b10, 3, 5));
                            var bytes: [4]u8 = undefined;
                            std.mem.writeInt(i32, &bytes, -offset, .little);
                            try code.appendSlice(&bytes);
                        }
                        // SUB dest, r11
                        try code.append(makeRex(true, 3, d)); // r11 as src
                        try code.append(0x29);
                        try code.append(makeModRM(0b11, 3, @as(u3, @truncate(d))));
                    } else if (v.dest == .stack and v.src == .reg) {
                        // SUB [rbp - offset], src (load first to scratch, sub, store back)
                        const s = regCode(v.src.reg);
                        const offset = v.dest.stack;
                        // Load stack into r11
                        try code.append(0x4C);
                        try code.append(0x8B);
                        if (offset >= -128 and offset <= 127) {
                            try code.append(makeModRM(0b01, 3, 5));
                            try code.append(@as(u8, @bitCast(@as(i8, @truncate(-offset)))));
                        } else {
                            try code.append(makeModRM(0b10, 3, 5));
                            var bytes: [4]u8 = undefined;
                            std.mem.writeInt(i32, &bytes, -offset, .little);
                            try code.appendSlice(&bytes);
                        }
                        // SUB r11, src
                        try code.append(makeRex(true, s, 3));
                        try code.append(0x29);
                        try code.append(makeModRM(0b11, @as(u3, @truncate(s)), 3));
                        // Store r11 back
                        try code.append(0x4C);
                        try code.append(0x89);
                        if (offset >= -128 and offset <= 127) {
                            try code.append(makeModRM(0b01, 3, 5));
                            try code.append(@as(u8, @bitCast(@as(i8, @truncate(-offset)))));
                        } else {
                            try code.append(makeModRM(0b10, 3, 5));
                            var bytes: [4]u8 = undefined;
                            std.mem.writeInt(i32, &bytes, -offset, .little);
                            try code.appendSlice(&bytes);
                        }
                    } else {
                        std.debug.print("sub: unsupported operands dest={s} src={s}\n", .{ @tagName(v.dest), @tagName(v.src) });
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
                    } else if (v.dest == .reg and v.src == .mem) {
                        const d = regCode(v.dest.reg);
                        const b = if (v.src.mem.base == .reg) regCode(v.src.mem.base.reg) else 0;
                        const idx = if (v.src.mem.index) |i| (if (i == .reg) regCode(i.reg) else 0) else 0;
                        try code.append(makeRexSib(true, d, b, idx));
                        try code.append(0x63);
                        try emitMemModRM(&code, @as(u3, @truncate(d)), v.src.mem);
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

                // ---- Int â†” float conversions ----
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
                        // Dalvik NaN bias: cmpl â†’ -1 on NaN, cmpg â†’ +1 on NaN.
                        // mov dest, bias
                        // ucomiss/ucomisd left, right   (unordered â†’ ZF=PF=CF=1)
                        // jp  end (+25)   ; NaN â†’ keep bias
                        // mov dest, 1
                        // ja  end (+16)   ; CF=0,ZF=0 â†’ left > right
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
                // Immediate count â†’ C1 /r ib.  Register count must be in CL â†’ D3 /r,
                // so the register form materializes MOV rcx, count first.  The RA pass
                // keeps RCX out of the general pool via the shift-count reservation.
                .shl, .shr, .ushr => {
                    const parts = switch (inst) {
                        .shl => .{ inst.shl.dest, inst.shl.src, @as(u3, 4) }, // /4 SHL
                        .shr => .{ inst.shr.dest, inst.shr.src, @as(u3, 7) }, // /7 SAR
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
                        // reg) â€” the RA hint avoids this; treat as unsupported to be safe.
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
                // x86 IDIV divides RDX:RAX by the operand: quotientâ†’RAX, remainderâ†’RDX.
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
                        // wrong (would clobber flags-free RAX? noâ€”pop doesn't touch RAX/RDX).
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
                        try code.append(0x0F);
                        try code.append(0x11);
                        try code.append(makeModRM(0b00, 0, 4));
                        try code.append(0x24);
                    }

                    // movaps/movsd xmm0, dest    (copy dividend)
                    try code.append(pfx);
                    {
                        const rex = makeRex(false, scratch, d);
                        if (rex != 0x40) try code.append(rex);
                    }
                    try code.append(0x0F);
                    try code.append(0x10);
                    try code.append(makeModRM(0b11, scratch, @as(u3, @truncate(d))));
                    // divss/divsd xmm0, src
                    try code.append(pfx);
                    {
                        const rex = makeRex(false, scratch, s);
                        if (rex != 0x40) try code.append(rex);
                    }
                    try code.append(0x0F);
                    try code.append(0x5E);
                    try code.append(makeModRM(0b11, scratch, @as(u3, @truncate(s))));
                    // roundss/roundsd xmm0, xmm0, 3 (truncate toward zero) -> 66 0F 3A 0A/0B /r ib
                    try code.append(0x66);
                    {
                        const rex = makeRex(false, scratch, scratch);
                        if (rex != 0x40) try code.append(rex);
                    }
                    try code.append(0x0F);
                    try code.append(0x3A);
                    try code.append(if (is64) @as(u8, 0x0B) else @as(u8, 0x0A));
                    try code.append(makeModRM(0b11, scratch, scratch));
                    try code.append(0x03); // round-toward-zero
                    // mulss/mulsd xmm0, src
                    try code.append(pfx);
                    {
                        const rex = makeRex(false, scratch, s);
                        if (rex != 0x40) try code.append(rex);
                    }
                    try code.append(0x0F);
                    try code.append(0x59);
                    try code.append(makeModRM(0b11, scratch, @as(u3, @truncate(s))));
                    // subss/subsd dest, xmm0    (dest -= trunc(dest/src)*src)
                    try code.append(pfx);
                    {
                        const rex = makeRex(false, d, scratch);
                        if (rex != 0x40) try code.append(rex);
                    }
                    try code.append(0x0F);
                    try code.append(0x5C);
                    try code.append(makeModRM(0b11, @as(u3, @truncate(d)), scratch));

                    if (!xmm0_is_operand) {
                        // movsd xmm0, [rsp] -> F2 0F 10 /r
                        try code.append(0xF2);
                        try code.append(0x0F);
                        try code.append(0x10);
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
                        } else if (op == .stack) {
                            const offset = op.stack;
                            try code.append(makeRex(true, 0, 5)); // RBP is 5, dest RAX is 0
                            try code.append(0x8B); // MOV rax, [rbp - offset]
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
                    // Restore local variable space
                    if (local_space > 0) {
                        try emitAddRsp(&code, local_space);
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
                    const call_pos = code.items.len;
                    if (v.gc_info) |gc_info| {
                        try local_gc_builder.addEntry(.{
                            .call_offset = @intCast(call_pos),
                            .stack_refs = gc_info.stack_refs,
                            .reg_refs = gc_info.reg_refs,
                        });
                    }

                    if (v.is_self_call) {
                        try code.append(0xE8);
                        const rel32 = -@as(i32, @intCast(code.items.len + 4));
                        var disp_bytes: [4]u8 = undefined;
                        std.mem.writeInt(i32, &disp_bytes, rel32, .little);
                        try code.appendSlice(&disp_bytes);
                    } else {
                        const ic_idx = num_inline_caches;
                        num_inline_caches += 1;

                        if (v.is_static) {
                            // --- Monomorphic Cache: Static Call ---
                            // 1. Load cached_target into r11 (RIP-relative)
                            // mov r11, [rip + disp32] -> 4C 8B 1D <disp32>
                            try code.appendSlice(&[_]u8{ 0x4C, 0x8B, 0x1D });
                            const target_patch_idx = code.items.len;
                            try code.appendSlice(&[_]u8{ 0, 0, 0, 0 });
                            try late_patches.append(allocator, .{
                                .patch_type = .target_ptr,
                                .inst_offset = target_patch_idx,
                                .next_inst_offset = code.items.len,
                                .ic_index = ic_idx,
                            });

                            // 2. Test r11, r11 -> 4D 85 DB
                            try code.appendSlice(&[_]u8{ 0x4D, 0x85, 0xDB });

                            // 3. jz cache_miss (rel8 offset is 8 bytes: 3 bytes for call r11, 5 bytes for jmp done)
                            // jz -> 74 08
                            try code.appendSlice(&[_]u8{ 0x74, 0x08 });

                            // 4. call r11 -> 41 FF D3
                            try code.appendSlice(&[_]u8{ 0x41, 0xFF, 0xD3 });

                            // 5. jmp done -> E9 <disp32>
                            try code.append(0xE9);
                            const jmp_done_idx = code.items.len;
                            try code.appendSlice(&[_]u8{ 0, 0, 0, 0 });

                            // --- Cache Miss / Slow Path ---
                            // Original slow path setup and call
                            // 1. Save XMMs (64 bytes)
                            try code.appendSlice(&[_]u8{ 0x48, 0x83, 0xEC, 0x40 });
                            try code.appendSlice(&[_]u8{ 0x66, 0x0F, 0xD6, 0x04, 0x24 });
                            try code.appendSlice(&[_]u8{ 0x66, 0x0F, 0xD6, 0x4C, 0x24, 0x08 });
                            try code.appendSlice(&[_]u8{ 0x66, 0x0F, 0xD6, 0x54, 0x24, 0x10 });
                            try code.appendSlice(&[_]u8{ 0x66, 0x0F, 0xD6, 0x5C, 0x24, 0x18 });

                            // 2. Push GPRs
                            try code.appendSlice(&[_]u8{ 0x51, 0x52, 0x41, 0x50, 0x41, 0x51 });

                            // 3. Setup args
                            try code.appendSlice(&[_]u8{ 0x48, 0x31, 0xC9 }); // xor rcx, rcx

                            // RDX = method_idx
                            try code.appendSlice(&[_]u8{ 0x48, 0xC7, 0xC2 });
                            var mi_bytes: [4]u8 = undefined;
                            std.mem.writeInt(i32, &mi_bytes, @intCast(v.method_idx), .little);
                            try code.appendSlice(&mi_bytes);

                            // R8 = dex_ptr
                            try code.appendSlice(&[_]u8{ 0x49, 0xB8 });
                            var dex_bytes: [8]u8 = undefined;
                            const dex_addr = if (dex) |d| @intFromPtr(d) else 0;
                            std.mem.writeInt(u64, &dex_bytes, dex_addr, .little);
                            try code.appendSlice(&dex_bytes);

                            // R9 = registry_ptr
                            try code.appendSlice(&[_]u8{ 0x49, 0xB9 });
                            var reg_bytes: [8]u8 = undefined;
                            const reg_addr = if (registry) |r| @intFromPtr(r) else 0;
                            std.mem.writeInt(u64, &reg_bytes, reg_addr, .little);
                            try code.appendSlice(&reg_bytes);

                            // Call resolveMethodVirtual
                            try code.appendSlice(&[_]u8{ 0x48, 0xB8 });
                            var fn_bytes: [8]u8 = undefined;
                            const fn_addr = @intFromPtr(&@import("class_loader").resolveMethodVirtual);
                            std.mem.writeInt(u64, &fn_bytes, fn_addr, .little);
                            try code.appendSlice(&fn_bytes);

                            try code.appendSlice(&[_]u8{ 0x48, 0x83, 0xEC, 0x20 });
                            try code.appendSlice(&[_]u8{ 0xFF, 0xD0 });
                            try code.appendSlice(&[_]u8{ 0x48, 0x83, 0xC4, 0x20 });

                            // Save result in R11
                            try code.appendSlice(&[_]u8{ 0x49, 0x89, 0xC3 });

                            // Restore GPRs
                            try code.appendSlice(&[_]u8{ 0x41, 0x59, 0x41, 0x58, 0x5A, 0x59 });

                            // Restore XMMs
                            try code.appendSlice(&[_]u8{ 0xF3, 0x0F, 0x7E, 0x04, 0x24 });
                            try code.appendSlice(&[_]u8{ 0xF3, 0x0F, 0x7E, 0x4C, 0x24, 0x08 });
                            try code.appendSlice(&[_]u8{ 0xF3, 0x0F, 0x7E, 0x54, 0x24, 0x10 });
                            try code.appendSlice(&[_]u8{ 0xF3, 0x0F, 0x7E, 0x5C, 0x24, 0x18 });
                            try code.appendSlice(&[_]u8{ 0x48, 0x83, 0xC4, 0x40 });

                            // Update inline cache with resolved target
                            // mov [rip + disp32], r11 -> 4C 89 1D <disp32>
                            try code.appendSlice(&[_]u8{ 0x4C, 0x89, 0x1D });
                            const target_update_idx = code.items.len;
                            try code.appendSlice(&[_]u8{ 0, 0, 0, 0 });
                            try late_patches.append(allocator, .{
                                .patch_type = .target_ptr,
                                .inst_offset = target_update_idx,
                                .next_inst_offset = code.items.len,
                                .ic_index = ic_idx,
                            });

                            // Guard against a null resolved target (unresolved method):
                            // test r11,r11; jz +3 skips the `call r11` so we degrade to
                            // a no-op instead of executing at address 0.
                            try code.appendSlice(&[_]u8{ 0x4D, 0x85, 0xDB }); // test r11, r11
                            try code.appendSlice(&[_]u8{ 0x74, 0x03 }); // jz +3 (over call r11)
                            // Call target
                            try code.appendSlice(&[_]u8{ 0x41, 0xFF, 0xD3 }); // call r11

                            // Patch jmp_done inline!
                            const done_offset = code.items.len;
                            const rel32 = @as(i32, @intCast(done_offset - (jmp_done_idx + 4)));
                            var patch_bytes: [4]u8 = undefined;
                            std.mem.writeInt(i32, &patch_bytes, rel32, .little);
                            for (patch_bytes, 0..) |pb, i| {
                                code.buf.items[jmp_done_idx + i] = pb;
                            }
                        } else {
                            // --- Monomorphic Cache: Virtual Call ---
                            // 0. Null check on receiver (rcx)
                            // test rcx, rcx -> 48 85 C9
                            try code.appendSlice(&[_]u8{ 0x48, 0x85, 0xC9 });
                            // jnz over the null error path (skip next 20 bytes: 48 c7 c0 addr (10) + and rsp -16 (4) + sub rsp 32 (4) + call rax (2))
                            // jnz -> 75 14
                            try code.appendSlice(&[_]u8{ 0x75, 0x14 });

                            // Null Pointer Exception path:
                            // mov rax, &throwNullPointerException
                            try code.appendSlice(&[_]u8{ 0x48, 0xB8 });
                            var npe_bytes: [8]u8 = undefined;
                            std.mem.writeInt(u64, &npe_bytes, @intFromPtr(&runtime.throwNullPointerException), .little);
                            try code.appendSlice(&npe_bytes);
                            // and rsp, -16
                            try code.appendSlice(&[_]u8{ 0x48, 0x83, 0xE4, 0xF0 });
                            // sub rsp, 32
                            try code.appendSlice(&[_]u8{ 0x48, 0x83, 0xEC, 0x20 });
                            // call rax
                            try code.appendSlice(&[_]u8{ 0xFF, 0xD0 });

                            // 1. Load receiver class_ptr: mov rax, [rcx - 16] -> 48 8B 41 F0
                            try code.appendSlice(&[_]u8{ 0x48, 0x8B, 0x41, 0xF0 });

                            // 2. Compare rax with cached_class (RIP-relative)
                            // cmp rax, [rip + disp32] -> 48 3B 05 <disp32>
                            try code.appendSlice(&[_]u8{ 0x48, 0x3B, 0x05 });
                            const class_patch_idx = code.items.len;
                            try code.appendSlice(&[_]u8{ 0, 0, 0, 0 });
                            try late_patches.append(allocator, .{
                                .patch_type = .class_ptr,
                                .inst_offset = class_patch_idx,
                                .next_inst_offset = code.items.len,
                                .ic_index = ic_idx,
                            });

                            // 3. jne cache_miss. Must skip: mov r11 (7) + test r11 (3)
                            //    + jz (2) + call r11 (3) + jmp done (5) = 20 bytes (0x14).
                            // jne -> 75 14
                            try code.appendSlice(&[_]u8{ 0x75, 0x14 });

                            // 4. Load cached_target into r11: mov r11, [rip + disp32] -> 4C 8B 1D <disp32>
                            try code.appendSlice(&[_]u8{ 0x4C, 0x8B, 0x1D });
                            const target_patch_idx = code.items.len;
                            try code.appendSlice(&[_]u8{ 0, 0, 0, 0 });
                            try late_patches.append(allocator, .{
                                .patch_type = .target_ptr,
                                .inst_offset = target_patch_idx,
                                .next_inst_offset = code.items.len,
                                .ic_index = ic_idx,
                            });

                            // 4b. Guard against a null/stale cached_target (e.g. a
                            //     zero-initialized IC matched a receiver whose class
                            //     pointer is also 0). test r11,r11; jz cache_miss.
                            //     jz must skip call r11 (3) + jmp done (5) = 8 (0x08).
                            try code.appendSlice(&[_]u8{ 0x4D, 0x85, 0xDB }); // test r11, r11
                            try code.appendSlice(&[_]u8{ 0x74, 0x08 }); // jz cache_miss

                            // 5. call r11 -> 41 FF D3
                            try code.appendSlice(&[_]u8{ 0x41, 0xFF, 0xD3 });

                            // 6. jmp done -> E9 <disp32>
                            try code.append(0xE9);
                            const jmp_done_idx = code.items.len;
                            try code.appendSlice(&[_]u8{ 0, 0, 0, 0 });

                            // --- Cache Miss / Slow Path ---
                            // 1. Save XMMs (64 bytes)
                            try code.appendSlice(&[_]u8{ 0x48, 0x83, 0xEC, 0x40 });
                            try code.appendSlice(&[_]u8{ 0x66, 0x0F, 0xD6, 0x04, 0x24 });
                            try code.appendSlice(&[_]u8{ 0x66, 0x0F, 0xD6, 0x4C, 0x24, 0x08 });
                            try code.appendSlice(&[_]u8{ 0x66, 0x0F, 0xD6, 0x54, 0x24, 0x10 });
                            try code.appendSlice(&[_]u8{ 0x66, 0x0F, 0xD6, 0x5C, 0x24, 0x18 });

                            // 2. Push GPRs
                            try code.appendSlice(&[_]u8{ 0x51, 0x52, 0x41, 0x50, 0x41, 0x51 });

                            // 3. Setup args for resolveMethodVirtual: mov rcx, [rsp+24]
                            try code.appendSlice(&[_]u8{ 0x48, 0x8B, 0x4C, 0x24, 0x18 });

                            // RDX = method_idx
                            try code.appendSlice(&[_]u8{ 0x48, 0xC7, 0xC2 });
                            var mi_bytes: [4]u8 = undefined;
                            std.mem.writeInt(i32, &mi_bytes, @intCast(v.method_idx), .little);
                            try code.appendSlice(&mi_bytes);

                            // R8 = dex_ptr
                            try code.appendSlice(&[_]u8{ 0x49, 0xB8 });
                            var dex_bytes: [8]u8 = undefined;
                            const dex_addr = if (dex) |d| @intFromPtr(d) else 0;
                            std.mem.writeInt(u64, &dex_bytes, dex_addr, .little);
                            try code.appendSlice(&dex_bytes);

                            // R9 = registry_ptr
                            try code.appendSlice(&[_]u8{ 0x49, 0xB9 });
                            var reg_bytes: [8]u8 = undefined;
                            const reg_addr = if (registry) |r| @intFromPtr(r) else 0;
                            std.mem.writeInt(u64, &reg_bytes, reg_addr, .little);
                            try code.appendSlice(&reg_bytes);

                            // Call resolveMethodVirtual
                            try code.appendSlice(&[_]u8{ 0x48, 0xB8 });
                            var fn_bytes: [8]u8 = undefined;
                            const fn_addr = @intFromPtr(&@import("class_loader").resolveMethodVirtual);
                            std.mem.writeInt(u64, &fn_bytes, fn_addr, .little);
                            try code.appendSlice(&fn_bytes);

                            try code.appendSlice(&[_]u8{ 0x48, 0x83, 0xEC, 0x20 });
                            try code.appendSlice(&[_]u8{ 0xFF, 0xD0 });
                            try code.appendSlice(&[_]u8{ 0x48, 0x83, 0xC4, 0x20 });

                            // Save result in R11
                            try code.appendSlice(&[_]u8{ 0x49, 0x89, 0xC3 });

                            // Restore GPRs
                            try code.appendSlice(&[_]u8{ 0x41, 0x59, 0x41, 0x58, 0x5A, 0x59 });

                            // Restore XMMs
                            try code.appendSlice(&[_]u8{ 0xF3, 0x0F, 0x7E, 0x04, 0x24 });
                            try code.appendSlice(&[_]u8{ 0xF3, 0x0F, 0x7E, 0x4C, 0x24, 0x08 });
                            try code.appendSlice(&[_]u8{ 0xF3, 0x0F, 0x7E, 0x54, 0x24, 0x10 });
                            try code.appendSlice(&[_]u8{ 0xF3, 0x0F, 0x7E, 0x5C, 0x24, 0x18 });
                            try code.appendSlice(&[_]u8{ 0x48, 0x83, 0xC4, 0x40 });

                            // Update inline cache: cached_class = [rcx - 16]
                            // Load class pointer into rax: mov rax, [rcx - 16] -> 48 8B 41 F0
                            try code.appendSlice(&[_]u8{ 0x48, 0x8B, 0x41, 0xF0 });

                            // Store class pointer into cached_class: mov [rip + disp32], rax -> 48 89 05 <disp32>
                            try code.appendSlice(&[_]u8{ 0x48, 0x89, 0x05 });
                            const class_update_idx = code.items.len;
                            try code.appendSlice(&[_]u8{ 0, 0, 0, 0 });
                            try late_patches.append(allocator, .{
                                .patch_type = .class_ptr,
                                .inst_offset = class_update_idx,
                                .next_inst_offset = code.items.len,
                                .ic_index = ic_idx,
                            });

                            // Store r11 into cached_target: mov [rip + disp32], r11 -> 4C 89 1D <disp32>
                            try code.appendSlice(&[_]u8{ 0x4C, 0x89, 0x1D });
                            const target_update_idx = code.items.len;
                            try code.appendSlice(&[_]u8{ 0, 0, 0, 0 });
                            try late_patches.append(allocator, .{
                                .patch_type = .target_ptr,
                                .inst_offset = target_update_idx,
                                .next_inst_offset = code.items.len,
                                .ic_index = ic_idx,
                            });

                            // Guard against a null resolved target (see static path).
                            try code.appendSlice(&[_]u8{ 0x4D, 0x85, 0xDB }); // test r11, r11
                            try code.appendSlice(&[_]u8{ 0x74, 0x03 }); // jz +3 (over call r11)
                            // Call target
                            try code.appendSlice(&[_]u8{ 0x41, 0xFF, 0xD3 }); // call r11

                            // Patch jmp_done inline!
                            const done_offset = code.items.len;
                            const rel32 = @as(i32, @intCast(done_offset - (jmp_done_idx + 4)));
                            var patch_bytes: [4]u8 = undefined;
                            std.mem.writeInt(i32, &patch_bytes, rel32, .little);
                            for (patch_bytes, 0..) |pb, i| {
                                code.buf.items[jmp_done_idx + i] = pb;
                            }
                        }
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
                .monitor_enter => |v| {
                    if (v.src == .reg) {
                        const s = regCode(v.src.reg);
                        if (s != 1) {
                            try code.append(makeRex(true, s, 1));
                            try code.append(0x89);
                            try code.append(makeModRM(0b11, @as(u3, @truncate(s)), 1));
                        }
                    } else if (v.src == .stack) {
                        const offset = v.src.stack;
                        try code.append(makeRex(true, 1, 5));
                        try code.append(0x8B);
                        if (offset >= -128 and offset <= 127) {
                            try code.append(makeModRM(0b01, 1, 5));
                            try code.append(@as(u8, @bitCast(@as(i8, @truncate(-offset)))));
                        } else {
                            try code.append(makeModRM(0b10, 1, 5));
                            var offset_bytes: [4]u8 = undefined;
                            std.mem.writeInt(i32, &offset_bytes, -offset, .little);
                            try code.appendSlice(&offset_bytes);
                        }
                    }

                    // MOV RAX, &monitorEnter
                    try code.append(0x48);
                    try code.append(0xB8);
                    var me_addr: [8]u8 = undefined;
                    std.mem.writeInt(u64, &me_addr, @intFromPtr(&runtime.monitorEnter), .little);
                    try code.appendSlice(&me_addr);
                    // sub rsp, 32  (Windows x64 shadow space)
                    try code.appendSlice(&[_]u8{ 0x48, 0x83, 0xEC, 0x20 });
                    // CALL RAX
                    try code.append(0xFF);
                    try code.append(0xD0);
                    // add rsp, 32
                    try code.appendSlice(&[_]u8{ 0x48, 0x83, 0xC4, 0x20 });
                },
                .monitor_exit => |v| {
                    if (v.src == .reg) {
                        const s = regCode(v.src.reg);
                        if (s != 1) {
                            try code.append(makeRex(true, s, 1));
                            try code.append(0x89);
                            try code.append(makeModRM(0b11, @as(u3, @truncate(s)), 1));
                        }
                    } else if (v.src == .stack) {
                        const offset = v.src.stack;
                        try code.append(makeRex(true, 1, 5));
                        try code.append(0x8B);
                        if (offset >= -128 and offset <= 127) {
                            try code.append(makeModRM(0b01, 1, 5));
                            try code.append(@as(u8, @bitCast(@as(i8, @truncate(-offset)))));
                        } else {
                            try code.append(makeModRM(0b10, 1, 5));
                            var offset_bytes: [4]u8 = undefined;
                            std.mem.writeInt(i32, &offset_bytes, -offset, .little);
                            try code.appendSlice(&offset_bytes);
                        }
                    }

                    // MOV RAX, &monitorExit
                    try code.append(0x48);
                    try code.append(0xB8);
                    var mex_addr: [8]u8 = undefined;
                    std.mem.writeInt(u64, &mex_addr, @intFromPtr(&runtime.monitorExit), .little);
                    try code.appendSlice(&mex_addr);
                    // sub rsp, 32  (Windows x64 shadow space)
                    try code.appendSlice(&[_]u8{ 0x48, 0x83, 0xEC, 0x20 });
                    // CALL RAX
                    try code.append(0xFF);
                    try code.append(0xD0);
                    // add rsp, 32
                    try code.appendSlice(&[_]u8{ 0x48, 0x83, 0xC4, 0x20 });
                },
                .alloc_arr => |v| {
                    // Determine element size from type_names at JIT-compile time
                    var elem_size: usize = 4;
                    if (dex != null and v.type_idx < dex.?.type_names.len) {
                        const tname = dex.?.type_names[v.type_idx];
                        if (tname.len > 1) {
                            elem_size = switch (tname[1]) {
                                'J', 'D' => 8,
                                'I', 'F' => 4,
                                'S', 'C' => 2,
                                'B', 'Z' => 1,
                                'L', '[' => 8,
                                else => 8,
                            };
                        }
                    }

                    // MOV RCX, size_reg  (arg1: count)
                    if (v.size == .reg) {
                        const s = regCode(v.size.reg);
                        if (s != 1) { // rcx = 1
                            try code.append(makeRex(true, s, 1));
                            try code.append(0x89);
                            try code.append(makeModRM(0b11, @as(u3, @truncate(s)), 1));
                        }
                    } else if (v.size == .stack) {
                        const offset = v.size.stack;
                        try code.append(makeRex(true, 1, 5));
                        try code.append(0x8B);
                        if (offset >= -128 and offset <= 127) {
                            try code.append(makeModRM(0b01, 1, 5));
                            try code.append(@as(u8, @bitCast(@as(i8, @truncate(-offset)))));
                        } else {
                            try code.append(makeModRM(0b10, 1, 5));
                            var offset_bytes: [4]u8 = undefined;
                            std.mem.writeInt(i32, &offset_bytes, -offset, .little);
                            try code.appendSlice(&offset_bytes);
                        }
                    }

                    // MOV EDX, elem_size  (arg2: element size, zero-extended)
                    try code.append(0xBA); // MOV edx, imm32
                    var es_bytes: [4]u8 = undefined;
                    std.mem.writeInt(u32, &es_bytes, @as(u32, @intCast(elem_size)), .little);
                    try code.appendSlice(&es_bytes);

                    // MOV RAX, &runtime.gcAllocArray
                    try code.append(0x48);
                    try code.append(0xB8);
                    var fn_bytes: [8]u8 = undefined;
                    std.mem.writeInt(u64, &fn_bytes, @intFromPtr(&runtime.gcAllocArray), .little);
                    try code.appendSlice(&fn_bytes);
                    // CALL RAX
                    try code.append(0xFF);
                    try code.append(0xD0);

                    // MOV dest, RAX
                    if (v.dest == .reg) {
                        const d = regCode(v.dest.reg);
                        if (d != 0) { // rax = 0
                            try code.append(makeRex(true, 0, d));
                            try code.append(0x89);
                            try code.append(makeModRM(0b11, 0, @as(u3, @truncate(d))));
                        }
                    } else if (v.dest == .stack) {
                        // MOV [rbp - offset], rax
                        const off2 = v.dest.stack;
                        try code.append(makeRex(true, 0, 5));
                        try code.append(0x89);
                        if (off2 >= -128 and off2 <= 127) {
                            try code.append(makeModRM(0b01, 0, 5));
                            try code.append(@as(u8, @bitCast(@as(i8, @truncate(-off2)))));
                        } else {
                            try code.append(makeModRM(0b10, 0, 5));
                            var off_bytes: [4]u8 = undefined;
                            std.mem.writeInt(i32, &off_bytes, -off2, .little);
                            try code.appendSlice(&off_bytes);
                        }
                    }
                },
                .alloc_obj => |v| {
                    if (v.is_stack) {
                        const emitMovRegToStack = struct {
                            fn f(c: *CodeWriter, src: u4, off: i32) !void {
                                const disp = -off;
                                try c.append(makeRex(true, @intCast(src >> 3), 0));
                                try c.append(0x89);
                                const reg_part = @as(u3, @truncate(src));
                                if (disp >= -128 and disp <= 127) {
                                    try c.append(makeModRM(0b01, reg_part, 5));
                                    try c.append(@as(u8, @bitCast(@as(i8, @truncate(disp)))));
                                } else {
                                    try c.append(makeModRM(0b10, reg_part, 5));
                                    var off_bytes: [4]u8 = undefined;
                                    std.mem.writeInt(i32, &off_bytes, disp, .little);
                                    try c.appendSlice(&off_bytes);
                                }
                            }
                        }.f;

                        const emitLeaStackToReg = struct {
                            fn f(c: *CodeWriter, dest: u4, off: i32, adjust: i32) !void {
                                const disp = -off + adjust;
                                try c.append(makeRex(true, @intCast(dest >> 3), 0));
                                try c.append(0x8D);
                                const reg_part = @as(u3, @truncate(dest));
                                if (disp >= -128 and disp <= 127) {
                                    try c.append(makeModRM(0b01, reg_part, 5));
                                    try c.append(@as(u8, @bitCast(@as(i8, @truncate(disp)))));
                                } else {
                                    try c.append(makeModRM(0b10, reg_part, 5));
                                    var off_bytes: [4]u8 = undefined;
                                    std.mem.writeInt(i32, &off_bytes, disp, .little);
                                    try c.appendSlice(&off_bytes);
                                }
                            }
                        }.f;

                        var class_ptr: usize = 0;
                        if (registry != null and dex != null and v.type_idx < dex.?.type_names.len) {
                            const tname = dex.?.type_names[v.type_idx];
                            if (registry.?.get(tname)) |cd| {
                                class_ptr = @intFromPtr(cd);
                            }
                        }

                        // 1. mov rax, class_ptr
                        try code.append(0x48);
                        try code.append(0xB8);
                        var class_bytes: [8]u8 = undefined;
                        std.mem.writeInt(u64, &class_bytes, class_ptr, .little);
                        try code.appendSlice(&class_bytes);

                        // 2. mov [rbp - (v.stack_offset + v.size)], rax (class_ptr)
                        try emitMovRegToStack(&code, 0, v.stack_offset + @as(i32, @intCast(v.size)));

                        // 3. xor rax, rax
                        try code.appendSlice(&[_]u8{ 0x48, 0x31, 0xC0 });

                        // 4. mov [rbp - (v.stack_offset + v.size - 8)], rax (monitor = 0)
                        try emitMovRegToStack(&code, 0, v.stack_offset + @as(i32, @intCast(v.size)) - 8);

                        // 5. Zero out fields (body starts at v.stack_offset + v.size - 16)
                        var zero_off: i32 = 16;
                        while (zero_off < v.size) : (zero_off += 8) {
                            try emitMovRegToStack(&code, 0, v.stack_offset + @as(i32, @intCast(v.size)) - zero_off);
                        }

                        // 6. lea rax, [rbp - (v.stack_offset + v.size - 16)] (object reference)
                        try emitLeaStackToReg(&code, 0, v.stack_offset + @as(i32, @intCast(v.size)), 16);
                    } else {
                        // Resolve the class so the object carries a real class_ptr in
                        // its header (needed for virtual dispatch) and is allocated at
                        // the class's true instance_size. Falling back to class_ptr=0
                        // / fields*8 left objects unclassed and under-allocated (e.g.
                        // StringBuilder's 4KB native layout), which corrupted the heap
                        // and broke virtual method resolution on the result.
                        var class_ptr: usize = 0;
                        var obj_size: usize = 8;
                        if (registry != null and dex != null and v.type_idx < dex.?.type_names.len) {
                            const tname = dex.?.type_names[v.type_idx];
                            if (registry.?.get(tname)) |cd| {
                                class_ptr = @intFromPtr(cd);
                                obj_size = cd.instance_size;
                                if (obj_size == 0) obj_size = cd.instance_fields.len * 8;
                                if (obj_size == 0) obj_size = 8;
                            }
                        }

                        // MOV RCX, class_ptr
                        try code.append(0x48);
                        try code.append(0xB9);
                        var class_bytes: [8]u8 = undefined;
                        std.mem.writeInt(u64, &class_bytes, class_ptr, .little);
                        try code.appendSlice(&class_bytes);

                        // MOV RDX, obj_size
                        try code.append(0x48);
                        try code.append(0xBA);
                        var sz_bytes: [8]u8 = undefined;
                        std.mem.writeInt(u64, &sz_bytes, obj_size, .little);
                        try code.appendSlice(&sz_bytes);

                        // MOV RAX, &runtime.gcAllocObj
                        try code.append(0x48);
                        try code.append(0xB8);
                        var fn_bytes: [8]u8 = undefined;
                        std.mem.writeInt(u64, &fn_bytes, @intFromPtr(&runtime.gcAllocObj), .little);
                        try code.appendSlice(&fn_bytes);
                        // CALL RAX
                        try code.append(0xFF);
                        try code.append(0xD0);
                    }

                    // MOV dest, RAX
                    if (v.dest == .reg) {
                        const d = regCode(v.dest.reg);
                        if (d != 0) {
                            try code.append(makeRex(true, 0, d));
                            try code.append(0x89);
                            try code.append(makeModRM(0b11, 0, @as(u3, @truncate(d))));
                        }
                    } else if (v.dest == .stack) {
                        const off2 = v.dest.stack;
                        try code.append(makeRex(true, 0, 5));
                        try code.append(0x89);
                        if (off2 >= -128 and off2 <= 127) {
                            try code.append(makeModRM(0b01, 0, 5));
                            try code.append(@as(u8, @bitCast(@as(i8, @truncate(-off2)))));
                        } else {
                            try code.append(makeModRM(0b10, 0, 5));
                            var off_bytes: [4]u8 = undefined;
                            std.mem.writeInt(i32, &off_bytes, -off2, .little);
                            try code.appendSlice(&off_bytes);
                        }
                    }
                },
                .new_string => |v| {
                    // Resolve the string-pool entry now (bytes live in the stable DEX
                    // buffer) and pass gcNewString(value_ptr, length) -> String in RAX.
                    var value_ptr: usize = 0;
                    var str_len: i32 = 0;
                    if (dex) |d| {
                        if (v.str_idx < d.string_pool.len) {
                            const s = d.string_pool[v.str_idx];
                            value_ptr = @intFromPtr(s.ptr);
                            str_len = @intCast(s.len);
                        }
                    }
                    // Shadow space for the callee (Windows x64).
                    try code.appendSlice(&[_]u8{ 0x48, 0x83, 0xEC, 0x20 }); // sub rsp, 0x20
                    // MOV RCX, value_ptr
                    try code.append(0x48);
                    try code.append(0xB9);
                    var vp_bytes: [8]u8 = undefined;
                    std.mem.writeInt(u64, &vp_bytes, value_ptr, .little);
                    try code.appendSlice(&vp_bytes);
                    // MOV EDX, length (zero/sign fits in 32; length is non-negative)
                    try code.append(0xBA);
                    var idx_bytes: [4]u8 = undefined;
                    std.mem.writeInt(i32, &idx_bytes, str_len, .little);
                    try code.appendSlice(&idx_bytes);
                    // MOV RAX, &gcNewString ; CALL RAX
                    try code.append(0x48);
                    try code.append(0xB8);
                    var fn_bytes: [8]u8 = undefined;
                    std.mem.writeInt(u64, &fn_bytes, @intFromPtr(&runtime.gcNewString), .little);
                    try code.appendSlice(&fn_bytes);
                    try code.appendSlice(&[_]u8{ 0xFF, 0xD0 }); // call rax
                    try code.appendSlice(&[_]u8{ 0x48, 0x83, 0xC4, 0x20 }); // add rsp, 0x20
                    // MOV dest, RAX
                    if (v.dest == .reg) {
                        const d = regCode(v.dest.reg);
                        if (d != 0) {
                            try code.append(makeRex(true, 0, d));
                            try code.append(0x89);
                            try code.append(makeModRM(0b11, 0, @as(u3, @truncate(d))));
                        }
                    } else if (v.dest == .stack) {
                        const off2 = v.dest.stack;
                        try code.append(makeRex(true, 0, 5));
                        try code.append(0x89);
                        if (off2 >= -128 and off2 <= 127) {
                            try code.append(makeModRM(0b01, 0, 5));
                            try code.append(@as(u8, @bitCast(@as(i8, @truncate(-off2)))));
                        } else {
                            try code.append(makeModRM(0b10, 0, 5));
                            var off_bytes: [4]u8 = undefined;
                            std.mem.writeInt(i32, &off_bytes, -off2, .little);
                            try code.appendSlice(&off_bytes);
                        }
                    }
                },
                .instance_of => |v| {
                    if (v.obj == .reg) {
                        const s = regCode(v.obj.reg);
                        if (s != 1) { // RCX
                            try code.append(makeRex(true, s, 1));
                            try code.append(0x89);
                            try code.append(makeModRM(0b11, 1, @as(u3, @truncate(s))));
                        }
                    } else if (v.obj == .stack) {
                        try code.append(makeRex(true, 1, 5));
                        try code.append(0x8B);
                        try emitMemModRM(&code, 1, .{ .base = .{ .stack = 0 }, .disp = -v.obj.stack });
                    }
                    try code.append(0x48);
                    try code.append(0xBA);
                    var idx_bytes: [8]u8 = undefined;
                    std.mem.writeInt(u64, &idx_bytes, v.type_idx, .little);
                    try code.appendSlice(&idx_bytes);

                    try code.append(0x48);
                    try code.append(0xB8);
                    var fn_bytes: [8]u8 = undefined;
                    std.mem.writeInt(u64, &fn_bytes, @intFromPtr(&runtime.gcInstanceOf), .little);
                    try code.appendSlice(&fn_bytes);
                    try code.append(0xFF);
                    try code.append(0xD0);

                    if (v.dest == .reg) {
                        const d = regCode(v.dest.reg);
                        if (d != 0) {
                            try code.append(makeRex(true, 0, d));
                            try code.append(0x89);
                            try code.append(makeModRM(0b11, 0, @as(u3, @truncate(d))));
                        }
                    } else if (v.dest == .stack) {
                        try code.append(makeRex(true, 0, 5));
                        try code.append(0x89);
                        try emitMemModRM(&code, 0, .{ .base = .{ .stack = 0 }, .disp = -v.dest.stack });
                    }
                },
                .move_exception => |v| {
                    try code.append(0x48);
                    try code.append(0xB8);
                    var fn_bytes: [8]u8 = undefined;
                    std.mem.writeInt(u64, &fn_bytes, @intFromPtr(&runtime.gcGetAndClearException), .little);
                    try code.appendSlice(&fn_bytes);
                    try code.append(0xFF);
                    try code.append(0xD0);

                    if (v.dest == .reg) {
                        const d = regCode(v.dest.reg);
                        if (d != 0) {
                            try code.append(makeRex(true, 0, d));
                            try code.append(0x89);
                            try code.append(makeModRM(0b11, 0, @as(u3, @truncate(d))));
                        }
                    } else if (v.dest == .stack) {
                        try code.append(makeRex(true, 0, 5));
                        try code.append(0x89);
                        try emitMemModRM(&code, 0, .{ .base = .{ .stack = 0 }, .disp = -v.dest.stack });
                    }
                },
                .fill_array_data => |v| {
                    if (v.array == .reg) {
                        const s = regCode(v.array.reg);
                        if (s != 1) { // RCX
                            try code.append(makeRex(true, s, 1));
                            try code.append(0x89);
                            try code.append(makeModRM(0b11, 1, @as(u3, @truncate(s))));
                        }
                    } else if (v.array == .stack) {
                        try code.append(makeRex(true, 1, 5));
                        try code.append(0x8B);
                        try emitMemModRM(&code, 1, .{ .base = .{ .stack = 0 }, .disp = -v.array.stack });
                    }
                    // RDX: data_ptr
                    try code.append(0x48);
                    try code.append(0xBA);
                    var ptr_bytes: [8]u8 = undefined;
                    std.mem.writeInt(u64, &ptr_bytes, v.data_ptr, .little);
                    try code.appendSlice(&ptr_bytes);
                    // R8: data_len
                    try code.append(0x49);
                    try code.append(0xB8);
                    var len_bytes: [8]u8 = undefined;
                    std.mem.writeInt(u64, &len_bytes, v.data_len, .little);
                    try code.appendSlice(&len_bytes);
                    // R9: elem_width
                    try code.append(0x49);
                    try code.append(0xB9);
                    var wid_bytes: [8]u8 = undefined;
                    std.mem.writeInt(u64, &wid_bytes, v.elem_width, .little);
                    try code.appendSlice(&wid_bytes);

                    try code.append(0x48);
                    try code.append(0xB8);
                    var fn_bytes: [8]u8 = undefined;
                    std.mem.writeInt(u64, &fn_bytes, @intFromPtr(&runtime.gcFillArrayData), .little);
                    try code.appendSlice(&fn_bytes);
                    try code.append(0xFF);
                    try code.append(0xD0);
                },
                .filled_new_array => |v| {
                    var elem_size: usize = 4;
                    if (dex != null and v.type_idx < dex.?.type_names.len) {
                        const tname = dex.?.type_names[v.type_idx];
                        if (tname.len > 1) {
                            elem_size = switch (tname[1]) {
                                'J', 'D' => 8,
                                'I', 'F' => 4,
                                'S', 'C' => 2,
                                'B', 'Z' => 1,
                                'L', '[' => 8,
                                else => 8,
                            };
                        }
                    }
                    var active_args: u32 = 0;
                    for (v.args) |a| if (a != null) {
                        active_args += 1;
                    };

                    // RCX: size
                    try code.append(0x48);
                    try code.append(0xB9);
                    var sz_bytes: [8]u8 = undefined;
                    std.mem.writeInt(u64, &sz_bytes, active_args, .little);
                    try code.appendSlice(&sz_bytes);

                    // RDX: elem_size
                    try code.append(0x48);
                    try code.append(0xBA);
                    var esz_bytes: [8]u8 = undefined;
                    std.mem.writeInt(u64, &esz_bytes, elem_size, .little);
                    try code.appendSlice(&esz_bytes);

                    try code.append(0x48);
                    try code.append(0xB8);
                    var fn_bytes: [8]u8 = undefined;
                    std.mem.writeInt(u64, &fn_bytes, @intFromPtr(&runtime.gcAllocArray), .little);
                    try code.appendSlice(&fn_bytes);
                    try code.append(0xFF);
                    try code.append(0xD0);

                    // Move RAX to dest (array ref)
                    if (v.dest == .reg) {
                        const d = regCode(v.dest.reg);
                        if (d != 0) {
                            try code.append(makeRex(true, 0, d));
                            try code.append(0x89);
                            try code.append(makeModRM(0b11, 0, @as(u3, @truncate(d))));
                        }
                    } else if (v.dest == .stack) {
                        try code.append(makeRex(true, 0, 5));
                        try code.append(0x89);
                        try emitMemModRM(&code, 0, .{ .base = .{ .stack = 0 }, .disp = -v.dest.stack });
                    }

                    // For each arg, MOV it into [RAX + 16 + i*elem_size]
                    // Wait, RAX is the array ptr. If we overwrote RAX, we can't use it!
                    // Let's store RAX to R11.
                    try code.append(0x49);
                    try code.append(0x89);
                    try code.append(0xC3); // MOV R11, RAX

                    for (v.args, 0..) |arg, i| {
                        if (arg) |a| {
                            const offset = @as(i32, @intCast(8 + i * elem_size));
                            // MOV R10, arg
                            if (a == .reg) {
                                const s = regCode(a.reg);
                                try code.append(makeRex(true, s, 2)); // R10 is 2 in high bits
                                try code.append(0x89);
                                try code.append(makeModRM(0b11, 2, @as(u3, @truncate(s))));
                            } else if (a == .stack) {
                                try code.append(makeRex(true, 2, 5));
                                try code.append(0x8B);
                                try emitMemModRM(&code, 2, .{ .base = .{ .stack = 0 }, .disp = -a.stack });
                            }
                            // MOV [R11 + offset], R10
                            // MOV [R11 + offset], R10
                            try code.append(makeRexSib(true, 2, 3, 0)); // R10 = 2, R11 = 3
                            try code.append(0x89);
                            try emitMemModRM(&code, 2, .{ .base = .{ .reg = .r11 }, .disp = offset });
                        }
                    }
                },
                .field_load => |v| {
                    if (v.obj) |obj_op| {
                        var offset: i32 = 0;
                        if (registry != null and dex != null) {
                            const fi = dex.?.field_items[v.field_idx];
                            if (registry.?.get(fi.class_name)) |cd| {
                                if (cd.fieldOffset(fi.field_name)) |off| {
                                    offset = @as(i32, @intCast(off));
                                }
                            }
                        }
                        // Load from [obj_op + offset] into r10 first
                        const b = regCode(obj_op.reg);
                        // MOV r10, [obj + offset]  (r10 = 10)
                        try code.append(makeRexSib(true, 10, b, 0));
                        try code.append(0x8B);
                        try emitMemModRM(&code, 2, .{ .base = .{ .reg = obj_op.reg }, .disp = offset }); // r10 low3 = 2
                        // Write r10 to dest
                        if (v.dest == .reg) {
                            const d = regCode(v.dest.reg);
                            if (d != 10) {
                                try code.append(makeRex(true, 10, d));
                                try code.append(0x89);
                                try code.append(makeModRM(0b11, 2, @as(u3, @truncate(d))));
                            }
                        } else if (v.dest == .stack) {
                            const off2 = v.dest.stack;
                            // MOV [rbp - off2], r10
                            try code.append(0x4C); // REX.W + REX.R(r10)
                            try code.append(0x89);
                            if (off2 >= -128 and off2 <= 127) {
                                try code.append(makeModRM(0b01, 2, 5));
                                try code.append(@as(u8, @bitCast(@as(i8, @truncate(-off2)))));
                            } else {
                                try code.append(makeModRM(0b10, 2, 5));
                                var bytes: [4]u8 = undefined;
                                std.mem.writeInt(i32, &bytes, -off2, .little);
                                try code.appendSlice(&bytes);
                            }
                        }
                    } else {
                        // Static field load
                        var static_ptr: usize = 0;
                        if (registry != null and dex != null) {
                            const fi = dex.?.field_items[v.field_idx];
                            if (registry.?.get(fi.class_name)) |cd| {
                                for (cd.static_fields, 0..) |f, i| {
                                    if (std.mem.eql(u8, f.name, fi.field_name)) {
                                        static_ptr = @intFromPtr(&cd.static_values[i]);
                                        break;
                                    }
                                }
                            }
                        }
                        // MOV R11, static_ptr (imm64)
                        try code.appendSlice(&[_]u8{ 0x49, 0xBB });
                        var ptr_bytes: [8]u8 = undefined;
                        std.mem.writeInt(u64, &ptr_bytes, static_ptr, .little);
                        try code.appendSlice(&ptr_bytes);
                        // MOV r10, [R11]
                        try code.appendSlice(&[_]u8{ 0x4D, 0x8B, 0x13 }); // REX.W+R+B, MOV r10,[r11] mod=00,r10=2,r11=3
                        // Write r10 to dest
                        if (v.dest == .reg) {
                            const d = regCode(v.dest.reg);
                            if (d != 10) {
                                try code.append(makeRex(true, 10, d));
                                try code.append(0x89);
                                try code.append(makeModRM(0b11, 2, @as(u3, @truncate(d))));
                            }
                        } else if (v.dest == .stack) {
                            const off2 = v.dest.stack;
                            try code.append(0x4C);
                            try code.append(0x89);
                            if (off2 >= -128 and off2 <= 127) {
                                try code.append(makeModRM(0b01, 2, 5));
                                try code.append(@as(u8, @bitCast(@as(i8, @truncate(-off2)))));
                            } else {
                                try code.append(makeModRM(0b10, 2, 5));
                                var bytes: [4]u8 = undefined;
                                std.mem.writeInt(i32, &bytes, -off2, .little);
                                try code.appendSlice(&bytes);
                            }
                        }
                    }
                },
                .field_store => |v| {
                    // Load src into r10 first
                    if (v.src == .reg) {
                        const s = regCode(v.src.reg);
                        if (s != 10) {
                            try code.append(makeRex(true, s, 10));
                            try code.append(0x89);
                            try code.append(makeModRM(0b11, @as(u3, @truncate(s)), 2)); // r10 low3 = 2
                        }
                    } else if (v.src == .stack) {
                        const off2 = v.src.stack;
                        try code.append(0x4C);
                        try code.append(0x8B);
                        if (off2 >= -128 and off2 <= 127) {
                            try code.append(makeModRM(0b01, 2, 5));
                            try code.append(@as(u8, @bitCast(@as(i8, @truncate(-off2)))));
                        } else {
                            try code.append(makeModRM(0b10, 2, 5));
                            var bytes: [4]u8 = undefined;
                            std.mem.writeInt(i32, &bytes, -off2, .little);
                            try code.appendSlice(&bytes);
                        }
                    }
                    if (v.obj) |obj_op| {
                        var offset: i32 = 0;
                        if (registry != null and dex != null) {
                            const fi = dex.?.field_items[v.field_idx];
                            if (registry.?.get(fi.class_name)) |cd| {
                                if (cd.fieldOffset(fi.field_name)) |off| {
                                    offset = @as(i32, @intCast(off));
                                }
                            }
                        }
                        // MOV [obj + offset], r10
                        const b = regCode(obj_op.reg);
                        try code.append(makeRexSib(true, 10, b, 0));
                        try code.append(0x89);
                        try emitMemModRM(&code, 2, .{ .base = .{ .reg = obj_op.reg }, .disp = offset });
                    } else {
                        // Static field store
                        var static_ptr: usize = 0;
                        if (registry != null and dex != null) {
                            const fi = dex.?.field_items[v.field_idx];
                            if (registry.?.get(fi.class_name)) |cd| {
                                for (cd.static_fields, 0..) |f, i| {
                                    if (std.mem.eql(u8, f.name, fi.field_name)) {
                                        static_ptr = @intFromPtr(&cd.static_values[i]);
                                        break;
                                    }
                                }
                            }
                        }
                        // MOV R11, static_ptr (imm64)
                        try code.appendSlice(&[_]u8{ 0x49, 0xBB });
                        var ptr_bytes: [8]u8 = undefined;
                        std.mem.writeInt(u64, &ptr_bytes, static_ptr, .little);
                        try code.appendSlice(&ptr_bytes);
                        // MOV [R11], r10  (r10=2, r11=3, REX.W+R+B)
                        try code.appendSlice(&[_]u8{ 0x4D, 0x89, 0x13 });
                    }
                },
                .bounds_check => |v| {
                    const loadOperand = struct {
                        fn f(cd: *CodeWriter, op: x86.Operand, reg: x86.PhysicalReg, is_32: bool) !x86.PhysicalReg {
                            switch (op) {
                                .reg => |r| return r,
                                .stack => |offset| {
                                    const d = regCode(reg);
                                    const rex = makeRex(!is_32, d, 5); // RBP is 5
                                    try cd.append(rex);
                                    try cd.append(0x8B); // MOV r, r/m
                                    if (offset >= -128 and offset <= 127) {
                                        try cd.append(makeModRM(0b01, @as(u3, @truncate(d)), 5));
                                        try cd.append(@as(u8, @bitCast(@as(i8, @truncate(-offset)))));
                                    } else {
                                        try cd.append(makeModRM(0b10, @as(u3, @truncate(d)), 5));
                                        var bytes: [4]u8 = undefined;
                                        std.mem.writeInt(i32, &bytes, -offset, .little);
                                        try cd.appendSlice(&bytes);
                                    }
                                    return reg;
                                },
                                else => unreachable,
                            }
                        }
                    }.f;

                    const arr_reg = try loadOperand(&code, v.array, .r11, false);
                    const idx_reg = try loadOperand(&code, v.index, .r10, true);

                    // mov eax, [arr_reg + 0] (load length)
                    const arr_code = regCode(arr_reg);
                    const eax_code = regCode(.rax);
                    const load_len_rex = makeRex(false, eax_code, arr_code);
                    if (load_len_rex != 0x40) try code.append(load_len_rex);
                    try code.append(0x8B);
                    try code.append(makeModRM(0b01, @as(u3, @truncate(eax_code)), @as(u3, @truncate(arr_code))));
                    try code.append(0);

                    // cmp idx_reg, eax
                    const idx_code = regCode(idx_reg);
                    const cmp_rex = makeRex(false, eax_code, idx_code);
                    if (cmp_rex != 0x40) try code.append(cmp_rex);
                    try code.append(0x39);
                    try code.append(makeModRM(0b11, @as(u3, @truncate(eax_code)), @as(u3, @truncate(idx_code))));

                    // jb short (0x72) to safe path
                    try code.append(0x72);
                    const jb_patch_idx = code.items.len;
                    try code.append(0); // placeholder

                    const fail_start = code.items.len;

                    // mov ecx, idx_reg
                    if (idx_reg != .rcx) {
                        const ecx_code = regCode(.rcx);
                        const mov1_rex = makeRex(false, idx_code, ecx_code);
                        if (mov1_rex != 0x40) try code.append(mov1_rex);
                        try code.append(0x89);
                        try code.append(makeModRM(0b11, @as(u3, @truncate(idx_code)), @as(u3, @truncate(ecx_code))));
                    }

                    // mov edx, eax
                    {
                        const edx_code = regCode(.rdx);
                        const mov2_rex = makeRex(false, eax_code, edx_code);
                        if (mov2_rex != 0x40) try code.append(mov2_rex);
                        try code.append(0x89);
                        try code.append(makeModRM(0b11, @as(u3, @truncate(eax_code)), @as(u3, @truncate(edx_code))));
                    }

                    // and rsp, -16
                    try code.appendSlice(&[_]u8{ 0x48, 0x83, 0xE4, 0xF0 });

                    // sub rsp, 32
                    try code.appendSlice(&[_]u8{ 0x48, 0x83, 0xEC, 0x20 });

                    // mov rax, &throwIndexOutOfBounds
                    try code.appendSlice(&[_]u8{ 0x48, 0xB8 });
                    var addr_bytes: [8]u8 = undefined;
                    std.mem.writeInt(u64, &addr_bytes, @intFromPtr(&runtime.throwIndexOutOfBounds), .little);
                    try code.appendSlice(&addr_bytes);

                    // call rax
                    try code.appendSlice(&[_]u8{ 0xFF, 0xD0 });

                    const fail_end = code.items.len;
                    const offset = fail_end - fail_start;
                    code.items[jb_patch_idx] = @intCast(offset);
                },
                else => {
                    std.debug.print("Unsupported instruction: {s}\n", .{@tagName(inst)});
                    return EmitterError.UnsupportedInstruction;
                },
            }
        }
    }

    // Trampoline removed for Asymmetric Dekker safepoints
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
            code.buf.items[reloc.patch_offset + i] = b;
        }
    }

    // --- Emit Inline Cache slots ---
    if (num_inline_caches > 0) {
        const ic_start_pos = code.items.len;
        const aligned_ic_start = std.mem.alignForward(usize, ic_start_pos, 8);
        var pad_i: usize = 0;
        while (pad_i < (aligned_ic_start - ic_start_pos)) : (pad_i += 1) {
            try code.append(0);
        }
        const ic_base = code.items.len;
        for (0..num_inline_caches) |_| {
            // 8 bytes for cached_class (0)
            try code.appendSlice(&[_]u8{0} ** 8);
            // 8 bytes for cached_target (0)
            try code.appendSlice(&[_]u8{0} ** 8);
        }

        // --- Resolve Late Patches ---
        for (late_patches.items) |lp| {
            const slot_offset = ic_base + lp.ic_index * 16 + (if (lp.patch_type == .target_ptr) @as(usize, 8) else @as(usize, 0));
            const rel32 = @as(i32, @intCast(slot_offset - lp.next_inst_offset));
            var patch_bytes: [4]u8 = undefined;
            std.mem.writeInt(i32, &patch_bytes, rel32, .little);
            for (patch_bytes, 0..) |pb, i| {
                code.buf.items[lp.inst_offset + i] = pb;
            }
        }
    }

    // Serialize GcMapTable at the end of the code buffer
    if (dex != null) {
        var gc_map_offset: u32 = 0;
        if (local_gc_builder.entries.items.len > 0) {
            const start_pos = code.items.len;
            const aligned_start = std.mem.alignForward(usize, start_pos, @alignOf(@import("gc_map").GcEntry));
            const padding = aligned_start - start_pos;
            var i: usize = 0;
            while (i < padding) : (i += 1) {
                try code.append(0);
            }

            gc_map_offset = @intCast(code.items.len);
            const size = local_gc_builder.serializedSize();
            const old_len = code.items.len;
            try code.buf.resize(allocator, old_len + size);
            code.updateItems();

            _ = local_gc_builder.serialize(code.items[old_len .. old_len + size]);
        }

        // Append gc_map_offset u32 at the very end
        var offset_bytes: [4]u8 = undefined;
        std.mem.writeInt(u32, &offset_bytes, gc_map_offset, .little);
        try code.appendSlice(&offset_bytes);
    }

    return code.toOwnedSlice();
}

// â”€â”€ Unit Tests â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€

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

    const bytes = try emitProgram(a, &prog, null, null);
    defer a.free(bytes);

    // Expected machine bytes:
    // MOV RAX, 42  -> 48 B8 2A 00 00 00 00 00 00 00
    // ADD RAX, RBX -> 48 01 D8
    // RET          -> C3
    const expected = [_]u8{
        0x55,
        0x48,
        0x89,
        0xE5,
        0x53, // push rbx
        0x48, 0x83, 0xEC, 0x08, // sub rsp, 8
        0x48, 0xB8, 0x2A, 0x00,
        0x00, 0x00, 0x00, 0x00,
        0x00, 0x00, 0x48, 0x01,
        0xD8,
        0x48, 0x83, 0xC4, 0x08, // add rsp, 8
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

    const bytes = try emitProgram(a, &prog, null, null);
    defer a.free(bytes);

    // Expected:
    // push r15       -> 41 57
    // sub rsp, 8     -> 48 83 EC 08
    // mov r8, 2      -> 49 B8 02 00 00 00 00 00 00 00
    // mov r15, 10    -> 49 BF 0A 00 00 00 00 00 00 00
    // add rsp, 8     -> 48 83 C4 08
    // pop r15        -> 41 5F
    // ret            -> C3
    const expected = [_]u8{
        0x55,
        0x48,
        0x89,
        0xE5,
        0x41,
        0x57,
        0x48,
        0x83,
        0xEC,
        0x08,
        0x49,
        0xB8,
        0x02,
        0x00,
        0x00,
        0x00,
        0x00,
        0x00,
        0x00,
        0x00,
        0x49,
        0xBF,
        0x0A,
        0x00,
        0x00,
        0x00,
        0x00,
        0x00,
        0x00,
        0x00,
        0x48,
        0x83,
        0xC4,
        0x08,
        0x41,
        0x5F,
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

    const bytes = try emitProgram(a, &prog, null, null);
    defer a.free(bytes);

    try std.testing.expect(bytes.len > 0);
}
