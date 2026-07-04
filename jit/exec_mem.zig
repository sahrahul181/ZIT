const std = @import("std");
const windows = std.os.windows;
const ir = @import("ir");
const cfg = @import("cfg");
const x86 = @import("x86");
const lower = @import("lower");
const regalloc = @import("regalloc");
const emitter = @import("emitter");
const instmod = @import("instruction");
const translate = @import("translate");
const runtime = @import("runtime");

extern "kernel32" fn VirtualAlloc(
    lpAddress: ?windows.LPVOID,
    dwSize: windows.SIZE_T,
    flAllocationType: windows.DWORD,
    flProtect: windows.DWORD,
) callconv(.winapi) ?windows.LPVOID;

extern "kernel32" fn VirtualFree(
    lpAddress: windows.LPVOID,
    dwSize: windows.SIZE_T,
    dwFreeType: windows.DWORD,
) callconv(.winapi) windows.BOOL;

/// Allocate raw virtual memory pages with PAGE_EXECUTE_READWRITE protection.
/// Direct kernel syscall, absolute zero overhead.
pub fn allocateExecMemory(size: usize) ![]u8 {
    const ptr = VirtualAlloc(
        null,
        size,
        0x1000 | 0x2000, // MEM_COMMIT | MEM_RESERVE
        0x40, // PAGE_EXECUTE_READWRITE
    ) orelse return error.VirtualAllocFailed;

    return @as([*]u8, @ptrCast(ptr))[0..size];
}

/// Free virtual memory pages with MEM_RELEASE.
pub fn freeExecMemory(slice: []u8) void {
    const res = VirtualFree(slice.ptr, 0, 0x8000); // MEM_RELEASE
    std.debug.assert(res != .FALSE);
}

// ── End-To-End JIT Execution Tests ──────────────────────────────────────────

test "exec_mem: end-to-end JIT execution on physical CPU" {
    const a = std.testing.allocator;

    // 1. Build an SSA CFG program representing: f(x) = x + 100
    // Arg 0 (x) is in version v0_1.
    // In Windows x86-64 calling convention, the first integer argument is passed in RCX.
    // Our register allocator will assign the first available register (RCX) to v0_1.
    
    var test_cfg = cfg.CFG{
        .blocks = std.ArrayList(cfg.BasicBlock).empty,
        .allocator = a,
    };
    defer test_cfg.deinit();

    var block = cfg.BasicBlock{
        .id = 0,
        .start_idx = 0,
        .end_idx = 0,
        .successors = std.ArrayList(usize).empty,
        .predecessors = std.ArrayList(usize).empty,
        .dominance_frontier = std.ArrayList(usize).empty,
        .phi_functions = std.ArrayList(cfg.PhiNode).empty,
        .dom_children = std.ArrayList(usize).empty,
        .idom = null,
        .instructions = std.ArrayList(ir.IRInst).empty,
    };

    const v1_0 = ir.SSAVar{ .reg = 1, .version = 0 }; // x (parameter, registers_size - ins_size + 0 = 2 - 1 = 1)
    const v0_1 = ir.SSAVar{ .reg = 0, .version = 1 }; // x + 100

    // add_lit v0_1 = v1_0 + 100
    try block.instructions.append(a, .{ .add_lit = .{ .dest = v0_1, .src = v1_0, .lit = 100 } });
    // ret v0_1
    try block.instructions.append(a, .{ .ret = .{ .src = v0_1 } });

    try test_cfg.blocks.append(a, block);

    // 2. Lower to Virtual Assembly
    var prog = try lower.lowerCFG(a, &test_cfg);
    defer prog.deinit();

    // 3. Allocate Registers
    try regalloc.allocateRegisters(a, &prog, &test_cfg, null, null, 2, 1, null, null);

    // 4. Emit Machine Code Bytes
    const code_bytes = try emitter.emitProgram(a, &prog, null, null);
    defer a.free(code_bytes);

    // 5. Map into Executable Virtual Memory
    const exec_page = try allocateExecMemory(code_bytes.len);
    defer freeExecMemory(exec_page);

    @memcpy(exec_page, code_bytes);

    // 6. Cast to Function Pointer and Run!
    // f(x) = x + 100
    const JITAddFn = *const fn (i64) callconv(.c) i64;
    const func = @as(JITAddFn, @ptrCast(exec_page.ptr));

    const result = func(25); // 25 + 100 = 125
    try std.testing.expectEqual(@as(i64, 125), result);
}

fn emptyTestBlock() cfg.BasicBlock {
    return .{
        .id = 0,
        .start_idx = 0,
        .end_idx = 0,
        .successors = std.ArrayList(usize).empty,
        .predecessors = std.ArrayList(usize).empty,
        .dominance_frontier = std.ArrayList(usize).empty,
        .phi_functions = std.ArrayList(cfg.PhiNode).empty,
        .dom_children = std.ArrayList(usize).empty,
        .idom = null,
        .instructions = std.ArrayList(ir.IRInst).empty,
    };
}

test "JIT: un_op neg and not execute correctly" {
    const a = std.testing.allocator;

    // f(x) = ~(-x)  → for x=5: -5 → ~(-5) = 4
    var test_cfg = cfg.CFG{ .blocks = std.ArrayList(cfg.BasicBlock).empty, .allocator = a };
    defer test_cfg.deinit();

    var block = emptyTestBlock();
    const param = ir.SSAVar{ .reg = 1, .version = 0 };
    const negged = ir.SSAVar{ .reg = 0, .version = 1 };
    const notted = ir.SSAVar{ .reg = 0, .version = 2 };

    try block.instructions.append(a, .{ .un_op = .{ .kind = .neg_long, .dest = negged, .src = param } });
    try block.instructions.append(a, .{ .un_op = .{ .kind = .not_long, .dest = notted, .src = negged } });
    try block.instructions.append(a, .{ .ret = .{ .src = notted } });
    try test_cfg.blocks.append(a, block);

    var prog = try lower.lowerCFG(a, &test_cfg);
    defer prog.deinit();
    try regalloc.allocateRegisters(a, &prog, &test_cfg, null, null, 2, 1, null, null);
    const code_bytes = try emitter.emitProgram(a, &prog, null, null);
    defer a.free(code_bytes);

    const exec_page = try allocateExecMemory(code_bytes.len);
    defer freeExecMemory(exec_page);
    @memcpy(exec_page, code_bytes);

    const JITFn = *const fn (i64) callconv(.c) i64;
    const func = @as(JITFn, @ptrCast(exec_page.ptr));
    try std.testing.expectEqual(@as(i64, 4), func(5));
    try std.testing.expectEqual(@as(i64, -8), func(-7)); // -(-7)=7, ~7 = -8
}

test "JIT: int_to_byte narrowing conversion executes correctly" {
    const a = std.testing.allocator;

    var test_cfg = cfg.CFG{ .blocks = std.ArrayList(cfg.BasicBlock).empty, .allocator = a };
    defer test_cfg.deinit();

    var block = emptyTestBlock();
    const param = ir.SSAVar{ .reg = 1, .version = 0 };
    const result = ir.SSAVar{ .reg = 0, .version = 1 };

    try block.instructions.append(a, .{ .un_op = .{ .kind = .int_to_byte, .dest = result, .src = param } });
    try block.instructions.append(a, .{ .ret = .{ .src = result } });
    try test_cfg.blocks.append(a, block);

    var prog = try lower.lowerCFG(a, &test_cfg);
    defer prog.deinit();
    try regalloc.allocateRegisters(a, &prog, &test_cfg, null, null, 2, 1, null, null);
    const code_bytes = try emitter.emitProgram(a, &prog, null, null);
    defer a.free(code_bytes);

    const exec_page = try allocateExecMemory(code_bytes.len);
    defer freeExecMemory(exec_page);
    @memcpy(exec_page, code_bytes);

    const JITFn = *const fn (i64) callconv(.c) i64;
    const func = @as(JITFn, @ptrCast(exec_page.ptr));
    try std.testing.expectEqual(@as(i64, 44), func(300)); // 300 & 0xFF = 0x2C = 44
    try std.testing.expectEqual(@as(i64, -56), func(200)); // 0xC8 sign-extends to -56
    try std.testing.expectEqual(@as(i64, -1), func(-1));
}

test "JIT: cmp_long three-way compare executes correctly" {
    const a = std.testing.allocator;

    var test_cfg = cfg.CFG{ .blocks = std.ArrayList(cfg.BasicBlock).empty, .allocator = a };
    defer test_cfg.deinit();

    var block = emptyTestBlock();
    const p0 = ir.SSAVar{ .reg = 1, .version = 0 };
    const p1 = ir.SSAVar{ .reg = 2, .version = 0 };
    const result = ir.SSAVar{ .reg = 0, .version = 1 };

    try block.instructions.append(a, .{ .cmp_op = .{ .kind = .cmp_long, .dest = result, .left = p0, .right = p1 } });
    try block.instructions.append(a, .{ .ret = .{ .src = result } });
    try test_cfg.blocks.append(a, block);

    var prog = try lower.lowerCFG(a, &test_cfg);
    defer prog.deinit();
    try regalloc.allocateRegisters(a, &prog, &test_cfg, null, null, 3, 2, null, null);
    const code_bytes = try emitter.emitProgram(a, &prog, null, null);
    defer a.free(code_bytes);

    const exec_page = try allocateExecMemory(code_bytes.len);
    defer freeExecMemory(exec_page);
    @memcpy(exec_page, code_bytes);

    const JITFn = *const fn (i64, i64) callconv(.c) i64;
    const func = @as(JITFn, @ptrCast(exec_page.ptr));
    try std.testing.expectEqual(@as(i64, 0), func(7, 7));
    try std.testing.expectEqual(@as(i64, 1), func(9, 2));
    try std.testing.expectEqual(@as(i64, -1), func(-5, 3));
    try std.testing.expectEqual(@as(i64, 1), func(1, -1));
}

test "JIT: cmpl_float and NaN bias execute correctly" {
    const a = std.testing.allocator;

    var test_cfg = cfg.CFG{ .blocks = std.ArrayList(cfg.BasicBlock).empty, .allocator = a };
    defer test_cfg.deinit();

    var block = emptyTestBlock();
    const p0 = ir.SSAVar{ .reg = 1, .version = 0 };
    const p1 = ir.SSAVar{ .reg = 2, .version = 0 };
    const result = ir.SSAVar{ .reg = 0, .version = 1 };

    try block.instructions.append(a, .{ .cmp_op = .{ .kind = .cmpl_float, .dest = result, .left = p0, .right = p1 } });
    try block.instructions.append(a, .{ .ret = .{ .src = result } });
    try test_cfg.blocks.append(a, block);

    var prog = try lower.lowerCFG(a, &test_cfg);
    defer prog.deinit();
    const float_params = [_]bool{ true, true };
    try regalloc.allocateRegisters(a, &prog, &test_cfg, &float_params, null, 3, 2, null, null);
    const code_bytes = try emitter.emitProgram(a, &prog, null, null);
    defer a.free(code_bytes);

    const exec_page = try allocateExecMemory(code_bytes.len);
    defer freeExecMemory(exec_page);
    @memcpy(exec_page, code_bytes);

    const JITFn = *const fn (f32, f32) callconv(.c) i64;
    const func = @as(JITFn, @ptrCast(exec_page.ptr));
    try std.testing.expectEqual(@as(i64, 0), func(2.5, 2.5));
    try std.testing.expectEqual(@as(i64, 1), func(3.5, 1.0));
    try std.testing.expectEqual(@as(i64, -1), func(-3.5, 1.0));
    // cmpl → NaN biases to -1
    try std.testing.expectEqual(@as(i64, -1), func(std.math.nan(f32), 1.0));
}

test "JIT: neg_float executes correctly" {
    const a = std.testing.allocator;

    var test_cfg = cfg.CFG{ .blocks = std.ArrayList(cfg.BasicBlock).empty, .allocator = a };
    defer test_cfg.deinit();

    var block = emptyTestBlock();
    const param = ir.SSAVar{ .reg = 1, .version = 0 };
    const result = ir.SSAVar{ .reg = 0, .version = 1 };

    try block.instructions.append(a, .{ .un_op = .{ .kind = .neg_float, .dest = result, .src = param } });
    try block.instructions.append(a, .{ .ret = .{ .src = result } });
    try test_cfg.blocks.append(a, block);

    var prog = try lower.lowerCFG(a, &test_cfg);
    defer prog.deinit();
    const float_params = [_]bool{true};
    try regalloc.allocateRegisters(a, &prog, &test_cfg, &float_params, null, 2, 1, null, null);
    const code_bytes = try emitter.emitProgram(a, &prog, null, null);
    defer a.free(code_bytes);

    const exec_page = try allocateExecMemory(code_bytes.len);
    defer freeExecMemory(exec_page);
    @memcpy(exec_page, code_bytes);

    const JITFn = *const fn (f32) callconv(.c) f32;
    const func = @as(JITFn, @ptrCast(exec_page.ptr));
    try std.testing.expectEqual(@as(f32, -2.5), func(2.5));
    try std.testing.expectEqual(@as(f32, 7.25), func(-7.25));
}

test "JIT: int_to_float conversion executes correctly" {
    const a = std.testing.allocator;

    var test_cfg = cfg.CFG{ .blocks = std.ArrayList(cfg.BasicBlock).empty, .allocator = a };
    defer test_cfg.deinit();

    var block = emptyTestBlock();
    const param = ir.SSAVar{ .reg = 1, .version = 0 };
    const result = ir.SSAVar{ .reg = 0, .version = 1 };

    try block.instructions.append(a, .{ .un_op = .{ .kind = .int_to_float, .dest = result, .src = param } });
    try block.instructions.append(a, .{ .ret = .{ .src = result } });
    try test_cfg.blocks.append(a, block);

    var prog = try lower.lowerCFG(a, &test_cfg);
    defer prog.deinit();
    try regalloc.allocateRegisters(a, &prog, &test_cfg, null, null, 2, 1, null, null);
    const code_bytes = try emitter.emitProgram(a, &prog, null, null);
    defer a.free(code_bytes);

    const exec_page = try allocateExecMemory(code_bytes.len);
    defer freeExecMemory(exec_page);
    @memcpy(exec_page, code_bytes);

    const JITFn = *const fn (i64) callconv(.c) f32;
    const func = @as(JITFn, @ptrCast(exec_page.ptr));
    try std.testing.expectEqual(@as(f32, 42.0), func(42));
    try std.testing.expectEqual(@as(f32, -3.0), func(-3));
}

test "JIT: integer division and remainder execute correctly" {
    const a = std.testing.allocator;

    // f(x, y) = (x / y) + (x % y)
    var test_cfg = cfg.CFG{ .blocks = std.ArrayList(cfg.BasicBlock).empty, .allocator = a };
    defer test_cfg.deinit();

    var block = emptyTestBlock();
    const x = ir.SSAVar{ .reg = 2, .version = 0 };
    const y = ir.SSAVar{ .reg = 3, .version = 0 };
    const q = ir.SSAVar{ .reg = 0, .version = 1 };
    const r = ir.SSAVar{ .reg = 1, .version = 1 };
    const sum = ir.SSAVar{ .reg = 0, .version = 2 };

    try block.instructions.append(a, .{ .div_int = .{ .dest = q, .left = x, .right = y } });
    try block.instructions.append(a, .{ .rem_int = .{ .dest = r, .left = x, .right = y } });
    try block.instructions.append(a, .{ .add_int = .{ .dest = sum, .left = q, .right = r } });
    try block.instructions.append(a, .{ .ret = .{ .src = sum } });
    try test_cfg.blocks.append(a, block);

    var prog = try lower.lowerCFG(a, &test_cfg);
    defer prog.deinit();
    try regalloc.allocateRegisters(a, &prog, &test_cfg, null, null, 4, 2, null, null);

    const code_bytes = try emitter.emitProgram(a, &prog, null, null);
    defer a.free(code_bytes);

    const exec_page = try allocateExecMemory(code_bytes.len);
    defer freeExecMemory(exec_page);
    @memcpy(exec_page, code_bytes);

    const JITFn = *const fn (i64, i64) callconv(.c) i64;
    const func = @as(JITFn, @ptrCast(exec_page.ptr));
    try std.testing.expectEqual(@as(i64, 7), func(17, 3)); // 17/3=5, 17%3=2 -> 7
    // 17/3 = 5, 17%3 = 2, 5+2 = 7
}

test "JIT: div/rem exact values" {
    const a = std.testing.allocator;

    var test_cfg = cfg.CFG{ .blocks = std.ArrayList(cfg.BasicBlock).empty, .allocator = a };
    defer test_cfg.deinit();

    var block = emptyTestBlock();
    const x = ir.SSAVar{ .reg = 1, .version = 0 };
    const y = ir.SSAVar{ .reg = 2, .version = 0 };
    const q = ir.SSAVar{ .reg = 0, .version = 1 };

    try block.instructions.append(a, .{ .div_int = .{ .dest = q, .left = x, .right = y } });
    try block.instructions.append(a, .{ .ret = .{ .src = q } });
    try test_cfg.blocks.append(a, block);

    var prog = try lower.lowerCFG(a, &test_cfg);
    defer prog.deinit();
    try regalloc.allocateRegisters(a, &prog, &test_cfg, null, null, 3, 2, null, null);
    const code_bytes = try emitter.emitProgram(a, &prog, null, null);
    defer a.free(code_bytes);

    const exec_page = try allocateExecMemory(code_bytes.len);
    defer freeExecMemory(exec_page);
    @memcpy(exec_page, code_bytes);

    const JITFn = *const fn (i64, i64) callconv(.c) i64;
    const func = @as(JITFn, @ptrCast(exec_page.ptr));
    try std.testing.expectEqual(@as(i64, 5), func(17, 3));
    try std.testing.expectEqual(@as(i64, -4), func(-20, 5));
    try std.testing.expectEqual(@as(i64, 0), func(3, 10));
}

test "JIT: rem exact values" {
    const a = std.testing.allocator;

    var test_cfg = cfg.CFG{ .blocks = std.ArrayList(cfg.BasicBlock).empty, .allocator = a };
    defer test_cfg.deinit();

    var block = emptyTestBlock();
    const x = ir.SSAVar{ .reg = 1, .version = 0 };
    const y = ir.SSAVar{ .reg = 2, .version = 0 };
    const r = ir.SSAVar{ .reg = 0, .version = 1 };

    try block.instructions.append(a, .{ .rem_int = .{ .dest = r, .left = x, .right = y } });
    try block.instructions.append(a, .{ .ret = .{ .src = r } });
    try test_cfg.blocks.append(a, block);

    var prog = try lower.lowerCFG(a, &test_cfg);
    defer prog.deinit();
    try regalloc.allocateRegisters(a, &prog, &test_cfg, null, null, 3, 2, null, null);
    const code_bytes = try emitter.emitProgram(a, &prog, null, null);
    defer a.free(code_bytes);

    const exec_page = try allocateExecMemory(code_bytes.len);
    defer freeExecMemory(exec_page);
    @memcpy(exec_page, code_bytes);

    const JITFn = *const fn (i64, i64) callconv(.c) i64;
    const func = @as(JITFn, @ptrCast(exec_page.ptr));
    try std.testing.expectEqual(@as(i64, 2), func(17, 3));
    try std.testing.expectEqual(@as(i64, -2), func(-17, 3)); // C truncated: -17%3=-2
    try std.testing.expectEqual(@as(i64, 3), func(3, 10));
}

test "JIT: bitwise and/or/xor execute correctly" {
    const a = std.testing.allocator;

    // f(x, y) = ((x & y) | (x ^ y))  == x | y
    var test_cfg = cfg.CFG{ .blocks = std.ArrayList(cfg.BasicBlock).empty, .allocator = a };
    defer test_cfg.deinit();

    var block = emptyTestBlock();
    const x = ir.SSAVar{ .reg = 2, .version = 0 };
    const y = ir.SSAVar{ .reg = 3, .version = 0 };
    const andv = ir.SSAVar{ .reg = 0, .version = 1 };
    const xorv = ir.SSAVar{ .reg = 1, .version = 1 };
    const orv = ir.SSAVar{ .reg = 0, .version = 2 };

    try block.instructions.append(a, .{ .and_int = .{ .dest = andv, .left = x, .right = y } });
    try block.instructions.append(a, .{ .xor_int = .{ .dest = xorv, .left = x, .right = y } });
    try block.instructions.append(a, .{ .or_int = .{ .dest = orv, .left = andv, .right = xorv } });
    try block.instructions.append(a, .{ .ret = .{ .src = orv } });
    try test_cfg.blocks.append(a, block);

    var prog = try lower.lowerCFG(a, &test_cfg);
    defer prog.deinit();
    try regalloc.allocateRegisters(a, &prog, &test_cfg, null, null, 4, 2, null, null);

    const code_bytes = try emitter.emitProgram(a, &prog, null, null);
    defer a.free(code_bytes);

    const exec_page = try allocateExecMemory(code_bytes.len);
    defer freeExecMemory(exec_page);
    @memcpy(exec_page, code_bytes);

    const JITFn = *const fn (i64, i64) callconv(.c) i64;
    const func = @as(JITFn, @ptrCast(exec_page.ptr));
    try std.testing.expectEqual(@as(i64, 0b1110), func(0b1010, 0b0110));
    try std.testing.expectEqual(@as(i64, 0xFF), func(0xF0, 0x0F));
}

test "JIT: shift by immediate and by register execute correctly" {
    const a = std.testing.allocator;

    // f(x, y) = (x << 2) >> y   (arithmetic)
    var test_cfg = cfg.CFG{ .blocks = std.ArrayList(cfg.BasicBlock).empty, .allocator = a };
    defer test_cfg.deinit();

    var block = emptyTestBlock();
    const x = ir.SSAVar{ .reg = 1, .version = 0 };
    const y = ir.SSAVar{ .reg = 2, .version = 0 };
    const shl = ir.SSAVar{ .reg = 0, .version = 1 };
    const shr = ir.SSAVar{ .reg = 0, .version = 2 };

    try block.instructions.append(a, .{ .shl_lit = .{ .dest = shl, .src = x, .lit = 2 } });
    try block.instructions.append(a, .{ .shr_int = .{ .dest = shr, .left = shl, .right = y } });
    try block.instructions.append(a, .{ .ret = .{ .src = shr } });
    try test_cfg.blocks.append(a, block);

    var prog = try lower.lowerCFG(a, &test_cfg);
    defer prog.deinit();
    try regalloc.allocateRegisters(a, &prog, &test_cfg, null, null, 3, 2, null, null);
    const code_bytes = try emitter.emitProgram(a, &prog, null, null);
    defer a.free(code_bytes);

    const exec_page = try allocateExecMemory(code_bytes.len);
    defer freeExecMemory(exec_page);
    @memcpy(exec_page, code_bytes);

    const JITFn = *const fn (i64, i64) callconv(.c) i64;
    const func = @as(JITFn, @ptrCast(exec_page.ptr));
    // (5 << 2) = 20, 20 >> 1 = 10
    try std.testing.expectEqual(@as(i64, 10), func(5, 1));
    // (8 << 2) = 32, 32 >> 3 = 4
    try std.testing.expectEqual(@as(i64, 4), func(8, 3));
}

test "JIT: if_ltz zero-comparison branch executes correctly" {
    const a = std.testing.allocator;


    // int f(int x) { if (x < 0) return 100; return 200; }
    const insns = [_]instmod.Instruction{
        .{ .if_ltz = .{ .src = 1, .offset = 3 } }, // 0: if x<0 goto idx 3
        .{ .const_ = .{ .dest = 0, .value = 200 } }, // 1
        .{ .return_ = .{ .src = 0 } }, // 2
        .{ .const_ = .{ .dest = 0, .value = 100 } }, // 3
        .{ .return_ = .{ .src = 0 } }, // 4
    };

    var test_cfg = try cfg.buildCFG(a, &insns);
    defer test_cfg.deinit();
    try test_cfg.computePredecessors();
    try test_cfg.computeDominators();
    try test_cfg.computeDominatorChildren();
    try test_cfg.computeDominanceFrontiers();
    try translate.translateCFG(a, &test_cfg, &insns);
    try test_cfg.renameVariables(2);

    var prog = try lower.lowerCFG(a, &test_cfg);
    defer prog.deinit();
    try regalloc.allocateRegisters(a, &prog, &test_cfg, null, null, 2, 1, null, null);
    const code_bytes = try emitter.emitProgram(a, &prog, null, null);
    defer a.free(code_bytes);

    const exec_page = try allocateExecMemory(code_bytes.len);
    defer freeExecMemory(exec_page);
    @memcpy(exec_page, code_bytes);

    const JITFn = *const fn (i64) callconv(.c) i64;
    const func = @as(JITFn, @ptrCast(exec_page.ptr));
    try std.testing.expectEqual(@as(i64, 100), func(-5));
    try std.testing.expectEqual(@as(i64, 200), func(7));
}

test "JIT: float remainder executes correctly" {
    const a = std.testing.allocator;

    var test_cfg = cfg.CFG{ .blocks = std.ArrayList(cfg.BasicBlock).empty, .allocator = a };
    defer test_cfg.deinit();

    var block = emptyTestBlock();
    const x = ir.SSAVar{ .reg = 1, .version = 0 };
    const y = ir.SSAVar{ .reg = 2, .version = 0 };
    const r = ir.SSAVar{ .reg = 0, .version = 1 };

    try block.instructions.append(a, .{ .rem_float = .{ .dest = r, .left = x, .right = y } });
    try block.instructions.append(a, .{ .ret = .{ .src = r } });
    try test_cfg.blocks.append(a, block);

    var prog = try lower.lowerCFG(a, &test_cfg);
    defer prog.deinit();
    const float_params = [_]bool{ true, true };
    try regalloc.allocateRegisters(a, &prog, &test_cfg, &float_params, null, 3, 2, null, null);
    const code_bytes = try emitter.emitProgram(a, &prog, null, null);
    defer a.free(code_bytes);

    const exec_page = try allocateExecMemory(code_bytes.len);
    defer freeExecMemory(exec_page);
    @memcpy(exec_page, code_bytes);

    const JITFn = *const fn (f32, f32) callconv(.c) f32;
    const func = @as(JITFn, @ptrCast(exec_page.ptr));
    try std.testing.expectEqual(@as(f32, 1.0), func(7.0, 3.0)); // 7 % 3 = 1
    try std.testing.expectEqual(@as(f32, 0.5), func(5.5, 1.0)); // 5.5 % 1 = 0.5
}

test "JIT: pass 5 parameters (stack parameter support)" {
    const a = std.testing.allocator;

    var test_cfg = cfg.CFG{
        .blocks = std.ArrayList(cfg.BasicBlock).empty,
        .allocator = a,
    };
    defer {
        for (test_cfg.blocks.items) |*b| b.instructions.deinit(a);
        test_cfg.blocks.deinit(a);
    }

    var block = cfg.BasicBlock{
        .id = 0,
        .start_idx = 0,
        .end_idx = 0,
        .successors = std.ArrayList(usize).empty,
        .predecessors = std.ArrayList(usize).empty,
        .dominance_frontier = std.ArrayList(usize).empty,
        .phi_functions = std.ArrayList(cfg.PhiNode).empty,
        .dom_children = std.ArrayList(usize).empty,
        .idom = null,
        .instructions = std.ArrayList(ir.IRInst).empty,
    };

    const v0_0 = ir.SSAVar{ .reg = 4, .version = 0 };
    const v1_0 = ir.SSAVar{ .reg = 5, .version = 0 };
    const v2_0 = ir.SSAVar{ .reg = 6, .version = 0 };
    const v3_0 = ir.SSAVar{ .reg = 7, .version = 0 };
    const v4_0 = ir.SSAVar{ .reg = 8, .version = 0 };

    const t0 = ir.SSAVar{ .reg = 0, .version = 1 };
    const t1 = ir.SSAVar{ .reg = 1, .version = 1 };
    const t2 = ir.SSAVar{ .reg = 2, .version = 1 };
    const t3 = ir.SSAVar{ .reg = 3, .version = 1 };

    try block.instructions.append(a, .{ .add_int = .{ .dest = t0, .left = v0_0, .right = v1_0 } });
    try block.instructions.append(a, .{ .add_int = .{ .dest = t1, .left = t0, .right = v2_0 } });
    try block.instructions.append(a, .{ .add_int = .{ .dest = t2, .left = t1, .right = v3_0 } });
    try block.instructions.append(a, .{ .add_int = .{ .dest = t3, .left = t2, .right = v4_0 } });
    try block.instructions.append(a, .{ .ret = .{ .src = t3 } });

    try test_cfg.blocks.append(a, block);

    var prog = try lower.lowerCFG(a, &test_cfg);
    defer prog.deinit();

    try regalloc.allocateRegisters(a, &prog, &test_cfg, null, null, 9, 5, null, null);
    const code_bytes = try emitter.emitProgram(a, &prog, null, null);
    defer a.free(code_bytes);

    const exec_page = try allocateExecMemory(code_bytes.len);
    defer freeExecMemory(exec_page);

    @memcpy(exec_page, code_bytes);

    const JITSum5Fn = *const fn (i64, i64, i64, i64, i64) callconv(.c) i64;
    const func = @as(JITSum5Fn, @ptrCast(exec_page.ptr));

    const result = func(10, 20, 30, 40, 50); // 10+20+30+40+50 = 150
    try std.testing.expectEqual(@as(i64, 150), result);
}

test "JIT: self-recursive static call (Fibonacci) executes correctly" {
    const a = std.testing.allocator;

    var invoke_1 = instmod.Invoke{
        .kind = .static,
        .dest = null,
        .class_name = "Main",
        .method_name = "fib",
        .signature = "(I)I",
        .args = &[_]u16{ 3 },
        .is_self_call = true,
    };
    var invoke_2 = instmod.Invoke{
        .kind = .static,
        .dest = null,
        .class_name = "Main",
        .method_name = "fib",
        .signature = "(I)I",
        .args = &[_]u16{ 5 },
        .is_self_call = true,
    };

    const insns = [_]instmod.Instruction{
        .{ .const_ = .{ .dest = 2, .value = 2 } }, // 0: const v2, 2
        .{ .if_ge = .{ .src1 = 7, .src2 = 2, .offset = 3 } }, // 1: if n >= 2 goto 4 (else_block)
        // then_block
        .{ .return_ = .{ .src = 7 } }, // 2: return n
        .{ .const_ = .{ .dest = 2, .value = 2 } }, // 3: dummy to align block boundaries
        // else_block (index 4)
        .{ .add_int_lit8 = .{ .dest = 3, .src = 7, .lit = -1 } }, // 4: v3 = n - 1
        .{ .invoke = &invoke_1 }, // 5: invoke-static {v3}, fib
        .{ .move_result = .{ .dest = 4 } }, // 6: v4 = result of fib(n-1)
        .{ .add_int_lit8 = .{ .dest = 5, .src = 7, .lit = -2 } }, // 7: v5 = n - 2
        .{ .invoke = &invoke_2 }, // 8: invoke-static {v5}, fib
        .{ .move_result = .{ .dest = 6 } }, // 9: v6 = result of fib(n-2)
        .{ .add_int = .{ .dest = 0, .src1 = 4, .src2 = 6 } }, // 10: v0 = v4 + v6
        .{ .return_ = .{ .src = 0 } }, // 11: return v0
    };

    var test_cfg = try cfg.buildCFG(a, &insns);
    defer test_cfg.deinit();

    try translate.translateCFG(a, &test_cfg, &insns);

    var prog = try lower.lowerCFG(a, &test_cfg);
    defer prog.deinit();

    try regalloc.allocateRegisters(a, &prog, &test_cfg, null, null, 8, 1, null, null);
    const code_bytes = try emitter.emitProgram(a, &prog, null, null);
    defer a.free(code_bytes);

    const exec_page = try allocateExecMemory(code_bytes.len);
    defer freeExecMemory(exec_page);

    @memcpy(exec_page, code_bytes);

    const JITFibFn = *const fn (i64) callconv(.c) i64;
    const func = @as(JITFibFn, @ptrCast(exec_page.ptr));

    // fib(0) = 0
    // fib(1) = 1
    // fib(2) = 1
    // fib(3) = 2
    // fib(4) = 3
    // fib(5) = 5
    // fib(6) = 8
    // fib(7) = 13
    // fib(8) = 21
    // fib(10) = 55
    try std.testing.expectEqual(@as(i64, 0), func(0));
    try std.testing.expectEqual(@as(i64, 1), func(1));
    try std.testing.expectEqual(@as(i64, 1), func(2));
    try std.testing.expectEqual(@as(i64, 2), func(3));
    try std.testing.expectEqual(@as(i64, 3), func(4));
    try std.testing.expectEqual(@as(i64, 5), func(5));
    try std.testing.expectEqual(@as(i64, 8), func(6));
    try std.testing.expectEqual(@as(i64, 13), func(7));
    try std.testing.expectEqual(@as(i64, 21), func(8));
    try std.testing.expectEqual(@as(i64, 55), func(10));
}

test "JIT: monitor-enter and monitor-exit execution correctness" {
    const a = std.testing.allocator;

    try runtime.initRuntime(a, 1024 * 1024);
    defer runtime.deinitRuntime();

    var test_cfg = cfg.CFG{ .blocks = std.ArrayList(cfg.BasicBlock).empty, .allocator = a };
    defer test_cfg.deinit();

    var block = emptyTestBlock();
    const x = ir.SSAVar{ .reg = 2, .version = 0 };

    try block.instructions.append(a, .{ .monitor_enter = .{ .src = x } });
    try block.instructions.append(a, .{ .monitor_exit = .{ .src = x } });
    try block.instructions.append(a, .{ .ret = .{ .src = null } });
    try test_cfg.blocks.append(a, block);

    var prog = try lower.lowerCFG(a, &test_cfg);
    defer prog.deinit();

    try regalloc.allocateRegisters(a, &prog, &test_cfg, null, null, 4, 1, null, null);
    const code_bytes = try emitter.emitProgram(a, &prog, null, null);
    defer a.free(code_bytes);

    const exec_page = try allocateExecMemory(code_bytes.len);
    defer freeExecMemory(exec_page);

    @memcpy(exec_page, code_bytes);

    const JITMonitorFn = *const fn (*anyopaque) callconv(.c) void;
    const func = @as(JITMonitorFn, @ptrCast(exec_page.ptr));

    const raw_mem = try a.alloc(u8, 32);
    defer a.free(raw_mem);

    const obj_hdr = @as(*runtime.ObjectHeader, @ptrCast(@alignCast(raw_mem.ptr)));
    obj_hdr.class_ptr = 0xAAAA;
    obj_hdr.monitor = 0;

    const obj_ptr = @intFromPtr(obj_hdr) + @sizeOf(runtime.ObjectHeader);

    func(@ptrFromInt(obj_ptr));

    try std.testing.expectEqual(@as(usize, 0), obj_hdr.monitor);
}
