const std = @import("std");
const windows = std.os.windows;
const ir = @import("ir");
const cfg = @import("cfg");
const x86 = @import("x86");
const lower = @import("lower");
const regalloc = @import("regalloc");
const emitter = @import("emitter");

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
    try regalloc.allocateRegisters(a, &prog, &test_cfg, null, 2, 1);

    // 4. Emit Machine Code Bytes
    const code_bytes = try emitter.emitProgram(a, &prog);
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
