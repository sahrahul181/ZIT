const std = @import("std");
const ir = @import("ir");

pub const GcCallSiteInfo = struct {
    stack_refs: u64 = 0,
    reg_refs: u32 = 0,
};

pub const PhysicalReg = enum {
    rax, rcx, rdx, rbx, rsi, rdi, r8, r9, r10, r11, r12, r13, r14, r15,
    xmm0, xmm1, xmm2, xmm3, xmm4, xmm5, xmm6, xmm7, xmm8, xmm9, xmm10, xmm11, xmm12, xmm13, xmm14, xmm15,

    pub fn name(self: PhysicalReg) []const u8 {
        return @tagName(self);
    }
};

pub const BaseReg = union(enum) {
    vreg: ir.SSAVar,
    reg:  PhysicalReg,
    stack: i32,

    pub fn format(self: BaseReg, writer: *std.Io.Writer) !void {
        switch (self) {
            .vreg  => |v| try writer.print("v{d}_{d}", .{ v.reg, v.version }),
            .reg   => |r| try writer.print("%{s}", .{r.name()}),
            .stack => |o| try writer.print("[rbp-{d}]", .{o}),
        }
    }
};

pub const MemoryAddress = struct {
    base:  BaseReg,
    index: ?BaseReg = null,
    scale: u3 = 1,
    disp:  i32 = 0,

    pub fn format(self: MemoryAddress, writer: *std.Io.Writer) !void {
        try writer.writeAll("[");
        try self.base.format(writer);
        if (self.index) |idx| {
            try writer.writeAll(" + ");
            try idx.format(writer);
            if (self.scale > 1) {
                try writer.print(" * {d}", .{self.scale});
            }
        }
        if (self.disp != 0) {
            if (self.disp > 0) {
                try writer.print(" + {d}", .{self.disp});
            } else {
                try writer.print(" - {d}", .{-self.disp});
            }
        }
        try writer.writeAll("]");
    }
};

/// Operands for x86 virtual assembly.
pub const Operand = union(enum) {
    vreg:  ir.SSAVar,
    reg:   PhysicalReg,
    stack: i32, // Stack offset from RBP/RSP
    mem:   MemoryAddress,
    imm:   i32,
    imm64: i64,

    pub fn format(self: Operand, writer: *std.Io.Writer) !void {
        switch (self) {
            .vreg  => |v| try writer.print("v{d}_{d}", .{ v.reg, v.version }),
            .reg   => |r| try writer.print("%{s}", .{r.name()}),
            .stack => |o| try writer.print("[rbp-{d}]", .{o}),
            .mem   => |m| try m.format(writer),
            .imm   => |v| try writer.print("#{d}", .{v}),
            .imm64 => |v| try writer.print("#{d}L", .{v}),
        }
    }
};

/// Virtual x86-64 instruction set (macro-assembler level, no physical registers yet).
pub const Inst = union(enum) {
    // ---- Data movement ----
    mov: struct { dest: Operand, src: Operand },

    // ---- Integer arithmetic (2-address: dest op= src) ----
    add:  struct { dest: Operand, src: Operand },
    sub:  struct { dest: Operand, src: Operand },
    imul: struct { dest: Operand, src: Operand },
    /// IDIV — quotient → dest, remainder → rem, divisor = src
    idiv: struct { dest: Operand, rem: Operand, src: Operand },
    /// IREM — same expansion as idiv but the remainder is the primary result
    irem: struct { dest: Operand, rem: Operand, src: Operand },
    /// NEG dest (unary negate)
    neg:  struct { dest: Operand },
    /// NOT dest (bitwise complement)
    not:  struct { dest: Operand },

    // ---- Sign/zero extensions (conversions; all extend into a 64-bit dest) ----
    movsxd:  struct { dest: Operand, src: Operand }, // sign-extend low 32 → 64  (long-to-int re-canonicalization)
    movsx8:  struct { dest: Operand, src: Operand }, // sign-extend low 8  → 64  (int-to-byte)
    movsx16: struct { dest: Operand, src: Operand }, // sign-extend low 16 → 64  (int-to-short)
    movzx16: struct { dest: Operand, src: Operand }, // zero-extend low 16 → 64  (int-to-char)

    // ---- Int ↔ float conversions (SSE scalar) ----
    cvtsi2ss:  struct { dest: Operand, src: Operand }, // gpr → xmm (f32)
    cvtsi2sd:  struct { dest: Operand, src: Operand }, // gpr → xmm (f64)
    cvttss2si: struct { dest: Operand, src: Operand }, // xmm (f32) → gpr, truncated
    cvttsd2si: struct { dest: Operand, src: Operand }, // xmm (f64) → gpr, truncated
    cvtss2sd:  struct { dest: Operand, src: Operand }, // f32 → f64
    cvtsd2ss:  struct { dest: Operand, src: Operand }, // f64 → f32

    // ---- SSE negation (dest = -dest, sign-bit flip) ----
    negss: struct { dest: Operand },
    negsd: struct { dest: Operand },

    // ---- Float remainder pseudo-op (needs an fmod runtime call to emit) ----
    frem32: struct { dest: Operand, src: Operand },
    frem64: struct { dest: Operand, src: Operand },

    // ---- Three-way compare: dest(gpr) = -1/0/1 with Dalvik NaN bias ----
    cmp3: struct { kind: ir.CmpKind, dest: Operand, left: Operand, right: Operand },

    // ---- Bitwise ----
    and_op: struct { dest: Operand, src: Operand },
    or_op:  struct { dest: Operand, src: Operand },
    xor_op: struct { dest: Operand, src: Operand },
    shl:    struct { dest: Operand, src: Operand },
    shr:    struct { dest: Operand, src: Operand },  // arithmetic (SAR)
    ushr:   struct { dest: Operand, src: Operand },  // logical    (SHR)

    // ---- SSE Floating-point Single Precision ----
    addss: struct { dest: Operand, src: Operand },
    subss: struct { dest: Operand, src: Operand },
    mulss: struct { dest: Operand, src: Operand },
    divss: struct { dest: Operand, src: Operand },
    movss: struct { dest: Operand, src: Operand },

    // ---- SSE Floating-point Double Precision ----
    addsd: struct { dest: Operand, src: Operand },
    subsd: struct { dest: Operand, src: Operand },
    mulsd: struct { dest: Operand, src: Operand },
    divsd: struct { dest: Operand, src: Operand },
    movsd: struct { dest: Operand, src: Operand },

    // ---- Comparisons & Branches ----
    cmp:     struct { left: Operand, right: Operand },
    test_op: struct { left: Operand, right: Operand },
    jmp: usize,
    je:  usize,
    jne: usize,
    jl:  usize,
    jle: usize,
    jg:  usize,
    jge: usize,
    jz:  usize,
    jnz: usize,

    // ---- Switch: lowered to a compare-and-branch chain by the emitter ----
    // `keys[i]` matches → jump to block `targets[i]`; fall through if none match.
    switch_stub: struct { src: Operand, keys: []const i32, targets: []const usize },

    // ---- Method call stub ----
    call: struct {
        dest:       ?Operand,
        method_idx: u32,
        is_static:  bool,
        arg_count:  usize,
        is_self_call: bool = false,
        gc_info: ?GcCallSiteInfo = null,
    },


    // ---- Allocation stubs ----
    alloc_obj: struct { dest: Operand, type_idx: u32 },
    alloc_arr: struct { dest: Operand, size: Operand, type_idx: u32 },
    filled_new_array: struct { dest: Operand, type_idx: u32, args: [5]?Operand },
    instance_of: struct { dest: Operand, obj: Operand, type_idx: u32 },
    fill_array_data: struct { array: Operand, data_ptr: usize, data_len: u32, elem_width: u32 },
    move_exception: struct { dest: Operand },

    // ---- Field access stubs ----
    field_load:  struct { dest: Operand, obj: ?Operand, field_idx: u32 },
    field_store: struct { src:  Operand, obj: ?Operand, field_idx: u32 },

    // ---- Array element access stubs ----
    arr_load:  struct { dest: Operand, array: Operand, index: Operand },
    arr_store: struct { src:  Operand, array: Operand, index: Operand },
    bounds_check: struct { index: Operand, array: Operand },

    // ---- Returns & Exceptions ----
    ret:        ?Operand,
    throw_stub: struct { src: Operand },
    monitor_enter: struct { src: Operand },
    monitor_exit: struct { src: Operand },

    // ---- Pretty printing ----
    pub fn format(self: Inst, writer: *std.Io.Writer) !void {
        switch (self) {
            .monitor_enter => |v| { try writer.writeAll("MONITOR_ENTER "); try v.src.format(writer); },
            .monitor_exit => |v| { try writer.writeAll("MONITOR_EXIT "); try v.src.format(writer); },
            .mov     => |v| { try writer.writeAll("MOV ");  try v.dest.format(writer); try writer.writeAll(", "); try v.src.format(writer); },
            .add     => |v| { try writer.writeAll("ADD ");  try v.dest.format(writer); try writer.writeAll(", "); try v.src.format(writer); },
            .sub     => |v| { try writer.writeAll("SUB ");  try v.dest.format(writer); try writer.writeAll(", "); try v.src.format(writer); },
            .imul    => |v| { try writer.writeAll("IMUL "); try v.dest.format(writer); try writer.writeAll(", "); try v.src.format(writer); },
            .idiv    => |v| { try writer.writeAll("IDIV "); try v.dest.format(writer); try writer.writeAll(", "); try v.rem.format(writer); try writer.writeAll(" <- "); try v.src.format(writer); },
            .irem    => |v| { try writer.writeAll("IREM "); try v.dest.format(writer); try writer.writeAll(", "); try v.rem.format(writer); try writer.writeAll(" <- "); try v.src.format(writer); },
            .neg     => |v| { try writer.writeAll("NEG ");  try v.dest.format(writer); },
            .not     => |v| { try writer.writeAll("NOT ");  try v.dest.format(writer); },
            .movsxd  => |v| { try writer.writeAll("MOVSXD ");  try v.dest.format(writer); try writer.writeAll(", "); try v.src.format(writer); },
            .movsx8  => |v| { try writer.writeAll("MOVSX8 ");  try v.dest.format(writer); try writer.writeAll(", "); try v.src.format(writer); },
            .movsx16 => |v| { try writer.writeAll("MOVSX16 "); try v.dest.format(writer); try writer.writeAll(", "); try v.src.format(writer); },
            .movzx16 => |v| { try writer.writeAll("MOVZX16 "); try v.dest.format(writer); try writer.writeAll(", "); try v.src.format(writer); },
            .cvtsi2ss  => |v| { try writer.writeAll("CVTSI2SS ");  try v.dest.format(writer); try writer.writeAll(", "); try v.src.format(writer); },
            .cvtsi2sd  => |v| { try writer.writeAll("CVTSI2SD ");  try v.dest.format(writer); try writer.writeAll(", "); try v.src.format(writer); },
            .cvttss2si => |v| { try writer.writeAll("CVTTSS2SI "); try v.dest.format(writer); try writer.writeAll(", "); try v.src.format(writer); },
            .cvttsd2si => |v| { try writer.writeAll("CVTTSD2SI "); try v.dest.format(writer); try writer.writeAll(", "); try v.src.format(writer); },
            .cvtss2sd  => |v| { try writer.writeAll("CVTSS2SD ");  try v.dest.format(writer); try writer.writeAll(", "); try v.src.format(writer); },
            .cvtsd2ss  => |v| { try writer.writeAll("CVTSD2SS ");  try v.dest.format(writer); try writer.writeAll(", "); try v.src.format(writer); },
            .negss => |v| { try writer.writeAll("NEGSS "); try v.dest.format(writer); },
            .negsd => |v| { try writer.writeAll("NEGSD "); try v.dest.format(writer); },
            .frem32 => |v| { try writer.writeAll("FREM32 "); try v.dest.format(writer); try writer.writeAll(", "); try v.src.format(writer); },
            .frem64 => |v| { try writer.writeAll("FREM64 "); try v.dest.format(writer); try writer.writeAll(", "); try v.src.format(writer); },
            .cmp3 => |v| { try writer.print("CMP3.{s} ", .{@tagName(v.kind)}); try v.dest.format(writer); try writer.writeAll(", "); try v.left.format(writer); try writer.writeAll(", "); try v.right.format(writer); },
            .and_op  => |v| { try writer.writeAll("AND ");  try v.dest.format(writer); try writer.writeAll(", "); try v.src.format(writer); },
            .or_op   => |v| { try writer.writeAll("OR ");   try v.dest.format(writer); try writer.writeAll(", "); try v.src.format(writer); },
            .xor_op  => |v| { try writer.writeAll("XOR ");  try v.dest.format(writer); try writer.writeAll(", "); try v.src.format(writer); },
            .shl     => |v| { try writer.writeAll("SHL ");  try v.dest.format(writer); try writer.writeAll(", "); try v.src.format(writer); },
            .shr     => |v| { try writer.writeAll("SAR ");  try v.dest.format(writer); try writer.writeAll(", "); try v.src.format(writer); },
            .ushr    => |v| { try writer.writeAll("SHR ");  try v.dest.format(writer); try writer.writeAll(", "); try v.src.format(writer); },
            .cmp     => |v| { try writer.writeAll("CMP ");  try v.left.format(writer);  try writer.writeAll(", "); try v.right.format(writer); },
            .test_op => |v| { try writer.writeAll("TEST "); try v.left.format(writer);  try writer.writeAll(", "); try v.right.format(writer); },
            .jmp  => |v| try writer.print("JMP bb{d}",  .{v}),
            .je   => |v| try writer.print("JE bb{d}",   .{v}),
            .jne  => |v| try writer.print("JNE bb{d}",  .{v}),
            .jl   => |v| try writer.print("JL bb{d}",   .{v}),
            .jle  => |v| try writer.print("JLE bb{d}",  .{v}),
            .jg   => |v| try writer.print("JG bb{d}",   .{v}),
            .jge  => |v| try writer.print("JGE bb{d}",  .{v}),
            .jz   => |v| try writer.print("JZ bb{d}",   .{v}),
            .jnz  => |v| try writer.print("JNZ bb{d}",  .{v}),

            .addss   => |v| { try writer.writeAll("ADDSS "); try v.dest.format(writer); try writer.writeAll(", "); try v.src.format(writer); },
            .subss   => |v| { try writer.writeAll("SUBSS "); try v.dest.format(writer); try writer.writeAll(", "); try v.src.format(writer); },
            .mulss   => |v| { try writer.writeAll("MULSS "); try v.dest.format(writer); try writer.writeAll(", "); try v.src.format(writer); },
            .divss   => |v| { try writer.writeAll("DIVSS "); try v.dest.format(writer); try writer.writeAll(", "); try v.src.format(writer); },
            .movss   => |v| { try writer.writeAll("MOVSS "); try v.dest.format(writer); try writer.writeAll(", "); try v.src.format(writer); },

            .addsd   => |v| { try writer.writeAll("ADDSD "); try v.dest.format(writer); try writer.writeAll(", "); try v.src.format(writer); },
            .subsd   => |v| { try writer.writeAll("SUBSD "); try v.dest.format(writer); try writer.writeAll(", "); try v.src.format(writer); },
            .mulsd   => |v| { try writer.writeAll("MULSD "); try v.dest.format(writer); try writer.writeAll(", "); try v.src.format(writer); },
            .divsd   => |v| { try writer.writeAll("DIVSD "); try v.dest.format(writer); try writer.writeAll(", "); try v.src.format(writer); },
            .movsd   => |v| { try writer.writeAll("MOVSD "); try v.dest.format(writer); try writer.writeAll(", "); try v.src.format(writer); },
            .switch_stub => |v| {
                try writer.writeAll("SWITCH ");
                try v.src.format(writer);
                try writer.writeAll(" [");
                for (v.keys, 0..) |k, i| {
                    if (i > 0) try writer.writeAll(", ");
                    try writer.print("{d}->bb{d}", .{ k, v.targets[i] });
                }
                try writer.writeAll("]");
            },
            .call => |v| {
                if (v.dest) |d| { try d.format(writer); try writer.writeAll(" = "); }
                try writer.print("CALL method[{d}]", .{v.method_idx});
                if (!v.is_static) try writer.writeAll(" (virtual)");
                try writer.print(" ({d} args)", .{v.arg_count});
            },
            .alloc_obj  => |v| { try v.dest.format(writer); try writer.print(" = NEW type[{d}]", .{v.type_idx}); },
            .alloc_arr  => |v| { try v.dest.format(writer); try writer.writeAll(" = NEWARR["); try v.size.format(writer); try writer.print("] type[{d}]", .{v.type_idx}); },
            .filled_new_array => |v| { try v.dest.format(writer); try writer.print(" = FILLED_NEWARR type[{d}]", .{v.type_idx}); },
            .instance_of => |v| { try v.dest.format(writer); try writer.writeAll(" = INSTANCEOF "); try v.obj.format(writer); try writer.print(" type[{d}]", .{v.type_idx}); },
            .fill_array_data => |v| { try writer.writeAll("FILL_ARRAY_DATA "); try v.array.format(writer); try writer.print(" ptr=0x{x} len={d} width={d}", .{v.data_ptr, v.data_len, v.elem_width}); },
            .move_exception => |v| { try v.dest.format(writer); try writer.writeAll(" = MOVE_EXCEPTION"); },
            .field_load  => |v| {
                try v.dest.format(writer); try writer.print(" = FLOAD field[{d}]", .{v.field_idx});
                if (v.obj) |o| { try writer.writeAll(" obj="); try o.format(writer); }
            },
            .field_store => |v| {
                try writer.print("FSTORE field[{d}]", .{v.field_idx});
                if (v.obj) |o| { try writer.writeAll(" obj="); try o.format(writer); }
                try writer.writeAll(", "); try v.src.format(writer);
            },
            .arr_load  => |v| { try v.dest.format(writer); try writer.writeAll(" = ALOAD ["); try v.array.format(writer); try writer.writeAll("]["); try v.index.format(writer); try writer.writeAll("]"); },
            .arr_store => |v| { try writer.writeAll("ASTORE ["); try v.array.format(writer); try writer.writeAll("]["); try v.index.format(writer); try writer.writeAll("] = "); try v.src.format(writer); },
            .ret => |v| {
                if (v) |op| { try writer.writeAll("RET "); try op.format(writer); } else try writer.writeAll("RET");
            },
            .throw_stub => |v| { try writer.writeAll("THROW "); try v.src.format(writer); },
            .bounds_check => |v| { try writer.writeAll("BOUNDS_CHECK idx="); try v.index.format(writer); try writer.writeAll(" arr="); try v.array.format(writer); },
        }
    }
};

pub const MachineBlock = struct {
    id: usize,
    instructions: std.ArrayList(Inst),

    pub fn deinit(self: *MachineBlock, allocator: std.mem.Allocator) void {
        self.instructions.deinit(allocator);
    }
};

pub const MachineProgram = struct {
    blocks: std.ArrayList(MachineBlock),
    allocator: std.mem.Allocator,
    stack_space: i32 = 0,

    pub fn deinit(self: *MachineProgram) void {
        for (self.blocks.items) |*b| b.instructions.deinit(self.allocator);
        self.blocks.deinit(self.allocator);
    }
};

