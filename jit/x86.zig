const std = @import("std");
const ir = @import("ir");

pub const PhysicalReg = enum {
    rax, rcx, rdx, rbx, rsi, rdi, r8, r9, r10, r11, r12, r13, r14, r15,

    pub fn name(self: PhysicalReg) []const u8 {
        return @tagName(self);
    }
};

/// Operands for x86 virtual assembly.
pub const Operand = union(enum) {
    vreg:  ir.SSAVar,
    reg:   PhysicalReg,
    stack: i32, // Stack offset from RBP/RSP
    imm:   i32,
    imm64: i64,

    pub fn format(self: Operand, writer: *std.Io.Writer) !void {
        switch (self) {
            .vreg  => |v| try writer.print("v{d}_{d}", .{ v.reg, v.version }),
            .reg   => |r| try writer.print("%{s}", .{r.name()}),
            .stack => |o| try writer.print("[rbp-{d}]", .{o}),
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

    // ---- Bitwise ----
    and_op: struct { dest: Operand, src: Operand },
    or_op:  struct { dest: Operand, src: Operand },
    xor_op: struct { dest: Operand, src: Operand },
    shl:    struct { dest: Operand, src: Operand },
    shr:    struct { dest: Operand, src: Operand },  // arithmetic (SAR)
    ushr:   struct { dest: Operand, src: Operand },  // logical    (SHR)

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

    // ---- Switch (jump-table stub) ----
    switch_stub: struct { src: Operand, num_cases: usize },

    // ---- Method call stub ----
    call: struct {
        dest:       ?Operand,
        method_idx: u32,
        is_static:  bool,
        arg_count:  usize,
    },

    // ---- Allocation stubs ----
    alloc_obj: struct { dest: Operand, type_idx: u32 },
    alloc_arr: struct { dest: Operand, size: Operand, type_idx: u32 },

    // ---- Field access stubs ----
    field_load:  struct { dest: Operand, obj: ?Operand, field_idx: u32 },
    field_store: struct { src:  Operand, obj: ?Operand, field_idx: u32 },

    // ---- Array element access stubs ----
    arr_load:  struct { dest: Operand, array: Operand, index: Operand },
    arr_store: struct { src:  Operand, array: Operand, index: Operand },

    // ---- Returns & Exceptions ----
    ret:        ?Operand,
    throw_stub: struct { src: Operand },

    // ---- Pretty printing ----
    pub fn format(self: Inst, writer: *std.Io.Writer) !void {
        switch (self) {
            .mov     => |v| { try writer.writeAll("MOV ");  try v.dest.format(writer); try writer.writeAll(", "); try v.src.format(writer); },
            .add     => |v| { try writer.writeAll("ADD ");  try v.dest.format(writer); try writer.writeAll(", "); try v.src.format(writer); },
            .sub     => |v| { try writer.writeAll("SUB ");  try v.dest.format(writer); try writer.writeAll(", "); try v.src.format(writer); },
            .imul    => |v| { try writer.writeAll("IMUL "); try v.dest.format(writer); try writer.writeAll(", "); try v.src.format(writer); },
            .idiv    => |v| { try writer.writeAll("IDIV "); try v.dest.format(writer); try writer.writeAll(", "); try v.rem.format(writer); try writer.writeAll(" <- "); try v.src.format(writer); },
            .irem    => |v| { try writer.writeAll("IREM "); try v.dest.format(writer); try writer.writeAll(", "); try v.rem.format(writer); try writer.writeAll(" <- "); try v.src.format(writer); },
            .neg     => |v| { try writer.writeAll("NEG ");  try v.dest.format(writer); },
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
            .switch_stub => |v| { try writer.writeAll("SWITCH "); try v.src.format(writer); try writer.print(", {d} cases", .{v.num_cases}); },
            .call => |v| {
                if (v.dest) |d| { try d.format(writer); try writer.writeAll(" = "); }
                try writer.print("CALL method[{d}]", .{v.method_idx});
                if (!v.is_static) try writer.writeAll(" (virtual)");
                try writer.print(" ({d} args)", .{v.arg_count});
            },
            .alloc_obj  => |v| { try v.dest.format(writer); try writer.print(" = NEW type[{d}]", .{v.type_idx}); },
            .alloc_arr  => |v| { try v.dest.format(writer); try writer.writeAll(" = NEWARR["); try v.size.format(writer); try writer.print("] type[{d}]", .{v.type_idx}); },
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

    pub fn deinit(self: *MachineProgram) void {
        for (self.blocks.items) |*b| b.instructions.deinit(self.allocator);
        self.blocks.deinit(self.allocator);
    }
};

