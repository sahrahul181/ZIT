//! Dalvik instruction set: Comprehensive definition for the complete Java
//! Standard Library object model and runtime.
//!
//! This expands the original `fib`-scoped instruction set to encompass the
//! full Dalvik bytecode vocabulary, including object instantiation, field
//! accesses (iget/iput), arrays, synchronization (monitor-enter/exit),
//! exceptions, and 64-bit/floating-point mathematics.
//!
//! Note: Dalvik's width-specific and encoding-specific variants (e.g.,
//! `move/from16`, `move/16`, `/2addr` binary ops, `goto/16`, `goto/32`)
//! are structurally flattened here into unified semantic operations. The
//! DEX parser handles resolving the compact encodings into these uniform
//! structs.

const std = @import("std");

// --- Operand Structures ---
// Designed for tight memory packing to minimize union bloat.

pub const CatchHandler = struct {
    type_idx: ?u32, // null for catch-all
    target_pc: u32,
};

pub const TryBlock = struct {
    start_pc: u32,
    end_pc: u32,
    handlers: []const CatchHandler,
};

pub const BinOp = struct { dest: u16, src1: u16, src2: u16 };
pub const UnOp = struct { dest: u16, src: u16 };
pub const LitOp = struct { dest: u16, src: u16, lit: i8 };
pub const Lit16Op = struct { dest: u16, src: u16, lit: i16 };
pub const IfOp = struct { offset: i32, src1: u16, src2: u16 };
pub const IfzOp = struct { offset: i32, src: u16 };
pub const CmpOp = struct { dest: u16, src1: u16, src2: u16 };

/// Represents instance field operations (iget/iput)
pub const FieldOp = struct { field_idx: u32, dest_or_src: u16, obj: u16 };
/// Represents static field operations (sget/sput)
pub const StaticFieldOp = struct { field_idx: u32, dest_or_src: u16 };
/// Represents array element operations (aget/aput)
pub const ArrayOp = struct { dest_or_src: u16, array: u16, index: u16 };
/// Represents type-based operations (new-instance, check-cast)
pub const TypeOp = struct { type_idx: u32, dest: u16 };
/// Represents switch statements pointing to a payload table.
/// `keys`/`targets` are the resolved payload table (parallel slices):
/// if `src == keys[i]`, branch to instruction `pc + targets[i]`.
/// The DEX parser fills these when it decodes the payload; when empty the
/// switch falls through (no resolved table available).
pub const SwitchOp = struct {
    payload_offset: i32,
    src: u16,
    keys: []const i32 = &.{},
    targets: []const i32 = &.{},
};

pub const InvokeKind = enum(u8) { virtual, super, direct, static, interface, polymorphic, custom };

/// Heavy struct: This is explicitly allocated by the parser and referenced via
/// pointer in the Instruction union. This prevents the entire Instruction array
/// from ballooning to ~96 bytes per instruction, keeping it cache-friendly.
pub const Invoke = struct {
    class_name: []const u8,
    method_name: []const u8,
    signature: []const u8,
    args: []const u16,

    /// Set by `jit/program.zig`'s `resolveInvokeTargets`. Index into the
    /// program's shared method list.
    call_target: ?u32 = null,

    /// Set by `jit/natives.zig`'s `resolveNativeTargets`. Index into the
    /// native function table (e.g., System.out.println).
    native_target: ?u32 = null,

    dest: ?u16,
    kind: InvokeKind,

    /// Set by jit/compiler.zig's `markSelfCalls` pass when this invoke is a
    /// direct recursive call to the method being compiled.
    is_self_call: bool = false,
};

// --- The Complete Dalvik Instruction Set ---
// Bound to u8 to guarantee tight 1-byte tags.
// Max payload size is now ~16-24 bytes instead of ~96.

pub const Instruction = union(enum(u8)) {
    // -- Base & Moves --
    nop,
    move: struct { dest: u16, src: u16 },
    move_wide: struct { dest: u16, src: u16 },
    move_object: struct { dest: u16, src: u16 },
    move_result: struct { dest: u16 },
    move_result_wide: struct { dest: u16 },
    move_result_object: struct { dest: u16 },
    move_exception: struct { dest: u16 },

    // -- Returns --
    return_void,
    return_: struct { src: u16 },
    return_wide: struct { src: u16 },
    return_object: struct { src: u16 },

    // -- Constants --
    const_: struct { value: i32, dest: u16 },
    const_wide: struct { value: i64, dest: u16 },
    const_string: struct { index: u32, dest: u16 },
    const_class: struct { type_idx: u32, dest: u16 },
    const_method_handle: struct { index: u32, dest: u16 },
    const_method_type: struct { index: u32, dest: u16 },

    // -- Monitors & Synchronization (Thin Locks) --
    monitor_enter: struct { src: u16 },
    monitor_exit: struct { src: u16 },

    // -- Checks & Casts --
    check_cast: struct { type_idx: u32, src: u16 },
    instance_of: struct { type_idx: u32, dest: u16, src: u16 },

    // -- Allocation & Arrays --
    array_length: struct { dest: u16, array: u16 },
    new_instance: TypeOp,
    new_array: struct { type_idx: u32, dest: u16, size: u16 },
    filled_new_array: struct { args: []const u16, type_idx: u32 }, // Keeping slice here; rarely used
    /// `data` is the resolved element payload (sign-extended to i64 regardless
    /// of element width). Filled by the DEX parser; empty = unresolved.
    fill_array_data: struct { payload_offset: i32, array: u16, data: []const i64 = &.{} },

    // -- Exceptions --
    throw_: struct { src: u16 },

    // -- Control Flow --
    goto_: struct { offset: i32 },
    packed_switch: SwitchOp,
    sparse_switch: SwitchOp,

    // -- Comparisons --
    cmpl_float: CmpOp,
    cmpg_float: CmpOp,
    cmpl_double: CmpOp,
    cmpg_double: CmpOp,
    cmp_long: CmpOp,

    // -- Conditional Branches --
    if_eq: IfOp,
    if_ne: IfOp,
    if_lt: IfOp,
    if_ge: IfOp,
    if_gt: IfOp,
    if_le: IfOp,
    if_eqz: IfzOp,
    if_nez: IfzOp,
    if_ltz: IfzOp,
    if_gez: IfzOp,
    if_gtz: IfzOp,
    if_lez: IfzOp,

    // -- Array Access (aget/aput) --
    aget: ArrayOp,
    aget_wide: ArrayOp,
    aget_object: ArrayOp,
    aget_boolean: ArrayOp,
    aget_byte: ArrayOp,
    aget_char: ArrayOp,
    aget_short: ArrayOp,
    aput: ArrayOp,
    aput_wide: ArrayOp,
    aput_object: ArrayOp,
    aput_boolean: ArrayOp,
    aput_byte: ArrayOp,
    aput_char: ArrayOp,
    aput_short: ArrayOp,

    // -- Instance Fields (iget/iput) --
    iget: FieldOp,
    iget_wide: FieldOp,
    iget_object: FieldOp,
    iget_boolean: FieldOp,
    iget_byte: FieldOp,
    iget_char: FieldOp,
    iget_short: FieldOp,
    iput: FieldOp,
    iput_wide: FieldOp,
    iput_object: FieldOp,
    iput_boolean: FieldOp,
    iput_byte: FieldOp,
    iput_char: FieldOp,
    iput_short: FieldOp,

    // -- Static Fields (sget/sput) --
    sget: StaticFieldOp,
    sget_wide: StaticFieldOp,
    sget_object: StaticFieldOp,
    sget_boolean: StaticFieldOp,
    sget_byte: StaticFieldOp,
    sget_char: StaticFieldOp,
    sget_short: StaticFieldOp,
    sput: StaticFieldOp,
    sput_wide: StaticFieldOp,
    sput_object: StaticFieldOp,
    sput_boolean: StaticFieldOp,
    sput_byte: StaticFieldOp,
    sput_char: StaticFieldOp,
    sput_short: StaticFieldOp,

    // -- Invocation --
    // Architectural Change: Stored as a pointer to significantly shrink the
    // Instruction union size, vastly improving L1 cache locality across the compiler.
    invoke: *Invoke,

    // -- Unary Math & Conversions --
    neg_int: UnOp,
    not_int: UnOp,
    neg_long: UnOp,
    not_long: UnOp,
    neg_float: UnOp,
    neg_double: UnOp,
    int_to_long: UnOp,
    int_to_float: UnOp,
    int_to_double: UnOp,
    long_to_int: UnOp,
    long_to_float: UnOp,
    long_to_double: UnOp,
    float_to_int: UnOp,
    float_to_long: UnOp,
    float_to_double: UnOp,
    double_to_int: UnOp,
    double_to_long: UnOp,
    double_to_float: UnOp,
    int_to_byte: UnOp,
    int_to_char: UnOp,
    int_to_short: UnOp,

    // -- Binary Math (Register/Register) --
    add_int: BinOp,
    sub_int: BinOp,
    mul_int: BinOp,
    div_int: BinOp,
    rem_int: BinOp,
    and_int: BinOp,
    or_int: BinOp,
    xor_int: BinOp,
    shl_int: BinOp,
    shr_int: BinOp,
    ushr_int: BinOp,
    add_long: BinOp,
    sub_long: BinOp,
    mul_long: BinOp,
    div_long: BinOp,
    rem_long: BinOp,
    and_long: BinOp,
    or_long: BinOp,
    xor_long: BinOp,
    shl_long: BinOp,
    shr_long: BinOp,
    ushr_long: BinOp,
    add_float: BinOp,
    sub_float: BinOp,
    mul_float: BinOp,
    div_float: BinOp,
    rem_float: BinOp,
    add_double: BinOp,
    sub_double: BinOp,
    mul_double: BinOp,
    div_double: BinOp,
    rem_double: BinOp,

    // -- Binary Math (Lit16) --
    add_int_lit16: Lit16Op,
    rsub_int_lit16: Lit16Op,
    mul_int_lit16: Lit16Op,
    div_int_lit16: Lit16Op,
    rem_int_lit16: Lit16Op,
    and_int_lit16: Lit16Op,
    or_int_lit16: Lit16Op,
    xor_int_lit16: Lit16Op,

    // -- Binary Math (Lit8) --
    add_int_lit8: LitOp,
    rsub_int_lit8: LitOp,
    mul_int_lit8: LitOp,
    div_int_lit8: LitOp,
    rem_int_lit8: LitOp,
    and_int_lit8: LitOp,
    or_int_lit8: LitOp,
    xor_int_lit8: LitOp,
    shl_int_lit8: LitOp,
    shr_int_lit8: LitOp,
    ushr_int_lit8: LitOp,

    /// Returns the branch offset for simple control-flow instructions, or null
    /// for everything else. (Note: Packed/Sparse switches return null here
    /// as they don't have a singular fixed offset; they use payload tables).
    pub fn branchOffset(self: Instruction) ?i32 {
        return switch (self) {
            .goto_ => |v| v.offset,
            .if_eq, .if_ne, .if_lt, .if_ge, .if_gt, .if_le => |v| v.offset,
            .if_eqz, .if_nez, .if_ltz, .if_gez, .if_gtz, .if_lez => |v| v.offset,
            else => null,
        };
    }
};

test "Instruction branchOffset" {
    const inst_goto = Instruction{ .goto_ = .{ .offset = 42 } };
    try std.testing.expectEqual(@as(?i32, 42), inst_goto.branchOffset());

    const inst_if_eq = Instruction{ .if_eq = .{ .src1 = 1, .src2 = 2, .offset = -10 } };
    try std.testing.expectEqual(@as(?i32, -10), inst_if_eq.branchOffset());

    const inst_if_eqz = Instruction{ .if_eqz = .{ .src = 1, .offset = 5 } };
    try std.testing.expectEqual(@as(?i32, 5), inst_if_eqz.branchOffset());

    const inst_nop = Instruction{ .nop = {} };
    try std.testing.expectEqual(@as(?i32, null), inst_nop.branchOffset());
}

