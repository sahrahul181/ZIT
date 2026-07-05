const std = @import("std");

// --- Variables ---

/// Represents a variable in Static Single Assignment (SSA) form.
/// Initially, `version` will be 0. The Renaming phase will overwrite it.
pub const SSAVar = struct {
    reg: u16,
    version: u32,

    /// Custom formatter to print variables like "v0_1"
    pub fn format(
        self: SSAVar,
        writer: *std.Io.Writer,
    ) !void {
        try writer.print("v{d}_{d}", .{ self.reg, self.version });
    }
};

/// An argument to a Phi function, linking a predecessor block to the
/// specific version of the variable that flows from it.
pub const PhiArg = struct {
    pred_block_id: usize,
    val: SSAVar,
};

// --- Operation Payloads ---

pub const BinOp = struct { dest: SSAVar, left: SSAVar, right: SSAVar };
pub const UnOp = struct { dest: SSAVar, src: SSAVar };
pub const BinOpLit = struct { dest: SSAVar, src: SSAVar, lit: i32 };

pub const CondBranch = struct {
    left: SSAVar,
    right: SSAVar,
    /// The block to jump to if the condition is true.
    /// (If false, it falls through to the next block sequentially).
    target_block_id: usize,
};

pub const CondBranchZ = struct { src: SSAVar, target_block_id: usize };

/// Unary operations: negation, bitwise-not, and all primitive type conversions.
/// Values live in 64-bit registers; int results are kept sign-extended to 64 bits,
/// so `int_to_long` is a plain copy while `long_to_int` re-sign-extends the low 32 bits.
pub const UnOpKind = enum {
    neg_int,
    not_int,
    neg_long,
    not_long,
    neg_float,
    neg_double,
    int_to_long,
    int_to_float,
    int_to_double,
    long_to_int,
    long_to_float,
    long_to_double,
    float_to_int,
    float_to_long,
    float_to_double,
    double_to_int,
    double_to_long,
    double_to_float,
    int_to_byte,
    int_to_char,
    int_to_short,
};

/// Three-way comparisons producing -1/0/1 in an integer register.
/// The `l`/`g` variants encode Dalvik's NaN bias: cmpl → -1 on NaN, cmpg → +1 on NaN.
pub const CmpKind = enum {
    cmp_long,
    cmpl_float,
    cmpg_float,
    cmpl_double,
    cmpg_double,
};

pub const FieldAccess = struct { dest_or_src: SSAVar, obj: SSAVar, field_idx: u32 };
pub const StaticFieldAccess = struct { dest_or_src: SSAVar, field_idx: u32 };
pub const ArrayAccess = struct { dest_or_src: SSAVar, array: SSAVar, index: SSAVar };

// --- The IR Instruction Set ---

/// A unified, SSA-ready instruction set.
/// Slices (like `[]PhiArg` or `[]SSAVar`) should be allocated using an ArenaAllocator
/// tied to the lifespan of the CFG.
pub const IRInst = union(enum) {
    // SSA specific
    phi: struct { dest: SSAVar, args: []PhiArg },

    // Base
    move: UnOp,

    // Unary math & type conversions
    un_op: struct { kind: UnOpKind, dest: SSAVar, src: SSAVar },

    // Three-way comparisons (cmp-long, cmpl/cmpg-float/double) → -1/0/1
    cmp_op: struct { kind: CmpKind, dest: SSAVar, left: SSAVar, right: SSAVar },

    // Constants
    const_int: struct { dest: SSAVar, val: i32 },
    const_wide: struct { dest: SSAVar, val: i64 },
    const_string: struct { dest: SSAVar, str_idx: u32 },
    const_class: struct { dest: SSAVar, type_idx: u32 },

    // Integer Math
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

    // Integer Math (Literal)
    add_lit: BinOpLit,
    sub_lit: BinOpLit,
    mul_lit: BinOpLit,
    div_lit: BinOpLit,
    rem_lit: BinOpLit,
    and_lit: BinOpLit,
    or_lit: BinOpLit,
    xor_lit: BinOpLit,
    shl_lit: BinOpLit,
    shr_lit: BinOpLit,
    ushr_lit: BinOpLit,

    // Long (64-bit integer) Math
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

    // Floating Point & Wide Math
    add_float: BinOp,
    sub_float: BinOp,
    mul_float: BinOp,
    div_float: BinOp,
    rem_float: BinOp,
    add_wide: BinOp,
    sub_wide: BinOp,
    mul_wide: BinOp,
    div_wide: BinOp,
    rem_wide: BinOp,

    // Object & Array Allocation
    new_instance: struct { dest: SSAVar, type_idx: u32 },
    new_array: struct { dest: SSAVar, size: SSAVar, type_idx: u32 },
    array_length: struct { dest: SSAVar, array: SSAVar },
    instance_of: struct { dest: SSAVar, obj: SSAVar, type_idx: u32 },
    filled_new_array: struct { dest: ?SSAVar, type_idx: u32, args: [5]?SSAVar },
    fill_array_data: struct { array: SSAVar, data_ptr: usize, data_len: u32, elem_width: u32 },
    move_exception: struct { dest: SSAVar },


    // Memory Access
    iget: FieldAccess,
    iput: FieldAccess,
    sget: StaticFieldAccess,
    sput: StaticFieldAccess,
    aget: ArrayAccess,
    aput: ArrayAccess,
    bounds_check: struct { index: SSAVar, array: SSAVar },

    // Control Flow
    goto: struct { target_block_id: usize },
    if_eq: CondBranch,
    if_ne: CondBranch,
    if_lt: CondBranch,
    if_ge: CondBranch,
    if_gt: CondBranch,
    if_le: CondBranch,
    if_eqz: CondBranchZ,
    if_nez: CondBranchZ,
    if_ltz: CondBranchZ,
    if_gez: CondBranchZ,
    if_gtz: CondBranchZ,
    if_lez: CondBranchZ,

    // Switches
    switch_op: struct { src: SSAVar, keys: []const i32, target_block_ids: []const usize },

    // Function Calls & Returns
    invoke: struct {
        dest: ?SSAVar, // null if return type is void or result is unused
        method_idx: u32,
        is_static: bool,
        args: []SSAVar,
        is_self_call: bool = false,
    },
    monitor_enter: struct { src: SSAVar },
    monitor_exit: struct { src: SSAVar },
    ret: struct { src: ?SSAVar },
    throw_op: struct { src: SSAVar },

    // --- Pretty Printing ---

    /// Dumps the IR instruction to a writer in a human-readable format.
    pub fn format(
        self: IRInst,
        writer: *std.Io.Writer,
    ) !void {
        switch (self) {
            .phi => |v| {
                try writer.print("{f} = phi(", .{v.dest});
                for (v.args, 0..) |arg, i| {
                    if (i > 0) try writer.writeAll(", ");
                    try writer.print("[bb{d}: {f}]", .{ arg.pred_block_id, arg.val });
                }
                try writer.writeAll(")");
            },
            .move => |v| try writer.print("{f} = move {f}", .{ v.dest, v.src }),
            .un_op => |v| try writer.print("{f} = {s} {f}", .{ v.dest, @tagName(v.kind), v.src }),
            .cmp_op => |v| try writer.print("{f} = {s} {f}, {f}", .{ v.dest, @tagName(v.kind), v.left, v.right }),

            .const_int => |v| try writer.print("{f} = const {d}", .{ v.dest, v.val }),
            .const_wide => |v| try writer.print("{f} = const-wide {d}", .{ v.dest, v.val }),
            .const_string => |v| try writer.print("{f} = const-string @{d}", .{ v.dest, v.str_idx }),
            .const_class => |v| try writer.print("{f} = const-class @{d}", .{ v.dest, v.type_idx }),

            .add_int => |v| try writer.print("{f} = add {f}, {f}", .{ v.dest, v.left, v.right }),
            .sub_int => |v| try writer.print("{f} = sub {f}, {f}", .{ v.dest, v.left, v.right }),
            .mul_int => |v| try writer.print("{f} = mul {f}, {f}", .{ v.dest, v.left, v.right }),
            .div_int => |v| try writer.print("{f} = div {f}, {f}", .{ v.dest, v.left, v.right }),
            .rem_int => |v| try writer.print("{f} = rem {f}, {f}", .{ v.dest, v.left, v.right }),
            .and_int => |v| try writer.print("{f} = and {f}, {f}", .{ v.dest, v.left, v.right }),
            .or_int => |v| try writer.print("{f} = or {f}, {f}", .{ v.dest, v.left, v.right }),
            .xor_int => |v| try writer.print("{f} = xor {f}, {f}", .{ v.dest, v.left, v.right }),
            .shl_int => |v| try writer.print("{f} = shl {f}, {f}", .{ v.dest, v.left, v.right }),
            .shr_int => |v| try writer.print("{f} = shr {f}, {f}", .{ v.dest, v.left, v.right }),
            .ushr_int => |v| try writer.print("{f} = ushr {f}, {f}", .{ v.dest, v.left, v.right }),

            .add_lit => |v| try writer.print("{f} = add {f}, #{d}", .{ v.dest, v.src, v.lit }),
            .sub_lit => |v| try writer.print("{f} = sub {f}, #{d}", .{ v.dest, v.src, v.lit }),
            .mul_lit => |v| try writer.print("{f} = mul {f}, #{d}", .{ v.dest, v.src, v.lit }),
            .div_lit => |v| try writer.print("{f} = div {f}, #{d}", .{ v.dest, v.src, v.lit }),
            .rem_lit => |v| try writer.print("{f} = rem {f}, #{d}", .{ v.dest, v.src, v.lit }),
            .and_lit => |v| try writer.print("{f} = and {f}, #{d}", .{ v.dest, v.src, v.lit }),
            .or_lit => |v| try writer.print("{f} = or {f}, #{d}", .{ v.dest, v.src, v.lit }),
            .xor_lit => |v| try writer.print("{f} = xor {f}, #{d}", .{ v.dest, v.src, v.lit }),
            .shl_lit => |v| try writer.print("{f} = shl {f}, #{d}", .{ v.dest, v.src, v.lit }),
            .shr_lit => |v| try writer.print("{f} = shr {f}, #{d}", .{ v.dest, v.src, v.lit }),
            .ushr_lit => |v| try writer.print("{f} = ushr {f}, #{d}", .{ v.dest, v.src, v.lit }),

            .add_long => |v| try writer.print("{f} = add-long {f}, {f}", .{ v.dest, v.left, v.right }),
            .sub_long => |v| try writer.print("{f} = sub-long {f}, {f}", .{ v.dest, v.left, v.right }),
            .mul_long => |v| try writer.print("{f} = mul-long {f}, {f}", .{ v.dest, v.left, v.right }),
            .div_long => |v| try writer.print("{f} = div-long {f}, {f}", .{ v.dest, v.left, v.right }),
            .rem_long => |v| try writer.print("{f} = rem-long {f}, {f}", .{ v.dest, v.left, v.right }),
            .and_long => |v| try writer.print("{f} = and-long {f}, {f}", .{ v.dest, v.left, v.right }),
            .or_long => |v| try writer.print("{f} = or-long {f}, {f}", .{ v.dest, v.left, v.right }),
            .xor_long => |v| try writer.print("{f} = xor-long {f}, {f}", .{ v.dest, v.left, v.right }),
            .shl_long => |v| try writer.print("{f} = shl-long {f}, {f}", .{ v.dest, v.left, v.right }),
            .shr_long => |v| try writer.print("{f} = shr-long {f}, {f}", .{ v.dest, v.left, v.right }),
            .ushr_long => |v| try writer.print("{f} = ushr-long {f}, {f}", .{ v.dest, v.left, v.right }),
            .add_float => |v| try writer.print("{f} = add {f}, {f}", .{ v.dest, v.left, v.right }),
            .sub_float => |v| try writer.print("{f} = sub {f}, {f}", .{ v.dest, v.left, v.right }),
            .mul_float => |v| try writer.print("{f} = mul {f}, {f}", .{ v.dest, v.left, v.right }),
            .div_float => |v| try writer.print("{f} = div {f}, {f}", .{ v.dest, v.left, v.right }),
            .rem_float => |v| try writer.print("{f} = rem {f}, {f}", .{ v.dest, v.left, v.right }),
            .add_wide => |v| try writer.print("{f} = add-wide {f}, {f}", .{ v.dest, v.left, v.right }),
            .sub_wide => |v| try writer.print("{f} = sub-wide {f}, {f}", .{ v.dest, v.left, v.right }),
            .mul_wide => |v| try writer.print("{f} = mul-wide {f}, {f}", .{ v.dest, v.left, v.right }),
            .div_wide => |v| try writer.print("{f} = div-wide {f}, {f}", .{ v.dest, v.left, v.right }),
            .rem_wide => |v| try writer.print("{f} = rem-wide {f}, {f}", .{ v.dest, v.left, v.right }),

            .new_instance => |v| try writer.print("{f} = new-instance type@{d}", .{ v.dest, v.type_idx }),
            .new_array => |v| try writer.print("{f} = new-array {f}, type@{d}", .{ v.dest, v.size, v.type_idx }),
            .array_length => |v| try writer.print("{f} = array-length {f}", .{ v.dest, v.array }),
            .instance_of => |v| try writer.print("{f} = instance-of {f}, type@{d}", .{ v.dest, v.obj, v.type_idx }),
            .filled_new_array => |v| {
                if (v.dest) |d| {
                    try writer.print("{f} = ", .{d});
                }
                try writer.print("filled-new-array type@{d} {{ ", .{v.type_idx});
                for (v.args) |arg| {
                    if (arg) |a| {
                        try writer.print("{f}, ", .{a});
                    }
                }
                try writer.writeAll("}");
            },
            .fill_array_data => |v| try writer.print("fill-array-data {f}, data_ptr=0x{x}, len={d}", .{ v.array, v.data_ptr, v.data_len }),
            .move_exception => |v| try writer.print("{f} = move-exception", .{ v.dest }),


            .iget => |v| try writer.print("{f} = iget {f}.@{d}", .{ v.dest_or_src, v.obj, v.field_idx }),
            .iput => |v| try writer.print("{f}.@{d} = iput {f}", .{ v.obj, v.field_idx, v.dest_or_src }),
            .sget => |v| try writer.print("{f} = sget @{d}", .{ v.dest_or_src, v.field_idx }),
            .sput => |v| try writer.print("@{d} = sput {f}", .{ v.field_idx, v.dest_or_src }),
            .aget => |v| try writer.print("{f} = aget {f}[{f}]", .{ v.dest_or_src, v.array, v.index }),
            .aput => |v| try writer.print("{f}[{f}] = aput {f}", .{ v.array, v.index, v.dest_or_src }),
            .bounds_check => |v| try writer.print("bounds_check {f}, {f}", .{ v.index, v.array }),

            .goto => |v| try writer.print("goto bb{d}", .{v.target_block_id}),

            .if_eq => |v| try writer.print("if {f} == {f} goto bb{d}", .{ v.left, v.right, v.target_block_id }),
            .if_ne => |v| try writer.print("if {f} != {f} goto bb{d}", .{ v.left, v.right, v.target_block_id }),
            .if_ge => |v| try writer.print("if {f} >= {f} goto bb{d}", .{ v.left, v.right, v.target_block_id }),
            .if_gt => |v| try writer.print("if {f} > {f} goto bb{d}", .{ v.left, v.right, v.target_block_id }),
            .if_lt => |v| try writer.print("if {f} < {f} goto bb{d}", .{ v.left, v.right, v.target_block_id }),
            .if_le => |v| try writer.print("if {f} <= {f} goto bb{d}", .{ v.left, v.right, v.target_block_id }),
            .if_eqz => |v| try writer.print("if {f} == 0 goto bb{d}", .{ v.src, v.target_block_id }),
            .if_nez => |v| try writer.print("if {f} != 0 goto bb{d}", .{ v.src, v.target_block_id }),
            .if_ltz => |v| try writer.print("if {f} < 0 goto bb{d}", .{ v.src, v.target_block_id }),
            .if_gez => |v| try writer.print("if {f} >= 0 goto bb{d}", .{ v.src, v.target_block_id }),
            .if_gtz => |v| try writer.print("if {f} > 0 goto bb{d}", .{ v.src, v.target_block_id }),
            .if_lez => |v| try writer.print("if {f} <= 0 goto bb{d}", .{ v.src, v.target_block_id }),

            .switch_op => |v| {
                try writer.print("switch {f} (", .{v.src});
                for (v.keys, 0..) |key, i| {
                    if (i > 0) try writer.writeAll(", ");
                    try writer.print("{d} -> bb{d}", .{ key, v.target_block_ids[i] });
                }
                try writer.writeAll(")");
            },

            .invoke => |v| {
                if (v.dest) |d| {
                    try writer.print("{f} = ", .{d});
                }
                const call_type = if (v.is_static) "invoke-static" else "invoke-virtual";
                try writer.print("{s} @{d}(", .{ call_type, v.method_idx });
                for (v.args, 0..) |arg, i| {
                    if (i > 0) try writer.writeAll(", ");
                    try writer.print("{f}", .{arg});
                }
                try writer.writeAll(")");
            },

            .monitor_enter => |v| try writer.print("monitor-enter {f}", .{v.src}),
            .monitor_exit => |v| try writer.print("monitor-exit {f}", .{v.src}),
            .ret => |v| {
                if (v.src) |s| {
                    try writer.print("ret {f}", .{s});
                } else {
                    try writer.writeAll("ret void");
                }
            },
            .throw_op => |v| try writer.print("throw {f}", .{v.src}),
        }
    }
};

test "ir formatting: const, binop, and move" {
    var buf: [128]u8 = undefined;

    // Test const_int
    const inst_const = IRInst{ .const_int = .{ .dest = .{ .reg = 0, .version = 1 }, .val = 42 } };
    const s1 = try std.fmt.bufPrint(&buf, "{f}", .{inst_const});
    try std.testing.expectEqualStrings("v0_1 = const 42", s1);

    // Test add_int
    const inst_add = IRInst{ .add_int = .{
        .dest = .{ .reg = 2, .version = 0 },
        .left = .{ .reg = 0, .version = 1 },
        .right = .{ .reg = 1, .version = 2 },
    } };
    const s2 = try std.fmt.bufPrint(&buf, "{f}", .{inst_add});
    try std.testing.expectEqualStrings("v2_0 = add v0_1, v1_2", s2);

    // Test move
    const inst_move = IRInst{ .move = .{ .dest = .{ .reg = 3, .version = 4 }, .src = .{ .reg = 2, .version = 0 } } };
    const s3 = try std.fmt.bufPrint(&buf, "{f}", .{inst_move});
    try std.testing.expectEqualStrings("v3_4 = move v2_0", s3);
}

test "ir formatting: phi and ret" {
    var buf: [256]u8 = undefined;
    const a = std.testing.allocator;

    var args = try a.alloc(PhiArg, 2);
    defer a.free(args);
    args[0] = .{ .pred_block_id = 0, .val = .{ .reg = 1, .version = 1 } };
    args[1] = .{ .pred_block_id = 1, .val = .{ .reg = 1, .version = 2 } };

    const inst_phi = IRInst{ .phi = .{ .dest = .{ .reg = 1, .version = 3 }, .args = args } };
    const s1 = try std.fmt.bufPrint(&buf, "{f}", .{inst_phi});
    try std.testing.expectEqualStrings("v1_3 = phi([bb0: v1_1], [bb1: v1_2])", s1);

    const inst_ret = IRInst{ .ret = .{ .src = .{ .reg = 1, .version = 3 } } };
    const s2 = try std.fmt.bufPrint(&buf, "{f}", .{inst_ret});
    try std.testing.expectEqualStrings("ret v1_3", s2);

    const inst_ret_void = IRInst{ .ret = .{ .src = null } };
    const s3 = try std.fmt.bufPrint(&buf, "{f}", .{inst_ret_void});
    try std.testing.expectEqualStrings("ret void", s3);
}

test "ir formatting: un_op and cmp_op" {
    var buf: [128]u8 = undefined;

    const inst_neg = IRInst{ .un_op = .{
        .kind = .neg_int,
        .dest = .{ .reg = 1, .version = 1 },
        .src = .{ .reg = 0, .version = 1 },
    } };
    const s1 = try std.fmt.bufPrint(&buf, "{f}", .{inst_neg});
    try std.testing.expectEqualStrings("v1_1 = neg_int v0_1", s1);

    const inst_conv = IRInst{ .un_op = .{
        .kind = .int_to_byte,
        .dest = .{ .reg = 2, .version = 0 },
        .src = .{ .reg = 1, .version = 1 },
    } };
    const s2 = try std.fmt.bufPrint(&buf, "{f}", .{inst_conv});
    try std.testing.expectEqualStrings("v2_0 = int_to_byte v1_1", s2);

    const inst_cmp = IRInst{ .cmp_op = .{
        .kind = .cmpl_float,
        .dest = .{ .reg = 0, .version = 2 },
        .left = .{ .reg = 1, .version = 0 },
        .right = .{ .reg = 2, .version = 0 },
    } };
    const s3 = try std.fmt.bufPrint(&buf, "{f}", .{inst_cmp});
    try std.testing.expectEqualStrings("v0_2 = cmpl_float v1_0, v2_0", s3);
}

test "ir formatting: new long and rem operations" {
    var buf: [128]u8 = undefined;

    const inst_rem = IRInst{ .rem_long = .{
        .dest = .{ .reg = 2, .version = 0 },
        .left = .{ .reg = 0, .version = 1 },
        .right = .{ .reg = 1, .version = 2 },
    } };
    const s1 = try std.fmt.bufPrint(&buf, "{f}", .{inst_rem});
    try std.testing.expectEqualStrings("v2_0 = rem-long v0_1, v1_2", s1);

    const inst_xor = IRInst{ .xor_long = .{
        .dest = .{ .reg = 3, .version = 0 },
        .left = .{ .reg = 2, .version = 0 },
        .right = .{ .reg = 1, .version = 2 },
    } };
    const s2 = try std.fmt.bufPrint(&buf, "{f}", .{inst_xor});
    try std.testing.expectEqualStrings("v3_0 = xor-long v2_0, v1_2", s2);

    const inst_remw = IRInst{ .rem_wide = .{
        .dest = .{ .reg = 4, .version = 0 },
        .left = .{ .reg = 0, .version = 0 },
        .right = .{ .reg = 2, .version = 0 },
    } };
    const s3 = try std.fmt.bufPrint(&buf, "{f}", .{inst_remw});
    try std.testing.expectEqualStrings("v4_0 = rem-wide v0_0, v2_0", s3);
}

test "ir formatting: long operations" {
    var buf: [128]u8 = undefined;

    // Test add_long
    const inst_add = IRInst{ .add_long = .{
        .dest = .{ .reg = 2, .version = 0 },
        .left = .{ .reg = 0, .version = 1 },
        .right = .{ .reg = 1, .version = 2 },
    } };
    const s1 = try std.fmt.bufPrint(&buf, "{f}", .{inst_add});
    try std.testing.expectEqualStrings("v2_0 = add-long v0_1, v1_2", s1);

    // Test sub_long
    const inst_sub = IRInst{ .sub_long = .{
        .dest = .{ .reg = 3, .version = 0 },
        .left = .{ .reg = 2, .version = 0 },
        .right = .{ .reg = 1, .version = 2 },
    } };
    const s2 = try std.fmt.bufPrint(&buf, "{f}", .{inst_sub});
    try std.testing.expectEqualStrings("v3_0 = sub-long v2_0, v1_2", s2);
}
