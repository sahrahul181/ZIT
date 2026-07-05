const std = @import("std");
const ir = @import("ir");

pub const DeoptMetadata = struct {
    pc: usize,
    stack_layout: std.ArrayList(ir.SSAVar),
};
