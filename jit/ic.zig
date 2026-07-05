const std = @import("std");

pub const InlineCache = struct {
    cached_class: usize = 0,
    cached_target: usize = 0,
    method_idx: u32,
};
