pub const immix = struct {
    pub const allocator = @import("gc/immix/allocator.zig");
    pub const layout = @import("gc/immix/layout.zig");
    pub const mark = @import("gc/immix/mark.zig");
    pub const sweep = @import("gc/immix/sweep.zig");
    pub const forwarding = @import("gc/immix/forwarding.zig");
};
