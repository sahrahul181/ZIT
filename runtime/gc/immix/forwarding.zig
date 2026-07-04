const std = @import("std");
const mark = @import("mark.zig");

// We use bit 62 of the class_ptr in the ObjectHeader to indicate if the object was forwarded.
// Bit 63 is the MARK_BIT (defined in mark.zig).
pub const FORWARDED_BIT: u64 = 1 << 62;
pub const FLAG_MASK: u64 = FORWARDED_BIT | mark.MARK_BIT;

/// Checks if an object has been forwarded to a new address during evacuation.
pub inline fn isForwarded(class_ptr_field: usize) bool {
    return (class_ptr_field & FORWARDED_BIT) != 0;
}

/// Retrieves the new forwarding address from an old object's header.
pub inline fn getForwardingAddress(class_ptr_field: usize) usize {
    std.debug.assert(isForwarded(class_ptr_field));
    // Strip both flag bits to recover the absolute memory address
    return class_ptr_field & ~FLAG_MASK;
}

/// Installs a forwarding pointer into an old object's header.
/// This replaces the class_ptr with the new physical address and sets the FORWARDED_BIT.
pub inline fn installForwardingPointer(class_ptr_field: *usize, new_address: usize) void {
    // The object is logically "marked" if it's forwarded, so we keep the MARK_BIT set too.
    const new_val = new_address | FORWARDED_BIT | mark.MARK_BIT;
    @atomicStore(usize, class_ptr_field, new_val, .release);
}

// ── Tests ─────────────────────────────────────────────────────────────────────

test "Forwarding logic" {
    var dummy_class_ptr: usize = 0x0000_1234_5678_9ABC;
    
    // Not forwarded initially
    try std.testing.expect(!isForwarded(dummy_class_ptr));
    
    // Let's pretend this object gets evacuated to a new address
    const new_obj_address: usize = 0x0000_BBBB_CCCC_DDDD;
    installForwardingPointer(&dummy_class_ptr, new_obj_address);
    
    // Now it should be forwarded
    try std.testing.expect(isForwarded(dummy_class_ptr));
    
    // And we can recover the exact new address
    const recovered_address = getForwardingAddress(dummy_class_ptr);
    try std.testing.expectEqual(new_obj_address, recovered_address);
    
    // The mark bit should also remain set since a forwarded object is intrinsically a live (marked) object
    try std.testing.expect(mark.isMarked(dummy_class_ptr));
}
