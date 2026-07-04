const std = @import("std");
const layout = @import("layout.zig");
const Block = layout.Block;
const LINE_SIZE = layout.LINE_SIZE;

// Mask for the highest bit of a 64-bit pointer, used to mark objects in the header.
pub const MARK_BIT: u64 = 1 << 63;

/// Attempt to mark an object. Returns true if it was newly marked, false if it was already marked.
pub inline fn markObjectHeader(class_ptr_field: *usize) bool {
    const current = @atomicLoad(usize, class_ptr_field, .acquire);
    if ((current & MARK_BIT) != 0) return false;
    
    // We use a CAS to handle concurrent marking safely
    return @cmpxchgWeak(usize, class_ptr_field, current, current | MARK_BIT, .release, .monotonic) == null;
}

pub inline fn isMarked(class_ptr: usize) bool {
    return (class_ptr & MARK_BIT) != 0;
}

pub inline fn getRawClassPtr(class_ptr: usize) usize {
    return class_ptr & ~MARK_BIT;
}

/// Given an object's start address and its size in bytes, mark the lines it occupies in its block.
pub fn markLines(obj_addr: usize, total_size: usize) void {
    const block = Block.fromAddress(obj_addr);
    const start_line = Block.lineIndex(obj_addr);
    
    // An object spans from obj_addr to obj_addr + total_size - 1
    const end_addr = obj_addr + total_size - 1;
    const end_line = Block.lineIndex(end_addr);
    
    for (start_line..end_line + 1) |line_idx| {
        block.line_map.set(line_idx);
    }
}

/// Traces and marks a single object autonomously. The caller (runtime) must 
/// provide the instance_size since GC is decoupled from VM class metadata.
pub fn markObject(obj_addr: usize, instance_size: usize) void {
    const class_ptr_field = @as(*usize, @ptrFromInt(obj_addr));
    
    // Try to mark the header. If it's already marked, we're done.
    if (!markObjectHeader(class_ptr_field)) return;
    
    // Header is 16 bytes (class_ptr + monitor)
    const header_size = 16;
    const total_size = std.mem.alignForward(usize, header_size + instance_size, 8);
    
    markLines(obj_addr, total_size);
}

// ── Tests ─────────────────────────────────────────────────────────────────────

test "Marking logic" {
    // 1. Test object header marking
    var dummy_class_ptr: usize = 0x0000_1234_5678_9ABC;
    
    try std.testing.expect(!isMarked(dummy_class_ptr));
    try std.testing.expectEqual(@as(usize, 0x0000_1234_5678_9ABC), getRawClassPtr(dummy_class_ptr));
    
    // Mark it
    const newly_marked = markObjectHeader(&dummy_class_ptr);
    try std.testing.expect(newly_marked);
    try std.testing.expect(isMarked(dummy_class_ptr));
    
    // Mark it again (should return false)
    const newly_marked_again = markObjectHeader(&dummy_class_ptr);
    try std.testing.expect(!newly_marked_again);
    
    // Unmasking should yield the original pointer
    try std.testing.expectEqual(@as(usize, 0x0000_1234_5678_9ABC), getRawClassPtr(dummy_class_ptr));
    
    // 2. Test line marking
    const allocator = std.testing.allocator;
    const raw_mem = try allocator.alloc(u8, layout.BLOCK_SIZE * 2);
    defer allocator.free(raw_mem);
    
    const raw_addr = @intFromPtr(raw_mem.ptr);
    const aligned_addr = (raw_addr + layout.BLOCK_SIZE - 1) & ~(layout.BLOCK_SIZE - 1);
    const block = @as(*Block, @ptrFromInt(aligned_addr));
    block.* = Block.init();
    
    // We have an object starting at Line 1, offset 10 (address = block_start + 256 + 10 = 266)
    // The object is 500 bytes long. 
    // It spans:
    // Line 1: 256..512 (246 bytes here)
    // Line 2: 512..768 (256 bytes here) -> total 502 bytes, so it ends in Line 2!
    // Wait: 266 + 500 - 1 = 765. Line 2 ends at 767. So it occupies Line 1 and 2.
    
    const obj_address = aligned_addr + layout.LINE_SIZE + 10;
    markLines(obj_address, 500);
    
    try std.testing.expect(!block.line_map.isSet(0)); // Metadata line
    try std.testing.expect(block.line_map.isSet(1));
    try std.testing.expect(block.line_map.isSet(2));
    try std.testing.expect(!block.line_map.isSet(3));
}
