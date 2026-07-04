const std = @import("std");
const layout = @import("layout.zig");
const Block = layout.Block;
const LINES_PER_BLOCK = layout.LINES_PER_BLOCK;

pub const BlockState = enum {
    empty,
    recyclable,
    full,
};

pub const SweepResult = struct {
    state: BlockState,
    free_lines: u16,
    hole_count: u16,
};

/// Sweeps a block by analyzing its line map.
/// It returns the block state, resets the line map for empty/recyclable lines, 
/// and determines if the block should be a candidate for opportunistic evacuation.
pub fn sweepBlock(block: *Block) SweepResult {
    var free_lines: u16 = 0;
    var hole_count: u16 = 0;
    var in_hole = false;
    
    // We start from Line 1, because Line 0 is the block metadata and is permanently occupied.
    for (1..LINES_PER_BLOCK) |i| {
        if (!block.line_map.isSet(i)) {
            free_lines += 1;
            if (!in_hole) {
                hole_count += 1;
                in_hole = true;
            }
        } else {
            in_hole = false;
        }
    }
    
    block.free_lines = free_lines;
    block.hole_count = hole_count;
    
    // An empty block has all lines free except Line 0
    if (free_lines == LINES_PER_BLOCK - 1) {
        block.flags.is_evacuation_candidate = false;
        return .{ .state = .empty, .free_lines = free_lines, .hole_count = hole_count };
    }
    
    // If the block has less than a certain threshold of free lines, it's considered full.
    // For example, less than 5% free lines (127 * 0.05 = 6).
    const is_full = free_lines < 6;
    
    if (is_full) {
        // Opportunistic Evacuation logic:
        // If it's full but highly fragmented (many small holes), it's a prime candidate for evacuation.
        // We'll define "highly fragmented" as having more than 3 holes, even though there's < 6 lines free.
        if (hole_count >= 3) {
            block.flags.is_evacuation_candidate = true;
        } else {
            block.flags.is_evacuation_candidate = false;
        }
        return .{ .state = .full, .free_lines = free_lines, .hole_count = hole_count };
    }
    
    // Otherwise, the block is recyclable. The mutator allocator can find holes in it.
    block.flags.is_evacuation_candidate = false;
    return .{ .state = .recyclable, .free_lines = free_lines, .hole_count = hole_count };
}

/// Reset a block's line map for a new GC cycle.
/// All previously marked lines become unmarked, EXCEPT we usually do this 
/// *after* sweeping. Wait, in Immix, we sweep after marking. 
/// Then we clear the marks to prepare for the *next* mark phase? 
/// Actually, the line map IS the allocation map! We only clear marks for lines
/// that are completely empty, but we leave marked lines as marked so the allocator
/// doesn't overwrite live objects. 
/// Wait: Immix clears the *entire* mark bitmap at the START of the GC cycle, 
/// then traces objects and sets the bits. 
/// Then sweep reads the bits, and hands the block back to the allocator.
/// The allocator uses those exact bits to find holes.
/// So we DO NOT clear the bits after sweeping! We clear them at the start of GC.
pub fn clearMarks(block: *Block) void {
    block.line_map.clear();
    // Re-mark Line 0 because it holds block metadata
    block.line_map.set(0);
}

// ── Tests ─────────────────────────────────────────────────────────────────────

test "Sweep logic" {
    const allocator = std.testing.allocator;
    const raw_mem = try allocator.alloc(u8, layout.BLOCK_SIZE * 2);
    defer allocator.free(raw_mem);
    
    const raw_addr = @intFromPtr(raw_mem.ptr);
    const aligned_addr = (raw_addr + layout.BLOCK_SIZE - 1) & ~(layout.BLOCK_SIZE - 1);
    const block = @as(*Block, @ptrFromInt(aligned_addr));
    block.* = Block.init();
    
    // Test 1: Completely empty block
    clearMarks(block); // Marks Line 0
    var result = sweepBlock(block);
    try std.testing.expectEqual(BlockState.empty, result.state);
    try std.testing.expectEqual(@as(u16, 127), result.free_lines);
    try std.testing.expectEqual(@as(u16, 1), result.hole_count); // One massive hole
    
    // Test 2: Full block (only 4 lines free, highly fragmented)
    clearMarks(block);
    for (1..layout.LINES_PER_BLOCK) |i| block.line_map.set(i);
    // Unmark a few lines to create small holes
    block.line_map.bits[0] &= ~(@as(u64, 1) << 10); // hole at 10
    block.line_map.bits[0] &= ~(@as(u64, 1) << 20); // hole at 20
    block.line_map.bits[0] &= ~(@as(u64, 1) << 30); // hole at 30
    block.line_map.bits[0] &= ~(@as(u64, 1) << 40); // hole at 40
    
    result = sweepBlock(block);
    try std.testing.expectEqual(BlockState.full, result.state);
    try std.testing.expectEqual(@as(u16, 4), result.free_lines);
    try std.testing.expectEqual(@as(u16, 4), result.hole_count);
    try std.testing.expect(block.flags.is_evacuation_candidate); // fragmented!
    
    // Test 3: Recyclable block
    clearMarks(block);
    for (1..50) |i| block.line_map.set(i); // First 49 lines used. Remaining 78 lines free as one hole.
    result = sweepBlock(block);
    try std.testing.expectEqual(BlockState.recyclable, result.state);
    try std.testing.expectEqual(@as(u16, 78), result.free_lines);
    try std.testing.expectEqual(@as(u16, 1), result.hole_count);
    try std.testing.expect(!block.flags.is_evacuation_candidate);
}
