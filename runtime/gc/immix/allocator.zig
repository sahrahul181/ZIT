const std = @import("std");
const layout = @import("layout.zig");
const Block = layout.Block;
const BLOCK_SIZE = layout.BLOCK_SIZE;
const LINE_SIZE = layout.LINE_SIZE;

/// Manages thread-local allocation (acting as a TLAB).
pub const MutatorAllocator = struct {
    /// The current block this thread is allocating into.
    current_block: ?*Block = null,
    
    /// Bump pointer for allocation.
    cursor: usize = 0,
    /// Upper limit of the current contiguous hole.
    limit: usize = 0,
    
    /// Request a new block from the global allocator when out of memory in current block.
    global_block_supplier: *const fn () ?*Block,
    
    pub fn init(supplier: *const fn () ?*Block) MutatorAllocator {
        return .{
            .global_block_supplier = supplier,
        };
    }
    
    /// Allocates `size` bytes. Returns null if OOM.
    pub inline fn alloc(self: *MutatorAllocator, size: usize) ?[*]u8 {
        // Fast path: bump allocation within current hole
        const aligned_size = std.mem.alignForward(usize, size, 8);
        
        while (true) {
            const next_cursor = self.cursor + aligned_size;
            if (next_cursor <= self.limit) {
                const ptr = self.cursor;
                self.cursor = next_cursor;
                return @as([*]u8, @ptrFromInt(ptr));
            }
            
            // Slow path: out of space in current hole.
            if (!self.findNextHole(aligned_size)) {
                // Out of space in current block. Request a new block.
                const new_block = self.global_block_supplier() orelse return null;
                self.setBlock(new_block);
            }
        }
    }
    
    /// Set a new block as the active allocation target.
    pub fn setBlock(self: *MutatorAllocator, block: *Block) void {
        self.current_block = block;
        // Start allocating from the first free line (Line 1, since Line 0 is metadata)
        // Wait! We should search for the first hole in the block, since a recycled block
        // might have marked lines scattered around. For a completely fresh block,
        // findNextHole will just find the huge hole from Line 1 to 127.
        self.cursor = @intFromPtr(block.lineAddress(1));
        self.limit = self.cursor; // Force findNextHole to trigger
    }
    
    /// Scan the current block's line_map for the next contiguous sequence of unmarked lines
    /// that is large enough to satisfy `min_size`.
    fn findNextHole(self: *MutatorAllocator, min_size: usize) bool {
        const block = self.current_block orelse return false;
        
        var start_line = if (self.limit == self.cursor) Block.lineIndex(self.cursor) else Block.lineIndex(self.limit);
        if (start_line >= layout.LINES_PER_BLOCK) return false;
        
        while (start_line < layout.LINES_PER_BLOCK) {
            // Find the first free line (bit is 0 in line_map)
            const hole_start = block.line_map.findFirstZeroAfter(start_line);
            if (hole_start >= layout.LINES_PER_BLOCK) return false; // No more holes
            
            // Find the end of this hole (first 1 after hole_start)
            const hole_end = block.line_map.findFirstOneAfter(hole_start);
            
            const current_hole_size = (hole_end - hole_start) * LINE_SIZE;
            if (current_hole_size >= min_size) {
                // Found a hole large enough
                self.cursor = @intFromPtr(block.lineAddress(hole_start));
                self.limit = @intFromPtr(block.lineAddress(hole_end));
                return true;
            }
            
            // Hole too small. Skip past it and keep looking.
            start_line = hole_end;
        }
        
        return false;
    }
};

// ── Tests ─────────────────────────────────────────────────────────────────────
var global_test_block: ?*Block = null;
fn mockBlockSupplier() ?*Block {
    const block = global_test_block;
    global_test_block = null; // Only supply one block
    return block;
}

test "MutatorAllocator basic and hole filling" {
    const allocator = std.testing.allocator;
    const raw_mem = try allocator.alloc(u8, BLOCK_SIZE * 2);
    defer allocator.free(raw_mem);
    
    const raw_addr = @intFromPtr(raw_mem.ptr);
    const aligned_addr = (raw_addr + BLOCK_SIZE - 1) & ~(BLOCK_SIZE - 1);
    const block = @as(*Block, @ptrFromInt(aligned_addr));
    block.* = Block.init();
    
    global_test_block = block;
    var mutator = MutatorAllocator.init(mockBlockSupplier);
    
    // First allocation should trigger a block fetch and allocate successfully.
    const ptr1 = mutator.alloc(100).?;
    try std.testing.expectEqual(@intFromPtr(block.lineAddress(1)), @intFromPtr(ptr1));
    
    // Next allocation should bump pointer
    const ptr2 = mutator.alloc(200).?;
    try std.testing.expectEqual(@intFromPtr(ptr1) + 104, @intFromPtr(ptr2)); // 100 aligned to 8 is 104
    
    // Now simulate fragmentation by artificially setting a line as marked.
    // Line 1 and Line 2 are currently being used (cursor is in Line 2).
    // Let's mark Line 4 as occupied.
    block.line_map.set(4);
    
    // Force the allocator to rescan for a hole by invalidating its cached limit.
    mutator.limit = mutator.cursor;
    
    // Allocate something big that won't fit before Line 4 (which is at byte 1024).
    // We are at ~byte 560 (Line 2). We have ~464 bytes until Line 4.
    // If we request 600 bytes, it must skip the hole and allocate starting at Line 5!
    const ptr3 = mutator.alloc(600).?;
    try std.testing.expectEqual(@intFromPtr(block.lineAddress(5)), @intFromPtr(ptr3));
}
