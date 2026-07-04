const std = @import("std");

pub const BLOCK_SIZE: usize = 32 * 1024; // 32KB
pub const LINE_SIZE: usize = 256;        // 256 bytes
pub const LINES_PER_BLOCK: usize = BLOCK_SIZE / LINE_SIZE; // 128 lines

/// Bitmask for 128 lines.
pub const LineBitmap = struct {
    bits: [2]u64 = .{ 0, 0 },

    pub inline fn set(self: *LineBitmap, line_idx: usize) void {
        const word_idx = line_idx / 64;
        const bit_idx = @as(u6, @intCast(line_idx % 64));
        self.bits[word_idx] |= (@as(u64, 1) << bit_idx);
    }

    pub inline fn isSet(self: *const LineBitmap, line_idx: usize) bool {
        const word_idx = line_idx / 64;
        const bit_idx = @as(u6, @intCast(line_idx % 64));
        return (self.bits[word_idx] & (@as(u64, 1) << bit_idx)) != 0;
    }
    
    pub inline fn clear(self: *LineBitmap) void {
        self.bits[0] = 0;
        self.bits[1] = 0;
    }
    
    pub fn findFirstZeroAfter(self: *const LineBitmap, start_line: usize) usize {
        if (start_line >= 128) return 128;
        
        var word_idx = start_line / 64;
        const bit_idx = @as(u6, @intCast(start_line % 64));
        
        // Scan current word
        var word = ~self.bits[word_idx];
        word &= ~((@as(u64, 1) << bit_idx) - 1); // clear bits before start_line
        
        if (word != 0) {
            return word_idx * 64 + @ctz(word);
        }
        
        // Scan next word if any
        word_idx += 1;
        if (word_idx < 2) {
            word = ~self.bits[word_idx];
            if (word != 0) {
                return word_idx * 64 + @ctz(word);
            }
        }
        
        return 128; // No zero found
    }
    
    pub fn findFirstOneAfter(self: *const LineBitmap, start_line: usize) usize {
        if (start_line >= 128) return 128;
        
        var word_idx = start_line / 64;
        const bit_idx = @as(u6, @intCast(start_line % 64));
        
        // Scan current word
        var word = self.bits[word_idx];
        word &= ~((@as(u64, 1) << bit_idx) - 1); // clear bits before start_line
        
        if (word != 0) {
            return word_idx * 64 + @ctz(word);
        }
        
        // Scan next word if any
        word_idx += 1;
        if (word_idx < 2) {
            word = self.bits[word_idx];
            if (word != 0) {
                return word_idx * 64 + @ctz(word);
            }
        }
        
        return 128; // No one found
    }
};

pub const BlockFlags = packed struct {
    is_evacuation_candidate: bool = false,
    _padding: u7 = 0,
};

/// A 32KB memory region. Metadata sits at the very beginning.
/// The first line (Line 0) is reserved for this Block metadata.
pub const Block = struct {
    line_map: LineBitmap,
    flags: BlockFlags,
    hole_count: u16,
    free_lines: u16,
    
    // Linked list for BlockAllocator
    next: ?*Block = null,

    pub fn init() Block {
        return .{
            .line_map = .{},
            .flags = .{},
            .hole_count = 0,
            .free_lines = LINES_PER_BLOCK - 1, // Line 0 is metadata
            .next = null,
        };
    }

    pub inline fn ptr(self: *Block) [*]u8 {
        return @as([*]u8, @ptrCast(self));
    }
    
    /// Address of a specific line
    pub inline fn lineAddress(self: *Block, line_idx: usize) [*]u8 {
        std.debug.assert(line_idx <= LINES_PER_BLOCK);
        return self.ptr() + (line_idx * LINE_SIZE);
    }
    
    /// Get Block pointer from any address inside the block
    pub inline fn fromAddress(address: usize) *Block {
        // Block is 32KB aligned, so we just mask off the lower 15 bits
        const block_start = address & ~(BLOCK_SIZE - 1);
        return @as(*Block, @ptrFromInt(block_start));
    }
    
    /// Get the line index for a given address
    pub inline fn lineIndex(address: usize) usize {
        const offset = address & (BLOCK_SIZE - 1);
        return offset / LINE_SIZE;
    }
};

test "Block basic operations" {
    const allocator = std.testing.allocator;
    // We allocate 64KB and find a 32KB aligned offset to simulate page allocation.
    const raw_mem = try allocator.alloc(u8, BLOCK_SIZE * 2);
    defer allocator.free(raw_mem);
    
    const raw_addr = @intFromPtr(raw_mem.ptr);
    const aligned_addr = (raw_addr + BLOCK_SIZE - 1) & ~(BLOCK_SIZE - 1);
    const block = @as(*Block, @ptrFromInt(aligned_addr));
    block.* = Block.init();
    
    try std.testing.expectEqual(@as(u16, 127), block.free_lines);
    
    block.line_map.set(5);
    try std.testing.expect(block.line_map.isSet(5));
    try std.testing.expect(!block.line_map.isSet(6));
    
    const addr = @intFromPtr(block.lineAddress(10));
    const recovered = Block.fromAddress(addr);
    try std.testing.expectEqual(block, recovered);
    
    const line_idx = Block.lineIndex(addr);
    try std.testing.expectEqual(@as(usize, 10), line_idx);
}
