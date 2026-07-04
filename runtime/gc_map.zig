//! GC Map — Phase 2
//!
//! Precise stack maps emitted by the JIT at every call site so the GC can
//! find all live object references on the JIT stack when objects move.
//!
//! Format is intentionally compact: each entry is 8 bytes.
//! The emitter stores a GcMapTable immediately after the native code in
//! executable memory.

const std = @import("std");

// ── Ref bitmap ────────────────────────────────────────────────────────────────
//
// For each call site we record:
//   - The instruction offset within the method (u32)
//   - A 64-bit bitmask where bit i = 1 means stack-slot i (above saved-rbp)
//     holds a live object reference that must be updated if the object moves.
//   - A register bitmask (low 16 bits of reg_refs) covering rax..r15.
//     bit 0 = rax, 1 = rcx, 2 = rdx, ... (same order as regCode() in emitter)

pub const GcEntry = struct {
    /// Byte offset of the call instruction from method start.
    call_offset: u32,
    /// Bitmask: bit i set → stack slot i*8(rbp) is a live object ref.
    stack_refs:  u64,
    /// Bitmask: bit i set → physical register i is a live object ref.
    reg_refs:    u32,
};

pub const GcMapTable = struct {
    entry_count: u32,
    padding:     u32 = 0,
    // Entries immediately follow in memory (variable-length).
    // Access via `entriesSlice`.

    pub fn entriesSlice(self: *const GcMapTable) []const GcEntry {
        const base = @intFromPtr(self) + @sizeOf(GcMapTable);
        const aligned = std.mem.alignForward(usize, base, @alignOf(GcEntry));
        return @as([*]const GcEntry, @ptrFromInt(aligned))[0..self.entry_count];
    }

    /// Find the GcEntry for a native PC offset, or null if not a call site.
    pub fn findEntry(self: *const GcMapTable, pc_offset: u32) ?GcEntry {
        for (self.entriesSlice()) |e| {
            if (e.call_offset == pc_offset) return e;
        }
        return null;
    }
};

/// Builder used by the register allocator to accumulate GC map entries,
/// then serialized into exec memory by the emitter after code generation.
pub const GcMapBuilder = struct {
    entries: std.ArrayList(GcEntry),
    allocator: std.mem.Allocator,

    pub fn init(allocator: std.mem.Allocator) GcMapBuilder {
        return .{
            .entries = .empty,
            .allocator = allocator,
        };
    }

    pub fn deinit(self: *GcMapBuilder) void {
        self.entries.deinit(self.allocator);
    }

    pub fn addEntry(self: *GcMapBuilder, entry: GcEntry) !void {
        try self.entries.append(self.allocator, entry);
    }

    /// Serialize the table into `buf`, which must be large enough.
    /// Returns number of bytes written.
    pub fn serialize(self: *const GcMapBuilder, buf: []u8) usize {
        const hdr_size  = std.mem.alignForward(usize, @sizeOf(GcMapTable), @alignOf(GcEntry));
        const body_size = self.entries.items.len * @sizeOf(GcEntry);
        const total     = hdr_size + body_size;
        std.debug.assert(buf.len >= total);

        const hdr = @as(*GcMapTable, @ptrCast(@alignCast(buf.ptr)));
        hdr.entry_count = @intCast(self.entries.items.len);
        hdr.padding = 0;
        const entry_buf = @as([*]GcEntry, @ptrCast(@alignCast(buf.ptr + hdr_size)));
        @memcpy(entry_buf[0..self.entries.items.len], self.entries.items);
        return total;
    }

    pub fn serializedSize(self: *const GcMapBuilder) usize {
        const hdr_size  = std.mem.alignForward(usize, @sizeOf(GcMapTable), @alignOf(GcEntry));
        return hdr_size + self.entries.items.len * @sizeOf(GcEntry);
    }
};

// ── Tests ─────────────────────────────────────────────────────────────────────

test "GcMapBuilder serialize and lookup" {
    const a = std.testing.allocator;
    var builder = GcMapBuilder.init(a);
    defer builder.deinit();

    try builder.addEntry(.{ .call_offset = 42, .stack_refs = 0b11, .reg_refs = 0 });
    try builder.addEntry(.{ .call_offset = 88, .stack_refs = 0,    .reg_refs = 1 });

    const size = builder.serializedSize();
    const buf = try a.alloc(u8, size);
    defer a.free(buf);

    const written = builder.serialize(buf);
    try std.testing.expectEqual(size, written);

    const table = @as(*const GcMapTable, @ptrCast(@alignCast(buf.ptr)));
    try std.testing.expectEqual(@as(u32, 2), table.entry_count);

    const found = table.findEntry(42).?;
    try std.testing.expectEqual(@as(u32, 42), found.call_offset);
    try std.testing.expectEqual(@as(u64, 0b11), found.stack_refs);

    try std.testing.expect(table.findEntry(99) == null);
}
