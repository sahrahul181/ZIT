//! Exception Handling — Phase 6
//!
//! Stack unwinding, DEX try/catch handler tables, and stack trace collection.
//! The same algorithm runs in both the interpreter and as a JIT slow-path.

const std = @import("std");
const instmod = @import("instruction");
const class_loader = @import("class_loader");

const TryBlock = instmod.TryBlock;
const CatchHandler = instmod.CatchHandler;
const MethodData = class_loader.MethodData;

// ── JIT exception handler table ──────────────────────────────────────────────
//
// Stored immediately after native code in executable memory.
// The emitter writes this after each compiled method.

pub const HandlerEntry = struct {
    from_offset:    u32,    // start of guarded native code range
    to_offset:      u32,    // end   of guarded native code range
    catch_type_idx: u32,    // type_idx of the catch type (0xFFFF_FFFF = catch-all)
    handler_offset: u32,    // native code offset of the catch block entry
};

pub const HandlerTable = struct {
    entry_count: u32,
    padding:     u32 = 0,

    pub fn entries(self: *const HandlerTable) []const HandlerEntry {
        const base = @intFromPtr(self) + @sizeOf(HandlerTable);
        const aligned = std.mem.alignForward(usize, base, @alignOf(HandlerEntry));
        return @as([*]const HandlerEntry, @ptrFromInt(aligned))[0..self.entry_count];
    }

    /// Find the handler for a native PC offset and thrown type.
    /// Returns the native handler offset, or null if no handler found.
    pub fn findHandler(self: *const HandlerTable, pc_off: u32, type_idx: u32) ?u32 {
        for (self.entries()) |e| {
            if (pc_off < e.from_offset or pc_off >= e.to_offset) continue;
            if (e.catch_type_idx == 0xFFFF_FFFF or e.catch_type_idx == type_idx) {
                return e.handler_offset;
            }
        }
        return null;
    }
};

// ── Handler table builder ─────────────────────────────────────────────────────

pub const HandlerTableBuilder = struct {
    entries: std.ArrayList(HandlerEntry),
    allocator: std.mem.Allocator,

    pub fn init(allocator: std.mem.Allocator) HandlerTableBuilder {
        return .{
            .entries = .empty,
            .allocator = allocator,
        };
    }

    pub fn deinit(self: *HandlerTableBuilder) void { self.entries.deinit(self.allocator); }

    pub fn addEntry(self: *HandlerTableBuilder, e: HandlerEntry) !void {
        try self.entries.append(self.allocator, e);
    }

    pub fn serializedSize(self: *const HandlerTableBuilder) usize {
        const hdr_size = std.mem.alignForward(usize, @sizeOf(HandlerTable), @alignOf(HandlerEntry));
        return hdr_size + self.entries.items.len * @sizeOf(HandlerEntry);
    }

    pub fn serialize(self: *const HandlerTableBuilder, buf: []u8) usize {
        const hdr_size = std.mem.alignForward(usize, @sizeOf(HandlerTable), @alignOf(HandlerEntry));
        const hdr = @as(*HandlerTable, @ptrCast(@alignCast(buf.ptr)));
        hdr.entry_count = @intCast(self.entries.items.len);
        hdr.padding = 0;
        const entry_buf = @as([*]HandlerEntry, @ptrCast(@alignCast(buf.ptr + hdr_size)));
        @memcpy(entry_buf[0..self.entries.items.len], self.entries.items);
        return self.serializedSize();
    }
};

// ── DEX try-block search ──────────────────────────────────────────────────────
//
// Used by the interpreter for bytecode-level exception dispatch.

pub fn findDexHandler(tries: []const TryBlock, pc: u32, type_idx: u32) ?u32 {
    for (tries) |tb| {
        if (pc < tb.start_pc or pc >= tb.end_pc) continue;
        for (tb.handlers) |h| {
            // catch-all (type_idx == null) or exact type match
            if (h.type_idx == null or h.type_idx == type_idx) return h.target_pc;
        }
    }
    return null;
}

// ── Stack frame info ──────────────────────────────────────────────────────────

pub const FrameInfo = struct {
    class_name:  []const u8,
    method_name: []const u8,
    source_file: []const u8,
    line_number: u32,
    next:        ?*FrameInfo,
};

// ── Stack trace collection ────────────────────────────────────────────────────

pub const StackTrace = struct {
    frames: std.ArrayList(FrameInfo),
    allocator: std.mem.Allocator,

    pub fn init(allocator: std.mem.Allocator) StackTrace {
        return .{
            .frames = .empty,
            .allocator = allocator,
        };
    }

    pub fn deinit(self: *StackTrace) void { self.frames.deinit(self.allocator); }

    pub fn push(self: *StackTrace, fi: FrameInfo) !void {
        try self.frames.append(self.allocator, fi);
    }

    pub fn print(self: *const StackTrace, writer: anytype) !void {
        for (self.frames.items) |f| {
            try writer.print("\tat {s}.{s}({s}:{d})\n", .{
                f.class_name, f.method_name, f.source_file, f.line_number,
            });
        }
    }
};

// ── Tests ─────────────────────────────────────────────────────────────────────

test "findDexHandler: finds catch-all handler" {
    const handlers = [_]CatchHandler{
        .{ .type_idx = null, .target_pc = 42 },
    };
    const tries = [_]TryBlock{
        .{ .start_pc = 0, .end_pc = 20, .handlers = &handlers },
    };
    const result = findDexHandler(&tries, 10, 0);
    try std.testing.expectEqual(@as(?u32, 42), result);
}

test "findDexHandler: misses when PC out of range" {
    const handlers = [_]CatchHandler{
        .{ .type_idx = null, .target_pc = 42 },
    };
    const tries = [_]TryBlock{
        .{ .start_pc = 0, .end_pc = 10, .handlers = &handlers },
    };
    try std.testing.expectEqual(@as(?u32, null), findDexHandler(&tries, 10, 0));
}

test "HandlerTableBuilder serialize and lookup" {
    const a = std.testing.allocator;
    var b = HandlerTableBuilder.init(a);
    defer b.deinit();

    try b.addEntry(.{ .from_offset = 0, .to_offset = 100, .catch_type_idx = 0xFFFF_FFFF, .handler_offset = 200 });
    const size = b.serializedSize();
    const buf = try a.alloc(u8, size);
    defer a.free(buf);
    _ = b.serialize(buf);

    const table = @as(*const HandlerTable, @ptrCast(@alignCast(buf.ptr)));
    try std.testing.expectEqual(@as(?u32, 200), table.findHandler(50, 999));
    try std.testing.expectEqual(@as(?u32, null), table.findHandler(150, 999));
}
