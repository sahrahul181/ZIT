//! End-to-end test: real d8-produced DEX → parser → decoder → CFG.
//!
//! Uses the classes.dex built by samples/build-dex.ps1 (from samples/Main.java),
//! embedded at compile time so the test is hermetic.

const std = @import("std");
const dexmod = @import("dex");
const cfgmod = @import("cfg");

const dex_bytes = @embedFile("classes.dex");

fn parseFixture(arena: std.mem.Allocator) !dexmod.DexFile {
    return dexmod.parse(arena, dex_bytes);
}

test "DEX magic and at least one class parse" {
    var arena_state = std.heap.ArenaAllocator.init(std.testing.allocator);
    defer arena_state.deinit();
    const dex = try parseFixture(arena_state.allocator());
    try std.testing.expect(dex.classes.items.len >= 1);
}

test "build CFG from Main.fib: has a loop back-edge" {
    var arena_state = std.heap.ArenaAllocator.init(std.testing.allocator);
    defer arena_state.deinit();
    const arena = arena_state.allocator();

    const dex = try parseFixture(arena);
    const method = dex.findMethod("Main", "fib") orelse return error.MethodNotFound;

    const insns = try dex.decodeMethod(arena, method);
    try std.testing.expect(insns.len > 0);

    var cfg = try cfgmod.buildCFG(std.testing.allocator, insns);
    defer cfg.deinit();

    // fib's `for` loop must produce more than one basic block, and at least one
    // block whose successor id is <= its own id (a back-edge / loop).
    try std.testing.expect(cfg.blocks.items.len > 1);

    var has_back_edge = false;
    for (cfg.blocks.items) |block| {
        for (block.successors.items) |succ| {
            if (succ <= block.id) has_back_edge = true;
        }
    }
    try std.testing.expect(has_back_edge);
}

test "every successor id is a valid block index" {
    var arena_state = std.heap.ArenaAllocator.init(std.testing.allocator);
    defer arena_state.deinit();
    const arena = arena_state.allocator();

    const dex = try parseFixture(arena);
    // Exercise the CFG builder over every decodable method in the file.
    for (dex.classes.items) |class| {
        for (class.methods.items) |method| {
            const insns = dex.decodeMethod(arena, method) catch continue;
            if (insns.len == 0) continue;

            var cfg = try cfgmod.buildCFG(std.testing.allocator, insns);
            defer cfg.deinit();

            for (cfg.blocks.items) |block| {
                for (block.successors.items) |succ| {
                    try std.testing.expect(succ < cfg.blocks.items.len);
                }
            }
        }
    }
}
