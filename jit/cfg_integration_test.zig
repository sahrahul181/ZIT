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

test "full JIT SSA compilation pipeline on Main.fib" {
    var arena_state = std.heap.ArenaAllocator.init(std.testing.allocator);
    defer arena_state.deinit();
    const arena = arena_state.allocator();

    const dex = try parseFixture(arena);
    const method = dex.findMethod("Main", "fib") orelse return error.MethodNotFound;

    const insns = try dex.decodeMethod(arena, method);
    try std.testing.expect(insns.len > 0);

    var cfg = try cfgmod.buildCFG(std.testing.allocator, insns);
    defer cfg.deinit();

    // 4. Compute predecessors, dominators, and frontiers
    try cfg.computePredecessors();
    try cfg.computeDominators();
    try cfg.computeDominatorChildren();
    try cfg.computeDominanceFrontiers();

    // 5. Translate to IR
    const translate = @import("translate");
    try translate.translateCFG(std.testing.allocator, &cfg, insns);

    // 6. Map Definitions (Find which blocks define which registers)
    var def_map = std.AutoHashMap(u16, std.ArrayList(usize)).init(std.testing.allocator);
    defer {
        var it = def_map.iterator();
        while (it.next()) |entry| entry.value_ptr.deinit(std.testing.allocator);
        def_map.deinit();
    }

    for (cfg.blocks.items) |block| {
        for (block.instructions.items) |inst| {
            const dest_reg: ?u16 = switch (inst) {
                .phi => |v| v.dest.reg,
                .move => |v| v.dest.reg,
                .const_int => |v| v.dest.reg,
                .const_wide => |v| v.dest.reg,
                .const_string => |v| v.dest.reg,
                .const_class => |v| v.dest.reg,
                .add_int, .sub_int, .mul_int, .div_int, .rem_int,
                .and_int, .or_int, .xor_int, .shl_int, .shr_int, .ushr_int,
                .add_float, .sub_float, .mul_float, .div_float,
                .add_wide, .sub_wide, .mul_wide, .div_wide,
                => |v| v.dest.reg,
                .add_lit, .sub_lit, .mul_lit, .div_lit, .rem_lit,
                .and_lit, .or_lit, .xor_lit, .shl_lit, .shr_lit, .ushr_lit,
                => |v| v.dest.reg,
                .new_instance => |v| v.dest.reg,
                .new_array => |v| v.dest.reg,
                .iget => |v| v.dest_or_src.reg,
                .sget => |v| v.dest_or_src.reg,
                .aget => |v| v.dest_or_src.reg,
                .invoke => |v| if (v.dest) |d| d.reg else null,
                else => null,
            };

            if (dest_reg) |reg| {
                var res = try def_map.getOrPut(reg);
                if (!res.found_existing) {
                    res.value_ptr.* = .empty;
                }
                var contains = false;
                for (res.value_ptr.items) |b_id| {
                    if (b_id == block.id) {
                        contains = true;
                        break;
                    }
                }
                if (!contains) {
                    try res.value_ptr.append(std.testing.allocator, block.id);
                }
            }
        }
    }

    // 7. Insert Phi Nodes using Dominance Frontiers
    try cfg.insertPhiFunctions(def_map);

    // 8. Rename Variables
    try cfg.renameVariables(method.registers_size);

    // Verify SSA renaming and phi nodes
    var has_phi = false;
    for (cfg.blocks.items) |block| {
        for (block.instructions.items) |inst| {
            if (inst == .phi) {
                has_phi = true;
            }
        }
    }
    try std.testing.expect(has_phi);
}
