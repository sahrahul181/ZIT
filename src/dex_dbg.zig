const std = @import("std");
const parser = @import("parser");
const cfgmod = @import("cfg");
const instruction = @import("instruction");
const printer = @import("printer");
const translate = @import("translate");
const ir = @import("ir");
const opt = @import("opt");
const dessa = @import("dessa");
const x86mod = @import("x86");
const lower = @import("lower");
const regalloc = @import("regalloc");
const emitter = @import("emitter");
const exec_mem = @import("exec_mem");
const Io = std.Io;

const c = @cImport({
    @cInclude("pb.h");
    @cInclude("metadata_decoder.h");
});

var resolve_arena: ?std.heap.ArenaAllocator = null;

fn resolveString(ctx: ?*anyopaque, idx: u32) callconv(.c) ?[*]const u8 {
    const d2: *const []const []const u8 = @ptrCast(@alignCast(ctx orelse return null));
    if (idx >= d2.*.len) return null;
    const str = d2.*[idx];
    if (resolve_arena) |*arena| {
        const copy = arena.allocator().dupeZ(u8, str) catch return null;
        return copy.ptr;
    }
    return null;
}

fn decodeKotlinMetadata(arena: std.mem.Allocator, data1: []const []const u8) ![]u8 {
    if (data1.len == 0 or data1[0].len == 0) return &.{};

    // First decode all strings from MUTF-8 to raw bytes
    var raw_parts = try arena.alloc([]u8, data1.len);
    for (data1, 0..) |s, idx| {
        var raw = try arena.alloc(u8, s.len);
        var i: usize = 0;
        var out_idx: usize = 0;
        while (i < s.len) {
            const b = s[i];
            if (b & 0x80 == 0) {
                raw[out_idx] = b;
                out_idx += 1;
                i += 1;
            } else if ((b & 0xe0) == 0xc0) {
                if (i + 1 >= s.len) return error.MalformedMutf8;
                const b2 = s[i+1];
                const char_val = (@as(u32, b & 0x1f) << 6) | (b2 & 0x3f);
                if (char_val == 0) {
                    raw[out_idx] = 0;
                } else {
                    raw[out_idx] = @intCast(char_val & 0xff);
                }
                out_idx += 1;
                i += 2;
            } else if ((b & 0xf0) == 0xe0) {
                if (i + 2 >= s.len) return error.MalformedMutf8;
                const b2 = s[i+1];
                const b3 = s[i+2];
                const char_val = (@as(u32, b & 0x0f) << 12) | (@as(u32, b2 & 0x3f) << 6) | (b3 & 0x3f);
                raw[out_idx] = @intCast(char_val & 0xff);
                out_idx += 1;
                i += 3;
            } else {
                raw[out_idx] = b;
                out_idx += 1;
                i += 1;
            }
        }
        raw_parts[idx] = raw[0..out_idx];
    }

    const first_raw = raw_parts[0];
    
    // Check for UtfEncoding (not packed)
    if (first_raw[0] == 0) {
        var total_len: usize = 0;
        for (raw_parts, 0..) |s, idx| {
            if (idx == 0) {
                total_len += s.len - 1;
            } else {
                total_len += s.len;
            }
        }
        const result = try arena.alloc(u8, total_len);
        var offset: usize = 0;
        for (raw_parts, 0..) |s, idx| {
            if (idx == 0) {
                @memcpy(result[offset..][0 .. s.len - 1], s[1..]);
                offset += s.len - 1;
            } else {
                @memcpy(result[offset..][0..s.len], s);
                offset += s.len;
            }
        }
        return result;
    }

    // Check for packed 8to7 encoding with marker (0xffff)
    var is_packed_with_marker = false;
    var marker_len: usize = 0;
    if (first_raw.len >= 3 and first_raw[0] == 0xef and first_raw[1] == 0xbf and first_raw[2] == 0xbf) {
        is_packed_with_marker = true;
        marker_len = 3;
    }

    // Combine strings into bytes
    var total_len: usize = 0;
    for (raw_parts, 0..) |s, idx| {
        if (idx == 0 and is_packed_with_marker) {
            total_len += s.len - marker_len;
        } else {
            total_len += s.len;
        }
    }

    const combined = try arena.alloc(u8, total_len);
    var offset: usize = 0;
    for (raw_parts, 0..) |s, idx| {
        if (idx == 0 and is_packed_with_marker) {
            @memcpy(combined[offset..][0 .. s.len - marker_len], s[marker_len..]);
            offset += s.len - marker_len;
        } else {
            @memcpy(combined[offset..][0..s.len], s);
            offset += s.len;
        }
    }

    // Subtract modulo 128: (val + 127) & 0x7f
    for (combined) |*b| {
        b.* = @intCast((@as(u32, b.*) + 127) & 0x7f);
    }

    // Decode 7to8
    const result_len = combined.len * 7 / 8;
    const result = try arena.alloc(u8, result_len);
    var byte_idx: usize = 0;
    var bit: u5 = 0;

    for (0..result_len) |i| {
        const first_part = @as(u32, combined[byte_idx]) >> bit;
        byte_idx += 1;
        const mask = (@as(u32, 1) << (bit + 1)) - 1;
        const second_part = (combined[byte_idx] & mask) << (7 - bit);
        result[i] = @intCast((first_part + second_part) & 0xff);

        if (bit == 6) {
            byte_idx += 1;
            bit = 0;
        } else {
            bit += 1;
        }
    }

    return result;
}

const Instruction = instruction.Instruction;
const InvokeKind = instruction.InvokeKind;
const MethodInfo = parser.MethodInfo;

fn usage(writer: anytype) !void {
    try writer.writeAll(
        \\Usage: dex-dbg <dex_file> <command> [args]
        \\
        \\Commands:
        \\  info                                Show summary metadata of the DEX file.
        \\  classes                             List all classes defined in the DEX file.
        \\  methods <class_name>                List all methods of a class.
        \\  fields <class_name>                 List all static and instance fields of a class.
        \\  types                               List all referenced type names.
        \\  strings [pattern]                   List or search for strings in the string pool.
        \\  disasm <class_name> <method_name>   Disassemble a method with raw hex bytes.
        \\  cfg <class_name> <method_name> [--dom]   Print CFG; --dom adds predecessors + idom.
        \\  ssa <class_name> <method_name>           Print SSA IR for a method.
        \\  ssa-opt <class_name> <method_name>       Print Optimized SSA IR (with Dead Code Elimination).
        \\  dessa <class_name> <method_name>         Print SSA IR after Out-of-SSA translation (eliminatePhis + propagateCopies).
        \\  lower <class_name> <method_name>         Print virtual x86-64 assembly (full pipeline: SSA-opt → de-SSA → lower).
        \\  codegen <class_name> <method_name>       Print register-allocated physical x86-64 assembly.
        \\  run <class_name> <method_name> [args...] Run JIT compiler on a method and execute it.
        \\  emit <class_name> <method_name> [f] Dumps method instructions to stdout or a file.
        \\  kotlin <class_name>                 Show Kotlin metadata declarations (decoded using C protobuf lib).
        \\
    );
}

fn findClass(dex: *const parser.DexFile, name: []const u8) ?parser.DexClass {
    for (dex.classes.items) |class| {
        if (std.mem.eql(u8, class.name, name) or std.mem.indexOf(u8, class.name, name) != null) {
            return class;
        }
    }
    return null;
}

fn findMethod(class: *const parser.DexClass, name: []const u8) ?parser.DexMethod {
    for (class.methods.items) |m| {
        const arrow = std.mem.indexOf(u8, m.name, "->") orelse continue;
        const mname = m.name[arrow + 2..];
        if (std.mem.eql(u8, mname, name) or std.mem.indexOf(u8, mname, name) != null) {
            return m;
        }
    }
    return null;
}

pub fn main(init: std.process.Init) !void {
    const arena: std.mem.Allocator = init.arena.allocator();
    const args = try init.minimal.args.toSlice(arena);

    // Stdout setup
    const io = init.io;
    var stdout_buffer: [1024]u8 = undefined;
    var stdout_file_writer: Io.File.Writer = .init(.stdout(), io, &stdout_buffer);
    const writer = &stdout_file_writer.interface;
    defer stdout_file_writer.flush() catch {};

    if (args.len < 3) {
        try usage(writer);
        return;
    }

    const dex_path = args[1];
    const cmd = args[2];

    // Open and parse the DEX file
    var file = Io.Dir.cwd().openFile(io, dex_path, .{}) catch |err| {
        try writer.print("Error: Could not open file '{s}': {s}\n", .{ dex_path, @errorName(err) });
        return;
    };
    defer file.close(io);

    var file_buffer: [4096]u8 = undefined;
    var file_reader = file.reader(io, &file_buffer);
    const bytes = file_reader.interface.allocRemaining(arena, .limited(100 * 1024 * 1024)) catch |err| {
        try writer.print("Error: Failed to read file: {s}\n", .{@errorName(err)});
        return;
    };

    const dex = parser.parse(arena, bytes) catch |err| {
        try writer.print("Error: Failed to parse DEX file: {s}\n", .{@errorName(err)});
        return;
    };

    if (std.mem.eql(u8, cmd, "info")) {
        try writer.print("DEX File Summary:\n", .{});
        try writer.print("  File Size: {d} bytes\n", .{dex.bytes.len});
        try writer.print("  Classes:   {d}\n", .{dex.classes.items.len});
        try writer.print("  Strings:   {d}\n", .{dex.string_pool.len});
        try writer.print("  Types:     {d}\n", .{dex.type_names.len});
        try writer.print("  Methods:   {d}\n", .{dex.method_items.len});
        try writer.print("  Fields:    {d}\n", .{dex.field_items.len});
    } else if (std.mem.eql(u8, cmd, "classes")) {
        try writer.print("Classes ({d}):\n", .{dex.classes.items.len});
        for (dex.classes.items) |class| {
            try writer.print("  {s}\n", .{class.name});
        }
    } else if (std.mem.eql(u8, cmd, "methods")) {
        if (args.len < 4) {
            try writer.print("Error: 'methods' command requires a <class_name> argument.\n", .{});
            return;
        }
        const class_arg = args[3];
        const class = findClass(&dex, class_arg) orelse {
            try writer.print("Error: Class '{s}' not found.\n", .{class_arg});
            return;
        };
        try writer.print("Methods in class {s} ({d}):\n", .{ class.name, class.methods.items.len });
        for (class.methods.items) |m| {
            try writer.print("  {s} (regs={d}, ins={d}, outs={d})\n", .{ m.name, m.registers_size, m.ins_size, m.outs_size });
        }
    } else if (std.mem.eql(u8, cmd, "fields")) {
        if (args.len < 4) {
            try writer.print("Error: 'fields' command requires a <class_name> argument.\n", .{});
            return;
        }
        const class_arg = args[3];
        const class = findClass(&dex, class_arg) orelse {
            try writer.print("Error: Class '{s}' not found.\n", .{class_arg});
            return;
        };
        try writer.print("Fields in class {s}:\n", .{class.name});
        var count: usize = 0;
        for (dex.field_items) |f| {
            if (std.mem.eql(u8, f.class_name, class.name)) {
                try writer.print("  {s}: {s}\n", .{ f.field_name, f.type_name });
                count += 1;
            }
        }
        if (count == 0) {
            try writer.print("  (No fields found)\n", .{});
        }
    } else if (std.mem.eql(u8, cmd, "types")) {
        try writer.print("Referenced Types ({d}):\n", .{dex.type_names.len});
        for (dex.type_names) |t| {
            try writer.print("  {s}\n", .{t});
        }
    } else if (std.mem.eql(u8, cmd, "strings")) {
        if (args.len >= 4) {
            const pattern = args[3];
            try writer.print("Strings matching '{s}':\n", .{pattern});
            for (dex.string_pool, 0..) |s, idx| {
                if (std.ascii.indexOfIgnoreCase(s, pattern) != null) {
                    try writer.print("  [{d:>5}] {s}\n", .{ idx, s });
                }
            }
        } else {
            try writer.print("String Pool ({d}):\n", .{dex.string_pool.len});
            for (dex.string_pool, 0..) |s, idx| {
                try writer.print("  [{d:>5}] {s}\n", .{ idx, s });
            }
        }
    } else if (std.mem.eql(u8, cmd, "disasm")) {
        if (args.len < 5) {
            try writer.print("Error: 'disasm' command requires <class_name> and <method_name> arguments.\n", .{});
            return;
        }
        const class_arg = args[3];
        const method_arg = args[4];

        const class = findClass(&dex, class_arg) orelse {
            try writer.print("Error: Class '{s}' not found.\n", .{class_arg});
            return;
        };
        const method = findMethod(&class, method_arg) orelse {
            try writer.print("Error: Method '{s}' not found in class '{s}'.\n", .{ method_arg, class.name });
            return;
        };

        try writer.print("Disassembly of {s}\n", .{method.name});
        try writer.print("  Registers: {d}, Ins: {d}, Outs: {d}, Static: {}\n\n", .{
            method.registers_size,
            method.ins_size,
            method.outs_size,
            method.is_static,
        });

        const insts = dex.decodeMethod(arena, method) catch |err| {
            try writer.print("Error decoding bytecode: {s}\n", .{@errorName(err)});
            return;
        };

        var pc: usize = 0;
        for (insts, 0..) |inst, idx| {
            const tag = std.meta.activeTag(inst);
            const opcode = @intFromEnum(tag);
            const width = parser.INSN_WIDTH[opcode];

            try writer.print("  [{d:>4}] PC={x:0>4} | ", .{ idx, pc });

            var w: usize = 0;
            while (w < width) : (w += 1) {
                const val = std.mem.readInt(u16, dex.bytes[method.code_off + 16 + (pc + w) * 2 ..][0..2], .little);
                try writer.print("{x:0>4} ", .{val});
            }

            var space_left = 25 - (width * 5);
            while (space_left > 0) : (space_left -= 1) {
                try writer.writeByte(' ');
            }
            try writer.writeAll(" | ");
            try printer.printInstruction(writer, inst);
            try writer.writeByte('\n');

            pc += width;
        }
    } else if (std.mem.eql(u8, cmd, "cfg")) {
        if (args.len < 5) {
            try writer.print("Error: 'cfg' command requires <class_name> and <method_name> arguments.\n", .{});
            return;
        }
        const class_arg = args[3];
        const method_arg = args[4];

        const class = findClass(&dex, class_arg) orelse {
            try writer.print("Error: Class '{s}' not found.\n", .{class_arg});
            return;
        };
        const method = findMethod(&class, method_arg) orelse {
            try writer.print("Error: Method '{s}' not found in class '{s}'.\n", .{ method_arg, class.name });
            return;
        };

        const insts = dex.decodeMethod(arena, method) catch |err| {
            try writer.print("Error decoding bytecode: {s}\n", .{@errorName(err)});
            return;
        };

        var cfg = cfgmod.buildCFG(arena, insts) catch |err| {
            try writer.print("Error building CFG: {s}\n", .{@errorName(err)});
            return;
        };

        // Optional: compute predecessors + dominators + dominance frontiers when --dom flag passed
        const show_dom = args.len >= 6 and std.mem.eql(u8, args[5], "--dom");
        if (show_dom) {
            cfg.computePredecessors() catch |err| {
                try writer.print("Error computing predecessors: {s}\n", .{@errorName(err)});
                return;
            };
            cfg.computeDominators() catch |err| {
                try writer.print("Error computing dominators: {s}\n", .{@errorName(err)});
                return;
            };
            cfg.computeDominanceFrontiers() catch |err| {
                try writer.print("Error computing dominance frontiers: {s}\n", .{@errorName(err)});
                return;
            };
        }

        try writer.print("CFG for {s}:\n", .{method.name});
        for (cfg.blocks.items) |block| {
            try writer.print("  Block {d}: instructions {d}..{d}\n", .{ block.id, block.start_idx, block.end_idx });
            // Successors
            try writer.print("    Successors: ", .{});
            if (block.successors.items.len == 0) {
                try writer.print("None", .{});
            } else {
                for (block.successors.items, 0..) |succ, i| {
                    if (i > 0) try writer.print(", ", .{});
                    try writer.print("{d}", .{succ});
                }
            }
            try writer.print("\n", .{});
            // Predecessors (only when --dom is active)
            if (show_dom) {
                try writer.print("    Predecessors: ", .{});
                if (block.predecessors.items.len == 0) {
                    try writer.print("None", .{});
                } else {
                    for (block.predecessors.items, 0..) |pred, i| {
                        if (i > 0) try writer.print(", ", .{});
                        try writer.print("{d}", .{pred});
                    }
                }
                try writer.print("\n", .{});
                // Immediate dominator
                if (block.idom) |idom| {
                    try writer.print("    IDom: Block {d}\n", .{idom});
                } else {
                    try writer.print("    IDom: (entry)\n", .{});
                }
                // Dominance frontier
                try writer.print("    Dom Frontier: ", .{});
                if (block.dominance_frontier.items.len == 0) {
                    try writer.print("None", .{});
                } else {
                    for (block.dominance_frontier.items, 0..) |df_id, i| {
                        if (i > 0) try writer.print(", ", .{});
                        try writer.print("{d}", .{df_id});
                    }
                }
                try writer.print("\n", .{});
            }
            var idx = block.start_idx;
            while (idx <= block.end_idx) : (idx += 1) {
                try writer.print("      [{d:>4}] ", .{idx});
                try printer.printInstruction(writer, insts[idx]);
                try writer.writeByte('\n');
            }
        }
    } else if (std.mem.eql(u8, cmd, "emit")) {
        if (args.len < 5) {
            try writer.print("Error: 'emit' command requires <class_name> and <method_name> arguments.\n", .{});
            return;
        }
        const class_arg = args[3];
        const method_arg = args[4];

        const class = findClass(&dex, class_arg) orelse {
            try writer.print("Error: Class '{s}' not found.\n", .{class_arg});
            return;
        };
        const method = findMethod(&class, method_arg) orelse {
            try writer.print("Error: Method '{s}' not found in class '{s}'.\n", .{ method_arg, class.name });
            return;
        };

        const insts = dex.decodeMethod(arena, method) catch |err| {
            try writer.print("Error decoding bytecode: {s}\n", .{@errorName(err)});
            return;
        };

        if (args.len >= 6) {
            const path = args[5];
            var f = Io.Dir.cwd().createFile(io, path, .{}) catch |err| {
                try writer.print("Error: Could not create output file '{s}': {s}\n", .{ path, @errorName(err) });
                return;
            };
            defer f.close(io);

            var out_buffer: [1024]u8 = undefined;
            var out_file_writer = Io.File.Writer.init(f, io, &out_buffer);
            const f_writer = &out_file_writer.interface;

            for (insts) |inst| {
                try printer.printInstruction(f_writer, inst);
                try f_writer.writeByte('\n');
            }
            try out_file_writer.flush();
            try writer.print("Instructions successfully emitted to '{s}'.\n", .{path});
        } else {
            for (insts) |inst| {
                try printer.printInstruction(writer, inst);
                try writer.writeByte('\n');
            }
        }
    } else if (std.mem.eql(u8, cmd, "ssa") or std.mem.eql(u8, cmd, "ssa-opt") or std.mem.eql(u8, cmd, "dessa") or std.mem.eql(u8, cmd, "lower") or std.mem.eql(u8, cmd, "codegen") or std.mem.eql(u8, cmd, "run")) {
        if (args.len < 5) {
            try writer.print("Error: '{s}' command requires <class_name> and <method_name> arguments.\n", .{cmd});
            return;
        }
        const class_arg = args[3];
        const method_arg = args[4];

        const class = findClass(&dex, class_arg) orelse {
            try writer.print("Error: Class '{s}' not found.\n", .{class_arg});
            return;
        };
        const method = findMethod(&class, method_arg) orelse {
            try writer.print("Error: Method '{s}' not found in class '{s}'.\n", .{ method_arg, class.name });
            return;
        };

        const insts = dex.decodeMethod(arena, method) catch |err| {
            try writer.print("Error decoding bytecode: {s}\n", .{@errorName(err)});
            return;
        };

        var cfg = cfgmod.buildCFG(arena, insts) catch |err| {
            try writer.print("Error building CFG: {s}\n", .{@errorName(err)});
            return;
        };

        try cfg.computePredecessors();
        try cfg.computeDominators();
        try cfg.computeDominatorChildren();
        try cfg.computeDominanceFrontiers();

        try translate.translateCFG(arena, &cfg, insts);

        var def_map = std.AutoHashMap(u16, std.ArrayList(usize)).init(arena);
        defer {
            var it = def_map.iterator();
            while (it.next()) |entry| entry.value_ptr.deinit(arena);
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
                        try res.value_ptr.append(arena, block.id);
                    }
                }
            }
        }

        try cfg.insertPhiFunctions(def_map);
        try cfg.renameVariables(method.registers_size);

        if (std.mem.eql(u8, cmd, "ssa-opt") or std.mem.eql(u8, cmd, "dessa") or std.mem.eql(u8, cmd, "lower") or std.mem.eql(u8, cmd, "codegen") or std.mem.eql(u8, cmd, "run")) {
            _ = try opt.optimize(arena, &cfg);
        }

        if (std.mem.eql(u8, cmd, "dessa") or std.mem.eql(u8, cmd, "lower") or std.mem.eql(u8, cmd, "codegen") or std.mem.eql(u8, cmd, "run")) {
            try dessa.eliminatePhis(arena, &cfg);
            while (try dessa.propagateCopies(arena, &cfg)) {}
            if (std.mem.eql(u8, cmd, "run")) {
                // Do not print anything yet
            } else {
                try writer.print("SSA IR after de-SSA (eliminatePhis + propagateCopies) for method {s}:\n", .{method.name});
            }
        } else {
            try writer.print("SSA IR for method {s}:\n", .{method.name});
        }
        if (std.mem.eql(u8, cmd, "lower") or std.mem.eql(u8, cmd, "codegen") or std.mem.eql(u8, cmd, "run")) {
            var machine = try lower.lowerCFG(arena, &cfg);
            defer machine.deinit();
            if (std.mem.eql(u8, cmd, "codegen") or std.mem.eql(u8, cmd, "run")) {
                try regalloc.allocateRegisters(arena, &machine, method.registers_size, method.ins_size);
                if (std.mem.eql(u8, cmd, "run")) {
                    const code_bytes = try emitter.emitProgram(arena, &machine);
                    defer arena.free(code_bytes);

                    const exec_page = try exec_mem.allocateExecMemory(code_bytes.len);
                    defer exec_mem.freeExecMemory(exec_page);

                    @memcpy(exec_page, code_bytes);

                    var arg0: i64 = 0;
                    var arg1: i64 = 0;
                    var arg2: i64 = 0;
                    var arg3: i64 = 0;
                    if (args.len >= 6) arg0 = std.fmt.parseInt(i64, args[5], 10) catch 0;
                    if (args.len >= 7) arg1 = std.fmt.parseInt(i64, args[6], 10) catch 0;
                    if (args.len >= 8) arg2 = std.fmt.parseInt(i64, args[7], 10) catch 0;
                    if (args.len >= 9) arg3 = std.fmt.parseInt(i64, args[8], 10) catch 0;

                    const JITFn = *const fn (i64, i64, i64, i64) callconv(.c) i64;
                    const func = @as(JITFn, @ptrCast(exec_page.ptr));

                    const result = func(arg0, arg1, arg2, arg3);
                    try writer.print("JIT execution result: {d}\n", .{result});
                    return;
                }
                try writer.print("Register-allocated x86-64 assembly for method {s}:\n", .{method.name});
            } else {
                try writer.print("Virtual x86-64 assembly for method {s}:\n", .{method.name});
            }
            for (machine.blocks.items) |mblock| {
                try writer.print("  Block {d}:\n", .{mblock.id});
                for (mblock.instructions.items) |minst| {
                    try writer.writeAll("    ");
                    try minst.format(writer);
                    try writer.writeByte('\n');
                }
            }
        } else {
            for (cfg.blocks.items) |block| {
                try writer.print("  Block {d}:\n", .{block.id});
                for (block.instructions.items) |inst| {
                    try writer.writeAll("    ");
                    try inst.format(writer);
                    try writer.writeByte('\n');
                }
            }
        }
    } else if (std.mem.eql(u8, cmd, "kotlin")) {
        if (args.len < 4) {
            try writer.print("Error: 'kotlin' command requires a <class_name> argument.\n", .{});
            return;
        }
        const class_arg = args[3];
        const class = findClass(&dex, class_arg) orelse {
            try writer.print("Error: Class '{s}' not found.\n", .{class_arg});
            return;
        };

        const meta = class.kotlin_metadata orelse {
            try writer.print("Class '{s}' does not contain Kotlin metadata annotations.\n", .{class.name});
            return;
        };

        try writer.print("Kotlin Metadata summary for class {s}:\n", .{class.name});
        try writer.print("  Kind: {d}\n", .{meta.kind});
        try writer.print("  Version: ", .{});
        for (meta.metadata_version, 0..) |v, j| {
            if (j > 0) try writer.print(".", .{});
            try writer.print("{d}", .{v});
        }
        try writer.print("\n", .{});
        if (meta.package_name) |p| {
            try writer.print("  Package: {s}\n", .{p});
        }

        if (meta.data1.len > 0) {
            const pb_buf = decodeKotlinMetadata(arena, meta.data1) catch |err| {
                try writer.print("Error decoding Kotlin metadata: {s}\n", .{@errorName(err)});
                return;
            };

            resolve_arena = std.heap.ArenaAllocator.init(arena);
            defer {
                if (resolve_arena) |*a| a.deinit();
            }

            c.decode_kotlin_class(pb_buf.ptr, pb_buf.len, resolveString, @ptrCast(@constCast(&meta.data2)));
        } else {
            try writer.print("  (Empty/No metadata payload)\n", .{});
        }
    } else {
        try writer.print("Error: Unknown command '{s}'.\n\n", .{cmd});
        try usage(writer);
    }
}
