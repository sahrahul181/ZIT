const std = @import("std");
const testing = std.testing;

const interpreter = @import("interpreter");
const instmod = @import("instruction");
const class_loader = @import("class_loader");
const parser = @import("parser");

const Interpreter = interpreter.Interpreter;
const Frame = interpreter.Frame;
const Instruction = instmod.Instruction;
const Value = interpreter.Value;

fn setupTest(allocator: std.mem.Allocator) !*Interpreter {
    // Mock DexFile
    const dex = try allocator.create(parser.DexFile);
    
    var string_pool = try allocator.alloc([]const u8, 1);
    string_pool[0] = "test_string";
    
    var type_names = try allocator.alloc([]const u8, 1);
    type_names[0] = "Ljava/lang/Object;";
    
    dex.* = .{
        .classes = std.ArrayList(parser.DexClass).empty,
        .bytes = &[_]u8{},
        .method_items = &[_]parser.MethodInfo{},
        .field_items = &[_]parser.FieldInfo{},
        .type_names = type_names,
        .string_pool = string_pool,
        .arena = allocator,
    };

    // Mock ClassRegistry
    const registry = try allocator.create(class_loader.ClassRegistry);
    registry.* = class_loader.ClassRegistry.init(allocator);

    const interp = try allocator.create(Interpreter);
    interp.* = Interpreter.init(allocator, registry, dex);
    return interp;
}

fn teardownTest(interp: *Interpreter) void {
    const alloc = interp.allocator;
    alloc.free(interp.dex.string_pool);
    alloc.free(interp.dex.type_names);
    alloc.destroy(interp.dex);
    alloc.destroy(interp.registry);
    alloc.destroy(interp);
}

fn runTest(interp: *Interpreter, method: *class_loader.MethodData, instrs: []const Instruction) !Frame {
    var frame = Frame.init(method);
    _ = try interp.runFrame(&frame, instrs);
    return frame;
}

test "Interpreter: Moves" {
    const alloc = testing.allocator;
    const interp = try setupTest(alloc);
    defer teardownTest(interp);

    var method = class_loader.MethodData.init(undefined, "Test", false, false);
    
    const instrs = [_]Instruction{
        .{ .const_ = .{ .dest = 0, .value = 42 } },
        .{ .move = .{ .dest = 1, .src = 0 } },
        .{ .const_wide = .{ .dest = 2, .value = 0x123456789ABCDEF0 } },
        .{ .move_wide = .{ .dest = 4, .src = 2 } },
        .{ .return_void = {} },
    };

    const frame = try runTest(interp, &method, &instrs);
    
    try testing.expectEqual(@as(u64, 42), frame.regs[1]);
    try testing.expectEqual(@as(u64, 0x123456789ABCDEF0), frame.regs[4]);
}

test "Interpreter: Arithmetic (Int)" {
    const alloc = testing.allocator;
    const interp = try setupTest(alloc);
    defer teardownTest(interp);

    var method = class_loader.MethodData.init(undefined, "Test", false, false);
    
    const instrs = [_]Instruction{
        .{ .const_ = .{ .dest = 0, .value = 10 } },
        .{ .const_ = .{ .dest = 1, .value = 5 } },
        .{ .add_int = .{ .dest = 2, .src1 = 0, .src2 = 1 } },
        .{ .sub_int = .{ .dest = 3, .src1 = 0, .src2 = 1 } },
        .{ .mul_int = .{ .dest = 4, .src1 = 0, .src2 = 1 } },
        .{ .div_int = .{ .dest = 5, .src1 = 0, .src2 = 1 } },
        .{ .rem_int = .{ .dest = 6, .src1 = 0, .src2 = 1 } },
        .{ .return_void = {} },
    };

    const frame = try runTest(interp, &method, &instrs);
    
    try testing.expectEqual(@as(i32, 15), @as(i32, @bitCast(@as(u32, @truncate(frame.regs[2])))));
    try testing.expectEqual(@as(i32, 5),  @as(i32, @bitCast(@as(u32, @truncate(frame.regs[3])))));
    try testing.expectEqual(@as(i32, 50), @as(i32, @bitCast(@as(u32, @truncate(frame.regs[4])))));
    try testing.expectEqual(@as(i32, 2),  @as(i32, @bitCast(@as(u32, @truncate(frame.regs[5])))));
    try testing.expectEqual(@as(i32, 0),  @as(i32, @bitCast(@as(u32, @truncate(frame.regs[6])))));
}

test "Interpreter: Control Flow" {
    const alloc = testing.allocator;
    const interp = try setupTest(alloc);
    defer teardownTest(interp);

    var method = class_loader.MethodData.init(undefined, "Test", false, false);
    
    // Test if_eq and goto
    const instrs = [_]Instruction{
        .{ .const_ = .{ .dest = 0, .value = 10 } },
        .{ .const_ = .{ .dest = 1, .value = 10 } },
        .{ .const_ = .{ .dest = 2, .value = 0 } },
        .{ .if_eq = .{ .src1 = 0, .src2 = 1, .offset = 2 } }, // Jump to const_ 1
        .{ .goto_ = .{ .offset = 2 } },                       // Should be skipped
        .{ .const_ = .{ .dest = 2, .value = 1 } },            // Target of if_eq
        .{ .return_void = {} },
    };

    const frame = try runTest(interp, &method, &instrs);
    
    try testing.expectEqual(@as(u64, 1), frame.regs[2]);
}
