//! Native Method Registry — Phase 7 (prep)
//!
//! Provides a JNI-like registry mapping Java method descriptors to Zig
//! function pointers.  Called by the interpreter and JIT for `native` methods.
//!
//! Registration format: "ClassName.methodName(signature)" → fn pointer

const std = @import("std");
const runtime = @import("runtime");
const class_loader = @import("class_loader");
const parser = @import("parser");
const registry_mod = @import("stdlib/registry.zig");

// ── Native function signature ─────────────────────────────────────────────────
//
// All native methods have the same C-calling-convention Zig signature.
// args[0] = `this` for instance methods (as usize ref), or first arg for statics.
// Returns a u64 (bit-cast the appropriate type; 0 for void).

pub const NativeFn = *const fn (args: [*]const u64, n_args: usize) callconv(.c) u64;

// ── Registry ──────────────────────────────────────────────────────────────────

pub const NativeRegistry = struct {
    map:       std.StringHashMap(NativeFn),
    allocator: std.mem.Allocator,
    mutex:     std.Io.Mutex,

    pub fn init(allocator: std.mem.Allocator) NativeRegistry {
        return .{
            .map       = std.StringHashMap(NativeFn).init(allocator),
            .allocator = allocator,
            .mutex     = .init,
        };
    }

    pub fn deinit(self: *NativeRegistry) void {
        var it = self.map.iterator();
        while (it.next()) |entry| {
            self.allocator.free(entry.key_ptr.*);
        }
        self.map.deinit();
    }

    /// Register a native implementation.
    /// `key` format: "ClassName->methodName(descriptor)"
    pub fn register(self: *NativeRegistry, key: []const u8, func: NativeFn) !void {
        self.mutex.lockUncancelable(runtime.global_io);
        defer self.mutex.unlock(runtime.global_io);
        const owned_key = try self.allocator.dupe(u8, key);
        try self.map.put(owned_key, func);
    }

    /// Look up a native implementation.
    pub fn resolve(self: *NativeRegistry, class_name: []const u8, method_name: []const u8, sig: []const u8) ?NativeFn {
        self.mutex.lockUncancelable(runtime.global_io);
        defer self.mutex.unlock(runtime.global_io);
        var buf: [512]u8 = undefined;
        const key = std.fmt.bufPrint(&buf, "{s}->{s}{s}", .{ class_name, method_name, sig }) catch return null;
        return self.map.get(key);
    }
};

// ── Built-in native implementations ──────────────────────────────────────────
//
// Native implementations are now modularized in `runtime/stdlib/`.
// The NativeRegistry dynamically loads them from `stdlib/registry.zig`.

pub fn registerBuiltins(reg: *NativeRegistry, class_reg: *class_loader.ClassRegistry) !void {
    for (registry_mod.stdlib_classes) |class_def| {
        try class_reg.defineNativeClass(class_def);
        
        for (class_def.methods) |md_def| {
            if (md_def.func_ptr) |ptr| {
                const func: NativeFn = @ptrCast(ptr);
                var buf: [512]u8 = undefined;
                const key = std.fmt.bufPrint(&buf, "{s}->{s}{s}", .{ class_def.name, md_def.name, md_def.signature }) catch continue;
                try reg.register(key, func);
            }
        }
    }
}

extern fn printf(format: [*]const u8, ...) callconv(.c) c_int;

const StringLayout = struct {
    value: [*]const u8,
    length: i32,
};

// Global JIT runtime context references for thread execution
pub var global_registry: ?*class_loader.ClassRegistry = null;
pub var global_dex: ?*const parser.DexFile = null;

// ── Global registry ───────────────────────────────────────────────────────────

pub var global_native_registry: ?NativeRegistry = null;

pub fn lookupNativeMethod(class_name: []const u8, name: []const u8, sig: []const u8) ?NativeFn {
    if (global_native_registry) |*r| {
        return r.resolve(class_name, name, sig);
    }
    return null;
}

pub fn initNativeRegistry(allocator: std.mem.Allocator, class_reg: *class_loader.ClassRegistry) !void {
    global_native_registry = NativeRegistry.init(allocator);
    try registerBuiltins(&global_native_registry.?, class_reg);
}

pub fn deinitNativeRegistry() void {
    if (global_native_registry) |*r| r.deinit();
}

// ── Tests ─────────────────────────────────────────────────────────────────────

test "NativeRegistry register and resolve" {
    runtime.global_io = std.testing.io;
    const a = std.testing.allocator;
    var reg = NativeRegistry.init(a);
    defer reg.deinit();

    var class_reg = class_loader.ClassRegistry.init(a);
    defer class_reg.deinit();
    try registerBuiltins(&reg, &class_reg);

    const fn_ptr = reg.resolve("java/lang/Math", "abs", "II");
    try std.testing.expect(fn_ptr != null);

    var args = [_]u64{ @bitCast(@as(i64, -42)) };
    const result = fn_ptr.?(&args, 1);
    try std.testing.expectEqual(@as(u64, 42), result);
}

test "NativeRegistry nanoTime returns nonzero" {
    runtime.global_io = std.testing.io;
    const a = std.testing.allocator;
    var reg = NativeRegistry.init(a);
    defer reg.deinit();
    var class_reg = class_loader.ClassRegistry.init(a);
    defer class_reg.deinit();
    try registerBuiltins(&reg, &class_reg);

    const fn_ptr = reg.resolve("java/lang/System", "nanoTime", "J").?;
    const result = fn_ptr(undefined, 0);
    try std.testing.expect(result != 0);
}
