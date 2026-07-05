//! Class Loader — Phase 1 of the Production JIT
//!
//! Loads, links, and lays out all classes from a DEX file so the runtime
//! knows field offsets, vtable slots, and super-class chains.
//!
//! Analogous to HotSpot's InstanceKlass + ConstantPool subsystem.

const std = @import("std");
const parser = @import("parser");
const instmod = @import("instruction");
const runtime = @import("runtime");
pub const InlineCache = struct {
    cached_class: usize = 0,
    cached_target: usize = 0,
    method_idx: u32,
};

// ── Field Descriptor ─────────────────────────────────────────────────────────

pub const FieldKind = enum {
    int,
    long,
    float,
    double,
    boolean,
    byte,
    short,
    char,
    reference, // any object or array
};

pub const FieldDescriptor = struct {
    name: []const u8,
    kind: FieldKind,
    offset: u32, // byte offset within instance data (after ObjectHeader)
    is_static: bool,
    class_name: []const u8,

    /// Parse a single-character or 'L' type descriptor to FieldKind.
    pub fn kindFromDesc(desc: []const u8) FieldKind {
        if (desc.len == 0) return .reference;
        return switch (desc[0]) {
            'I' => .int,
            'J' => .long,
            'F' => .float,
            'D' => .double,
            'Z' => .boolean,
            'B' => .byte,
            'S' => .short,
            'C' => .char,
            else => .reference,
        };
    }

    pub fn sizeOf(kind: FieldKind) u32 {
        return switch (kind) {
            .long, .double => 8,
            .int, .float, .reference => 4,
            .boolean, .byte => 1,
            .short, .char => 2,
        };
    }

    pub fn alignOf(kind: FieldKind) u32 {
        return switch (kind) {
            .long, .double => 8,
            .int, .float, .reference => 4,
            .short, .char => 2,
            .boolean, .byte => 1,
        };
    }
};

// ── Static Field Storage ──────────────────────────────────────────────────────

pub const FieldSlot = extern union {
    int: i32,
    long: i64,
    float: f32,
    double: f64,
    boolean: bool,
    byte: i8,
    char: u16,
    short: i16,
    reference: usize,
};

// ── Method Data ───────────────────────────────────────────────────────────────

pub const InitState = enum { not_started, in_progress, done, failed };

pub const MethodData = struct {
    name: []const u8,
    class_name: []const u8,
    signature: []const u8,
    method_idx: u32,
    is_static: bool,
    is_native: bool,
    is_abstract: bool,
    registers_size: u16,
    ins_size: u16,
    outs_size: u16,
    vtable_slot: u32, // 0xFFFF_FFFF if not virtual
    code_off: usize, // 0 if abstract / native
    tries: []const instmod.TryBlock,

    // Runtime state (mutated after initial load)
    invocation_count: std.atomic.Value(u32),
    /// Native code entry point, published by the JIT. 0 = not yet compiled.
    /// Atomic because it is written by the compiling thread and read by every
    /// other thread that dispatches this method; a plain field would let the
    /// optimizer cache a stale null (observed under ReleaseFast), causing other
    /// threads to interpret a hot method forever.
    jit_entry_atomic: std.atomic.Value(usize),
    gc_map_table: ?usize = null, // absolute address of GcMapTable in exec memory
    /// For native methods: the raw C function pointer
    /// (fn(args: [*]const u64, n: usize) callconv(.c) u64). null for bytecode methods.
    native_fn: ?usize = null,
    /// Lazily-generated per-method trampoline that adapts the JIT call ABI to the
    /// native fn. 0 = not yet generated. Atomic (see jit_entry_atomic rationale).
    native_trampoline: std.atomic.Value(usize) = std.atomic.Value(usize).init(0),

    /// Returns the published JIT entry, or null if not yet compiled.
    pub inline fn jitEntry(self: *const MethodData) ?usize {
        const v = self.jit_entry_atomic.load(.acquire);
        return if (v == 0) null else v;
    }

    /// Publish a compiled entry point so other threads observe it.
    pub inline fn setJitEntry(self: *MethodData, entry: usize) void {
        self.jit_entry_atomic.store(entry, .release);
    }

    pub fn init(dm: parser.DexMethod, class_name: []const u8, is_native: bool, is_abstract: bool) MethodData {
        return .{
            .name = dm.name,
            .class_name = class_name,
            .signature = dm.signature,
            .method_idx = dm.method_idx,
            .is_static = dm.is_static,
            .is_native = is_native,
            .is_abstract = is_abstract,
            .registers_size = dm.registers_size,
            .ins_size = dm.ins_size,
            .outs_size = dm.outs_size,
            .vtable_slot = 0xFFFF_FFFF,
            .code_off = dm.code_off,
            .tries = dm.tries,
            .invocation_count = std.atomic.Value(u32).init(0),
            .jit_entry_atomic = std.atomic.Value(usize).init(0),
            .gc_map_table = null,
        };
    }

    pub fn incrementAndCheck(self: *MethodData, threshold: u32) bool {
        const prev = self.invocation_count.fetchAdd(1, .monotonic);
        return (prev + 1) >= threshold;
    }
};

// ── Class Data ────────────────────────────────────────────────────────────────

pub const ItableEntry = struct {
    interface_class: *ClassData,
    methods: []*MethodData,
};

pub const ClassData = struct {
    /// Internal name, e.g. "java/lang/Thread" or "ThreadedCompute"
    name: []const u8,
    super: ?*ClassData,
    interfaces: []*ClassData,
    itable: []ItableEntry = &.{},

    /// Total allocation size in bytes (ObjectHeader already excluded,
    /// the GC adds it). Includes all inherited + own instance fields.
    instance_size: u32,

    instance_fields: []FieldDescriptor,
    static_fields: []FieldDescriptor,
    static_values: []FieldSlot, // indexed parallel to static_fields

    /// vtable[i] → *MethodData.  Index 0..super.vtable.len may be inherited.
    vtable: []*MethodData,

    /// All methods (direct + virtual), keyed by flat index in declaration order.
    methods: []*MethodData,

    init_state: std.atomic.Value(u32), // 0=not_started,1=in_progress,2=done,3=failed
    clinit_mutex: std.Io.Mutex,

    allocator: std.mem.Allocator,

    pub fn deinit(self: *ClassData) void {
        self.allocator.free(self.name);
        self.allocator.free(self.interfaces);
        for (self.itable) |*entry| {
            self.allocator.free(entry.methods);
        }
        self.allocator.free(self.itable);
        self.allocator.free(self.instance_fields);
        self.allocator.free(self.static_fields);
        self.allocator.free(self.static_values);
        self.allocator.free(self.vtable);
        for (self.methods) |m| {
            self.allocator.free(m.name);
            self.allocator.free(m.class_name);
            self.allocator.free(m.signature);
            self.allocator.destroy(m);
        }
        self.allocator.free(self.methods);
        self.allocator.destroy(self);
    }

    pub fn findMethod(self: *const ClassData, name: []const u8, sig: []const u8) ?*MethodData {
        for (self.methods) |m| {
            // m.name is "ClassName->methodName"; strip prefix
            const arrow = std.mem.indexOf(u8, m.name, "->") orelse 0;
            const short = if (arrow > 0) m.name[arrow + 2 ..] else m.name;
            if (std.mem.eql(u8, short, name) and std.mem.eql(u8, m.signature, sig)) {
                return m;
            }
        }
        return null;
    }

    pub fn fieldOffset(self: *const ClassData, name: []const u8) ?u32 {
        for (self.instance_fields) |f| {
            if (std.mem.eql(u8, f.name, name)) return f.offset;
        }
        return null;
    }

    pub fn staticSlot(self: *ClassData, name: []const u8) ?*FieldSlot {
        for (self.static_fields, 0..) |f, i| {
            if (std.mem.eql(u8, f.name, name)) return &self.static_values[i];
        }
        return null;
    }
};

// ── Class Registry ────────────────────────────────────────────────────────────

pub const ClassRegistry = struct {
    /// descriptor → *ClassData (owns all ClassData)
    map: std.StringHashMap(*ClassData),
    allocator: std.mem.Allocator,
    mutex: std.Io.Mutex,

    /// Invocation threshold before a method is enqueued for JIT compilation.
    jit_threshold: u32 = 1000,

    pub fn init(allocator: std.mem.Allocator) ClassRegistry {
        return .{
            .map = std.StringHashMap(*ClassData).init(allocator),
            .allocator = allocator,
            .mutex = .init,
        };
    }

    pub fn deinit(self: *ClassRegistry) void {
        var it = self.map.valueIterator();
        while (it.next()) |cd| cd.*.deinit();
        self.map.deinit();
    }

    /// Return an already-loaded class or null.
    pub fn get(self: *ClassRegistry, name: []const u8) ?*ClassData {
        self.mutex.lockUncancelable(runtime.global_io);
        defer self.mutex.unlock(runtime.global_io);
        return self.map.get(name);
    }

    /// Dynamically register a built-in native class.
    pub fn defineNativeClass(self: *ClassRegistry, class_def: anytype) !void {
        self.mutex.lockUncancelable(runtime.global_io);
        defer self.mutex.unlock(runtime.global_io);

        if (self.map.contains(class_def.name)) return;

        const cd = try self.allocator.create(ClassData);
        const super_class = if (class_def.super_name) |sn| self.map.get(sn) else null;

        const sfields = try self.allocator.alloc(FieldDescriptor, class_def.static_fields.len);
        for (class_def.static_fields, 0..) |sf, i| {
            sfields[i] = .{
                // Field name/class_name here are comptime string literals with
                // static lifetime (from NativeClassDef), so borrow rather than dupe.
                // FieldDescriptor names are not freed in ClassData.deinit; duping
                // them leaks. This matches the DEX-loaded static-field path.
                .name = sf.name,
                .kind = FieldDescriptor.kindFromDesc(sf.signature),
                .offset = 0,
                .is_static = true,
                .class_name = class_def.name,
            };
        }
        const svalues = try self.allocator.alloc(FieldSlot, class_def.static_fields.len);
        @memset(svalues, .{ .reference = 0 });

        cd.* = ClassData{
            .name = try self.allocator.dupe(u8, class_def.name),
            .super = super_class,
            .interfaces = &.{},
            .instance_size = class_def.instance_size,
            .instance_fields = &.{},
            .static_fields = sfields,
            .static_values = svalues,
            .vtable = &.{},
            .methods = &.{},
            .init_state = std.atomic.Value(u32).init(2),
            .clinit_mutex = .init,
            .allocator = self.allocator,
        };

        var methods: std.ArrayListUnmanaged(*MethodData) = .empty;
        for (class_def.methods) |md_def| {
            const md = try self.allocator.create(MethodData);
            const full_name = try std.fmt.allocPrint(self.allocator, "{s}->{s}", .{ class_def.name, md_def.name });
            md.* = .{
                .name = full_name,
                .class_name = try self.allocator.dupe(u8, class_def.name),
                .signature = try self.allocator.dupe(u8, md_def.signature),
                .method_idx = 0xFFFF_FFFF,
                .is_static = md_def.is_static,
                .is_native = md_def.func_ptr != null,
                .is_abstract = false,
                .registers_size = 4,
                .ins_size = 2,
                .outs_size = 0,
                .vtable_slot = 0xFFFF_FFFF,
                .code_off = 0,
                .tries = &.{},
                .invocation_count = std.atomic.Value(u32).init(0),
                .jit_entry_atomic = std.atomic.Value(usize).init(0),
                .native_fn = if (md_def.func_ptr) |fp| @intFromPtr(fp) else null,
            };
            try methods.append(self.allocator, md);
        }
        cd.methods = try methods.toOwnedSlice(self.allocator);

        try buildVtable(self.allocator, cd);
        try self.map.put(cd.name, cd);
    }

    /// Load all classes from a parsed DEX file.  Must be called once per DEX.
    pub fn loadDex(self: *ClassRegistry, dex: *const parser.DexFile) !void {
        // Pass 1: Create ClassData stubs for every class in the DEX (needed to
        // resolve super-class pointers in pass 2 even for circular hierarchies).
        for (dex.classes.items) |*dc| {
            if (self.map.contains(dc.name)) continue;
            const cd = try self.allocator.create(ClassData);
            cd.* = ClassData{
                // Own the name so ClassData.deinit can free it uniformly. Borrowing
                // dc.name (DEX-arena memory) here caused a heap-corruption crash at
                // shutdown when deinit tried to free non-owned memory.
                .name = try self.allocator.dupe(u8, dc.name),
                .super = null,
                .interfaces = &.{},
                .instance_size = 0,
                .instance_fields = &.{},
                .static_fields = &.{},
                .static_values = &.{},
                .vtable = &.{},
                .methods = &.{},
                .init_state = std.atomic.Value(u32).init(0),
                .clinit_mutex = .init,
                .allocator = self.allocator,
            };
            // Key on the owned name so the map key outlives the DEX arena.
            try self.map.put(cd.name, cd);
        }

        // Pass 2: Fully populate each ClassData.
        for (dex.classes.items) |*dc| {
            const cd = self.map.get(dc.name).?;
            try self.linkClass(cd, dc, dex);
        }
    }

    /// Fully link one class: resolve super, compute field layout, build vtable.
    fn linkClass(self: *ClassRegistry, cd: *ClassData, dc: *const parser.DexClass, dex: *const parser.DexFile) !void {
        // Resolve super class
        if (dc.super_class_idx != 0xFFFF_FFFF) {
            if (dc.super_class_idx < dex.type_names.len) {
                const super_name = dex.type_names[dc.super_class_idx];
                cd.super = self.map.get(super_name);
            }
        }

        // ── Field layout ────────────────────────────────────────────────────
        // Collect fields from field_items for this class.
        var ifields: std.ArrayList(FieldDescriptor) = .empty;
        var sfields: std.ArrayList(FieldDescriptor) = .empty;
        defer ifields.deinit(self.allocator);
        defer sfields.deinit(self.allocator);

        for (dex.field_items, 0..) |fi, fi_idx| {
            if (!std.mem.eql(u8, fi.class_name, dc.name)) continue;
            const kind = FieldDescriptor.kindFromDesc(fi.type_name);

            var is_static = false;
            for (dc.static_field_indices.items) |sfi| {
                if (sfi == fi_idx) {
                    is_static = true;
                    break;
                }
            }

            if (is_static) {
                try sfields.append(self.allocator, .{
                    .name = fi.field_name,
                    .kind = kind,
                    .offset = 0,
                    .is_static = true,
                    .class_name = fi.class_name,
                });
            } else {
                try ifields.append(self.allocator, .{
                    .name = fi.field_name,
                    .kind = kind,
                    .offset = 0,
                    .is_static = false,
                    .class_name = fi.class_name,
                });
            }
        }

        // Compute instance field offsets (inherit from super first)
        var cursor: u32 = if (cd.super) |s| s.instance_size else 0;
        for (ifields.items) |*f| {
            const a = FieldDescriptor.alignOf(f.kind);
            cursor = std.mem.alignForward(u32, cursor, a);
            f.offset = cursor;
            cursor += FieldDescriptor.sizeOf(f.kind);
        }
        cd.instance_size = cursor;

        cd.instance_fields = try self.allocator.dupe(FieldDescriptor, ifields.items);
        cd.static_fields = try self.allocator.dupe(FieldDescriptor, sfields.items);
        cd.static_values = try self.allocator.alloc(FieldSlot, sfields.items.len);
        @memset(std.mem.sliceAsBytes(cd.static_values), 0);
        for (cd.static_values) |*sv| sv.* = .{ .int = 0 };

        // ── Method list ─────────────────────────────────────────────────────
        var methods = try self.allocator.alloc(*MethodData, dc.methods.items.len);
        for (dc.methods.items, 0..) |dm, i| {
            const md = try self.allocator.create(MethodData);
            md.* = MethodData.init(dm, dc.name, false, false);
            // MethodData.init borrows name/class_name/signature from the DEX arena.
            // Dupe them so ClassData.deinit can free them without corrupting the
            // heap (and so they outlive the parsed DEX).
            md.name = try self.allocator.dupe(u8, md.name);
            md.class_name = try self.allocator.dupe(u8, md.class_name);
            md.signature = try self.allocator.dupe(u8, md.signature);
            methods[i] = md;
        }
        cd.methods = methods;

        // ── Vtable & Itable ──────────────────────────────────────────────────
        try buildVtable(self.allocator, cd);
        try buildItable(self.allocator, cd);
    }
};

// ── Vtable Builder ────────────────────────────────────────────────────────────

/// Build the vtable for `cd` by extending its super-class vtable.
/// Virtual methods override existing slots (same name+sig), new methods append.
fn buildVtable(allocator: std.mem.Allocator, cd: *ClassData) !void {
    // Start with a mutable copy of the super's vtable.
    var slots: std.ArrayList(*MethodData) = .empty;
    defer slots.deinit(allocator);

    if (cd.super) |s| {
        try slots.appendSlice(allocator, s.vtable);
    }

    for (cd.methods) |md| {
        if (md.is_static) continue;

        // Strip "ClassName->" prefix for comparison
        const arrow = std.mem.indexOf(u8, md.name, "->") orelse 0;
        const short_name = if (arrow > 0) md.name[arrow + 2 ..] else md.name;

        // Skip constructors — they are never virtual
        if (std.mem.eql(u8, short_name, "<init>") or
            std.mem.eql(u8, short_name, "<clinit>")) continue;

        // Check if this overrides a parent slot
        var found_slot: ?usize = null;
        for (slots.items, 0..) |slot_md, si| {
            const sa = std.mem.indexOf(u8, slot_md.name, "->") orelse 0;
            const slot_short = if (sa > 0) slot_md.name[sa + 2 ..] else slot_md.name;
            if (std.mem.eql(u8, slot_short, short_name) and
                std.mem.eql(u8, slot_md.signature, md.signature))
            {
                found_slot = si;
                break;
            }
        }

        if (found_slot) |si| {
            slots.items[si] = md;
            md.vtable_slot = @intCast(si);
        } else {
            md.vtable_slot = @intCast(slots.items.len);
            try slots.append(allocator, md);
        }
    }

    cd.vtable = try allocator.dupe(*MethodData, slots.items);
}

fn buildItable(allocator: std.mem.Allocator, cd: *ClassData) !void {
    var itfs = std.ArrayList(*ClassData).empty;
    defer itfs.deinit(allocator);

    const addTransitive = struct {
        fn run(list: *std.ArrayList(*ClassData), alloc: std.mem.Allocator, target: *ClassData) !void {
            for (list.items) |existing| {
                if (existing == target) return;
            }
            try list.append(alloc, target);
            for (target.interfaces) |super_itf| {
                try run(list, alloc, super_itf);
            }
        }
    }.run;

    var curr: ?*ClassData = cd;
    while (curr) |c| : (curr = c.super) {
        for (c.interfaces) |itf| {
            try addTransitive(&itfs, allocator, itf);
        }
    }

    var entries = try allocator.alloc(ItableEntry, itfs.items.len);
    for (itfs.items, 0..) |itf, i| {
        var itf_methods = try allocator.alloc(*MethodData, itf.methods.len);
        for (itf.methods, 0..) |m, j| {
            const name_arrow = std.mem.indexOf(u8, m.name, "->") orelse 0;
            const short_name = if (name_arrow > 0) m.name[name_arrow + 2 ..] else m.name;

            var found: ?*MethodData = null;
            var search_curr: ?*ClassData = cd;
            while (search_curr) |sc| : (search_curr = sc.super) {
                if (sc.findMethod(short_name, m.signature)) |found_m| {
                    found = found_m;
                    break;
                }
            }
            itf_methods[j] = found orelse m;
        }
        entries[i] = .{
            .interface_class = itf,
            .methods = itf_methods,
        };
    }
    cd.itable = entries;
}

// ── Tests ─────────────────────────────────────────────────────────────────────

test "FieldDescriptor.kindFromDesc and sizeOf" {
    try std.testing.expectEqual(FieldKind.int, FieldDescriptor.kindFromDesc("I"));
    try std.testing.expectEqual(FieldKind.long, FieldDescriptor.kindFromDesc("J"));
    try std.testing.expectEqual(FieldKind.double, FieldDescriptor.kindFromDesc("D"));
    try std.testing.expectEqual(FieldKind.reference, FieldDescriptor.kindFromDesc("Ljava/lang/Object;"));
    try std.testing.expectEqual(@as(u32, 8), FieldDescriptor.sizeOf(.long));
    try std.testing.expectEqual(@as(u32, 4), FieldDescriptor.sizeOf(.int));
    try std.testing.expectEqual(@as(u32, 1), FieldDescriptor.sizeOf(.boolean));
}

test "ClassRegistry init and deinit" {
    var reg = ClassRegistry.init(std.testing.allocator);
    defer reg.deinit();
    try std.testing.expect(reg.get("NonExistent") == null);
}

test "vtable slot assignment: child overrides parent" {
    runtime.global_io = std.testing.io;
    const allocator = std.testing.allocator;

    // Create a minimal parent class with one virtual method
    const parent_method = try allocator.create(MethodData);
    parent_method.* = MethodData{
        .name = "Parent->hashCode",
        .class_name = "Parent",
        .signature = "I",
        .method_idx = 0xFFFF_FFFF,
        .is_static = false,
        .is_native = false,
        .is_abstract = false,
        .registers_size = 2,
        .ins_size = 1,
        .outs_size = 0,
        .vtable_slot = 0,
        .code_off = 0,
        .tries = &.{},
        .invocation_count = std.atomic.Value(u32).init(0),
        .jit_entry_atomic = std.atomic.Value(usize).init(0),
    };
    var parent_methods = [_]*MethodData{parent_method};
    var parent_vtable = [_]*MethodData{parent_method};

    var parent = ClassData{
        .name = "Parent",
        .super = null,
        .interfaces = &.{},
        .instance_size = 0,
        .instance_fields = &.{},
        .static_fields = &.{},
        .static_values = &.{},
        .vtable = &parent_vtable,
        .methods = &parent_methods,
        .init_state = std.atomic.Value(u32).init(2),
        .clinit_mutex = .init,
        .allocator = allocator,
    };

    // Create a child that overrides hashCode
    const child_method = try allocator.create(MethodData);
    child_method.* = MethodData{
        .name = "Child->hashCode",
        .class_name = "Child",
        .signature = "I",
        .method_idx = 0xFFFF_FFFF,
        .is_static = false,
        .is_native = false,
        .is_abstract = false,
        .registers_size = 2,
        .ins_size = 1,
        .outs_size = 0,
        .vtable_slot = 0xFFFF_FFFF,
        .code_off = 100,
        .tries = &.{},
        .invocation_count = std.atomic.Value(u32).init(0),
        .jit_entry_atomic = std.atomic.Value(usize).init(0),
    };
    var child_methods = [_]*MethodData{child_method};

    var child = ClassData{
        .name = "Child",
        .super = &parent,
        .interfaces = &.{},
        .instance_size = 0,
        .instance_fields = &.{},
        .static_fields = &.{},
        .static_values = &.{},
        .vtable = &.{},
        .methods = &child_methods,
        .init_state = std.atomic.Value(u32).init(2),
        .clinit_mutex = .init,
        .allocator = allocator,
    };

    try buildVtable(allocator, &child);
    defer allocator.free(child.vtable);

    // Child should have exactly one vtable slot, occupied by child_method
    try std.testing.expectEqual(@as(usize, 1), child.vtable.len);
    try std.testing.expectEqual(child_method, child.vtable[0]);
    try std.testing.expectEqual(@as(u32, 0), child_method.vtable_slot);

    allocator.destroy(parent_method);
    allocator.destroy(child_method);
}

// bootstrapStdLib has been completely removed in favor of dynamic resolution

pub var jit_compile_fn: ?*const fn (method_ptr: usize, registry_ptr: usize, dex_ptr: usize) callconv(.c) usize = null;
pub var jit_compile_osr_fn: ?*const fn (method_ptr: usize, loop_pc: u32, registry_ptr: usize, dex_ptr: usize) callconv(.c) usize = null;

pub fn resolveMethodVirtual(receiver: usize, method_idx: u32, dex_ptr: usize, registry_ptr: usize) callconv(.c) usize {
    const dex = @as(*const parser.DexFile, @ptrFromInt(dex_ptr));
    const itf_method_info = dex.method_items[method_idx];

    // Find matching MethodData in ClassData vtable/itable hierarchy
    var target_method: ?*MethodData = null;

    const name_arrow = std.mem.indexOf(u8, itf_method_info.method_name, "->") orelse 0;
    const short_name = if (name_arrow > 0) itf_method_info.method_name[name_arrow + 2 ..] else itf_method_info.method_name;

    // Only attempt receiver-class dispatch when the object actually carries a
    // class pointer. Objects allocated without one (class_ptr == 0) fall through
    // to the global lookup below rather than dereferencing a null ClassData.
    if (receiver != 0 and @as(*const runtime.ObjectHeader, @ptrFromInt(receiver - 16)).class_ptr != 0) {
        const obj = @as(*const runtime.ObjectHeader, @ptrFromInt(receiver - 16));
        const cd = @as(*const ClassData, @ptrFromInt(obj.class_ptr));

        // 1. Search in receiver class vtable
        for (cd.vtable) |m| {
            const ma = std.mem.indexOf(u8, m.name, "->") orelse 0;
            const m_short = if (ma > 0) m.name[ma + 2 ..] else m.name;
            if (std.mem.eql(u8, m_short, short_name) and std.mem.eql(u8, m.signature, itf_method_info.signature)) {
                target_method = m;
                break;
            }
        }

        // 2. Search in receiver class itable if not found in vtable
        if (target_method == null) {
            for (cd.itable) |entry| {
                for (entry.methods) |m| {
                    const ma = std.mem.indexOf(u8, m.name, "->") orelse 0;
                    const m_short = if (ma > 0) m.name[ma + 2 ..] else m.name;
                    if (std.mem.eql(u8, m_short, short_name) and std.mem.eql(u8, m.signature, itf_method_info.signature)) {
                        target_method = m;
                        break;
                    }
                }
                if (target_method != null) break;
            }
        }

        // 3. Search direct methods if still not found
        if (target_method == null) {
            var search_cd: ?*const ClassData = cd;
            while (search_cd) |sc| : (search_cd = sc.super) {
                if (sc.findMethod(short_name, itf_method_info.signature)) |m| {
                    target_method = m;
                    break;
                }
            }
        }
    } else {
        // Static dispatch using declaring class
        const registry = @as(*ClassRegistry, @ptrFromInt(registry_ptr));
        const decl_cd = registry.get(itf_method_info.class_name) orelse {
            std.debug.panic("ClassNotFoundException: {s}", .{itf_method_info.class_name});
        };
        var search_cd: ?*const ClassData = decl_cd;
        while (search_cd) |sc| : (search_cd = sc.super) {
            if (sc.findMethod(short_name, itf_method_info.signature)) |m| {
                target_method = m;
                break;
            }
        }
    }

    // Fallback: if receiver-class dispatch found nothing (e.g. the object had a
    // null class pointer), resolve via the method's declaring class by name. This
    // covers JIT-allocated objects whose header class_ptr was not populated.
    if (target_method == null) {
        const registry = @as(*ClassRegistry, @ptrFromInt(registry_ptr));
        if (registry.get(itf_method_info.class_name)) |decl_cd| {
            var search_cd: ?*const ClassData = decl_cd;
            while (search_cd) |sc| : (search_cd = sc.super) {
                if (sc.findMethod(short_name, itf_method_info.signature)) |m| {
                    target_method = m;
                    break;
                }
            }
        }
    }

    const method = target_method orelse {
        std.debug.panic("NoSuchMethodError: {s}.{s}{s}", .{
            itf_method_info.class_name, itf_method_info.method_name, itf_method_info.signature,
        });
    };

    // Native methods have no bytecode to JIT. Return a per-method marshalling
    // trampoline that converts the JIT register-arg ABI (args in RCX/RDX/R8/R9)
    // into the native ABI (RCX = &args[], RDX = count) and calls the native fn.
    // The trampoline is generated once per method with the native fn baked in as
    // an immediate — it must NOT depend on any shared/thread-local state, because
    // the monomorphic inline cache stores the trampoline address and calls it on
    // subsequent hits without re-running this resolver.
    if (method.is_native) {
        if (method.native_fn) |nfn| {
            return getNativeTrampoline(method, nfn);
        }
        return 0; // native method with no implementation: skip (guarded call)
    }

    if (method.jitEntry()) |entry| {
        return entry;
    }
    if (jit_compile_fn) |compile_fn| {
        return compile_fn(@intFromPtr(method), registry_ptr, dex_ptr);
    }

    std.debug.panic("JIT compiler function not initialized", .{});
}

/// Hook installed by the driver so this module can allocate executable memory
/// for native trampolines without depending on the JIT backend directly.
pub var alloc_exec_fn: ?*const fn (usize) callconv(.c) usize = null;
var native_tramp_mutex: runtime.SpinLock = .{};

/// Return (creating on first use) a marshalling trampoline for `method` that
/// spills RCX/RDX/R8/R9 into a stack array and calls `nfn(&array, 4)`. The
/// native fn pointer is embedded directly, so the trampoline is self-contained
/// and safe to cache in the inline cache. The trampoline address is memoized in
/// `method.native_trampoline`.
fn getNativeTrampoline(method: *MethodData, nfn: usize) usize {
    const existing = method.native_trampoline.load(.acquire);
    if (existing != 0) return existing;
    native_tramp_mutex.lock();
    defer native_tramp_mutex.unlock();
    const again = method.native_trampoline.load(.acquire);
    if (again != 0) return again; // lost the race

    const alloc = alloc_exec_fn orelse return 0;
    // Machine code (Windows x64), RSP%16==8 on entry:
    //   sub  rsp, 0x48
    //   mov  [rsp+0x20], rcx / rdx / r8 / r9
    //   lea  rcx, [rsp+0x20]
    //   mov  rdx, 4
    //   movabs rax, nfn
    //   call rax
    //   add  rsp, 0x48
    //   ret
    var buf: [64]u8 = undefined;
    var n: usize = 0;
    const put = struct {
        fn f(b: []u8, i: *usize, bytes: []const u8) void {
            @memcpy(b[i.*..][0..bytes.len], bytes);
            i.* += bytes.len;
        }
    }.f;
    put(&buf, &n, &[_]u8{ 0x48, 0x83, 0xEC, 0x48 });       // sub rsp, 0x48
    put(&buf, &n, &[_]u8{ 0x48, 0x89, 0x4C, 0x24, 0x20 }); // mov [rsp+0x20], rcx
    put(&buf, &n, &[_]u8{ 0x48, 0x89, 0x54, 0x24, 0x28 }); // mov [rsp+0x28], rdx
    put(&buf, &n, &[_]u8{ 0x4C, 0x89, 0x44, 0x24, 0x30 }); // mov [rsp+0x30], r8
    put(&buf, &n, &[_]u8{ 0x4C, 0x89, 0x4C, 0x24, 0x38 }); // mov [rsp+0x38], r9
    put(&buf, &n, &[_]u8{ 0x48, 0x8D, 0x4C, 0x24, 0x20 }); // lea rcx, [rsp+0x20]
    put(&buf, &n, &[_]u8{ 0x48, 0xC7, 0xC2, 0x04, 0x00, 0x00, 0x00 }); // mov rdx, 4
    put(&buf, &n, &[_]u8{ 0x48, 0xB8 });                   // movabs rax, imm64
    var nfn_bytes: [8]u8 = undefined;
    std.mem.writeInt(u64, &nfn_bytes, nfn, .little);
    put(&buf, &n, &nfn_bytes);
    put(&buf, &n, &[_]u8{ 0xFF, 0xD0 });                   // call rax
    put(&buf, &n, &[_]u8{ 0x48, 0x83, 0xC4, 0x48 });       // add rsp, 0x48
    put(&buf, &n, &[_]u8{ 0xC3 });                         // ret

    const page = alloc(n);
    if (page == 0) return 0;
    @memcpy(@as([*]u8, @ptrFromInt(page))[0..n], buf[0..n]);
    method.native_trampoline.store(page, .release);
    return page;
}

pub fn resolveMethodVirtualIC(receiver: usize, method_idx: u32, dex_ptr: usize, registry_ptr: usize, ic_ptr: usize) callconv(.c) usize {
    const target = resolveMethodVirtual(receiver, method_idx, dex_ptr, registry_ptr);
    if (receiver != 0) {
        const obj = @as(*const runtime.ObjectHeader, @ptrFromInt(receiver - 16));
        const ic = @as(*InlineCache, @ptrFromInt(ic_ptr));
        ic.cached_class = obj.class_ptr;
        ic.cached_target = target;
    }
    return target;
}

// ── Tests ─────────────────────────────────────────────────────────────────────

const testing = std.testing;

test "ClassRegistry defineNativeClass basic" {
    // We create a dummy Object class definition.
    const DummyDef = struct {
        name: []const u8,
        super_name: ?[]const u8,
        instance_size: u32,
        methods: []const struct {
            name: []const u8,
            signature: []const u8,
            is_static: bool,
            func_ptr: ?*const fn ([*]const u64, usize) callconv(.c) u64,
        },
        static_fields: []const struct { name: []const u8, signature: []const u8 } = &.{},
    };

    var reg = ClassRegistry.init(testing.allocator);
    defer reg.deinit();

    // Define a dummy class
    const dummy_class_def = DummyDef{
        .name = "java/lang/DummyObject",
        .super_name = null,
        .instance_size = 16,
        .methods = &.{
            .{ .name = "hashCode", .signature = "()I", .is_static = false, .func_ptr = null },
            .{ .name = "clone", .signature = "()Ljava/lang/Object;", .is_static = false, .func_ptr = null },
        },
    };

    try reg.defineNativeClass(dummy_class_def);

    // Verify it is found
    const cd = reg.get("java/lang/DummyObject");
    try testing.expect(cd != null);
    try testing.expectEqualStrings("java/lang/DummyObject", cd.?.name);
    try testing.expectEqual(@as(u32, 16), cd.?.instance_size);
    try testing.expect(cd.?.super == null);

    // Verify method resolution
    const m_hash = cd.?.findMethod("hashCode", "()I");
    try testing.expect(m_hash != null);
    try testing.expectEqualStrings("java/lang/DummyObject->hashCode", m_hash.?.name);
    try testing.expectEqualStrings("()I", m_hash.?.signature);

    const m_clone = cd.?.findMethod("clone", "()Ljava/lang/Object;");
    try testing.expect(m_clone != null);

    // Should not find non-existent method
    try testing.expect(cd.?.findMethod("nonExistent", "()V") == null);
}

test "ClassRegistry defineNativeClass inheritance and vtable" {
    const DummyDef = struct {
        name: []const u8,
        super_name: ?[]const u8,
        instance_size: u32,
        methods: []const struct {
            name: []const u8,
            signature: []const u8,
            is_static: bool,
            func_ptr: ?*const fn ([*]const u64, usize) callconv(.c) u64,
        },
        static_fields: []const struct { name: []const u8, signature: []const u8 } = &.{},
    };

    var reg = ClassRegistry.init(testing.allocator);
    defer reg.deinit();

    // Define parent class
    const parent_def = DummyDef{
        .name = "Parent",
        .super_name = null,
        .instance_size = 16,
        .methods = &.{
            .{ .name = "overrideMe", .signature = "()V", .is_static = false, .func_ptr = null },
            .{ .name = "parentMethod", .signature = "()I", .is_static = false, .func_ptr = null },
        },
    };
    try reg.defineNativeClass(parent_def);

    // Define child class inheriting from parent
    const child_def = DummyDef{
        .name = "Child",
        .super_name = "Parent",
        .instance_size = 24, // instance size should be larger or equal
        .methods = &.{
            .{ .name = "overrideMe", .signature = "()V", .is_static = false, .func_ptr = null },
            .{ .name = "childMethod", .signature = "()V", .is_static = false, .func_ptr = null },
        },
    };
    try reg.defineNativeClass(child_def);

    const child_cd = reg.get("Child").?;
    const parent_cd = reg.get("Parent").?;

    // Check inheritance
    try testing.expect(child_cd.super == parent_cd);

    // Check vtable
    // Parent has 2 virtual methods, so its vtable should be size 2.
    // Child inherits parentMethod and overrides overrideMe, plus adds childMethod.
    // Vtable length should be 3.
    try testing.expectEqual(@as(usize, 2), parent_cd.vtable.len);
    try testing.expectEqual(@as(usize, 3), child_cd.vtable.len);

    const child_override = child_cd.findMethod("overrideMe", "()V").?;
    const parent_override = parent_cd.findMethod("overrideMe", "()V").?;

    // overrideMe should be at the same vtable slot in both child and parent
    try testing.expect(child_override.vtable_slot == parent_override.vtable_slot);

    // child's vtable should point to its own overrideMe method
    try testing.expect(child_cd.vtable[child_override.vtable_slot] == child_override);
    try testing.expect(parent_cd.vtable[parent_override.vtable_slot] == parent_override);

    // parentMethod should be inherited exactly
    const parent_method = parent_cd.findMethod("parentMethod", "()I").?;
    try testing.expect(child_cd.vtable[parent_method.vtable_slot] == parent_method);
}
