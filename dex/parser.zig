//! DEX binary format parser: Full standard library object model support.
//!
//! Parses the entire Dalvik vocabulary (objects, arrays, thin-locks, Math,
//! Exceptions) and maps it cleanly to the optimized 24-byte Instruction union.
//! Leverages Zig 0.16 strict memory/slice APIs for safety and performance.

const std = @import("std");
const instmod = @import("instruction");
const Instruction = instmod.Instruction;
const Invoke = instmod.Invoke;
const InvokeKind = instmod.InvokeKind;

pub const MethodInfo = struct {
    class_name: []const u8,
    method_name: []const u8,
    signature: []const u8,
};

pub const FieldInfo = struct {
    class_name: []const u8,
    type_name: []const u8,
    field_name: []const u8,
};

pub const DexMethod = struct {
    name: []const u8,
    registers_size: u16,
    ins_size: u16,
    outs_size: u16,
    is_static: bool,
    signature: []const u8,
    code_off: usize,
    tries: []const instmod.TryBlock = &.{},
};

pub const KotlinMetadata = struct {
    kind: u32,
    metadata_version: []const u32,
    data1: []const []const u8,
    data2: []const []const u8,
    package_name: ?[]const u8 = null,
};

pub const DexClass = struct {
    name: []const u8,
    super_class_idx: u32,
    methods: std.ArrayList(DexMethod),
    static_field_indices: std.ArrayList(u32),
    kotlin_metadata: ?KotlinMetadata = null,
};

pub const DexFile = struct {
    classes: std.ArrayList(DexClass),
    bytes: []const u8,
    method_items: []const MethodInfo,
    field_items: []const FieldInfo,
    /// type_idx → class name (L-prefix stripped), e.g. "java/lang/String".
    type_names: []const []const u8,
    string_pool: [][]const u8,
    arena: std.mem.Allocator,

    pub fn findMethod(self: *const DexFile, class_name: []const u8, method_name: []const u8) ?DexMethod {
        for (self.classes.items) |class| {
            if (!std.mem.eql(u8, class.name, class_name)) continue;
            for (class.methods.items) |m| {
                const arrow = std.mem.indexOf(u8, m.name, "->") orelse continue;
                if (std.mem.eql(u8, m.name[arrow + 2 ..], method_name)) return m;
            }
        }
        return null;
    }

    pub fn decodeMethod(self: *const DexFile, allocator: std.mem.Allocator, method: DexMethod) ![]Instruction {
        return decodeBytecode(allocator, self.bytes, method.code_off, self.method_items, self.string_pool);
    }
};

// ── Instruction width lookup table (256-byte LUT, avoids fat switch) ─────────
// Each entry is the width in u16 code units for that opcode.
pub const INSN_WIDTH: [256]u8 = blk: {
    var lut = [_]u8{1} ** 256;
    // 1-unit opcodes (already defaulted)
    // 2-unit opcodes
    for ([_]u8{
        0x02, 0x05, 0x08, 0x13, 0x15, 0x16, 0x19, 0x1a, 0x1c, 0x1f, 0x20,
        0x22, 0x23, 0x29, 0x2d, 0x2e, 0x2f, 0x30, 0x31, 0x32, 0x33, 0x34,
        0x35, 0x36, 0x37, 0x38, 0x39, 0x3a, 0x3b, 0x3c, 0x3d, 0x44, 0x45,
        0x46, 0x47, 0x48, 0x49, 0x4a, 0x4b, 0x4c, 0x4d, 0x4e, 0x4f, 0x50,
        0x51, 0x52, 0x53, 0x54, 0x55, 0x56, 0x57, 0x58, 0x59, 0x5a, 0x5b,
        0x5c, 0x5d, 0x5e, 0x5f, 0x60, 0x61, 0x62, 0x63, 0x64, 0x65, 0x66,
        0x67, 0x68, 0x69, 0x6a, 0x6b, 0x6c, 0x6d, 0x90, 0x91, 0x92, 0x93,
        0x94, 0x95, 0x96, 0x97, 0x98, 0x99, 0x9a, 0x9b, 0x9c, 0x9d, 0x9e,
        0x9f, 0xa0, 0xa1, 0xa2, 0xa3, 0xa4, 0xa5, 0xa6, 0xa7, 0xa8, 0xa9,
        0xaa, 0xab, 0xac, 0xad, 0xae, 0xaf,
        // 0xb0..0xcf are /2addr (12x) = 1 unit — NOT listed here
        0xd0, 0xd1, 0xd2, 0xd3, 0xd4,
        0xd5, 0xd6, 0xd7, 0xd8, 0xd9, 0xda, 0xdb, 0xdc, 0xdd, 0xde, 0xdf,
        0xe0, 0xe1, 0xe2, 0xfe, 0xff,
    }) |op| lut[op] = 2;

    // 3-unit opcodes
    for ([_]u8{
        0x03, 0x06, 0x09, 0x14, 0x17, 0x1b, 0x24, 0x25, 0x26, 0x2a, 0x2b,
        0x2c, 0x6e, 0x6f, 0x70, 0x71, 0x72, 0x74, 0x75, 0x76, 0x77, 0x78,
        0xfc, 0xfd,
    }) |op| lut[op] = 3;
    // 4-unit opcodes
    lut[0xfa] = 4;
    lut[0xfb] = 4;
    // 5-unit opcodes
    lut[0x18] = 5;
    break :blk lut;
};

// ── Zero-copy string reads ────────────────────────────────────────────────────
inline fn u32At(bytes: []const u8, offset: usize) u32 {
    return std.mem.readInt(u32, bytes[offset..][0..4], .little);
}

inline fn u16At(bytes: []const u8, offset: usize) u16 {
    return std.mem.readInt(u16, bytes[offset..][0..2], .little);
}

fn readUleb128(bytes: []const u8, cursor: *usize) u32 {
    var value: u32 = 0;
    var shift: u5 = 0;
    while (true) {
        const b = bytes[cursor.*];
        cursor.* += 1;
        value |= (@as(u32, b & 0x7F)) << shift;
        if (b & 0x80 == 0) break;
        shift += 7;
    }
    return value;
}

fn readSleb128(bytes: []const u8, cursor: *usize) i32 {
    var result: i32 = 0;
    var shift: u5 = 0;
    var byte: u8 = 0;
    while (true) {
        byte = bytes[cursor.*];
        cursor.* += 1;
        result |= @as(i32, byte & 0x7f) << shift;
        shift += 7;
        if ((byte & 0x80) == 0) {
            break;
        }
    }
    if (shift < 32 and (byte & 0x40) != 0) {
        result |= -(@as(i32, 1) << shift);
    }
    return result;
}

pub const ParseError = error{
    FileTooSmall,
    InvalidMagic,
    StringIndexOutOfBounds,
    TypeIndexOutOfBounds,
    OutOfMemory,
};

fn readStringZeroCopy(bytes: []const u8, string_ids_off: usize, string_ids_size: usize, str_idx: usize) error{StringIndexOutOfBounds}![]const u8 {
    if (str_idx >= string_ids_size) return error.StringIndexOutOfBounds;
    const data_off: usize = u32At(bytes, string_ids_off + str_idx * 4);
    var cursor: usize = data_off;
    while (true) {
        const b = bytes[cursor];
        cursor += 1;
        if (b & 0x80 == 0) break;
    }
    var end = cursor;
    while (bytes[end] != 0) {
        end += 1;
    }
    return bytes[cursor..end];
}

fn stripTypePrefix(name: []const u8) []const u8 {
    if (name.len >= 2 and name[0] == 'L' and name[name.len - 1] == ';') {
        return name[1 .. name.len - 1];
    }
    return name;
}

const EncodedValue = union(enum) {
    int: u64,
    string: []const u8,
    array: []const EncodedValue,
    boolean: bool,
    other: void,
};

fn parseEncodedValue(bytes: []const u8, cursor: *usize, arena: std.mem.Allocator, string_pool: [][]const u8) anyerror!EncodedValue {
    const val_type_arg = bytes[cursor.*];
    cursor.* += 1;
    const val_type = val_type_arg & 0x1f;
    const val_arg = val_type_arg >> 5;

    switch (val_type) {
        0x00...0x07 => { // Byte, Short, Char, Int, Long, Float, Double
            const len = val_arg + 1;
            var val: u64 = 0;
            for (0..len) |j| {
                val |= @as(u64, bytes[cursor.* + j]) << @intCast(j * 8);
            }
            cursor.* += len;
            return .{ .int = val };
        },
        0x17 => { // String
            const len = val_arg + 1;
            var idx: usize = 0;
            for (0..len) |j| {
                idx |= @as(usize, bytes[cursor.* + j]) << @intCast(j * 8);
            }
            cursor.* += len;
            return .{ .string = if (idx < string_pool.len) string_pool[idx] else "" };
        },
        0x1c => { // Array
            const size = readUleb128(bytes, cursor);
            var arr = try arena.alloc(EncodedValue, size);
            for (0..size) |j| {
                arr[j] = try parseEncodedValue(bytes, cursor, arena, string_pool);
            }
            return .{ .array = arr };
        },
        0x1f => { // Boolean
            return .{ .boolean = val_arg != 0 };
        },
        else => {
            const len = val_arg + 1;
            cursor.* += len;
            return .other;
        }
    }
}

fn extractKotlinMetadata(
    arena: std.mem.Allocator,
    bytes: []const u8,
    annotations_off: usize,
    string_pool: [][]const u8,
    type_names: []const []const u8,
    string_ids_off: usize,
    string_ids_size: usize,
) !?KotlinMetadata {
    if (annotations_off == 0) return null;
    if (annotations_off >= bytes.len) return null;

    const class_annotations_off = u32At(bytes, annotations_off);
    if (class_annotations_off == 0 or class_annotations_off >= bytes.len) return null;

    const size = u32At(bytes, class_annotations_off);
    for (0..size) |i| {
        const ann_off = u32At(bytes, class_annotations_off + 4 + i * 4);
        if (ann_off == 0 or ann_off >= bytes.len) continue;

        var cursor: usize = ann_off;
        _ = bytes[cursor]; // visibility
        cursor += 1;

        const type_idx = readUleb128(bytes, &cursor);
        if (type_idx >= type_names.len) continue;

        const type_name = type_names[type_idx];
        if (std.mem.eql(u8, type_name, "kotlin/Metadata")) {
            const pair_size = readUleb128(bytes, &cursor);
            
            var kind: u32 = 0;
            var mv: []const u32 = &.{};
            var d1: []const []const u8 = &.{};
            var d2: []const []const u8 = &.{};
            var pn: ?[]const u8 = null;

            for (0..pair_size) |_| {
                const name_idx = readUleb128(bytes, &cursor);
                const name = try readStringZeroCopy(bytes, string_ids_off, string_ids_size, name_idx);
                const val = try parseEncodedValue(bytes, &cursor, arena, string_pool);

                if (std.mem.eql(u8, name, "k")) {
                    if (val == .int) {
                        kind = @intCast(val.int);
                    }
                } else if (std.mem.eql(u8, name, "mv")) {
                    if (val == .array) {
                        var mv_arr = try arena.alloc(u32, val.array.len);
                        for (val.array, 0..) |v, j| {
                            mv_arr[j] = if (v == .int) @intCast(v.int) else 0;
                        }
                        mv = mv_arr;
                    }
                } else if (std.mem.eql(u8, name, "d1")) {
                    if (val == .array) {
                        var d1_arr = try arena.alloc([]const u8, val.array.len);
                        for (val.array, 0..) |v, j| {
                            d1_arr[j] = if (v == .string) v.string else "";
                        }
                        d1 = d1_arr;
                    }
                } else if (std.mem.eql(u8, name, "d2")) {
                    if (val == .array) {
                        var d2_arr = try arena.alloc([]const u8, val.array.len);
                        for (val.array, 0..) |v, j| {
                            d2_arr[j] = if (v == .string) v.string else "";
                        }
                        d2 = d2_arr;
                    }
                } else if (std.mem.eql(u8, name, "pn")) {
                    if (val == .string) {
                        pn = val.string;
                    }
                }
            }

            return KotlinMetadata{
                .kind = kind,
                .metadata_version = mv,
                .data1 = d1,
                .data2 = d2,
                .package_name = pn,
            };
        }
    }

    return null;
}

pub fn parse(arena: std.mem.Allocator, bytes: []const u8) !DexFile {
    if (bytes.len < 0x70) return error.FileTooSmall;
    if (!std.mem.eql(u8, bytes[0..3], "dex")) return error.InvalidMagic;

    const string_ids_size: usize = u32At(bytes, 0x38);
    const string_ids_off: usize = u32At(bytes, 0x3c);
    const type_ids_size: usize = u32At(bytes, 0x40);
    const type_ids_off: usize = u32At(bytes, 0x44);
    const proto_ids_off: usize = u32At(bytes, 0x4c);
    const field_ids_size: usize = u32At(bytes, 0x50);
    const field_ids_off: usize = u32At(bytes, 0x54);
    const method_ids_size: usize = u32At(bytes, 0x58);
    const method_ids_off: usize = u32At(bytes, 0x5c);
    const class_defs_size: usize = u32At(bytes, 0x60);
    const class_defs_off: usize = u32At(bytes, 0x64);

    const string_pool = try arena.alloc([]const u8, string_ids_size);
    for (0..string_ids_size) |i| {
        string_pool[i] = try readStringZeroCopy(bytes, string_ids_off, string_ids_size, i);
    }

    const readTypeName = struct {
        fn f(b: []const u8, sio: usize, sis: usize, tio: usize, tis: usize, type_idx: usize) ![]const u8 {
            if (type_idx >= tis) return error.TypeIndexOutOfBounds;
            const str_idx: usize = u32At(b, tio + type_idx * 4);
            return readStringZeroCopy(b, sio, sis, str_idx);
        }
    }.f;

    const method_items = try arena.alloc(MethodInfo, method_ids_size);
    for (0..method_ids_size) |i| {
        const off = method_ids_off + i * 8;
        const class_idx: usize = u16At(bytes, off);
        const proto_idx: usize = u16At(bytes, off + 2);
        const name_idx: usize = u32At(bytes, off + 4);

        const class_name_raw = try readTypeName(bytes, string_ids_off, string_ids_size, type_ids_off, type_ids_size, class_idx);
        const method_name = try readStringZeroCopy(bytes, string_ids_off, string_ids_size, name_idx);

        const proto_off = proto_ids_off + proto_idx * 12;
        const shorty_idx: usize = u32At(bytes, proto_off);
        const signature = try readStringZeroCopy(bytes, string_ids_off, string_ids_size, shorty_idx);

        method_items[i] = .{
            .class_name = stripTypePrefix(class_name_raw),
            .method_name = method_name,
            .signature = signature,
        };
    }

    const type_names = try arena.alloc([]const u8, type_ids_size);
    for (0..type_ids_size) |i| {
        const raw = try readTypeName(bytes, string_ids_off, string_ids_size, type_ids_off, type_ids_size, i);
        type_names[i] = stripTypePrefix(raw);
    }

    const field_items = try arena.alloc(FieldInfo, field_ids_size);
    for (0..field_ids_size) |i| {
        const off = field_ids_off + i * 8;
        const class_idx: usize = u16At(bytes, off);
        const type_idx: usize = u16At(bytes, off + 2);
        const name_idx: usize = u32At(bytes, off + 4);

        const class_name_raw = try readTypeName(bytes, string_ids_off, string_ids_size, type_ids_off, type_ids_size, class_idx);
        const type_name_raw = try readTypeName(bytes, string_ids_off, string_ids_size, type_ids_off, type_ids_size, type_idx);
        const field_name = try readStringZeroCopy(bytes, string_ids_off, string_ids_size, name_idx);

        field_items[i] = .{
            .class_name = stripTypePrefix(class_name_raw),
            .type_name = stripTypePrefix(type_name_raw),
            .field_name = field_name,
        };
    }

    var classes = std.ArrayList(DexClass).empty;

    for (0..class_defs_size) |i| {
        const class_def_off = class_defs_off + i * 32;
        const class_idx: usize = u32At(bytes, class_def_off);
        const class_name_raw = try readTypeName(bytes, string_ids_off, string_ids_size, type_ids_off, type_ids_size, class_idx);
        const class_data_off: usize = u32At(bytes, class_def_off + 24);
        if (class_data_off == 0) continue;

        var cursor = class_data_off;
        const static_fields_size = readUleb128(bytes, &cursor);
        const instance_fields_size = readUleb128(bytes, &cursor);
        const direct_methods_size = readUleb128(bytes, &cursor);
        const virtual_methods_size = readUleb128(bytes, &cursor);

        var static_field_indices = try std.ArrayList(u32).initCapacity(arena, static_fields_size);
        var fidx: u32 = 0;
        for (0..static_fields_size) |_| {
            fidx += readUleb128(bytes, &cursor);
            _ = readUleb128(bytes, &cursor); // access_flags
            static_field_indices.appendAssumeCapacity(fidx);
        }
        for (0..instance_fields_size) |_| {
            _ = readUleb128(bytes, &cursor);
            _ = readUleb128(bytes, &cursor);
        }

        const total_methods = direct_methods_size + virtual_methods_size;
        var methods = try std.ArrayList(DexMethod).initCapacity(arena, total_methods);

        var method_idx: u32 = 0;
        for (0..direct_methods_size) |_| {
            method_idx += readUleb128(bytes, &cursor);
            const access_flags = readUleb128(bytes, &cursor);
            const code_off: usize = readUleb128(bytes, &cursor);
            if (code_off > 0) {
                methods.appendAssumeCapacity(readMethod(arena, bytes, method_items[method_idx], access_flags, code_off));
            }
        }

        var virtual_method_idx: u32 = 0;
        for (0..virtual_methods_size) |_| {
            virtual_method_idx += readUleb128(bytes, &cursor);
            const access_flags = readUleb128(bytes, &cursor);
            const code_off: usize = readUleb128(bytes, &cursor);
            if (code_off > 0) {
                methods.appendAssumeCapacity(readMethod(arena, bytes, method_items[virtual_method_idx], access_flags, code_off));
            }
        }

        const super_class_idx: u32 = u32At(bytes, class_def_off + 8);
        const annotations_off: usize = u32At(bytes, class_def_off + 20);
        const kotlin_meta = try extractKotlinMetadata(
            arena,
            bytes,
            annotations_off,
            string_pool,
            type_names,
            string_ids_off,
            string_ids_size,
        );

        try classes.append(arena, .{
            .name = stripTypePrefix(class_name_raw),
            .super_class_idx = super_class_idx,
            .methods = methods,
            .static_field_indices = static_field_indices,
            .kotlin_metadata = kotlin_meta,
        });
    }

    return .{
        .classes = classes,
        .bytes = bytes,
        .method_items = method_items,
        .field_items = field_items,
        .type_names = type_names,
        .string_pool = string_pool,
        .arena = arena,
    };
}

fn readTries(
    arena: std.mem.Allocator,
    bytes: []const u8,
    code_off: usize,
) ![]const instmod.TryBlock {
    const tries_size = u16At(bytes, code_off + 6);
    if (tries_size == 0) return &.{};

    const insns_size = u32At(bytes, code_off + 12);
    var tries_start = code_off + 16 + insns_size * 2;
    if ((insns_size & 1) != 0) {
        tries_start += 2;
    }

    const handlers_start = tries_start + tries_size * 8;
    const tries = try arena.alloc(instmod.TryBlock, tries_size);

    for (0..tries_size) |i| {
        const try_off = tries_start + i * 8;
        const start_addr = u32At(bytes, try_off);
        const insn_count = u16At(bytes, try_off + 4);
        const handler_off = u16At(bytes, try_off + 6);

        var cursor = handlers_start + handler_off;
        const size_val = readSleb128(bytes, &cursor);
        const abs_size = @abs(size_val);

        const handlers_count = abs_size + (if (size_val <= 0) @as(usize, 1) else @as(usize, 0));
        const handlers = try arena.alloc(instmod.CatchHandler, handlers_count);

        for (0..abs_size) |j| {
            const type_idx = readUleb128(bytes, &cursor);
            const addr = readUleb128(bytes, &cursor);
            handlers[j] = .{
                .type_idx = @intCast(type_idx),
                .target_pc = @intCast(addr),
            };
        }

        if (size_val <= 0) {
            const catch_all_addr = readUleb128(bytes, &cursor);
            handlers[abs_size] = .{
                .type_idx = null,
                .target_pc = @intCast(catch_all_addr),
            };
        }

        tries[i] = .{
            .start_pc = start_addr,
            .end_pc = start_addr + insn_count,
            .handlers = handlers,
        };
    }

    return tries;
}

fn readMethod(arena: std.mem.Allocator, bytes: []const u8, info: MethodInfo, access_flags: u32, code_off: usize) DexMethod {
    const name = std.fmt.allocPrint(arena, "{s}->{s}", .{ info.class_name, info.method_name }) catch info.method_name;
    return .{
        .name = name,
        .registers_size = u16At(bytes, code_off),
        .ins_size = u16At(bytes, code_off + 2),
        .outs_size = u16At(bytes, code_off + 4),
        .is_static = (access_flags & 0x0008) != 0,
        .signature = info.signature,
        .code_off = code_off,
        .tries = readTries(arena, bytes, code_off) catch &.{},
    };
}

// ── Instruction decoding ──────────────────────────────────────────────────────

const BranchEntry = struct { idx: u32, target_pc: u32 };
const BranchKind = enum { goto_, if_eq, if_ne, if_lt, if_ge, if_gt, if_le, if_eqz, if_nez, if_ltz, if_gez, if_gtz, if_lez };
const PendingBranch = struct { entry: BranchEntry, kind: BranchKind, src1: u16, src2: u16 };
const PendingSwitch = struct { idx: u32, target_pcs: []u32, is_packed: bool };

const PACKED_SWITCH_PAYLOAD: u16 = 0x0100;
const SPARSE_SWITCH_PAYLOAD: u16 = 0x0200;
const FILL_ARRAY_DATA_PAYLOAD: u16 = 0x0300;

fn readPayloadElem(words: []const u16, k: usize, width: usize) i64 {
    var v: u64 = 0;
    const byte_off = k * width;
    for (0..width) |bi| {
        const j = byte_off + bi;
        const w = words[j / 2];
        const b: u8 = if (j % 2 == 0) @truncate(w) else @truncate(w >> 8);
        v |= @as(u64, b) << @intCast(8 * bi);
    }
    return switch (width) {
        1 => @as(i8, @bitCast(@as(u8, @truncate(v)))),
        2 => @as(i16, @bitCast(@as(u16, @truncate(v)))),
        4 => @as(i32, @bitCast(@as(u32, @truncate(v)))),
        else => @bitCast(v),
    };
}

const PcIdx = struct { pc: u32, idx: u32 };
fn bsearchPc(map: []const PcIdx, target_pc: u32) ?u32 {
    var lo: usize = 0;
    var hi: usize = map.len;
    while (lo < hi) {
        const mid = lo + (hi - lo) / 2;
        if (map[mid].pc == target_pc) return map[mid].idx;
        if (map[mid].pc < target_pc) lo = mid + 1 else hi = mid;
    }
    return null;
}

inline fn decode35cArgs(buf: *[5]u16, regs_word: u16, code_unit: u16, arg_count: usize) []const u16 {
    buf.* = .{
        regs_word & 0xF,
        (regs_word >> 4) & 0xF,
        (regs_word >> 8) & 0xF,
        (regs_word >> 12) & 0xF,
        (code_unit >> 8) & 0xF,
    };
    return buf[0..@min(arg_count, 5)];
}

pub const DecodeError = error{ UnsupportedOpcode, BadBranchTarget, TruncatedInstruction, OutOfMemory };
fn decodeBytecode(
    allocator: std.mem.Allocator,
    bytes: []const u8,
    code_off: usize,
    method_items: []const MethodInfo,
    string_pool: [][]const u8,
) ![]Instruction {
    _ = string_pool;
    const insns_size: usize = u32At(bytes, code_off + 12);
    if (insns_size == 0) return &.{};

    const insns = try allocator.alloc(u16, insns_size);
    defer allocator.free(insns);
    for (0..insns_size) |j| insns[j] = u16At(bytes, code_off + 16 + j * 2);

    const out = try allocator.alloc(Instruction, insns_size);
    errdefer allocator.free(out);

    const pc_map = try allocator.alloc(PcIdx, insns_size);
    defer allocator.free(pc_map);

    const pending = try allocator.alloc(PendingBranch, insns_size);
    defer allocator.free(pending);

    const pending_sw = try allocator.alloc(PendingSwitch, insns_size);
    defer allocator.free(pending_sw);

    var n_out: u32 = 0;
    var n_map: u32 = 0;
    var n_pending: u32 = 0;
    var n_pending_sw: u32 = 0;
    var pc: usize = 0;

    while (pc < insns.len) {
        const current_pc: u32 = @intCast(pc);
        const cu = insns[pc];
        const opcode: u8 = @truncate(cu & 0xFF);
        const width: usize = INSN_WIDTH[opcode];

        if (opcode == 0x00 and cu != 0x0000) {
            const skip: usize = switch (cu) {
                PACKED_SWITCH_PAYLOAD => blk: {
                    if (pc + 2 > insns.len) return error.TruncatedInstruction;
                    break :blk @as(usize, insns[pc + 1]) * 2 + 4;
                },
                SPARSE_SWITCH_PAYLOAD => blk: {
                    if (pc + 2 > insns.len) return error.TruncatedInstruction;
                    break :blk @as(usize, insns[pc + 1]) * 4 + 2;
                },
                FILL_ARRAY_DATA_PAYLOAD => blk: {
                    if (pc + 4 > insns.len) return error.TruncatedInstruction;
                    const ew: usize = insns[pc + 1];
                    const sz: usize = @as(u32, insns[pc + 2]) | (@as(u32, insns[pc + 3]) << 16);
                    break :blk (sz * ew + 1) / 2 + 4;
                },
                else => 1,
            };
            pc += skip;
            continue;
        }

        // Guard: every multi-word decode case below reads insns[pc+1 .. pc+width].
        if (pc + width > insns.len) return error.TruncatedInstruction;

        pc_map[n_map] = .{ .pc = current_pc, .idx = n_out };
        n_map += 1;

        const inst: Instruction = switch (opcode) {
            0x00 => .nop,

            0x01 => .{ .move = .{ .dest = (cu >> 8) & 0xF, .src = (cu >> 12) & 0xF } },
            0x02 => .{ .move = .{ .dest = (cu >> 8) & 0xFF, .src = insns[pc + 1] } },
            0x03 => .{ .move = .{ .dest = insns[pc + 1], .src = insns[pc + 2] } },
            0x04 => .{ .move_wide = .{ .dest = (cu >> 8) & 0xF, .src = (cu >> 12) & 0xF } },
            0x05 => .{ .move_wide = .{ .dest = (cu >> 8) & 0xFF, .src = insns[pc + 1] } },
            0x06 => .{ .move_wide = .{ .dest = insns[pc + 1], .src = insns[pc + 2] } },
            0x07 => .{ .move_object = .{ .dest = (cu >> 8) & 0xF, .src = (cu >> 12) & 0xF } },
            0x08 => .{ .move_object = .{ .dest = (cu >> 8) & 0xFF, .src = insns[pc + 1] } },
            0x09 => .{ .move_object = .{ .dest = insns[pc + 1], .src = insns[pc + 2] } },
            0x0a => .{ .move_result = .{ .dest = (cu >> 8) & 0xFF } },
            0x0b => .{ .move_result_wide = .{ .dest = (cu >> 8) & 0xFF } },
            0x0c => .{ .move_result_object = .{ .dest = (cu >> 8) & 0xFF } },
            0x0d => .{ .move_exception = .{ .dest = (cu >> 8) & 0xFF } },

            0x0e => .return_void,
            0x0f => .{ .return_ = .{ .src = (cu >> 8) & 0xFF } },
            0x10 => .{ .return_wide = .{ .src = (cu >> 8) & 0xFF } },
            0x11 => .{ .return_object = .{ .src = (cu >> 8) & 0xFF } },

            0x12 => blk: {
                var raw_lit: i8 = @intCast((cu >> 12) & 0xF);
                if (raw_lit & 8 != 0) raw_lit |= -16;
                break :blk .{ .const_ = .{ .dest = (cu >> 8) & 0xF, .value = raw_lit } };
            },
            0x13 => .{ .const_ = .{ .dest = (cu >> 8) & 0xFF, .value = @as(i16, @bitCast(insns[pc + 1])) } },
            0x14 => .{ .const_ = .{ .dest = (cu >> 8) & 0xFF, .value = @bitCast(@as(u32, insns[pc + 1]) | (@as(u32, insns[pc + 2]) << 16)) } },
            0x15 => .{ .const_ = .{ .dest = (cu >> 8) & 0xFF, .value = @bitCast(@as(u32, insns[pc + 1]) << 16) } },
            0x16 => .{ .const_wide = .{ .dest = (cu >> 8) & 0xFF, .value = @as(i16, @bitCast(insns[pc + 1])) } },
            0x17 => .{ .const_wide = .{ .dest = (cu >> 8) & 0xFF, .value = @as(i32, @bitCast(@as(u32, insns[pc + 1]) | (@as(u32, insns[pc + 2]) << 16))) } },
            0x18 => blk: {
                const lo: u64 = @as(u32, insns[pc + 1]) | (@as(u32, insns[pc + 2]) << 16);
                const hi: u64 = @as(u32, insns[pc + 3]) | (@as(u32, insns[pc + 4]) << 16);
                break :blk .{ .const_wide = .{ .dest = (cu >> 8) & 0xFF, .value = @bitCast(lo | (hi << 32)) } };
            },
            0x19 => .{ .const_wide = .{ .dest = (cu >> 8) & 0xFF, .value = @bitCast(@as(u64, insns[pc + 1]) << 48) } },
            0x1a => .{ .const_string = .{ .dest = (cu >> 8) & 0xFF, .index = insns[pc + 1] } },
            0x1b => .{ .const_string = .{ .dest = (cu >> 8) & 0xFF, .index = @as(u32, insns[pc + 1]) | (@as(u32, insns[pc + 2]) << 16) } },
            0x1c => .{ .const_class = .{ .dest = (cu >> 8) & 0xFF, .type_idx = insns[pc + 1] } },

            0x1d => .{ .monitor_enter = .{ .src = (cu >> 8) & 0xFF } },
            0x1e => .{ .monitor_exit = .{ .src = (cu >> 8) & 0xFF } },
            0x1f => .{ .check_cast = .{ .src = (cu >> 8) & 0xFF, .type_idx = insns[pc + 1] } },
            0x20 => .{ .instance_of = .{ .dest = (cu >> 8) & 0xF, .src = (cu >> 12) & 0xF, .type_idx = insns[pc + 1] } },
            0x21 => .{ .array_length = .{ .dest = (cu >> 8) & 0xF, .array = (cu >> 12) & 0xF } },
            0x22 => .{ .new_instance = .{ .dest = (cu >> 8) & 0xFF, .type_idx = insns[pc + 1] } },
            0x23 => .{ .new_array = .{ .dest = (cu >> 8) & 0xF, .size = (cu >> 12) & 0xF, .type_idx = insns[pc + 1] } },

            0x24 => blk: {
                const arg_count: usize = (cu >> 12) & 0xF;
                const type_idx: u32 = insns[pc + 1];
                var five_buf: [5]u16 = undefined;
                const args = try allocator.dupe(u16, decode35cArgs(&five_buf, insns[pc + 2], cu, arg_count));
                break :blk .{ .filled_new_array = .{ .args = args, .type_idx = type_idx } };
            },
            0x25 => blk: {
                const arg_count: usize = (cu >> 8) & 0xFF;
                const type_idx: u32 = insns[pc + 1];
                const reg_c = insns[pc + 2];
                const args = try allocator.alloc(u16, arg_count);
                for (0..arg_count) |k| args[k] = reg_c + @as(u16, @intCast(k));
                break :blk .{ .filled_new_array = .{ .args = args, .type_idx = type_idx } };
            },
            0x26 => blk: {
                const payload_off: i32 = @bitCast(@as(u32, insns[pc + 1]) | (@as(u32, insns[pc + 2]) << 16));
                const arr_reg: u16 = (cu >> 8) & 0xFF;
                const ppc: i64 = @as(i64, current_pc) + payload_off;
                if (ppc >= 0 and @as(usize, @intCast(ppc)) + 4 <= insns.len) {
                    const p: usize = @intCast(ppc);
                    if (insns[p] == FILL_ARRAY_DATA_PAYLOAD) {
                        const elem_width: usize = insns[p + 1];
                        const size: usize = @as(u32, insns[p + 2]) | (@as(u32, insns[p + 3]) << 16);
                        const data_words = (size * elem_width + 1) / 2;
                        const width_ok = elem_width == 1 or elem_width == 2 or elem_width == 4 or elem_width == 8;
                        if (width_ok and p + 4 + data_words <= insns.len) {
                            const data = try allocator.alloc(i64, size);
                            for (0..size) |k| {
                                data[k] = readPayloadElem(insns[p + 4 ..], k, elem_width);
                            }
                            break :blk .{ .fill_array_data = .{ .array = arr_reg, .payload_offset = payload_off, .data = data } };
                        }
                    }
                }
                break :blk .{ .fill_array_data = .{ .array = arr_reg, .payload_offset = payload_off } };
            },

            0x27 => .{ .throw_ = .{ .src = (cu >> 8) & 0xFF } },

            0x28 => blk: {
                const offset8: i32 = @as(i8, @bitCast(@as(u8, @truncate(cu >> 8))));
                const target: u32 = @intCast(@as(i32, @intCast(current_pc)) + offset8);
                pending[n_pending] = .{ .entry = .{ .idx = n_out, .target_pc = target }, .kind = .goto_, .src1 = 0, .src2 = 0 };
                n_pending += 1;
                break :blk .{ .goto_ = .{ .offset = 0 } };
            },
            0x29 => blk: {
                const offset16: i32 = @as(i16, @bitCast(insns[pc + 1]));
                const target: u32 = @intCast(@as(i32, @intCast(current_pc)) + offset16);
                pending[n_pending] = .{ .entry = .{ .idx = n_out, .target_pc = target }, .kind = .goto_, .src1 = 0, .src2 = 0 };
                n_pending += 1;
                break :blk .{ .goto_ = .{ .offset = 0 } };
            },
            0x2a => blk: {
                const payload_off: i32 = @bitCast(@as(u32, insns[pc + 1]) | (@as(u32, insns[pc + 2]) << 16));
                const src: u16 = (cu >> 8) & 0xFF;
                const ppc: i64 = @as(i64, current_pc) + payload_off;
                if (ppc >= 0 and @as(usize, @intCast(ppc)) + 4 <= insns.len) {
                    const p: usize = @intCast(ppc);
                    if (insns[p] == PACKED_SWITCH_PAYLOAD) {
                        const size: usize = insns[p + 1];
                        if (p + 4 + size * 2 <= insns.len) {
                            const first_key: i32 = @bitCast(@as(u32, insns[p + 2]) | (@as(u32, insns[p + 3]) << 16));
                            const keys = try allocator.alloc(i32, size);
                            const tpcs = try allocator.alloc(u32, size);
                            for (0..size) |k| {
                                keys[k] = first_key +% @as(i32, @intCast(k));
                                const rel: i32 = @bitCast(@as(u32, insns[p + 4 + k * 2]) | (@as(u32, insns[p + 5 + k * 2]) << 16));
                                tpcs[k] = @intCast(@as(i32, @intCast(current_pc)) + rel);
                            }
                            pending_sw[n_pending_sw] = .{ .idx = n_out, .target_pcs = tpcs, .is_packed = true };
                            n_pending_sw += 1;
                            break :blk .{ .packed_switch = .{ .src = src, .payload_offset = payload_off, .keys = keys } };
                        }
                    }
                }
                break :blk .{ .packed_switch = .{ .src = src, .payload_offset = payload_off } };
            },
            0x2b => blk: {
                const payload_off: i32 = @bitCast(@as(u32, insns[pc + 1]) | (@as(u32, insns[pc + 2]) << 16));
                const src: u16 = (cu >> 8) & 0xFF;
                const ppc: i64 = @as(i64, current_pc) + payload_off;
                if (ppc >= 0 and @as(usize, @intCast(ppc)) + 2 <= insns.len) {
                    const p: usize = @intCast(ppc);
                    if (insns[p] == SPARSE_SWITCH_PAYLOAD) {
                        const size: usize = insns[p + 1];
                        if (p + 2 + size * 4 <= insns.len) {
                            const keys = try allocator.alloc(i32, size);
                            const tpcs = try allocator.alloc(u32, size);
                            const keys_base = p + 2;
                            const targets_base = keys_base + size * 2;
                            for (0..size) |k| {
                                keys[k] = @bitCast(@as(u32, insns[keys_base + k * 2]) | (@as(u32, insns[keys_base + k * 2 + 1]) << 16));
                                const rel: i32 = @bitCast(@as(u32, insns[targets_base + k * 2]) | (@as(u32, insns[targets_base + k * 2 + 1]) << 16));
                                tpcs[k] = @intCast(@as(i32, @intCast(current_pc)) + rel);
                            }
                            pending_sw[n_pending_sw] = .{ .idx = n_out, .target_pcs = tpcs, .is_packed = false };
                            n_pending_sw += 1;
                            break :blk .{ .sparse_switch = .{ .src = src, .payload_offset = payload_off, .keys = keys } };
                        }
                    }
                }
                break :blk .{ .sparse_switch = .{ .src = src, .payload_offset = payload_off } };
            },

            0x2d...0x31 => blk: {
                const a: u16 = (cu >> 8) & 0xFF;
                const b: u16 = insns[pc + 1] & 0xFF;
                const c: u16 = insns[pc + 1] >> 8;
                const op = instmod.CmpOp{ .dest = a, .src1 = b, .src2 = c };
                break :blk switch (opcode) {
                    0x2d => .{ .cmpl_float = op },
                    0x2e => .{ .cmpg_float = op },
                    0x2f => .{ .cmpl_double = op },
                    0x30 => .{ .cmpg_double = op },
                    0x31 => .{ .cmp_long = op },
                    else => unreachable,
                };
            },

            0x32...0x37 => blk: {
                const target: u32 = @intCast(@as(i32, @intCast(current_pc)) + @as(i32, @as(i16, @bitCast(insns[pc + 1]))));
                const kind: BranchKind = switch (opcode) {
                    0x32 => .if_eq,
                    0x33 => .if_ne,
                    0x34 => .if_lt,
                    0x35 => .if_ge,
                    0x36 => .if_gt,
                    0x37 => .if_le,
                    else => unreachable,
                };
                pending[n_pending] = .{ .entry = .{ .idx = n_out, .target_pc = target }, .kind = kind, .src1 = (cu >> 8) & 0xF, .src2 = (cu >> 12) & 0xF };
                n_pending += 1;
                break :blk .{ .if_eq = .{ .src1 = 0, .src2 = 0, .offset = 0 } };
            },

            0x38...0x3d => blk: {
                const target: u32 = @intCast(@as(i32, @intCast(current_pc)) + @as(i32, @as(i16, @bitCast(insns[pc + 1]))));
                const kind: BranchKind = switch (opcode) {
                    0x38 => .if_eqz,
                    0x39 => .if_nez,
                    0x3a => .if_ltz,
                    0x3b => .if_gez,
                    0x3c => .if_gtz,
                    0x3d => .if_lez,
                    else => unreachable,
                };
                pending[n_pending] = .{ .entry = .{ .idx = n_out, .target_pc = target }, .kind = kind, .src1 = (cu >> 8) & 0xFF, .src2 = 0 };
                n_pending += 1;
                break :blk .{ .if_eqz = .{ .src = 0, .offset = 0 } };
            },

            0x44...0x51 => blk: {
                const a: u16 = (cu >> 8) & 0xFF;
                const b: u16 = insns[pc + 1] & 0xFF;
                const c: u16 = insns[pc + 1] >> 8;
                const op_s = instmod.ArrayOp{ .dest_or_src = a, .array = b, .index = c };
                const is_put = opcode >= 0x4b;
                const variant = opcode - if (is_put) @as(u8, 0x4b) else @as(u8, 0x44);
                break :blk if (is_put) switch (variant) {
                    0 => .{ .aput = op_s },
                    1 => .{ .aput_wide = op_s },
                    2 => .{ .aput_object = op_s },
                    3 => .{ .aput_boolean = op_s },
                    4 => .{ .aput_byte = op_s },
                    5 => .{ .aput_char = op_s },
                    6 => .{ .aput_short = op_s },
                    else => unreachable,
                } else switch (variant) {
                    0 => .{ .aget = op_s },
                    1 => .{ .aget_wide = op_s },
                    2 => .{ .aget_object = op_s },
                    3 => .{ .aget_boolean = op_s },
                    4 => .{ .aget_byte = op_s },
                    5 => .{ .aget_char = op_s },
                    6 => .{ .aget_short = op_s },
                    else => unreachable,
                };
            },

            0x52...0x5f => blk: {
                const a: u16 = (cu >> 8) & 0xF;
                const b: u16 = (cu >> 12) & 0xF;
                const c: u32 = insns[pc + 1];
                const op_s = instmod.FieldOp{ .dest_or_src = a, .obj = b, .field_idx = c };
                const is_put = opcode >= 0x59;
                const variant = opcode - if (is_put) @as(u8, 0x59) else @as(u8, 0x52);
                break :blk if (is_put) switch (variant) {
                    0 => .{ .iput = op_s },
                    1 => .{ .iput_wide = op_s },
                    2 => .{ .iput_object = op_s },
                    3 => .{ .iput_boolean = op_s },
                    4 => .{ .iput_byte = op_s },
                    5 => .{ .iput_char = op_s },
                    6 => .{ .iput_short = op_s },
                    else => unreachable,
                } else switch (variant) {
                    0 => .{ .iget = op_s },
                    1 => .{ .iget_wide = op_s },
                    2 => .{ .iget_object = op_s },
                    3 => .{ .iget_boolean = op_s },
                    4 => .{ .iget_byte = op_s },
                    5 => .{ .iget_char = op_s },
                    6 => .{ .iget_short = op_s },
                    else => unreachable,
                };
            },

            0x60...0x6d => blk: {
                const a: u16 = (cu >> 8) & 0xFF;
                const b: u32 = insns[pc + 1];
                const op_s = instmod.StaticFieldOp{ .dest_or_src = a, .field_idx = b };
                const is_put = opcode >= 0x67;
                const variant = opcode - if (is_put) @as(u8, 0x67) else @as(u8, 0x60);
                break :blk if (is_put) switch (variant) {
                    0 => .{ .sput = op_s },
                    1 => .{ .sput_wide = op_s },
                    2 => .{ .sput_object = op_s },
                    3 => .{ .sput_boolean = op_s },
                    4 => .{ .sput_byte = op_s },
                    5 => .{ .sput_char = op_s },
                    6 => .{ .sput_short = op_s },
                    else => unreachable,
                } else switch (variant) {
                    0 => .{ .sget = op_s },
                    1 => .{ .sget_wide = op_s },
                    2 => .{ .sget_object = op_s },
                    3 => .{ .sget_boolean = op_s },
                    4 => .{ .sget_byte = op_s },
                    5 => .{ .sget_char = op_s },
                    6 => .{ .sget_short = op_s },
                    else => unreachable,
                };
            },

            0x6e...0x78 => blk: {
                const is_range = opcode >= 0x74;
                const arg_count: usize = if (is_range) (cu >> 8) & 0xFF else (cu >> 12) & 0xF;
                const method_idx: usize = insns[pc + 1];

                var five_buf: [5]u16 = undefined;
                const args: []const u16 = if (is_range) args_blk: {
                    const reg_c = insns[pc + 2];
                    if (arg_count <= 5) {
                        for (0..arg_count) |k| five_buf[k] = reg_c + @as(u16, @intCast(k));
                        break :args_blk try allocator.dupe(u16, five_buf[0..arg_count]);
                    } else {
                        var range_buf = try allocator.alloc(u16, arg_count);
                        for (0..arg_count) |k| range_buf[k] = reg_c + @as(u16, @intCast(k));
                        break :args_blk range_buf;
                    }
                } else try allocator.dupe(u16, decode35cArgs(&five_buf, insns[pc + 2], cu, arg_count));

                const info = if (method_idx < method_items.len) method_items[method_idx] else MethodInfo{ .class_name = "", .method_name = "", .signature = "" };
                const base_op: u8 = if (is_range) opcode - 6 else opcode;
                const kind: InvokeKind = switch (base_op) {
                    0x6e => .virtual,
                    0x6f => .super,
                    0x70 => .direct,
                    0x71 => .static,
                    0x72 => .interface,
                    else => return error.UnsupportedOpcode,
                };

                const invoke_ptr = try allocator.create(Invoke);
                invoke_ptr.* = .{
                    .kind = kind,
                    .dest = null,
                    .class_name = info.class_name,
                    .method_name = info.method_name,
                    .signature = info.signature,
                    .args = args,
                    .method_idx = @intCast(method_idx),
                    .is_self_call = false,
                    .call_target = null,
                    .native_target = null,
                };
                break :blk .{ .invoke = invoke_ptr };
            },

            0xfa, 0xfb => blk: {
                const is_range = opcode == 0xfb;
                const arg_count: usize = if (is_range) (cu >> 8) & 0xFF else (cu >> 12) & 0xF;
                const method_idx: usize = insns[pc + 1];

                var five_buf: [5]u16 = undefined;
                const args: []const u16 = if (is_range) args_blk: {
                    const reg_c = insns[pc + 2];
                    if (arg_count <= 5) {
                        for (0..arg_count) |k| five_buf[k] = reg_c + @as(u16, @intCast(k));
                        break :args_blk try allocator.dupe(u16, five_buf[0..arg_count]);
                    } else {
                        var range_buf = try allocator.alloc(u16, arg_count);
                        for (0..arg_count) |k| range_buf[k] = reg_c + @as(u16, @intCast(k));
                        break :args_blk range_buf;
                    }
                } else try allocator.dupe(u16, decode35cArgs(&five_buf, insns[pc + 2], cu, arg_count));

                const info = if (method_idx < method_items.len) method_items[method_idx] else MethodInfo{ .class_name = "", .method_name = "", .signature = "" };
                const invoke_ptr = try allocator.create(Invoke);
                invoke_ptr.* = .{
                    .kind = .polymorphic,
                    .dest = null,
                    .class_name = info.class_name,
                    .method_name = info.method_name,
                    .signature = info.signature,
                    .args = args,
                    .method_idx = @intCast(method_idx),
                    .is_self_call = false,
                    .call_target = null,
                    .native_target = null,
                };
                break :blk .{ .invoke = invoke_ptr };
            },

            0xfc, 0xfd => blk: {
                const is_range = opcode == 0xfd;
                const arg_count: usize = if (is_range) (cu >> 8) & 0xFF else (cu >> 12) & 0xF;
                var five_buf: [5]u16 = undefined;
                const args: []const u16 = if (is_range) args_blk: {
                    const reg_c = insns[pc + 2];
                    if (arg_count <= 5) {
                        for (0..arg_count) |k| five_buf[k] = reg_c + @as(u16, @intCast(k));
                        break :args_blk try allocator.dupe(u16, five_buf[0..arg_count]);
                    } else {
                        var range_buf = try allocator.alloc(u16, arg_count);
                        for (0..arg_count) |k| range_buf[k] = reg_c + @as(u16, @intCast(k));
                        break :args_blk range_buf;
                    }
                } else try allocator.dupe(u16, decode35cArgs(&five_buf, insns[pc + 2], cu, arg_count));

                const invoke_ptr = try allocator.create(Invoke);
                invoke_ptr.* = .{
                    .kind = .custom,
                    .dest = null,
                    .class_name = "",
                    .method_name = "",
                    .signature = "",
                    .args = args,
                    .is_self_call = false,
                    .call_target = null,
                    .native_target = null,
                };
                break :blk .{ .invoke = invoke_ptr };
            },

            0xfe => .{ .const_method_handle = .{ .dest = (cu >> 8) & 0xFF, .index = insns[pc + 1] } },
            0xff => .{ .const_method_type = .{ .dest = (cu >> 8) & 0xFF, .index = insns[pc + 1] } },

            0x7b...0x8f => blk: {
                const a: u16 = (cu >> 8) & 0xF;
                const b: u16 = (cu >> 12) & 0xF;
                const op = instmod.UnOp{ .dest = a, .src = b };
                break :blk switch (opcode) {
                    0x7b => .{ .neg_int = op },
                    0x7c => .{ .not_int = op },
                    0x7d => .{ .neg_long = op },
                    0x7e => .{ .not_long = op },
                    0x7f => .{ .neg_float = op },
                    0x80 => .{ .neg_double = op },
                    0x81 => .{ .int_to_long = op },
                    0x82 => .{ .int_to_float = op },
                    0x83 => .{ .int_to_double = op },
                    0x84 => .{ .long_to_int = op },
                    0x85 => .{ .long_to_float = op },
                    0x86 => .{ .long_to_double = op },
                    0x87 => .{ .float_to_int = op },
                    0x88 => .{ .float_to_long = op },
                    0x89 => .{ .float_to_double = op },
                    0x8a => .{ .double_to_int = op },
                    0x8b => .{ .double_to_long = op },
                    0x8c => .{ .double_to_float = op },
                    0x8d => .{ .int_to_byte = op },
                    0x8e => .{ .int_to_char = op },
                    0x8f => .{ .int_to_short = op },
                    else => unreachable,
                };
            },

            0x90...0xaf => blk: {
                const a: u16 = (cu >> 8) & 0xFF;
                const b: u16 = insns[pc + 1] & 0xFF;
                const c: u16 = insns[pc + 1] >> 8;
                const op = instmod.BinOp{ .dest = a, .src1 = b, .src2 = c };
                break :blk switch (opcode - 0x90) {
                    0 => .{ .add_int = op },
                    1 => .{ .sub_int = op },
                    2 => .{ .mul_int = op },
                    3 => .{ .div_int = op },
                    4 => .{ .rem_int = op },
                    5 => .{ .and_int = op },
                    6 => .{ .or_int = op },
                    7 => .{ .xor_int = op },
                    8 => .{ .shl_int = op },
                    9 => .{ .shr_int = op },
                    10 => .{ .ushr_int = op },
                    11 => .{ .add_long = op },
                    12 => .{ .sub_long = op },
                    13 => .{ .mul_long = op },
                    14 => .{ .div_long = op },
                    15 => .{ .rem_long = op },
                    16 => .{ .and_long = op },
                    17 => .{ .or_long = op },
                    18 => .{ .xor_long = op },
                    19 => .{ .shl_long = op },
                    20 => .{ .shr_long = op },
                    21 => .{ .ushr_long = op },
                    22 => .{ .add_float = op },
                    23 => .{ .sub_float = op },
                    24 => .{ .mul_float = op },
                    25 => .{ .div_float = op },
                    26 => .{ .rem_float = op },
                    27 => .{ .add_double = op },
                    28 => .{ .sub_double = op },
                    29 => .{ .mul_double = op },
                    30 => .{ .div_double = op },
                    31 => .{ .rem_double = op },
                    else => unreachable,
                };
            },

            0xb0...0xcf => blk: {
                const a: u16 = (cu >> 8) & 0xF;
                const b: u16 = (cu >> 12) & 0xF;
                const op = instmod.BinOp{ .dest = a, .src1 = a, .src2 = b };
                break :blk switch (opcode - 0xb0) {
                    0 => .{ .add_int = op },
                    1 => .{ .sub_int = op },
                    2 => .{ .mul_int = op },
                    3 => .{ .div_int = op },
                    4 => .{ .rem_int = op },
                    5 => .{ .and_int = op },
                    6 => .{ .or_int = op },
                    7 => .{ .xor_int = op },
                    8 => .{ .shl_int = op },
                    9 => .{ .shr_int = op },
                    10 => .{ .ushr_int = op },
                    11 => .{ .add_long = op },
                    12 => .{ .sub_long = op },
                    13 => .{ .mul_long = op },
                    14 => .{ .div_long = op },
                    15 => .{ .rem_long = op },
                    16 => .{ .and_long = op },
                    17 => .{ .or_long = op },
                    18 => .{ .xor_long = op },
                    19 => .{ .shl_long = op },
                    20 => .{ .shr_long = op },
                    21 => .{ .ushr_long = op },
                    22 => .{ .add_float = op },
                    23 => .{ .sub_float = op },
                    24 => .{ .mul_float = op },
                    25 => .{ .div_float = op },
                    26 => .{ .rem_float = op },
                    27 => .{ .add_double = op },
                    28 => .{ .sub_double = op },
                    29 => .{ .mul_double = op },
                    30 => .{ .div_double = op },
                    31 => .{ .rem_double = op },
                    else => unreachable,
                };
            },

            0xd0...0xd7 => blk: {
                const a: u16 = (cu >> 8) & 0xF;
                const b: u16 = (cu >> 12) & 0xF;
                const c: i16 = @bitCast(insns[pc + 1]);
                const op = instmod.Lit16Op{ .dest = a, .src = b, .lit = c };
                break :blk switch (opcode) {
                    0xd0 => .{ .add_int_lit16 = op },
                    0xd1 => .{ .rsub_int_lit16 = op },
                    0xd2 => .{ .mul_int_lit16 = op },
                    0xd3 => .{ .div_int_lit16 = op },
                    0xd4 => .{ .rem_int_lit16 = op },
                    0xd5 => .{ .and_int_lit16 = op },
                    0xd6 => .{ .or_int_lit16 = op },
                    0xd7 => .{ .xor_int_lit16 = op },
                    else => unreachable,
                };
            },

            0xd8...0xe2 => blk: {
                const a: u16 = (cu >> 8) & 0xFF;
                const b: u16 = insns[pc + 1] & 0xFF;
                const c: i8 = @bitCast(@as(u8, @truncate(insns[pc + 1] >> 8)));
                const op = instmod.LitOp{ .dest = a, .src = b, .lit = c };
                break :blk switch (opcode) {
                    0xd8 => .{ .add_int_lit8 = op },
                    0xd9 => .{ .rsub_int_lit8 = op },
                    0xda => .{ .mul_int_lit8 = op },
                    0xdb => .{ .div_int_lit8 = op },
                    0xdc => .{ .rem_int_lit8 = op },
                    0xdd => .{ .and_int_lit8 = op },
                    0xde => .{ .or_int_lit8 = op },
                    0xdf => .{ .xor_int_lit8 = op },
                    0xe0 => .{ .shl_int_lit8 = op },
                    0xe1 => .{ .shr_int_lit8 = op },
                    0xe2 => .{ .ushr_int_lit8 = op },
                    else => return error.UnsupportedOpcode,
                };
            },
            else => return error.UnsupportedOpcode,
        };

        out[n_out] = inst;
        n_out += 1;
        pc += width;
    }

    const final = try allocator.realloc(out, n_out);
    const map = pc_map[0..n_map];
    for (pending[0..n_pending]) |p| {
        const target_idx = bsearchPc(map, p.entry.target_pc) orelse return error.BadBranchTarget;
        const offset: i32 = @as(i32, @intCast(target_idx)) - @as(i32, @intCast(p.entry.idx));
        final[p.entry.idx] = switch (p.kind) {
            .goto_ => .{ .goto_ = .{ .offset = offset } },
            .if_eq => .{ .if_eq = .{ .src1 = p.src1, .src2 = p.src2, .offset = offset } },
            .if_ne => .{ .if_ne = .{ .src1 = p.src1, .src2 = p.src2, .offset = offset } },
            .if_lt => .{ .if_lt = .{ .src1 = p.src1, .src2 = p.src2, .offset = offset } },
            .if_ge => .{ .if_ge = .{ .src1 = p.src1, .src2 = p.src2, .offset = offset } },
            .if_gt => .{ .if_gt = .{ .src1 = p.src1, .src2 = p.src2, .offset = offset } },
            .if_le => .{ .if_le = .{ .src1 = p.src1, .src2 = p.src2, .offset = offset } },
            .if_eqz => .{ .if_eqz = .{ .src = p.src1, .offset = offset } },
            .if_nez => .{ .if_nez = .{ .src = p.src1, .offset = offset } },
            .if_ltz => .{ .if_ltz = .{ .src = p.src1, .offset = offset } },
            .if_gez => .{ .if_gez = .{ .src = p.src1, .offset = offset } },
            .if_gtz => .{ .if_gtz = .{ .src = p.src1, .offset = offset } },
            .if_lez => .{ .if_lez = .{ .src = p.src1, .offset = offset } },
        };
    }

    for (pending_sw[0..n_pending_sw]) |ps| {
        const toffs = try allocator.alloc(i32, ps.target_pcs.len);
        for (ps.target_pcs, 0..) |tpc, k| {
            const tidx = bsearchPc(map, tpc) orelse return error.BadBranchTarget;
            toffs[k] = @as(i32, @intCast(tidx)) - @as(i32, @intCast(ps.idx));
        }
        allocator.free(ps.target_pcs);
        if (ps.is_packed) {
            final[ps.idx].packed_switch.targets = toffs;
        } else {
            final[ps.idx].sparse_switch.targets = toffs;
        }
    }
    return final;
}

test "decode moves and nop" {
    const allocator = std.testing.allocator;

    const code_units = [_]u16{
        0x0000, // nop
        0x4301, // move
        0x5602, 0x1234, // move/from16
        0x0003, 0x1234, 0x5678, // move/16
        0x6504, // move_wide
        0x7805, 0x2345, // move_wide/from16
        0x0006, 0x2345, 0x6789, // move_wide/16
        0x8707, // move_object
        0x9a08, 0x3456, // move_object/from16
        0x0009, 0x3456, 0x789a, // move_object/16
        0xde0a, // move_result
        0xef0b, // move_result_wide
        0xfa0c, // move_result_object
        0xfb0d, // move_exception
    };

    var bytes: [16 + code_units.len * 2]u8 = undefined;
    std.mem.writeInt(u16, bytes[0..2], 0, .little);
    std.mem.writeInt(u16, bytes[2..4], 0, .little);
    std.mem.writeInt(u16, bytes[4..6], 0, .little);
    std.mem.writeInt(u16, bytes[6..8], 0, .little);
    std.mem.writeInt(u32, bytes[8..12], 0, .little);
    std.mem.writeInt(u32, bytes[12..16], code_units.len, .little);
    for (code_units, 0..) |unit, idx| {
        std.mem.writeInt(u16, bytes[16 + idx * 2 ..][0..2], unit, .little);
    }

    const decoded = try decodeBytecode(allocator, &bytes, 0, &.{}, &.{});
    defer allocator.free(decoded);

    try std.testing.expectEqual(@as(usize, 14), decoded.len);
    try std.testing.expect(decoded[0] == .nop);

    try std.testing.expectEqual(Instruction{ .move = .{ .dest = 3, .src = 4 } }, decoded[1]);
    try std.testing.expectEqual(Instruction{ .move = .{ .dest = 0x56, .src = 0x1234 } }, decoded[2]);
    try std.testing.expectEqual(Instruction{ .move = .{ .dest = 0x1234, .src = 0x5678 } }, decoded[3]);

    try std.testing.expectEqual(Instruction{ .move_wide = .{ .dest = 5, .src = 6 } }, decoded[4]);
    try std.testing.expectEqual(Instruction{ .move_wide = .{ .dest = 0x78, .src = 0x2345 } }, decoded[5]);
    try std.testing.expectEqual(Instruction{ .move_wide = .{ .dest = 0x2345, .src = 0x6789 } }, decoded[6]);

    try std.testing.expectEqual(Instruction{ .move_object = .{ .dest = 7, .src = 8 } }, decoded[7]);
    try std.testing.expectEqual(Instruction{ .move_object = .{ .dest = 0x9a, .src = 0x3456 } }, decoded[8]);
    try std.testing.expectEqual(Instruction{ .move_object = .{ .dest = 0x3456, .src = 0x789a } }, decoded[9]);

    try std.testing.expectEqual(Instruction{ .move_result = .{ .dest = 0xde } }, decoded[10]);
    try std.testing.expectEqual(Instruction{ .move_result_wide = .{ .dest = 0xef } }, decoded[11]);
    try std.testing.expectEqual(Instruction{ .move_result_object = .{ .dest = 0xfa } }, decoded[12]);
    try std.testing.expectEqual(Instruction{ .move_exception = .{ .dest = 0xfb } }, decoded[13]);
}

test "decode returns" {
    const allocator = std.testing.allocator;

    const code_units = [_]u16{
        0x000e, // return-void
        0x120f, // return
        0x3410, // return_wide
        0x5611, // return_object
    };

    var bytes: [16 + code_units.len * 2]u8 = undefined;
    std.mem.writeInt(u16, bytes[0..2], 0, .little);
    std.mem.writeInt(u16, bytes[2..4], 0, .little);
    std.mem.writeInt(u16, bytes[4..6], 0, .little);
    std.mem.writeInt(u16, bytes[6..8], 0, .little);
    std.mem.writeInt(u32, bytes[8..12], 0, .little);
    std.mem.writeInt(u32, bytes[12..16], code_units.len, .little);
    for (code_units, 0..) |unit, idx| {
        std.mem.writeInt(u16, bytes[16 + idx * 2 ..][0..2], unit, .little);
    }

    const decoded = try decodeBytecode(allocator, &bytes, 0, &.{}, &.{});
    defer allocator.free(decoded);

    try std.testing.expectEqual(@as(usize, 4), decoded.len);
    try std.testing.expect(decoded[0] == .return_void);
    try std.testing.expectEqual(Instruction{ .return_ = .{ .src = 0x12 } }, decoded[1]);
    try std.testing.expectEqual(Instruction{ .return_wide = .{ .src = 0x34 } }, decoded[2]);
    try std.testing.expectEqual(Instruction{ .return_object = .{ .src = 0x56 } }, decoded[3]);
}

test "decode constants" {
    const allocator = std.testing.allocator;

    const code_units = [_]u16{
        0x4312, // const/4 v3, 4
        0xf312, // const/4 v3, -1
        0x5613, 0x8000, // const/16 v86, -32768
        0x7814, 0x3456, 0x1200, // const v120, 0x12003456
        0x9a15, 0x1234, // const/high16 v154, 0x12340000
        0xbc16, 0x8000, // const-wide/16 v188, -32768
        0xde17, 0x3456, 0x1200, // const-wide/32 v222, 0x12003456
        0xf018, 0x1111, 0x2222, 0x3333, 0x4444, // const-wide v240, 0x4444333322221111
        0x1219, 0x5555, // const-wide/high16 v18, 0x5555000000000000
        0x341a, 0x7890, // const-string v52, string@0x7890
        0x561b, 0x5678, 0x1234, // const-string/jumbo v86, string@0x12345678
        0x781c, 0xabcd, // const-class v120, class@0xabcd
        0x9afe, 0xcdef, // const-method-handle v154, handle@0xcdef
        0xbcff, 0xface, // const-method-type v188, type@0xface
    };

    var bytes: [16 + code_units.len * 2]u8 = undefined;
    std.mem.writeInt(u16, bytes[0..2], 0, .little);
    std.mem.writeInt(u16, bytes[2..4], 0, .little);
    std.mem.writeInt(u16, bytes[4..6], 0, .little);
    std.mem.writeInt(u16, bytes[6..8], 0, .little);
    std.mem.writeInt(u32, bytes[8..12], 0, .little);
    std.mem.writeInt(u32, bytes[12..16], code_units.len, .little);
    for (code_units, 0..) |unit, idx| {
        std.mem.writeInt(u16, bytes[16 + idx * 2 ..][0..2], unit, .little);
    }

    const decoded = try decodeBytecode(allocator, &bytes, 0, &.{}, &.{});
    defer allocator.free(decoded);

    try std.testing.expectEqual(@as(usize, 14), decoded.len);

    try std.testing.expectEqual(Instruction{ .const_ = .{ .dest = 3, .value = 4 } }, decoded[0]);
    try std.testing.expectEqual(Instruction{ .const_ = .{ .dest = 3, .value = -1 } }, decoded[1]);
    try std.testing.expectEqual(Instruction{ .const_ = .{ .dest = 0x56, .value = -32768 } }, decoded[2]);
    try std.testing.expectEqual(Instruction{ .const_ = .{ .dest = 0x78, .value = 0x12003456 } }, decoded[3]);
    try std.testing.expectEqual(Instruction{ .const_ = .{ .dest = 0x9a, .value = 0x12340000 } }, decoded[4]);

    try std.testing.expectEqual(Instruction{ .const_wide = .{ .dest = 0xbc, .value = -32768 } }, decoded[5]);
    try std.testing.expectEqual(Instruction{ .const_wide = .{ .dest = 0xde, .value = 0x12003456 } }, decoded[6]);
    try std.testing.expectEqual(Instruction{ .const_wide = .{ .dest = 0xf0, .value = 0x4444333322221111 } }, decoded[7]);
    try std.testing.expectEqual(Instruction{ .const_wide = .{ .dest = 0x12, .value = 0x5555000000000000 } }, decoded[8]);

    try std.testing.expectEqual(Instruction{ .const_string = .{ .dest = 0x34, .index = 0x7890 } }, decoded[9]);
    try std.testing.expectEqual(Instruction{ .const_string = .{ .dest = 0x56, .index = 0x12345678 } }, decoded[10]);
    try std.testing.expectEqual(Instruction{ .const_class = .{ .dest = 0x78, .type_idx = 0xabcd } }, decoded[11]);
    try std.testing.expectEqual(Instruction{ .const_method_handle = .{ .dest = 0x9a, .index = 0xcdef } }, decoded[12]);
    try std.testing.expectEqual(Instruction{ .const_method_type = .{ .dest = 0xbc, .index = 0xface } }, decoded[13]);
}

test "decode monitors and check casts" {
    const allocator = std.testing.allocator;

    const code_units = [_]u16{
        0x121d, // monitor-enter
        0x341e, // monitor-exit
        0x561f, 0xabcd, // check-cast
        0x8720, 0xcdef, // instance-of
    };

    var bytes: [16 + code_units.len * 2]u8 = undefined;
    std.mem.writeInt(u16, bytes[0..2], 0, .little);
    std.mem.writeInt(u16, bytes[2..4], 0, .little);
    std.mem.writeInt(u16, bytes[4..6], 0, .little);
    std.mem.writeInt(u16, bytes[6..8], 0, .little);
    std.mem.writeInt(u32, bytes[8..12], 0, .little);
    std.mem.writeInt(u32, bytes[12..16], code_units.len, .little);
    for (code_units, 0..) |unit, idx| {
        std.mem.writeInt(u16, bytes[16 + idx * 2 ..][0..2], unit, .little);
    }

    const decoded = try decodeBytecode(allocator, &bytes, 0, &.{}, &.{});
    defer allocator.free(decoded);

    try std.testing.expectEqual(@as(usize, 4), decoded.len);
    try std.testing.expectEqual(Instruction{ .monitor_enter = .{ .src = 0x12 } }, decoded[0]);
    try std.testing.expectEqual(Instruction{ .monitor_exit = .{ .src = 0x34 } }, decoded[1]);
    try std.testing.expectEqual(Instruction{ .check_cast = .{ .src = 0x56, .type_idx = 0xabcd } }, decoded[2]);
    try std.testing.expectEqual(Instruction{ .instance_of = .{ .dest = 7, .src = 8, .type_idx = 0xcdef } }, decoded[3]);
}

test "decode arrays and exceptions" {
    const allocator = std.testing.allocator;

    const code_units = [_]u16{
        0x4321, 
        0x5622, 0xabcd, 
        0x8723, 0xcdef, 
        0x3024, 0x1234, 0x4321, 
        0x0425, 0x5678, 0x0010, 
        0x1226, 0x0006, 0x0000, 
        0x9927, 
        0x0000,
        0x0000,
        0x0300,
        2,
        3, 0,
        0x1000, 0x2000, 0x3000,
    };

    var bytes: [16 + code_units.len * 2]u8 = undefined;
    std.mem.writeInt(u16, bytes[0..2], 0, .little);
    std.mem.writeInt(u16, bytes[2..4], 0, .little);
    std.mem.writeInt(u16, bytes[4..6], 0, .little);
    std.mem.writeInt(u16, bytes[6..8], 0, .little);
    std.mem.writeInt(u32, bytes[8..12], 0, .little);
    std.mem.writeInt(u32, bytes[12..16], code_units.len, .little);
    for (code_units, 0..) |unit, idx| {
        std.mem.writeInt(u16, bytes[16 + idx * 2 ..][0..2], unit, .little);
    }

    const decoded = try decodeBytecode(allocator, &bytes, 0, &.{}, &.{});
    defer {
        for (decoded) |ins| {
            switch (ins) {
                .filled_new_array => |op| allocator.free(op.args),
                .fill_array_data => |op| {
                    if (op.data.len > 0) allocator.free(op.data);
                },
                else => {},
            }
        }
        allocator.free(decoded);
    }

    try std.testing.expectEqual(@as(usize, 9), decoded.len);
    try std.testing.expectEqual(Instruction{ .array_length = .{ .dest = 3, .array = 4 } }, decoded[0]);
    try std.testing.expectEqual(Instruction{ .new_instance = .{ .dest = 0x56, .type_idx = 0xabcd } }, decoded[1]);
    try std.testing.expectEqual(Instruction{ .new_array = .{ .dest = 7, .size = 8, .type_idx = 0xcdef } }, decoded[2]);

    try std.testing.expectEqual(@as(u32, 0x1234), decoded[3].filled_new_array.type_idx);
    try std.testing.expectEqualSlices(u16, &[_]u16{ 1, 2, 3 }, decoded[3].filled_new_array.args);

    try std.testing.expectEqual(@as(u32, 0x5678), decoded[4].filled_new_array.type_idx);
    try std.testing.expectEqualSlices(u16, &[_]u16{ 16, 17, 18, 19 }, decoded[4].filled_new_array.args);

    try std.testing.expectEqual(@as(u16, 0x12), decoded[5].fill_array_data.array);
    try std.testing.expectEqual(@as(i32, 6), decoded[5].fill_array_data.payload_offset);
    try std.testing.expectEqualSlices(i64, &[_]i64{ 0x1000, 0x2000, 0x3000 }, decoded[5].fill_array_data.data);

    try std.testing.expectEqual(Instruction{ .throw_ = .{ .src = 0x99 } }, decoded[6]);
    try std.testing.expect(decoded[7] == .nop);
    try std.testing.expect(decoded[8] == .nop);
}

test "decode gotos" {
    const allocator = std.testing.allocator;

    const code_units = [_]u16{
        0x0328, // goto +3
        0x0000, // nop
        0x0000, // nop
        0x0000, // nop
        0x0029, 0xfffd, // goto/16 -3
    };

    var bytes: [16 + code_units.len * 2]u8 = undefined;
    std.mem.writeInt(u16, bytes[0..2], 0, .little);
    std.mem.writeInt(u16, bytes[2..4], 0, .little);
    std.mem.writeInt(u16, bytes[4..6], 0, .little);
    std.mem.writeInt(u16, bytes[6..8], 0, .little);
    std.mem.writeInt(u32, bytes[8..12], 0, .little);
    std.mem.writeInt(u32, bytes[12..16], code_units.len, .little);
    for (code_units, 0..) |unit, idx| {
        std.mem.writeInt(u16, bytes[16 + idx * 2 ..][0..2], unit, .little);
    }

    const decoded = try decodeBytecode(allocator, &bytes, 0, &.{}, &.{});
    defer allocator.free(decoded);

    try std.testing.expectEqual(@as(usize, 5), decoded.len);
    try std.testing.expectEqual(Instruction{ .goto_ = .{ .offset = 3 } }, decoded[0]);
    try std.testing.expect(decoded[1] == .nop);
    try std.testing.expect(decoded[2] == .nop);
    try std.testing.expect(decoded[3] == .nop);
    try std.testing.expectEqual(Instruction{ .goto_ = .{ .offset = -3 } }, decoded[4]);
}

test "decode switches" {
    const allocator = std.testing.allocator;

    const code_units = [_]u16{
        0x052a, 0x0005, 0x0000, // packed_switch
        0x0000, // nop
        0x0000, // nop
        0x0100, // PACKED_SWITCH_PAYLOAD
        2,      // size
        10, 0,  // first_key
        3, 0,   // target 0 offset relative to switch PC
        4, 0,   // target 1 offset relative to switch PC
    };

    var bytes: [16 + code_units.len * 2]u8 = undefined;
    std.mem.writeInt(u16, bytes[0..2], 0, .little);
    std.mem.writeInt(u16, bytes[2..4], 0, .little);
    std.mem.writeInt(u16, bytes[4..6], 0, .little);
    std.mem.writeInt(u16, bytes[6..8], 0, .little);
    std.mem.writeInt(u32, bytes[8..12], 0, .little);
    std.mem.writeInt(u32, bytes[12..16], code_units.len, .little);
    for (code_units, 0..) |unit, idx| {
        std.mem.writeInt(u16, bytes[16 + idx * 2 ..][0..2], unit, .little);
    }

    const decoded = try decodeBytecode(allocator, &bytes, 0, &.{}, &.{});
    defer {
        for (decoded) |ins| {
            switch (ins) {
                .packed_switch => |op| {
                    if (op.keys.len > 0) allocator.free(op.keys);
                    if (op.targets.len > 0) allocator.free(op.targets);
                },
                else => {},
            }
        }
        allocator.free(decoded);
    }

    try std.testing.expectEqual(@as(usize, 3), decoded.len);
    try std.testing.expectEqual(@as(u16, 5), decoded[0].packed_switch.src);
    try std.testing.expectEqual(@as(i32, 5), decoded[0].packed_switch.payload_offset);
    try std.testing.expectEqualSlices(i32, &[_]i32{ 10, 11 }, decoded[0].packed_switch.keys);
    try std.testing.expectEqualSlices(i32, &[_]i32{ 1, 2 }, decoded[0].packed_switch.targets);

    const code_units_sparse = [_]u16{
        0x062b, 0x0005, 0x0000, // sparse_switch
        0x0000, // nop
        0x0000, // nop
        0x0200, // SPARSE_SWITCH_PAYLOAD
        2,      // size
        20, 0,  // key 0
        30, 0,  // key 1
        3, 0,   // target 0 offset relative to switch PC
        4, 0,   // target 1 offset relative to switch PC
    };

    var bytes_sparse: [16 + code_units_sparse.len * 2]u8 = undefined;
    std.mem.writeInt(u16, bytes_sparse[0..2], 0, .little);
    std.mem.writeInt(u16, bytes_sparse[2..4], 0, .little);
    std.mem.writeInt(u16, bytes_sparse[4..6], 0, .little);
    std.mem.writeInt(u16, bytes_sparse[6..8], 0, .little);
    std.mem.writeInt(u32, bytes_sparse[8..12], 0, .little);
    std.mem.writeInt(u32, bytes_sparse[12..16], code_units_sparse.len, .little);
    for (code_units_sparse, 0..) |unit, idx| {
        std.mem.writeInt(u16, bytes_sparse[16 + idx * 2 ..][0..2], unit, .little);
    }

    const decoded_sparse = try decodeBytecode(allocator, &bytes_sparse, 0, &.{}, &.{});
    defer {
        for (decoded_sparse) |ins| {
            switch (ins) {
                .sparse_switch => |op| {
                    if (op.keys.len > 0) allocator.free(op.keys);
                    if (op.targets.len > 0) allocator.free(op.targets);
                },
                else => {},
            }
        }
        allocator.free(decoded_sparse);
    }

    try std.testing.expectEqual(@as(usize, 3), decoded_sparse.len);
    try std.testing.expectEqual(@as(u16, 6), decoded_sparse[0].sparse_switch.src);
    try std.testing.expectEqual(@as(i32, 5), decoded_sparse[0].sparse_switch.payload_offset);
    try std.testing.expectEqualSlices(i32, &[_]i32{ 20, 30 }, decoded_sparse[0].sparse_switch.keys);
    try std.testing.expectEqualSlices(i32, &[_]i32{ 1, 2 }, decoded_sparse[0].sparse_switch.targets);
}

test "decode comparisons" {
    const allocator = std.testing.allocator;

    const code_units = [_]u16{
        0x122d, 0x5634, // cmpl_float dest=0x12, src1=0x34, src2=0x56
        0x122e, 0x5634, // cmpg_float dest=0x12, src1=0x34, src2=0x56
        0x122f, 0x5634, // cmpl_double dest=0x12, src1=0x34, src2=0x56
        0x1230, 0x5634, // cmpg_double dest=0x12, src1=0x34, src2=0x56
        0x1231, 0x5634, // cmp_long dest=0x12, src1=0x34, src2=0x56
    };

    var bytes: [16 + code_units.len * 2]u8 = undefined;
    std.mem.writeInt(u16, bytes[0..2], 0, .little);
    std.mem.writeInt(u16, bytes[2..4], 0, .little);
    std.mem.writeInt(u16, bytes[4..6], 0, .little);
    std.mem.writeInt(u16, bytes[6..8], 0, .little);
    std.mem.writeInt(u32, bytes[8..12], 0, .little);
    std.mem.writeInt(u32, bytes[12..16], code_units.len, .little);
    for (code_units, 0..) |unit, idx| {
        std.mem.writeInt(u16, bytes[16 + idx * 2 ..][0..2], unit, .little);
    }

    const decoded = try decodeBytecode(allocator, &bytes, 0, &.{}, &.{});
    defer allocator.free(decoded);

    try std.testing.expectEqual(@as(usize, 5), decoded.len);
    try std.testing.expectEqual(Instruction{ .cmpl_float = .{ .dest = 0x12, .src1 = 0x34, .src2 = 0x56 } }, decoded[0]);
    try std.testing.expectEqual(Instruction{ .cmpg_float = .{ .dest = 0x12, .src1 = 0x34, .src2 = 0x56 } }, decoded[1]);
    try std.testing.expectEqual(Instruction{ .cmpl_double = .{ .dest = 0x12, .src1 = 0x34, .src2 = 0x56 } }, decoded[2]);
    try std.testing.expectEqual(Instruction{ .cmpg_double = .{ .dest = 0x12, .src1 = 0x34, .src2 = 0x56 } }, decoded[3]);
    try std.testing.expectEqual(Instruction{ .cmp_long = .{ .dest = 0x12, .src1 = 0x34, .src2 = 0x56 } }, decoded[4]);
}

test "decode branches" {
    const allocator = std.testing.allocator;

    const code_units = [_]u16{
        0x4332, 24, // 0: if_eq v3, v4, PC=24
        0x4333, 22, // 1: if_ne v3, v4, PC=24
        0x4334, 20, // 2: if_lt v3, v4, PC=24
        0x4335, 18, // 3: if_ge v3, v4, PC=24
        0x4336, 16, // 4: if_gt v3, v4, PC=24
        0x4337, 14, // 5: if_le v3, v4, PC=24
        0x0538, 12, // 6: if_eqz v5, PC=24
        0x0539, 10, // 7: if_nez v5, PC=24
        0x053a, 8,  // 8: if_ltz v5, PC=24
        0x053b, 6,  // 9: if_gez v5, PC=24
        0x053c, 4,  // 10: if_gtz v5, PC=24
        0x053d, 2,  // 11: if_lez v5, PC=24
        0x0000,     // 12: nop (PC=24)
    };

    var bytes: [16 + code_units.len * 2]u8 = undefined;
    std.mem.writeInt(u16, bytes[0..2], 0, .little);
    std.mem.writeInt(u16, bytes[2..4], 0, .little);
    std.mem.writeInt(u16, bytes[4..6], 0, .little);
    std.mem.writeInt(u16, bytes[6..8], 0, .little);
    std.mem.writeInt(u32, bytes[8..12], 0, .little);
    std.mem.writeInt(u32, bytes[12..16], code_units.len, .little);
    for (code_units, 0..) |unit, idx| {
        std.mem.writeInt(u16, bytes[16 + idx * 2 ..][0..2], unit, .little);
    }

    const decoded = try decodeBytecode(allocator, &bytes, 0, &.{}, &.{});
    defer allocator.free(decoded);

    try std.testing.expectEqual(@as(usize, 13), decoded.len);
    try std.testing.expectEqual(Instruction{ .if_eq = .{ .src1 = 3, .src2 = 4, .offset = 12 } }, decoded[0]);
    try std.testing.expectEqual(Instruction{ .if_ne = .{ .src1 = 3, .src2 = 4, .offset = 11 } }, decoded[1]);
    try std.testing.expectEqual(Instruction{ .if_lt = .{ .src1 = 3, .src2 = 4, .offset = 10 } }, decoded[2]);
    try std.testing.expectEqual(Instruction{ .if_ge = .{ .src1 = 3, .src2 = 4, .offset = 9 } }, decoded[3]);
    try std.testing.expectEqual(Instruction{ .if_gt = .{ .src1 = 3, .src2 = 4, .offset = 8 } }, decoded[4]);
    try std.testing.expectEqual(Instruction{ .if_le = .{ .src1 = 3, .src2 = 4, .offset = 7 } }, decoded[5]);
    try std.testing.expectEqual(Instruction{ .if_eqz = .{ .src = 5, .offset = 6 } }, decoded[6]);
    try std.testing.expectEqual(Instruction{ .if_nez = .{ .src = 5, .offset = 5 } }, decoded[7]);
    try std.testing.expectEqual(Instruction{ .if_ltz = .{ .src = 5, .offset = 4 } }, decoded[8]);
    try std.testing.expectEqual(Instruction{ .if_gez = .{ .src = 5, .offset = 3 } }, decoded[9]);
    try std.testing.expectEqual(Instruction{ .if_gtz = .{ .src = 5, .offset = 2 } }, decoded[10]);
    try std.testing.expectEqual(Instruction{ .if_lez = .{ .src = 5, .offset = 1 } }, decoded[11]);
    try std.testing.expect(decoded[12] == .nop);
}

test "decode array access" {
    const allocator = std.testing.allocator;

    const code_units = [_]u16{
        0x1244, 0x5634, // aget dest=0x12, array=0x34, index=0x56
        0x1245, 0x5634, // aget_wide
        0x1246, 0x5634, // aget_object
        0x1247, 0x5634, // aget_boolean
        0x1248, 0x5634, // aget_byte
        0x1249, 0x5634, // aget_char
        0x124a, 0x5634, // aget_short
        0x124b, 0x5634, // aput src=0x12, array=0x34, index=0x56
        0x124c, 0x5634, // aput_wide
        0x124d, 0x5634, // aput_object
        0x124e, 0x5634, // aput_boolean
        0x124f, 0x5634, // aput_byte
        0x1250, 0x5634, // aput_char
        0x1251, 0x5634, // aput_short
    };

    var bytes: [16 + code_units.len * 2]u8 = undefined;
    std.mem.writeInt(u16, bytes[0..2], 0, .little);
    std.mem.writeInt(u16, bytes[2..4], 0, .little);
    std.mem.writeInt(u16, bytes[4..6], 0, .little);
    std.mem.writeInt(u16, bytes[6..8], 0, .little);
    std.mem.writeInt(u32, bytes[8..12], 0, .little);
    std.mem.writeInt(u32, bytes[12..16], code_units.len, .little);
    for (code_units, 0..) |unit, idx| {
        std.mem.writeInt(u16, bytes[16 + idx * 2 ..][0..2], unit, .little);
    }

    const decoded = try decodeBytecode(allocator, &bytes, 0, &.{}, &.{});
    defer allocator.free(decoded);

    try std.testing.expectEqual(@as(usize, 14), decoded.len);
    const expected_op = instmod.ArrayOp{ .dest_or_src = 0x12, .array = 0x34, .index = 0x56 };
    try std.testing.expectEqual(Instruction{ .aget = expected_op }, decoded[0]);
    try std.testing.expectEqual(Instruction{ .aget_wide = expected_op }, decoded[1]);
    try std.testing.expectEqual(Instruction{ .aget_object = expected_op }, decoded[2]);
    try std.testing.expectEqual(Instruction{ .aget_boolean = expected_op }, decoded[3]);
    try std.testing.expectEqual(Instruction{ .aget_byte = expected_op }, decoded[4]);
    try std.testing.expectEqual(Instruction{ .aget_char = expected_op }, decoded[5]);
    try std.testing.expectEqual(Instruction{ .aget_short = expected_op }, decoded[6]);
    try std.testing.expectEqual(Instruction{ .aput = expected_op }, decoded[7]);
    try std.testing.expectEqual(Instruction{ .aput_wide = expected_op }, decoded[8]);
    try std.testing.expectEqual(Instruction{ .aput_object = expected_op }, decoded[9]);
    try std.testing.expectEqual(Instruction{ .aput_boolean = expected_op }, decoded[10]);
    try std.testing.expectEqual(Instruction{ .aput_byte = expected_op }, decoded[11]);
    try std.testing.expectEqual(Instruction{ .aput_char = expected_op }, decoded[12]);
    try std.testing.expectEqual(Instruction{ .aput_short = expected_op }, decoded[13]);
}

test "decode instance fields" {
    const allocator = std.testing.allocator;

    const code_units = [_]u16{
        0x4352, 0xabcd, // iget dest=3, obj=4, field_idx=0xabcd
        0x4353, 0xabcd, // iget_wide
        0x4354, 0xabcd, // iget_object
        0x4355, 0xabcd, // iget_boolean
        0x4356, 0xabcd, // iget_byte
        0x4357, 0xabcd, // iget_char
        0x4358, 0xabcd, // iget_short
        0x4359, 0xabcd, // iput src=3, obj=4, field_idx=0xabcd
        0x435a, 0xabcd, // iput_wide
        0x435b, 0xabcd, // iput_object
        0x435c, 0xabcd, // iput_boolean
        0x435d, 0xabcd, // iput_byte
        0x435e, 0xabcd, // iput_char
        0x435f, 0xabcd, // iput_short
    };

    var bytes: [16 + code_units.len * 2]u8 = undefined;
    std.mem.writeInt(u16, bytes[0..2], 0, .little);
    std.mem.writeInt(u16, bytes[2..4], 0, .little);
    std.mem.writeInt(u16, bytes[4..6], 0, .little);
    std.mem.writeInt(u16, bytes[6..8], 0, .little);
    std.mem.writeInt(u32, bytes[8..12], 0, .little);
    std.mem.writeInt(u32, bytes[12..16], code_units.len, .little);
    for (code_units, 0..) |unit, idx| {
        std.mem.writeInt(u16, bytes[16 + idx * 2 ..][0..2], unit, .little);
    }

    const decoded = try decodeBytecode(allocator, &bytes, 0, &.{}, &.{});
    defer allocator.free(decoded);

    try std.testing.expectEqual(@as(usize, 14), decoded.len);
    const expected_op = instmod.FieldOp{ .dest_or_src = 3, .obj = 4, .field_idx = 0xabcd };
    try std.testing.expectEqual(Instruction{ .iget = expected_op }, decoded[0]);
    try std.testing.expectEqual(Instruction{ .iget_wide = expected_op }, decoded[1]);
    try std.testing.expectEqual(Instruction{ .iget_object = expected_op }, decoded[2]);
    try std.testing.expectEqual(Instruction{ .iget_boolean = expected_op }, decoded[3]);
    try std.testing.expectEqual(Instruction{ .iget_byte = expected_op }, decoded[4]);
    try std.testing.expectEqual(Instruction{ .iget_char = expected_op }, decoded[5]);
    try std.testing.expectEqual(Instruction{ .iget_short = expected_op }, decoded[6]);
    try std.testing.expectEqual(Instruction{ .iput = expected_op }, decoded[7]);
    try std.testing.expectEqual(Instruction{ .iput_wide = expected_op }, decoded[8]);
    try std.testing.expectEqual(Instruction{ .iput_object = expected_op }, decoded[9]);
    try std.testing.expectEqual(Instruction{ .iput_boolean = expected_op }, decoded[10]);
    try std.testing.expectEqual(Instruction{ .iput_byte = expected_op }, decoded[11]);
    try std.testing.expectEqual(Instruction{ .iput_char = expected_op }, decoded[12]);
    try std.testing.expectEqual(Instruction{ .iput_short = expected_op }, decoded[13]);
}

test "decode static fields" {
    const allocator = std.testing.allocator;

    const code_units = [_]u16{
        0x1260, 0xabcd, // sget dest=0x12, field_idx=0xabcd
        0x1261, 0xabcd, // sget_wide
        0x1262, 0xabcd, // sget_object
        0x1263, 0xabcd, // sget_boolean
        0x1264, 0xabcd, // sget_byte
        0x1265, 0xabcd, // sget_char
        0x1266, 0xabcd, // sget_short
        0x1267, 0xabcd, // sput src=0x12, field_idx=0xabcd
        0x1268, 0xabcd, // sput_wide
        0x1269, 0xabcd, // sput_object
        0x126a, 0xabcd, // sput_boolean
        0x126b, 0xabcd, // sput_byte
        0x126c, 0xabcd, // sput_char
        0x126d, 0xabcd, // sput_short
    };

    var bytes: [16 + code_units.len * 2]u8 = undefined;
    std.mem.writeInt(u16, bytes[0..2], 0, .little);
    std.mem.writeInt(u16, bytes[2..4], 0, .little);
    std.mem.writeInt(u16, bytes[4..6], 0, .little);
    std.mem.writeInt(u16, bytes[6..8], 0, .little);
    std.mem.writeInt(u32, bytes[8..12], 0, .little);
    std.mem.writeInt(u32, bytes[12..16], code_units.len, .little);
    for (code_units, 0..) |unit, idx| {
        std.mem.writeInt(u16, bytes[16 + idx * 2 ..][0..2], unit, .little);
    }

    const decoded = try decodeBytecode(allocator, &bytes, 0, &.{}, &.{});
    defer allocator.free(decoded);

    try std.testing.expectEqual(@as(usize, 14), decoded.len);
    const expected_op = instmod.StaticFieldOp{ .dest_or_src = 0x12, .field_idx = 0xabcd };
    try std.testing.expectEqual(Instruction{ .sget = expected_op }, decoded[0]);
    try std.testing.expectEqual(Instruction{ .sget_wide = expected_op }, decoded[1]);
    try std.testing.expectEqual(Instruction{ .sget_object = expected_op }, decoded[2]);
    try std.testing.expectEqual(Instruction{ .sget_boolean = expected_op }, decoded[3]);
    try std.testing.expectEqual(Instruction{ .sget_byte = expected_op }, decoded[4]);
    try std.testing.expectEqual(Instruction{ .sget_char = expected_op }, decoded[5]);
    try std.testing.expectEqual(Instruction{ .sget_short = expected_op }, decoded[6]);
    try std.testing.expectEqual(Instruction{ .sput = expected_op }, decoded[7]);
    try std.testing.expectEqual(Instruction{ .sput_wide = expected_op }, decoded[8]);
    try std.testing.expectEqual(Instruction{ .sput_object = expected_op }, decoded[9]);
    try std.testing.expectEqual(Instruction{ .sput_boolean = expected_op }, decoded[10]);
    try std.testing.expectEqual(Instruction{ .sput_byte = expected_op }, decoded[11]);
    try std.testing.expectEqual(Instruction{ .sput_char = expected_op }, decoded[12]);
    try std.testing.expectEqual(Instruction{ .sput_short = expected_op }, decoded[13]);
}

test "decode invokes" {
    const allocator = std.testing.allocator;

    const method_items = [_]MethodInfo{
        .{
            .class_name = "java/lang/String",
            .method_name = "length",
            .signature = "()I",
        },
    };

    const code_units = [_]u16{
        0x106e, 0x0000, 0x0004, // invoke-virtual {v4}, method@0
        0x0274, 0x0000, 0x0010, // invoke-virtual/range {v16..v17}, method@0
        0x10fa, 0x0000, 0x0004, 0x0000, // invoke-polymorphic {v4}, method@0, proto@0
        0x10fc, 0x0000, 0x0004, // invoke-custom {v4}, method@0
    };

    var bytes: [16 + code_units.len * 2]u8 = undefined;
    std.mem.writeInt(u16, bytes[0..2], 0, .little);
    std.mem.writeInt(u16, bytes[2..4], 0, .little);
    std.mem.writeInt(u16, bytes[4..6], 0, .little);
    std.mem.writeInt(u16, bytes[6..8], 0, .little);
    std.mem.writeInt(u32, bytes[8..12], 0, .little);
    std.mem.writeInt(u32, bytes[12..16], code_units.len, .little);
    for (code_units, 0..) |unit, idx| {
        std.mem.writeInt(u16, bytes[16 + idx * 2 ..][0..2], unit, .little);
    }

    const decoded = try decodeBytecode(allocator, &bytes, 0, &method_items, &.{});
    defer {
        for (decoded) |ins| {
            switch (ins) {
                .invoke => |op| {
                    allocator.free(op.args);
                    allocator.destroy(op);
                },
                else => {},
            }
        }
        allocator.free(decoded);
    }

    try std.testing.expectEqual(@as(usize, 4), decoded.len);

    // 0: invoke-virtual
    try std.testing.expectEqual(InvokeKind.virtual, decoded[0].invoke.kind);
    try std.testing.expectEqualStrings("java/lang/String", decoded[0].invoke.class_name);
    try std.testing.expectEqualStrings("length", decoded[0].invoke.method_name);
    try std.testing.expectEqualStrings("()I", decoded[0].invoke.signature);
    try std.testing.expectEqualSlices(u16, &[_]u16{ 4 }, decoded[0].invoke.args);

    // 1: invoke-virtual/range
    try std.testing.expectEqual(InvokeKind.virtual, decoded[1].invoke.kind);
    try std.testing.expectEqualSlices(u16, &[_]u16{ 16, 17 }, decoded[1].invoke.args);

    // 2: invoke-polymorphic
    try std.testing.expectEqual(InvokeKind.polymorphic, decoded[2].invoke.kind);
    try std.testing.expectEqualSlices(u16, &[_]u16{ 4 }, decoded[2].invoke.args);

    // 3: invoke-custom
    try std.testing.expectEqual(InvokeKind.custom, decoded[3].invoke.kind);
    try std.testing.expectEqualSlices(u16, &[_]u16{ 4 }, decoded[3].invoke.args);
}

test "decode unary math" {
    const allocator = std.testing.allocator;

    const code_units = [_]u16{
        0x437b, // neg_int
        0x437c, // not_int
        0x437d, // neg_long
        0x437e, // not_long
        0x437f, // neg_float
        0x4380, // neg_double
        0x4381, // int_to_long
        0x4382, // int_to_float
        0x4383, // int_to_double
        0x4384, // long_to_int
        0x4385, // long_to_float
        0x4386, // long_to_double
        0x4387, // float_to_int
        0x4388, // float_to_long
        0x4389, // float_to_double
        0x438a, // double_to_int
        0x438b, // double_to_long
        0x438c, // double_to_float
        0x438d, // int_to_byte
        0x438e, // int_to_char
        0x438f, // int_to_short
    };

    var bytes: [16 + code_units.len * 2]u8 = undefined;
    std.mem.writeInt(u16, bytes[0..2], 0, .little);
    std.mem.writeInt(u16, bytes[2..4], 0, .little);
    std.mem.writeInt(u16, bytes[4..6], 0, .little);
    std.mem.writeInt(u16, bytes[6..8], 0, .little);
    std.mem.writeInt(u32, bytes[8..12], 0, .little);
    std.mem.writeInt(u32, bytes[12..16], code_units.len, .little);
    for (code_units, 0..) |unit, idx| {
        std.mem.writeInt(u16, bytes[16 + idx * 2 ..][0..2], unit, .little);
    }

    const decoded = try decodeBytecode(allocator, &bytes, 0, &.{}, &.{});
    defer allocator.free(decoded);

    try std.testing.expectEqual(@as(usize, 21), decoded.len);
    const expected_op = instmod.UnOp{ .dest = 3, .src = 4 };
    try std.testing.expectEqual(Instruction{ .neg_int = expected_op }, decoded[0]);
    try std.testing.expectEqual(Instruction{ .not_int = expected_op }, decoded[1]);
    try std.testing.expectEqual(Instruction{ .neg_long = expected_op }, decoded[2]);
    try std.testing.expectEqual(Instruction{ .not_long = expected_op }, decoded[3]);
    try std.testing.expectEqual(Instruction{ .neg_float = expected_op }, decoded[4]);
    try std.testing.expectEqual(Instruction{ .neg_double = expected_op }, decoded[5]);
    try std.testing.expectEqual(Instruction{ .int_to_long = expected_op }, decoded[6]);
    try std.testing.expectEqual(Instruction{ .int_to_float = expected_op }, decoded[7]);
    try std.testing.expectEqual(Instruction{ .int_to_double = expected_op }, decoded[8]);
    try std.testing.expectEqual(Instruction{ .long_to_int = expected_op }, decoded[9]);
    try std.testing.expectEqual(Instruction{ .long_to_float = expected_op }, decoded[10]);
    try std.testing.expectEqual(Instruction{ .long_to_double = expected_op }, decoded[11]);
    try std.testing.expectEqual(Instruction{ .float_to_int = expected_op }, decoded[12]);
    try std.testing.expectEqual(Instruction{ .float_to_long = expected_op }, decoded[13]);
    try std.testing.expectEqual(Instruction{ .float_to_double = expected_op }, decoded[14]);
    try std.testing.expectEqual(Instruction{ .double_to_int = expected_op }, decoded[15]);
    try std.testing.expectEqual(Instruction{ .double_to_long = expected_op }, decoded[16]);
    try std.testing.expectEqual(Instruction{ .double_to_float = expected_op }, decoded[17]);
    try std.testing.expectEqual(Instruction{ .int_to_byte = expected_op }, decoded[18]);
    try std.testing.expectEqual(Instruction{ .int_to_char = expected_op }, decoded[19]);
    try std.testing.expectEqual(Instruction{ .int_to_short = expected_op }, decoded[20]);
}

test "decode binary math" {
    const allocator = std.testing.allocator;

    const code_units = [_]u16{
        0x1290, 0x5634, // add_int
        0x1291, 0x5634, // sub_int
        0x1292, 0x5634, // mul_int
        0x1293, 0x5634, // div_int
        0x1294, 0x5634, // rem_int
        0x1295, 0x5634, // and_int
        0x1296, 0x5634, // or_int
        0x1297, 0x5634, // xor_int
        0x1298, 0x5634, // shl_int
        0x1299, 0x5634, // shr_int
        0x129a, 0x5634, // ushr_int
        0x129b, 0x5634, // add_long
        0x129c, 0x5634, // sub_long
        0x129d, 0x5634, // mul_long
        0x129e, 0x5634, // div_long
        0x129f, 0x5634, // rem_long
        0x12a0, 0x5634, // and_long
        0x12a1, 0x5634, // or_long
        0x12a2, 0x5634, // xor_long
        0x12a3, 0x5634, // shl_long
        0x12a4, 0x5634, // shr_long
        0x12a5, 0x5634, // ushr_long
        0x12a6, 0x5634, // add_float
        0x12a7, 0x5634, // sub_float
        0x12a8, 0x5634, // mul_float
        0x12a9, 0x5634, // div_float
        0x12aa, 0x5634, // rem_float
        0x12ab, 0x5634, // add_double
        0x12ac, 0x5634, // sub_double
        0x12ad, 0x5634, // mul_double
        0x12ae, 0x5634, // div_double
        0x12af, 0x5634, // rem_double
    };

    var bytes: [16 + code_units.len * 2]u8 = undefined;
    std.mem.writeInt(u16, bytes[0..2], 0, .little);
    std.mem.writeInt(u16, bytes[2..4], 0, .little);
    std.mem.writeInt(u16, bytes[4..6], 0, .little);
    std.mem.writeInt(u16, bytes[6..8], 0, .little);
    std.mem.writeInt(u32, bytes[8..12], 0, .little);
    std.mem.writeInt(u32, bytes[12..16], code_units.len, .little);
    for (code_units, 0..) |unit, idx| {
        std.mem.writeInt(u16, bytes[16 + idx * 2 ..][0..2], unit, .little);
    }

    const decoded = try decodeBytecode(allocator, &bytes, 0, &.{}, &.{});
    defer allocator.free(decoded);

    try std.testing.expectEqual(@as(usize, 32), decoded.len);
    const expected_op = instmod.BinOp{ .dest = 0x12, .src1 = 0x34, .src2 = 0x56 };
    try std.testing.expectEqual(Instruction{ .add_int = expected_op }, decoded[0]);
    try std.testing.expectEqual(Instruction{ .sub_int = expected_op }, decoded[1]);
    try std.testing.expectEqual(Instruction{ .mul_int = expected_op }, decoded[2]);
    try std.testing.expectEqual(Instruction{ .div_int = expected_op }, decoded[3]);
    try std.testing.expectEqual(Instruction{ .rem_int = expected_op }, decoded[4]);
    try std.testing.expectEqual(Instruction{ .and_int = expected_op }, decoded[5]);
    try std.testing.expectEqual(Instruction{ .or_int = expected_op }, decoded[6]);
    try std.testing.expectEqual(Instruction{ .xor_int = expected_op }, decoded[7]);
    try std.testing.expectEqual(Instruction{ .shl_int = expected_op }, decoded[8]);
    try std.testing.expectEqual(Instruction{ .shr_int = expected_op }, decoded[9]);
    try std.testing.expectEqual(Instruction{ .ushr_int = expected_op }, decoded[10]);
    try std.testing.expectEqual(Instruction{ .add_long = expected_op }, decoded[11]);
    try std.testing.expectEqual(Instruction{ .sub_long = expected_op }, decoded[12]);
    try std.testing.expectEqual(Instruction{ .mul_long = expected_op }, decoded[13]);
    try std.testing.expectEqual(Instruction{ .div_long = expected_op }, decoded[14]);
    try std.testing.expectEqual(Instruction{ .rem_long = expected_op }, decoded[15]);
    try std.testing.expectEqual(Instruction{ .and_long = expected_op }, decoded[16]);
    try std.testing.expectEqual(Instruction{ .or_long = expected_op }, decoded[17]);
    try std.testing.expectEqual(Instruction{ .xor_long = expected_op }, decoded[18]);
    try std.testing.expectEqual(Instruction{ .shl_long = expected_op }, decoded[19]);
    try std.testing.expectEqual(Instruction{ .shr_long = expected_op }, decoded[20]);
    try std.testing.expectEqual(Instruction{ .ushr_long = expected_op }, decoded[21]);
    try std.testing.expectEqual(Instruction{ .add_float = expected_op }, decoded[22]);
    try std.testing.expectEqual(Instruction{ .sub_float = expected_op }, decoded[23]);
    try std.testing.expectEqual(Instruction{ .mul_float = expected_op }, decoded[24]);
    try std.testing.expectEqual(Instruction{ .div_float = expected_op }, decoded[25]);
    try std.testing.expectEqual(Instruction{ .rem_float = expected_op }, decoded[26]);
    try std.testing.expectEqual(Instruction{ .add_double = expected_op }, decoded[27]);
    try std.testing.expectEqual(Instruction{ .sub_double = expected_op }, decoded[28]);
    try std.testing.expectEqual(Instruction{ .mul_double = expected_op }, decoded[29]);
    try std.testing.expectEqual(Instruction{ .div_double = expected_op }, decoded[30]);
    try std.testing.expectEqual(Instruction{ .rem_double = expected_op }, decoded[31]);
}

test "decode binary math lit16" {
    const allocator = std.testing.allocator;

    const code_units = [_]u16{
        0x43d0, 0x1234, // add_int_lit16
        0x43d1, 0x1234, // rsub_int_lit16
        0x43d2, 0x1234, // mul_int_lit16
        0x43d3, 0x1234, // div_int_lit16
        0x43d4, 0x1234, // rem_int_lit16
        0x43d5, 0x1234, // and_int_lit16
        0x43d6, 0x1234, // or_int_lit16
        0x43d7, 0x1234, // xor_int_lit16
    };

    var bytes: [16 + code_units.len * 2]u8 = undefined;
    std.mem.writeInt(u16, bytes[0..2], 0, .little);
    std.mem.writeInt(u16, bytes[2..4], 0, .little);
    std.mem.writeInt(u16, bytes[4..6], 0, .little);
    std.mem.writeInt(u16, bytes[6..8], 0, .little);
    std.mem.writeInt(u32, bytes[8..12], 0, .little);
    std.mem.writeInt(u32, bytes[12..16], code_units.len, .little);
    for (code_units, 0..) |unit, idx| {
        std.mem.writeInt(u16, bytes[16 + idx * 2 ..][0..2], unit, .little);
    }

    const decoded = try decodeBytecode(allocator, &bytes, 0, &.{}, &.{});
    defer allocator.free(decoded);

    try std.testing.expectEqual(@as(usize, 8), decoded.len);
    const expected_op = instmod.Lit16Op{ .dest = 3, .src = 4, .lit = 0x1234 };
    try std.testing.expectEqual(Instruction{ .add_int_lit16 = expected_op }, decoded[0]);
    try std.testing.expectEqual(Instruction{ .rsub_int_lit16 = expected_op }, decoded[1]);
    try std.testing.expectEqual(Instruction{ .mul_int_lit16 = expected_op }, decoded[2]);
    try std.testing.expectEqual(Instruction{ .div_int_lit16 = expected_op }, decoded[3]);
    try std.testing.expectEqual(Instruction{ .rem_int_lit16 = expected_op }, decoded[4]);
    try std.testing.expectEqual(Instruction{ .and_int_lit16 = expected_op }, decoded[5]);
    try std.testing.expectEqual(Instruction{ .or_int_lit16 = expected_op }, decoded[6]);
    try std.testing.expectEqual(Instruction{ .xor_int_lit16 = expected_op }, decoded[7]);
}

test "decode binary math lit8" {
    const allocator = std.testing.allocator;

    const code_units = [_]u16{
        0x12d8, 0x5634, // add_int_lit8
        0x12d9, 0x5634, // rsub_int_lit8
        0x12da, 0x5634, // mul_int_lit8
        0x12db, 0x5634, // div_int_lit8
        0x12dc, 0x5634, // rem_int_lit8
        0x12dd, 0x5634, // and_int_lit8
        0x12de, 0x5634, // or_int_lit8
        0x12df, 0x5634, // xor_int_lit8
        0x12e0, 0x5634, // shl_int_lit8
        0x12e1, 0x5634, // shr_int_lit8
        0x12e2, 0x5634, // ushr_int_lit8
    };

    var bytes: [16 + code_units.len * 2]u8 = undefined;
    std.mem.writeInt(u16, bytes[0..2], 0, .little);
    std.mem.writeInt(u16, bytes[2..4], 0, .little);
    std.mem.writeInt(u16, bytes[4..6], 0, .little);
    std.mem.writeInt(u16, bytes[6..8], 0, .little);
    std.mem.writeInt(u32, bytes[8..12], 0, .little);
    std.mem.writeInt(u32, bytes[12..16], code_units.len, .little);
    for (code_units, 0..) |unit, idx| {
        std.mem.writeInt(u16, bytes[16 + idx * 2 ..][0..2], unit, .little);
    }

    const decoded = try decodeBytecode(allocator, &bytes, 0, &.{}, &.{});
    defer allocator.free(decoded);

    try std.testing.expectEqual(@as(usize, 11), decoded.len);
    const expected_op = instmod.LitOp{ .dest = 0x12, .src = 0x34, .lit = 0x56 };
    try std.testing.expectEqual(Instruction{ .add_int_lit8 = expected_op }, decoded[0]);
    try std.testing.expectEqual(Instruction{ .rsub_int_lit8 = expected_op }, decoded[1]);
    try std.testing.expectEqual(Instruction{ .mul_int_lit8 = expected_op }, decoded[2]);
    try std.testing.expectEqual(Instruction{ .div_int_lit8 = expected_op }, decoded[3]);
    try std.testing.expectEqual(Instruction{ .rem_int_lit8 = expected_op }, decoded[4]);
    try std.testing.expectEqual(Instruction{ .and_int_lit8 = expected_op }, decoded[5]);
    try std.testing.expectEqual(Instruction{ .or_int_lit8 = expected_op }, decoded[6]);
    try std.testing.expectEqual(Instruction{ .xor_int_lit8 = expected_op }, decoded[7]);
    try std.testing.expectEqual(Instruction{ .shl_int_lit8 = expected_op }, decoded[8]);
    try std.testing.expectEqual(Instruction{ .shr_int_lit8 = expected_op }, decoded[9]);
    try std.testing.expectEqual(Instruction{ .ushr_int_lit8 = expected_op }, decoded[10]);
}

test "extractKotlinMetadata" {
    var arena_state = std.heap.ArenaAllocator.init(std.testing.allocator);
    defer arena_state.deinit();
    const allocator = arena_state.allocator();

    var mock_bytes = [_]u8{0} ** 300;
    
    // annotations_directory_item
    std.mem.writeInt(u32, mock_bytes[4..8], 8, .little);
    
    // annotation_set_item
    std.mem.writeInt(u32, mock_bytes[8..12], 1, .little);
    std.mem.writeInt(u32, mock_bytes[12..16], 16, .little);
    
    // annotation_item
    mock_bytes[16] = 1; // visibility
    mock_bytes[17] = 0; // type_idx
    mock_bytes[18] = 3; // pair_size
    
    // Pair 0 ("k")
    mock_bytes[19] = 0; // name_idx
    mock_bytes[20] = 0x03; // INT
    mock_bytes[21] = 1; // value
    
    // Pair 1 ("mv")
    mock_bytes[22] = 1; // name_idx
    mock_bytes[23] = 0x1c; // ARRAY
    mock_bytes[24] = 3; // size
    mock_bytes[25] = 0x03;
    mock_bytes[26] = 1;
    mock_bytes[27] = 0x03;
    mock_bytes[28] = 9;
    mock_bytes[29] = 0x03;
    mock_bytes[30] = 0;
    
    // Pair 2 ("d1")
    mock_bytes[31] = 2; // name_idx
    mock_bytes[32] = 0x1c; // ARRAY
    mock_bytes[33] = 1; // size
    mock_bytes[34] = 0x17; // STRING
    mock_bytes[35] = 3; // index 3
    
    // Strings in string pool
    var string_pool = [_][]const u8{
        "k", "mv", "d1", "abc"
    };
    
    // Mock string_ids and data for readStringZeroCopy
    std.mem.writeInt(u32, mock_bytes[100..104], 200, .little);
    std.mem.writeInt(u32, mock_bytes[104..108], 210, .little);
    std.mem.writeInt(u32, mock_bytes[108..112], 220, .little);
    
    mock_bytes[200] = 1; mock_bytes[201] = 'k';
    mock_bytes[210] = 2; mock_bytes[211] = 'm'; mock_bytes[212] = 'v';
    mock_bytes[220] = 2; mock_bytes[221] = 'd'; mock_bytes[222] = '1';
    
    var type_names = [_][]const u8{
        "kotlin/Metadata"
    };
    
    const meta = (try extractKotlinMetadata(
        allocator,
        &mock_bytes,
        4,
        &string_pool,
        &type_names,
        100,
        3
    )).?;
    
    try std.testing.expectEqual(@as(u32, 1), meta.kind);
    try std.testing.expectEqualSlices(u32, &[_]u32{ 1, 9, 0 }, meta.metadata_version);
    try std.testing.expectEqualSlices([]const u8, &[_][]const u8{ "abc" }, meta.data1);
}

















