#include "pb.h"
#include "metadata_decoder.h"
#include <stdio.h>

// Real field numbers from ProtoBuf.Class / ProtoBuf.Function / ProtoBuf.Property
// Class.FUNCTION_FIELD_NUMBER = 9
// Class.PROPERTY_FIELD_NUMBER = 10
// Class.CONSTRUCTOR_FIELD_NUMBER = 8
// Function.NAME_FIELD_NUMBER = 2
// Property.NAME_FIELD_NUMBER = 2

typedef struct {
    resolve_str_t resolve;
    void *ctx;
    int indent;
} decode_ctx_t;

static void print_indent(int indent) {
    for (int i = 0; i < indent; i++) {
        printf("  ");
    }
}

static void decode_constructor(pb_istream_t *stream, decode_ctx_t *ctx) {
    pb_field_t f;
    int param_count = 0;

    while (pb_read_field(stream, &f)) {
        // ValueParameter is tag 2 (VALUE_PARAMETER_FIELD_NUMBER inside Constructor)
        if (f.tag == 2 && f.wire_type == PB_WT_STRING) {
            param_count++;
        }
    }

    print_indent(ctx->indent);
    printf("  constructor(");
    for (int i = 0; i < param_count; i++) {
        if (i > 0) printf(", ");
        printf("param%d", i);
    }
    printf(")\n");
}

static void decode_function(pb_istream_t *stream, decode_ctx_t *ctx) {
    pb_field_t f;
    uint32_t name_idx = 0;
    
    while (pb_read_field(stream, &f)) {
        // Function.NAME_FIELD_NUMBER = 2, stored as a varint (string table index)
        if (f.tag == 2 && f.wire_type == PB_WT_VARINT) {
            name_idx = (uint32_t)f.value.varint;
        }
    }
    
    print_indent(ctx->indent);
    const char *name = (name_idx != 0) ? ctx->resolve(ctx->ctx, name_idx) : NULL;
    printf("  fun %s()\n", name ? name : "<unknown>");
}

static void decode_property(pb_istream_t *stream, decode_ctx_t *ctx) {
    pb_field_t f;
    uint32_t name_idx = 0;
    
    while (pb_read_field(stream, &f)) {
        // Property.NAME_FIELD_NUMBER = 2, stored as a varint (string table index)
        if (f.tag == 2 && f.wire_type == PB_WT_VARINT) {
            name_idx = (uint32_t)f.value.varint;
        }
    }
    
    print_indent(ctx->indent);
    const char *name = (name_idx != 0) ? ctx->resolve(ctx->ctx, name_idx) : NULL;
    printf("  val %s\n", name ? name : "<unknown>");
}

void decode_kotlin_class(const uint8_t *buf, size_t len, resolve_str_t resolve, void *resolve_ctx) {
    // The stream starts with a varint-length-prefixed JvmProtoBuf.StringTableTypes,
    // followed by the ProtoBuf.Class message.
    uint64_t string_table_size = 0;
    size_t offset = 0;
    int shift = 0;
    while (offset < len) {
        uint8_t byte = buf[offset++];
        string_table_size |= (uint64_t)(byte & 0x7F) << shift;
        if (!(byte & 0x80)) break;
        shift += 7;
    }
    
    if (offset + string_table_size > len) {
        printf("Error: Invalid string table size\n");
        return;
    }
    
    size_t class_offset = offset + (size_t)string_table_size;
    pb_istream_t class_stream = pb_istream_from_buffer(buf + class_offset, len - class_offset);
    pb_field_t f;
    decode_ctx_t ctx = { resolve, resolve_ctx, 1 };
    
    printf("Kotlin Class Declarations:\n");
    while (pb_read_field(&class_stream, &f)) {
        if (f.wire_type != PB_WT_STRING) continue;

        if (f.tag == 8) { // Class.CONSTRUCTOR_FIELD_NUMBER = 8
            pb_istream_t sub = pb_istream_from_buffer(f.value.bytes.buf, f.value.bytes.len);
            decode_constructor(&sub, &ctx);
        } else if (f.tag == 9) { // Class.FUNCTION_FIELD_NUMBER = 9
            pb_istream_t sub = pb_istream_from_buffer(f.value.bytes.buf, f.value.bytes.len);
            decode_function(&sub, &ctx);
        } else if (f.tag == 10) { // Class.PROPERTY_FIELD_NUMBER = 10
            pb_istream_t sub = pb_istream_from_buffer(f.value.bytes.buf, f.value.bytes.len);
            decode_property(&sub, &ctx);
        }
    }
}
