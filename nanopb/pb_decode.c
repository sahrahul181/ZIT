#include "pb.h"
#include <stdio.h>

pb_istream_t pb_istream_from_buffer(const uint8_t *buf, size_t len) {
    pb_istream_t stream;
    stream.buf = buf;
    stream.len = len;
    stream.offset = 0;
    return stream;
}

static bool read_varint(pb_istream_t *stream, uint64_t *val) {
    uint64_t result = 0;
    int shift = 0;
    while (stream->offset < stream->len) {
        uint8_t byte = stream->buf[stream->offset++];
        result |= (uint64_t)(byte & 0x7F) << shift;
        if (!(byte & 0x80)) {
            *val = result;
            return true;
        }
        shift += 7;
        if (shift >= 64) {
            return false; // overflow
        }
    }
    return false; // EOF
}

bool pb_read_field(pb_istream_t *stream, pb_field_t *field) {
    if (stream->offset >= stream->len) {
        return false;
    }

    uint64_t key;
    if (!read_varint(stream, &key)) {
        return false;
    }

    field->wire_type = key & 0x7;
    field->tag = key >> 3;

    switch (field->wire_type) {
        case PB_WT_VARINT:
            return read_varint(stream, &field->value.varint);

        case PB_WT_64BIT:
            if (stream->offset + 8 > stream->len) return false;
            field->value.fixed64 = 0;
            for (int i = 0; i < 8; i++) {
                field->value.fixed64 |= (uint64_t)stream->buf[stream->offset++] << (i * 8);
            }
            return true;

        case PB_WT_STRING: {
            uint64_t len;
            if (!read_varint(stream, &len)) return false;
            if (stream->offset + len > stream->len) return false;
            field->value.bytes.buf = &stream->buf[stream->offset];
            field->value.bytes.len = len;
            stream->offset += len;
            return true;
        }

        case PB_WT_32BIT:
            if (stream->offset + 4 > stream->len) return false;
            field->value.fixed32 = 0;
            for (int i = 0; i < 4; i++) {
                field->value.fixed32 |= (uint32_t)stream->buf[stream->offset++] << (i * 8);
            }
            return true;

        default:
            return false; // Unknown wire type
    }
}
