#ifndef MINI_PB_H
#define MINI_PB_H

#include <stdint.h>
#include <stdbool.h>
#include <stddef.h>

typedef struct {
    const uint8_t *buf;
    size_t len;
    size_t offset;
} pb_istream_t;

typedef enum {
    PB_WT_VARINT = 0,
    PB_WT_64BIT = 1,
    PB_WT_STRING = 2,
    PB_WT_32BIT = 5
} pb_wire_type_t;

typedef struct {
    uint32_t tag;
    uint32_t wire_type;
    union {
        uint64_t varint;
        struct {
            const uint8_t *buf;
            size_t len;
        } bytes;
        uint32_t fixed32;
        uint64_t fixed64;
    } value;
} pb_field_t;

pb_istream_t pb_istream_from_buffer(const uint8_t *buf, size_t len);
bool pb_read_field(pb_istream_t *stream, pb_field_t *field);

#endif // MINI_PB_H
