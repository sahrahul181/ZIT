#ifndef METADATA_DECODER_H
#define METADATA_DECODER_H

#include <stdint.h>
#include <stddef.h>

typedef const char* (*resolve_str_t)(void *ctx, uint32_t idx);

void decode_kotlin_class(const uint8_t *buf, size_t len, resolve_str_t resolve, void *resolve_ctx);

#endif // METADATA_DECODER_H
