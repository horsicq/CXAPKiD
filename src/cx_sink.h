/*
 * CXAPKiD - C port of APKiD (https://github.com/rednaga/APKiD)
 * Copyright (C) 2026 hors <horsicq@gmail.com>
 * SPDX-License-Identifier: MIT
 */
#ifndef CX_SINK_H
#define CX_SINK_H

#include "cx_common.h"

#include <xxfclib/io/xx_io.h>

#ifdef __cplusplus
extern "C" {
#endif

/* A write-only, growable memory device for xxfclib decoders. It keeps at
 * most `limit` bytes; once the limit is reached it refuses further output
 * so the decoder stops early (`full`). Memory grows with the output, so a
 * member that declares a huge size cannot force a huge allocation beyond
 * what the caller reserves with cx_sink_reserve(). */
typedef struct cx_sink {
    xx_io_device device;
    uint8_t *data;
    size_t size;
    size_t capacity; /* usable bytes at data (committed ones in a reservation) */
    size_t limit;
    size_t reserved; /* address space reserved at data; 0: heap memory */
    uint32_t crc;    /* CRC-32 of the bytes kept, when `checksum` is set */
    bool checksum;
    bool full;
    bool no_memory;
} cx_sink;

void cx_sink_init(cx_sink *sink, size_t limit);
/* Allocate `capacity` bytes (at most the limit) before decoding, for output
 * whose size is known. A failed allocation is not an error: the sink then
 * grows with the output, as without the reservation. */
void cx_sink_reserve(cx_sink *sink, size_t capacity);
/* Reserve address space for `capacity` bytes (at most the limit) and commit
 * memory only as the output arrives, so large output is never copied while
 * it grows and a size that is never reached costs no memory. Output beyond
 * the reservation moves to the heap and grows as usual. Returns false when
 * this is not available (32-bit or non-Windows builds, or the reservation
 * failed); the sink is then unchanged. Call it before any output. */
bool cx_sink_reserve_space(cx_sink *sink, size_t capacity);
/* Detach the bytes (never NULL on success; NULL when out of memory). Release
 * them with cx_sink_release(), passing *mapped. */
uint8_t *cx_sink_detach(cx_sink *sink, size_t *size, bool *mapped);
void cx_sink_release(uint8_t *data, bool mapped);
void cx_sink_free(cx_sink *sink);

#ifdef __cplusplus
}
#endif

#endif
