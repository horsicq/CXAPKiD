/*
 * CXAPKiD - C port of APKiD (https://github.com/rednaga/APKiD)
 * Copyright (C) 2026 hors <horsicq@gmail.com>
 * SPDX-License-Identifier: MIT
 */
#include "cx_xz.h"
#include "cx_sink.h"

#include <xxfclib/algo/crc/xx_crc.h>
#include <xxfclib/algo/lzma/xx_lzma.h>
#include <xxfclib/algo/sha/xx_sha.h>

#include <stdlib.h>
#include <string.h>

#define CX_XZ_FILTER_LZMA2 0x21

static const uint8_t cx_xz_magic[6] = {0xFD, '7', 'z', 'X', 'Z', 0x00};

static uint32_t cx_xz_rd32(const uint8_t *p)
{
    return (uint32_t)p[0] | ((uint32_t)p[1] << 8) | ((uint32_t)p[2] << 16) | ((uint32_t)p[3] << 24);
}

static uint64_t cx_xz_rd64(const uint8_t *p)
{
    return (uint64_t)cx_xz_rd32(p) | ((uint64_t)cx_xz_rd32(p + 4) << 32);
}

static bool cx_xz_fail(char **error, const char *message)
{
    if (error && !*error) *error = cx_strdup(message);
    return false;
}

/* Variable-length integer of the .xz format. */
static bool cx_xz_vli(const uint8_t *data, size_t end, size_t *position, uint64_t *value)
{
    uint64_t result = 0;
    for (unsigned i = 0; i < 9; ++i) {
        if (*position >= end) return false;
        uint8_t byte = data[(*position)++];
        result |= (uint64_t)(byte & 0x7F) << (7 * i);
        if (!(byte & 0x80)) {
            if (i && byte == 0) return false; /* not minimally encoded */
            *value = result;
            return true;
        }
    }
    return false;
}

static size_t cx_xz_check_size(unsigned check)
{
    static const uint8_t sizes[16] = {0, 4, 4, 4, 8, 8, 8, 16, 16, 16, 32, 32, 32, 64, 64, 64};
    return sizes[check & 0x0F];
}

static bool cx_xz_verify_check(unsigned check, const uint8_t *data, size_t size, const uint8_t *expected)
{
    switch (check) {
    case 0x01:
        return xx_crc32_calc(0, data, size) == cx_xz_rd32(expected);
    case 0x04:
        return xx_crc64_xz_calc(0, data, size) == cx_xz_rd64(expected);
    case 0x0A: {
        uint8_t digest[32];
        return xx_sha256_memory(data, size, digest) && memcmp(digest, expected, sizeof(digest)) == 0;
    }
    default:
        return true; /* liblzma skips check types it does not know */
    }
}

/* Walk the LZMA2 chunks of a block: the compressed extent (end marker
 * included) and the uncompressed size. */
static bool cx_xz_lzma2_extent(const uint8_t *data, size_t size, size_t *compressed, uint64_t *uncompressed)
{
    size_t position = 0;
    uint64_t total = 0;
    for (;;) {
        if (position >= size) return false;
        uint8_t control = data[position];
        if (control == 0x00) {
            *compressed = position + 1;
            *uncompressed = total;
            return true;
        }
        if (control == 0x01 || control == 0x02) {
            if (size - position < 3) return false;
            size_t chunk = ((size_t)data[position + 1] << 8 | data[position + 2]) + 1;
            if (size - position - 3 < chunk) return false;
            position += 3 + chunk;
            total += chunk;
        } else if (control >= 0x80) {
            size_t header = control >= 0xC0 ? 6 : 5;
            if (size - position < header) return false;
            uint64_t unpacked = (((uint64_t)(control & 0x1F) << 16) | ((uint64_t)data[position + 1] << 8) | data[position + 2]) + 1;
            size_t packed = ((size_t)data[position + 3] << 8 | data[position + 4]) + 1;
            if (size - position - header < packed) return false;
            position += header + packed;
            total += unpacked;
        } else {
            return false;
        }
    }
}

typedef struct cx_xz_record {
    uint64_t unpadded;
    uint64_t uncompressed;
} cx_xz_record;

/* One .xz stream starting at data[0]. */
static bool cx_xz_stream(const uint8_t *data, size_t size, size_t *used, cx_buf *out, char **error)
{
    cx_xz_record *records = NULL;
    size_t record_count = 0, record_capacity = 0;
    bool ok = false;

    if (size < 12 || memcmp(data, cx_xz_magic, 6) != 0) return cx_xz_fail(error, "Input format not supported by decoder");
    if (data[6] != 0 || (data[7] & 0xF0) || xx_crc32_calc(0, data + 6, 2) != cx_xz_rd32(data + 8))
        return cx_xz_fail(error, "Corrupt input data");
    unsigned check = data[7] & 0x0F;
    size_t check_size = cx_xz_check_size(check), position = 12;

    for (;;) {
        if (position >= size) {
            cx_xz_fail(error, "Compressed data ended before the end-of-stream marker was reached");
            goto done;
        }
        if (data[position] == 0x00) break; /* index indicator */

        size_t block_start = position, header_size = ((size_t)data[position] + 1) * 4;
        if (size - position < header_size || xx_crc32_calc(0, data + position, header_size - 4) !=
                                                 cx_xz_rd32(data + position + header_size - 4)) {
            cx_xz_fail(error, "Corrupt input data");
            goto done;
        }
        size_t header_end = position + header_size - 4, cursor = position + 2;
        uint8_t flags = data[position + 1];
        uint64_t declared_compressed = UINT64_MAX, declared_uncompressed = UINT64_MAX;
        if (flags & 0x3C) {
            cx_xz_fail(error, "Unsupported options");
            goto done;
        }
        if ((flags & 0x40) && !cx_xz_vli(data, header_end, &cursor, &declared_compressed)) {
            cx_xz_fail(error, "Corrupt input data");
            goto done;
        }
        if ((flags & 0x80) && !cx_xz_vli(data, header_end, &cursor, &declared_uncompressed)) {
            cx_xz_fail(error, "Corrupt input data");
            goto done;
        }
        unsigned filters = (flags & 0x03) + 1;
        uint8_t lzma2_props = 0;
        for (unsigned i = 0; i < filters; ++i) {
            uint64_t id, props_size;
            if (!cx_xz_vli(data, header_end, &cursor, &id) || !cx_xz_vli(data, header_end, &cursor, &props_size) ||
                props_size > header_end - cursor) {
                cx_xz_fail(error, "Corrupt input data");
                goto done;
            }
            if (id != CX_XZ_FILTER_LZMA2 || i + 1 != filters || props_size != 1) {
                if (error && !*error) *error = cx_format("unsupported XZ filter 0x%llx", (unsigned long long)id);
                goto done;
            }
            lzma2_props = data[cursor];
            cursor += (size_t)props_size;
        }
        for (; cursor < header_end; ++cursor)
            if (data[cursor]) {
                cx_xz_fail(error, "Corrupt input data");
                goto done;
            }

        position = block_start + header_size;
        size_t compressed;
        uint64_t uncompressed;
        if (!cx_xz_lzma2_extent(data + position, size - position, &compressed, &uncompressed) ||
            (declared_compressed != UINT64_MAX && declared_compressed != compressed) ||
            (declared_uncompressed != UINT64_MAX && declared_uncompressed != uncompressed) || uncompressed > SIZE_MAX) {
            cx_xz_fail(error, "Corrupt input data");
            goto done;
        }
        size_t first = out->length;
        if (uncompressed) {
            cx_buf_append(out, NULL, 0);
            uint8_t *block = (uint8_t *)malloc((size_t)uncompressed);
            size_t written = 0;
            if (!block) {
                cx_xz_fail(error, "Cannot allocate memory");
                goto done;
            }
            bool decoded = xx_lzma2_decompress_memory(data + position, compressed, lzma2_props, block, (size_t)uncompressed,
                                                      &written) &&
                           written == uncompressed;
            if (decoded) cx_buf_append(out, block, written);
            free(block);
            if (!decoded) {
                cx_xz_fail(error, "Corrupt input data");
                goto done;
            }
        }
        position += compressed;
        size_t unpadded = header_size + compressed;
        while ((position - block_start) % 4) {
            if (position >= size || data[position]) {
                cx_xz_fail(error, "Corrupt input data");
                goto done;
            }
            ++position;
        }
        if (size - position < check_size ||
            !cx_xz_verify_check(check, (const uint8_t *)out->data + first, out->length - first, data + position)) {
            cx_xz_fail(error, "Corrupt input data");
            goto done;
        }
        position += check_size;
        if (record_count == record_capacity) {
            record_capacity = record_capacity ? record_capacity * 2 : 8;
            records = (cx_xz_record *)cx_realloc(records, record_capacity * sizeof(*records));
        }
        records[record_count].unpadded = unpadded + check_size;
        records[record_count].uncompressed = uncompressed;
        ++record_count;
    }

    /* Index */
    size_t index_start = position++;
    uint64_t count;
    if (!cx_xz_vli(data, size, &position, &count) || count != record_count) {
        cx_xz_fail(error, "Corrupt input data");
        goto done;
    }
    for (size_t i = 0; i < record_count; ++i) {
        uint64_t unpadded, uncompressed;
        if (!cx_xz_vli(data, size, &position, &unpadded) || !cx_xz_vli(data, size, &position, &uncompressed) ||
            unpadded != records[i].unpadded || uncompressed != records[i].uncompressed) {
            cx_xz_fail(error, "Corrupt input data");
            goto done;
        }
    }
    while ((position - index_start) % 4) {
        if (position >= size || data[position]) {
            cx_xz_fail(error, "Corrupt input data");
            goto done;
        }
        ++position;
    }
    if (size - position < 4 + 12 ||
        xx_crc32_calc(0, data + index_start, position - index_start) != cx_xz_rd32(data + position)) {
        cx_xz_fail(error, "Corrupt input data");
        goto done;
    }
    position += 4;

    /* Footer */
    const uint8_t *footer = data + position;
    if (memcmp(footer + 10, "YZ", 2) != 0 || xx_crc32_calc(0, footer + 4, 6) != cx_xz_rd32(footer) ||
        memcmp(footer + 8, data + 6, 2) != 0 ||
        ((uint64_t)cx_xz_rd32(footer + 4) + 1) * 4 != (uint64_t)(position - index_start)) {
        cx_xz_fail(error, "Corrupt input data");
        goto done;
    }
    *used = position + 12;
    ok = true;
done:
    free(records);
    return ok;
}

/* .lzma (LZMA_Alone) as liblzma's picky auto decoder accepts it. */
static bool cx_xz_alone(const uint8_t *data, size_t size, cx_buf *out, char **error)
{
    if (size < 13) return cx_xz_fail(error, "Compressed data ended before the end-of-stream marker was reached");
    unsigned props = data[0], lc = props % 9, lp = (props / 9) % 5;
    uint32_t dictionary = cx_xz_rd32(data + 1);
    uint64_t declared = cx_xz_rd64(data + 5);
    if (props > (4 * 5 + 4) * 9 + 8 || lc + lp > 4) return cx_xz_fail(error, "Input format not supported by decoder");
    if (dictionary != UINT32_MAX) {
        uint32_t d = dictionary - 1;
        d |= d >> 2;
        d |= d >> 3;
        d |= d >> 4;
        d |= d >> 8;
        d |= d >> 16;
        ++d;
        if (d != dictionary) return cx_xz_fail(error, "Input format not supported by decoder");
    }
    if (declared != UINT64_MAX && declared >= ((uint64_t)1 << 38))
        return cx_xz_fail(error, "Input format not supported by decoder");

    cx_sink sink;
    cx_sink_init(&sink, declared == UINT64_MAX || declared > SIZE_MAX ? SIZE_MAX : (size_t)declared);
    bool decoded = declared == 0 ||
                   (size > 13 && xx_lzma_unpack_memory_to_device(data + 13, size - 13, data, 5,
                                                                 declared == UINT64_MAX ? -1 : (int64_t)declared,
                                                                 &sink.device, NULL));
    if (!decoded || sink.no_memory) {
        cx_sink_free(&sink);
        return cx_xz_fail(error, sink.no_memory ? "Cannot allocate memory" : "Corrupt input data");
    }
    size_t length;
    bool mapped;
    uint8_t *bytes = cx_sink_detach(&sink, &length, &mapped);
    if (!bytes) return cx_xz_fail(error, "Cannot allocate memory");
    cx_buf_append(out, bytes, length);
    cx_sink_release(bytes, mapped);
    return true;
}

bool cx_xz_decompress(const uint8_t *data, size_t size, uint8_t **out, size_t *out_size, char **error)
{
    cx_buf result = {0};
    *out = NULL;
    *out_size = 0;
    if (error) *error = NULL;
    cx_buf_append(&result, "", 0);

    if (size >= 6 && memcmp(data, cx_xz_magic, 6) == 0) {
        size_t used = 0;
        if (!cx_xz_stream(data, size, &used, &result, error)) {
            cx_buf_free(&result);
            return false;
        }
        /* Further concatenated streams; anything else after a decoded
           stream is ignored, as lzma.decompress() does for invalid data. */
        while (used < size && size - used >= 6 && memcmp(data + used, cx_xz_magic, 6) == 0) {
            size_t next = 0;
            size_t before = result.length;
            char *ignored = NULL;
            if (!cx_xz_stream(data + used, size - used, &next, &result, &ignored)) {
                free(ignored);
                result.length = before;
                break;
            }
            used += next;
        }
    } else if (!cx_xz_alone(data, size, &result, error)) {
        cx_buf_free(&result);
        return false;
    }
    *out_size = result.length;
    *out = (uint8_t *)cx_buf_detach(&result);
    return true;
}
