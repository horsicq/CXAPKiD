/*
 * CXAPKiD - C port of APKiD (https://github.com/rednaga/APKiD)
 * Copyright (C) 2026 hors <horsicq@gmail.com>
 * SPDX-License-Identifier: MIT
 *
 * The walk follows libyara/modules/dex.c of YARA 3.11, including its
 * quirks: a string value is the `utf16_size` bytes after the first byte of
 * its string_data_item, and a member that cannot be resolved stops the
 * current member list but not the class. Reads are bounds checked here.
 */
#include "cx_dex.h"

#include <stdlib.h>
#include <string.h>

#define CX_DEX_HEADER_SIZE 0x70

typedef struct cx_dex {
    const uint8_t *data;
    size_t size;
    /* string_ids[i]: -1 when YARA 3.11 leaves the entry undefined */
    int64_t *string_offset;
    uint32_t *string_value_size;
    /* Memo of cx_dex_string_unicode per string: 0 not yet known, 1 ASCII,
       2 has a byte above 0x7F. Member names repeat (<init>, run, ...). */
    uint8_t *string_unicode;
    uint32_t string_count;
    uint32_t field_ids_size, field_ids_offset;
    uint32_t method_ids_size, method_ids_offset;
} cx_dex;

static uint32_t cx_dex_u32(const cx_dex *dex, size_t offset)
{
    const uint8_t *p = dex->data + offset;
    return (uint32_t)p[0] | ((uint32_t)p[1] << 8) | ((uint32_t)p[2] << 16) | ((uint32_t)p[3] << 24);
}

/* fits_in_dex(dex, dex->data + offset, size) */
static bool cx_dex_fits(const cx_dex *dex, uint64_t offset, uint64_t size)
{
    return size <= dex->size && offset <= dex->size - size;
}

static uint8_t cx_dex_byte(const cx_dex *dex, size_t offset)
{
    return offset < dex->size ? dex->data[offset] : 0;
}

/* read_uleb128() of YARA 3.11: at most five bytes, no range checks. */
static uint32_t cx_dex_uleb128(const cx_dex *dex, size_t offset, uint32_t *size)
{
    uint32_t result = cx_dex_byte(dex, offset++);
    ++*size;
    if (result > 0x7f) {
        uint32_t cur = cx_dex_byte(dex, offset++);
        ++*size;
        result = (result & 0x7f) | ((cur & 0x7f) << 7);
        if (cur > 0x7f) {
            cur = cx_dex_byte(dex, offset++);
            ++*size;
            result |= (cur & 0x7f) << 14;
            if (cur > 0x7f) {
                cur = cx_dex_byte(dex, offset++);
                ++*size;
                result |= (cur & 0x7f) << 21;
                if (cur > 0x7f) {
                    cur = cx_dex_byte(dex, offset++);
                    ++*size;
                    result |= cur << 28;
                }
            }
        }
    }
    return result;
}

/* dex_get_integer() / dex_get_string() treat an index above this as
 * undefined ("a reasonably large limit to table indexes"). */
#define CX_DEX_MAX_INDEX 0x80000u

/* string_ids[index].value has a byte outside 0x00-0x7F. */
static bool cx_dex_string_unicode(const cx_dex *dex, uint32_t index, bool *defined)
{
    *defined = false;
    if (index > CX_DEX_MAX_INDEX || index >= dex->string_count || dex->string_offset[index] < 0) return false;
    *defined = true;
    if (dex->string_unicode[index]) return dex->string_unicode[index] == 2;
    size_t start = (size_t)dex->string_offset[index] + 1, length = dex->string_value_size[index];
    size_t end = start < dex->size ? (length < dex->size - start ? start + length : dex->size) : start;
    const uint8_t *p = dex->data + start, *stop = dex->data + end;
    bool unicode = false;
    for (; stop - p >= 8 && !unicode; p += 8) {
        uint64_t word;
        memcpy(&word, p, sizeof(word));
        unicode = (word & UINT64_C(0x8080808080808080)) != 0;
    }
    for (; p < stop && !unicode; ++p) unicode = (*p & 0x80) != 0;
    dex->string_unicode[index] = unicode ? 2 : 1;
    return unicode;
}

/* load_encoded_field() / load_encoded_method(): the bytes consumed, 0 when
 * the member cannot be loaded. *name_unicode tells whether the member's
 * name was set and has a non-ASCII byte. */
static uint32_t cx_dex_member(const cx_dex *dex, size_t start, uint32_t *previous, bool method, bool *name_unicode)
{
    uint32_t used = 0, diff;
    bool defined;
    *name_unicode = false;
    if (!cx_dex_fits(dex, start, method ? 12 : 8)) return 0;
    diff = cx_dex_uleb128(dex, start, &used);
    (void)cx_dex_uleb128(dex, start + used, &used); /* access_flags */
    if (method) (void)cx_dex_uleb128(dex, start + used, &used); /* code_off */
    *previous += diff;
    /* field_ids[idx] / method_ids[idx] exist for idx < size, and the getter
       gives up above CX_DEX_MAX_INDEX. */
    uint32_t count = method ? dex->method_ids_size : dex->field_ids_size;
    if (*previous >= count || *previous > CX_DEX_MAX_INDEX) return 0;
    size_t item = (size_t)(method ? dex->method_ids_offset : dex->field_ids_offset) + (size_t)*previous * 8;
    uint32_t name_idx = cx_dex_u32(dex, item + 4);
    *name_unicode = cx_dex_string_unicode(dex, name_idx, &defined) && defined;
    return used;
}

void cx_dex_legacy_analyze(const uint8_t *data, size_t size, cx_dex_legacy *result)
{
    static const char *const magics[] = {"dex\n035", "dex\n036", "dex\n037", "dex\n038"};
    cx_dex dex;
    memset(result, 0, sizeof(*result));
    if (size < CX_DEX_HEADER_SIZE) return;
    for (size_t i = 0; i < sizeof(magics) / sizeof(magics[0]) && !result->parsed; ++i)
        result->parsed = memcmp(data, magics[i], 8) == 0; /* includes the NUL */
    if (!result->parsed) return;

    memset(&dex, 0, sizeof(dex));
    dex.data = data;
    dex.size = size;
    uint32_t string_ids_size = cx_dex_u32(&dex, 0x38), string_ids_offset = cx_dex_u32(&dex, 0x3C);
    uint32_t type_ids_size = cx_dex_u32(&dex, 0x40), type_ids_offset = cx_dex_u32(&dex, 0x44);
    uint32_t proto_ids_size = cx_dex_u32(&dex, 0x48), proto_ids_offset = cx_dex_u32(&dex, 0x4C);
    uint32_t map_offset = cx_dex_u32(&dex, 0x34);
    uint32_t class_defs_size = cx_dex_u32(&dex, 0x60), class_defs_offset = cx_dex_u32(&dex, 0x64);
    dex.field_ids_size = cx_dex_u32(&dex, 0x50);
    dex.field_ids_offset = cx_dex_u32(&dex, 0x54);
    dex.method_ids_size = cx_dex_u32(&dex, 0x58);
    dex.method_ids_offset = cx_dex_u32(&dex, 0x5C);

    /* String IDs */
    if (!cx_dex_fits(&dex, string_ids_offset, (uint64_t)string_ids_size * 4)) return;
    dex.string_count = string_ids_size;
    dex.string_offset = (int64_t *)cx_malloc((string_ids_size ? string_ids_size : 1) * sizeof(int64_t));
    dex.string_value_size = (uint32_t *)cx_malloc((string_ids_size ? string_ids_size : 1) * sizeof(uint32_t));
    dex.string_unicode = (uint8_t *)cx_calloc(string_ids_size ? string_ids_size : 1, 1);
    int64_t previous_offset = -1;
    for (uint32_t i = 0; i < string_ids_size; ++i) {
        uint32_t offset = cx_dex_u32(&dex, (size_t)string_ids_offset + (size_t)i * 4), unused = 0, value;
        dex.string_offset[i] = -1;
        dex.string_value_size[i] = 0;
        if (!cx_dex_fits(&dex, offset, 4)) {
            previous_offset = -1;
            continue;
        }
        value = cx_dex_uleb128(&dex, offset, &unused);
        if (!cx_dex_fits(&dex, offset, value)) {
            previous_offset = -1;
            continue;
        }
        dex.string_offset[i] = offset;
        dex.string_value_size[i] = value;
        if (previous_offset >= 0 && (int64_t)offset < previous_offset) result->unsorted_string_pool = true;
        previous_offset = offset;
    }

    /* The remaining ID tables only gate the class data walk. */
    if (!cx_dex_fits(&dex, type_ids_offset, (uint64_t)type_ids_size * 4) ||
        !cx_dex_fits(&dex, proto_ids_offset, (uint64_t)proto_ids_size * 12) ||
        !cx_dex_fits(&dex, dex.field_ids_offset, (uint64_t)dex.field_ids_size * 8) ||
        !cx_dex_fits(&dex, dex.method_ids_offset, (uint64_t)dex.method_ids_size * 8))
        goto done;
    if (map_offset != 0 && cx_dex_fits(&dex, map_offset, 4) &&
        !cx_dex_fits(&dex, map_offset, 4 + (uint64_t)cx_dex_u32(&dex, map_offset) * 12))
        goto done;
    if (!cx_dex_fits(&dex, class_defs_offset, (uint64_t)class_defs_size * 32)) goto done;

    /* Class data: dex.field[] and dex.method[] in YARA 3.11's order. */
    uint64_t field_index = 0, method_index = 0;
    for (uint32_t i = 0; i < class_defs_size; ++i) {
        uint32_t class_data = cx_dex_u32(&dex, (size_t)class_defs_offset + (size_t)i * 32 + 24);
        if (!class_data) continue;
        if (!cx_dex_fits(&dex, class_data, 16)) break;
        uint32_t used = 0;
        uint32_t lists[4];
        for (int k = 0; k < 4; ++k) lists[k] = cx_dex_uleb128(&dex, (size_t)class_data + used, &used);
        for (int k = 0; k < 4; ++k) {
            bool method = k >= 2;
            uint32_t previous = 0;
            for (uint32_t j = 0; j < lists[k]; ++j) {
                bool unicode;
                uint32_t consumed = cx_dex_member(&dex, (size_t)class_data + used, &previous, method, &unicode);
                if (!consumed) break;
                used += consumed;
                if (method) {
                    if (unicode && method_index <= dex.method_ids_size) ++result->unicode_method_names;
                    ++method_index;
                } else {
                    if (unicode && field_index <= dex.field_ids_size) ++result->unicode_field_names;
                    ++field_index;
                }
            }
        }
    }
done:
    free(dex.string_offset);
    free(dex.string_value_size);
    free(dex.string_unicode);
}
