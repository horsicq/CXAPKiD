/*
 * CXAPKiD - C port of APKiD (https://github.com/rednaga/APKiD)
 * Copyright (C) 2026 hors <horsicq@gmail.com>
 * SPDX-License-Identifier: MIT
 */
#include "cx_zip.h"
#include "cx_sink.h"

#include <xxfclib/algo/bzip2/xx_bzip2.h>
#include <xxfclib/algo/crc/xx_crc.h>
#include <xxfclib/algo/deflate/xx_deflate.h>
#include <xxfclib/algo/lzma/xx_lzma.h>

#include <stdlib.h>
#include <string.h>

#define CX_SIZE_END_CENT_DIR 22
#define CX_SIZE_END_CENT_DIR64 56
#define CX_SIZE_END_CENT_DIR64_LOCATOR 20
#define CX_SIZE_CENTRAL_DIR 46
#define CX_SIZE_FILE_HEADER 30
#define CX_ZIP_MAX_COMMENT 0xFFFF

#define CX_MASK_ENCRYPTED 0x0001
#define CX_MASK_COMPRESSED_PATCH 0x0020
#define CX_MASK_STRONG_ENCRYPTION 0x0040
#define CX_MASK_UTF_FILENAME 0x0800

/* The most output reserved up front for one compressed member. The declared
   size can lie, so it is trusted only this far; a larger member grows from
   here as before. (--entry-max-scan-size is accepted but unused, as in
   APKiD, so it cannot serve as the cap.) */
#define CX_ZIP_RESERVE_MAX ((size_t)16 << 20)

/* CPython's cp437 codec, upper half. The lower half is ASCII. */
static const uint16_t cx_cp437_high[128] = {
    0x00C7, 0x00FC, 0x00E9, 0x00E2, 0x00E4, 0x00E0, 0x00E5, 0x00E7, 0x00EA, 0x00EB, 0x00E8, 0x00EF, 0x00EE, 0x00EC, 0x00C4, 0x00C5,
    0x00C9, 0x00E6, 0x00C6, 0x00F4, 0x00F6, 0x00F2, 0x00FB, 0x00F9, 0x00FF, 0x00D6, 0x00DC, 0x00A2, 0x00A3, 0x00A5, 0x20A7, 0x0192,
    0x00E1, 0x00ED, 0x00F3, 0x00FA, 0x00F1, 0x00D1, 0x00AA, 0x00BA, 0x00BF, 0x2310, 0x00AC, 0x00BD, 0x00BC, 0x00A1, 0x00AB, 0x00BB,
    0x2591, 0x2592, 0x2593, 0x2502, 0x2524, 0x2561, 0x2562, 0x2556, 0x2555, 0x2563, 0x2551, 0x2557, 0x255D, 0x255C, 0x255B, 0x2510,
    0x2514, 0x2534, 0x252C, 0x251C, 0x2500, 0x253C, 0x255E, 0x255F, 0x255A, 0x2554, 0x2569, 0x2566, 0x2560, 0x2550, 0x256C, 0x2567,
    0x2568, 0x2564, 0x2565, 0x2559, 0x2558, 0x2552, 0x2553, 0x256B, 0x256A, 0x2518, 0x250C, 0x2588, 0x2584, 0x258C, 0x2590, 0x2580,
    0x03B1, 0x00DF, 0x0393, 0x03C0, 0x03A3, 0x03C3, 0x00B5, 0x03C4, 0x03A6, 0x0398, 0x03A9, 0x03B4, 0x221E, 0x03C6, 0x03B5, 0x2229,
    0x2261, 0x00B1, 0x2265, 0x2264, 0x2320, 0x2321, 0x00F7, 0x2248, 0x00B0, 0x2219, 0x00B7, 0x221A, 0x207F, 0x00B2, 0x25A0, 0x00A0};

static uint16_t cx_rd16(const uint8_t *p)
{
    return (uint16_t)(p[0] | (p[1] << 8));
}

static uint32_t cx_rd32(const uint8_t *p)
{
    return (uint32_t)p[0] | ((uint32_t)p[1] << 8) | ((uint32_t)p[2] << 16) | ((uint32_t)p[3] << 24);
}

static uint64_t cx_rd64(const uint8_t *p)
{
    return (uint64_t)cx_rd32(p) | ((uint64_t)cx_rd32(p + 4) << 32);
}

/* Decode a member name. CPython raises UnicodeDecodeError for a name whose
 * UTF-8 flag is set but whose bytes are not UTF-8, which aborts the whole
 * archive; invalid bytes become U+FFFD here (see docs/PORTING.md). */
static char *cx_zip_decode_name(const uint8_t *raw, size_t length, bool utf8, size_t *out_length)
{
    cx_buf out = {0};
    cx_buf_append(&out, "", 0);
    for (size_t i = 0; i < length;) {
        if (utf8) {
            int32_t code_point;
            size_t used = cx_utf8_decode(raw + i, length - i, &code_point);
            if (code_point < 0)
                cx_utf8_encode(&out, 0xFFFD);
            else
                cx_buf_append(&out, raw + i, used);
            i += used;
        } else {
            uint8_t c = raw[i++];
            if (c < 0x80)
                cx_buf_putc(&out, (char)c);
            else
                cx_utf8_encode(&out, cx_cp437_high[c - 0x80]);
        }
    }
    *out_length = out.length;
    return cx_buf_detach(&out);
}

/* zipfile._sanitize_filename() */
static char *cx_zip_sanitize(const char *name, size_t length)
{
    size_t end = 0;
    while (end < length && name[end]) ++end;
    char *result = cx_strndup(name, end);
#ifdef _WIN32
    for (char *p = result; *p; ++p)
        if (*p == '\\') *p = '/';
#endif
    return result;
}

static char *cx_zip_repr(const char *text, size_t length)
{
    /* A readable stand-in for Python's repr() in error messages. */
    cx_buf out = {0};
    cx_buf_putc(&out, '\'');
    for (size_t i = 0; i < length; ++i) {
        unsigned char c = (unsigned char)text[i];
        if (c == '\'' || c == '\\')
            cx_buf_printf(&out, "\\%c", c);
        else if (c < 0x20 || c == 0x7F)
            cx_buf_printf(&out, "\\x%02x", c);
        else
            cx_buf_putc(&out, (char)c);
    }
    cx_buf_putc(&out, '\'');
    return cx_buf_detach(&out);
}

typedef struct cx_end_rec {
    bool zip64;
    uint64_t disk_number;
    uint64_t disk_start;
    uint64_t entries_this_disk;
    uint64_t entries_total;
    uint64_t size;
    uint64_t offset;
    uint64_t location;
} cx_end_rec;

static void cx_zip_parse_end(const uint8_t *p, size_t location, cx_end_rec *rec)
{
    memset(rec, 0, sizeof(*rec));
    rec->disk_number = cx_rd16(p + 4);
    rec->disk_start = cx_rd16(p + 6);
    rec->entries_this_disk = cx_rd16(p + 8);
    rec->entries_total = cx_rd16(p + 10);
    rec->size = cx_rd32(p + 12);
    rec->offset = cx_rd32(p + 16);
    rec->location = location;
}

/* zipfile._EndRecData64(): returns false for BadZipFile. */
static bool cx_zip_end_rec64(const uint8_t *data, size_t size, cx_end_rec *rec, char **error)
{
    (void)size;
    if (rec->location < CX_SIZE_END_CENT_DIR64_LOCATOR) return true;
    const uint8_t *locator = data + rec->location - CX_SIZE_END_CENT_DIR64_LOCATOR;
    if (memcmp(locator, "PK\x06\x07", 4) != 0) return true;
    uint32_t disk_number = cx_rd32(locator + 4);
    uint32_t disks = cx_rd32(locator + 16);
    if (disk_number != 0 || disks > 1) {
        if (error) *error = cx_strdup("zipfiles that span multiple disks are not supported");
        return false;
    }
    if (rec->location < CX_SIZE_END_CENT_DIR64_LOCATOR + CX_SIZE_END_CENT_DIR64) {
        if (error) *error = cx_strdup("negative seek value");
        return false;
    }
    const uint8_t *end64 = locator - CX_SIZE_END_CENT_DIR64;
    if (memcmp(end64, "PK\x06\x06", 4) != 0) return true;
    rec->zip64 = true;
    rec->disk_number = cx_rd32(end64 + 16);
    rec->disk_start = cx_rd32(end64 + 20);
    rec->entries_this_disk = cx_rd64(end64 + 24);
    rec->entries_total = cx_rd64(end64 + 32);
    rec->size = cx_rd64(end64 + 40);
    rec->offset = cx_rd64(end64 + 48);
    return true;
}

/* zipfile._EndRecData(): 1 found, 0 not found, -1 BadZipFile. */
static int cx_zip_end_rec(const uint8_t *data, size_t size, cx_end_rec *rec, char **error)
{
    if (size < CX_SIZE_END_CENT_DIR) return 0;
    const uint8_t *tail = data + size - CX_SIZE_END_CENT_DIR;
    if (memcmp(tail, "PK\x05\x06", 4) == 0 && tail[20] == 0 && tail[21] == 0) {
        cx_zip_parse_end(tail, size - CX_SIZE_END_CENT_DIR, rec);
        return cx_zip_end_rec64(data, size, rec, error) ? 1 : -1;
    }
    size_t start = size > (size_t)CX_ZIP_MAX_COMMENT + CX_SIZE_END_CENT_DIR ? size - CX_ZIP_MAX_COMMENT - CX_SIZE_END_CENT_DIR : 0;
    /* data.rfind(stringEndArchive) */
    for (size_t at = size - 4 + 1; at-- > start;) {
        if (data[at] != 'P' || memcmp(data + at, "PK\x05\x06", 4) != 0) continue;
        if (size - at < CX_SIZE_END_CENT_DIR) return 0;
        cx_zip_parse_end(data + at, at, rec);
        return cx_zip_end_rec64(data, size, rec, error) ? 1 : -1;
    }
    return 0;
}

bool cx_zip_is_zipfile(const uint8_t *data, size_t size)
{
    cx_end_rec rec;
    return cx_zip_end_rec(data, size, &rec, NULL) == 1;
}

static cx_zip_status cx_zip_fail(char **error, cx_zip_status status, char *message)
{
    if (error)
        *error = message;
    else
        free(message);
    return status;
}

/* ZipInfo._decodeExtra(). CPython raises BadZipFile for a truncated extra
 * record, which aborts the whole archive; parsing just stops here. */
static void cx_zip_decode_extra(cx_zip_info *info, const uint8_t *extra, size_t length, uint32_t name_crc)
{
    while (length >= 4) {
        uint16_t type = cx_rd16(extra);
        size_t record = cx_rd16(extra + 2);
        if (record + 4 > length) break;
        const uint8_t *p = extra + 4;
        if (type == 0x0001) {
            size_t left = record;
            if (info->file_size == 0xFFFFFFFFu || info->file_size == UINT64_MAX) {
                if (left < 8) goto next;
                info->file_size = cx_rd64(p);
                p += 8;
                left -= 8;
            }
            if (info->compress_size == 0xFFFFFFFFu) {
                if (left < 8) goto next;
                info->compress_size = cx_rd64(p);
                p += 8;
                left -= 8;
            }
            if (info->header_offset == 0xFFFFFFFF) {
                if (left < 8) goto next;
                uint64_t offset = cx_rd64(p);
                info->header_offset = offset > (uint64_t)INT64_MAX ? INT64_MAX : (int64_t)offset;
            }
        } else if (type == 0x7075 && record >= 5) {
            /* Info-ZIP Unicode Path Extra Field */
            if (p[0] == 1 && cx_rd32(p + 1) == name_crc && record > 5) {
                size_t name_length = record - 5, decoded_length;
                char *decoded = cx_zip_decode_name(p + 5, name_length, true, &decoded_length);
                bool valid = true;
                for (size_t i = 0; i < name_length;) {
                    int32_t code_point;
                    i += cx_utf8_decode(p + 5 + i, name_length - i, &code_point);
                    if (code_point < 0) valid = false;
                }
                if (valid) {
                    free(info->filename);
                    info->filename = cx_zip_sanitize(decoded, decoded_length);
                }
                free(decoded);
            }
        }
    next:
        extra += record + 4;
        length -= record + 4;
    }
}

typedef struct cx_zip_order {
    int64_t offset;
    size_t index;
} cx_zip_order;

static int cx_zip_order_compare(const void *a, const void *b)
{
    const cx_zip_order *left = (const cx_zip_order *)a, *right = (const cx_zip_order *)b;
    if (left->offset != right->offset) return left->offset < right->offset ? -1 : 1;
    return left->index < right->index ? -1 : (left->index > right->index);
}

cx_zip_status cx_zip_open(cx_zip *zip, const uint8_t *data, size_t size, char **error)
{
    cx_end_rec rec;
    char *end_error = NULL;
    memset(zip, 0, sizeof(*zip));
    zip->data = data;
    zip->size = size;
    if (error) *error = NULL;

    int found = cx_zip_end_rec(data, size, &rec, &end_error);
    if (found < 0) return cx_zip_fail(error, CX_ZIP_BAD, end_error);
    if (found == 0) return cx_zip_fail(error, CX_ZIP_BAD, cx_strdup("File is not a zip file"));

    /* concat = location - size_cd - offset_cd [- zip64 records];
       start_dir = offset_cd + concat */
    uint64_t trailer = rec.zip64 ? CX_SIZE_END_CENT_DIR64 + CX_SIZE_END_CENT_DIR64_LOCATOR : 0;
    if (rec.size > rec.location || trailer > rec.location - rec.size)
        return cx_zip_fail(error, CX_ZIP_BAD, cx_strdup("Bad offset for central directory"));
    uint64_t start_dir = rec.location - rec.size - trailer;
    int64_t concat = (int64_t)start_dir - (rec.offset > (uint64_t)INT64_MAX ? INT64_MAX : (int64_t)rec.offset);

    const uint8_t *cd = data + start_dir;
    size_t cd_size = (size_t)(rec.size < size - start_dir ? rec.size : size - start_dir);
    size_t capacity = 0, position = 0;
    uint64_t total = 0;
    while (total < rec.size) {
        if (cd_size - position < CX_SIZE_CENTRAL_DIR) {
            cx_zip_close(zip);
            return cx_zip_fail(error, CX_ZIP_BAD, cx_strdup("Truncated central directory"));
        }
        const uint8_t *entry = cd + position;
        if (memcmp(entry, "PK\x01\x02", 4) != 0) {
            cx_zip_close(zip);
            return cx_zip_fail(error, CX_ZIP_BAD, cx_strdup("Bad magic number for central directory"));
        }
        size_t name_length = cx_rd16(entry + 28), extra_length = cx_rd16(entry + 30), comment_length = cx_rd16(entry + 32);
        position += CX_SIZE_CENTRAL_DIR;
        /* io.BytesIO.read() returns short data at the end of the buffer. */
        size_t name_read = name_length < cd_size - position ? name_length : cd_size - position;
        const uint8_t *raw_name = cd + position;
        position += name_read;
        size_t extra_read = extra_length < cd_size - position ? extra_length : cd_size - position;
        const uint8_t *extra = cd + position;
        position += extra_read;
        position += comment_length < cd_size - position ? comment_length : cd_size - position;

        if (zip->count == capacity) {
            capacity = capacity ? capacity * 2 : 16;
            zip->infos = (cx_zip_info *)cx_realloc(zip->infos, capacity * sizeof(*zip->infos));
        }
        cx_zip_info *info = &zip->infos[zip->count++];
        memset(info, 0, sizeof(*info));
        info->flag_bits = cx_rd16(entry + 8);
        info->orig_filename = cx_zip_decode_name(raw_name, name_read, (info->flag_bits & CX_MASK_UTF_FILENAME) != 0,
                                                 &info->orig_filename_length);
        info->filename = cx_zip_sanitize(info->orig_filename, info->orig_filename_length);
        info->extract_version = entry[6];
        info->compress_type = cx_rd16(entry + 10);
        info->crc = cx_rd32(entry + 16);
        info->compress_size = cx_rd32(entry + 20);
        info->file_size = cx_rd32(entry + 24);
        info->header_offset = cx_rd32(entry + 42);
        /* CPython rejects extract_version > 63 with NotImplementedError for
           the whole archive; the field is ignored here (docs/PORTING.md). */
        cx_zip_decode_extra(info, extra, extra_read, xx_crc32_calc(0, raw_name, name_read));
        info->header_offset += concat;
        total += CX_SIZE_CENTRAL_DIR + name_length + extra_length + comment_length;
    }

    /* end_offset: the start of the next local header in offset order. */
    if (zip->count) {
        cx_zip_order *order = (cx_zip_order *)cx_malloc(zip->count * sizeof(*order));
        for (size_t i = 0; i < zip->count; ++i) {
            order[i].offset = zip->infos[i].header_offset;
            order[i].index = i;
        }
        qsort(order, zip->count, sizeof(*order), cx_zip_order_compare);
        int64_t end_offset = (int64_t)start_dir;
        for (size_t i = zip->count; i-- > 0;) {
            zip->infos[order[i].index].end_offset = end_offset;
            end_offset = order[i].offset;
        }
        free(order);
    }
    return CX_ZIP_OK;
}

void cx_zip_close(cx_zip *zip)
{
    for (size_t i = 0; i < zip->count; ++i) {
        free(zip->infos[i].filename);
        free(zip->infos[i].orig_filename);
    }
    free(zip->infos);
    zip->infos = NULL;
    zip->count = 0;
}

bool cx_zip_info_is_dir(const cx_zip_info *info)
{
    size_t length = strlen(info->filename);
    if (!length) return false;
#ifdef _WIN32
    return info->filename[length - 1] == '/' || info->filename[length - 1] == '\\';
#else
    return info->filename[length - 1] == '/';
#endif
}

cx_zip_status cx_zip_open_entry(const cx_zip *zip, const cx_zip_info *info, uint64_t *data_offset, char **warning,
                                char **error)
{
    if (warning) *warning = NULL;
    if (error) *error = NULL;
    if (info->header_offset < 0 || (uint64_t)info->header_offset > zip->size ||
        zip->size - (size_t)info->header_offset < CX_SIZE_FILE_HEADER)
        return cx_zip_fail(error, CX_ZIP_BAD, cx_strdup("Truncated file header"));
    const uint8_t *header = zip->data + info->header_offset;
    if (memcmp(header, "PK\x03\x04", 4) != 0)
        return cx_zip_fail(error, CX_ZIP_BAD, cx_strdup("Bad magic number for file header"));
    size_t name_length = cx_rd16(header + 26), extra_length = cx_rd16(header + 28);
    size_t available = zip->size - (size_t)info->header_offset - CX_SIZE_FILE_HEADER;
    size_t name_read = name_length < available ? name_length : available;
    uint64_t position = (uint64_t)info->header_offset + CX_SIZE_FILE_HEADER + name_read + extra_length;

    if (info->flag_bits & CX_MASK_COMPRESSED_PATCH)
        return cx_zip_fail(error, CX_ZIP_NOT_IMPLEMENTED, cx_strdup("compressed patched data (flag bit 5)"));
    if (info->flag_bits & CX_MASK_STRONG_ENCRYPTION)
        return cx_zip_fail(error, CX_ZIP_NOT_IMPLEMENTED, cx_strdup("strong encryption (flag bit 6)"));

    size_t local_length;
    char *local_name = cx_zip_decode_name(header + CX_SIZE_FILE_HEADER, name_read,
                                          (cx_rd16(header + 6) & CX_MASK_UTF_FILENAME) != 0, &local_length);
    bool same = local_length == info->orig_filename_length && memcmp(local_name, info->orig_filename, local_length) == 0;
    if (!same) {
        char *directory = cx_zip_repr(info->orig_filename, info->orig_filename_length);
        char *local = cx_zip_repr(local_name, local_length);
        char *message = cx_format("File name in directory %s and header %s differ.", directory, local);
        free(directory);
        free(local);
        free(local_name);
        return cx_zip_fail(error, CX_ZIP_BAD, message);
    }
    free(local_name);

    if (position + info->compress_size < position || (int64_t)(position + info->compress_size) > info->end_offset ||
        position + info->compress_size > (uint64_t)INT64_MAX) {
        char *name = cx_zip_repr(info->orig_filename, info->orig_filename_length);
        char *message = cx_format("Overlapped entries: %s (possible zip bomb)", name);
        free(name);
        if (info->end_offset != info->header_offset) return cx_zip_fail(error, CX_ZIP_OVERLAPPED, message);
        if (warning)
            *warning = message;
        else
            free(message);
    }

    if (info->flag_bits & CX_MASK_ENCRYPTED) {
        char *name = cx_zip_repr(info->filename, strlen(info->filename));
        char *message = cx_format("File %s is encrypted, password required for extraction", name);
        free(name);
        return cx_zip_fail(error, CX_ZIP_ENCRYPTED, message);
    }
    if (info->compress_type != CX_ZIP_STORED && info->compress_type != CX_ZIP_DEFLATED &&
        info->compress_type != CX_ZIP_BZIP2 && info->compress_type != CX_ZIP_LZMA) {
        return cx_zip_fail(error, CX_ZIP_NOT_IMPLEMENTED, cx_strdup("That compression method is not supported"));
    }
    *data_offset = position;
    return CX_ZIP_OK;
}

/* `crc` is the CRC-32 of the member's bytes. */
static cx_zip_status cx_zip_check_crc(const cx_zip_info *info, uint32_t crc, char **error)
{
    if (crc == info->crc) return CX_ZIP_OK;
    char *name = cx_zip_repr(info->filename, strlen(info->filename));
    char *message = cx_format("Bad CRC-32 for file %s", name);
    free(name);
    return cx_zip_fail(error, CX_ZIP_BAD, message);
}

void cx_zip_free(uint8_t *data, cx_zip_owner owner)
{
    if (owner != CX_ZIP_BORROWED) cx_sink_release(data, owner == CX_ZIP_MAPPED);
}

/* The most output a member's data can decompress to, for the reservation
   only: Deflate expands at most 1032:1. Others can go further; their output
   then moves from the reservation to the heap (one copy). */
static size_t cx_zip_output_bound(size_t input_size)
{
    size_t slack = (size_t)1 << 20;
    if (input_size > (SIZE_MAX - slack) / 1032) return SIZE_MAX;
    return input_size * 1032 + slack;
}

cx_zip_status cx_zip_read(const cx_zip *zip, const cx_zip_info *info, uint64_t data_offset, size_t limit, uint8_t **out,
                          size_t *out_size, bool *complete, cx_zip_owner *owner, char **error)
{
    *out = NULL;
    *out_size = 0;
    *complete = false;
    *owner = CX_ZIP_OWNED;
    if (error) *error = NULL;

    size_t available = data_offset < zip->size ? zip->size - (size_t)data_offset : 0;
    const uint8_t *input = zip->data + (data_offset < zip->size ? data_offset : zip->size);
    bool input_truncated = info->compress_size > available;
    size_t input_size = input_truncated ? available : (size_t)info->compress_size;
    size_t target = info->file_size > SIZE_MAX ? SIZE_MAX : (size_t)info->file_size;
    size_t cap = (limit && limit < target) ? limit : target;
    bool limited = cap < target;

    if (info->compress_type == CX_ZIP_STORED) {
        uint64_t total = info->compress_size < info->file_size ? info->compress_size : info->file_size;
        size_t wanted = total < cap ? (size_t)total : cap;
        if (wanted > available) return cx_zip_fail(error, CX_ZIP_DATA_ERROR, cx_strdup("EOFError"));
        /* The bytes already sit uncompressed in the archive: hand them out
           in place, no copy. The CRC-32 checks the very same bytes. */
        *out = (uint8_t *)input;
        *owner = CX_ZIP_BORROWED;
        *out_size = wanted;
        *complete = wanted == total;
        if (!*complete) return CX_ZIP_OK;
        cx_zip_status status = cx_zip_check_crc(info, xx_crc32_calc(0, input, wanted), error);
        if (status != CX_ZIP_OK) {
            *out = NULL;
            *out_size = 0;
            *owner = CX_ZIP_OWNED;
        }
        return status;
    }

    cx_sink sink;
    cx_sink_init(&sink, cap);
    sink.checksum = true;
    /* One allocation of the declared size instead of growing by doubling.
       A larger member gets address space for as much as its data can
       plausibly hold, committed as the output arrives: a lying size costs
       no memory, and the output is never copied while it grows. */
    size_t plausible = cx_zip_output_bound(input_size);
    if (plausible > cap) plausible = cap;
    if (plausible <= CX_ZIP_RESERVE_MAX || !cx_sink_reserve_space(&sink, plausible))
        cx_sink_reserve(&sink, cap < CX_ZIP_RESERVE_MAX ? cap : CX_ZIP_RESERVE_MAX);
    bool ok = false;
    if (cap == 0) {
        ok = true; /* nothing is kept from a member declared empty */
    } else if (info->compress_type == CX_ZIP_DEFLATED) {
        size_t consumed = 0;
        ok = input_size && xx_deflate_unpack_memory_to_device_ex(input, input_size, &sink.device, &consumed, false, NULL);
    } else if (info->compress_type == CX_ZIP_BZIP2) {
        size_t consumed = 0;
        ok = input_size && xx_bzip2_unpack_memory_to_device_ex(input, input_size, &sink.device, &consumed, NULL);
    } else if (info->compress_type == CX_ZIP_LZMA) {
        /* zipfile.LZMADecompressor: version (2), properties size (2),
           LZMA1 properties, then the raw stream. */
        if (input_size > 4) {
            size_t props_size = cx_rd16(input + 2);
            if (input_size > 4 + props_size) {
                if (props_size != 5) {
                    cx_sink_free(&sink);
                    return cx_zip_fail(error, CX_ZIP_DATA_ERROR, cx_strdup("Invalid or unsupported options"));
                }
                int64_t expected = (info->flag_bits & 0x0002) ? -1 : (int64_t)info->file_size;
                ok = xx_lzma_unpack_memory_to_device(input + 4 + props_size, input_size - 4 - props_size, input + 4,
                                                     props_size, expected, &sink.device, NULL);
            }
        }
    }

    if (sink.no_memory) {
        cx_sink_free(&sink);
        return cx_zip_fail(error, CX_ZIP_NO_MEMORY, cx_strdup("out of memory"));
    }
    if (!sink.full && !ok && input_truncated) {
        cx_sink_free(&sink);
        return cx_zip_fail(error, CX_ZIP_DATA_ERROR, cx_strdup("EOFError"));
    }
    /* A decoder failure without truncated input: CPython either raised a
       decompressor error or reached the end of the member's data, and in
       the latter case the CRC-32 decides. Both end the same way unless the
       partial output is exactly the member, which the CRC check accepts. */
    bool full = sink.full, mapped = false;
    uint32_t crc = sink.crc;
    *out = cx_sink_detach(&sink, out_size, &mapped);
    if (!*out) return cx_zip_fail(error, CX_ZIP_NO_MEMORY, cx_strdup("out of memory"));
    *owner = mapped ? CX_ZIP_MAPPED : CX_ZIP_OWNED;
    *complete = !(full && limited);
    if (!*complete) return CX_ZIP_OK;
    /* The sink's CRC-32 covers exactly the *out_size bytes it kept. */
    cx_zip_status status = cx_zip_check_crc(info, crc, error);
    if (status != CX_ZIP_OK) {
        if (!ok && !full) {
            free(*error);
            *error = cx_strdup("invalid compressed data");
            status = CX_ZIP_DATA_ERROR;
        }
        cx_zip_free(*out, *owner);
        *out = NULL;
        *out_size = 0;
        *owner = CX_ZIP_OWNED;
    }
    return status;
}

bool cx_zip_raw_data(const cx_zip *zip, const cx_zip_info *info, const uint8_t **data, size_t *size)
{
    if (info->header_offset < 0 || (uint64_t)info->header_offset > zip->size ||
        zip->size - (size_t)info->header_offset < CX_SIZE_FILE_HEADER)
        return false;
    const uint8_t *header = zip->data + info->header_offset;
    uint64_t offset = (uint64_t)info->header_offset + CX_SIZE_FILE_HEADER + cx_rd16(header + 26) + cx_rd16(header + 28);
    if (offset > zip->size) offset = zip->size;
    size_t available = zip->size - (size_t)offset;
    *data = zip->data + offset;
    *size = info->compress_size < available ? (size_t)info->compress_size : available;
    return true;
}
