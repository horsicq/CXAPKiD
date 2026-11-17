/*
 * CXAPKiD - C port of APKiD (https://github.com/rednaga/APKiD)
 * Copyright (C) 2026 hors <horsicq@gmail.com>
 * SPDX-License-Identifier: MIT
 *
 * In-memory ZIP reader that follows CPython's zipfile module (3.13): the same
 * end-of-central-directory search, entry list, name decoding and sanitizing,
 * local-header checks, supported methods and CRC verification. APKiD's
 * results depend on which entries zipfile can open, so the reader keeps its
 * decisions. The deliberate differences are listed in docs/PORTING.md.
 */
#ifndef CX_ZIP_H
#define CX_ZIP_H

#include "cx_common.h"

#ifdef __cplusplus
extern "C" {
#endif

#define CX_ZIP_STORED 0
#define CX_ZIP_DEFLATED 8
#define CX_ZIP_BZIP2 12
#define CX_ZIP_LZMA 14
#define CX_ZIP_XZ 95

typedef struct cx_zip_info {
    char *filename;      /* UTF-8, sanitized like ZipInfo.filename */
    char *orig_filename; /* UTF-8, as decoded from the central directory */
    size_t orig_filename_length; /* may contain NUL characters */
    uint16_t flag_bits;
    uint16_t compress_type;
    uint8_t extract_version;
    uint32_t crc;
    uint64_t compress_size;
    uint64_t file_size;
    int64_t header_offset; /* absolute, prepended data included */
    int64_t end_offset;    /* next local header or the central directory */
} cx_zip_info;

typedef struct cx_zip {
    const uint8_t *data;
    size_t size;
    cx_zip_info *infos;
    size_t count;
} cx_zip;

typedef enum cx_zip_status {
    CX_ZIP_OK = 0,
    CX_ZIP_BAD,             /* zipfile.BadZipFile */
    CX_ZIP_OVERLAPPED,      /* BadZipFile("Overlapped entries ...") */
    CX_ZIP_NOT_IMPLEMENTED, /* NotImplementedError: method or flag */
    CX_ZIP_ENCRYPTED,       /* RuntimeError: password required */
    CX_ZIP_DATA_ERROR,      /* zlib/bz2/lzma error or EOFError */
    CX_ZIP_NO_MEMORY        /* decompressed data does not fit in memory */
} cx_zip_status;

/* zipfile.is_zipfile(): an end of central directory record can be found. */
bool cx_zip_is_zipfile(const uint8_t *data, size_t size);

/* zipfile.ZipFile(data). The data must outlive the archive. */
cx_zip_status cx_zip_open(cx_zip *zip, const uint8_t *data, size_t size, char **error);
void cx_zip_close(cx_zip *zip);

/* ZipInfo.is_dir() */
bool cx_zip_info_is_dir(const cx_zip_info *info);

/* The checks of ZipFile.open() for reading, in CPython's order. On success
 * *data_offset is the absolute offset of the member's data. A warning about
 * a member sharing its local header with another one is stored in *warning,
 * also when a later check fails (CPython emits a UserWarning and goes on);
 * the caller frees it. */
cx_zip_status cx_zip_open_entry(const cx_zip *zip, const cx_zip_info *info, uint64_t *data_offset, char **warning,
                                char **error);

/* Who owns the bytes cx_zip_read() returns. */
typedef enum cx_zip_owner {
    CX_ZIP_OWNED,    /* heap memory (malloc) */
    CX_ZIP_BORROWED, /* points into the archive's data */
    CX_ZIP_MAPPED    /* reserved address space */
} cx_zip_owner;

/* Release bytes from cx_zip_read() (nothing for borrowed ones). */
void cx_zip_free(uint8_t *data, cx_zip_owner owner);

/* ZipExtFile.read(): decompress a member opened by cx_zip_open_entry().
 * limit = 0 reads the whole member; a positive limit stops after that many
 * bytes, like read(limit). *complete reports whether the member's end was
 * reached; the CRC-32 is only verified then, as ZipExtFile does.
 * A stored member is not copied: *out then points into the archive's data,
 * which must outlive it, and *owner is CX_ZIP_BORROWED. The caller releases
 * *out with cx_zip_free(*out, *owner). */
cx_zip_status cx_zip_read(const cx_zip *zip, const cx_zip_info *info, uint64_t data_offset, size_t limit, uint8_t **out,
                          size_t *out_size, bool *complete, cx_zip_owner *owner, char **error);

/* The member's raw data as APKiD reads it for XZ members: the local header's
 * name and extra lengths locate the data, compress_size bytes long. */
bool cx_zip_raw_data(const cx_zip *zip, const cx_zip_info *info, const uint8_t **data, size_t *size);

#ifdef __cplusplus
}
#endif

#endif
