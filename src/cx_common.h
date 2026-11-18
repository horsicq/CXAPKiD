/*
 * CXAPKiD - C port of APKiD (https://github.com/rednaga/APKiD)
 * Copyright (C) 2026 hors <horsicq@gmail.com>
 * SPDX-License-Identifier: MIT
 */
#ifndef CX_COMMON_H
#define CX_COMMON_H

#include <stdarg.h>
#include <stdbool.h>
#include <stddef.h>
#include <stdint.h>

#ifdef __cplusplus
extern "C" {
#endif

#ifdef _WIN32
#define CX_PATH_SEP '\\'
#else
#define CX_PATH_SEP '/'
#endif

/* Allocation helpers. A console tool has nothing useful to do when the heap
 * is exhausted while building small bookkeeping structures, so these report
 * and exit. Large, input-driven buffers (decompressed entries, file data)
 * use the plain allocator and fail gracefully instead. */
void cx_out_of_memory(void);
void *cx_malloc(size_t size);
void *cx_calloc(size_t count, size_t size);
void *cx_realloc(void *block, size_t size);
char *cx_strdup(const char *text);
char *cx_strndup(const char *text, size_t length);
char *cx_format(const char *format, ...);

/* Growable byte buffer, always NUL terminated after the first append. */
typedef struct cx_buf {
    char *data;
    size_t length;
    size_t capacity;
} cx_buf;

void cx_buf_free(cx_buf *buffer);
void cx_buf_append(cx_buf *buffer, const void *data, size_t length);
void cx_buf_puts(cx_buf *buffer, const char *text);
void cx_buf_putc(cx_buf *buffer, char c);
void cx_buf_printf(cx_buf *buffer, const char *format, ...);
void cx_buf_vprintf(cx_buf *buffer, const char *format, va_list args);
/* Detach the contents (never NULL) and reset the buffer. */
char *cx_buf_detach(cx_buf *buffer);

/* ASCII-only case helpers used for file name tests. */
bool cx_ends_with_nocase(const char *text, const char *suffix);
bool cx_starts_with_nocase(const char *text, const char *prefix);

/* Python's os.path.basename / os.path.join for the host platform. */
const char *cx_path_basename(const char *path);
char *cx_path_join(const char *left, const char *right);
bool cx_is_path_sep(char c);

/* Decode one UTF-8 code point. Returns the number of bytes consumed (>= 1)
 * and stores the code point, or -1 in *code_point for an invalid sequence
 * (one byte is consumed then). Surrogates and overlong forms are invalid,
 * as in Python's strict UTF-8 codec. */
size_t cx_utf8_decode(const uint8_t *text, size_t length, int32_t *code_point);

#ifdef __cplusplus
}
#endif

#endif
