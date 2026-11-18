/*
 * CXAPKiD - C port of APKiD (https://github.com/rednaga/APKiD)
 * Copyright (C) 2026 hors <horsicq@gmail.com>
 * SPDX-License-Identifier: MIT
 */
#include "cx_common.h"

#include <stdio.h>
#include <stdlib.h>
#include <string.h>

void cx_out_of_memory(void)
{
    fputs("cxapkid: out of memory\n", stderr);
    exit(1);
}

void *cx_malloc(size_t size)
{
    void *block = malloc(size ? size : 1);
    if (!block) cx_out_of_memory();
    return block;
}

void *cx_calloc(size_t count, size_t size)
{
    void *block = calloc(count ? count : 1, size ? size : 1);
    if (!block) cx_out_of_memory();
    return block;
}

void *cx_realloc(void *block, size_t size)
{
    void *larger = realloc(block, size ? size : 1);
    if (!larger) cx_out_of_memory();
    return larger;
}

char *cx_strndup(const char *text, size_t length)
{
    char *copy = (char *)cx_malloc(length + 1);
    if (length) memcpy(copy, text, length);
    copy[length] = '\0';
    return copy;
}

char *cx_strdup(const char *text)
{
    return cx_strndup(text ? text : "", text ? strlen(text) : 0);
}

char *cx_format(const char *format, ...)
{
    cx_buf buffer = {0};
    va_list args;
    va_start(args, format);
    cx_buf_vprintf(&buffer, format, args);
    va_end(args);
    return cx_buf_detach(&buffer);
}

void cx_buf_free(cx_buf *buffer)
{
    free(buffer->data);
    buffer->data = NULL;
    buffer->length = buffer->capacity = 0;
}

static void cx_buf_reserve(cx_buf *buffer, size_t extra)
{
    size_t needed;
    if (extra > SIZE_MAX - buffer->length - 1) cx_out_of_memory();
    needed = buffer->length + extra + 1;
    if (needed <= buffer->capacity) return;
    size_t capacity = buffer->capacity ? buffer->capacity : 64;
    while (capacity < needed) {
        if (capacity > SIZE_MAX / 2) {
            capacity = needed;
            break;
        }
        capacity *= 2;
    }
    buffer->data = (char *)cx_realloc(buffer->data, capacity);
    buffer->capacity = capacity;
}

void cx_buf_append(cx_buf *buffer, const void *data, size_t length)
{
    cx_buf_reserve(buffer, length);
    if (length) memcpy(buffer->data + buffer->length, data, length);
    buffer->length += length;
    buffer->data[buffer->length] = '\0';
}

void cx_buf_puts(cx_buf *buffer, const char *text)
{
    cx_buf_append(buffer, text, strlen(text));
}

void cx_buf_putc(cx_buf *buffer, char c)
{
    cx_buf_append(buffer, &c, 1);
}

void cx_buf_vprintf(cx_buf *buffer, const char *format, va_list args)
{
    va_list copy;
    int needed;
    va_copy(copy, args);
    needed = vsnprintf(NULL, 0, format, copy);
    va_end(copy);
    if (needed < 0) return;
    cx_buf_reserve(buffer, (size_t)needed);
    vsnprintf(buffer->data + buffer->length, (size_t)needed + 1, format, args);
    buffer->length += (size_t)needed;
}

void cx_buf_printf(cx_buf *buffer, const char *format, ...)
{
    va_list args;
    va_start(args, format);
    cx_buf_vprintf(buffer, format, args);
    va_end(args);
}

char *cx_buf_detach(cx_buf *buffer)
{
    char *data = buffer->data;
    if (!data) data = cx_strdup("");
    buffer->data = NULL;
    buffer->length = buffer->capacity = 0;
    return data;
}

static int cx_ascii_lower(int c)
{
    return (c >= 'A' && c <= 'Z') ? c - 'A' + 'a' : c;
}

bool cx_ends_with_nocase(const char *text, const char *suffix)
{
    size_t text_length = strlen(text), suffix_length = strlen(suffix);
    if (suffix_length > text_length) return false;
    text += text_length - suffix_length;
    for (size_t i = 0; i < suffix_length; ++i)
        if (cx_ascii_lower((unsigned char)text[i]) != cx_ascii_lower((unsigned char)suffix[i])) return false;
    return true;
}

bool cx_starts_with_nocase(const char *text, const char *prefix)
{
    for (; *prefix; ++text, ++prefix) {
        if (!*text) return false;
        if (cx_ascii_lower((unsigned char)*text) != cx_ascii_lower((unsigned char)*prefix)) return false;
    }
    return true;
}

bool cx_is_path_sep(char c)
{
#ifdef _WIN32
    return c == '\\' || c == '/';
#else
    return c == '/';
#endif
}

const char *cx_path_basename(const char *path)
{
    const char *base = path;
#ifdef _WIN32
    /* ntpath.basename drops a drive specification as well. */
    if (path[0] && path[1] == ':') base = path + 2;
#endif
    for (const char *p = base; *p; ++p)
        if (cx_is_path_sep(*p)) base = p + 1;
    return base;
}

char *cx_path_join(const char *left, const char *right)
{
    size_t length = strlen(left);
    if (cx_is_path_sep(right[0])) return cx_strdup(right);
#ifdef _WIN32
    if (length == 2 && left[1] == ':') return cx_format("%s%s", left, right);
#endif
    if (length == 0 || cx_is_path_sep(left[length - 1])) return cx_format("%s%s", left, right);
    return cx_format("%s%c%s", left, CX_PATH_SEP, right);
}

size_t cx_utf8_decode(const uint8_t *text, size_t length, int32_t *code_point)
{
    uint32_t c = text[0], minimum;
    size_t needed;
    *code_point = -1;
    if (c < 0x80) {
        *code_point = (int32_t)c;
        return 1;
    }
    if (c >= 0xC2 && c <= 0xDF) {
        needed = 1;
        c &= 0x1F;
        minimum = 0x80;
    } else if (c >= 0xE0 && c <= 0xEF) {
        needed = 2;
        c &= 0x0F;
        minimum = 0x800;
    } else if (c >= 0xF0 && c <= 0xF4) {
        needed = 3;
        c &= 0x07;
        minimum = 0x10000;
    } else {
        return 1;
    }
    if (length < needed + 1) return 1;
    for (size_t i = 1; i <= needed; ++i) {
        if ((text[i] & 0xC0) != 0x80) return 1;
        c = (c << 6) | (text[i] & 0x3F);
    }
    if (c < minimum || c > 0x10FFFF || (c >= 0xD800 && c <= 0xDFFF)) return 1;
    *code_point = (int32_t)c;
    return needed + 1;
}
