/*
 * CXAPKiD - C port of APKiD (https://github.com/rednaga/APKiD)
 * Copyright (C) 2026 hors <horsicq@gmail.com>
 * SPDX-License-Identifier: MIT
 */
#include "cx_apkid.h"

#include <xxfclib/io/xx_io.h>
#include <xxfclib/terminal/xx_terminal.h>

#include <stdio.h>
#include <stdlib.h>
#include <string.h>

/* ------------------------------------------------------------- colors */

/* Colored console text is printed through xxfclib's terminal module, which
 * detects the terminal (redirected output stays plain), uses ANSI sequences
 * or native Windows console attributes, and restores the console when done.
 * Console text is built ahead of printing (and parallel jobs keep it in
 * their logs), so a colored span is marked in the text: CX_MARK followed by
 * 'a' + color index starts it, CX_MARK '.' ends it, and CX_MARK CX_MARK is
 * a literal CX_MARK byte. Text only carries marks when colors are on. */
#define CX_MARK '\001'
#define CX_UNSET UINT32_MAX

typedef struct cx_color {
    uint32_t foreground, background; /* 0xRRGGBB or CX_UNSET */
} cx_color;

/* APKiD's ANSI codes as the xxfclib palette colors that print as those codes
 * (compiler 36, manipulator 96, abnormal 97 -> 37, anti_* 95, packer 91,
 * obfuscator 93, dropper 92, embedded 94, file_type 33, internal 35); the
 * 256-color ones (tracker 208, the file name's background 240) exactly. */
static const cx_color cx_colors[] = {
    {0x585858U, CX_UNSET}, /* 0: unused as a foreground */
    {0x00FFFFU, CX_UNSET}, /* 1 compiler */
    {0x008080U, CX_UNSET}, /* 2 manipulator */
    {0xFFFFFFU, CX_UNSET}, /* 3 abnormal */
    {0x800080U, CX_UNSET}, /* 4 anti_vm, anti_disassembly, anti_debug, anti_root */
    {0x800000U, CX_UNSET}, /* 5 packer, protector, anticheat */
    {0x808000U, CX_UNSET}, /* 6 obfuscator */
    {0x008000U, CX_UNSET}, /* 7 dropper */
    {0x000080U, CX_UNSET}, /* 8 embedded */
    {0xFFFF00U, CX_UNSET}, /* 9 file_type */
    {0xFF00FFU, CX_UNSET}, /* 10 internal */
    {0xFF8700U, CX_UNSET}, /* 11 tracker */
    {CX_UNSET, 0x585858U}, /* 12 file name (background) */
};
#define CX_COLOR_KEY 12

static xx_terminal_state cx_terminal;
static bool cx_terminal_ready;

/* colorize_tag(): the color index of a tag, 0 for none. */
static int cx_tag_color(const char *tag)
{
    if (strcmp(tag, "compiler") == 0) return 1;
    if (strcmp(tag, "manipulator") == 0) return 2;
    if (strcmp(tag, "abnormal") == 0) return 3;
    if (strcmp(tag, "anti_vm") == 0 || strcmp(tag, "anti_disassembly") == 0 || strcmp(tag, "anti_debug") == 0 || strcmp(tag, "anti_root") == 0) return 4;
    if (strcmp(tag, "packer") == 0 || strcmp(tag, "protector") == 0 || strcmp(tag, "anticheat") == 0) return 5;
    if (strcmp(tag, "obfuscator") == 0) return 6;
    if (strcmp(tag, "dropper") == 0) return 7;
    if (strcmp(tag, "embedded") == 0) return 8;
    if (strcmp(tag, "file_type") == 0) return 9;
    if (strcmp(tag, "internal") == 0) return 10;
    if (strcmp(tag, "tracker") == 0) return 11;
    return 0;
}

/* Text with every CX_MARK byte doubled. */
static void cx_buf_put_text(cx_buf *out, const char *text)
{
    for (const char *mark; (mark = strchr(text, CX_MARK)) != NULL; text = mark + 1) {
        cx_buf_append(out, text, (size_t)(mark - text) + 1);
        cx_buf_putc(out, CX_MARK);
    }
    cx_buf_puts(out, text);
}

static void cx_buf_put_colored(cx_buf *out, int color, const char *text)
{
    cx_buf_putc(out, CX_MARK);
    cx_buf_putc(out, (char)('a' + color));
    cx_buf_put_text(out, text);
    cx_buf_putc(out, CX_MARK);
    cx_buf_putc(out, '.');
}

/* Print marked text: plain runs and colored spans in order. */
static void cx_print_marked(const char *text)
{
    cx_buf run = {0};
    int color = -1;
    cx_buf_append(&run, "", 0);
    for (const char *p = text;; ++p) {
        bool end = *p == '\0';
        if (!end && *p != CX_MARK) {
            cx_buf_putc(&run, *p);
            continue;
        }
        if (!end && p[1] == CX_MARK) {
            cx_buf_putc(&run, CX_MARK);
            ++p;
            continue;
        }
        if (run.length) {
            if (color >= 0)
                (void)xx_terminal_write_color_ex(&cx_terminal, run.data, run.length, cx_colors[color].foreground, cx_colors[color].background, XX_TERMINAL_COLOR_EXACT);
            else (void)xx_terminal_write(&cx_terminal, run.data, run.length);
            run.length = 0;
        }
        if (end || p[1] == '\0') break;
        ++p;
        color = *p == '.' ? -1 : *p - 'a';
        if (color >= (int)(sizeof(cx_colors) / sizeof(cx_colors[0]))) color = -1;
    }
    cx_buf_free(&run);
    (void)xx_terminal_flush(&cx_terminal);
}

void cx_output_init(cx_output *output, const cx_options *options, const char *rules_sha256)
{
    memset(output, 0, sizeof(*output));
    output->options = options;
    output->rules_sha256 = rules_sha256;
    /* sys.stdout.isatty(): xxfclib decides whether stdout is a terminal that
       shows colors (and how); JSON and output-dir runs never color. */
    if (!options->json && !options->output_dir && xx_is_color_output_enabled()) {
        cx_terminal = xx_terminal_init(XX_TERMINAL_STDOUT);
        cx_terminal_ready = true;
        output->colorize = cx_terminal.type != XX_TERMINAL_TYPE_NONE;
    }
}

void cx_output_finish(cx_output *output)
{
    (void)output;
    if (!cx_terminal_ready) return;
    fflush(stdout);
    xx_terminal_finish(&cx_terminal);
    cx_terminal_ready = false;
}

/* ------------------------------------------------- _build_match_results() */

typedef struct cx_group {
    char *tags;                    /* ', '.join(sorted(m.tags)) */
    const cx_match **descriptions; /* the matches whose description is listed */
    size_t count;
} cx_group;

typedef struct cx_groups {
    cx_group *items;
    size_t count;
} cx_groups;

static bool cx_has_tag(const cx_match *match, const char *tag)
{
    for (size_t i = 0; i < match->tag_count; ++i)
        if (strcmp(match->tags[i], tag) == 0) return true;
    return false;
}

/* A rule without a description shows its name. */
static const char *cx_description_text(const cx_match *match)
{
    return match->description ? match->description : match->rule;
}

/* `description not in results[tags]`, Python's ==: text equals text, and a
 * number equals a number of the same value, True being 1 and False 0. */
static bool cx_same_description(const cx_match *a, const cx_match *b)
{
    bool a_number = a->description && a->description_kind != CX_DESCRIPTION_TEXT;
    bool b_number = b->description && b->description_kind != CX_DESCRIPTION_TEXT;
    if (a_number != b_number) return false;
    if (a_number) return a->description_number == b->description_number;
    return strcmp(cx_description_text(a), cx_description_text(b)) == 0;
}

/* json.dumps() of a description: a string, a number, or true/false. */
static void cx_json_description(cx_buf *out, const cx_match *match)
{
    if (!match->description || match->description_kind == CX_DESCRIPTION_TEXT) cx_json_string(out, cx_description_text(match));
    else if (match->description_kind == CX_DESCRIPTION_BOOLEAN) cx_buf_puts(out, match->description_number ? "true" : "false");
    else cx_buf_printf(out, "%lld", (long long)match->description_number);
}

static void cx_build_groups(const cx_options *options, const cx_match_list *matches, cx_groups *groups)
{
    memset(groups, 0, sizeof(*groups));
    for (size_t i = 0; i < matches->count; ++i) {
        const cx_match *match = &matches->items[i];
        if (cx_has_tag(match, "file_type") && !options->include_types) continue;
        if (cx_has_tag(match, "tracker") && !options->include_trackers) continue;
        cx_buf tags = {0};
        cx_buf_append(&tags, "", 0);
        for (size_t t = 0; t < match->tag_count; ++t) {
            if (t) cx_buf_puts(&tags, ", ");
            cx_buf_puts(&tags, match->tags[t]);
        }
        cx_group *group = NULL;
        for (size_t g = 0; g < groups->count; ++g)
            if (strcmp(groups->items[g].tags, tags.data) == 0) group = &groups->items[g];
        if (!group) {
            groups->items = (cx_group *)cx_realloc(groups->items, (groups->count + 1) * sizeof(*groups->items));
            group = &groups->items[groups->count++];
            group->tags = cx_buf_detach(&tags);
            group->descriptions = NULL;
            group->count = 0;
        } else {
            cx_buf_free(&tags);
        }
        bool seen = false;
        for (size_t d = 0; d < group->count && !seen; ++d) seen = cx_same_description(group->descriptions[d], match);
        if (!seen) {
            group->descriptions = (const cx_match **)cx_realloc((void *)group->descriptions, (group->count + 1) * sizeof(cx_match *));
            group->descriptions[group->count++] = match;
        }
    }
}

static void cx_free_groups(cx_groups *groups)
{
    for (size_t g = 0; g < groups->count; ++g) {
        free(groups->items[g].tags);
        free((void *)groups->items[g].descriptions);
    }
    free(groups->items);
    memset(groups, 0, sizeof(*groups));
}

/* The console lists descriptions sorted by their text. */
static int cx_compare_descriptions(const void *a, const void *b)
{
    return strcmp(cx_description_text(*(const cx_match *const *)a), cx_description_text(*(const cx_match *const *)b));
}

static int cx_compare_groups(const void *a, const void *b)
{
    return strcmp(((const cx_group *)a)->tags, ((const cx_group *)b)->tags);
}

/* ---------------------------------------------------------------- JSON */

/* json.dumps() string with ensure_ascii=True. Bytes that are not UTF-8 are
 * written as lone surrogates, as Python's surrogateescape would. */
void cx_json_string(cx_buf *out, const char *text)
{
    const uint8_t *p = (const uint8_t *)text;
    size_t length = strlen(text);
    cx_buf_putc(out, '"');
    for (size_t i = 0; i < length;) {
        int32_t code_point;
        size_t used = cx_utf8_decode(p + i, length - i, &code_point);
        if (code_point < 0) code_point = 0xDC00 + p[i];
        i += used;
        switch (code_point) {
            case '"': cx_buf_puts(out, "\\\""); continue;
            case '\\': cx_buf_puts(out, "\\\\"); continue;
            case '\n': cx_buf_puts(out, "\\n"); continue;
            case '\r': cx_buf_puts(out, "\\r"); continue;
            case '\t': cx_buf_puts(out, "\\t"); continue;
            case '\b': cx_buf_puts(out, "\\b"); continue;
            case '\f': cx_buf_puts(out, "\\f"); continue;
            default: break;
        }
        if (code_point >= 0x20 && code_point <= 0x7E) {
            cx_buf_putc(out, (char)code_point);
        } else if (code_point > 0xFFFF) {
            uint32_t value = (uint32_t)code_point - 0x10000;
            cx_buf_printf(out, "\\u%04x\\u%04x", 0xD800 + (value >> 10), 0xDC00 + (value & 0x3FF));
        } else {
            cx_buf_printf(out, "\\u%04x", (unsigned)code_point);
        }
    }
    cx_buf_putc(out, '"');
}

/* build_json_output(), serialized as json.dumps(output, sort_keys=...) */
static char *cx_build_json(const cx_output *output, const cx_results *results, bool sort_keys)
{
    cx_buf out = {0};
    cx_buf files = {0};
    bool first_file = true;

    cx_buf_puts(&files, "[");
    for (size_t r = 0; r < results->count; ++r) {
        cx_groups groups;
        cx_build_groups(output->options, &results->items[r].matches, &groups);
        if (!groups.count) {
            cx_free_groups(&groups);
            continue;
        }
        if (sort_keys) qsort(groups.items, groups.count, sizeof(*groups.items), cx_compare_groups);
        if (!first_file) cx_buf_puts(&files, ", ");
        first_file = false;
        cx_buf_puts(&files, "{\"filename\": ");
        cx_json_string(&files, results->items[r].key);
        cx_buf_puts(&files, ", \"matches\": {");
        for (size_t g = 0; g < groups.count; ++g) {
            if (g) cx_buf_puts(&files, ", ");
            cx_json_string(&files, groups.items[g].tags);
            cx_buf_puts(&files, ": [");
            for (size_t d = 0; d < groups.items[g].count; ++d) {
                if (d) cx_buf_puts(&files, ", ");
                cx_json_description(&files, groups.items[g].descriptions[d]);
            }
            cx_buf_puts(&files, "]");
        }
        cx_buf_puts(&files, "}}");
        cx_free_groups(&groups);
    }
    cx_buf_puts(&files, "]");

    cx_buf_puts(&out, "{\"apkid_version\": ");
    cx_json_string(&out, CXAPKID_APKID_VERSION);
    if (sort_keys) {
        cx_buf_puts(&out, ", \"files\": ");
        cx_buf_append(&out, files.data, files.length);
        cx_buf_puts(&out, ", \"rules_sha256\": ");
        cx_json_string(&out, output->rules_sha256);
    } else {
        cx_buf_puts(&out, ", \"rules_sha256\": ");
        cx_json_string(&out, output->rules_sha256);
        cx_buf_puts(&out, ", \"files\": ");
        cx_buf_append(&out, files.data, files.length);
    }
    cx_buf_puts(&out, "}");
    cx_buf_free(&files);
    return cx_buf_detach(&out);
}

/* ------------------------------------------------------------- writing */

static void cx_render_console(cx_output *output, const cx_results *results, cx_buf *out)
{
    for (size_t r = 0; r < results->count; ++r) {
        cx_groups groups;
        cx_build_groups(output->options, &results->items[r].matches, &groups);
        if (!groups.count) {
            cx_free_groups(&groups);
            continue;
        }
        qsort(groups.items, groups.count, sizeof(*groups.items), cx_compare_groups);
        if (output->colorize) {
            cx_buf_puts(out, "[*] ");
            cx_buf_put_colored(out, CX_COLOR_KEY, results->items[r].key);
            cx_buf_putc(out, '\n');
        } else {
            cx_buf_printf(out, "[*] %s\n", results->items[r].key);
        }
        for (size_t g = 0; g < groups.count; ++g) {
            cx_group *group = &groups.items[g];
            qsort((void *)group->descriptions, group->count, sizeof(cx_match *), cx_compare_descriptions);
            cx_buf_puts(out, " |-> ");
            if (output->colorize) {
                /* _colorize_tags(): color each tag of the group */
                const char *tag = group->tags;
                while (*tag) {
                    const char *end = strstr(tag, ", ");
                    size_t length = end ? (size_t)(end - tag) : strlen(tag);
                    char *name = cx_strndup(tag, length);
                    int color = cx_tag_color(name);
                    if (color) cx_buf_put_colored(out, color, name);
                    else cx_buf_put_text(out, name);
                    free(name);
                    if (!end) break;
                    cx_buf_puts(out, ", ");
                    tag = end + 2;
                }
            } else {
                cx_buf_puts(out, group->tags);
            }
            cx_buf_puts(out, " : ");
            for (size_t d = 0; d < group->count; ++d) {
                if (d) cx_buf_puts(out, ", ");
                if (output->colorize) cx_buf_put_text(out, cx_description_text(group->descriptions[d]));
                else cx_buf_puts(out, cx_description_text(group->descriptions[d]));
            }
            cx_buf_putc(out, '\n');
        }
        cx_free_groups(&groups);
    }
}

/* Map an input path below output_dir. Strip its root and current-directory
 * components, but refuse parent traversal instead of writing outside it. */
static char *cx_output_path(const char *output_dir, const char *base_file)
{
    char *path = cx_strdup(output_dir);
    const char *part = base_file;
#ifdef _WIN32
    if (part[0] && part[1] == ':') part += 2;
#endif
    for (;;) {
        const char *end = part;
        while (*end && !cx_is_path_sep(*end)) ++end;
        size_t length = (size_t)(end - part);
        bool skip = length == 0 || (length == 1 && part[0] == '.');
        bool invalid = length == 2 && part[0] == '.' && part[1] == '.';
#ifdef _WIN32
        /* Win32 normalizes trailing dots/spaces and interprets colons as
           drives or alternate streams, so do not allow those aliases. */
        if (!skip && (part[length - 1] == '.' || part[length - 1] == ' ' || memchr(part, ':', length))) invalid = true;
#endif
        if (invalid) {
            free(path);
            return NULL;
        }
        if (!skip) {
            char *name = cx_strndup(part, length);
            char *joined = cx_path_join(path, name);
            free(name);
            free(path);
            path = joined;
        }
        if (!*end) break;
        part = end + 1;
    }
    return path;
}

static void cx_write_output_dir(cx_output *output, const cx_results *results, cx_log *log)
{
    /* The shortest key is the scanned file itself. */
    const char *base_file = results->items[0].key;
    for (size_t r = 1; r < results->count; ++r)
        if (strlen(results->items[r].key) < strlen(base_file)) base_file = results->items[r].key;
    char *out_file = cx_output_path(output->options->output_dir, base_file);
    if (!out_file) {
        cx_log_emit(log, 2, cx_format("cxapkid: %s: unsafe output path\n", base_file));
        output->failed = true;
        return;
    }
    char *json = cx_build_json(output, results, false);
    const char *filename = cx_path_basename(out_file);
    char *parent = filename == out_file ? cx_strdup(".") : cx_strndup(out_file, (size_t)(filename - out_file));
    xx_io_device *device = NULL;
    /* Also prevent existing links below the output directory from redirecting
       writes. The I/O scope handles both symlinks and Windows reparse points. */
    xx_io_extract_scope scope = {0};
    bool scoped = xx_io_extract_begin(&scope, output->options->output_dir);
    /* Validate the directory itself: the file-parent fast path on Windows
       can otherwise miss a junction higher up an existing parent path. */
    if (!scoped || !xx_io_create_dirs_a(parent, true) || !(device = xx_io_file_open(out_file, "wb")) ||
        xx_io_write(device, json, strlen(json)) != (ssize_t)strlen(json)) {
        cx_log_emit(log, 2, cx_format("cxapkid: %s: could not write results\n", out_file));
        output->failed = true;
    }
    if (device) xx_io_close(device);
    if (scoped) xx_io_extract_end(&scope);
    free(parent);
    free(json);
    free(out_file);
}

void cx_output_write(cx_output *output, const cx_results *results, cx_log *log)
{
    if (output->options->output_dir) {
        cx_write_output_dir(output, results, log);
    } else if (output->options->json) {
        char *json = cx_build_json(output, results, true);
        cx_buf line = {0};
        cx_buf_puts(&line, json);
        cx_buf_putc(&line, '\n');
        free(json);
        cx_log_emit(log, 1, cx_buf_detach(&line));
    } else {
        cx_buf text = {0};
        /* Marked text starts with CX_MARK '!' (see cx_log_print). */
        if (output->colorize) {
            cx_buf_putc(&text, CX_MARK);
            cx_buf_putc(&text, '!');
        }
        size_t start = text.length;
        cx_render_console(output, results, &text);
        if (text.length > start) cx_log_emit(log, 1, cx_buf_detach(&text));
        else cx_buf_free(&text);
    }
}

/* ---------------------------------------------------------------- logs */

static void cx_log_print(int stream, const char *text)
{
    if (stream == 2) {
        fflush(stdout);
        fputs(text, stderr);
        fflush(stderr);
    } else if (text[0] == CX_MARK && text[1] == '!' && cx_terminal_ready) {
        fflush(stdout);
        cx_print_marked(text + 2);
    } else {
        fputs(text, stdout);
        fflush(stdout);
    }
}

void cx_log_emit(cx_log *log, int stream, char *text)
{
    if (!log) {
        cx_log_print(stream, text);
        free(text);
        return;
    }
    if (log->count == log->capacity) {
        log->capacity = log->capacity ? log->capacity * 2 : 8;
        log->items = (cx_log_entry *)cx_realloc(log->items, log->capacity * sizeof(*log->items));
    }
    log->items[log->count].stream = stream;
    log->items[log->count].text = text;
    log->items[log->count].record = NULL;
    ++log->count;
}

void cx_log_print_text(int stream, const char *text)
{
    cx_log_print(stream, text);
}

void cx_log_flush(cx_log *log)
{
    for (size_t i = 0; i < log->count; ++i) {
        if (log->items[i].stream) cx_log_print(log->items[i].stream, log->items[i].text);
        free(log->items[i].text);
    }
    free(log->items);
    memset(log, 0, sizeof(*log));
}

/* ------------------------------------------------------- _print_matches */

static bool cx_name_in(const cx_name_set *set, const char *name)
{
    for (size_t i = 0; i < set->count; ++i)
        if (strcmp(set->items[i], name) == 0) return true;
    return false;
}

/* repr(bytes) */
static void cx_bytes_repr(cx_buf *out, const uint8_t *data, size_t length)
{
    char quote = '\'';
    if (memchr(data, '\'', length) && !memchr(data, '"', length)) quote = '"';
    cx_buf_putc(out, 'b');
    cx_buf_putc(out, quote);
    for (size_t i = 0; i < length; ++i) {
        uint8_t c = data[i];
        if (c == (uint8_t)quote || c == '\\') cx_buf_printf(out, "\\%c", c);
        else if (c == '\t') cx_buf_puts(out, "\\t");
        else if (c == '\n') cx_buf_puts(out, "\\n");
        else if (c == '\r') cx_buf_puts(out, "\\r");
        else if (c < 0x20 || c >= 0x7F) cx_buf_printf(out, "\\x%02x", c);
        else cx_buf_putc(out, (char)c);
    }
    cx_buf_putc(out, quote);
}

void cx_output_format_matches(const cx_options *options, const char *name, const cx_match_list *matches, cx_buf *out)
{
    if (!options->print_matches) return;
    for (size_t i = 0; i < matches->count; ++i) {
        const cx_match *match = &matches->items[i];
        if (cx_name_in(&options->print_exclude, match->rule) || (options->print_include.count && !cx_name_in(&options->print_include, match->rule))) continue;
        cx_buf_printf(out, "[%s] in '%s':", match->rule, name);
        for (size_t s = 0; s < match->string_count; ++s) {
            const cx_string_match *string = &match->strings[s];
            cx_buf_printf(out, "\n\t0x%08llx %s ", (unsigned long long)string->offset, string->identifier);
            cx_bytes_repr(out, string->data ? string->data : (const uint8_t *)"", string->length);
        }
        cx_buf_puts(out, "\n\n");
    }
}
