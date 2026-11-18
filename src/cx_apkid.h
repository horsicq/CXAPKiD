/*
 * CXAPKiD - C port of APKiD (https://github.com/rednaga/APKiD)
 * Copyright (C) 2026 hors <horsicq@gmail.com>
 * SPDX-License-Identifier: MIT
 *
 * apkid/apkid.py (Options, Scanner) and apkid/output.py (OutputFormatter).
 */
#ifndef CX_APKID_H
#define CX_APKID_H

#include "cx_common.h"

#include <yara_x.h>

#ifdef __cplusplus
extern "C" {
#endif

#ifndef CXAPKID_VERSION
#define CXAPKID_VERSION "1.0.0"
#endif
/* The APKiD release whose logic and rules this port follows. */
#ifndef CXAPKID_APKID_VERSION
#define CXAPKID_APKID_VERSION "3.2.0"
#endif
#define CXAPKID_COPYRIGHT "Copyright (C) 2026 hors"

typedef enum cx_typing {
    CX_TYPING_MAGIC,
    CX_TYPING_FILENAME,
    CX_TYPING_NONE
} cx_typing;

typedef struct cx_name_set {
    char **items;
    size_t count;
} cx_name_set;

typedef struct cx_options {
    int64_t timeout;             /* seconds; <= 0 disables the limit */
    bool verbose;
    bool json;
    const char *output_dir;      /* implies JSON */
    cx_typing typing;
    int64_t entry_max_scan_size; /* accepted; unused, as in APKiD */
    int64_t scan_depth;
    bool recursive;
    bool include_trackers;
    bool include_types;
    bool print_matches;          /* print filter active */
    cx_name_set print_include;
    cx_name_set print_exclude;
    const char *rules_dir;       /* NULL: the rules/ folder next to the executable */
    int64_t threads;             /* ZIP members scanned in parallel; <= 0 auto */
} cx_options;

/* Messages of one parallel task, written out in member order afterwards so
 * the output does not depend on scheduling. */
typedef struct cx_log_entry {
    int stream;   /* 1 stdout, 2 stderr; 0 a scan record (cx_scan.c) */
    char *text;
    void *record; /* stream 0 */
} cx_log_entry;

typedef struct cx_log {
    cx_log_entry *items;
    size_t count;
    size_t capacity;
} cx_log;

typedef struct cx_string_match {
    char *identifier;
    uint64_t offset;
    uint8_t *data; /* at most 512 bytes, as YARA keeps */
    size_t length;
} cx_string_match;

/* What a rule's meta "description" is in yara-python: str, int or bool. */
typedef enum cx_description_kind {
    CX_DESCRIPTION_TEXT,
    CX_DESCRIPTION_INTEGER,
    CX_DESCRIPTION_BOOLEAN
} cx_description_kind;

typedef struct cx_match {
    size_t ns;         /* the rule's namespace, in declaration order */
    char *rule;
    char *description; /* meta "description" as text (str() of it), NULL when absent */
    cx_description_kind description_kind;
    int64_t description_number; /* the value of an integer or boolean description */
    char **tags;       /* sorted */
    size_t tag_count;
    cx_string_match *strings;
    size_t string_count;
} cx_match;

typedef struct cx_match_list {
    cx_match *items;
    size_t count;
    size_t capacity;
} cx_match_list;

typedef struct cx_result {
    char *key; /* path, or path!entry!nested-entry */
    cx_match_list matches;
} cx_result;

typedef struct cx_results {
    cx_result *items;
    size_t count;
    size_t capacity;
} cx_results;

typedef struct cx_output {
    const cx_options *options;
    const char *rules_sha256;
    bool colorize;
    bool failed;
} cx_output;

typedef struct cx_scanner {
    const cx_options *options;
    cx_output *output;
    YRX_SCANNER *yrx;
    const YRX_RULES *rules;
    const uint8_t *data; /* buffer being scanned, for match data */
    size_t size;
    cx_match_list *current;
    cx_log *log;                 /* NULL: messages go out directly */
    struct cx_scanner *workers;  /* one per thread, created on first use */
    size_t worker_count;
    struct cx_namespaces *namespaces; /* the rules' namespaces (owner's, shared) */
    bool record;                 /* scans leave records in the log (see cx_scan.c) */
    bool used;                   /* has scanned an input (its YARA-X scanner has a history) */
} cx_scanner;

void cx_match_list_free(cx_match_list *list);
void cx_results_free(cx_results *results);

bool cx_scanner_init(cx_scanner *scanner, const cx_options *options, const YRX_RULES *rules, cx_output *output,
                     char **error);
void cx_scanner_free(cx_scanner *scanner);
/* Scanner.scan(path) for every input: files, or every file of a directory.
 * Output is the same as scanning them one after another. */
void cx_scanner_scan_inputs(cx_scanner *scanner, const char *const *paths, size_t count);

/* json.dumps(text): a JSON string, everything outside ASCII escaped. */
void cx_json_string(cx_buf *out, const char *text);

void cx_output_init(cx_output *output, const cx_options *options, const char *rules_sha256);
/* Restores the console after colored output (pairs with cx_output_init). */
void cx_output_finish(cx_output *output);
/* OutputFormatter.write(); text goes to `log`, or out directly when NULL. */
void cx_output_write(cx_output *output, const cx_results *results, cx_log *log);

/* Append a message (owned, freed later) to `log`, or print it when NULL. */
void cx_log_emit(cx_log *log, int stream, char *text);
/* Print and release the messages of a log, in order. */
void cx_log_flush(cx_log *log);
/* Print one message as cx_log_flush() does. */
void cx_log_print_text(int stream, const char *text);
/* Scanner._print_matches(): the text to print, appended to `out`. */
void cx_output_format_matches(const cx_options *options, const char *name, const cx_match_list *matches, cx_buf *out);

#ifdef __cplusplus
}
#endif

#endif
