/*
 * CXAPKiD - C port of APKiD (https://github.com/rednaga/APKiD)
 * Copyright (C) 2026 hors <horsicq@gmail.com>
 * SPDX-License-Identifier: MIT
 */
#if !defined(_WIN32) && !defined(_POSIX_C_SOURCE)
#define _POSIX_C_SOURCE 200809L
#endif

#include "cx_apkid.h"
#include "cx_rules.h"

#include <xxyara_ext.h>
#include <xxfclib/formats/archive/zip/xx_zip_py.h>
#include <xxfclib/formats/executable/dex/xx_dex_legacy.h>
#include <xxfclib/fs/xx_fs.h>
#include <xxfclib/list/xx_list.h>
#include <xxfclib/strings/xx_string.h>
#include <xxfclib/threads/xx_threads.h>
#include <xxfclib/global/xx_global.h>
#include <xxfclib/rt/xx_rt.h>

#include <stdio.h>
#include <stdlib.h>
#include <string.h>

#ifdef _WIN32
#include <windows.h>
#else
#include <sys/stat.h>
#endif

/* YR_CONFIG_MAX_MATCH_DATA: bytes of a string match kept by YARA. */
#define CX_MAX_MATCH_DATA 512

typedef enum cx_file_type {
    CX_FILE_UNKNOWN,
    CX_FILE_ZIP,
    CX_FILE_DEX,
    CX_FILE_ELF,
    CX_FILE_RES,
    CX_FILE_DLL
} cx_file_type;

/* SCANNABLE_FILE_MAGICS */
static cx_file_type cx_type_file(const uint8_t *data, size_t size)
{
    if (size < 4) return CX_FILE_UNKNOWN;
    if (memcmp(data, "PK\x03\x04", 4) == 0 || memcmp(data, "PK\x05\x06", 4) == 0 || memcmp(data, "PK\x07\x08", 4) == 0)
        return CX_FILE_ZIP;
    if (memcmp(data, "dex\n", 4) == 0 || memcmp(data, "dey\n", 4) == 0) return CX_FILE_DEX;
    if (memcmp(data, "\x7f" "ELF", 4) == 0) return CX_FILE_ELF;
    if (memcmp(data, "\x02\x00\x0c\x00", 4) == 0) return CX_FILE_RES;
    if (memcmp(data, "MZ\x90\x00", 4) == 0) return CX_FILE_DLL;
    return CX_FILE_UNKNOWN;
}

/* Scanner._should_scan() */
static bool cx_should_scan(const cx_scanner *scanner, const uint8_t *data, size_t size, const char *name)
{
    switch (scanner->options->typing) {
    case CX_TYPING_MAGIC:
        return cx_type_file(data, size) != CX_FILE_UNKNOWN;
    case CX_TYPING_FILENAME:
        /* APKiD also tests name.lower().startswith('AndroidManifest.xml'),
           which can never be true; it is left out on purpose. */
        return cx_starts_with_nocase(name, "classes") || cx_starts_with_nocase(name, "lib/") ||
               cx_ends_with_nocase(name, ".so") || cx_ends_with_nocase(name, ".dex") ||
               cx_ends_with_nocase(name, ".apk") || cx_ends_with_nocase(name, ".arsc") ||
               cx_ends_with_nocase(name, ".dll");
    default:
        return true;
    }
}

/* Scanner._is_zipfile() */
static bool cx_is_zipfile(const cx_scanner *scanner, const uint8_t *data, size_t size, const char *name)
{
    if (scanner->options->typing == CX_TYPING_FILENAME)
        return cx_ends_with_nocase(name, ".apk") || cx_ends_with_nocase(name, ".zip") || cx_ends_with_nocase(name, ".jar");
    return cx_type_file(data, size) == CX_FILE_ZIP && xx_zip_py_is_zipfile(data, size);
}

void cx_match_list_free(cx_match_list *list)
{
    for (size_t i = 0; i < list->count; ++i) {
        cx_match *match = &list->items[i];
        free(match->rule);
        free(match->description);
        for (size_t t = 0; t < match->tag_count; ++t) free(match->tags[t]);
        free(match->tags);
        for (size_t s = 0; s < match->string_count; ++s) {
            free(match->strings[s].identifier);
            free(match->strings[s].data);
        }
        free(match->strings);
    }
    free(list->items);
    memset(list, 0, sizeof(*list));
}

void cx_results_free(cx_results *results)
{
    for (size_t i = 0; i < results->count; ++i) {
        free(results->items[i].key);
        cx_match_list_free(&results->items[i].matches);
    }
    free(results->items);
    memset(results, 0, sizeof(*results));
}

/* results[key] = matches: a repeated key keeps its first position and takes
 * the new matches, like a Python dict. Takes ownership of key and matches. */
static void cx_results_set(cx_results *results, char *key, cx_match_list *matches)
{
    for (size_t i = 0; i < results->count; ++i) {
        if (strcmp(results->items[i].key, key) == 0) {
            free(key);
            cx_match_list_free(&results->items[i].matches);
            results->items[i].matches = *matches;
            memset(matches, 0, sizeof(*matches));
            return;
        }
    }
    if (results->count == results->capacity) {
        results->capacity = results->capacity ? results->capacity * 2 : 16;
        results->items = (cx_result *)cx_realloc(results->items, results->capacity * sizeof(*results->items));
    }
    results->items[results->count].key = key;
    results->items[results->count].matches = *matches;
    ++results->count;
    memset(matches, 0, sizeof(*matches));
}

/* ---------------------------------------------------------- YARA matching */

typedef struct cx_pattern_context {
    cx_scanner *scanner;
    cx_match *match;
    char *identifier;
} cx_pattern_context;

static void cx_on_tag(const char *tag, void *user_data)
{
    cx_match *match = (cx_match *)user_data;
    match->tags = (char **)cx_realloc(match->tags, (match->tag_count + 1) * sizeof(char *));
    match->tags[match->tag_count++] = cx_strdup(tag);
}

static void cx_on_metadata(const YRX_METADATA *metadata, void *user_data)
{
    cx_match *match = (cx_match *)user_data;
    if (strcmp(metadata->identifier, "description") != 0) return;
    /* The last "description" of a rule counts, as in yara-python's dict. */
    free(match->description);
    match->description = NULL;
    match->description_kind = CX_DESCRIPTION_TEXT;
    match->description_number = 0;
    if (metadata->value_type == YRX_STRING) {
        match->description = cx_strdup(metadata->value.string);
    } else if (metadata->value_type == YRX_BYTES) {
        match->description = cx_strndup((const char *)metadata->value.bytes.data, metadata->value.bytes.length);
    } else if (metadata->value_type == YRX_I64) {
        /* yara-python 3.11 hands an integer over as a C int: APKiD sees the
           low 32 bits of the value. */
        match->description_kind = CX_DESCRIPTION_INTEGER;
        match->description_number = (int64_t)(int32_t)(uint32_t)(uint64_t)metadata->value.i64;
        match->description = cx_format("%lld", (long long)match->description_number);
    } else if (metadata->value_type == YRX_F64) {
        match->description = cx_format("%g", metadata->value.f64);
    } else if (metadata->value_type == YRX_BOOLEAN) {
        match->description_kind = CX_DESCRIPTION_BOOLEAN;
        match->description_number = metadata->value.boolean ? 1 : 0;
        match->description = cx_strdup(metadata->value.boolean ? "True" : "False");
    }
}

static void cx_on_pattern_match(const YRX_MATCH *found, void *user_data)
{
    cx_pattern_context *context = (cx_pattern_context *)user_data;
    cx_match *match = context->match;
    const cx_scanner *scanner = context->scanner;
    cx_string_match *entry;
    match->strings = (cx_string_match *)cx_realloc(match->strings, (match->string_count + 1) * sizeof(*match->strings));
    entry = &match->strings[match->string_count++];
    entry->identifier = cx_strdup(context->identifier);
    entry->offset = found->offset;
    entry->length = 0;
    entry->data = NULL;
    if (found->offset < scanner->size) {
        size_t length = found->length;
        if (length > scanner->size - found->offset) length = scanner->size - found->offset;
        if (length > CX_MAX_MATCH_DATA) length = CX_MAX_MATCH_DATA;
        entry->data = (uint8_t *)cx_malloc(length);
        memcpy(entry->data, scanner->data + found->offset, length);
        entry->length = length;
    }
}

static void cx_on_pattern(const YRX_PATTERN *pattern, void *user_data)
{
    cx_pattern_context *context = (cx_pattern_context *)user_data;
    const uint8_t *identifier = NULL;
    size_t length = 0;
    if (yrx_pattern_identifier(pattern, &identifier, &length) != YRX_SUCCESS) return;
    context->identifier = cx_strndup((const char *)identifier, length);
    yrx_pattern_iter_matches(pattern, cx_on_pattern_match, context);
    free(context->identifier);
    context->identifier = NULL;
}

static int cx_compare_strings(const void *a, const void *b)
{
    return strcmp(*(char *const *)a, *(char *const *)b);
}

/* The rules' namespaces in declaration order. A YARA-X scanner reports the
 * matching rules grouped by namespace, in the order in which namespaces
 * first had a matching rule over the scanner's whole life (each group in
 * declaration order). The order of results therefore depends on what the
 * scanner scanned before; see the parallel jobs below. */
typedef struct cx_namespaces {
    char **names;
    size_t *lengths;
    size_t count;
    bool contiguous; /* each namespace's rules are one run of declarations */
    size_t *order;    /* first matches in input order, shared only with the flusher */
    size_t next;
} cx_namespaces;

static size_t cx_namespace_find(const cx_namespaces *table, const uint8_t *name, size_t length)
{
    for (size_t i = 0; i < table->count; ++i)
        if (table->lengths[i] == length && memcmp(table->names[i], name, length) == 0) return i;
    return SIZE_MAX;
}

static void cx_on_rule_namespace(const YRX_RULE *rule, void *user_data)
{
    cx_namespaces *table = (cx_namespaces *)user_data;
    const uint8_t *name = NULL;
    size_t length = 0;
    if (yrx_rule_namespace(rule, &name, &length) != YRX_SUCCESS) {
        table->contiguous = false;
        return;
    }
    if (table->count && table->lengths[table->count - 1] == length &&
        memcmp(table->names[table->count - 1], name, length) == 0)
        return;
    if (cx_namespace_find(table, name, length) != SIZE_MAX) {
        table->contiguous = false; /* a namespace resumed after another one */
        return;
    }
    table->names = (char **)cx_realloc(table->names, (table->count + 1) * sizeof(char *));
    table->lengths = (size_t *)cx_realloc(table->lengths, (table->count + 1) * sizeof(size_t));
    table->names[table->count] = cx_strndup((const char *)name, length);
    table->lengths[table->count] = length;
    ++table->count;
}

static cx_namespaces *cx_namespaces_create(const YRX_RULES *rules)
{
    cx_namespaces *table = (cx_namespaces *)cx_calloc(1, sizeof(*table));
    table->contiguous = true;
    if (yrx_rules_iter(rules, cx_on_rule_namespace, table) != YRX_SUCCESS) table->contiguous = false;
    table->order = (size_t *)cx_malloc((table->count ? table->count : 1) * sizeof(size_t));
    for (size_t i = 0; i < table->count; ++i) table->order[i] = SIZE_MAX;
    return table;
}

static void cx_namespaces_free(cx_namespaces *table)
{
    if (!table) return;
    for (size_t i = 0; i < table->count; ++i) free(table->names[i]);
    free(table->names);
    free(table->lengths);
    free(table->order);
    free(table);
}

/* Stable: each namespace's matches keep their declaration order. */
static void cx_reorder_matches(const size_t *order, size_t count, cx_match_list *list)
{
    for (size_t i = 1; i < list->count; ++i) {
        cx_match item = list->items[i];
        size_t rank = item.ns < count ? order[item.ns] : SIZE_MAX, at = i;
        while (at > 0) {
            size_t ns = list->items[at - 1].ns;
            if ((ns < count ? order[ns] : SIZE_MAX) <= rank) break;
            list->items[at] = list->items[at - 1];
            --at;
        }
        list->items[at] = item;
    }
}

/* Sequential scans also maintain the canonical history, so a later pool
 * starts from it instead of the owner's schedule-dependent YARA-X history. */
static void cx_namespaces_match(cx_namespaces *table, cx_match_list *matches)
{
    for (size_t ns = 0; ns < table->count; ++ns) {
        if (table->order[ns] != SIZE_MAX) continue;
        for (size_t i = 0; i < matches->count; ++i) {
            if (matches->items[i].ns != ns) continue;
            table->order[ns] = table->next++;
            break;
        }
    }
    cx_reorder_matches(table->order, table->count, matches);
}

static void cx_on_matching_rule(const YRX_RULE *rule, void *user_data)
{
    cx_scanner *scanner = (cx_scanner *)user_data;
    cx_match_list *list = scanner->current;
    const uint8_t *identifier = NULL;
    size_t length = 0;
    cx_match *match;
    if (!list) return;
    if (list->count == list->capacity) {
        list->capacity = list->capacity ? list->capacity * 2 : 16;
        list->items = (cx_match *)cx_realloc(list->items, list->capacity * sizeof(*list->items));
    }
    match = &list->items[list->count++];
    memset(match, 0, sizeof(*match));
    match->ns = SIZE_MAX;
    if (scanner->namespaces && yrx_rule_namespace(rule, &identifier, &length) == YRX_SUCCESS)
        match->ns = cx_namespace_find(scanner->namespaces, identifier, length);
    identifier = NULL;
    length = 0;
    if (yrx_rule_identifier(rule, &identifier, &length) == YRX_SUCCESS)
        match->rule = cx_strndup((const char *)identifier, length);
    else
        match->rule = cx_strdup("");
    yrx_rule_iter_tags(rule, cx_on_tag, match);
    if (match->tag_count > 1) qsort(match->tags, match->tag_count, sizeof(char *), cx_compare_strings);
    yrx_rule_iter_metadata(rule, cx_on_metadata, match);
    if (scanner->options->print_matches) {
        cx_pattern_context context = {scanner, match, NULL};
        yrx_rule_iter_patterns(rule, cx_on_pattern, &context);
    }
}

/* YARA 3.11's elf module parses ELF32/ELF64 in either byte order, and only
 * when the data is longer than the ELF header (`block->size > sizeof`). */
static bool cx_legacy_elf_rejects(const uint8_t *data, size_t size)
{
    if (size < 4 || memcmp(data, "\x7f" "ELF", 4) != 0) return false;
    if (size < 16 || (data[5] != 1 && data[5] != 2)) return true;
    if (data[4] == 1) return size <= 52;
    if (data[4] == 2) return size <= 64;
    return true;
}

static YRX_RESULT cx_create_yrx(cx_scanner *scanner, YRX_SCANNER **yrx, bool timed, char **error)
{
    if (yrx_scanner_create(scanner->rules, yrx) != YRX_SUCCESS) {
        *error = cx_format("creating scanner: %s", yrx_last_error() ? yrx_last_error() : "failed");
        return YRX_SCAN_ERROR;
    }
    /* Only yrx_scanner_scan is used, never the multi-block API, so the
       scanner need not keep its own copy of every scanned buffer. */
    if (xxyara_scanner_retain_scan_data(*yrx, false) != YRX_SUCCESS) {
        *error = cx_format("creating scanner: %s", yrx_last_error() ? yrx_last_error() : "failed");
        return YRX_SCAN_ERROR;
    }
    if (timed && yrx_scanner_set_timeout(*yrx, (uint64_t)scanner->options->timeout) != YRX_SUCCESS) {
        *error = cx_format("setting timeout: %s", yrx_last_error() ? yrx_last_error() : "failed");
        return YRX_SCAN_ERROR;
    }
    if (yrx_scanner_on_matching_rule(*yrx, cx_on_matching_rule, scanner) != YRX_SUCCESS) {
        *error = cx_format("registering callback: %s", yrx_last_error() ? yrx_last_error() : "failed");
        return YRX_SCAN_ERROR;
    }
    return YRX_SUCCESS;
}

/* --dex-all-versions: a DEX that YARA 3.11 rejects only for its version
 * (039 and newer) is treated as parsed. The values the legacy module would
 * have given are computed over a copy that carries version 038; the layout
 * those values depend on is the same. */
static void cx_newer_dex_analyze(const uint8_t *data, size_t size, xx_dex_legacy *legacy)
{
    uint8_t *copy;
    if (size < 8 || memcmp(data, "dex\n0", 5) != 0 || data[7] != 0) return;
    if (data[5] < '0' || data[5] > '9' || data[6] < '0' || data[6] > '9') return;
    if ((data[5] - '0') * 10 + (data[6] - '0') < 39) return;
    copy = (uint8_t *)cx_malloc(size);
    memcpy(copy, data, size);
    copy[5] = '3';
    copy[6] = '8';
    if (!xx_dex_legacy_analyze(copy, size, legacy)) cx_out_of_memory();
    free(copy);
}

/* One scan: the legacy module state for this buffer, then the rules. */
static YRX_RESULT cx_run_scan(cx_scanner *scanner, YRX_SCANNER *yrx, const uint8_t *data, size_t size,
                              const xx_dex_legacy *legacy, cx_match_list *out)
{
    static const uint8_t empty[1] = {0};
    YRX_RESULT result;
    /* APKiD's dex module is YARA 3.11's: it only parses DEX 035-038. Where
       it would not parse, YARA-X's dex module output is withheld so every
       dex.* value is undefined, as APKiD sees it. The same holds for ELF
       data no longer than its header. */
    if (!legacy->parsed) (void)yrx_scanner_set_module_output(yrx, "dex", empty, 0);
    if (cx_legacy_elf_rejects(data, size)) (void)yrx_scanner_set_module_output(yrx, "elf", empty, 0);
    if (yrx_scanner_set_global_int(yrx, CX_GLOBAL_UNICODE_FIELD_NAMES, legacy->unicode_field_names) != YRX_SUCCESS ||
        yrx_scanner_set_global_int(yrx, CX_GLOBAL_UNICODE_METHOD_NAMES, legacy->unicode_method_names) != YRX_SUCCESS ||
        yrx_scanner_set_global_bool(yrx, CX_GLOBAL_UNSORTED_STRING_POOL, legacy->unsorted_string_pool) != YRX_SUCCESS)
        return YRX_VARIABLE_ERROR;
    scanner->data = size ? data : empty;
    scanner->size = size;
    scanner->current = out;
    result = yrx_scanner_scan(yrx, scanner->data, size);
    scanner->current = NULL;
    scanner->data = NULL;
    scanner->size = 0;
    return result;
}

/* In a parallel run of an archive's members, a scan leaves records in its
 * job's log: the namespaces of its matches, and (-m) the matches to print.
 * The flusher replays them in sequential order (cx_pool_merge). */
typedef struct cx_scan_record {
    size_t *namespaces; /* ascending */
    size_t count;
    char *key;          /* a print: the key and a copy of the matches */
    cx_match_list matches;
} cx_scan_record;

static void cx_log_record(cx_log *log, cx_scan_record *record)
{
    cx_log_emit(log, 0, NULL);
    log->items[log->count - 1].record = record;
}

static void cx_scan_record_free(cx_scan_record *record)
{
    if (!record) return;
    free(record->namespaces);
    free(record->key);
    cx_match_list_free(&record->matches);
    free(record);
}

static void cx_record_namespaces(cx_scanner *scanner, const cx_match_list *matches)
{
    cx_scan_record *record = (cx_scan_record *)cx_calloc(1, sizeof(*record));
    record->namespaces = (size_t *)cx_malloc(matches->count * sizeof(size_t));
    for (size_t i = 0; i < matches->count; ++i) {
        size_t ns = matches->items[i].ns, at = record->count;
        bool seen = false;
        for (size_t k = 0; k < record->count && !seen; ++k) seen = record->namespaces[k] == ns;
        if (seen || ns == SIZE_MAX) continue;
        while (at > 0 && record->namespaces[at - 1] > ns) {
            record->namespaces[at] = record->namespaces[at - 1];
            --at;
        }
        record->namespaces[at] = ns;
        ++record->count;
    }
    cx_log_record(scanner->log, record);
}

/* A full copy. (Its only user prints the --print-matches lines, which show
 * no description: no output depends on the three description fields here.) */
static void cx_match_copy(cx_match *to, const cx_match *from)
{
    memset(to, 0, sizeof(*to));
    to->ns = from->ns;
    to->rule = cx_strdup(from->rule);
    to->description = from->description ? cx_strdup(from->description) : NULL;
    to->description_kind = from->description_kind;
    to->description_number = from->description_number;
    to->tag_count = from->tag_count;
    to->tags = (char **)cx_malloc((from->tag_count ? from->tag_count : 1) * sizeof(char *));
    for (size_t t = 0; t < from->tag_count; ++t) to->tags[t] = cx_strdup(from->tags[t]);
    to->string_count = from->string_count;
    to->strings = (cx_string_match *)cx_malloc((from->string_count ? from->string_count : 1) * sizeof(cx_string_match));
    for (size_t s = 0; s < from->string_count; ++s) {
        const cx_string_match *source = &from->strings[s];
        cx_string_match *target = &to->strings[s];
        target->identifier = cx_strdup(source->identifier);
        target->offset = source->offset;
        target->length = source->length;
        target->data = NULL;
        if (source->data) {
            target->data = (uint8_t *)cx_malloc(source->length ? source->length : 1);
            memcpy(target->data, source->data, source->length);
        }
    }
}

/* rules.match(data=..., timeout=...) */
static bool cx_match_data(cx_scanner *scanner, const uint8_t *data, size_t size, cx_match_list *out, char **error)
{
    YRX_RESULT result;
    xx_dex_legacy legacy;
    memset(out, 0, sizeof(*out));
    /* A worker creates its YARA-X scanner on its own thread when it first
       has data to scan: building one costs as much as copying every rule,
       and most archive members are skipped by typing. */
    if (!scanner->yrx && cx_create_yrx(scanner, &scanner->yrx, scanner->options->timeout > 0, error) != YRX_SUCCESS) {
        if (scanner->yrx) yrx_scanner_destroy(scanner->yrx);
        scanner->yrx = NULL;
        return false;
    }
    if (!xx_dex_legacy_analyze(data, size, &legacy)) cx_out_of_memory();
    if (!legacy.parsed && scanner->options->dex_all_versions) cx_newer_dex_analyze(data, size, &legacy);
    result = cx_run_scan(scanner, scanner->yrx, data, size, &legacy, out);
    if (result == YRX_SUCCESS) {
        if (scanner->record && scanner->log) {
            if (out->count) cx_record_namespaces(scanner, out);
        } else if (scanner->namespaces && scanner->namespaces->contiguous) {
            cx_namespaces_match(scanner->namespaces, out);
        }
        return true;
    }
    cx_match_list_free(out);
    if (result == YRX_SCAN_TIMEOUT)
        *error = cx_strdup("Scanning timed out");
    else
        *error = cx_strdup(yrx_last_error() && *yrx_last_error() ? yrx_last_error() : "scan error");
    return false;
}

/* --------------------------------------------------------------- scanning */

/* APKiD prints the traceback of the exception and carries on. */
static void cx_report(cx_scanner *scanner, const char *what, const char *message)
{
    cx_log_emit(scanner->log, 2, cx_format("Exception scanning %s: %s\n", what, message));
}

static void cx_report_entry(cx_scanner *scanner, const xx_zip_py_info *info, const char *prefix, int64_t depth,
                            const char *message)
{
    char *what = cx_format("%s in %s, depth=%lld", info->filename, prefix, (long long)depth);
    cx_report(scanner, what, message ? message : "error");
    free(what);
}

/* The UserWarnings zipfile.ZipFile() emitted for the archive. */
static void cx_report_warnings(cx_scanner *scanner, const xx_zip_py *zip)
{
    if (!scanner->options->verbose) return;
    for (size_t i = 0; i < zip->warning_count; ++i)
        cx_log_emit(scanner->log, 2, cx_format("UserWarning: %s\n", zip->warnings[i]));
}

static void cx_print_found(cx_scanner *scanner, const char *key, const cx_match_list *matches)
{
    cx_buf text = {0};
    if (scanner->record && scanner->log) {
        /* Printed by the flusher, in the order a sequential run reports. */
        if (!scanner->options->print_matches) return;
        cx_scan_record *record = (cx_scan_record *)cx_calloc(1, sizeof(*record));
        record->key = cx_strdup(key);
        record->matches.items = (cx_match *)cx_malloc((matches->count ? matches->count : 1) * sizeof(cx_match));
        for (size_t i = 0; i < matches->count; ++i) cx_match_copy(&record->matches.items[i], &matches->items[i]);
        record->matches.count = record->matches.capacity = matches->count;
        cx_log_record(scanner->log, record);
        return;
    }
    cx_output_format_matches(scanner->options, key, matches, &text);
    if (text.length)
        cx_log_emit(scanner->log, 1, cx_buf_detach(&text));
    else
        cx_buf_free(&text);
}

static void cx_scan_zip(cx_scanner *scanner, const xx_zip_py *zip, int64_t depth, const char *prefix, cx_results *results);

/* A member job of a parallel run that may hand its nested archive's members
 * to other threads (see cx_pool_spawn). */
typedef struct cx_spawn cx_spawn;
static bool cx_pool_spawn(cx_scanner *scanner, cx_spawn *spawn, const xx_zip_py_info *info, const char *prefix, uint8_t *data,
                          size_t size, xx_zip_py_owner owner);

/* Scanner._scan_zip_entry(). With `spawn`, a member that is an archive to
 * scan may continue as jobs of the parallel run: then the rules over the
 * member and each nested member are separate jobs, written out in the same
 * order as here. */
static void cx_scan_zip_entry(cx_scanner *scanner, const xx_zip_py *zip, const xx_zip_py_info *info, int64_t depth,
                              const char *prefix, cx_results *results, cx_spawn *spawn)
{
    const cx_options *options = scanner->options;
    uint64_t data_offset = 0;
    char *warning = NULL, *error = NULL;
    uint8_t *data = NULL;
    size_t size = 0;
    bool complete = false;
    xx_zip_py_owner owner = XX_ZIP_PY_OWNED; /* how data is released (borrowed: a stored member) */
    xx_zip_py_status status = xx_zip_py_open_entry(zip, info, &data_offset, &warning, &error);

    if (status == XX_ZIP_PY_NO_MEMORY) cx_out_of_memory();
    if (status == XX_ZIP_PY_VALUE_ERROR && depth == 0) {
        /* A negative header offset: io.BytesIO raises ValueError, but APKiD
           reads the outermost archive from a file, which raises
           OSError(EINVAL). */
        cx_report_entry(scanner, info, prefix, depth, "[Errno 22] Invalid argument");
        xx_zip_py_free_text(warning);
        xx_zip_py_free_text(error);
        return;
    }
    if (warning) {
        if (options->verbose) cx_log_emit(scanner->log, 2, cx_format("UserWarning: %s\n", warning));
        xx_zip_py_free_text(warning);
    }
    if (status == XX_ZIP_PY_OVERLAPPED) {
        if (options->verbose)
            cx_log_emit(scanner->log, 1,
                        cx_format("[W] Skipping overlapped entry %s (possible zip bomb)\n", info->filename));
        xx_zip_py_free_text(error);
        return;
    }
    if (status == XX_ZIP_PY_NOT_IMPLEMENTED) {
        xx_zip_py_free_text(error);
        error = NULL;
        if (info->compress_type != XX_ZIP_PY_XZ) {
            cx_log_emit(scanner->log, 1,
                        cx_format("[E] Unsupported compression method %u for %s\n", (unsigned)info->compress_type,
                                  info->filename));
            return;
        }
        /* XZ: APKiD decompresses the raw member data with lzma.decompress()
           and scans it without the typing check. */
        const uint8_t *raw = NULL;
        size_t raw_size = 0;
        if (!xx_zip_py_raw_data(zip, info, &raw, &raw_size)) {
            cx_log_emit(scanner->log, 1,
                        cx_format("[E] Failed to decompress %s: %s\n", info->filename, "truncated local file header"));
            return;
        }
        if (!xx_zip_py_xz_decompress(raw, raw_size, &data, &size, &error)) {
            cx_log_emit(scanner->log, 1,
                        cx_format("[E] Failed to decompress %s: %s\n", info->filename, error ? error : "error"));
            xx_zip_py_free_text(error);
            return;
        }
    } else if (status != XX_ZIP_PY_OK) {
        cx_report_entry(scanner, info, prefix, depth, error);
        xx_zip_py_free_text(error);
        return;
    } else {
        /* entry.read(4), then the typing test (on those bytes or on the
           name), then entry.read(). ZipExtFile takes at least MIN_READ_SIZE
           (4096) bytes of the member's data for read(4): a member that ends
           within them is complete, CRC checked and all here already at this
           point; one that fails within them fails here, scanned or not,
           whatever the typing. */
        status = xx_zip_py_read(zip, info, data_offset, 4, &data, &size, &complete, &owner, &error);
        if (status == XX_ZIP_PY_OK && !cx_should_scan(scanner, data, size < 4 ? size : 4, info->filename)) {
            xx_zip_py_free(data, owner);
            return;
        }
        if (status == XX_ZIP_PY_OK && !complete) {
            xx_zip_py_free(data, owner);
            data = NULL;
            status = xx_zip_py_read_rest(zip, info, data_offset, 4, &data, &size, &owner, &error);
        }
        if (status == XX_ZIP_PY_OVERLAPPED) {
            xx_zip_py_free_text(error);
            return;
        }
        if (status != XX_ZIP_PY_OK) {
            cx_report_entry(scanner, info, prefix, depth, error);
            xx_zip_py_free_text(error);
            return;
        }
    }

    /* The nested-archive test does not depend on the rules' outcome; it is
       only made earlier here. */
    if (spawn && depth < options->scan_depth && cx_is_zipfile(scanner, data, size, info->filename) &&
        cx_pool_spawn(scanner, spawn, info, prefix, data, size, owner))
        return; /* the spawned jobs own data now */

    char *key = cx_format("%s!%s", prefix, info->filename);
    cx_match_list matches;
    if (!cx_match_data(scanner, data, size, &matches, &error)) {
        cx_report_entry(scanner, info, prefix, depth, error);
        free(error);
        free(key);
        xx_zip_py_free(data, owner);
        return;
    }
    if (matches.count) {
        cx_print_found(scanner, key, &matches);
        cx_results_set(results, cx_strdup(key), &matches);
    }
    if (depth < options->scan_depth && cx_is_zipfile(scanner, data, size, info->filename)) {
        xx_zip_py nested;
        xx_zip_py_status opened = xx_zip_py_open(&nested, data, size, &error);
        if (opened == XX_ZIP_PY_NO_MEMORY) cx_out_of_memory();
        if (opened != XX_ZIP_PY_OK) {
            cx_report_entry(scanner, info, prefix, depth, error);
            xx_zip_py_free_text(error);
        } else {
            cx_report_warnings(scanner, &nested);
            cx_scan_zip(scanner, &nested, depth + 1, key, results);
            xx_zip_py_close(&nested);
        }
    }
    free(key);
    xx_zip_py_free(data, owner);
}

/* Scanner._scan_zip() */
static void cx_scan_zip(cx_scanner *scanner, const xx_zip_py *zip, int64_t depth, const char *prefix, cx_results *results)
{
    for (size_t i = 0; i < zip->count; ++i) {
        if (xx_zip_py_info_is_dir(&zip->infos[i])) continue;
        cx_scan_zip_entry(scanner, zip, &zip->infos[i], depth, prefix, results, NULL);
    }
}

/* The rules over a whole input file, the first step of scan_file_obj(). */
static void cx_scan_whole(cx_scanner *scanner, const uint8_t *data, size_t size, const char *file_path,
                          cx_results *results)
{
    cx_match_list matches;
    char *error = NULL;
    if (!cx_match_data(scanner, data, size, &matches, &error)) {
        cx_report(scanner, file_path, error);
        free(error);
    } else if (matches.count) {
        cx_print_found(scanner, file_path, &matches);
        cx_results_set(results, cx_strdup(file_path), &matches);
    }
}

/* --------------------------------------------------------- parallel jobs */

/* A job is a whole input file, the scan of the outermost archive as a whole
 * file, or one member of that archive. Jobs run on worker threads; their
 * results and messages are kept per job and written in job order, so the
 * output equals a sequential run. Jobs may start in another order (largest
 * first), which only changes when the work is done.
 *
 * A member job whose member is itself an archive to scan may hand the rest
 * of its work to other threads: the rules over the member, then one job per
 * nested member (a group). They are written out right after the member job,
 * in that order, as the sequential scan writes them. The nested members run
 * while the rules over the member run; if those fail, the sequential scan
 * stops there, so the nested jobs' output is dropped. */
typedef struct cx_group {
    const xx_zip_py_info *info; /* the member */
    const char *prefix;
    char *key;               /* prefix!member */
    uint8_t *data;           /* the member's bytes, shared by the group */
    size_t size;
    xx_zip_py_owner owner;
    xx_zip_py zip;           /* the member as an archive */
    size_t pending;          /* jobs of the group not finished */
    bool match_failed;
} cx_group;

typedef struct cx_job {
    const char *path;          /* file job */
    const xx_zip_py_info *info; /* member job (nested member in a group) */
    bool archive;              /* the archive itself (rules.match on all of it) */
    cx_group *group;           /* a job of a group: the rules over the member when info is NULL */
    uint64_t cost;             /* start order: the largest first */
    cx_results results;        /* retained until this job is written in input order */
    cx_log log;
    bool done;
    bool merged;               /* own messages and results written out */
    struct cx_job *children;   /* the group a member job spawned, in output order */
    size_t child_count;
    size_t child_flushed;
} cx_job;

typedef struct cx_pool {
    cx_job *jobs;
    size_t *order;  /* start order: indices into jobs; NULL: job order */
    size_t count;
    size_t next;    /* first job not started (index into order) */
    size_t flushed; /* first job not written out */
    xx_mutex_t *mutex;
    xx_cond_t *cond; /* NULL: member jobs do not spawn groups */
    size_t running;  /* jobs started and not finished */
    cx_job **queue;  /* spawned jobs, in start order */
    size_t queue_next;
    size_t queue_count;
    size_t queue_capacity;
    const xx_zip_py *zip; /* member and archive jobs */
    const char *prefix;
    cx_results *results;
    /* Scan records replayed (see cx_pool_merge): the namespaces' order of
       first matches over the jobs written so far, by declaration index. */
    size_t *ns_order;  /* NULL: no records */
    size_t ns_count;
    size_t ns_next;
    const cx_options *options;
    cx_output *output;
} cx_pool;

struct cx_spawn {
    cx_pool *pool;
    cx_job *job;
    cx_job *inline_job; /* set by cx_pool_spawn: the group's first job, run by the caller */
};

typedef struct cx_pool_thread {
    cx_pool *pool;
    cx_scanner *worker;
} cx_pool_thread;

static void cx_scan_file(cx_scanner *scanner, const char *file_path);
static void cx_scan_file_results(cx_scanner *scanner, const char *file_path, cx_results *results);

static size_t cx_thread_count(const cx_options *options)
{
    if (options->threads > 0) return options->threads > 64 ? 64 : (size_t)options->threads;
    size_t cpus = xx_thread_cpu_count();
    return cpus > 8 ? 8 : (cpus ? cpus : 1);
}

typedef struct cx_job_rank {
    uint64_t cost;
    size_t index;
} cx_job_rank;

static int cx_compare_ranks(const void *a, const void *b)
{
    const cx_job_rank *left = (const cx_job_rank *)a, *right = (const cx_job_rank *)b;
    if (left->cost != right->cost) return left->cost > right->cost ? -1 : 1;
    return left->index < right->index ? -1 : (left->index > right->index);
}

/* The indices of jobs[0..count), largest cost first (ties in job order). */
static size_t *cx_rank_jobs(const cx_job *jobs, size_t count)
{
    cx_job_rank *ranks = (cx_job_rank *)cx_malloc(count * sizeof(*ranks));
    for (size_t i = 0; i < count; ++i) {
        ranks[i].cost = jobs[i].cost;
        ranks[i].index = i;
    }
    qsort(ranks, count, sizeof(*ranks), cx_compare_ranks);
    size_t *order = (size_t *)cx_malloc(count * sizeof(size_t));
    for (size_t i = 0; i < count; ++i) order[i] = ranks[i].index;
    free(ranks);
    return order;
}

/* An estimate of a member job's work, for its start order only: the bytes
 * it scans, twice for a compressed member (decompression, then the scan). */
static uint64_t cx_member_cost(const xx_zip_py_info *info)
{
    uint64_t size = info->file_size > ((uint64_t)1 << 62) ? ((uint64_t)1 << 62) : info->file_size;
    return info->compress_type == XX_ZIP_PY_STORED ? size : size * 2;
}

/* The member's data is an archive with members: continue as a group of jobs
 * (see above). False leaves everything to the caller, unchanged. */
static bool cx_pool_spawn(cx_scanner *scanner, cx_spawn *spawn, const xx_zip_py_info *info, const char *prefix, uint8_t *data,
                          size_t size, xx_zip_py_owner owner)
{
    cx_pool *pool = spawn->pool;
    xx_zip_py nested;
    xx_zip_py_status opened = xx_zip_py_open(&nested, data, size, NULL);
    if (opened == XX_ZIP_PY_NO_MEMORY) cx_out_of_memory();
    if (opened != XX_ZIP_PY_OK) return false; /* reported after the rules, as before */
    size_t members = 0;
    for (size_t i = 0; i < nested.count; ++i)
        if (!xx_zip_py_info_is_dir(&nested.infos[i])) ++members;
    if (!members) {
        xx_zip_py_close(&nested);
        return false;
    }
    cx_report_warnings(scanner, &nested);
    cx_group *group = (cx_group *)cx_calloc(1, sizeof(*group));
    group->info = info;
    group->prefix = prefix;
    group->key = cx_format("%s!%s", prefix, info->filename);
    group->data = data;
    group->size = size;
    group->owner = owner;
    group->zip = nested;
    group->pending = members + 1;
    cx_job *children = (cx_job *)cx_calloc(members + 1, sizeof(cx_job));
    children[0].group = group;
    children[0].cost = size;
    size_t count = 1;
    for (size_t i = 0; i < group->zip.count; ++i) {
        if (xx_zip_py_info_is_dir(&group->zip.infos[i])) continue;
        children[count].group = group;
        children[count].info = &group->zip.infos[i];
        children[count].cost = cx_member_cost(&group->zip.infos[i]);
        ++count;
    }
    /* The rules over the member run right here, on the scanner that would
       run them in a sequential scan; the nested members go to the queue. */
    size_t *order = cx_rank_jobs(children + 1, count - 1);
    xx_mutex_lock(pool->mutex);
    spawn->job->children = children;
    spawn->job->child_count = count;
    if (pool->queue_count + count > pool->queue_capacity) {
        size_t capacity = pool->queue_capacity ? pool->queue_capacity : 64;
        while (capacity < pool->queue_count + count) capacity *= 2;
        pool->queue = (cx_job **)cx_realloc(pool->queue, capacity * sizeof(cx_job *));
        pool->queue_capacity = capacity;
    }
    for (size_t i = 0; i + 1 < count; ++i) pool->queue[pool->queue_count++] = &children[1 + order[i]];
    xx_cond_broadcast(pool->cond);
    xx_mutex_unlock(pool->mutex);
    free(order);
    spawn->inline_job = &children[0];
    return true;
}

/* The rules over a group's member: the match step of _scan_zip_entry(). */
static void cx_scan_group_match(cx_scanner *scanner, cx_group *group, cx_results *results)
{
    cx_match_list matches;
    char *error = NULL;
    if (!cx_match_data(scanner, group->data, group->size, &matches, &error)) {
        cx_report_entry(scanner, group->info, group->prefix, 0, error);
        free(error);
        group->match_failed = true; /* read by the flusher once this job is done */
        return;
    }
    if (matches.count) {
        cx_print_found(scanner, group->key, &matches);
        cx_results_set(results, cx_strdup(group->key), &matches);
    }
}

/* A sequential run scans everything with one scanner, so the order of a
 * scan's matches follows the namespaces' first matches over all earlier
 * scans. Jobs scan with other scanners; their matches are put in that order
 * here: namespaces of a scan not seen before join in declaration order. */
static void cx_pool_seen(cx_pool *pool, const cx_scan_record *record)
{
    for (size_t i = 0; i < record->count; ++i)
        if (record->namespaces[i] < pool->ns_count && pool->ns_order[record->namespaces[i]] == SIZE_MAX)
            pool->ns_order[record->namespaces[i]] = pool->ns_next++;
}

static void cx_pool_reorder(const cx_pool *pool, cx_match_list *list)
{
    cx_reorder_matches(pool->ns_order, pool->ns_count, list);
}

/* Write out one finished job: its messages, then (all but file jobs) its
 * results[key] = matches in member order. A dropped job writes nothing. */
static void cx_pool_merge(cx_pool *pool, cx_job *job, bool drop)
{
    for (size_t i = 0; i < job->log.count; ++i) {
        cx_log_entry *entry = &job->log.items[i];
        cx_scan_record *record = (cx_scan_record *)entry->record;
        if (!drop && entry->stream) {
            cx_log_print_text(entry->stream, entry->text);
        } else if (!drop && record && !record->key) {
            cx_pool_seen(pool, record);
        } else if (!drop && record) {
            cx_buf text = {0};
            cx_pool_reorder(pool, &record->matches);
            cx_output_format_matches(pool->options, record->key, &record->matches, &text);
            if (text.length) cx_log_print_text(1, text.data);
            cx_buf_free(&text);
        }
        free(entry->text);
        cx_scan_record_free(record);
    }
    free(job->log.items);
    memset(&job->log, 0, sizeof(job->log));
    if (drop) {
        cx_results_free(&job->results);
        return;
    }
    if (job->path) {
        for (size_t i = 0; i < job->results.count; ++i)
            if (pool->ns_order) cx_pool_reorder(pool, &job->results.items[i].matches);
        /* Output files, as well as stdout/stderr, are written by the one
         * flusher. Aliased input paths may name the same output file. */
        if (job->results.count) cx_output_write(pool->output, &job->results, NULL);
        cx_results_free(&job->results);
        return;
    }
    for (size_t i = 0; i < job->results.count; ++i) {
        if (pool->ns_order) cx_pool_reorder(pool, &job->results.items[i].matches);
        cx_results_set(pool->results, job->results.items[i].key, &job->results.items[i].matches);
        job->results.items[i].key = NULL;
    }
    free(job->results.items);
    memset(&job->results, 0, sizeof(job->results));
}

/* The next job to write out, if it is done (all: every job), in output
 * order: each job, then the group it spawned. Called with the lock held. */
static cx_job *cx_pool_next_merge(cx_pool *pool, bool all, bool *drop)
{
    *drop = false;
    while (pool->flushed < pool->count) {
        cx_job *job = &pool->jobs[pool->flushed];
        if (!job->merged) {
            if (!all && !job->done) return NULL;
            job->merged = true;
            return job;
        }
        if (job->child_flushed < job->child_count) {
            cx_job *child = &job->children[job->child_flushed];
            if (!all && !child->done) return NULL;
            ++job->child_flushed;
            /* Nothing follows rules over the member that failed. */
            *drop = child->info && child->group->match_failed;
            return child;
        }
        ++pool->flushed;
    }
    return NULL;
}

/* Finished jobs in order, as far as they are done (all: every job). */
static void cx_pool_flush(cx_pool *pool, bool all)
{
    for (;;) {
        bool drop;
        xx_mutex_lock(pool->mutex);
        cx_job *job = cx_pool_next_merge(pool, all, &drop);
        xx_mutex_unlock(pool->mutex);
        if (!job) return;
        cx_pool_merge(pool, job, drop);
    }
}

/* Mark a job done (`taken`: it came from cx_pool_take). The last job of a
 * group releases what the group shared. */
static void cx_pool_finish(cx_pool *pool, cx_job *job, bool taken)
{
    cx_group *finished = NULL;
    xx_mutex_lock(pool->mutex);
    job->done = true;
    if (taken) --pool->running;
    if (job->group && --job->group->pending == 0) finished = job->group;
    if (pool->cond) xx_cond_broadcast(pool->cond);
    xx_mutex_unlock(pool->mutex);
    if (finished) {
        xx_zip_py_close(&finished->zip);
        xx_zip_py_free(finished->data, finished->owner);
        finished->data = NULL;
        free(finished->key);
        finished->key = NULL;
    }
}

static void cx_pool_do(cx_pool *pool, cx_scanner *worker, cx_job *job)
{
    worker->log = &job->log;
    if (job->path) {
        cx_scan_file_results(worker, job->path, &job->results);
    } else if (job->archive) {
        cx_scan_whole(worker, pool->zip->data, pool->zip->size, pool->prefix, &job->results);
    } else if (job->group && !job->info) {
        cx_scan_group_match(worker, job->group, &job->results);
    } else if (job->group) {
        cx_scan_zip_entry(worker, &job->group->zip, job->info, 1, job->group->key, &job->results, NULL);
    } else {
        cx_spawn spawn = {pool, job, NULL};
        cx_scan_zip_entry(worker, pool->zip, job->info, 0, pool->prefix, &job->results, pool->cond ? &spawn : NULL);
        if (spawn.inline_job) {
            worker->log = &spawn.inline_job->log;
            cx_scan_group_match(worker, spawn.inline_job->group, &spawn.inline_job->results);
            worker->log = NULL;
            cx_pool_finish(pool, spawn.inline_job, false);
        }
    }
    worker->log = NULL;
}

/* The next job to start, waiting while running jobs may still spawn some.
 * Called with the lock held. */
static cx_job *cx_pool_take(cx_pool *pool)
{
    for (;;) {
        if (pool->queue_next < pool->queue_count) return pool->queue[pool->queue_next++];
        if (pool->next < pool->count) {
            size_t index = pool->order ? pool->order[pool->next] : pool->next;
            ++pool->next;
            return &pool->jobs[index];
        }
        if (!pool->cond || !pool->running) return NULL;
        (void)xx_cond_wait(pool->cond, pool->mutex, 50);
    }
}

static void cx_pool_work(cx_pool *pool, cx_scanner *worker, bool flusher)
{
    for (;;) {
        xx_mutex_lock(pool->mutex);
        cx_job *job = cx_pool_take(pool);
        if (job) ++pool->running;
        xx_mutex_unlock(pool->mutex);
        if (!job) return;
        cx_pool_do(pool, worker, job);
        cx_pool_finish(pool, job, true);
        if (flusher) cx_pool_flush(pool, false);
    }
}

static int cx_pool_thread_main(void *argument)
{
    cx_pool_thread *thread = (cx_pool_thread *)argument;
    cx_pool_work(thread->pool, thread->worker, false);
    return 0;
}

/* A worker's YARA-X scanner is created lazily, see cx_match_data. */
static void cx_init_worker(const cx_scanner *owner, cx_scanner *worker)
{
    memset(worker, 0, sizeof(*worker));
    worker->options = owner->options;
    worker->output = owner->output;
    worker->rules = owner->rules;
    worker->namespaces = owner->namespaces;
}

/* Scans leave records for the flusher (or stop doing so). */
static void cx_pool_set_record(cx_scanner *owner, size_t threads, bool record)
{
    owner->record = record;
    for (size_t i = 0; i + 1 < threads; ++i) owner->workers[i].record = record;
}

/* Run the jobs on the owner (also the flusher) and its workers. Member jobs
 * spawn groups only with `nested` set and a condition variable. */
static void cx_pool_run(cx_scanner *owner, cx_pool *pool, bool nested)
{
    size_t threads = cx_thread_count(owner->options);
    if (threads > pool->count && !nested) threads = pool->count;
    if (threads > 1 && !owner->workers) {
        owner->workers = (cx_scanner *)cx_calloc(threads - 1, sizeof(cx_scanner));
        for (size_t i = 0; i < threads - 1; ++i) cx_init_worker(owner, &owner->workers[i]);
        owner->worker_count = threads - 1;
    }
    if (threads - 1 > owner->worker_count) threads = owner->worker_count + 1;
    pool->options = owner->options;
    pool->output = owner->output;

    pool->mutex = xx_mutex_create();
    if (!pool->mutex) {
        /* No threads without a lock: the jobs one after another. */
        for (size_t i = 0; i < pool->count; ++i) {
            cx_job *job = &pool->jobs[i];
            cx_pool_do(pool, owner, job);
            cx_pool_merge(pool, job, false);
        }
        return;
    }
    pool->cond = nested ? xx_cond_create() : NULL;
    /* File jobs and archive-member jobs use several scanners. Replay their
       namespace history in input order, starting with earlier scans. */
    bool record = owner->namespaces && owner->namespaces->contiguous;
    if (record) {
        pool->ns_count = owner->namespaces->count;
        pool->ns_order = owner->namespaces->order;
        pool->ns_next = owner->namespaces->next;
        cx_pool_set_record(owner, threads, true);
    }
    /* xxfclib initializes its CPU feature flags and its heap handle lazily
       and without a lock; do both here, before any worker starts. */
    (void)xx_has_sse2();
    xx_rt_free(xx_rt_malloc(1));
    cx_pool_thread *args = (cx_pool_thread *)cx_calloc(threads, sizeof(*args));
    xx_thread_t **handles = (xx_thread_t **)cx_calloc(threads, sizeof(*handles));
    for (size_t i = 1; i < threads; ++i) {
        args[i].pool = pool;
        args[i].worker = &owner->workers[i - 1];
        /* Deep rule conditions need the main thread's 8 MiB stack. A thread
           that cannot start leaves its jobs to the others. */
        handles[i] = xx_thread_create_ex(cx_pool_thread_main, &args[i], (size_t)8 << 20);
    }
    cx_pool_work(pool, owner, true);
    for (size_t i = 1; i < threads; ++i)
        if (handles[i]) xx_thread_join(handles[i], NULL);
    cx_pool_flush(pool, true);
    if (record) {
        owner->namespaces->next = pool->ns_next;
        cx_pool_set_record(owner, threads, false);
    }
    for (size_t i = 0; i < pool->count; ++i) {
        if (!pool->jobs[i].children) continue;
        free(pool->jobs[i].children[0].group);
        free(pool->jobs[i].children);
    }
    free(pool->queue);
    if (pool->cond) xx_cond_destroy(pool->cond);
    xx_mutex_destroy(pool->mutex);
    free(handles);
    free(args);
}

/* Scanner.scan_file_obj() */
static void cx_scan_file_obj(cx_scanner *scanner, const uint8_t *data, size_t size, const char *file_path,
                             cx_results *results)
{
    const char *file_name = cx_path_basename(file_path);
    char *error = NULL;
    if (!cx_should_scan(scanner, data, size, file_name)) return;
    /* APKiD reads this archive from a file, where zipfile gives up on a
       seek that io.BytesIO (and so xx_zip_py) lets pass: is_zipfile() is
       False then, and ZipFile() raises. */
    bool unseekable = xx_zip_py_file_seek_fails(data, size);
    if (!cx_is_zipfile(scanner, data, size, file_name) ||
        (unseekable && scanner->options->typing != CX_TYPING_FILENAME)) {
        cx_scan_whole(scanner, data, size, file_path, results);
        return;
    }
    if (unseekable) {
        cx_scan_whole(scanner, data, size, file_path, results);
        cx_report(scanner, file_path, "File is not a zip file");
        return;
    }
    /* The archive is opened before the whole-file scan, which does not
       depend on it; a failure is reported after that scan, as before. */
    xx_zip_py zip;
    xx_zip_py_status opened = xx_zip_py_open(&zip, data, size, &error);
    if (opened == XX_ZIP_PY_NO_MEMORY) cx_out_of_memory();
    if (opened != XX_ZIP_PY_OK) {
        cx_scan_whole(scanner, data, size, file_path, results);
        cx_report(scanner, file_path, error ? error : "error");
        xx_zip_py_free_text(error);
        return;
    }
    cx_report_warnings(scanner, &zip);
    size_t members = 0;
    for (size_t i = 0; i < zip.count; ++i)
        if (!xx_zip_py_info_is_dir(&zip.infos[i])) ++members;
    /* The whole-file scan (job 0) and the members of the outermost archive
       in parallel, unless this scan is itself a job of a parallel run. The
       jobs' matches can be put in the sequential order (cx_pool_merge) only
       for rules whose namespaces are contiguous and when this scanner has
       scanned nothing before; otherwise everything runs in sequence. */
    if (!scanner->log && members > 0 && cx_thread_count(scanner->options) > 1 && !scanner->used &&
        scanner->namespaces && scanner->namespaces->contiguous) {
        cx_pool pool;
        memset(&pool, 0, sizeof(pool));
        pool.jobs = (cx_job *)cx_calloc(members + 1, sizeof(cx_job));
        pool.jobs[0].archive = true;
        pool.jobs[0].cost = size;
        pool.count = 1;
        for (size_t i = 0; i < zip.count; ++i) {
            if (xx_zip_py_info_is_dir(&zip.infos[i])) continue;
            pool.jobs[pool.count].info = &zip.infos[i];
            pool.jobs[pool.count].cost = cx_member_cost(&zip.infos[i]);
            ++pool.count;
        }
        pool.zip = &zip;
        pool.prefix = file_path;
        pool.results = results;
        pool.order = cx_rank_jobs(pool.jobs, pool.count);
        cx_pool_run(scanner, &pool, true);
        free(pool.order);
        free(pool.jobs);
    } else {
        cx_scan_whole(scanner, data, size, file_path, results);
        cx_scan_zip(scanner, &zip, 0, file_path, results);
    }
    xx_zip_py_close(&zip);
}

/* File jobs retain their results until the ordered flusher writes them. */
static void cx_scan_file_results(cx_scanner *scanner, const char *file_path, cx_results *results)
{
    int64_t size = 0;
    char *data = xx_fs_read_file(file_path, &size);
    if (!data) {
        cx_report(scanner, file_path, "could not read the file");
        return;
    }
    cx_scan_file_obj(scanner, (const uint8_t *)data, (size_t)size, file_path, results);
    scanner->used = true;
    xx_str_free(data);
}

/* Scanner.scan_file() */
static void cx_scan_file(cx_scanner *scanner, const char *file_path)
{
    cx_results results = {0};
    cx_scan_file_results(scanner, file_path, &results);
    if (results.count) cx_output_write(scanner->output, &results, scanner->log);
    cx_results_free(&results);
}

#ifdef _WIN32
/* os.walk() yields entries in file system order; NTFS keeps a directory
 * sorted by upper-cased name, so compare case-insensitively there. */
static int cx_compare_entries(const void *a, const void *b)
{
    const char *left = (*(xx_fs_entry_t *const *)a)->name, *right = (*(xx_fs_entry_t *const *)b)->name;
    for (size_t i = 0;; ++i) {
        int l = (unsigned char)left[i], r = (unsigned char)right[i];
        if (l >= 'a' && l <= 'z') l -= 'a' - 'A';
        if (r >= 'a' && r <= 'z') r -= 'a' - 'A';
        if (l != r) return l < r ? -1 : 1;
        if (!l) return strcmp(left, right);
    }
}
#endif

static bool cx_list_directory(const char *path, xx_list_t *entries)
{
    bool ok;
    if (!xx_list_init(entries, sizeof(xx_fs_entry_t *), NULL)) return false;
    ok = xx_fs_list_dir_sorted(path, entries, XX_FS_SORT_NAME);
#ifdef _WIN32
    if (xx_list_count(entries) > 1)
        qsort(xx_list_at(entries, 0), xx_list_count(entries), sizeof(xx_fs_entry_t *), cx_compare_entries);
#endif
    return ok;
}

static void cx_free_entries(xx_list_t *entries)
{
    for (size_t i = 0; i < xx_list_count(entries); ++i) xx_fs_entry_free(*(xx_fs_entry_t **)xx_list_at(entries, i));
    xx_list_cleanup(entries);
}

/* The files Scanner.scan(path) visits, in its order. */
typedef struct cx_paths {
    char **items;
    size_t count;
    size_t capacity;
} cx_paths;

static void cx_paths_add(cx_paths *paths, char *path)
{
    if (paths->count == paths->capacity) {
        paths->capacity = paths->capacity ? paths->capacity * 2 : 64;
        paths->items = (char **)cx_realloc(paths->items, paths->capacity * sizeof(char *));
    }
    paths->items[paths->count++] = path;
}

static void cx_collect(cx_scanner *scanner, const char *path, cx_paths *paths);

/* os.walk(followlinks=False): inspect the entry itself, not its target.
 * An explicitly supplied directory may still be a link; only descendants
 * discovered during the recursive walk are filtered here. */
static bool cx_walk_directory(const char *path)
{
#ifdef _WIN32
    wchar_t *wide = (wchar_t *)xx_rt_utf8_to_utf16(path);
    if (!wide) return false;
    DWORD needed = GetFullPathNameW(wide, 0, NULL, NULL);
    if (!needed) {
        xx_rt_free(wide);
        return false;
    }
    wchar_t *full = (wchar_t *)cx_malloc(((size_t)needed + 1) * sizeof(wchar_t));
    DWORD length = GetFullPathNameW(wide, needed + 1, full, NULL);
    xx_rt_free(wide);
    if (!length || length > needed) {
        free(full);
        return false;
    }
    /* Match xxfclib's long-path handling while inspecting the entry itself. */
    wchar_t *extended = NULL;
    const wchar_t *api_path = full;
    if (!(full[0] == L'\\' && full[1] == L'\\' && full[2] == L'?' && full[3] == L'\\')) {
        bool unc = full[0] == L'\\' && full[1] == L'\\';
        size_t skip = unc ? 2 : 0, prefix = unc ? 8 : 4;
        extended = (wchar_t *)cx_malloc((prefix + length - skip + 1) * sizeof(wchar_t));
        memcpy(extended, unc ? L"\\\\?\\UNC\\" : L"\\\\?\\", prefix * sizeof(wchar_t));
        memcpy(extended + prefix, full + skip, (length - skip + 1) * sizeof(wchar_t));
        api_path = extended;
    }
    DWORD attributes = GetFileAttributesW(api_path);
    free(extended);
    free(full);
    return attributes != INVALID_FILE_ATTRIBUTES &&
           (attributes & (FILE_ATTRIBUTE_DIRECTORY | FILE_ATTRIBUTE_REPARSE_POINT)) == FILE_ATTRIBUTE_DIRECTORY;
#else
    struct stat info;
    return lstat(path, &info) == 0 && S_ISDIR(info.st_mode);
#endif
}

/* os.walk(): the files of a directory, then each subdirectory in turn. */
static void cx_collect_walk(cx_scanner *scanner, const char *directory, cx_paths *paths)
{
    xx_list_t entries;
    if (!cx_list_directory(directory, &entries)) {
        /* os.walk(onerror=None): a directory that cannot be listed is
           skipped without a message. */
        cx_free_entries(&entries);
        return;
    }
    for (size_t i = 0; i < xx_list_count(&entries); ++i) {
        xx_fs_entry_t *entry = *(xx_fs_entry_t **)xx_list_at(&entries, i);
        if (entry->type == XX_FS_ENTRY_DIR) continue;
        char *path = cx_path_join(directory, entry->name);
        cx_collect(scanner, path, paths);
        free(path);
    }
    for (size_t i = 0; i < xx_list_count(&entries); ++i) {
        xx_fs_entry_t *entry = *(xx_fs_entry_t **)xx_list_at(&entries, i);
        if (entry->type != XX_FS_ENTRY_DIR) continue;
        char *path = cx_path_join(directory, entry->name);
        if (cx_walk_directory(path)) cx_collect_walk(scanner, path, paths);
        free(path);
    }
    cx_free_entries(&entries);
}

/* Scanner.scan_directory() / _yield_file_paths() */
static void cx_collect_directory(cx_scanner *scanner, const char *directory, cx_paths *paths)
{
    if (scanner->options->recursive) {
        cx_collect_walk(scanner, directory, paths);
        return;
    }
    xx_list_t entries;
    if (!cx_list_directory(directory, &entries)) {
        cx_report(scanner, directory, "could not list the directory");
        cx_free_entries(&entries);
        return;
    }
    for (size_t i = 0; i < xx_list_count(&entries); ++i) {
        xx_fs_entry_t *entry = *(xx_fs_entry_t **)xx_list_at(&entries, i);
        char *path = cx_path_join(directory, entry->name);
        if (!xx_fs_is_dir(path)) cx_collect(scanner, path, paths);
        free(path);
    }
    cx_free_entries(&entries);
}

/* Scanner.scan() */
static void cx_collect(cx_scanner *scanner, const char *path, cx_paths *paths)
{
    if (xx_fs_is_file(path))
        cx_paths_add(paths, cx_strdup(path));
    else if (xx_fs_is_dir(path))
        cx_collect_directory(scanner, path, paths);
}

void cx_scanner_scan_inputs(cx_scanner *scanner, const char *const *inputs, size_t count)
{
    cx_paths paths = {0};
    for (size_t i = 0; i < count; ++i) cx_collect(scanner, inputs[i], &paths);
    if (paths.count > 1 && cx_thread_count(scanner->options) > 1 && scanner->namespaces && scanner->namespaces->contiguous) {
        cx_pool pool;
        memset(&pool, 0, sizeof(pool));
        pool.jobs = (cx_job *)cx_calloc(paths.count, sizeof(cx_job));
        for (size_t i = 0; i < paths.count; ++i) pool.jobs[i].path = paths.items[i];
        pool.count = paths.count;
        cx_pool_run(scanner, &pool, false);
        free(pool.jobs);
    } else {
        for (size_t i = 0; i < paths.count; ++i) cx_scan_file(scanner, paths.items[i]);
    }
    for (size_t i = 0; i < paths.count; ++i) free(paths.items[i]);
    free(paths.items);
}

bool cx_scanner_init(cx_scanner *scanner, const cx_options *options, const YRX_RULES *rules, cx_output *output,
                     char **error)
{
    memset(scanner, 0, sizeof(*scanner));
    scanner->options = options;
    scanner->output = output;
    scanner->rules = rules;
    if (cx_create_yrx(scanner, &scanner->yrx, options->timeout > 0, error) != YRX_SUCCESS) {
        cx_scanner_free(scanner);
        return false;
    }
    if (cx_thread_count(options) > 1) scanner->namespaces = cx_namespaces_create(rules);
    return true;
}

void cx_scanner_free(cx_scanner *scanner)
{
    for (size_t i = 0; i < scanner->worker_count; ++i)
        if (scanner->workers[i].yrx) yrx_scanner_destroy(scanner->workers[i].yrx);
    free(scanner->workers);
    scanner->workers = NULL;
    scanner->worker_count = 0;
    if (scanner->yrx) yrx_scanner_destroy(scanner->yrx);
    scanner->yrx = NULL;
    cx_namespaces_free(scanner->namespaces);
    scanner->namespaces = NULL;
}
