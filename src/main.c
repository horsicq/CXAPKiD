/*
 * CXAPKiD - C port of APKiD (https://github.com/rednaga/APKiD)
 * Copyright (C) 2026 hors <horsicq@gmail.com>
 * SPDX-License-Identifier: MIT
 *
 * apkid/main.py: the command line, parsed the way argparse parses it.
 */
#include "cx_apkid.h"
#include "cx_pyunicode.h"
#include "cx_rules.h"

#include <stdio.h>
#include <stdlib.h>
#include <string.h>

#ifdef _WIN32
#include <windows.h>
#include <wchar.h>
#endif

#define CX_PROG "cxapkid"

typedef enum cx_option_id {
    OPT_HELP,
    OPT_VERSION,
    OPT_VERBOSE,
    OPT_TIMEOUT,
    OPT_RECURSIVE,
    OPT_SCAN_DEPTH,
    OPT_ENTRY_MAX_SCAN_SIZE,
    OPT_TYPING,
    OPT_SCAN_TRACKERS,
    OPT_JSON,
    OPT_OUTPUT_DIR,
    OPT_PRINT_MATCHES,
    OPT_PRINT_FILTER,
    OPT_INCLUDE_TYPES,
    OPT_RULES_DIR,
    OPT_THREADS,
    OPT_DEX_ALL_VERSIONS
} cx_option_id;

typedef struct cx_option_def {
    const char *short_name; /* "-t", "-st", or NULL */
    const char *long_name;  /* "--timeout" */
    const char *metavar;    /* NULL for flags */
    cx_option_id id;
    bool apkid; /* an option of APKiD itself */
} cx_option_def;

/* In the order APKiD adds them to its parser (messages list them so); the
 * options APKiD does not have come last. */
static const cx_option_def cx_option_defs[] = {
    {"-h", "--help", NULL, OPT_HELP, true},
    {"-v", "--verbose", NULL, OPT_VERBOSE, true},
    {"-t", "--timeout", "TIMEOUT", OPT_TIMEOUT, true},
    {"-r", "--recursive", NULL, OPT_RECURSIVE, true},
    {NULL, "--scan-depth", "SCAN_DEPTH", OPT_SCAN_DEPTH, true},
    {NULL, "--entry-max-scan-size", "ENTRY_MAX_SCAN_SIZE", OPT_ENTRY_MAX_SCAN_SIZE, true},
    {NULL, "--typing", "{magic,filename,none}", OPT_TYPING, true},
    {"-st", "--scan-trackers", NULL, OPT_SCAN_TRACKERS, true},
    {"-j", "--json", NULL, OPT_JSON, true},
    {"-o", "--output-dir", "DIR", OPT_OUTPUT_DIR, true},
    {"-m", "--print-matches", NULL, OPT_PRINT_MATCHES, true},
    {NULL, "--print-filter", "RULES", OPT_PRINT_FILTER, true},
    {NULL, "--include-types", NULL, OPT_INCLUDE_TYPES, true},
    {NULL, "--rules-dir", "DIR", OPT_RULES_DIR, false},
    {NULL, "--threads", "N", OPT_THREADS, false},
    {NULL, "--dex-all-versions", NULL, OPT_DEX_ALL_VERSIONS, false},
    {"-V", "--version", NULL, OPT_VERSION, false},
};
#define CX_OPTION_COUNT (sizeof(cx_option_defs) / sizeof(cx_option_defs[0]))

/* argparse's _option_string_actions: every option string, in order. */
typedef struct cx_option_string {
    const char *name;
    const cx_option_def *def;
} cx_option_string;

static cx_option_string cx_option_strings[2 * CX_OPTION_COUNT];
static size_t cx_option_string_count;

static void cx_option_strings_init(void)
{
    cx_option_string_count = 0;
    for (size_t i = 0; i < CX_OPTION_COUNT; ++i) {
        const cx_option_def *def = &cx_option_defs[i];
        if (def->short_name) {
            cx_option_strings[cx_option_string_count].name = def->short_name;
            cx_option_strings[cx_option_string_count++].def = def;
        }
        cx_option_strings[cx_option_string_count].name = def->long_name;
        cx_option_strings[cx_option_string_count++].def = def;
    }
}

/* Wrapped at 100 columns, the width APKiD gives its help formatter. */
static const char cx_usage[] = "usage: " CX_PROG
                               " [-h] [-v] [-t TIMEOUT] [-r] [--scan-depth SCAN_DEPTH]\n"
                               "               [--entry-max-scan-size ENTRY_MAX_SCAN_SIZE] [--typing {magic,filename,none}] [-st]\n"
                               "               [-j] [-o DIR] [-m] [--print-filter RULES] [--include-types] [--rules-dir DIR]\n"
                               "               [--threads N] [--dex-all-versions] [-V]\n"
                               "               [FILE ...]\n";

static void cx_help(void)
{
    fputs(cx_usage, stdout);
    fputs(
        "\n"
        "CXAPKiD - Android Application Identifier v" CXAPKID_APKID_VERSION " (C port, " CXAPKID_VERSION ")\n" CXAPKID_COPYRIGHT
        "\n"
        "\n"
        "positional arguments:\n"
        "  FILE                                         apk, dex, or directory (default: None)\n"
        "\n"
        "options:\n"
        "  -h, --help                                   show this help message and exit\n"
        "  -v, --verbose                                log debug messages (default: False)\n"
        "\n"
        "scanning:\n"
        "  -t, --timeout TIMEOUT                        Yara scan timeout (in seconds) (default: 30)\n"
        "  -r, --recursive                              recurse into subdirectories (default: False)\n"
        "  --scan-depth SCAN_DEPTH                      how deep to go when scanning nested zips (default:\n"
        "                                               2)\n"
        "  --entry-max-scan-size ENTRY_MAX_SCAN_SIZE    max zip entry size to scan in bytes, 0 = no limit\n"
        "                                               (default: 104857600)\n"
        "  --typing {magic,filename,none}               method to decide which files to scan (default:\n"
        "                                               magic)\n"
        "  -st, --scan-trackers                         scans for embedded trackers (default: False)\n"
        "\n"
        "output:\n"
        "  -j, --json                                   output scan results in JSON format (default:\n"
        "                                               False)\n"
        "  -o, --output-dir DIR                         write individual results here (implies --json)\n"
        "                                               (default: None)\n"
        "  -m, --print-matches                          print matched rules and strings to stdout\n"
        "                                               (default: False)\n"
        "  --print-filter RULES                         filter printed matches: comma-separated rule\n"
        "                                               names to include ('+' or no prefix) or exclude\n"
        "                                               ('-' prefix). Implies --print-matches. Use '='\n"
        "                                               when the value starts with '-', e.g. --print-\n"
        "                                               filter=-is_apk,-is_signed_apk (default: )\n"
        "  --include-types                              include file type info for matched files\n"
        "                                               (default: False)\n"
        "\n"
        "CXAPKiD:\n"
        "  --rules-dir DIR                              compile the *.yara rules of DIR\n"
        "                                               (default: rules/ beside the executable)\n"
        "  --threads N                                  files or ZIP members scanned in parallel; the\n"
        "                                               output is the same; 0 = one per CPU, at most 8\n"
        "                                               (default: 0)\n"
        "  --dex-all-versions                           let the dex module parse DEX 039 and newer; APKiD\n"
        "                                               reports those as yara_issue (default: False)\n"
        "  -V, --version                               show the version and exit\n",
        stdout);
}

/* parser.error(): the usage, then the message; exit code 2. Takes over the
 * message buffer. */
static int cx_usage_error(cx_buf *message)
{
    fputs(cx_usage, stderr);
    fprintf(stderr, CX_PROG ": error: %s\n", message->data ? message->data : "");
    cx_buf_free(message);
    return 2;
}

/* "argument -t/--timeout: ", the start of an ArgumentError's text. */
static void cx_buf_put_argument(cx_buf *out, const cx_option_def *def)
{
    cx_buf_puts(out, "argument ");
    if (def->short_name) {
        cx_buf_puts(out, def->short_name);
        cx_buf_putc(out, '/');
    }
    cx_buf_puts(out, def->long_name);
    cx_buf_puts(out, ": ");
}

/* ------------------------------------------------ Python's view of text */

static bool cx_py_is_space(int32_t code_point)
{
    size_t low = 0, high = sizeof(cx_py_spaces) / sizeof(cx_py_spaces[0]);
    while (low < high) {
        size_t middle = (low + high) / 2;
        if (cx_py_spaces[middle] < (uint32_t)code_point) low = middle + 1;
        else high = middle;
    }
    return low < sizeof(cx_py_spaces) / sizeof(cx_py_spaces[0]) && cx_py_spaces[low] == (uint32_t)code_point;
}

/* The value of a decimal digit of any script, or -1. */
static int cx_py_digit(int32_t code_point)
{
    size_t low = 0, high = sizeof(cx_py_digit_zeros) / sizeof(cx_py_digit_zeros[0]);
    if (code_point < '0') return -1;
    /* the last run that starts at or before the code point */
    while (low < high) {
        size_t middle = (low + high) / 2;
        if (cx_py_digit_zeros[middle] <= (uint32_t)code_point) low = middle + 1;
        else high = middle;
    }
    if (!low || (uint32_t)code_point - cx_py_digit_zeros[low - 1] > 9) return -1;
    return (int)((uint32_t)code_point - cx_py_digit_zeros[low - 1]);
}

static bool cx_py_is_printable(int32_t code_point)
{
    size_t low = 0, high = sizeof(cx_py_unprintable) / sizeof(cx_py_unprintable[0]);
    if (code_point < 0x7F) return code_point >= 0x20;
    while (low < high) {
        size_t middle = (low + high) / 2;
        if (cx_py_unprintable[middle][1] < (uint32_t)code_point) low = middle + 1;
        else high = middle;
    }
    return code_point != 0x7F && !(low < sizeof(cx_py_unprintable) / sizeof(cx_py_unprintable[0]) && cx_py_unprintable[low][0] <= (uint32_t)code_point);
}

/* repr(text), which is how argparse quotes a value in its messages ('%r').
 * Bytes that are not UTF-8 are shown as the lone surrogates Python would
 * have decoded them to. */
static void cx_buf_put_repr(cx_buf *out, const char *text)
{
    const uint8_t *p = (const uint8_t *)text;
    size_t length = strlen(text);
    char quote = strchr(text, '\'') && !strchr(text, '"') ? '"' : '\'';
    cx_buf_putc(out, quote);
    for (size_t i = 0; i < length;) {
        int32_t code_point;
        size_t used = cx_utf8_decode(p + i, length - i, &code_point);
        if (code_point < 0) {
            cx_buf_printf(out, "\\udc%02x", (unsigned)p[i]);
        } else if (code_point == quote || code_point == '\\') {
            cx_buf_putc(out, '\\');
            cx_buf_putc(out, (char)code_point);
        } else if (code_point == '\t') {
            cx_buf_puts(out, "\\t");
        } else if (code_point == '\n') {
            cx_buf_puts(out, "\\n");
        } else if (code_point == '\r') {
            cx_buf_puts(out, "\\r");
        } else if (cx_py_is_printable(code_point)) {
            cx_buf_append(out, p + i, used);
        } else if (code_point <= 0xFF) {
            cx_buf_printf(out, "\\x%02x", (unsigned)code_point);
        } else if (code_point <= 0xFFFF) {
            cx_buf_printf(out, "\\u%04x", (unsigned)code_point);
        } else {
            cx_buf_printf(out, "\\U%08x", (unsigned)code_point);
        }
        i += used;
    }
    cx_buf_putc(out, quote);
}

/* One code point at *p (before `end`) as a decimal digit: steps over it and
 * returns true. */
static bool cx_py_skip_digit(const uint8_t **p, const uint8_t *end)
{
    int32_t code_point;
    size_t used;
    if (*p >= end) return false;
    used = cx_utf8_decode(*p, (size_t)(end - *p), &code_point);
    if (code_point < 0 || cx_py_digit(code_point) < 0) return false;
    *p += used;
    return true;
}

/* argparse's _negative_number_matcher, ^-\d+$|^-\d*\.\d+$ as Python's re
 * reads it: \d is a decimal digit of any script and $ also matches before
 * one final newline. Such arguments are values, not options. */
static bool cx_negative_number(const char *arg)
{
    const uint8_t *p = (const uint8_t *)arg + 1, *end;
    bool digits = false;
    if (arg[0] != '-') return false;
    end = p + strlen(arg + 1);
    while (cx_py_skip_digit(&p, end)) digits = true;
    if (p == end || (*p == '\n' && p + 1 == end)) return digits;
    if (*p++ != '.') return false;
    digits = false;
    while (cx_py_skip_digit(&p, end)) digits = true;
    return digits && (p == end || (*p == '\n' && p + 1 == end));
}

/* The longest value int() converts: sys.get_int_max_str_digits(). */
#define CX_PY_INT_MAX_DIGITS 4300

/* int(text): whitespace around it, a sign, decimal digits of any script and
 * single '_' between digits. A value outside int64_t saturates (Python has
 * no such limit). */
static bool cx_parse_int(const char *text, int64_t *value)
{
    const uint8_t *bytes = (const uint8_t *)text;
    size_t length = strlen(text), digit_count = 0;
    cx_buf ascii = {0};
    const char *p;
    bool negative = false, ok = false;
    uint64_t result = 0;

    /* Whitespace and digits outside ASCII become ' ' and '0'..'9' first, as
       in CPython; anything else outside ASCII is an error. */
    cx_buf_append(&ascii, "", 0);
    for (size_t i = 0; i < length;) {
        int32_t code_point;
        size_t used = cx_utf8_decode(bytes + i, length - i, &code_point);
        i += used;
        if (code_point >= 0 && code_point < 0x80) cx_buf_putc(&ascii, (char)code_point);
        else if (code_point >= 0 && cx_py_is_space(code_point)) cx_buf_putc(&ascii, ' ');
        else if (code_point >= 0 && cx_py_digit(code_point) >= 0) cx_buf_putc(&ascii, (char)('0' + cx_py_digit(code_point)));
        else goto done;
    }
    p = ascii.data;
    while (*p == ' ' || (*p >= '\t' && *p <= '\r')) ++p;
    if (*p == '+' || *p == '-') negative = *p++ == '-';
    for (; *p; ++p) {
        if (*p == '_' && digit_count && p[-1] != '_' && p[1] >= '0' && p[1] <= '9') continue;
        if (*p < '0' || *p > '9') break;
        ++digit_count;
        if (result <= (UINT64_MAX - 9) / 10) result = result * 10 + (uint64_t)(*p - '0');
        else result = UINT64_MAX;
    }
    while (*p == ' ' || (*p >= '\t' && *p <= '\r')) ++p;
    if (!digit_count || digit_count > CX_PY_INT_MAX_DIGITS || *p) goto done;
    if (negative) *value = result > (uint64_t)INT64_MAX ? INT64_MIN : -(int64_t)result;
    else *value = result > (uint64_t)INT64_MAX ? INT64_MAX : (int64_t)result;
    ok = true;
done:
    cx_buf_free(&ascii);
    return ok;
}

static void cx_name_set_add(cx_name_set *set, const char *name, size_t length)
{
    for (size_t i = 0; i < set->count; ++i)
        if (strlen(set->items[i]) == length && memcmp(set->items[i], name, length) == 0) return;
    set->items = (char **)cx_realloc(set->items, (set->count + 1) * sizeof(char *));
    set->items[set->count++] = cx_strndup(name, length);
}

/* parse_print_filter(); tokens lose the whitespace str.strip() removes. */
static void cx_parse_print_filter(cx_options *options, const char *value)
{
    const char *token = value;
    for (;;) {
        const char *end = strchr(token, ',');
        size_t length = end ? (size_t)(end - token) : strlen(token);
        size_t first = length, last = 0;
        for (size_t i = 0; i < length;) {
            int32_t code_point;
            size_t used = cx_utf8_decode((const uint8_t *)token + i, length - i, &code_point);
            bool space = code_point == ' ' || (code_point >= '\t' && code_point <= '\r') || (code_point >= 0x1C && code_point <= 0x1F) ||
                         (code_point >= 0x80 && cx_py_is_space(code_point));
            if (!space) {
                if (first == length) first = i;
                last = i + used;
            }
            i += used;
        }
        if (first < length) {
            const char *name = token + first;
            length = last - first;
            if (name[0] == '-') cx_name_set_add(&options->print_exclude, name + 1, length - 1);
            else if (name[0] == '+') cx_name_set_add(&options->print_include, name + 1, length - 1);
            else cx_name_set_add(&options->print_include, name, length);
        }
        if (!end) break;
        token = end + 1;
    }
}

static void cx_name_set_free(cx_name_set *set)
{
    for (size_t i = 0; i < set->count; ++i) free(set->items[i]);
    free(set->items);
    memset(set, 0, sizeof(*set));
}

typedef struct cx_args {
    cx_options options;
    const char **inputs;
    size_t input_count;
    bool print_matches;
    const char *print_filter;
    bool help;
    bool version;
} cx_args;

/* Apply one option; value is NULL for flags. Returns 0, an exit code, or -1
 * when parsing stops here (help and version).  */
static int cx_apply_option(cx_args *args, const cx_option_def *def, const char *value)
{
    cx_options *options = &args->options;
    cx_buf message = {0};
    switch (def->id) {
        /* argparse runs these actions as soon as they are parsed: arguments
           after them are not looked at. */
        case OPT_HELP: args->help = true; return -1;
        case OPT_VERSION: args->version = true; return -1;
        case OPT_VERBOSE: options->verbose = true; break;
        case OPT_RECURSIVE: options->recursive = true; break;
        case OPT_SCAN_TRACKERS: options->include_trackers = true; break;
        case OPT_JSON: options->json = true; break;
        case OPT_PRINT_MATCHES: args->print_matches = true; break;
        case OPT_INCLUDE_TYPES: options->include_types = true; break;
        case OPT_DEX_ALL_VERSIONS: options->dex_all_versions = true; break;
        case OPT_OUTPUT_DIR: options->output_dir = value; break;
        case OPT_PRINT_FILTER: args->print_filter = value; break;
        case OPT_RULES_DIR: options->rules_dir = value; break;
        case OPT_TYPING:
            if (strcmp(value, "magic") == 0) {
                options->typing = CX_TYPING_MAGIC;
            } else if (strcmp(value, "filename") == 0) {
                options->typing = CX_TYPING_FILENAME;
            } else if (strcmp(value, "none") == 0) {
                options->typing = CX_TYPING_NONE;
            } else {
                cx_buf_put_argument(&message, def);
                cx_buf_puts(&message, "invalid choice: ");
                cx_buf_put_repr(&message, value);
                cx_buf_puts(&message, " (choose from magic, filename, none)");
                return cx_usage_error(&message);
            }
            break;
        case OPT_TIMEOUT:
        case OPT_SCAN_DEPTH:
        case OPT_ENTRY_MAX_SCAN_SIZE:
        case OPT_THREADS: {
            int64_t number;
            if (!cx_parse_int(value, &number)) {
                cx_buf_put_argument(&message, def);
                cx_buf_puts(&message, "invalid int value: ");
                cx_buf_put_repr(&message, value);
                return cx_usage_error(&message);
            }
            if (def->id == OPT_TIMEOUT) options->timeout = number;
            else if (def->id == OPT_SCAN_DEPTH) options->scan_depth = number;
            else if (def->id == OPT_THREADS) options->threads = number;
            else options->entry_max_scan_size = number;
            break;
        }
    }
    return 0;
}

/* DECISION (the only place it is made): an abbreviation that APKiD resolves
 * to one of its own options keeps that meaning, although an option only
 * CXAPKiD has starts the same way: "--r" is --recursive (not ambiguous with
 * --rules-dir) and "--v", "--ve", "--ver" are --verbose (not ambiguous with
 * --version). Every command line APKiD accepts is then parsed as APKiD
 * parses it. Set to 0 for plain argparse behaviour over all options: those
 * four become "ambiguous option" errors. tests/argparse_parity.py has the
 * same switch (APKID_ABBREVIATION_FIRST), and tests/cli.cmake one case
 * (abbreviation_of_apkid_option). */
#define CX_APKID_ABBREVIATION_FIRST 1

/* One reading of an argument as an option: argparse's option tuple. */
typedef enum cx_separator {
    CX_SEP_ABSENT, /* no value in the argument */
    CX_SEP_NONE,   /* "-t5": the value follows the option directly */
    CX_SEP_EQUALS  /* "-t=5", "--timeout=5" */
} cx_separator;

typedef struct cx_option_tuple {
    const cx_option_def *def; /* NULL: looks like an option, but is none */
    const char *name;         /* the option string it stands for */
    cx_separator separator;
    const char *value; /* the explicit argument; NULL when absent */
} cx_option_tuple;

/* ArgumentParser._parse_optional() with _get_option_tuples(): false when
 * the argument is positional. Several tuples mean an ambiguous
 * abbreviation; `tuples` has room for every option string. */
static bool cx_parse_optional(const char *arg, cx_option_tuple *tuples, size_t *count)
{
    const char *equals;
    size_t prefix_length, apkid_count = 0, apkid_at = 0;
    cx_separator separator;

    *count = 0;
    if (arg[0] != '-') return false;
    for (size_t k = 0; k < cx_option_string_count; ++k)
        if (strcmp(cx_option_strings[k].name, arg) == 0) {
            cx_option_tuple tuple = {cx_option_strings[k].def, cx_option_strings[k].name, CX_SEP_ABSENT, NULL};
            tuples[(*count)++] = tuple;
            return true;
        }
    if (!arg[1]) return false;

    equals = strchr(arg, '=');
    prefix_length = equals ? (size_t)(equals - arg) : strlen(arg);
    separator = equals ? CX_SEP_EQUALS : CX_SEP_ABSENT;
    if (equals)
        for (size_t k = 0; k < cx_option_string_count; ++k) {
            const char *name = cx_option_strings[k].name;
            if (strlen(name) == prefix_length && memcmp(name, arg, prefix_length) == 0) {
                cx_option_tuple tuple = {cx_option_strings[k].def, name, CX_SEP_EQUALS, equals + 1};
                tuples[(*count)++] = tuple;
                return true;
            }
        }

    /* Abbreviations: any option string the text before '=' starts; and for
       a single dash also the one-letter option with the rest as its value. */
    for (size_t k = 0; k < cx_option_string_count; ++k) {
        const char *name = cx_option_strings[k].name;
        cx_option_tuple tuple = {cx_option_strings[k].def, name, separator, equals ? equals + 1 : NULL};
        if (arg[1] != '-' && name[1] == arg[1] && !name[2]) {
            tuple.separator = CX_SEP_NONE;
            tuple.value = arg + 2;
        } else if (strncmp(name, arg, prefix_length) != 0) {
            continue;
        }
        if (tuple.def->apkid) {
            ++apkid_count;
            apkid_at = *count;
        }
        tuples[(*count)++] = tuple;
    }
    if (CX_APKID_ABBREVIATION_FIRST && *count > 1 && apkid_count == 1) {
        tuples[0] = tuples[apkid_at];
        *count = 1;
    }
    if (*count) return true;

    if (cx_negative_number(arg)) return false;
    if (strchr(arg, ' ')) return false;
    {
        cx_option_tuple tuple = {NULL, arg, CX_SEP_ABSENT, NULL};
        tuples[(*count)++] = tuple;
    }
    return true;
}

/* ArgumentParser._parse_known_args() for one positional with nargs='*'. */
typedef struct cx_parser {
    cx_args *args;
    char **strings; /* the arguments after the program name */
    size_t count;
    char *pattern;        /* per argument: 'O' option, 'A' argument, '-' the "--" */
    bool positional_open; /* FILE has not taken its arguments yet */
    cx_buf extras;        /* arguments nothing consumed, joined by ' ' */
    size_t extra_count;
} cx_parser;

static void cx_parser_extra(cx_parser *parser, const char *prefix, const char *text)
{
    if (parser->extra_count++) cx_buf_putc(&parser->extras, ' ');
    cx_buf_puts(&parser->extras, prefix);
    cx_buf_puts(&parser->extras, text);
}

/* consume_positionals(): FILE takes the run of arguments at `start`, once;
 * the first "--" in it is dropped. Returns the index after the run. */
static size_t cx_consume_positionals(cx_parser *parser, size_t start)
{
    size_t end = start;
    bool dashes_dropped = false;
    if (!parser->positional_open) return start;
    while (end < parser->count && parser->pattern[end] != 'O') ++end;
    /* An empty match right before an option leaves FILE open. */
    if (end == start && end < parser->count) return start;
    for (size_t i = start; i < end; ++i) {
        if (parser->pattern[i] == '-' && !dashes_dropped) {
            dashes_dropped = true;
            continue;
        }
        parser->args->inputs[parser->args->input_count++] = parser->strings[i];
    }
    parser->positional_open = false;
    return end;
}

typedef struct cx_pending {
    const cx_option_def *def;
    const char *value;
} cx_pending;

/* consume_optional(): the option at `start`, the one-letter options packed
 * behind it ("-rvj") and its value. All of them are read before the first
 * is applied. Returns 0 and the next index in *stop, an exit code, or -1
 * when parsing stops (help, version). */
static int cx_consume_optional(cx_parser *parser, size_t start, size_t *stop)
{
    const char *arg = parser->strings[start];
    cx_option_tuple tuples[2 * CX_OPTION_COUNT + 1];
    size_t tuple_count = 0, pending_count = 0;
    cx_pending *pending;
    cx_buf message = {0};
    const cx_option_def *def;
    const char *name, *value;
    cx_separator separator;
    int code = 0;

    (void)cx_parse_optional(arg, tuples, &tuple_count);
    if (tuple_count > 1) {
        cx_buf_printf(&message, "ambiguous option: %s could match ", arg);
        for (size_t k = 0; k < tuple_count; ++k) {
            if (k) cx_buf_puts(&message, ", ");
            cx_buf_puts(&message, tuples[k].name);
        }
        return cx_usage_error(&message);
    }
    def = tuples[0].def;
    name = tuples[0].name;
    separator = tuples[0].separator;
    value = tuples[0].value;
    if (!def) {
        cx_parser_extra(parser, "", arg);
        *stop = start + 1;
        return 0;
    }

    pending = (cx_pending *)cx_calloc(strlen(arg) + 1, sizeof(*pending));
    for (;;) {
        if (!value) {
            /* the value, if the option takes one, is the next argument */
            if (def->metavar) {
                if (start + 1 >= parser->count || parser->pattern[start + 1] != 'A') {
                    cx_buf_put_argument(&message, def);
                    cx_buf_puts(&message, "expected one argument");
                    code = cx_usage_error(&message);
                    goto done;
                }
                pending[pending_count].def = def;
                pending[pending_count++].value = parser->strings[start + 1];
                *stop = start + 2;
            } else {
                pending[pending_count++].def = def;
                *stop = start + 1;
            }
            break;
        }
        if (def->metavar) {
            pending[pending_count].def = def;
            pending[pending_count++].value = value;
            *stop = start + 1;
            break;
        }
        /* A flag with text behind it: more one-letter options when the flag
           has a single dash and the text does not come after '='. */
        if (name[1] == '-' || !value[0] || separator == CX_SEP_EQUALS || value[0] == '-') {
            cx_buf_put_argument(&message, def);
            cx_buf_puts(&message, "ignored explicit argument ");
            cx_buf_put_repr(&message, value);
            code = cx_usage_error(&message);
            goto done;
        }
        pending[pending_count++].def = def;
        def = NULL;
        for (size_t k = 0; k < cx_option_string_count && !def; ++k) {
            const char *candidate = cx_option_strings[k].name;
            if (candidate[1] == value[0] && !candidate[2]) {
                def = cx_option_strings[k].def;
                name = candidate;
            }
        }
        if (!def) {
            cx_parser_extra(parser, "-", value);
            *stop = start + 1;
            break;
        }
        ++value;
        if (!*value) {
            value = NULL;
            separator = CX_SEP_ABSENT;
        } else if (*value == '=') {
            ++value;
            separator = CX_SEP_EQUALS;
        } else {
            separator = CX_SEP_NONE;
        }
    }
    for (size_t k = 0; k < pending_count && !code; ++k) code = cx_apply_option(parser->args, pending[k].def, pending[k].value);
done:
    free(pending);
    return code;
}

/* parse_args(): options and FILE runs alternate, as argparse reads them.
 * Returns 0 or the exit code of a usage error. */
static int cx_parse_args(int argc, char **argv, cx_args *args)
{
    cx_parser parser;
    cx_option_tuple tuples[2 * CX_OPTION_COUNT + 1];
    size_t tuple_count, start = 0, option_end = 0; /* option_end: one past the last option */
    bool options_done = false;
    int code = 0;

    memset(args, 0, sizeof(*args));
    args->options.timeout = 30;
    args->options.scan_depth = 2;
    args->options.entry_max_scan_size = 100 * 1024 * 1024;
    args->options.typing = CX_TYPING_MAGIC;
    args->options.threads = 0;
    args->inputs = (const char **)cx_calloc((size_t)argc + 1, sizeof(char *));
    cx_option_strings_init();

    memset(&parser, 0, sizeof(parser));
    parser.args = args;
    parser.strings = argv + 1;
    parser.count = argc > 1 ? (size_t)argc - 1 : 0;
    parser.pattern = (char *)cx_malloc(parser.count + 1);
    parser.positional_open = true;
    cx_buf_append(&parser.extras, "", 0);
    for (size_t i = 0; i < parser.count; ++i) {
        if (options_done) {
            parser.pattern[i] = 'A';
        } else if (strcmp(parser.strings[i], "--") == 0) {
            parser.pattern[i] = '-';
            options_done = true;
        } else if (cx_parse_optional(parser.strings[i], tuples, &tuple_count)) {
            parser.pattern[i] = 'O';
            option_end = i + 1;
        } else {
            parser.pattern[i] = 'A';
        }
    }
    parser.pattern[parser.count] = '\0';

    while (start < option_end) {
        size_t next = start;
        while (parser.pattern[next] != 'O') ++next;
        if (next != start) {
            size_t end = cx_consume_positionals(&parser, start);
            if (end > start) {
                start = end;
                continue;
            }
            /* FILE has its arguments already: these are left over */
            for (; start < next; ++start) cx_parser_extra(&parser, "", parser.strings[start]);
        }
        code = cx_consume_optional(&parser, start, &start);
        if (code) goto done;
    }
    start = cx_consume_positionals(&parser, start);
    for (; start < parser.count; ++start) cx_parser_extra(&parser, "", parser.strings[start]);

    if (parser.extra_count) {
        cx_buf message = {0};
        cx_buf_puts(&message, "unrecognized arguments: ");
        cx_buf_puts(&message, parser.extras.data);
        code = cx_usage_error(&message);
        goto done;
    }
    if (args->print_matches || (args->print_filter && *args->print_filter)) {
        args->options.print_matches = true;
        if (args->print_filter) cx_parse_print_filter(&args->options, args->print_filter);
    }
done:
    free(parser.pattern);
    cx_buf_free(&parser.extras);
    return code < 0 ? 0 : code;
}

#ifdef CXAPKID_PARSE_TEST
/* Only in the test program cxapkid_parse_test (never in cxapkid): it parses
 * its command line exactly as cxapkid does and prints the result instead
 * of scanning. tests/cli.cmake and tests/argparse_parity.py use it. */
static void cx_dump_names(cx_buf *out, const char *key, const cx_name_set *set)
{
    cx_buf_printf(out, ", \"%s\": [", key);
    for (size_t i = 0; i < set->count; ++i) {
        if (i) cx_buf_puts(out, ", ");
        cx_json_string(out, set->items[i]);
    }
    cx_buf_putc(out, ']');
}

/* What the command line was parsed to, as one JSON object named like
 * argparse's namespace. */
static void cx_dump_args(const cx_args *args)
{
    const cx_options *options = &args->options;
    cx_buf out = {0};
    cx_buf_puts(&out, "{\"input\": [");
    for (size_t i = 0; i < args->input_count; ++i) {
        if (i) cx_buf_puts(&out, ", ");
        cx_json_string(&out, args->inputs[i]);
    }
    cx_buf_printf(&out, "], \"verbose\": %s, \"timeout\": %lld, \"recursive\": %s, \"scan_depth\": %lld", options->verbose ? "true" : "false",
                  (long long)options->timeout, options->recursive ? "true" : "false", (long long)options->scan_depth);
    cx_buf_printf(&out, ", \"entry_max_scan_size\": %lld, \"typing\": \"%s\", \"scan_trackers\": %s, \"json\": %s", (long long)options->entry_max_scan_size,
                  options->typing == CX_TYPING_MAGIC      ? "magic"
                  : options->typing == CX_TYPING_FILENAME ? "filename"
                                                          : "none",
                  options->include_trackers ? "true" : "false", options->json ? "true" : "false");
    cx_buf_puts(&out, ", \"output_dir\": ");
    if (options->output_dir) cx_json_string(&out, options->output_dir);
    else cx_buf_puts(&out, "null");
    cx_buf_printf(&out, ", \"print_matches\": %s, \"print_filter\": ", args->print_matches ? "true" : "false");
    cx_json_string(&out, args->print_filter ? args->print_filter : "");
    cx_buf_printf(&out, ", \"include_types\": %s, \"filter_active\": %s", options->include_types ? "true" : "false", options->print_matches ? "true" : "false");
    cx_dump_names(&out, "filter_include", &options->print_include);
    cx_dump_names(&out, "filter_exclude", &options->print_exclude);
    cx_buf_puts(&out, ", \"rules_dir\": ");
    if (options->rules_dir) cx_json_string(&out, options->rules_dir);
    else cx_buf_puts(&out, "null");
    cx_buf_printf(&out, ", \"threads\": %lld, \"dex_all_versions\": %s}\n", (long long)options->threads, options->dex_all_versions ? "true" : "false");
    fputs(out.data, stdout);
    cx_buf_free(&out);
}
#else
/* Scan the inputs with the parsed options; the exit code. */
static int cx_scan(const cx_args *args)
{
    cx_rules rules;
    cx_output output;
    cx_scanner scanner;
    char *error = NULL;
    int result = 0;

    if (!args->options.json && !args->options.output_dir)
        printf("[+] CXAPKiD %s :: APKiD %s port :: " CXAPKID_COPYRIGHT " :: rules from RedNaga :: rednaga.io\n", CXAPKID_VERSION, CXAPKID_APKID_VERSION);
    fflush(stdout);

    if (!cx_rules_load(&rules, args->options.rules_dir, args->options.include_trackers, &error)) {
        fprintf(stderr, CX_PROG ": %s\n", error ? error : "could not load rules");
        free(error);
        return 1;
    }
    cx_output_init(&output, &args->options, rules.sha256);
    if (!cx_scanner_init(&scanner, &args->options, rules.rules, &output, &error)) {
        fprintf(stderr, CX_PROG ": %s\n", error);
        free(error);
        cx_output_finish(&output);
        cx_rules_free(&rules);
        return 1;
    }
    cx_scanner_scan_inputs(&scanner, args->inputs, args->input_count);
    cx_scanner_free(&scanner);
    cx_output_finish(&output);
    cx_rules_free(&rules);
    if (output.failed) result = 1;
    return result;
}
#endif

static int cx_run(int argc, char **argv)
{
    cx_args args;
    int result = cx_parse_args(argc, argv, &args);

    if (result != 0) {
        /* a usage error: reported */
    } else if (args.help) {
        cx_help();
    } else if (args.version) {
        printf(CX_PROG " %s (APKiD %s)\n" CXAPKID_COPYRIGHT "\n", CXAPKID_VERSION, CXAPKID_APKID_VERSION);
    } else {
#ifdef CXAPKID_PARSE_TEST
        cx_dump_args(&args);
#else
        result = cx_scan(&args);
#endif
    }
    if (fflush(stdout) != 0) result = 1;
    free((void *)args.inputs);
    cx_name_set_free(&args.options.print_include);
    cx_name_set_free(&args.options.print_exclude);
    return result;
}

#ifdef _WIN32
/* The arguments of a command line as the Microsoft C runtime (UCRT) splits
 * it for wmain(), which is what Python receives in sys.argv:
 * - the program name ends at a blank outside double quotes; nothing is
 *   escaped in it;
 * - arguments are separated by spaces and tabs outside double quotes;
 * - 2n backslashes before a quote are n backslashes and the quote toggles
 *   quoting; 2n+1 are n backslashes and a literal quote; other backslashes
 *   are literal;
 * - inside quotes, two quotes are one literal quote and quoting goes on.
 * CommandLineToArgvW() and the older msvcrt.dll (MinGW's default runtime)
 * differ in the last rule: there the second quote ends the quoting.
 * Returns the arguments (argv[0] included) in one block for free(). */
static wchar_t **cx_split_command_line(const wchar_t *line, int *count)
{
    size_t length = wcslen(line), used = 0;
    /* at most one argument per two characters, plus the program name */
    wchar_t **argv = (wchar_t **)cx_malloc((length / 2 + 3) * sizeof(wchar_t *) + (length + 2) * sizeof(wchar_t));
    wchar_t *out = (wchar_t *)(argv + length / 2 + 3);
    const wchar_t *p = line;
    bool in_quotes = false;
    int argc = 0;

    argv[argc++] = out;
    for (; *p && (in_quotes || (*p != L' ' && *p != L'\t')); ++p) {
        if (*p == L'"') in_quotes = !in_quotes;
        else out[used++] = *p;
    }
    out[used++] = L'\0';
    if (*p) ++p;

    in_quotes = false;
    for (;;) {
        while (*p == L' ' || *p == L'\t') ++p;
        if (!*p) break;
        argv[argc++] = out + used;
        for (;;) {
            bool copy = true;
            size_t slashes = 0;
            while (*p == L'\\') {
                ++p;
                ++slashes;
            }
            if (*p == L'"') {
                if (slashes % 2 == 0) {
                    if (in_quotes && p[1] == L'"') {
                        ++p; /* "" inside quotes: one quote */
                    } else {
                        copy = false;
                        in_quotes = !in_quotes;
                    }
                }
                slashes /= 2;
            }
            while (slashes--) out[used++] = L'\\';
            if (!*p || (!in_quotes && (*p == L' ' || *p == L'\t'))) break;
            if (copy) out[used++] = *p;
            ++p;
        }
        out[used++] = L'\0';
    }
    argv[argc] = NULL;
    *count = argc;
    return argv;
}

int main(void)
{
    int argc = 0, result = 1;
    char **argv = NULL;
    wchar_t **wide;
    UINT code_page = GetConsoleOutputCP();

    /* Report faults through the exit code instead of a blocking dialog. */
    (void)SetErrorMode(SetErrorMode(0) | SEM_FAILCRITICALERRORS | SEM_NOGPFAULTERRORBOX | SEM_NOOPENFILEERRORBOX);
    /* Results are UTF-8; let the console show them as such while we run. */
    bool restore_code_page = code_page && code_page != CP_UTF8 && SetConsoleOutputCP(CP_UTF8);

    wide = cx_split_command_line(GetCommandLineW(), &argc);
    argv = (char **)cx_calloc((size_t)argc + 1, sizeof(char *));
    for (int i = 0; i < argc; ++i) {
        int count = WideCharToMultiByte(CP_UTF8, 0, wide[i], -1, NULL, 0, NULL, NULL);
        if (count <= 0) {
            fputs(CX_PROG ": could not decode the command line\n", stderr);
            goto done;
        }
        argv[i] = (char *)cx_malloc((size_t)count);
        WideCharToMultiByte(CP_UTF8, 0, wide[i], -1, argv[i], count, NULL, NULL);
    }
    result = cx_run(argc, argv);
done:
    for (int i = 0; i < argc; ++i) free(argv[i]);
    free(argv);
    free(wide);
    fflush(stdout);
    if (restore_code_page) SetConsoleOutputCP(code_page);
    return result;
}
#else
int main(int argc, char **argv)
{
    return cx_run(argc, argv);
}
#endif
