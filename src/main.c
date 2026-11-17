/*
 * CXAPKiD - C port of APKiD (https://github.com/rednaga/APKiD)
 * Copyright (C) 2026 hors <horsicq@gmail.com>
 * SPDX-License-Identifier: MIT
 *
 * apkid/main.py: the command line, parsed the way argparse parses it.
 */
#include "cx_apkid.h"
#include "cx_rules.h"

#include <ctype.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>

#ifdef _WIN32
#include <windows.h>
#include <shellapi.h>
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
    OPT_THREADS
} cx_option_id;

typedef struct cx_option_def {
    const char *short_name; /* "-t", "-st", or NULL */
    const char *long_name;  /* "--timeout" */
    const char *metavar;    /* NULL for flags */
    cx_option_id id;
} cx_option_def;

static const cx_option_def cx_option_defs[] = {
    {"-h", "--help", NULL, OPT_HELP},
    {"-v", "--verbose", NULL, OPT_VERBOSE},
    {"-t", "--timeout", "TIMEOUT", OPT_TIMEOUT},
    {"-r", "--recursive", NULL, OPT_RECURSIVE},
    {NULL, "--scan-depth", "SCAN_DEPTH", OPT_SCAN_DEPTH},
    {NULL, "--entry-max-scan-size", "ENTRY_MAX_SCAN_SIZE", OPT_ENTRY_MAX_SCAN_SIZE},
    {NULL, "--typing", "{magic,filename,none}", OPT_TYPING},
    {"-st", "--scan-trackers", NULL, OPT_SCAN_TRACKERS},
    {"-j", "--json", NULL, OPT_JSON},
    {"-o", "--output-dir", "DIR", OPT_OUTPUT_DIR},
    {"-m", "--print-matches", NULL, OPT_PRINT_MATCHES},
    {NULL, "--print-filter", "RULES", OPT_PRINT_FILTER},
    {NULL, "--include-types", NULL, OPT_INCLUDE_TYPES},
    {NULL, "--rules-dir", "DIR", OPT_RULES_DIR},
    {NULL, "--threads", "N", OPT_THREADS},
    {"-V", "--version", NULL, OPT_VERSION},
};
#define CX_OPTION_COUNT (sizeof(cx_option_defs) / sizeof(cx_option_defs[0]))

static const char cx_usage[] =
    "usage: " CX_PROG " [-h] [-v] [-t TIMEOUT] [-r] [--scan-depth SCAN_DEPTH]\n"
    "               [--entry-max-scan-size ENTRY_MAX_SCAN_SIZE]\n"
    "               [--typing {magic,filename,none}] [-st] [-j] [-o DIR] [-m]\n"
    "               [--print-filter RULES] [--include-types] [--rules-dir DIR]\n"
    "               [--threads N] [-V]\n"
    "               [FILE ...]\n";

static void cx_help(void)
{
    fputs(cx_usage, stdout);
    fputs("\n"
          "CXAPKiD - Android Application Identifier v" CXAPKID_APKID_VERSION " (C port, " CXAPKID_VERSION ")\n"
          CXAPKID_COPYRIGHT "\n"
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
          "  -V, --version                               show the version and exit\n",
          stdout);
}

static int cx_usage_error(const char *format, const char *a, const char *b)
{
    fputs(cx_usage, stderr);
    fprintf(stderr, CX_PROG ": error: ");
    fprintf(stderr, format, a, b);
    fputc('\n', stderr);
    return 2;
}

static const char *cx_option_label(const cx_option_def *def)
{
    static char label[96];
    if (def->short_name)
        snprintf(label, sizeof(label), "%s/%s", def->short_name, def->long_name);
    else
        snprintf(label, sizeof(label), "%s", def->long_name);
    return label;
}

/* argparse's _negative_number_matcher, ^-\d+$|^-\d*\.\d+$: such arguments
 * are values, not options. */
static bool cx_negative_number(const char *arg)
{
    const char *p = arg + 1;
    if (arg[0] != '-') return false;
    while (isdigit((unsigned char)*p)) ++p;
    if (!*p) return p > arg + 1;
    if (*p++ != '.' || !isdigit((unsigned char)*p)) return false;
    while (isdigit((unsigned char)*p)) ++p;
    return !*p;
}

/* int(text): surrounding whitespace, a sign and '_' between digits. */
static bool cx_parse_int(const char *text, int64_t *value)
{
    const char *p = text;
    bool negative = false, digit_seen = false;
    uint64_t result = 0;
    while (isspace((unsigned char)*p)) ++p;
    if (*p == '+' || *p == '-') negative = *p++ == '-';
    for (; *p; ++p) {
        if (*p == '_' && digit_seen && isdigit((unsigned char)p[1])) continue;
        if (!isdigit((unsigned char)*p)) break;
        digit_seen = true;
        if (result <= (UINT64_MAX - 9) / 10) result = result * 10 + (uint64_t)(*p - '0');
    }
    while (isspace((unsigned char)*p)) ++p;
    if (!digit_seen || *p) return false;
    if (negative)
        *value = result > (uint64_t)INT64_MAX ? INT64_MIN : -(int64_t)result;
    else
        *value = result > (uint64_t)INT64_MAX ? INT64_MAX : (int64_t)result;
    return true;
}

static void cx_name_set_add(cx_name_set *set, const char *name, size_t length)
{
    for (size_t i = 0; i < set->count; ++i)
        if (strlen(set->items[i]) == length && memcmp(set->items[i], name, length) == 0) return;
    set->items = (char **)cx_realloc(set->items, (set->count + 1) * sizeof(char *));
    set->items[set->count++] = cx_strndup(name, length);
}

/* parse_print_filter() */
static void cx_parse_print_filter(cx_options *options, const char *value)
{
    const char *token = value;
    for (;;) {
        const char *end = strchr(token, ',');
        size_t length = end ? (size_t)(end - token) : strlen(token);
        while (length && isspace((unsigned char)*token)) {
            ++token;
            --length;
        }
        while (length && isspace((unsigned char)token[length - 1])) --length;
        if (length) {
            if (token[0] == '-')
                cx_name_set_add(&options->print_exclude, token + 1, length - 1);
            else if (token[0] == '+')
                cx_name_set_add(&options->print_include, token + 1, length - 1);
            else
                cx_name_set_add(&options->print_include, token, length);
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
    case OPT_OUTPUT_DIR: options->output_dir = value; break;
    case OPT_PRINT_FILTER: args->print_filter = value; break;
    case OPT_RULES_DIR: options->rules_dir = value; break;
    case OPT_TYPING:
        if (strcmp(value, "magic") == 0)
            options->typing = CX_TYPING_MAGIC;
        else if (strcmp(value, "filename") == 0)
            options->typing = CX_TYPING_FILENAME;
        else if (strcmp(value, "none") == 0)
            options->typing = CX_TYPING_NONE;
        else
            return cx_usage_error("argument --typing: invalid choice: '%s' (choose from %s)", value,
                                  "'magic', 'filename', 'none'");
        break;
    case OPT_TIMEOUT:
    case OPT_SCAN_DEPTH:
    case OPT_ENTRY_MAX_SCAN_SIZE:
    case OPT_THREADS: {
        int64_t number;
        if (!cx_parse_int(value, &number))
            return cx_usage_error("argument %s: invalid int value: '%s'", cx_option_label(def), value);
        if (def->id == OPT_TIMEOUT)
            options->timeout = number;
        else if (def->id == OPT_SCAN_DEPTH)
            options->scan_depth = number;
        else if (def->id == OPT_THREADS)
            options->threads = number;
        else
            options->entry_max_scan_size = number;
        break;
    }
    }
    return 0;
}

/* The long option named by `name` (no '='): an exact name or a unique
 * prefix, as argparse's allow_abbrev does. */
static int cx_find_long(const char *name, size_t length, const cx_option_def **found)
{
    const cx_option_def *match = NULL;
    size_t matches = 0;
    for (size_t i = 0; i < CX_OPTION_COUNT; ++i) {
        const char *candidate = cx_option_defs[i].long_name;
        if (strlen(candidate) == length && memcmp(candidate, name, length) == 0) {
            *found = &cx_option_defs[i];
            return 1;
        }
        if (strlen(candidate) > length && memcmp(candidate, name, length) == 0) {
            match = &cx_option_defs[i];
            ++matches;
        }
    }
    *found = match;
    return (int)matches;
}

static int cx_parse_args(int argc, char **argv, cx_args *args)
{
    memset(args, 0, sizeof(*args));
    args->options.timeout = 30;
    args->options.scan_depth = 2;
    args->options.entry_max_scan_size = 100 * 1024 * 1024;
    args->options.typing = CX_TYPING_MAGIC;
    args->options.threads = 0;
    args->inputs = (const char **)cx_calloc((size_t)argc + 1, sizeof(char *));

    bool options_done = false;
    for (int i = 1; i < argc; ++i) {
        const char *arg = argv[i];
        const cx_option_def *def = NULL;
        const char *value = NULL;
        int code;

        if (options_done || arg[0] != '-' || !arg[1] || cx_negative_number(arg)) {
            args->inputs[args->input_count++] = arg;
            continue;
        }
        if (strcmp(arg, "--") == 0) {
            options_done = true;
            continue;
        }
        if (arg[1] == '-') {
            const char *equals = strchr(arg, '=');
            size_t length = equals ? (size_t)(equals - arg) : strlen(arg);
            int count = cx_find_long(arg, length, &def);
            if (count == 0) return cx_usage_error("unrecognized arguments: %s%s", arg, "");
            if (count > 1) {
                char *name = cx_strndup(arg, length);
                cx_buf candidates = {0};
                for (size_t k = 0; k < CX_OPTION_COUNT; ++k)
                    if (strncmp(cx_option_defs[k].long_name, name, length) == 0) {
                        if (candidates.length) cx_buf_puts(&candidates, ", ");
                        cx_buf_puts(&candidates, cx_option_defs[k].long_name);
                    }
                code = cx_usage_error("ambiguous option: %s could match %s", name, candidates.data);
                cx_buf_free(&candidates);
                free(name);
                return code;
            }
            if (equals) {
                if (!def->metavar)
                    return cx_usage_error("argument %s: ignored explicit argument '%s'", cx_option_label(def), equals + 1);
                value = equals + 1;
            }
        } else {
            /* Exact single-dash names first ("-st"), then "-tVALUE" and
               combined flags such as "-rv". */
            for (size_t k = 0; k < CX_OPTION_COUNT && !def; ++k)
                if (cx_option_defs[k].short_name && strcmp(cx_option_defs[k].short_name, arg) == 0)
                    def = &cx_option_defs[k];
            if (!def) {
                const char *p = arg + 1;
                while (*p) {
                    const cx_option_def *flag = NULL;
                    for (size_t k = 0; k < CX_OPTION_COUNT && !flag; ++k) {
                        const char *s = cx_option_defs[k].short_name;
                        if (s && s[1] == *p && !s[2]) flag = &cx_option_defs[k];
                    }
                    if (!flag) return cx_usage_error("unrecognized arguments: %s%s", arg, "");
                    if (flag->metavar) {
                        if (p[1]) {
                            value = p[1] == '=' ? p + 2 : p + 1;
                            def = flag;
                            break;
                        }
                        def = flag;
                        break;
                    }
                    if ((code = cx_apply_option(args, flag, NULL)) != 0) return code < 0 ? 0 : code;
                    ++p;
                }
                if (!def) continue;
            }
        }
        if (def->metavar && !value) {
            if (i + 1 >= argc || (argv[i + 1][0] == '-' && argv[i + 1][1] && !cx_negative_number(argv[i + 1])))
                return cx_usage_error("argument %s: expected one argument%s", cx_option_label(def), "");
            value = argv[++i];
        }
        if ((code = cx_apply_option(args, def, value)) != 0) return code < 0 ? 0 : code;
    }

    if (args->print_matches || (args->print_filter && *args->print_filter)) {
        args->options.print_matches = true;
        if (args->print_filter) cx_parse_print_filter(&args->options, args->print_filter);
    }
    return 0;
}

static int cx_run(int argc, char **argv)
{
    cx_args args;
    cx_rules rules;
    cx_output output;
    cx_scanner scanner;
    char *error = NULL;
    int result = cx_parse_args(argc, argv, &args);

    if (result != 0) goto cleanup;
    if (args.help) {
        cx_help();
        goto cleanup;
    }
    if (args.version) {
        printf(CX_PROG " %s (APKiD %s)\n" CXAPKID_COPYRIGHT "\n", CXAPKID_VERSION, CXAPKID_APKID_VERSION);
        goto cleanup;
    }
    if (!args.options.json && !args.options.output_dir)
        printf("[+] CXAPKiD %s :: APKiD %s port :: " CXAPKID_COPYRIGHT " :: rules from RedNaga :: rednaga.io\n",
               CXAPKID_VERSION, CXAPKID_APKID_VERSION);
    fflush(stdout);

    if (!cx_rules_load(&rules, args.options.rules_dir, args.options.include_trackers, &error)) {
        fprintf(stderr, CX_PROG ": %s\n", error ? error : "could not load rules");
        free(error);
        result = 1;
        goto cleanup;
    }
    cx_output_init(&output, &args.options, rules.sha256);
    if (!cx_scanner_init(&scanner, &args.options, rules.rules, &output, &error)) {
        fprintf(stderr, CX_PROG ": %s\n", error);
        free(error);
        cx_output_finish(&output);
        cx_rules_free(&rules);
        result = 1;
        goto cleanup;
    }
    cx_scanner_scan_inputs(&scanner, args.inputs, args.input_count);
    cx_scanner_free(&scanner);
    cx_output_finish(&output);
    cx_rules_free(&rules);
    if (output.failed) result = 1;
cleanup:
    if (fflush(stdout) != 0) result = 1;
    free((void *)args.inputs);
    cx_name_set_free(&args.options.print_include);
    cx_name_set_free(&args.options.print_exclude);
    return result;
}

#ifdef _WIN32
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

    wide = CommandLineToArgvW(GetCommandLineW(), &argc);
    if (!wide) {
        fputs(CX_PROG ": could not read the command line\n", stderr);
        if (restore_code_page) SetConsoleOutputCP(code_page);
        return 1;
    }
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
    LocalFree(wide);
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
