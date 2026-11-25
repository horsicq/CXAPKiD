/*
 * CXAPKiD - C port of APKiD (https://github.com/rednaga/APKiD)
 * Copyright (C) 2026 hors <horsicq@gmail.com>
 * SPDX-License-Identifier: MIT
 */
/* POSIX 2008 for readlink() on Linux. Not on the BSDs and macOS: there a
 * _POSIX_C_SOURCE hides the extensions used below (sysctl() and
 * KERN_PROC_PATHNAME on FreeBSD), and their default visibility already
 * includes POSIX 2008. */
#if !defined(_WIN32) && !defined(__FreeBSD__) && !defined(__APPLE__) && !defined(_POSIX_C_SOURCE)
#define _POSIX_C_SOURCE 200809L
#endif

#include "cx_rules.h"

#include <xxfclib/algo/sha/xx_sha.h>
#include <xxfclib/fs/xx_fs.h>
#include <xxfclib/list/xx_list.h>
#include <xxfclib/strings/xx_string.h>

#include <stdlib.h>
#include <string.h>

#ifdef _WIN32
#include <windows.h>
#elif defined(__APPLE__)
#include <mach-o/dyld.h>
#elif defined(__FreeBSD__)
#include <sys/types.h>
#include <sys/sysctl.h>
#else
#include <unistd.h>
#endif

#define CX_RULES_MAX_INCLUDE_DEPTH 16

typedef struct cx_source {
    char *key;  /* file path */
    char *name; /* relative path, used as namespace and origin */
    const uint8_t *data;
    size_t size;
    char *owned; /* xx_fs_read_file() result */
    bool expanding;
} cx_source;

typedef struct cx_source_set {
    cx_source *items;
    size_t count;
    size_t capacity;
} cx_source_set;

/* Resolve the running image, not argv[0] or the working directory: packages
 * must find their own rules when launched through PATH, a shortcut or a link. */
static char *cx_executable_path(void)
{
#ifdef _WIN32
    for (DWORD capacity = 256; capacity <= 32768; capacity *= 2) {
        wchar_t *wide = (wchar_t *)cx_malloc((size_t)capacity * sizeof(*wide));
        DWORD length = GetModuleFileNameW(NULL, wide, capacity);
        if (!length) {
            free(wide);
            return NULL;
        }
        if (length < capacity) {
            wide[length] = L'\0';
            char *utf8 = xx_str_unicode_to_utf8(wide);
            free(wide);
            if (!utf8) return NULL;
            char *path = cx_strdup(utf8);
            xx_str_free(utf8);
            return path;
        }
        free(wide);
    }
    return NULL;
#elif defined(__APPLE__)
    char probe[1];
    uint32_t size = sizeof(probe);
    if (_NSGetExecutablePath(probe, &size) == 0 || !size) return NULL;
    char *path = (char *)cx_malloc(size);
    if (_NSGetExecutablePath(path, &size) != 0) {
        free(path);
        return NULL;
    }
    char *absolute = realpath(path, NULL);
    free(path);
    return absolute;
#elif defined(__FreeBSD__)
    int mib[] = {CTL_KERN, KERN_PROC, KERN_PROC_PATHNAME, -1};
    size_t size = 0;
    if (sysctl(mib, 4, NULL, &size, NULL, 0) != 0 || !size) return NULL;
    char *path = (char *)cx_malloc(size + 1);
    if (sysctl(mib, 4, path, &size, NULL, 0) != 0) {
        free(path);
        return NULL;
    }
    path[size] = '\0';
    return path;
#elif defined(__linux__)
    for (size_t capacity = 256; capacity <= 1024 * 1024; capacity *= 2) {
        char *path = (char *)cx_malloc(capacity + 1);
        ssize_t length = readlink("/proc/self/exe", path, capacity);
        if (length < 0) {
            free(path);
            return NULL;
        }
        if ((size_t)length < capacity) {
            path[length] = '\0';
            return path;
        }
        free(path);
    }
    return NULL;
#else
    return NULL;
#endif
}

static char *cx_default_rules_dir(void)
{
    char *executable = cx_executable_path();
    if (!executable) return NULL;
    char *directory = xx_fs_path_dir(executable);
    free(executable);
    if (!directory) return NULL;
    char *rules_dir = cx_path_join(directory, "rules");
    xx_str_free(directory);
    return rules_dir;
}

static cx_source *cx_source_add(cx_source_set *set)
{
    if (set->count == set->capacity) {
        set->capacity = set->capacity ? set->capacity * 2 : 32;
        set->items = (cx_source *)cx_realloc(set->items, set->capacity * sizeof(*set->items));
    }
    cx_source *source = &set->items[set->count++];
    memset(source, 0, sizeof(*source));
    return source;
}

static void cx_source_set_free(cx_source_set *set)
{
    for (size_t i = 0; i < set->count; ++i) {
        free(set->items[i].key);
        free(set->items[i].name);
        if (set->items[i].owned) xx_str_free(set->items[i].owned);
    }
    free(set->items);
    memset(set, 0, sizeof(*set));
}

static bool cx_rules_selected(const char *name, bool include_trackers)
{
    /* RulesManager._collect_yara_files() */
    if (!cx_ends_with_nocase(name, ".yara")) return false;
    const char *base = strrchr(name, '/');
    base = base ? base + 1 : name;
    if (!include_trackers && cx_ends_with_nocase(base, "trackers.yara") && strlen(base) == strlen("trackers.yara")) return false;
    return true;
}

/* Collapse "." and ".." segments of a '/' separated relative path. Returns
 * NULL when the path leaves the root. */
static char *cx_rules_normalize(const char *path)
{
    char *copy = cx_strdup(path);
    char **parts = (char **)cx_calloc(strlen(path) + 1, sizeof(char *));
    size_t count = 0;
    for (char *token = copy; token;) {
        char *slash = strchr(token, '/');
        if (slash) *slash = '\0';
        if (strcmp(token, "..") == 0) {
            if (!count) {
                free(parts);
                free(copy);
                return NULL;
            }
            --count;
        } else if (*token && strcmp(token, ".") != 0) {
            parts[count++] = token;
        }
        token = slash ? slash + 1 : NULL;
    }
    cx_buf out = {0};
    for (size_t i = 0; i < count; ++i) {
        if (i) cx_buf_putc(&out, '/');
        cx_buf_puts(&out, parts[i]);
    }
    free(parts);
    free(copy);
    return cx_buf_detach(&out);
}

/* The end of the first `count` '/'-separated components at `from` (after the
 * separator that ends the last one, or at the end of the string). */
static size_t cx_rules_skip_components(const char *path, size_t from, unsigned count)
{
    while (count--) {
        const char *slash = strchr(path + from, '/');
        if (!slash) return strlen(path);
        from = (size_t)(slash - path) + 1;
    }
    return from;
}

static bool cx_rules_drive(const char *path)
{
    return ((path[0] >= 'A' && path[0] <= 'Z') || (path[0] >= 'a' && path[0] <= 'z')) && path[1] == ':' && path[2] == '/';
}

/* A path with '/' separators and "." / ".." collapsed, keeping its root:
 * "/" (POSIX), "C:/" (drive), "//server/share/" (UNC), "//?/C:/" and
 * "//?/UNC/server/share/" (Windows extended-length paths; "//./" likewise),
 * so an executable or a rule directory on a network share or a long path
 * still resolves. When ".." would leave the root, the path is returned with
 * '/' separators only, uncollapsed (it then names no collected file). */
static char *cx_rules_canonical(const char *path)
{
    char *copy = cx_strdup(path);
    for (char *p = copy; *p; ++p)
        if (*p == '\\') *p = '/';
    size_t root = 0;
    if (copy[0] == '/' && copy[1] == '/' && (copy[2] == '?' || copy[2] == '.') && copy[3] == '/') {
        root = 4;
        if (strncmp(copy + 4, "UNC/", 4) == 0) root = cx_rules_skip_components(copy, 8, 2); /* //?/UNC/server/share/ */
        else if (cx_rules_drive(copy + 4)) root = 7;                                        /* //?/C:/ */
    } else if (copy[0] == '/' && copy[1] == '/') {
        root = cx_rules_skip_components(copy, 2, 2); /* //server/share/ */
    } else if (cx_rules_drive(copy)) {
        root = 3; /* C:/ */
    } else if (copy[0] == '/') {
        root = 1;
    }
    char *rest = cx_rules_normalize(copy + root);
    if (!rest) return copy;
    char *canonical = cx_format("%.*s%s", (int)root, copy, rest);
    free(rest);
    free(copy);
    return canonical;
}

static void cx_rules_walk(cx_source_set *set, const char *directory, const char *relative)
{
    xx_list_t entries;
    if (!xx_list_init(&entries, sizeof(xx_fs_entry_t *), NULL)) return;
    xx_fs_list_dir_sorted(directory, &entries, XX_FS_SORT_NAME);
    for (size_t i = 0; i < xx_list_count(&entries); ++i) {
        xx_fs_entry_t *entry = *(xx_fs_entry_t **)xx_list_at(&entries, i);
        char *name = *relative ? cx_format("%s/%s", relative, entry->name) : cx_strdup(entry->name);
        char *path = cx_path_join(directory, entry->name);
        if (entry->type == XX_FS_ENTRY_DIR) {
            cx_rules_walk(set, path, name);
            free(path);
            free(name);
        } else {
            cx_source *source = cx_source_add(set);
            source->key = path;
            source->name = name;
        }
        xx_fs_entry_free(entry);
    }
    xx_list_cleanup(&entries);
}

static bool cx_source_load(cx_source *source, char **error)
{
    int64_t size = 0;
    if (source->data || source->owned) return true;
    source->owned = xx_fs_read_file(source->key, &size);
    if (!source->owned || size < 0) {
        *error = cx_format("%s: could not read rule file", source->key);
        return false;
    }
    source->data = (const uint8_t *)source->owned;
    source->size = (size_t)size;
    return true;
}

static bool cx_rules_absolute(const char *path)
{
    if (path[0] == '/' || path[0] == '\\') return true;
#ifdef _WIN32
    if (((path[0] >= 'A' && path[0] <= 'Z') || (path[0] >= 'a' && path[0] <= 'z')) && path[1] == ':') return true;
#endif
    return false;
}

static cx_source *cx_rules_resolve(cx_source_set *set, const cx_source *from, const char *include, char **error)
{
    /* Directory rules: resolve against the including file, as YARA does. */
    char *path;
    if (cx_rules_absolute(include)) {
        path = cx_strdup(include);
    } else {
        const char *base = cx_path_basename(from->key);
        path = cx_format("%.*s%s", (int)(base - from->key), from->key, include);
    }
    char *key = cx_rules_canonical(path);
    free(path);
    cx_source *found = NULL;
    for (size_t i = 0; i < set->count && !found; ++i) {
        char *candidate = cx_rules_canonical(set->items[i].key);
        if (strcmp(candidate, key) == 0) found = &set->items[i];
        free(candidate);
    }
    if (!found) {
#ifdef _WIN32
        /* Extended-length (\\?\) paths are not normalized by Windows, so
           UNC and extended keys go back to '\' before the file is opened. */
        if (key[0] == '/' && key[1] == '/')
            for (char *p = key; *p; ++p)
                if (*p == '/') *p = '\\';
#endif
        if (!xx_fs_is_file(key)) {
            *error = cx_format("%s: include file not found: %s", from->name, include);
            free(key);
            return NULL;
        }
        found = cx_source_add(set);
        found->key = key;
        found->name = cx_strdup(key);
        return found;
    }
    free(key);
    return found;
}

static bool cx_rules_identifier_start(unsigned char c)
{
    return (c >= 'a' && c <= 'z') || (c >= 'A' && c <= 'Z') || c == '_';
}

static bool cx_rules_space(unsigned char c)
{
    return c == ' ' || c == '\t' || c == '\r' || c == '\n' || c == '\f' || c == '\v';
}

/* Strings and regular expressions both escape their closing delimiter with
 * a backslash. In YARA, a non-comment '/' starts a regexp; division is '\\'. */
static size_t cx_rules_skip_literal(const char *text, size_t size, size_t position)
{
    char delimiter = text[position++];
    while (position < size) {
        char c = text[position++];
        if (c == delimiter) break;
        if (c == '\\' && position < size) ++position;
    }
    return position;
}

/* The caller has consumed the include keyword outside comments/literals.
 * Consume only its quoted path, leaving any following tokens intact. Include
 * paths retain backslashes, as in YARA's include lexer (Windows paths). */
static bool cx_rules_include_path(const char *text, size_t size, size_t *position, char **path)
{
    size_t i = *position;
    if (i == size || !cx_rules_space((unsigned char)text[i])) return false;
    while (i < size && cx_rules_space((unsigned char)text[i])) ++i;
    if (i == size || text[i] != '"') return false;
    size_t start = ++i;
    while (i < size && text[i] != '"') ++i;
    if (i == size) return false;
    *path = cx_strndup(text + start, i - start);
    *position = i + 1;
    return true;
}

/* Textual include expansion: the compiler sees one source per namespace,
 * exactly what YARA's include statement produces. */
static bool cx_rules_expand(cx_source_set *set, size_t index, cx_buf *out, unsigned depth, char **error)
{
    if (depth > CX_RULES_MAX_INCLUDE_DEPTH) {
        *error = cx_format("%s: includes nested too deeply", set->items[index].name);
        return false;
    }
    if (!cx_source_load(&set->items[index], error)) return false;
    if (set->items[index].expanding) {
        *error = cx_format("%s: recursive include", set->items[index].name);
        return false;
    }
    set->items[index].expanding = true;
    const char *text = (const char *)set->items[index].data;
    size_t size = set->items[index].size, position = 0, copied = 0;
    bool ok = true;
    while (ok && position < size) {
        unsigned char c = (unsigned char)text[position];
        if (c == '/' && position + 1 < size && text[position + 1] == '/') {
            position += 2;
            while (position < size && text[position] != '\n') ++position;
            continue;
        }
        if (c == '/' && position + 1 < size && text[position + 1] == '*') {
            position += 2;
            while (position + 1 < size && !(text[position] == '*' && text[position + 1] == '/')) ++position;
            position = position + 1 < size ? position + 2 : size;
            continue;
        }
        if (c == '"' || c == '/') {
            position = cx_rules_skip_literal(text, size, position);
            continue;
        }
        if (!cx_rules_identifier_start(c)) {
            ++position;
            continue;
        }
        size_t start = position++;
        while (position < size && (cx_rules_identifier_start((unsigned char)text[position]) || (text[position] >= '0' && text[position] <= '9'))) ++position;
        char *include = NULL;
        if (position - start == 7 && memcmp(text + start, "include", 7) == 0 && cx_rules_include_path(text, size, &position, &include)) {
            cx_buf_append(out, text + copied, start - copied);
            cx_source *target = cx_rules_resolve(set, &set->items[index], include, error);
            free(include);
            if (!target) {
                ok = false;
                break;
            }
            /* resolve() may grow the array; work with indexes. */
            size_t target_index = (size_t)(target - set->items);
            cx_buf_putc(out, '\n');
            ok = cx_rules_expand(set, target_index, out, depth + 1, error);
            cx_buf_putc(out, '\n');
            copied = position;
        }
    }
    /* Even an empty file must supply a non-NULL, NUL-terminated compiler
     * source. Appending zero bytes allocates that empty string as well. */
    if (ok) cx_buf_append(out, text + copied, size - copied);
    set->items[index].expanding = false;
    return ok;
}

static void cx_rules_hash_update(xx_sha256_context *context, const uint8_t *data, size_t size)
{
    /* Hash with LF line ends, so a CRLF checkout yields upstream's value. */
    size_t start = 0;
    for (size_t i = 0; i + 1 < size; ++i) {
        if (data[i] == '\r' && data[i + 1] == '\n') {
            xx_sha256_update(context, data + start, i - start);
            start = i + 1;
        }
    }
    xx_sha256_update(context, data + start, size - start);
}

static int cx_rules_compare(const void *a, const void *b)
{
    return strcmp(((const cx_source *)a)->name, ((const cx_source *)b)->name);
}

bool cx_rules_load(cx_rules *rules, const char *rules_dir, bool include_trackers, char **error)
{
    cx_source_set set = {0};
    size_t *selected = NULL, selected_count = 0;
    YRX_COMPILER *compiler = NULL;
    xx_sha256_context context;
    uint8_t digest[32];
    bool ok = false;
    char *default_dir = NULL;

    memset(rules, 0, sizeof(*rules));
    *error = NULL;
    if (!rules_dir) {
        default_dir = cx_default_rules_dir();
        if (!default_dir) {
            *error = cx_strdup("could not find the executable directory; use --rules-dir DIR");
            goto done;
        }
        rules_dir = default_dir;
    }
    if (!xx_fs_is_dir(rules_dir)) {
        *error = cx_format("%s: rules directory not found", rules_dir);
        goto done;
    }
    cx_rules_walk(&set, rules_dir, "");
    if (set.count > 1) qsort(set.items, set.count, sizeof(*set.items), cx_rules_compare);
    selected = (size_t *)cx_calloc(set.count + 1, sizeof(*selected));
    for (size_t i = 0; i < set.count; ++i)
        if (cx_rules_selected(set.items[i].name, include_trackers)) selected[selected_count++] = i;
    if (!selected_count) {
        *error = cx_format("%s: no .yara rule files found", rules_dir);
        goto done;
    }

    if (!xx_sha256_init(&context)) {
        *error = cx_strdup("SHA-256 is not available");
        goto done;
    }
    for (size_t i = 0; i < selected_count; ++i) {
        cx_source *source = &set.items[selected[i]];
        if (!cx_source_load(source, error)) goto done;
        cx_rules_hash_update(&context, source->data, source->size);
    }
    if (!xx_sha256_final(&context, digest, sizeof(digest))) {
        *error = cx_strdup("SHA-256 failed");
        goto done;
    }
    for (size_t i = 0; i < sizeof(digest); ++i) {
        static const char hex[] = "0123456789abcdef";
        rules->sha256[i * 2] = hex[digest[i] >> 4];
        rules->sha256[i * 2 + 1] = hex[digest[i] & 15];
    }
    rules->sha256[64] = '\0';

    if (yrx_compiler_create(0, &compiler) != YRX_SUCCESS) {
        *error = cx_format("creating compiler: %s", yrx_last_error() ? yrx_last_error() : "failed");
        goto done;
    }
    /* yara-python never shows compiler warnings, and neither does CXAPKiD:
       not collecting them saves about a tenth of the compile. */
    (void)yrx_compiler_max_warnings(compiler, 0);
    /* Values of YARA 3.11's dex module that YARA-X lacks (cx_rules.h). */
    if (yrx_compiler_define_global_int(compiler, CX_GLOBAL_UNICODE_FIELD_NAMES, 0) != YRX_SUCCESS ||
        yrx_compiler_define_global_int(compiler, CX_GLOBAL_UNICODE_METHOD_NAMES, 0) != YRX_SUCCESS ||
        yrx_compiler_define_global_bool(compiler, CX_GLOBAL_UNSORTED_STRING_POOL, false) != YRX_SUCCESS) {
        *error = cx_format("defining globals: %s", yrx_last_error() ? yrx_last_error() : "failed");
        goto done;
    }
    for (size_t i = 0; i < selected_count; ++i) {
        cx_buf source = {0};
        char *name;
        if (!cx_rules_expand(&set, selected[i], &source, 0, error)) {
            cx_buf_free(&source);
            goto done;
        }
        name = set.items[selected[i]].name;
        if (memchr(source.data, '\0', source.length)) {
            *error = cx_format("%s: rule source contains a NUL byte", name);
            cx_buf_free(&source);
            goto done;
        }
        if (yrx_compiler_new_namespace(compiler, name) != YRX_SUCCESS || yrx_compiler_add_source_with_origin(compiler, source.data, name) != YRX_SUCCESS) {
            const char *message = yrx_last_error();
            *error = cx_format("%s: %s", name, message && *message ? message : "compilation failed");
            cx_buf_free(&source);
            goto done;
        }
        cx_buf_free(&source);
    }
    rules->rules = yrx_compiler_build(compiler);
    if (!rules->rules) {
        *error = cx_format("building rules: %s", yrx_last_error() ? yrx_last_error() : "failed");
        goto done;
    }
    rules->file_count = selected_count;
    ok = true;
done:
    if (compiler) yrx_compiler_destroy(compiler);
    free(selected);
    cx_source_set_free(&set);
    free(default_dir);
    return ok;
}

void cx_rules_free(cx_rules *rules)
{
    if (rules->rules) yrx_rules_destroy(rules->rules);
    memset(rules, 0, sizeof(*rules));
}
