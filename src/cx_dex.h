/*
 * CXAPKiD - C port of APKiD (https://github.com/rednaga/APKiD)
 * Copyright (C) 2026 hors <horsicq@gmail.com>
 * SPDX-License-Identifier: MIT
 *
 * APKiD runs its rules on yara-python-dex, whose dex module is YARA 3.11's.
 * A few of its rules use parts of that module that YARA-X's dex module does
 * not have (the fields and methods defined in class data, the string ID
 * offsets). This unit walks a DEX the way YARA 3.11's dex_parse() does and
 * computes those values; the scanner hands them to the rules as globals.
 */
#ifndef CX_DEX_H
#define CX_DEX_H

#include "cx_common.h"

#ifdef __cplusplus
extern "C" {
#endif

/* Globals defined for every rule set and set before each scan. */
#define CX_GLOBAL_UNICODE_FIELD_NAMES "cxapkid_dex_unicode_field_names"
#define CX_GLOBAL_UNICODE_METHOD_NAMES "cxapkid_dex_unicode_method_names"
#define CX_GLOBAL_UNSORTED_STRING_POOL "cxapkid_dex_unsorted_string_pool"

typedef struct cx_dex_legacy {
    /* YARA 3.11 parses the data: magic "dex\n035\0" to "dex\n038\0" and a
       whole header. Otherwise every dex.* value is undefined there. */
    bool parsed;
    /* for i in (0..dex.header.field_ids_size): dex.field[i].name has a
       byte outside 0x00-0x7F (what /[^\x00-\x7F]{1,4}/ finds) */
    int64_t unicode_field_names;
    /* the same over dex.method[i], i <= dex.header.method_ids_size */
    int64_t unicode_method_names;
    /* for any i in (0..dex.header.string_ids_size - 1) :
       (dex.string_ids[i + 1].offset < dex.string_ids[i].offset) */
    bool unsorted_string_pool;
} cx_dex_legacy;

void cx_dex_legacy_analyze(const uint8_t *data, size_t size, cx_dex_legacy *result);

#ifdef __cplusplus
}
#endif

#endif
