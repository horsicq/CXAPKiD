/*
 * CXAPKiD - C port of APKiD (https://github.com/rednaga/APKiD)
 * Copyright (C) 2026 hors <horsicq@gmail.com>
 * SPDX-License-Identifier: MIT
 *
 * apkid/rules.py: the rule set APKiD compiles from the .yara files in
 * apkid/rules/<type> (trackers.yara only with --scan-trackers), one
 * namespace per file, and the
 * SHA-256 reported as "rules_sha256".
 */
#ifndef CX_RULES_H
#define CX_RULES_H

#include "cx_common.h"

#include <yara_x.h>

#ifdef __cplusplus
extern "C" {
#endif

/* Values of YARA 3.11's dex module that YARA-X lacks: globals defined for
 * every rule set and set before each scan from xxfclib's
 * xx_dex_legacy_analyze() (xxfclib/formats/executable/dex/xx_dex_legacy.h). */
#define CX_GLOBAL_UNICODE_FIELD_NAMES "cxapkid_dex_unicode_field_names"
#define CX_GLOBAL_UNICODE_METHOD_NAMES "cxapkid_dex_unicode_method_names"
#define CX_GLOBAL_UNSORTED_STRING_POOL "cxapkid_dex_unsorted_string_pool"

typedef struct cx_rules {
    YRX_RULES *rules;
    char sha256[65];
    size_t file_count;
} cx_rules;

/* Compile the *.yara files under rules_dir, or rules/ beside the executable
 * when rules_dir == NULL. On failure returns false with a message to free. */
bool cx_rules_load(cx_rules *rules, const char *rules_dir, bool include_trackers, char **error);
void cx_rules_free(cx_rules *rules);

#ifdef __cplusplus
}
#endif

#endif
