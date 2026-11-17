/*
 * CXAPKiD - C port of APKiD (https://github.com/rednaga/APKiD)
 * Copyright (C) 2026 hors <horsicq@gmail.com>
 * SPDX-License-Identifier: MIT
 *
 * lzma.decompress(data) for ZIP members stored with method 95 (XZ):
 * .xz streams whose filter chain is LZMA2, and .lzma (LZMA_Alone) data,
 * decoded with xxfclib's LZMA codecs.
 */
#ifndef CX_XZ_H
#define CX_XZ_H

#include "cx_common.h"

#ifdef __cplusplus
extern "C" {
#endif

/* Returns true and a malloc'ed buffer on success, false and an error
 * message (caller frees) otherwise. */
bool cx_xz_decompress(const uint8_t *data, size_t size, uint8_t **out, size_t *out_size, char **error);

#ifdef __cplusplus
}
#endif

#endif
