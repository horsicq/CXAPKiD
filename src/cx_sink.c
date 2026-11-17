/*
 * CXAPKiD - C port of APKiD (https://github.com/rednaga/APKiD)
 * Copyright (C) 2026 hors <horsicq@gmail.com>
 * SPDX-License-Identifier: MIT
 */
#include "cx_sink.h"

#include <xxfclib/algo/crc/xx_crc.h>

#include <stdlib.h>
#include <string.h>

#if defined(_WIN64)
#include <windows.h>
#define CX_SINK_SPACE 1
#endif

/* Committed memory grows in steps of at least this much (and at most 64 MiB
   ahead of the output). Readers use only the `size` bytes written: there is
   no guaranteed slack past them (later writes may fill the committed part). */
#define CX_SINK_COMMIT_STEP ((size_t)1 << 20)
#define CX_SINK_COMMIT_AHEAD ((size_t)64 << 20)
#define CX_SINK_SLACK ((size_t)64 << 10)

#ifdef CX_SINK_SPACE
/* Make at least `needed` bytes usable in the reservation. */
static bool cx_sink_commit(cx_sink *sink, size_t needed)
{
    size_t step = sink->capacity < CX_SINK_COMMIT_STEP ? CX_SINK_COMMIT_STEP : sink->capacity;
    if (step > CX_SINK_COMMIT_AHEAD) step = CX_SINK_COMMIT_AHEAD;
    size_t target = needed + 4096;
    if (target < sink->capacity + step) target = sink->capacity + step;
    target = (target + 0xFFFF) & ~(size_t)0xFFFF;
    if (target > sink->reserved) target = sink->reserved;
    if (!VirtualAlloc(sink->data + sink->capacity, target - sink->capacity, MEM_COMMIT, PAGE_READWRITE)) return false;
    sink->capacity = target;
    return true;
}
#endif

/* Room for `needed` bytes in total. */
static bool cx_sink_grow(cx_sink *sink, size_t needed)
{
#ifdef CX_SINK_SPACE
    if (sink->reserved) {
        if (needed <= sink->reserved - 4096) return cx_sink_commit(sink, needed);
        /* Beyond the reservation: the heap from here on, as before. */
        size_t capacity = sink->reserved;
        while (capacity < needed) capacity = capacity > SIZE_MAX / 2 ? needed : capacity * 2;
        if (capacity > sink->limit) capacity = sink->limit;
        uint8_t *heap = (uint8_t *)malloc(capacity);
        if (!heap) return false;
        if (sink->size) memcpy(heap, sink->data, sink->size);
        VirtualFree(sink->data, 0, MEM_RELEASE);
        sink->data = heap;
        sink->capacity = capacity;
        sink->reserved = 0;
        return true;
    }
#endif
    size_t capacity = sink->capacity ? sink->capacity : 65536;
    while (capacity < needed) capacity = capacity > SIZE_MAX / 2 ? needed : capacity * 2;
    if (capacity > sink->limit) capacity = sink->limit;
    uint8_t *larger = (uint8_t *)realloc(sink->data, capacity);
    if (!larger) return false;
    sink->data = larger;
    sink->capacity = capacity;
    return true;
}

static ssize_t cx_sink_write(xx_io_device *self, const void *buffer, size_t count)
{
    cx_sink *sink = (cx_sink *)self->priv;
    size_t room = sink->limit - sink->size, take = count < room ? count : room;
    if (take > sink->capacity - sink->size && !cx_sink_grow(sink, sink->size + take)) {
        sink->no_memory = true;
        return -1;
    }
    if (take) {
        memcpy(sink->data + sink->size, buffer, take);
        /* The CRC-32 of the kept bytes, while they are still in cache:
           the same value as one pass over all of them afterwards. */
        if (sink->checksum) sink->crc = xx_crc32_calc(sink->crc, buffer, take);
    }
    sink->size += take;
    if (take < count) {
        sink->full = true;
        return -1;
    }
    return (ssize_t)count;
}

static int64_t cx_sink_size(xx_io_device *self)
{
    return (int64_t)((cx_sink *)self->priv)->size;
}

static int cx_sink_seek64(xx_io_device *self, int64_t offset, int whence)
{
    /* Sequential output only: allow "seeks" that do not move. */
    cx_sink *sink = (cx_sink *)self->priv;
    int64_t target = whence == 0 ? offset : (int64_t)sink->size + offset;
    return target == (int64_t)sink->size ? 0 : -1;
}

static int cx_sink_seek(xx_io_device *self, long offset, int whence)
{
    return cx_sink_seek64(self, offset, whence);
}

static int cx_sink_close(xx_io_device *self)
{
    (void)self;
    return 0;
}

void cx_sink_init(cx_sink *sink, size_t limit)
{
    memset(sink, 0, sizeof(*sink));
    sink->limit = limit;
    sink->device.write = cx_sink_write;
    sink->device.seek = cx_sink_seek;
    sink->device.seek64 = cx_sink_seek64;
    sink->device.tell = cx_sink_size;
    sink->device.size = cx_sink_size;
    sink->device.total_size = cx_sink_size;
    sink->device.get_total_size = cx_sink_size;
    sink->device.close = cx_sink_close;
    sink->device.priv = sink;
}

void cx_sink_reserve(cx_sink *sink, size_t capacity)
{
    if (capacity > sink->limit) capacity = sink->limit;
    if (capacity <= sink->capacity || sink->reserved) return;
    uint8_t *larger = (uint8_t *)realloc(sink->data, capacity);
    if (!larger) return;
    sink->data = larger;
    sink->capacity = capacity;
}

bool cx_sink_reserve_space(cx_sink *sink, size_t capacity)
{
#ifdef CX_SINK_SPACE
    if (capacity > sink->limit) capacity = sink->limit;
    if (sink->data || capacity > SIZE_MAX - 2 * CX_SINK_SLACK) return false;
    size_t reserved = (capacity + CX_SINK_SLACK + 0xFFFF) & ~(size_t)0xFFFF;
    void *base = VirtualAlloc(NULL, reserved, MEM_RESERVE, PAGE_READWRITE);
    if (!base) return false;
    sink->data = (uint8_t *)base;
    sink->capacity = 0;
    sink->reserved = reserved;
    return true;
#else
    (void)sink;
    (void)capacity;
    return false;
#endif
}

uint8_t *cx_sink_detach(cx_sink *sink, size_t *size, bool *mapped)
{
    uint8_t *data = sink->data ? sink->data : (uint8_t *)malloc(1);
    *mapped = sink->data && sink->reserved;
    *size = data ? sink->size : 0;
    sink->data = NULL;
    sink->size = sink->capacity = sink->reserved = 0;
    return data;
}

void cx_sink_release(uint8_t *data, bool mapped)
{
#ifdef CX_SINK_SPACE
    if (mapped) {
        if (data) VirtualFree(data, 0, MEM_RELEASE);
        return;
    }
#else
    (void)mapped;
#endif
    free(data);
}

void cx_sink_free(cx_sink *sink)
{
    cx_sink_release(sink->data, sink->reserved != 0);
    sink->data = NULL;
    sink->size = sink->capacity = sink->reserved = 0;
}
