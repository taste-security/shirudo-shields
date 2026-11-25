/* SPDX-License-Identifier: GPL-2.0 OR BSD-2-Clause */
/* Copyright (c) 2026 Authors of shirudo */
/*
 * What obs_table.h needs, cut from shirudo's upatches/kernel-obs/obs_common.h
 * without the task, socket and network helpers of kernel-obs. A source
 * sets OBS_ARENA_PAGES before it includes the file.
 */
#ifndef KERNEL_OBS_COMMON_H
#define KERNEL_OBS_COMMON_H

#include <bpf/bpf_core_read.h>
#include "misc.h"

#if !defined(__BPF_FEATURE_ADDR_SPACE_CAST)
#error "BPF arena access requires clang address-space cast support"
#endif

#ifndef OBS_ARENA_PAGES
#error "define OBS_ARENA_PAGES before including obs_common.h"
#endif

#define __arena		__attribute__((address_space(1))) \
			__attribute__((btf_type_tag("arena")))
#define NUMA_NO_NODE	(-1)

#define E2BIG		7
#define ENOMEM		12
#define EINVAL		22
#define ENOSPC		28

/* Record and header flags shared by every serializer page. */
#define OBS_HDR_F_PEEK		(1u << 0)
#define OBS_REC_F_PRESENT	(1u << 0)

/* ctx->flags bit the exporter sets to read without draining. */
#define OBS_CTX_F_PEEK		SERIAL_CTX_F_PEEK

enum obs_touch_status {
	OBS_TOUCH_HIT = 0,
	OBS_TOUCH_CREATED = 1,
	OBS_TOUCH_NO_STATE = 2,
	OBS_TOUCH_OVERFLOW = 3,
	OBS_TOUCH_CAS_FAIL = 4,
};

struct {
	__uint(type, BPF_MAP_TYPE_ARENA);
	__uint(map_flags, BPF_F_MMAPABLE);
	__uint(max_entries, OBS_ARENA_PAGES);
#if defined(__TARGET_ARCH_arm64) || defined(__aarch64__)
	enum { obs_map_extra = 1ULL << 32 } map_extra;
#else
	enum { obs_map_extra = 1ULL << 44 } map_extra;
#endif
} obs_i_arena SEC(".maps");

struct {
	__uint(type, BPF_MAP_TYPE_ARRAY);
	__uint(max_entries, 4);
	__type(key, __u32);
	__type(value, struct serial_chunk);
} shirudo_ser SEC(".maps");

void __arena *bpf_arena_alloc_pages(void *map, void __arena *addr,
				    __u32 page_cnt, int node_id,
				    __u64 flags) __ksym __weak;

/*
 * The verifier binds a program to the arena only through a direct
 * reference to the map.  Programs that merely dereference pointers the
 * init program allocated make this no-op call on their cold path.
 */
static __always_inline void obs_arena_associate(void)
{
	bpf_arena_alloc_pages(&obs_i_arena, 0, 0, NUMA_NO_NODE, 0);
}

static __always_inline __u64 obs_now(void)
{
	return bpf_ktime_get_boot_ns();
}

static __always_inline __u64 obs_hash_mix(__u64 h, __u64 v)
{
	h ^= v + 0x9e3779b97f4a7c15ULL + (h << 6) + (h >> 2);
	h ^= h >> 33;
	h *= 0xff51afd7ed558ccdULL;
	h ^= h >> 33;
	return h;
}

/*
 * Word copies and compares keep the table template independent of the
 * key layout; every key and value is a multiple of eight bytes.  The
 * barriers keep clang from forming memcpy or memset intrinsics, which
 * the BPF backend cannot lower for arena memory.
 */
static __always_inline void obs_copy_in(void __arena *dst, const void *src,
					__u32 words)
{
	__u64 __arena *d = dst;
	const __u64 *s = src;
	__u32 i;

#pragma clang loop unroll(disable)
	for (i = 0; i < words; i++) {
		barrier_var(i);
		d[i] = s[i];
	}
}

static __always_inline void obs_zero(void __arena *dst, __u32 words)
{
	__u64 __arena *d = dst;
	__u32 i;

#pragma clang loop unroll(disable)
	for (i = 0; i < words; i++) {
		barrier_var(i);
		d[i] = 0;
	}
}

static __always_inline bool obs_words_equal(const void __arena *a,
					    const void *b, __u32 words)
{
	const __u64 __arena *x = a;
	const __u64 *y = b;
	__u32 i;

#pragma clang loop unroll(full)
	for (i = 0; i < words; i++) {
		if (x[i] != y[i])
			return false;
	}
	return true;
}

static __always_inline __u32 obs_hash_words(const void *p, __u32 words)
{
	const __u64 *w = p;
	__u64 h = 0;
	__u32 i;

#pragma clang loop unroll(full)
	for (i = 0; i < words; i++)
		h = obs_hash_mix(h, w[i]);
	return (__u32)h;
}

/* Serializer page header, written into slot zero of every page. */
struct obs_serial_header {
	__u32 magic;
	__u16 version;
	__u16 header_size;
	__u16 record_size;
	__u16 records_per_page;
	__u32 capacity;
	__u32 buckets;
	__u32 key_size;
	__u32 val_size;
	__u32 flags;
	__u64 boot_now_ns;
	__u64 since_ns;
	__u32 used;
	__u32 overflow;
	__u32 lost;
	__u32 reserved;
};

BUILD_BUG_ON(sizeof(struct obs_serial_header) != 64);

#define OBS_SERIAL_VERSION	1
#define OBS_SERIAL_PAGE_CHUNKS	4

static __always_inline void obs_serial_error(struct serialize_ctx *ctx,
					     int status)
{
	struct serial_chunk *chunk;
	__u32 key = 0;

	chunk = bpf_map_lookup_elem(&shirudo_ser, &key);
	if (!chunk)
		return;
	chunk->magic = SERIAL_MAGIC;
	chunk->version = SERIAL_VERSION;
	chunk->flags = SERIAL_F_DONE;
	chunk->status = status;
	chunk->chunk_index = 0;
	chunk->total_chunks = 1;
	chunk->bytes_total = 0;
	chunk->bytes_in_chunk = 0;
	chunk->page_index = ctx ? ctx->page_index : 0;
	chunk->reserved = 0;
	chunk->cursor = ctx ? ctx->cursor : 0;
	chunk->next_cursor = chunk->cursor;
	chunk->invocation_id = ctx ? ctx->invocation_id : 0;
}

/* Copy arena words into a serializer chunk at a verifier-known offset. */
static __always_inline void obs_emit_bytes(struct serial_chunk *chunk,
					   __u32 off, const void __arena *src,
					   __u32 words)
{
	const __u64 __arena *s = src;
	__u32 i;

#pragma clang loop unroll(full)
	for (i = 0; i < words; i++)
		*(__u64 *)&chunk->data[off + i * 8] = s[i];
}

static __always_inline bool
obs_serial_ctx_valid(const struct serialize_ctx *ctx)
{
	return ctx && ctx->magic == SERIAL_MAGIC &&
	       ctx->version == SERIAL_VERSION &&
	       ctx->chunk_payload_size == SERIAL_CHUNK_PAYLOAD;
}

#endif /* KERNEL_OBS_COMMON_H */
