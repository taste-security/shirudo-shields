/* SPDX-License-Identifier: GPL-2.0 OR BSD-2-Clause */
/* Copyright (c) 2026 Authors of shirudo */
/*
 * Double-buffered arena hash table and its serializer, instantiated by
 * including this file once per table with OBS_T, OBS_T_MAP, OBS_T_KEY,
 * OBS_T_VAL, OBS_T_CAPACITY, OBS_T_BUCKETS, OBS_T_STEPS, OBS_T_MAGIC,
 * OBS_T_RECORD and OBS_T_EMIT defined.
 *
 * Hooks append into the active buffer; an export flips the buffers,
 * drains the inactive one and clears it, so the table holds one export
 * interval of records, never fills up for good, and reports the
 * allocations it refused.  Records are therefore per-interval deltas.
 */

#ifndef OBS_CAT
#define OBS_CAT_(a, b)	a##b
#define OBS_CAT(a, b)	OBS_CAT_(a, b)
#endif
#define OBS_FN(name)	OBS_CAT(OBS_CAT(OBS_T, _), name)

#define OBS_T_KEY_WORDS		(sizeof(OBS_T_KEY) / 8)
#define OBS_T_VAL_WORDS		(sizeof(OBS_T_VAL) / 8)
#define OBS_T_PER_CHUNK		(SERIAL_CHUNK_PAYLOAD / OBS_T_RECORD)
#define OBS_T_PER_PAGE		(OBS_T_PER_CHUNK * OBS_SERIAL_PAGE_CHUNKS)

BUILD_BUG_ON(sizeof(OBS_T_KEY) % 8);
BUILD_BUG_ON(sizeof(OBS_T_VAL) % 8);
BUILD_BUG_ON(OBS_T_BUCKETS & (OBS_T_BUCKETS - 1));
BUILD_BUG_ON(sizeof(struct obs_serial_header) > OBS_T_RECORD);
BUILD_BUG_ON(OBS_T_RECORD % 8);
BUILD_BUG_ON(OBS_T_PER_CHUNK < 1);
BUILD_BUG_ON_MSG(OBS_T_CAPACITY > 0xffff,
		 "table capacity must fit the header");

struct OBS_FN(entry) {
	__u32 next;
	__u32 used;
	OBS_T_KEY key;
	OBS_T_VAL val;
};

struct OBS_FN(table_state) {
	__u32 next_slot;
	__u32 overflow;
	__u64 since_ns;
	__u32 heads[OBS_T_BUCKETS];
	struct OBS_FN(entry) entries[OBS_T_CAPACITY + 1];
};

enum {
	OBS_FN(STATE_PAGES) = (sizeof(struct OBS_FN(table_state)) + 4095) / 4096,
};

static struct OBS_FN(table_state) __arena *OBS_FN(states)[2];
static struct OBS_FN(table_state) __arena *OBS_FN(active);
static struct OBS_FN(table_state) __arena *OBS_FN(drain);
static __u32 OBS_FN(lost);

static int OBS_T_EMIT(struct serial_chunk *chunk, __u32 off,
		      const struct OBS_FN(entry) __arena *e);

/*
 * The barrier keeps clang from turning the loop into a memset, which
 * the BPF backend cannot lower for arena memory.
 */
static __always_inline void
OBS_FN(clear)(struct OBS_FN(table_state) __arena *state)
{
	__u32 i;

#pragma clang loop unroll(disable)
	for (i = 0; i < OBS_T_BUCKETS; i++) {
		barrier_var(i);
		state->heads[i] = 0;
	}
	state->overflow = 0;
	state->next_slot = 1;
}

static __always_inline int OBS_FN(init)(__u64 now)
{
	struct OBS_FN(table_state) __arena *state;
	int i;

	if (READ_ONCE(OBS_FN(active)))
		return 0;
	for (i = 0; i < 2; i++) {
		state = bpf_arena_alloc_pages(&obs_i_arena, 0,
					      OBS_FN(STATE_PAGES),
					      NUMA_NO_NODE, 0);
		if (!state)
			return -ENOMEM;
		OBS_FN(clear)(state);
		state->since_ns = now;
		OBS_FN(states)[i] = state;
	}
	OBS_FN(drain) = OBS_FN(states)[1];
	__atomic_store_n(&OBS_FN(active), OBS_FN(states)[0], __ATOMIC_RELEASE);
	return 0;
}

static __always_inline struct OBS_FN(entry) __arena *
OBS_FN(touch)(const OBS_T_KEY *key, int *status)
{
	struct OBS_FN(table_state) __arena *state = READ_ONCE(OBS_FN(active));
	struct OBS_FN(entry) __arena *e;
	__u32 b, idx, head, i;

	*status = OBS_TOUCH_NO_STATE;
	if (!state) {
		obs_arena_associate();
		return 0;
	}
	b = obs_hash_words(key, OBS_T_KEY_WORDS) & (OBS_T_BUCKETS - 1);
	idx = READ_ONCE(state->heads[b]);
#pragma clang loop unroll(disable)
	for (i = 0; i < OBS_T_STEPS; i++) {
		if (idx == 0 || idx > OBS_T_CAPACITY)
			break;
		e = &state->entries[idx];
		if (READ_ONCE(e->used) &&
		    obs_words_equal(&e->key, key, OBS_T_KEY_WORDS)) {
			*status = OBS_TOUCH_HIT;
			return e;
		}
		idx = READ_ONCE(e->next);
	}

	idx = __sync_fetch_and_add(&state->next_slot, 1);
	if (idx == 0 || idx > OBS_T_CAPACITY) {
		__sync_fetch_and_add(&state->overflow, 1);
		*status = OBS_TOUCH_OVERFLOW;
		return 0;
	}
	e = &state->entries[idx];
	e->used = 0;
	obs_copy_in(&e->key, key, OBS_T_KEY_WORDS);
	obs_zero(&e->val, OBS_T_VAL_WORDS);
#pragma clang loop unroll(disable)
	for (i = 0; i < 4; i++) {
		head = READ_ONCE(state->heads[b]);
		e->next = head;
		if (__sync_val_compare_and_swap(&state->heads[b], head, idx) ==
		    head) {
			WRITE_ONCE(e->used, 1);
			*status = OBS_TOUCH_CREATED;
			return e;
		}
	}
	__sync_fetch_and_add(&state->overflow, 1);
	*status = OBS_TOUCH_CAS_FAIL;
	return 0;
}

static __always_inline void OBS_FN(flip)(__u64 now)
{
	struct OBS_FN(table_state) __arena *cur = READ_ONCE(OBS_FN(active));
	struct OBS_FN(table_state) __arena *spare = OBS_FN(drain);
	__u32 n;

	if (!cur || !spare)
		return;
	if (spare->next_slot != 1) {
		n = spare->next_slot - 1;
		if (n > OBS_T_CAPACITY)
			n = OBS_T_CAPACITY;
		OBS_FN(lost) += n;
		OBS_FN(clear)(spare);
	}
	spare->since_ns = now;
	__atomic_store_n(&OBS_FN(active), spare, __ATOMIC_RELEASE);
	OBS_FN(drain) = cur;
}

static __always_inline struct serial_chunk *
OBS_FN(slot)(__u32 page_slot, __u32 *off_out)
{
	struct serial_chunk *chunk;
	__u32 key, slot, off;

	barrier_var(page_slot);
	if (page_slot >= OBS_T_PER_PAGE)
		return 0;
	key = page_slot / OBS_T_PER_CHUNK;
	slot = page_slot % OBS_T_PER_CHUNK;
	barrier_var(key);
	barrier_var(slot);
	if (key >= OBS_SERIAL_PAGE_CHUNKS)
		return 0;
	off = slot * OBS_T_RECORD;
	barrier_var(off);
	if (off > SERIAL_CHUNK_PAYLOAD - OBS_T_RECORD)
		return 0;
	chunk = bpf_map_lookup_elem(&shirudo_ser, &key);
	if (!chunk)
		return 0;
	*off_out = off;
	return chunk;
}

static __always_inline int OBS_FN(chunk_meta)(__u32 key, __u32 flags,
					      __u32 total_chunks,
					      __u32 page_bytes,
					      const struct serialize_ctx *ctx,
					      __u64 next_cursor)
{
	struct serial_chunk *chunk;
	__u32 used;

	if (key >= total_chunks)
		return 0;
	used = page_bytes - key * SERIAL_CHUNK_PAYLOAD;
	if (used > SERIAL_CHUNK_PAYLOAD)
		used = SERIAL_CHUNK_PAYLOAD;
	chunk = bpf_map_lookup_elem(&shirudo_ser, &key);
	if (!chunk)
		return -ENOSPC;
	chunk->magic = SERIAL_MAGIC;
	chunk->version = SERIAL_VERSION;
	chunk->flags = flags;
	chunk->status = 0;
	chunk->chunk_index = key;
	chunk->total_chunks = total_chunks;
	chunk->bytes_total = page_bytes;
	chunk->bytes_in_chunk = used;
	chunk->page_index = ctx->page_index;
	chunk->reserved = 0;
	chunk->cursor = ctx->cursor;
	chunk->next_cursor = next_cursor;
	chunk->invocation_id = ctx->invocation_id;
	return 0;
}

static __always_inline int
OBS_FN(emit_header)(const struct OBS_FN(table_state) __arena *state,
		    __u32 hdr_flags, __u64 now)
{
	struct serial_chunk *chunk;
	__u32 off, used;

	chunk = OBS_FN(slot)(0, &off);
	if (!chunk)
		return -ENOSPC;
	used = state->next_slot ? state->next_slot - 1 : 0;
	if (used > OBS_T_CAPACITY)
		used = OBS_T_CAPACITY;
	*(__u32 *)&chunk->data[off] = OBS_T_MAGIC;
	*(__u16 *)&chunk->data[off + 4] = OBS_SERIAL_VERSION;
	*(__u16 *)&chunk->data[off + 6] = sizeof(struct obs_serial_header);
	*(__u16 *)&chunk->data[off + 8] = OBS_T_RECORD;
	*(__u16 *)&chunk->data[off + 10] = OBS_T_PER_PAGE;
	*(__u32 *)&chunk->data[off + 12] = OBS_T_CAPACITY;
	*(__u32 *)&chunk->data[off + 16] = OBS_T_BUCKETS;
	*(__u32 *)&chunk->data[off + 20] = sizeof(OBS_T_KEY);
	*(__u32 *)&chunk->data[off + 24] = sizeof(OBS_T_VAL);
	*(__u32 *)&chunk->data[off + 28] = hdr_flags;
	*(__u64 *)&chunk->data[off + 32] = now;
	*(__u64 *)&chunk->data[off + 40] = state->since_ns;
	*(__u32 *)&chunk->data[off + 48] = used;
	*(__u32 *)&chunk->data[off + 52] = state->overflow;
	*(__u32 *)&chunk->data[off + 56] = OBS_FN(lost);
	*(__u32 *)&chunk->data[off + 60] = 0;
	return 0;
}

struct OBS_FN(emit_ctx) {
	struct OBS_FN(table_state) __arena *state;
	__u32 start;
	__u32 used;
	__u32 output_slots;
	__u32 next;
	int ret;
};

static int OBS_FN(emit_cb)(__u32 scanned, void *data)
{
	struct OBS_FN(emit_ctx) *emit = data;
	struct OBS_FN(entry) __arena *e;
	struct serial_chunk *chunk;
	__u32 idx, off;
	int ret;

	if (emit->ret)
		return 1;
	idx = emit->start + scanned + 1;
	if (idx == 0 || idx > emit->used || idx > OBS_T_CAPACITY) {
		emit->next = emit->used;
		return 1;
	}
	if (emit->output_slots >= OBS_T_PER_PAGE) {
		emit->next = idx - 1;
		return 1;
	}
	emit->next = idx;
	e = &emit->state->entries[idx];
	if (!e->used)
		return 0;
	chunk = OBS_FN(slot)(emit->output_slots, &off);
	if (!chunk) {
		emit->ret = -ENOSPC;
		return 1;
	}
	*(__u32 *)&chunk->data[off] = idx;
	*(__u32 *)&chunk->data[off + 4] = OBS_REC_F_PRESENT;
	ret = OBS_T_EMIT(chunk, off, e);
	if (ret) {
		emit->ret = ret;
		return 1;
	}
	emit->output_slots++;
	return 0;
}

SEC("syscall")
int OBS_CAT(shirudo_serialize__, OBS_T_MAP)(struct serialize_ctx *ctx)
{
	struct OBS_FN(emit_ctx) emit = {};
	struct OBS_FN(table_state) __arena *state;
	__u32 flags = 0, hdr_flags = 0, total_chunks, page_bytes, scan, i;
	__u64 now = obs_now();
	bool peek;
	int ret;

	if (!obs_serial_ctx_valid(ctx))
		return -EINVAL;
	if (ctx->max_chunks < OBS_SERIAL_PAGE_CHUNKS) {
		obs_serial_error(ctx, -E2BIG);
		return -E2BIG;
	}
	if (ctx->cursor > OBS_T_CAPACITY) {
		obs_serial_error(ctx, -EINVAL);
		return -EINVAL;
	}
	peek = (ctx->flags & OBS_CTX_F_PEEK) != 0;
	if (peek) {
		hdr_flags |= OBS_HDR_F_PEEK;
		state = READ_ONCE(OBS_FN(active));
	} else {
		if (ctx->cursor == 0)
			OBS_FN(flip)(now);
		state = OBS_FN(drain);
	}
	if (!state) {
		obs_arena_associate();
		obs_serial_error(ctx, -ENOMEM);
		return -ENOMEM;
	}

#pragma clang loop unroll(full)
	for (i = 0; i < OBS_SERIAL_PAGE_CHUNKS; i++) {
		ret = OBS_FN(chunk_meta)(i, 0, OBS_SERIAL_PAGE_CHUNKS,
					 OBS_SERIAL_PAGE_CHUNKS *
					 SERIAL_CHUNK_PAYLOAD,
					 ctx, ctx->cursor);
		if (ret) {
			obs_serial_error(ctx, ret);
			return ret;
		}
	}
	ret = OBS_FN(emit_header)(state, hdr_flags, now);
	if (ret) {
		obs_serial_error(ctx, ret);
		return ret;
	}

	emit.state = state;
	emit.start = (__u32)ctx->cursor;
	emit.used = state->next_slot ? state->next_slot - 1 : 0;
	if (emit.used > OBS_T_CAPACITY)
		emit.used = OBS_T_CAPACITY;
	emit.output_slots = 1;
	emit.next = emit.start;
	if (emit.start < emit.used) {
		scan = emit.used - emit.start;
		ret = bpf_loop(scan, OBS_FN(emit_cb), &emit, 0);
		if (ret < 0) {
			obs_serial_error(ctx, ret);
			return ret;
		}
		if (emit.ret) {
			obs_serial_error(ctx, emit.ret);
			return emit.ret;
		}
	} else {
		emit.next = emit.used;
	}

	if (emit.next >= emit.used) {
		flags = SERIAL_F_DONE;
		if (!peek) {
			OBS_FN(clear)(state);
			OBS_FN(lost) = 0;
		}
	}
	total_chunks = (emit.output_slots + OBS_T_PER_CHUNK - 1) /
		       OBS_T_PER_CHUNK;
	if (total_chunks == 0)
		total_chunks = 1;
	page_bytes = (total_chunks - 1) * SERIAL_CHUNK_PAYLOAD +
		     (emit.output_slots - (total_chunks - 1) *
		      OBS_T_PER_CHUNK) * OBS_T_RECORD;
#pragma clang loop unroll(full)
	for (i = 0; i < OBS_SERIAL_PAGE_CHUNKS; i++) {
		ret = OBS_FN(chunk_meta)(i, flags, total_chunks, page_bytes,
					 ctx, emit.next);
		if (ret)
			return ret;
	}
	return 0;
}

#undef OBS_T_KEY_WORDS
#undef OBS_T_VAL_WORDS
#undef OBS_T_PER_CHUNK
#undef OBS_T_PER_PAGE
#undef OBS_FN
#undef OBS_T
#undef OBS_T_MAP
#undef OBS_T_KEY
#undef OBS_T_VAL
#undef OBS_T_CAPACITY
#undef OBS_T_BUCKETS
#undef OBS_T_STEPS
#undef OBS_T_MAGIC
#undef OBS_T_RECORD
#undef OBS_T_EMIT
