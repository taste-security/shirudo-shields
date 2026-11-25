// SPDX-License-Identifier: GPL-2.0 OR BSD-2-Clause
/*
 * Copyright (c) 2026 Authors of shirudo-shields
 *
 * nginx2shell-h2guard: follows the HTTP/2 frames nginx reads and writes
 * through OpenSSL and ends the worker before it parses a WINDOW_UPDATE or
 * SETTINGS frame that takes a send window past 2^31-1 (RFC 9113 6.9.1).
 */
#define BPF_NO_KFUNC_PROTOTYPES
#include "h2guard_config.h"
#include "vmlinux.h"
#include <bpf/bpf_helpers.h>
#include <bpf/bpf_tracing.h>
#include "decoder.h"
#include "serializer.h"
#define OBS_ARENA_PAGES		128
#include "obs_common.h"

char _license[] SEC("license") = "Dual BSD/GPL";

#define EFAULT			14
#define EEXIST			17
#define SIGKILL			9

#define H2_MAX_WINDOW		0x7fffffffLL
#define H2_DEFAULT_WINDOW	65535
#define H2_PREFACE_LEN		24
#define H2_FRAME_HEADER_LEN	9
#define H2_WINDOW_UPDATE_LEN	4
#define H2_SETTING_LEN		6
#define H2_SETTINGS_INITIAL_WINDOW_SIZE	0x4
#define H2_FLAG_ACK		0x1
#define H2_STREAM_MASK		0x7fffffffu
#define H2_PARSER_BUF		16
#define H2_STREAM_SLOTS		8
#define H2_COMM_LEN		16

/*
 * One step of a walk takes a frame header, a field of a payload or the
 * rest of a payload, so it consumes four bytes or more but at the end of
 * the buffer: len / 4 + 4 steps finish any read or write, and the limit
 * covers 256 KiB, more than nginx hands OpenSSL at once.
 */
#define H2_WALK_MAX		(1u << 16)

enum h2_frame_type {
	H2_DATA = 0x0,
	H2_HEADERS = 0x1,
	H2_RST_STREAM = 0x3,
	H2_SETTINGS = 0x4,
	H2_WINDOW_UPDATE = 0x8,
	H2_CONTINUATION = 0x9,
};

enum h2_conn_mode {
	H2_MODE_PREFACE = 0,
	H2_MODE_FRAMES = 1,
	H2_MODE_IGNORED = 2,
};

/* decoders/h2_events.lua names these. */
enum h2_reason {
	H2_REASON_CONN_WINDOW = 1,
	H2_REASON_STREAM_WINDOW = 2,
	H2_REASON_SETTINGS_WINDOW = 3,
	H2_REASON_UNTRACKED = 4,
	H2_REASON_DESYNC = 5,
	H2_REASON_OVERSIZE = 6,
};

enum h2_action {
	H2_ACTION_RECORDED = 0,
	H2_ACTION_KILLED = 1,
	H2_ACTION_KILL_FAILED = 2,
};

enum h2_call_fn {
	H2_CALL_READ = 1,
	H2_CALL_WRITE = 2,
	H2_CALL_SENDFILE = 3,
};

/* The arguments of an SSL call, from its entry to its return. */
struct h2_call {
	__u64	ssl;
	__u64	buf;
	__u32	fn;
	__u32	reserved;
};

/*
 * The frame being read in one direction. A header, or a field of the
 * payload the guard reads, collects in buf until it is whole, so frames
 * may span reads and writes in any way.
 */
struct h2_parser {
	__u32	payload_left;
	__u32	frame_len;
	__u32	stream;
	__u8	type;
	__u8	flags;
	__u8	in_payload;
	__u8	have;
	__u8	reserved_bit;
	__u8	reserved[3];
	__u8	buf[H2_PARSER_BUF];
};

/*
 * A stream from the HEADERS that opened it on. Slots are taken by stream
 * id, and a stream that loses its slot is no longer checked, never
 * checked with counts from another stream.
 */
struct h2_stream {
	__u32	id;
	__u32	reserved;
	__s64	credit;
	__s64	sent;
};

/*
 * nginx's send windows as far as the client set them: the connection
 * window is H2_DEFAULT_WINDOW + credit - sent, a stream's window is
 * initial_window + its credit - its sent. sent counts the DATA nginx
 * handed OpenSSL, so the client, which received no more than that, sees
 * a window at least as large: a client that keeps RFC 9113 6.9.1 never
 * takes these past 2^31-1. nginx credits the unsent DATA of a cancelled
 * stream back to its window, so its window is at most this one too.
 */
struct h2_conn {
	__u32	mode;
	__u32	preface_have;
	__s64	initial_window;
	__s64	credit;
	__s64	sent;
	__u32	rst_count;
	__u32	reserved;
	struct h2_parser in;
	struct h2_parser out;
	struct h2_stream streams[H2_STREAM_SLOTS];
};

struct h2_conn_key {
	__u64	ssl;
	__u32	tgid;
	__u32	reserved;
};

/* A walk over one buffer of a call, and the hit that ended it. */
struct h2_walk {
	struct h2_conn *conn;
	__u64	buf;
	__u32	len;
	__u32	off;
	bool	out;
	__u32	reason;
	__u32	stream;
	__u32	increment;
	__s64	window;
};

struct h2_event_key {
	__u64	ssl;
	__u32	tgid;
	__u32	reason;
	__u32	stream;
	__u32	reserved;
};

struct h2_event_val {
	__u64	count;
	__u64	first_ns;
	__u64	last_ns;
	__s64	window;
	__u32	increment;
	__u32	pid;
	__u32	rst_count;
	__u32	action;
	char	comm[H2_COMM_LEN];
};

/* A thread drives one SSL call at a time: OpenSSL needs no more. */
struct {
	__uint(type, BPF_MAP_TYPE_LRU_HASH);
	__uint(max_entries, 4096);
	__type(key, __u64);
	__type(value, struct h2_call);
} h2_calls SEC(".maps");

/*
 * Not LRU: an LRU map hands an element to another key while a run may
 * still hold it, and two connections sharing counts could make a false
 * hit. SSL_free removes a connection, and a kill removes every
 * connection of the worker. When the map is full a new connection goes
 * unchecked, recorded as H2_REASON_UNTRACKED.
 */
struct {
	__uint(type, BPF_MAP_TYPE_HASH);
	__uint(map_flags, BPF_F_NO_PREALLOC);
	__uint(max_entries, 32768);
	__type(key, struct h2_conn_key);
	__type(value, struct h2_conn);
} h2_conns SEC(".maps");

static const struct h2_conn h2_conn_new = {
	.initial_window = H2_DEFAULT_WINDOW,
};

static const char h2_preface[32] = "PRI * HTTP/2.0\r\n\r\nSM\r\n\r\n";
static const char h2_comm[] = H2GUARD_COMM;

BUILD_BUG_ON(sizeof(h2_comm) > H2_COMM_LEN);

/* Carries the table's name for the serializer, the decoder and `upatch map`. */
struct {
	__uint(type, BPF_MAP_TYPE_ARRAY);
	__uint(max_entries, 1);
	__type(key, __u32);
	__type(value, __u8);
} h2_events SEC(".maps");

const struct decoder_manifest h2_events_decoder SEC(".rodata") = {
	.magic = DECODER_MANIFEST_MAGIC,
	.version = UPATCH_DECODER_VERSION,
	.language = UPATCH_DECODER_LANG_LUA,
	.api_version = 1,
	.input_format = UPATCH_DECODER_INPUT_MAP_V1,
	.export_signal = UPATCH_DECODER_EXPORT_LOG,
	.upatch = "nginx2shell-h2guard",
	.map = "h2_events",
	.source = "decoders/h2_events.lua",
	.entrypoint = "decode",
};

#define OBS_T		h2_events
#define OBS_T_MAP	h2_events
#define OBS_T_KEY	struct h2_event_key
#define OBS_T_VAL	struct h2_event_val
#define OBS_T_CAPACITY	1024
#define OBS_T_BUCKETS	512
#define OBS_T_STEPS	8
#define OBS_T_MAGIC	0x47423248u	/* "H2BG" little-endian */
#define OBS_T_RECORD	96
#define OBS_T_EMIT	h2_emit_record
#include "obs_table.h"

static int h2_emit_record(struct serial_chunk *chunk, __u32 off,
			  const struct h2_events_entry __arena *e)
{
	*(__u64 *)&chunk->data[off + 8] = e->key.ssl;
	*(__u32 *)&chunk->data[off + 16] = e->key.tgid;
	*(__u32 *)&chunk->data[off + 20] = e->key.reason;
	*(__u32 *)&chunk->data[off + 24] = e->key.stream;
	*(__u32 *)&chunk->data[off + 28] = e->val.pid;
	*(__u64 *)&chunk->data[off + 32] = e->val.count;
	*(__u64 *)&chunk->data[off + 40] = e->val.first_ns;
	*(__u64 *)&chunk->data[off + 48] = e->val.last_ns;
	*(__s64 *)&chunk->data[off + 56] = e->val.window;
	*(__u32 *)&chunk->data[off + 64] = e->val.increment;
	*(__u32 *)&chunk->data[off + 68] = e->val.rst_count;
	*(__u32 *)&chunk->data[off + 72] = e->val.action;
	*(__u32 *)&chunk->data[off + 76] = 0;
	obs_emit_bytes(chunk, off + 80, e->val.comm, H2_COMM_LEN / 8);
	return 0;
}

static __always_inline void h2_record(struct h2_event_key *key,
				      const struct h2_walk *walk,
				      __u32 rst_count, __u32 action)
{
	struct h2_events_entry __arena *e;
	char comm[H2_COMM_LEN] = {};
	__u64 pid_tgid = bpf_get_current_pid_tgid();
	__u64 now = obs_now();
	int status;

	key->tgid = pid_tgid >> 32;
	e = h2_events_touch(key, &status);
	if (!e)
		return;
	if (status == OBS_TOUCH_CREATED) {
		bpf_get_current_comm(comm, sizeof(comm));
		obs_copy_in(e->val.comm, comm, H2_COMM_LEN / 8);
		e->val.first_ns = now;
	}
	__sync_fetch_and_add(&e->val.count, 1);
	e->val.last_ns = now;
	e->val.pid = (__u32)pid_tgid;
	e->val.rst_count = rst_count;
	e->val.action = action;
	if (walk) {
		e->val.window = walk->window;
		e->val.increment = walk->increment;
	}
}

/* Records that the guard stopped following connections, one per reason. */
static __always_inline void h2_record_fail_open(__u32 reason)
{
	struct h2_event_key key = { .reason = reason };

	h2_record(&key, NULL, 0, H2_ACTION_RECORDED);
}

static __always_inline __u32 h2_be16(const __u8 *b)
{
	return (__u32)b[0] << 8 | b[1];
}

static __always_inline __u32 h2_be32(const __u8 *b)
{
	return (__u32)b[0] << 24 | (__u32)b[1] << 16 | (__u32)b[2] << 8 | b[3];
}

static __always_inline struct h2_stream *h2_slot(struct h2_conn *conn,
						 __u32 stream)
{
	return &conn->streams[(stream >> 1) & (H2_STREAM_SLOTS - 1)];
}

static __always_inline int h2_stop(struct h2_walk *walk, __u32 reason,
				   __u32 stream, __s64 window,
				   __u32 increment)
{
	walk->reason = reason;
	walk->stream = stream;
	walk->window = window;
	walk->increment = increment;
	return 1;
}

/*
 * Copies the next bytes of the buffer into p->buf until it holds want
 * bytes, or the buffer ends. want is at most a frame header.
 */
static __always_inline int h2_collect(struct h2_walk *walk,
				      struct h2_parser *p, __u32 want)
{
	__u8 bytes[H2_PARSER_BUF] = {};
	__u32 have = p->have;
	__u32 n, i;

	if (have >= want || want > H2_FRAME_HEADER_LEN)
		return -EINVAL;
	n = walk->len - walk->off;
	if (n > want - have)
		n = want - have;
	if (n == 0 || n > H2_FRAME_HEADER_LEN)
		return -EINVAL;
	if (bpf_probe_read_user(bytes, n, (const void *)(walk->buf + walk->off)))
		return -EFAULT;
#pragma clang loop unroll(full)
	for (i = 0; i < H2_FRAME_HEADER_LEN; i++) {
		if (i < n)
			p->buf[(have + i) & (H2_PARSER_BUF - 1)] = bytes[i];
	}
	p->have = have + n;
	walk->off += n;
	return 0;
}

static __always_inline void h2_decode_header(struct h2_parser *p)
{
	const __u8 *b = p->buf;

	p->frame_len = (__u32)b[0] << 16 | (__u32)b[1] << 8 | b[2];
	p->type = b[3];
	p->flags = b[4];
	p->reserved_bit = b[5] >> 7;
	p->stream = h2_be32(&b[5]) & H2_STREAM_MASK;
	p->have = 0;
}

/* nginx writes only the frame types RFC 9113 defines, with R clear. */
static __always_inline int h2_out_header(struct h2_walk *walk,
					 const struct h2_parser *p)
{
	struct h2_conn *conn = walk->conn;
	struct h2_stream *s;

	if (p->type > H2_CONTINUATION || p->reserved_bit)
		return h2_stop(walk, H2_REASON_DESYNC, p->stream, 0, 0);
	if (p->type != H2_DATA)
		return 0;
	conn->sent += p->frame_len;
	s = h2_slot(conn, p->stream);
	if (s->id && s->id == p->stream)
		s->sent += p->frame_len;
	return 0;
}

static __always_inline int h2_in_header(struct h2_walk *walk,
					const struct h2_parser *p)
{
	struct h2_conn *conn = walk->conn;
	struct h2_stream *s = h2_slot(conn, p->stream);

	if (p->type == H2_HEADERS && (p->stream & 1) && s->id != p->stream) {
		s->id = p->stream;
		s->credit = 0;
		s->sent = 0;
	} else if (p->type == H2_RST_STREAM) {
		conn->rst_count++;
		if (s->id == p->stream)
			s->id = 0;
	}
	return 0;
}

static __always_inline int h2_window_update(struct h2_walk *walk,
					    __u32 stream, __u32 increment)
{
	struct h2_conn *conn = walk->conn;
	struct h2_stream *s;
	__s64 window;

	if (!increment)
		return 0;
	if (!stream) {
		conn->credit += increment;
		window = H2_DEFAULT_WINDOW + conn->credit - conn->sent;
		if (window > H2_MAX_WINDOW)
			return h2_stop(walk, H2_REASON_CONN_WINDOW, 0, window,
				       increment);
		return 0;
	}
	s = h2_slot(conn, stream);
	if (s->id != stream)
		return 0;
	s->credit += increment;
	window = conn->initial_window + s->credit - s->sent;
	if (window > H2_MAX_WINDOW)
		return h2_stop(walk, H2_REASON_STREAM_WINDOW, stream, window,
			       increment);
	return 0;
}

/* A new initial window moves every open stream's window by the change. */
static __always_inline int h2_initial_window(struct h2_walk *walk,
					     __u32 value)
{
	struct h2_conn *conn = walk->conn;
	struct h2_stream *s;
	__s64 window;
	__u32 i;

	if (value > H2_MAX_WINDOW)
		return h2_stop(walk, H2_REASON_SETTINGS_WINDOW, 0, value, 0);
	conn->initial_window = value;
#pragma clang loop unroll(full)
	for (i = 0; i < H2_STREAM_SLOTS; i++) {
		s = &conn->streams[i];
		if (!s->id)
			continue;
		window = conn->initial_window + s->credit - s->sent;
		if (window > H2_MAX_WINDOW)
			return h2_stop(walk, H2_REASON_SETTINGS_WINDOW, s->id,
				       window, 0);
	}
	return 0;
}

static __always_inline int h2_in_field(struct h2_walk *walk,
				       const struct h2_parser *p)
{
	if (p->type == H2_WINDOW_UPDATE)
		return h2_window_update(walk, p->stream,
					h2_be32(p->buf) & H2_STREAM_MASK);
	if (h2_be16(p->buf) == H2_SETTINGS_INITIAL_WINDOW_SIZE)
		return h2_initial_window(walk, h2_be32(&p->buf[2]));
	return 0;
}

/* The length of the payload fields the guard reads, 0 to skip a payload. */
static __always_inline __u32 h2_field_len(const struct h2_walk *walk,
					  const struct h2_parser *p)
{
	if (walk->out)
		return 0;
	if (p->type == H2_WINDOW_UPDATE &&
	    p->frame_len == H2_WINDOW_UPDATE_LEN)
		return H2_WINDOW_UPDATE_LEN;
	if (p->type == H2_SETTINGS && !(p->flags & H2_FLAG_ACK))
		return H2_SETTING_LEN;
	return 0;
}

static __always_inline int h2_step_header(struct h2_walk *walk,
					  struct h2_parser *p)
{
	int stop;

	if (h2_collect(walk, p, H2_FRAME_HEADER_LEN))
		return h2_stop(walk, H2_REASON_DESYNC, 0, 0, 0);
	if (p->have < H2_FRAME_HEADER_LEN)
		return 0;
	h2_decode_header(p);
	stop = walk->out ? h2_out_header(walk, p) : h2_in_header(walk, p);
	if (stop)
		return stop;
	p->payload_left = p->frame_len;
	p->in_payload = p->frame_len != 0;
	return 0;
}

static __always_inline int h2_step_payload(struct h2_walk *walk,
					   struct h2_parser *p)
{
	__u32 field = h2_field_len(walk, p);
	__u32 start = walk->off;
	__u32 n;

	if (field && (p->have || p->payload_left >= field)) {
		if (h2_collect(walk, p, field))
			return h2_stop(walk, H2_REASON_DESYNC, p->stream, 0, 0);
		n = walk->off - start;
		if (n > p->payload_left)
			return h2_stop(walk, H2_REASON_DESYNC, p->stream, 0, 0);
		p->payload_left -= n;
		if (p->have == field) {
			p->have = 0;
			if (h2_in_field(walk, p))
				return 1;
		}
	} else {
		n = walk->len - walk->off;
		if (n > p->payload_left)
			n = p->payload_left;
		walk->off += n;
		p->payload_left -= n;
	}
	if (!p->payload_left) {
		p->in_payload = 0;
		p->have = 0;
	}
	return 0;
}

static int h2_step(__u32 index, void *data)
{
	struct h2_walk *walk = data;
	struct h2_parser *p;

	if (walk->off >= walk->len)
		return 1;
	p = walk->out ? &walk->conn->out : &walk->conn->in;
	if (p->in_payload)
		return h2_step_payload(walk, p);
	return h2_step_header(walk, p);
}

static __always_inline void h2_walk(struct h2_walk *walk,
				    struct h2_conn *conn, __u64 buf,
				    __u32 len, bool out)
{
	__u32 steps = len / 4 + 4;

	walk->conn = conn;
	walk->buf = buf;
	walk->len = len;
	walk->off = 0;
	walk->out = out;
	if (!len)
		return;
	if (steps > H2_WALK_MAX)
		steps = H2_WALK_MAX;
	bpf_loop(steps, h2_step, walk, 0);
	if (!walk->reason && walk->off < walk->len)
		walk->reason = H2_REASON_OVERSIZE;
}

static __always_inline struct h2_conn *h2_conn_get(__u64 ssl, __u32 tgid,
						   bool create)
{
	struct h2_conn_key key = { .ssl = ssl, .tgid = tgid };
	struct h2_conn *conn;
	long err;

	conn = bpf_map_lookup_elem(&h2_conns, &key);
	if (conn || !create)
		return conn;
	err = bpf_map_update_elem(&h2_conns, &key, &h2_conn_new, BPF_NOEXIST);
	if (err && err != -EEXIST) {
		h2_record_fail_open(H2_REASON_UNTRACKED);
		return NULL;
	}
	return bpf_map_lookup_elem(&h2_conns, &key);
}

static long h2_purge_conn(struct bpf_map *map, struct h2_conn_key *key,
			  struct h2_conn *conn, __u32 *tgid)
{
	if (key->tgid == *tgid)
		bpf_map_delete_elem(&h2_conns, key);
	return 0;
}

/*
 * The signal is pending when the uretprobe returns, and the kernel
 * delivers it before the worker runs another instruction of its own: the
 * worker never parses the frames. A killed worker calls SSL_free on none
 * of its connections, so their state goes here.
 */
static __always_inline __u32 h2_act(void)
{
	__u32 tgid = bpf_get_current_pid_tgid() >> 32;

	if (!H2GUARD_KILL)
		return H2_ACTION_RECORDED;
	if (bpf_send_signal(SIGKILL))
		return H2_ACTION_KILL_FAILED;
	bpf_for_each_map_elem(&h2_conns, h2_purge_conn, &tgid, 0);
	return H2_ACTION_KILLED;
}

static __always_inline void h2_settle(const struct h2_walk *walk, __u64 ssl)
{
	struct h2_conn *conn = walk->conn;
	struct h2_event_key key = {};
	__u32 rst_count, action;

	if (!walk->reason)
		return;
	conn->mode = H2_MODE_IGNORED;
	if (walk->reason == H2_REASON_DESYNC ||
	    walk->reason == H2_REASON_OVERSIZE) {
		h2_record_fail_open(walk->reason);
		return;
	}
	/* h2_act() may delete the state conn points to. */
	rst_count = conn->rst_count;
	action = h2_act();
	key.ssl = ssl;
	key.reason = walk->reason;
	key.stream = walk->stream;
	h2_record(&key, walk, rst_count, action);
}

static __always_inline bool h2_comm_matches(void)
{
	char comm[H2_COMM_LEN] = {};
	__u32 i;

	bpf_get_current_comm(comm, sizeof(comm));
#pragma clang loop unroll(full)
	for (i = 0; i < sizeof(h2_comm); i++) {
		if (comm[i] != h2_comm[i])
			return false;
	}
	return true;
}

static __always_inline int h2_call_enter(__u32 fn, const void *ssl,
					 const void *buf)
{
	__u64 id = bpf_get_current_pid_tgid();
	struct h2_call call = {
		.ssl = (__u64)ssl,
		.buf = (__u64)buf,
		.fn = fn,
	};

	if (!h2_comm_matches())
		return 0;
	bpf_map_update_elem(&h2_calls, &id, &call, BPF_ANY);
	return 0;
}

static __always_inline bool h2_call_leave(__u32 fn, struct h2_call *call)
{
	__u64 id = bpf_get_current_pid_tgid();
	struct h2_call *saved;

	saved = bpf_map_lookup_elem(&h2_calls, &id);
	if (!saved)
		return false;
	*call = *saved;
	bpf_map_delete_elem(&h2_calls, &id);
	return call->fn == fn;
}

/* Matches the client preface, which may come in pieces, from buf on. */
static __always_inline int h2_preface_check(struct h2_conn *conn,
					    __u64 buf, __u32 len,
					    __u32 *used)
{
	char bytes[H2_PREFACE_LEN] = {};
	__u32 have = conn->preface_have;
	__u32 n, i;

	if (have >= H2_PREFACE_LEN)
		return -EINVAL;
	n = H2_PREFACE_LEN - have;
	if (n > len)
		n = len;
	if (n == 0 || n > H2_PREFACE_LEN)
		return -EINVAL;
	if (bpf_probe_read_user(bytes, n, (const void *)buf))
		return -EFAULT;
#pragma clang loop unroll(full)
	for (i = 0; i < H2_PREFACE_LEN; i++) {
		if (i < n && bytes[i] != h2_preface[(have + i) & 31])
			return -EINVAL;
	}
	conn->preface_have = have + n;
	*used = n;
	return 0;
}

SEC("uprobe/" H2GUARD_LIBSSL ":SSL_read")
int BPF_UPROBE(h2guard_read, void *ssl, void *buf, int num)
{
	return h2_call_enter(H2_CALL_READ, ssl, buf);
}

/* Runs before SSL_read returns, so before nginx sees the bytes. */
SEC("uretprobe/" H2GUARD_LIBSSL ":SSL_read")
int BPF_URETPROBE(h2guard_read_return, int ret)
{
	struct h2_walk walk = {};
	struct h2_call call;
	struct h2_conn *conn;
	__u32 used = 0;

	if (!h2_call_leave(H2_CALL_READ, &call) || ret <= 0)
		return 0;
	conn = h2_conn_get(call.ssl, bpf_get_current_pid_tgid() >> 32, true);
	if (!conn || conn->mode == H2_MODE_IGNORED)
		return 0;
	if (conn->mode == H2_MODE_PREFACE) {
		if (h2_preface_check(conn, call.buf, ret, &used)) {
			conn->mode = H2_MODE_IGNORED;
			return 0;
		}
		if (conn->preface_have < H2_PREFACE_LEN)
			return 0;
		conn->mode = H2_MODE_FRAMES;
	}
	h2_walk(&walk, conn, call.buf + used, ret - used, false);
	h2_settle(&walk, call.ssl);
	return 0;
}

SEC("uprobe/" H2GUARD_LIBSSL ":SSL_write")
int BPF_UPROBE(h2guard_write, void *ssl, const void *buf, int num)
{
	return h2_call_enter(H2_CALL_WRITE, ssl, buf);
}

/*
 * Counts the DATA nginx handed OpenSSL. nginx may write its SETTINGS
 * before it reads the client preface, so the write side starts the
 * state as well; a connection the read side then finds not to be HTTP/2
 * is ignored.
 */
SEC("uretprobe/" H2GUARD_LIBSSL ":SSL_write")
int BPF_URETPROBE(h2guard_write_return, int ret)
{
	struct h2_walk walk = {};
	struct h2_call call;
	struct h2_conn *conn;

	if (!h2_call_leave(H2_CALL_WRITE, &call) || ret <= 0)
		return 0;
	conn = h2_conn_get(call.ssl, bpf_get_current_pid_tgid() >> 32, true);
	if (!conn || conn->mode == H2_MODE_IGNORED)
		return 0;
	h2_walk(&walk, conn, call.buf, ret, true);
	if (conn->mode == H2_MODE_FRAMES)
		h2_settle(&walk, call.ssl);
	else if (walk.reason)
		conn->mode = H2_MODE_IGNORED;
	return 0;
}

SEC("uprobe/" H2GUARD_LIBSSL ":SSL_sendfile")
int BPF_UPROBE(h2guard_sendfile, void *ssl)
{
	return h2_call_enter(H2_CALL_SENDFILE, ssl, NULL);
}

/* With kernel TLS, the payload of a DATA frame comes from a file. */
SEC("uretprobe/" H2GUARD_LIBSSL ":SSL_sendfile")
int BPF_URETPROBE(h2guard_sendfile_return, long ret)
{
	struct h2_call call;
	struct h2_conn *conn;
	struct h2_parser *p;

	if (!h2_call_leave(H2_CALL_SENDFILE, &call) || ret <= 0)
		return 0;
	conn = h2_conn_get(call.ssl, bpf_get_current_pid_tgid() >> 32, false);
	if (!conn || conn->mode == H2_MODE_IGNORED)
		return 0;
	p = &conn->out;
	if (!p->in_payload || p->type != H2_DATA || ret > p->payload_left) {
		if (conn->mode == H2_MODE_FRAMES)
			h2_record_fail_open(H2_REASON_DESYNC);
		conn->mode = H2_MODE_IGNORED;
		return 0;
	}
	p->payload_left -= ret;
	if (!p->payload_left)
		p->in_payload = 0;
	return 0;
}

SEC("uprobe/" H2GUARD_LIBSSL ":SSL_free")
int BPF_UPROBE(h2guard_free, void *ssl)
{
	struct h2_conn_key key = {
		.ssl = (__u64)ssl,
		.tgid = bpf_get_current_pid_tgid() >> 32,
	};

	bpf_map_delete_elem(&h2_conns, &key);
	return 0;
}

/* Runs once right after attachment and allocates the table in the arena. */
SEC("syscall")
int shirudo_test__h2guard_init(void *ctx)
{
	return h2_events_init(obs_now());
}
