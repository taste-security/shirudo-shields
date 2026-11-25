/* SPDX-License-Identifier: GPL-2.0 OR BSD-2-Clause */
/* Copyright (c) 2026 Authors of shirudo-shields */
/*
 * The settings of nginx2shell-h2guard. `shirudo bpm build` passes no
 * compiler flags and a section name is a string the compiler fixes, so
 * they live here: edit this file and rebuild.
 */
#ifndef H2GUARD_CONFIG_H
#define H2GUARD_CONFIG_H

/*
 * The libssl nginx loads, as an absolute path on the target. The builder
 * opens the same path on the operator host to find SSL_read, SSL_write,
 * SSL_sendfile and SSL_free and to record the file's GNU build ID; the
 * target refuses a file with another build ID (binary_mismatch). The
 * default is the libssl of the Alpine based nginx images.
 */
#define H2GUARD_LIBSSL		"/usr/lib/libssl.so.3"

/*
 * A uprobe fires in every process that maps the file; the guard follows
 * only the SSL calls of tasks with this name, which nginx's master and
 * workers carry.
 */
#define H2GUARD_COMM		"nginx"

/* 1 sends SIGKILL to the worker on a hit, 0 only records the hit. */
#define H2GUARD_KILL		1

/* The architecture whose registers bpf_tracing.h reads arguments from. */
#if !defined(__TARGET_ARCH_x86) && !defined(__TARGET_ARCH_arm64) && \
	!defined(__TARGET_ARCH_riscv)
#define __TARGET_ARCH_x86
#endif

#endif /* H2GUARD_CONFIG_H */
