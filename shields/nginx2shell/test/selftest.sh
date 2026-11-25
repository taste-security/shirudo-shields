#!/bin/sh
# SPDX-License-Identifier: BSD-2-Clause
#
# selftest: the guard assertion must reject weak evidence. find_new_kill is
# fed synthetic event dumps and must count only a new action=killed record
# with the expected reason, from a pid with no kill before the case. This
# runs on parsing alone, so it needs no guard; it guards the assertion the
# guard scenarios rely on.

. "$(dirname "$0")/lib.sh"

reason=conn_window_over_max
earlier="3001"

# A kill from an earlier case (its pid already had a kill record) must not
# count as this case's enforcement.
cat >"$W/stale" <<EOF
total=1 hits=1 records=1
  reason=$reason action=killed comm=nginx pid=3001 tgid=3001 count=1
EOF
check "a stale killed event from an earlier case is rejected" \
	[ -z "$(find_new_kill "$W/stale" "$reason" "$earlier")" ]

# A kill_failed is not enforcement.
cat >"$W/kf" <<EOF
total=2 hits=2 records=2
  reason=$reason action=killed comm=nginx pid=3001 tgid=3001 count=1
  reason=$reason action=kill_failed comm=nginx pid=3002 tgid=3002 count=1
EOF
check "a fresh kill_failed event is not accepted as a kill" \
	[ -z "$(find_new_kill "$W/kf" "$reason" "$earlier")" ]

# A recorded-only event (observe mode) is not enforcement.
cat >"$W/rec" <<EOF
total=2 hits=2 records=2
  reason=$reason action=killed comm=nginx pid=3001 tgid=3001 count=1
  reason=$reason action=recorded comm=nginx pid=3002 tgid=3002 count=1
EOF
check "a fresh action=recorded event is not accepted as a kill" \
	[ -z "$(find_new_kill "$W/rec" "$reason" "$earlier")" ]

# A new kill with the wrong reason is rejected.
cat >"$W/wrong" <<EOF
total=1 hits=1 records=1
  reason=stream_window_over_max action=killed comm=nginx pid=3002 tgid=3002 count=1
EOF
check "a new killed event with the wrong reason is rejected" \
	[ -z "$(find_new_kill "$W/wrong" "$reason" "$earlier")" ]

# A genuine new kill is matched, among stale and failed records.
cat >"$W/good" <<EOF
total=4 hits=3 records=4
  reason=$reason action=killed comm=nginx pid=3001 tgid=3001 count=1
  reason=$reason action=kill_failed comm=nginx pid=4000 tgid=4000 count=1
  reason=$reason action=killed comm=nginx pid=3002 tgid=3002 count=1
  reason=untracked_table_full comm=nginx pid=3002 tgid=3002 count=1
EOF
got=$(find_new_kill "$W/good" "$reason" "$earlier")
check "a genuine new kill is matched (pid $got)" [ "$got" = 3002 ]

# killed_pids lists only the killed records, so the earlier-kills set a case
# starts from excludes kill_failed and recorded pids.
check "killed_pids lists only action=killed pids ($(killed_pids "$W/good" | tr '\n' ' '))" \
	[ "$(killed_pids "$W/good" | tr '\n' ' ')" = "3001 3002 " ]

finish
