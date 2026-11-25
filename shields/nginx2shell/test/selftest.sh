#!/bin/sh
# SPDX-License-Identifier: BSD-2-Clause
#
# selftest: the guard assertion must reject weak evidence. find_fresh_kill
# is fed synthetic event dumps and must count only a genuine action=killed
# record on the worker that handled the case. This runs on parsing alone,
# so it needs no guard; it guards the assertion the other scenarios rely on.

. "$(dirname "$0")/lib.sh"

reason=conn_window_over_max
worker_set="3001
3002"

# A kill on a worker that did not handle this case (a stale event from an
# earlier case, whose worker is gone) must not count.
cat >"$W/stale" <<EOF
total=1 hits=1 records=1
  reason=$reason action=killed comm=nginx pid=9999 tgid=9999 count=1
EOF
check "a killed event on an unrelated pid is rejected" \
	[ -z "$(find_fresh_kill "$W/stale" "$reason" "$worker_set")" ]

# A kill_failed on the right worker is not enforcement.
cat >"$W/kf" <<EOF
total=1 hits=1 records=1
  reason=$reason action=kill_failed comm=nginx pid=3001 tgid=3001 count=1
EOF
check "a fresh kill_failed event is not accepted as a kill" \
	[ -z "$(find_fresh_kill "$W/kf" "$reason" "$worker_set")" ]

# A recorded-only event (observe mode) is not enforcement.
cat >"$W/rec" <<EOF
total=1 hits=1 records=1
  reason=$reason action=recorded comm=nginx pid=3002 tgid=3002 count=1
EOF
check "an action=recorded event is not accepted as a kill" \
	[ -z "$(find_fresh_kill "$W/rec" "$reason" "$worker_set")" ]

# A kill with the wrong reason is rejected.
cat >"$W/wrong" <<EOF
total=1 hits=1 records=1
  reason=stream_window_over_max action=killed comm=nginx pid=3001 tgid=3001 count=1
EOF
check "a killed event with the wrong reason is rejected" \
	[ -z "$(find_fresh_kill "$W/wrong" "$reason" "$worker_set")" ]

# A genuine kill on the handling worker is matched, among other records.
cat >"$W/good" <<EOF
total=3 hits=3 records=3
  reason=$reason action=kill_failed comm=nginx pid=4000 tgid=4000 count=1
  reason=$reason action=killed comm=nginx pid=3002 tgid=3002 count=1
  reason=untracked_table_full comm=nginx pid=3002 tgid=3002 count=1
EOF
got=$(find_fresh_kill "$W/good" "$reason" "$worker_set")
check "a genuine kill on the handling worker is matched (pid $got)" [ "$got" = 3002 ]

finish
