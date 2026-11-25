#!/bin/sh
# SPDX-License-Identifier: BSD-2-Clause
#
# lifecycle: the guard's connection table must not keep entries of a
# worker that is gone. The guard removes an entry when nginx calls SSL_free
# and removes a worker's entries when the guard itself kills it. A worker
# that exits any other way (killed from outside, crashed, out of memory)
# calls SSL_free on none of its connections. If those entries stayed, the
# table (32768 entries, not LRU) would fill over time and the guard would
# stop tracking new connections: it would fail open.
#
# The test holds ordinary HTTP/2 connections open to fixed nginx 1.31.9,
# checks the guard tracks them, kills the instance's workers from outside
# with SIGKILL (the guard is not involved), and requires the table to drop
# back once the workers are gone. nginx must recover.

. "$(dirname "$0")/lib.sh"
need curl python3

loaded "$H2GUARD" || { fail "$H2GUARD is not loaded; lifecycle runs under the shield"; finish; }
HOLD=$N2S_REPO/tools/h2probe/h2hold
COUNT=8

# conn_entries: how many entries the guard's connection table holds.
conn_entries()
{
	"$SHIRUDO_RUNTIME" upatch map "$H2GUARD" h2_conns --peek --show-full 2>/dev/null |
		sed -n 's/^Entries:[[:space:]]*\([0-9]*\) of.*/\1/p'
}

e0=$(conn_entries)
if [ -z "$e0" ]; then
	fail "cannot read the guard's connection table (upatch map $H2GUARD h2_conns)"
	finish
fi
info "connection table entries before: $e0"

python3 "$HOLD" --count "$COUNT" --seconds 45 "$N2S_PATCHED_URL" >"$W/hold" 2>&1 &
holder=$!
held=0
for _ in $(seq 50); do
	grep -q "^HELD $COUNT" "$W/hold" && { held=1; break; }
	kill -0 "$holder" 2>/dev/null || break
	sleep 0.2
done
if [ "$held" -ne 1 ]; then
	sed 's/^/      | /' "$W/hold"
	kill "$holder" 2>/dev/null
	fail "could not hold $COUNT HTTP/2 connections open"
	finish
fi
sleep 1
e1=$(conn_entries)
check "the guard tracks the $COUNT held connections ($e0 -> $e1 entries)" \
	[ "${e1:-0}" -ge $((e0 + COUNT)) ]

master_pid=$(master patched)
old_workers=$(workers patched)
info "nginx 1.31.9 master $master_pid, workers $(printf '%s' "$old_workers" | tr '\n' ' ')"
for pid in $old_workers; do
	kill -9 "$pid" 2>/dev/null
done

# Wait for every killed worker to be gone and replaced.
replaced=0
for _ in $(seq 50); do
	now=" $(workers patched | tr '\n' ' ') "
	stale=0
	for pid in $old_workers; do
		case $now in *" $pid "*) stale=1 ;; esac
	done
	if [ "$stale" -eq 0 ] && [ -n "$(workers patched)" ]; then
		replaced=1
		break
	fi
	sleep 0.2
done
check "the killed workers are gone and nginx started new ones" [ "$replaced" -eq 1 ]

# The killed workers called SSL_free on none of their connections. Their
# entries must still go, or the table leaks.
e2=$(conn_entries)
for _ in $(seq 15); do
	[ "${e2:-0}" -le "$e0" ] && break
	sleep 0.2
	e2=$(conn_entries)
done
check "the entries of the killed workers were removed ($e1 -> $e2, started at $e0)" \
	[ "${e2:-0}" -le "$e0" ]

kill "$holder" 2>/dev/null
wait "$holder" 2>/dev/null

if [ -n "$master_pid" ] && [ "$(master patched)" = "$master_pid" ]; then
	pass "the 1.31.9 master survived (pid $master_pid)"
else
	fail "the 1.31.9 master changed ($master_pid -> $(master patched))"
fi
status=$(https_status "$N2S_PATCHED_URL/")
check "nginx 1.31.9 serves a fresh HTTP/2 request ($status)" [ "$status" = "200 2" ]

finish
