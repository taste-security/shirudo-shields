#!/bin/sh
# SPDX-License-Identifier: BSD-2-Clause
#
# Scenario 5, h2guard: the shield is loaded. For each form of the RFC 9113
# 6.9.1 over-limit flow-control pattern, sent to FIXED nginx 1.31.9 (h2probe
# refuses anything older), the guard must cut the connection before nginx
# answers and then prove enforcement: a fresh action=killed event with the
# right reason on the very worker that handled the case, nginx's own log
# showing that worker exited on SIGKILL, the master still alive with a
# replacement, a fresh 200, and no crash. Each form is one case.

. "$(dirname "$0")/lib.sh"
need curl python3

case $N2S_PATCHED_URL in
*:8443*) fail "N2S_PATCHED_URL points at the vulnerable instance"; finish ;;
esac
for u in "$CONTAIN" "$H2GUARD"; do
	loaded "$u" || { fail "$u is not loaded; h2guard runs under the shield"; finish; }
done

for pattern in direct rst-then-credit; do
	guard_before patched
	python3 "$H2PROBE" --pattern "$pattern" --expect cut "$N2S_PATCHED_URL" >"$W/probe" 2>&1
	pstatus=$?
	grep -v '  frame DATA' "$W/probe" | sed 's/^/      | /'
	if [ "$pstatus" -eq 3 ]; then
		fail "h2guard $pattern: h2probe refused $N2S_PATCHED_URL: is it nginx 1.31.9?"
		continue
	fi
	if grep -q "^PATTERN $pattern RESULT cut " "$W/probe"; then
		pass "h2guard $pattern: the connection was cut before nginx answered"
	else
		fail "h2guard $pattern: not cut: $(sed -n "s/^PATTERN $pattern RESULT //p" "$W/probe")"
		continue
	fi
	guard_enforced conn_window_over_max "h2guard $pattern"
done

# Negative controls, under the same loaded shield: the legal boundary and
# ordinary HTTP/2 must NOT be a hit and must NOT kill a worker.
guard_before patched
python3 "$H2PROBE" --pattern at-limit --expect served "$N2S_PATCHED_URL" >"$W/legal" 2>&1
grep -E "^(PATTERN|SERVER|GATE)" "$W/legal" | sed 's/^/      | /'
if grep -q "^PATTERN at-limit RESULT served " "$W/legal"; then
	pass "h2guard control: a window at exactly 2^31-1 is served, not cut"
else
	fail "h2guard control: the legal maximum was not served: $(sed -n 's/^PATTERN at-limit RESULT //p' "$W/legal")"
fi
events "$H2GUARD" "$H2GUARD_EVENTS" "$W/ctrl"
check "h2guard control: the legal maximum is no new guard hit ($(hits "$W/gb") -> $(hits "$W/ctrl"))" \
	[ "$(hits "$W/ctrl")" = "$(hits "$W/gb")" ]
check "h2guard control: no worker was killed by the legal maximum" \
	[ -z "$(find_new_kill "$W/ctrl" conn_window_over_max "$GB_KILLED")" ]

# Full map dump for the artifact.
{
	echo "# shirudo-runtime upatch map"
	"$SHIRUDO_RUNTIME" upatch map 2>&1
	for u in "$CONTAIN" "$H2GUARD"; do
		for m in $("$SHIRUDO_RUNTIME" upatch map "$u" --json 2>/dev/null |
			python3 -c 'import json, sys
for m in json.load(sys.stdin).get("maps", []):
    print(m["name"])' 2>/dev/null); do
			echo "# shirudo-runtime upatch map $u $m --peek --show-full"
			"$SHIRUDO_RUNTIME" upatch map "$u" "$m" --peek --show-full 2>&1
		done
	done
} >"$N2S_OUT/upatch-map.txt" 2>&1
info "map dump: $N2S_OUT/upatch-map.txt"

finish
