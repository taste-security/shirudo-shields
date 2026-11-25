#!/bin/sh
# SPDX-License-Identifier: BSD-2-Clause
#
# Scenario 4, h2guard: the shield is loaded. h2probe sends the RFC 9113
# 6.9.1 over-limit flow-control pattern, in both forms, to FIXED nginx
# 1.31.9 only: h2probe itself refuses any server whose Server header does
# not name 1.31.9 or later. In baseline that nginx answered with GOAWAY;
# now the guard cuts the connection before nginx answers, records the hit
# in its map, and nginx's master starts a new worker.

. "$(dirname "$0")/lib.sh"
need curl python3

case $N2S_PATCHED_URL in
*:8443*) fail "N2S_PATCHED_URL points at the vulnerable instance"; finish ;;
esac

events "$H2GUARD" "$H2GUARD_EVENTS" "$W/before"
killed=$(killed_lines)
info "nginx 1.31.9 workers before: $(workers patched)"

python3 "$H2PROBE" --expect cut "$N2S_PATCHED_URL" >"$W/probe" 2>&1
status=$?
grep -v '  frame DATA' "$W/probe" | sed 's/^/      | /'
for pattern in direct rst-then-credit; do
	if grep -q "^PATTERN $pattern RESULT cut " "$W/probe"; then
		pass "$pattern: the connection was cut before nginx answered"
	else
		fail "$pattern: $(sed -n "s/^PATTERN $pattern RESULT //p" "$W/probe")"
	fi
done
[ "$status" -ne 3 ] || fail "h2probe refused $N2S_PATCHED_URL: is it nginx 1.31.9?"

events "$H2GUARD" "$H2GUARD_EVENTS" "$W/after"
cp "$W/after" "$N2S_OUT/h2guard-events.txt"
sed 's/^/      | /' "$W/after"
before=$(hits "$W/before")
after=$(hits "$W/after")
if [ "${after:-0}" -gt "${before:-0}" ]; then
	pass "the hits are in $H2GUARD's $H2GUARD_EVENTS map (${before:-0} -> $after)"
else
	sed 's/^/      | /' "$W/after.err"
	fail "no new hit in $H2GUARD's $H2GUARD_EVENTS map (${before:-0} -> ${after:-0})"
fi
if grep -q 'action=killed' "$W/after"; then
	info "action: the worker was killed with SIGKILL"
fi
info "nginx: $(( $(killed_lines) - killed )) worker exit(s) on a signal; workers now $(workers patched)"

sleep 1
status=$(https_status "$N2S_PATCHED_URL/")
check "nginx 1.31.9 serves again after the cut ($status)" [ "$status" = "200 2" ]
status=$(https_status "$N2S_VULN_URL/")
check "nginx 1.31.8 was not touched ($status)" [ "$status" = "200 2" ]

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
