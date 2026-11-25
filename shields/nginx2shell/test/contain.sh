#!/bin/sh
# SPDX-License-Identifier: BSD-2-Clause
#
# Scenario 2, contain: the shield is loaded. The same SIMULATED
# post-exploit step on nginx 1.31.8: the kernel refuses the worker's exec
# and its connect out, the response says so, the refusals are in the
# contain upatch's map, and nginx keeps serving.

. "$(dirname "$0")/lib.sh"
need curl python3

events "$CONTAIN" "$CONTAIN_EVENTS" "$W/before"

simulated_rce "$N2S_VULN_URL" >"$W/rce" || :
sed 's/^/      | /' "$W/rce"
check "the response is labeled SIMULATED" grep -q '^SIMULATED' "$W/rce"

if [ "$(field exec "$W/rce")" = refused ]; then
	pass "the kernel refused the worker's exec of /bin/sh ($(errno_of exec "$W/rce"))"
else
	fail "the worker's exec was not refused: $(grep '^exec=' "$W/rce")"
fi
if [ "$(field connect "$W/rce")" = refused ]; then
	pass "the kernel refused the worker's connect to 192.0.2.1:4444 ($(errno_of connect "$W/rce"))"
else
	fail "the worker's connect was not refused: $(grep '^connect=' "$W/rce")"
fi

status=$(https_status "$N2S_VULN_URL/")
check "nginx 1.31.8 keeps serving: GET / is $status" [ "$status" = "200 2" ]
status=$(https_status "$N2S_PATCHED_URL/")
check "nginx 1.31.9 keeps serving: GET / is $status" [ "$status" = "200 2" ]

events "$CONTAIN" "$CONTAIN_EVENTS" "$W/after"
sed 's/^/      | /' "$W/after"
before=$(hits "$W/before")
after=$(hits "$W/after")
if [ "${after:-0}" -gt "${before:-0}" ] && grep -q 'comm=nginx' "$W/after"; then
	pass "the refusals are in $CONTAIN's $CONTAIN_EVENTS map (${before:-0} -> $after)"
else
	sed 's/^/      | /' "$W/after.err"
	fail "no new refusal of nginx in $CONTAIN's $CONTAIN_EVENTS map (${before:-0} -> ${after:-0})"
fi

finish
