#!/bin/sh
# SPDX-License-Identifier: BSD-2-Clause
#
# intercept: the protection proof on the real vulnerable binary. With the
# shield loaded, the Nginx2Shell trigger (the RFC 9113 6.9.1 over-limit
# flow-control pattern) is sent to nginx 1.31.8, inside the affected range.
# The guard must kill the worker at SSL_read, before nginx's flow-control
# code reads the over-limit frame, so the underflow is never reached.
#
# The trigger is sent to the vulnerable instance ONLY here, and ONLY once
# the shield is confirmed loaded: the connection is cut before nginx parses
# the frame, so the bug does not run. A worker that exits on a crash signal
# (SIGSEGV and the like), rather than the guard's SIGKILL, would mean the
# frame reached the vulnerable code, and fails the scenario. No exploit is
# sent: the pattern is two frames, the same a conformance suite sends.

. "$(dirname "$0")/lib.sh"
need curl python3

case $N2S_VULN_URL in
*:9443*) fail "N2S_VULN_URL points at the fixed instance"; finish ;;
esac

# Never send the trigger to vulnerable nginx unless the shield is loaded.
for u in "$CONTAIN" "$H2GUARD"; do
	loaded "$u" || { fail "$u is not loaded; not sending the trigger to vulnerable nginx"; finish; }
done
pass "the shield is loaded, so the trigger will be cut before nginx parses it"

events "$H2GUARD" "$H2GUARD_EVENTS" "$W/before"
crash0=$(crash_lines)
master=$(sh "$N2S_DEMO" master vulnerable)
info "nginx 1.31.8 master $master, workers $(workers vulnerable)"

# --behind-shield forces --expect cut: the only pass is the connection cut
# before nginx answers. Both attack forms, to the vulnerable instance.
python3 "$H2PROBE" --behind-shield "$N2S_VULN_URL" >"$W/probe" 2>&1
pstatus=$?
grep -v '  frame DATA' "$W/probe" | sed 's/^/      | /'
for pattern in direct rst-then-credit; do
	if grep -q "^PATTERN $pattern RESULT cut " "$W/probe"; then
		pass "the trigger to vulnerable 1.31.8 was cut before nginx parsed it ($pattern)"
	else
		fail "$pattern: the trigger was not cut: $(sed -n "s/^PATTERN $pattern RESULT //p" "$W/probe")"
	fi
done
[ "$pstatus" -ne 3 ] || fail "h2probe refused to send: the --behind-shield gate did not open"

events "$H2GUARD" "$H2GUARD_EVENTS" "$W/after"
sed 's/^/      | /' "$W/after"
before=$(hits "$W/before")
after=$(hits "$W/after")
if [ "${after:-0}" -gt "${before:-0}" ] && grep -q 'comm=nginx' "$W/after"; then
	pass "the guard recorded the interception on the vulnerable worker (${before:-0} -> $after)"
else
	sed 's/^/      | /' "$W/after.err"
	fail "no guard hit for the vulnerable worker (${before:-0} -> ${after:-0})"
fi
if grep -q 'action=killed' "$W/after"; then
	pass "the worker was stopped by the guard's SIGKILL, before the frame was parsed"
else
	info "action: $(sed -n 's/.*\(action=[a-z_]*\).*/\1/p' "$W/after" | tail -n 1)"
fi

# A crash signal (not the guard's SIGKILL) would mean the frame reached
# nginx's flow-control code. There must be none.
check "no nginx 1.31.8 worker crashed: the vulnerable code never ran ($(crash_lines) crash signals)" \
	[ "$(crash_lines)" = "$crash0" ]

# The master forks a fresh worker; the instance keeps serving.
master_survived()
{
	[ -n "$master" ] && [ "$(sh "$N2S_DEMO" master vulnerable)" = "$master" ]
}
check "the 1.31.8 master survived the cut (pid $master)" master_survived
status=$(https_status "$N2S_VULN_URL/")
check "nginx 1.31.8 serves again after the cut ($status)" [ "$status" = "200 2" ]

finish
