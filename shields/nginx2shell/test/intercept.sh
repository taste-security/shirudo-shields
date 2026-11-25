#!/bin/sh
# SPDX-License-Identifier: BSD-2-Clause
#
# intercept: the protection proof on the real vulnerable binary. With the
# shield loaded, each form of the Nginx2Shell trigger (the RFC 9113 6.9.1
# over-limit flow-control pattern) is sent to nginx 1.31.8, inside the
# affected range. The guard must kill the worker at SSL_read, before nginx's
# flow-control code reads the over-limit frame, so the underflow never runs.
#
# Sent to the vulnerable instance ONLY here, and ONLY once the shield is
# confirmed loaded. Each form is one case, judged like h2guard: a fresh
# action=killed event with the right reason on the worker that handled it,
# nginx's log showing that worker exited on SIGKILL (not a crash signal, so
# the frame never reached the bug), the master alive with a replacement, and
# a fresh 200. No exploit is sent: the pattern is two frames, the same a
# conformance suite sends, and nginx never parses them under the shield.

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

for pattern in direct rst-then-credit; do
	guard_before vulnerable
	python3 "$H2PROBE" --behind-shield --pattern "$pattern" "$N2S_VULN_URL" >"$W/probe" 2>&1
	pstatus=$?
	grep -v '  frame DATA' "$W/probe" | sed 's/^/      | /'
	if [ "$pstatus" -eq 3 ]; then
		fail "intercept $pattern: h2probe refused to send; the --behind-shield gate did not open"
		continue
	fi
	if grep -q "^PATTERN $pattern RESULT cut " "$W/probe"; then
		pass "intercept $pattern: the trigger to vulnerable 1.31.8 was cut before nginx parsed it"
	else
		fail "intercept $pattern: the trigger was not cut: $(sed -n "s/^PATTERN $pattern RESULT //p" "$W/probe")"
		continue
	fi
	guard_enforced conn_window_over_max "intercept $pattern"
done

finish
