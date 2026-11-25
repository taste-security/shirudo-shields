#!/bin/sh
# SPDX-License-Identifier: BSD-2-Clause
#
# Scenario 1, baseline: the shield is NOT loaded. The SIMULATED
# post-exploit step on nginx 1.31.8 runs a shell and connects out, which
# proves the later scenarios can see a block. Two controls of the probe:
# h2probe refuses nginx 1.31.8 before sending anything, and fixed nginx
# 1.31.9, unshielded, answers the over-limit pattern with
# GOAWAY(FLOW_CONTROL_ERROR) as RFC 9113 asks.

. "$(dirname "$0")/lib.sh"
need curl python3

if loaded "$CONTAIN" || loaded "$H2GUARD"; then
	fail "the shield is loaded; the baseline needs a target without it"
else
	pass "the shield is not loaded"
fi

expect_simulated_rce_runs

python3 "$H2PROBE" "$N2S_VULN_URL" >"$W/refuse" 2>&1
status=$?
sed 's/^/      | /' "$W/refuse"
if [ "$status" -eq 3 ] && grep -q '^REFUSED' "$W/refuse" && ! grep -q '^SENT' "$W/refuse"; then
	pass "h2probe refuses nginx 1.31.8 and sends nothing to it"
else
	fail "h2probe did not refuse nginx 1.31.8 (exit $status)"
fi

python3 "$H2PROBE" --expect answered "$N2S_PATCHED_URL" >"$W/control" 2>&1
status=$?
grep -v '  frame DATA' "$W/control" | sed 's/^/      | /'
if [ "$status" -eq 0 ] && [ "$(grep -c 'RESULT answered GOAWAY error=FLOW_CONTROL_ERROR' "$W/control")" -eq 2 ]; then
	pass "unshielded nginx 1.31.9 answers both forms of the pattern with GOAWAY FLOW_CONTROL_ERROR"
else
	fail "unshielded nginx 1.31.9 did not answer the pattern with GOAWAY FLOW_CONTROL_ERROR (exit $status)"
fi

finish
