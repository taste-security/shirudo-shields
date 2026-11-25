#!/bin/sh
# SPDX-License-Identifier: BSD-2-Clause
#
# Scenario 5, unload: apply the package's unload directives in reverse
# name order, as `shirudo bpm uninstall` does. The shield is gone, and
# the SIMULATED post-exploit step of scenario 1 runs again.

. "$(dirname "$0")/lib.sh"
need curl python3

unloads=0
# shellcheck disable=SC2045 # reverse name order; the names have no blanks
for directive in $(ls -r "$N2S_SHIELD_DIR"/upatches/*.unload.upatch 2>/dev/null); do
	unloads=$((unloads + 1))
	name=$(basename "$directive" .unload.upatch)
	if "$SHIRUDO_RUNTIME" upatch unload --report="$N2S_OUT/unload-$name.json" "$directive" \
		>"$W/unload" 2>&1; then
		pass "upatch unload $name"
	else
		sed 's/^/      | /' "$W/unload"
		fail "upatch unload $name"
	fi
done
[ "$unloads" -gt 0 ] || fail "no unload directives in $N2S_SHIELD_DIR/upatches"

if loaded "$CONTAIN" || loaded "$H2GUARD"; then
	fail "the shield is still loaded"
else
	pass "the shield is no longer loaded"
fi

expect_simulated_rce_runs

finish
