#!/bin/sh
# SPDX-License-Identifier: BSD-2-Clause
#
# usage: run-all.sh [--narrate] [<scenario>...]
#
# Runs the nginx2shell scenarios on a Shirudo target, as root, in the
# order: selftest (the guard assertion rejects weak evidence), baseline
# (shield not loaded), load, contain, legit, h2guard, intercept,
# regression, lifecycle, unload. Every scenario runs even when one before it
# failed, so that unload always runs. Prints one "SCENARIO <name> PASS"
# or "FAIL" line each and exits 1 if any failed. --narrate prints a short
# line before each scenario, for a recording; the demo is this run.
#
# Expects nginx2shell-demo.sh install to have run, and the shield not to
# be loaded. See lib.sh for the settings.

here=$(cd "$(dirname "$0")" && pwd)
narrate=0
if [ "${1:-}" = --narrate ]; then
	narrate=1
	shift
fi
[ $# -gt 0 ] || set -- selftest baseline load contain legit h2guard intercept regression lifecycle unload

N2S_OUT=${N2S_OUT:-${SHIELD_OUT:-/var/tmp/nginx2shell-test}}
export N2S_OUT
mkdir -p "$N2S_OUT"
: >"$N2S_OUT/summary.txt"
demo=$here/../demo/nginx2shell-demo.sh

say()
{
	[ "$narrate" -eq 1 ] || return 0
	printf '\n\033[1m%s\033[0m\n\n' "$*"
	sleep 2
}

title()
{
	case $1 in
	selftest) echo "0 · Self-test: the guard assertion rejects a stale kill, a kill_failed and a recorded-only event" ;;
	baseline) echo "1 · Without the shield: a SIMULATED post-exploit shell runs as the nginx worker" ;;
	load) echo "2 · Load the Shirudo shield" ;;
	contain) echo "3 · Same SIMULATED step with the shield: shell, callback and webshell drop refused, nginx keeps serving" ;;
	legit) echo "4 · Normal HTTP/2 traffic: every request served, nothing cut" ;;
	h2guard) echo "5 · The over-limit flow-control pattern, sent only to fixed nginx 1.31.9: the guard cuts it first" ;;
	intercept) echo "6 · The same trigger aimed at vulnerable nginx 1.31.8, with the shield on: cut before nginx parses it, no crash" ;;
	regression) echo "7 · Regression: the exact limit, a sustained attack, an nginx reload, then normal traffic" ;;
	lifecycle) echo "8 · Lifecycle: workers killed from outside leave no entries behind in the guard's table" ;;
	unload) echo "9 · Unload the shield: the SIMULATED shell runs again" ;;
	*) echo "$1" ;;
	esac
}

# The map export timer drains the serializer-backed maps every five
# seconds; the scenarios read the maps before and after, so it waits.
timer=
if systemctl is-active --quiet shirudo-map-export.timer 2>/dev/null; then
	timer=shirudo-map-export.timer
	systemctl stop "$timer"
fi

say "nginx2shell · Shirudo shield for CVE-2026-123007 · nginx 1.31.8 on :8443, fixed 1.31.9 on :9443"
sh "$demo" start

# Record what this run tested, so a result can be reproduced: the kernel,
# and each nginx build with the OpenSSL it was built with and runs with.
root=${N2S_ROOT:-/var/lib/nginx2shell-demo}
{
	echo "kernel $(uname -r)"
	for bin in /usr/sbin/nginx /usr/local/sbin/nginx; do
		echo "$bin:"
		chroot "$root" "$bin" -V 2>&1 | grep -E "version|OpenSSL" | sed 's/^/  /'
	done
} >"$N2S_OUT/versions.txt" 2>&1
sed 's/^/      /' "$N2S_OUT/versions.txt"

failed=0
for scenario in "$@"; do
	say "$(title "$scenario")"
	if sh "$here/$scenario.sh"; then
		result=PASS
	else
		result=FAIL
		failed=1
	fi
	echo "SCENARIO $scenario $result"
done

[ -z "$timer" ] || systemctl start "$timer"

# Keep the nginx worker-lifecycle log with the run's artifacts: the guard
# scenarios assert a specific worker exited on SIGKILL, and these are the
# lines they match. SHIELD_OUT is uploaded as part of the VM result.
sh "$demo" logs >"$N2S_OUT/nginx-error.log" 2>&1 || :

say "Summary"
printf '%-10s %-6s %s\n' SCENARIO RESULT CHECKS
while read -r name result passes fails; do
	printf '%-10s %-6s %s %s\n' "$name" "$result" "$passes" "$fails"
done <"$N2S_OUT/summary.txt"
exit "$failed"
