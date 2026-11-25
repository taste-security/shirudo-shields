# SPDX-License-Identifier: BSD-2-Clause
#
# Sourced by the nginx2shell scenario scripts. They run on a Shirudo
# target, as root, against the two nginx instances of
# ../demo/nginx2shell-demo.sh, and print one "PASS: <scenario>: <what>" or
# "FAIL: <scenario>: <what>" line per check. Settings, all optional:
#
#   N2S_SHIELD_DIR    the shield's upatches: a directory holding
#   (SHIELD_PKG_DIR)  upatches/*.upatch and *.unload.upatch, as a .bee
#                     unpacks (default: build/shield in this repository)
#   N2S_OUT           where results and map dumps go
#   (SHIELD_OUT)      (default /var/tmp/nginx2shell-test)
#   SHIRUDO_RUNTIME   the runtime binary (default shirudo-runtime)
#   N2S_ROOT          the demo's chroot (default /var/lib/nginx2shell-demo)
#   N2S_VULN_URL      nginx 1.31.8 (default https://127.0.0.1:8443)
#   N2S_PATCHED_URL   nginx 1.31.9 (default https://127.0.0.1:9443)
#
# The clients (curl, python3) are the target's own, linked to its own
# libssl, not to the chroot's /usr/lib/libssl.so.3 the guard probes.
#
# shellcheck disable=SC2034 # the scenarios use what this file sets

N2S_TEST_DIR=$(cd "$(dirname "$0")" && pwd)
N2S_REPO=${N2S_REPO:-$(cd "$N2S_TEST_DIR/../../.." && pwd)}
N2S_DEMO=$N2S_REPO/shields/nginx2shell/demo/nginx2shell-demo.sh
N2S_SHIELD_DIR=${N2S_SHIELD_DIR:-${SHIELD_PKG_DIR:-$N2S_REPO/build/shield}}
N2S_OUT=${N2S_OUT:-${SHIELD_OUT:-/var/tmp/nginx2shell-test}}
N2S_ROOT=${N2S_ROOT:-/var/lib/nginx2shell-demo}
SHIRUDO_RUNTIME=${SHIRUDO_RUNTIME:-shirudo-runtime}
N2S_VULN_URL=${N2S_VULN_URL:-https://127.0.0.1:8443}
N2S_PATCHED_URL=${N2S_PATCHED_URL:-https://127.0.0.1:9443}
H2PROBE=$N2S_REPO/tools/h2probe/h2probe
H2CLIENT=$N2S_REPO/tools/h2probe/h2client
EVENTS=$N2S_TEST_DIR/events.py
# The upatches of the shield and the maps that hold what they refused.
CONTAIN=nginx2shell-contain
H2GUARD=nginx2shell-h2guard
CONTAIN_EVENTS=${N2S_CONTAIN_EVENTS_MAP:-refused}
H2GUARD_EVENTS=${N2S_H2GUARD_EVENTS_MAP:-h2_events}
BIG_SIZE=8388608
export N2S_ROOT

SCENARIO=${SCENARIO:-$(basename "$0" .sh)}
N2S_FAILS=0
N2S_PASSES=0
mkdir -p "$N2S_OUT"
W=$(mktemp -d)
trap 'rm -rf "$W"' EXIT

pass()
{
	N2S_PASSES=$((N2S_PASSES + 1))
	printf 'PASS: %s: %s\n' "$SCENARIO" "$*"
}

fail()
{
	N2S_FAILS=$((N2S_FAILS + 1))
	printf 'FAIL: %s: %s\n' "$SCENARIO" "$*"
}

info()
{
	printf '      %s\n' "$*"
}

# check <what> <command>...: PASS when the command succeeds.
check()
{
	what=$1
	shift
	if "$@"; then
		pass "$what"
	else
		fail "$what"
	fi
}

finish()
{
	printf '%s %s pass=%d fail=%d\n' "$SCENARIO" \
		"$([ "$N2S_FAILS" -eq 0 ] && echo PASS || echo FAIL)" \
		"$N2S_PASSES" "$N2S_FAILS" >>"$N2S_OUT/summary.txt"
	[ "$N2S_FAILS" -eq 0 ]
	exit $?
}

need()
{
	for cmd in "$@"; do
		command -v "$cmd" >/dev/null 2>&1 && continue
		fail "the target has no $cmd"
		finish
	done
}

# The SIMULATED post-exploit step on instance $1 (a URL); the body goes
# to standard output.
simulated_rce()
{
	curl -sk --http2 --max-time 20 "$1/__simulated_rce"
}

field()
{
	sed -n "s/^$1=\([a-z]*\).*/\1/p" "$2" | head -n 1
}

errno_of()
{
	sed -n "s/^$1=[a-z]* errno=\([A-Z0-9]*\).*/\1/p" "$2" | head -n 1
}

# The checks of scenario 1, which scenario 5 repeats.
expect_simulated_rce_runs()
{
	simulated_rce "$N2S_VULN_URL" >"$W/rce" || :
	sed 's/^/      | /' "$W/rce"
	check "the response is labeled SIMULATED" grep -q '^SIMULATED' "$W/rce"
	if [ "$(field exec "$W/rce")" = ok ] && grep -q '^exec=ok output=".*uid=' "$W/rce"; then
		pass "the nginx worker ran /bin/sh -c id: $(sed -n 's/^exec=ok output="\([^"]*\)".*/\1/p' "$W/rce")"
	else
		fail "the nginx worker could not run /bin/sh -c id: $(grep '^exec=' "$W/rce")"
	fi
	case $(field connect "$W/rce") in
	ok | attempted)
		pass "the kernel let the worker connect out to 192.0.2.1:4444 ($(grep '^connect=' "$W/rce" | cut -d' ' -f1-2))"
		;;
	*)
		fail "the worker's connect to 192.0.2.1:4444 did not go out: $(grep '^connect=' "$W/rce")"
		;;
	esac
	for kind in html txt; do
		expect_drop "$kind" ok "$W/rce"
	done
}

# expect_drop <html|txt> <ok|refused> <response>: the SIMULATED file drop
# of that kind in /var/lib/n2s-drop, a directory the worker owns, had that
# outcome. Without the shield both drops work, so a refusal under it is the
# shield's deny rule and not the file's permissions.
expect_drop()
{
	got=$(field "drop_$1" "$3")
	line=$(grep "^drop_$1=" "$3")
	if [ "$got" = "$2" ]; then
		case $2 in
		ok) pass "the worker created a .$1 file in /var/lib/n2s-drop" ;;
		*) pass "the kernel refused the worker's .$1 file drop ($(errno_of "drop_$1" "$3"))" ;;
		esac
	else
		fail "the .$1 file drop: expected $2, got: ${line:-no drop_$1 line}"
	fi
}

# loaded <upatch>: whether upatch list shows it loaded.
loaded()
{
	"$SHIRUDO_RUNTIME" upatch list 2>/dev/null |
		awk -v n="$1" '$1 == n && $2 == "yes" { found = 1 } END { exit !found }'
}

# events <upatch> <map> <file>: the decoded records of the map, peeked,
# summarized by events.py; the first line is "total=<n> hits=<h> ...".
# The file is empty when the map cannot be read.
events()
{
	if "$SHIRUDO_RUNTIME" upatch map "$1" "$2" --peek --json >"$3.json" 2>"$3.err"; then
		python3 "$EVENTS" <"$3.json" >"$3"
	else
		: >"$3"
	fi
}

total()
{
	sed -n '1s/^total=\([0-9]*\).*/\1/p' "$1"
}

hits()
{
	sed -n '1s/^total=[0-9]* hits=\([0-9]*\).*/\1/p' "$1"
}

# The PIDs of instance $1's workers, comma separated.
workers()
{
	sh "$N2S_DEMO" workers "$1" | paste -sd, -
}

killed_lines()
{
	cat "$N2S_ROOT"/var/log/nginx/n2s-*.error.log 2>/dev/null |
		grep -c 'exited on signal' || :
}

# Worker exits from a crash: SIGSEGV (11), SIGABRT (6), SIGBUS (7) or
# SIGILL (4). nginx's flow-control bug, if the frames reached it, would
# show up here. The guard's own stop is SIGKILL (9), which this does not
# count, so a crash is told apart from an interception.
crash_lines()
{
	cat "$N2S_ROOT"/var/log/nginx/n2s-*.error.log 2>/dev/null |
		grep -cE 'exited on signal (4|6|7|11)' || :
}

https_status()
{
	curl -sk --http2 --max-time 20 -o /dev/null -w '%{http_code} %{http_version}' "$1"
}

master()
{
	sh "$N2S_DEMO" master "$1"
}

instance_url()
{
	case $1 in
	vulnerable) echo "$N2S_VULN_URL" ;;
	patched) echo "$N2S_PATCHED_URL" ;;
	esac
}

# worker_exited_on <pid> <signal> <instance>: the instance's own error log
# says its worker <pid> exited on that signal. Each instance logs to its own
# file, so a match also proves the worker belonged to that instance. The
# guard's stop is signal 9 (SIGKILL).
worker_exited_on()
{
	grep -qE "worker process $1 exited on signal $2" \
		"$N2S_ROOT/var/log/nginx/n2s-$3.error.log" 2>/dev/null
}

# killed_pids <events-file>: the pids of every action=killed record.
killed_pids()
{
	awk '/^  / && / action=killed / {
		for (i = 1; i <= NF; i++) if ($i ~ /^pid=/) print substr($i, 5)
	}' "$1"
}

# find_new_kill <events-file> <reason> <earlier-kills>: the pid of an
# action=killed record with the given reason whose pid is not among
# <earlier-kills> (the pids killed before this case, newline or space
# separated). Prints nothing when none matches, so a stale kill from an
# earlier case, an action=recorded, an action=kill_failed or a wrong reason
# does not count as enforcement. Used by guard_enforced and exercised
# directly by the selftest scenario.
find_new_kill()
{
	awk -v reason="$2" -v earlier=" $(printf '%s' "$3" | tr '\n' ' ') " '
		/^  / {
			a = ""; r = ""; p = "";
			for (i = 1; i <= NF; i++) {
				if ($i ~ /^action=/) a = substr($i, 8);
				else if ($i ~ /^reason=/) r = substr($i, 8);
				else if ($i ~ /^pid=/) p = substr($i, 5);
			}
			if (a == "killed" && r == reason && p != "" &&
				index(earlier, " " p " ") == 0) { print p; exit }
		}' "$1"
}

# guard_before <instance>: capture the state a guard case is judged against.
# The scenario calls this right before the probe, then guard_enforced after.
guard_before()
{
	GB_INSTANCE=$1
	GB_MASTER=$(master "$1")
	GB_CRASH=$(crash_lines)
	events "$H2GUARD" "$H2GUARD_EVENTS" "$W/gb"
	GB_HITS=$(hits "$W/gb")
	GB_KILLED=$(killed_pids "$W/gb")
}

# guard_enforced <reason> <label>: after a probe that should have been cut,
# prove the guard killed the worker that handled it. Requires a new hit, a
# new action=killed record with that reason (a pid with no kill record
# before the case), the instance's own error log showing that worker exited
# on SIGKILL, that worker now gone, the master still alive with a worker
# running, a fresh HTTP/2 200, and no crash signal in the window.
guard_enforced()
{
	reason=$1
	label=$2
	inst=$GB_INSTANCE
	events "$H2GUARD" "$H2GUARD_EVENTS" "$W/ga"
	now_hits=$(hits "$W/ga")
	if [ "${now_hits:-0}" -le "${GB_HITS:-0}" ]; then
		sed 's/^/      | /' "$W/ga"
		fail "$label: no new guard hit (${GB_HITS:-0} -> ${now_hits:-0})"
		return
	fi
	pid=$(find_new_kill "$W/ga" "$reason" "$GB_KILLED")
	if [ -z "$pid" ]; then
		sed 's/^/      | /' "$W/ga"
		fail "$label: no new action=killed event with reason=$reason"
		return
	fi
	pass "$label: a new kill event for this case (pid $pid, reason=$reason, action=killed)"
	ok=0
	for _ in 1 2 3 4 5 6 7 8 9 10 11 12 13 14 15; do
		if worker_exited_on "$pid" 9 "$inst"; then ok=1; break; fi
		sleep 0.3
	done
	check "$label: the $inst error log shows its worker $pid exited on SIGKILL (signal 9)" [ "$ok" = 1 ]
	check "$label: no worker crashed in this case ($(crash_lines) crash signals total)" \
		[ "$(crash_lines)" = "${GB_CRASH:-0}" ]
	case " $(workers "$inst" | tr '\n' ' ') " in
	*" $pid "*) fail "$label: the killed worker $pid is still running" ;;
	*) pass "$label: the killed worker $pid is gone" ;;
	esac
	if [ -n "$GB_MASTER" ] && [ "$(master "$inst")" = "$GB_MASTER" ]; then
		pass "$label: the $inst master survived (pid $GB_MASTER)"
	else
		fail "$label: the $inst master changed ($GB_MASTER -> $(master "$inst"))"
	fi
	check "$label: a replacement worker is running" [ -n "$(workers "$inst")" ]
	status=$(https_status "$(instance_url "$inst")/")
	check "$label: $inst serves a fresh HTTP/2 request ($status)" [ "$status" = "200 2" ]
}
