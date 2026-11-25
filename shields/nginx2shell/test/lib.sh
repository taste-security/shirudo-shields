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

https_status()
{
	curl -sk --http2 --max-time 20 -o /dev/null -w '%{http_code} %{http_version}' "$1"
}
