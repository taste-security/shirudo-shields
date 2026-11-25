#!/bin/sh
# SPDX-License-Identifier: BSD-2-Clause
#
# Regression, run with the shield loaded. The scenarios before it show
# each layer working once; this one pins the edges a later change to the
# shield, to Shirudo or to nginx could break without any of them noticing.
# It recreates the conditions CVE-2026-123007 needs inside the test VM: a
# vulnerable-range nginx (1.31.8) with HTTP/2 and TLS for the post-exploit
# checks, and the over-limit flow-control input, sent only to FIXED nginx
# 1.31.9 (h2probe refuses any other). No exploit is run or needed.
#
#   1  the limit, exactly: a window at 2^31-1 is legal and served, one
#      past it is cut. Catches an off-by-one either way.
#   2  a sustained attack: the guard cuts every attempt in a row, the
#      master survives, a fresh worker serves after each, and the
#      vulnerable instance is never touched.
#   3  across an nginx reload: fresh workers stay contained and guarded.
#   4  containment of files: a .html drop (webshell, defacement) is
#      refused, a .txt drop no rule denies still works.
#   5  ordinary traffic afterwards: HTTP/1.1 and HTTP/2 with cancels work,
#      with no guard hit and no worker killed.

. "$(dirname "$0")/lib.sh"
need curl python3

case $N2S_PATCHED_URL in
*:8443*) fail "N2S_PATCHED_URL points at the vulnerable instance"; finish ;;
esac

for u in "$CONTAIN" "$H2GUARD"; do
	loaded "$u" || { fail "$u is not loaded; regression runs under the shield"; finish; }
done

# probe <pattern> <expected RESULT prefix>: one h2probe run against the
# fixed instance. h2probe's own gate refuses a vulnerable nginx (exit 3).
probe()
{
	python3 "$H2PROBE" --pattern "$1" "$N2S_PATCHED_URL" >"$W/probe-$1" 2>&1
	rc=$?
	result=$(sed -n "s/^PATTERN $1 RESULT //p" "$W/probe-$1")
	[ "$rc" -ne 3 ] || { fail "h2probe refused $N2S_PATCHED_URL: is it nginx 1.31.9?"; return 1; }
	case $result in
	"$2"*) return 0 ;;
	*) info "$1: $result"; return 1 ;;
	esac
}

guard_hits()
{
	events "$H2GUARD" "$H2GUARD_EVENTS" "$W/hits"
	hits "$W/hits"
}

# serves_soon <url>: GET / is 200 over HTTP/2 within 5 s, the time nginx
# needs to fork a fresh worker after the guard killed one.
serves_soon()
{
	for _ in $(seq 25); do
		[ "$(https_status "$1/")" = "200 2" ] && return 0
		sleep 0.2
	done
	return 1
}

# --- 1  the limit, exactly ---------------------------------------------
h0=$(guard_hits)
patched_workers=$(workers patched)
check "1: a connection window raised to exactly 2^31-1 is legal and served" \
	probe at-limit "served status=200"
check "1: SETTINGS_INITIAL_WINDOW_SIZE at its legal maximum 2^31-1 is served" \
	probe settings-at-max "served status=200"
h1=$(guard_hits)
check "1: the legal maximum is no guard hit (${h0:-0} -> ${h1:-0})" [ "${h1:-0}" = "${h0:-0}" ]
check "1: no 1.31.9 worker was killed at the limit" [ "$(workers patched)" = "$patched_workers" ]
# One past the limit is cut, and the guard provably killed the worker that
# handled it (same assertion h2guard uses): fresh action=killed with the
# right reason on that worker, confirmed in nginx's log, with recovery.
guard_before patched
check "1: one past the limit is cut before nginx answers" probe one-over "cut "
guard_enforced conn_window_over_max "1"
h2=$(guard_hits)

# --- 2  a sustained attack ---------------------------------------------
ROUNDS=5
master=$(sh "$N2S_DEMO" master patched)
vuln_workers=$(workers vulnerable)
cut=0
served=0
for round in $(seq "$ROUNDS"); do
	probe direct "cut " && cut=$((cut + 1))
	serves_soon "$N2S_PATCHED_URL" && served=$((served + 1))
	info "round $round: workers $(workers patched)"
done
h3=$(guard_hits)
check "2: the guard cut $cut of $ROUNDS attacks in a row" [ "$cut" -eq "$ROUNDS" ]
check "2: a fresh worker served after $served of $ROUNDS cuts" [ "$served" -eq "$ROUNDS" ]
check "2: every attack is a guard hit (${h2:-0} -> ${h3:-0})" \
	[ "$(( ${h3:-0} - ${h2:-0} ))" -ge "$ROUNDS" ]
master_survived()
{
	[ -n "$master" ] && [ "$(sh "$N2S_DEMO" master patched)" = "$master" ]
}
check "2: the 1.31.9 master survived every cut (pid $master)" master_survived
check "2: the vulnerable instance was never touched" [ "$(workers vulnerable)" = "$vuln_workers" ]

# --- 3  across an nginx reload -----------------------------------------
if sh "$N2S_DEMO" reload >"$W/reload" 2>&1; then
	pass "3: nginx reloaded ($(cat "$W/reload"))"
else
	fail "3: nginx did not reload: $(cat "$W/reload")"
fi
simulated_rce "$N2S_VULN_URL" >"$W/rce" || :
sed 's/^/      | /' "$W/rce"
check "3: a fresh 1.31.8 worker still cannot exec /bin/sh" [ "$(field exec "$W/rce")" = refused ]
check "3: a fresh 1.31.8 worker still cannot connect out" [ "$(field connect "$W/rce")" = refused ]
check "3: a fresh 1.31.9 worker is still guarded" probe direct "cut "
check "3: nginx 1.31.9 serves after that cut" serves_soon "$N2S_PATCHED_URL"

# --- 4  containment of files -------------------------------------------
expect_drop html refused "$W/rce"
expect_drop txt ok "$W/rce"
check "4: the SIMULATED .html drop left no file behind" \
	[ ! -e "$N2S_ROOT/var/lib/n2s-drop/simulated-drop.html" ]

# --- 5  ordinary traffic afterwards ------------------------------------
h4=$(guard_hits)
killed=$(killed_lines)
vuln_workers=$(workers vulnerable)
patched_workers=$(workers patched)
for url in "$N2S_VULN_URL" "$N2S_PATCHED_URL"; do
	status=$(curl -sk --http1.1 --max-time 20 -o /dev/null -w '%{http_code} %{http_version}' "$url/")
	check "5: HTTP/1.1 GET / on $url is 200 ($status)" [ "$status" = "200 1.1" ]
done
curl -sk --http1.1 --max-time 120 -o "$W/big1.bin" -w '%{http_code} %{size_download}' \
	"$N2S_PATCHED_URL/big.bin" >"$W/big1" 2>&1 || :
want=$(sha256sum <"$N2S_ROOT/usr/share/nginx/n2s/big.bin" | cut -d' ' -f1)
got=$(sha256sum <"$W/big1.bin" 2>/dev/null | cut -d' ' -f1)
big1_whole()
{
	[ "$(cat "$W/big1")" = "200 $BIG_SIZE" ] && [ "$want" = "$got" ]
}
check "5: an 8 MiB HTTP/1.1 download arrives whole ($(cat "$W/big1"))" big1_whole
for url in "$N2S_VULN_URL" "$N2S_PATCHED_URL"; do
	if python3 "$H2CLIENT" --requests 20 --cancels 10 --big-size "$BIG_SIZE" "$url" >"$W/h2client" 2>&1; then
		pass "5: HTTP/2 on $url: interleaved streams and cancels with data in flight"
	else
		sed 's/^/      | /' "$W/h2client"
		fail "5: HTTP/2 on $url failed after the attacks"
	fi
done
h5=$(guard_hits)
check "5: ordinary traffic is no guard hit (${h4:-0} -> ${h5:-0})" [ "${h5:-0}" = "${h4:-0}" ]
none_killed()
{
	[ "$(workers vulnerable)" = "$vuln_workers" ] &&
		[ "$(workers patched)" = "$patched_workers" ] &&
		[ "$(killed_lines)" = "$killed" ]
}
check "5: no worker was killed by ordinary traffic" none_killed

finish
