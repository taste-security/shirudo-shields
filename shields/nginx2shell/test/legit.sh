#!/bin/sh
# SPDX-License-Identifier: BSD-2-Clause
#
# Scenario 3, legit: the shield is loaded. Ordinary HTTP/2 to nginx
# 1.31.8: single and parallel requests with curl --http2, an 8 MiB
# download that takes hundreds of WINDOW_UPDATEs, a download cut short,
# and h2client's browser-like cancels (RST_STREAM CANCEL with data in
# flight, then more requests on the same connection). Every request
# answers 200, the guard records nothing and kills no worker.

. "$(dirname "$0")/lib.sh"
need curl python3

events "$H2GUARD" "$H2GUARD_EVENTS" "$W/before"
vuln_workers=$(workers vulnerable)
patched_workers=$(workers patched)
killed=$(killed_lines)
info "workers before: 1.31.8 $vuln_workers, 1.31.9 $patched_workers"

status=$(https_status "$N2S_VULN_URL/")
check "curl --http2 GET / is 200 over HTTP/2 ($status)" [ "$status" = "200 2" ]

set --
for i in $(seq 50); do
	set -- "$@" -o /dev/null "$N2S_VULN_URL/?n=$i"
done
curl -sk --http2 --parallel --parallel-max 25 --max-time 60 \
	-w '%{http_code} %{http_version}\n' "$@" >"$W/parallel" 2>&1 || :
ok=$(grep -c '^200 2$' "$W/parallel" || :)
check "50 parallel curl --http2 requests: $ok answered 200" [ "$ok" -eq 50 ]

curl -sk --http2 --max-time 120 -o "$W/big.bin" -w '%{http_code} %{http_version} %{size_download}\n' \
	"$N2S_VULN_URL/big.bin" >"$W/big" 2>&1 || :
want=$(sha256sum <"$N2S_ROOT/usr/share/nginx/n2s/big.bin" | cut -d' ' -f1)
got=$(sha256sum <"$W/big.bin" 2>/dev/null | cut -d' ' -f1)
if [ "$(cat "$W/big")" = "200 2 $BIG_SIZE" ] && [ "$want" = "$got" ]; then
	pass "an 8 MiB download over HTTP/2 arrives whole"
else
	fail "the 8 MiB download did not arrive whole: $(cat "$W/big")"
fi

curl -sk --http2 --limit-rate 1M --max-time 1 -o /dev/null "$N2S_VULN_URL/big.bin" >/dev/null 2>&1
status=$?
check "a download abandoned midway ends on the client's side (curl exit $status)" [ "$status" -eq 28 ]

for url in "$N2S_VULN_URL" "$N2S_PATCHED_URL"; do
	python3 "$H2CLIENT" --requests 20 --cancels 10 --big-size "$BIG_SIZE" "$url" >"$W/h2client" 2>&1
	status=$?
	tail -n 1 "$W/h2client" | sed 's/^/      | /'
	check "h2client on $url: 21 streams interleaved and 10 cancelled with data in flight" [ "$status" -eq 0 ]
done

status=$(https_status "$N2S_VULN_URL/")
check "nginx 1.31.8 still serves ($status)" [ "$status" = "200 2" ]
check "no nginx 1.31.8 worker was killed ($(workers vulnerable))" [ "$(workers vulnerable)" = "$vuln_workers" ]
check "no nginx 1.31.9 worker was killed ($(workers patched))" [ "$(workers patched)" = "$patched_workers" ]
check "nginx logged no worker exit on a signal" [ "$(killed_lines)" = "$killed" ]

events "$H2GUARD" "$H2GUARD_EVENTS" "$W/after"
before=$(hits "$W/before")
after=$(hits "$W/after")
if [ -n "$after" ] && [ "$after" = "${before:-0}" ]; then
	pass "the guard recorded no hit (hits in $H2GUARD_EVENTS stay $after)"
else
	sed 's/^/      | /' "$W/after" "$W/after.err"
	fail "the guard recorded a hit, or its map could not be read (${before:-?} -> ${after:-?})"
fi
if [ "$(total "$W/after")" != "$(total "$W/before")" ]; then
	info "the guard noted connections it stopped following:"
	sed 's/^/      | /' "$W/after"
fi

finish
