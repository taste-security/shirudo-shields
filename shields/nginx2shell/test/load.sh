#!/bin/sh
# SPDX-License-Identifier: BSD-2-Clause
#
# Load the shield: every upatches/*.upatch of the package in name order,
# as `shirudo bpm install` does, each load verified by the kernel and
# measured. Then restart nginx, since a task carries the policy of the
# file it executed, and the nginx processes started before the load
# executed an unlabeled file.

. "$(dirname "$0")/lib.sh"

set -- "$N2S_SHIELD_DIR"/upatches/*.upatch
loads=0
for upatch in "$@"; do
	case $upatch in
	*.unload.upatch | *"*"*) continue ;;
	esac
	loads=$((loads + 1))
	name=$(basename "$upatch" .upatch)
	if "$SHIRUDO_RUNTIME" upatch load --report="$N2S_OUT/load-$name.json" "$upatch" \
		>"$W/load" 2>&1; then
		pass "upatch load $name"
	else
		sed 's/^/      | /' "$W/load"
		fail "upatch load $name: category $(sed -n 's/.*"category": *"\([^"]*\)".*/\1/p' "$N2S_OUT/load-$name.json" 2>/dev/null | head -n 1)"
	fi
done
[ "$loads" -gt 0 ] || fail "no upatches in $N2S_SHIELD_DIR/upatches"

check "$CONTAIN is loaded" loaded "$CONTAIN"
check "$H2GUARD is loaded" loaded "$H2GUARD"

for path in /usr/sbin/nginx /usr/local/sbin/nginx; do
	bits=$(python3 -c 'import os, sys
try:
    print(hex(int.from_bytes(os.getxattr(sys.argv[1], "security.bpf.shirudo.policy"), sys.byteorder)))
except OSError:
    print("none")' "$path")
	if [ "$bits" != none ]; then
		pass "$path carries the policy label $bits"
	else
		fail "$path carries no policy label"
	fi
done

if sh "$N2S_DEMO" start >"$W/start" 2>&1; then
	pass "nginx restarted under the shield"
else
	sed 's/^/      | /' "$W/start"
	fail "nginx did not restart under the shield"
fi
"$SHIRUDO_RUNTIME" upatch list 2>&1 | sed 's/^/      | /'

finish
