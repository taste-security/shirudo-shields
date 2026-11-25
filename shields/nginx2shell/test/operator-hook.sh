#!/bin/sh
# SPDX-License-Identifier: BSD-2-Clause
#
# usage: operator-hook.sh before|after <stage>
#
# Run as root on the operator host around `shirudo bpm build` by
# tools/ci/build-shield.sh. The h2guard upatch probes the libssl nginx
# loads, at N2S_LIBSSL (/usr/lib/libssl.so.3, the demo image's path), and
# the builder opens that same path on the operator host to find the
# probed functions and record the file's build ID, which the target then
# checks. before puts the demo image's libssl, from <stage>/rootfs.tar,
# at that path (moving aside a different file found there); after puts
# things back. The target gets the identical file through
# nginx2shell-demo.sh install, a hard link of the chroot's copy.

set -eu

[ $# -eq 2 ] || { echo "usage: $0 before|after <stage>" >&2; exit 2; }
libssl=${N2S_LIBSSL:-/usr/lib/libssl.so.3}
stage=$2
aside=$libssl.nginx2shell-aside
placed=$libssl.nginx2shell-placed

case $1 in
before)
	tmp=$(mktemp -d)
	tar -xf "$stage/rootfs.tar" -C "$tmp" usr/lib/libssl.so.3
	if [ -e "$libssl" ] && ! cmp -s "$libssl" "$tmp/usr/lib/libssl.so.3"; then
		mv "$libssl" "$aside"
	fi
	if [ ! -e "$libssl" ]; then
		install -D -m 0755 "$tmp/usr/lib/libssl.so.3" "$libssl"
		: >"$placed"
	fi
	rm -rf "$tmp"
	echo "operator host: $libssl is the demo image's libssl ($(sha256sum <"$libssl" | cut -c1-16))"
	;;
after)
	if [ -e "$placed" ]; then
		rm -f "$libssl" "$placed"
	fi
	if [ -e "$aside" ]; then
		mv "$aside" "$libssl"
	fi
	;;
*)
	echo "usage: $0 before|after <stage>" >&2
	exit 2
	;;
esac
