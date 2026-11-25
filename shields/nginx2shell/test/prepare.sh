#!/bin/sh
# SPDX-License-Identifier: BSD-2-Clause
#
# usage: prepare.sh <stage>
#
# Run as root on the target before the scenarios, with <stage> as CI
# lays it out: rootfs.tar from demo/build.sh, the repository in repo/
# and the unpacked package in shield/. Installs and starts the two nginx
# instances in their chroot, and says what the target brings.

set -eu

stage=$1
demo=$stage/repo/shields/nginx2shell/demo/nginx2shell-demo.sh
libssl=${N2S_LIBSSL:-/usr/lib/libssl.so.3}

echo "target: $(uname -srm)"
"${SHIRUDO_RUNTIME:-shirudo-runtime}" status 2>&1 | sed -n '1,6p'
for cmd in curl python3; do
	if command -v "$cmd" >/dev/null 2>&1; then
		echo "$cmd: $("$cmd" --version 2>&1 | head -n 1)"
	else
		echo "prepare: the target has no $cmd, which the scenarios need" >&2
		exit 1
	fi
done
curl --version | grep -q 'HTTP2' || {
	echo "prepare: the target's curl has no HTTP/2" >&2
	exit 1
}

sh "$demo" install "$stage/rootfs.tar"
sh "$demo" start
sh "$demo" status
ls -li "$libssl" /var/lib/nginx2shell-demo/usr/lib/libssl.so.3
