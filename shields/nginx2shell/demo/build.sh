#!/bin/sh
# SPDX-License-Identifier: BSD-2-Clause
#
# usage: build.sh <archive>
#
# Builds the image of the Dockerfile beside this script and writes its
# file system to <archive>, a tar, for nginx2shell-demo.sh to run nginx
# from on a Shirudo target, which runs no Docker (shirudo locks bpf()
# down to signed loaders, and a container runtime loads its own BPF).
# The same approach as Shirudo's upatches/app-sandbox/demo/build.sh.
# Needs Docker and, the first time, the network; no root.
#
# DOCKER_PLATFORM, linux/amd64 by default on x86-64, picks the image of
# another architecture.

set -eu

[ $# -eq 1 ] || { echo "usage: $0 <archive>" >&2; exit 2; }
here=$(cd "$(dirname "$0")" && pwd)
image=${N2S_IMAGE:-shirudo-nginx2shell-demo}

if [ -n "${DOCKER_PLATFORM:-}" ]; then
	docker build -q --platform "$DOCKER_PLATFORM" -t "$image" "$here" >/dev/null
else
	docker build -q -t "$image" "$here" >/dev/null
fi
container=$(docker create "$image")
trap 'docker rm "$container" >/dev/null' EXIT
# The target binds its own /dev there.
docker export "$container" >"$1"
echo "$image -> $1"
