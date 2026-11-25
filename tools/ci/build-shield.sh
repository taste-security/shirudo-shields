#!/bin/sh
# SPDX-License-Identifier: BSD-2-Clause
#
# usage: build-shield.sh <shield> <version> <stage>
#
# Builds shields/<shield> into a .bee with `shirudo bpm build`, signed
# with the test VM's operator keys, and unpacks it under <stage>/shield,
# where the target finds upatches/*.upatch and *.unload.upatch through
# the VM's read-only share of the Shirudo checkout. As Shirudo's own
# t9114 does, the package directory is a copy with the checkout's vendor/
# and bpf/ linked in, for the libbpf headers, vmlinux.h and policy.h.
#
# shields/<shield>/test/operator-hook.sh, when present, runs as root with
# "before <stage>" ahead of the build and "after <stage>" once it ends,
# for what the build needs on the operator host.
#
# Run from the root of this repository, after shirudo.sh build.

set -eu

[ $# -eq 3 ] || { echo "usage: $0 <shield> <version> <stage>" >&2; exit 2; }
shield=$1
version=$2
stage=$3
repo=$(pwd)
ci=$repo/tools/ci
SHIRUDO_DIR=$(cd "${SHIRUDO_DIR:-_shirudo}" && pwd)
SHIRUDO_PRIVATE_DIR=${SHIRUDO_PRIVATE_DIR:-${RUNNER_TEMP:-/tmp}/shirudo-private}
export SHIRUDO_DIR SHIRUDO_PRIVATE_DIR
keys=$SHIRUDO_PRIVATE_DIR/operator-keys/keys
src=$repo/shields/$shield
hook=$src/test/operator-hook.sh
work=$(mktemp -d)
mkdir -p "$stage"

cleanup()
{
	[ ! -f "$hook" ] || sh "$ci/shirudo.sh" sudo sh "$hook" after "$stage" || :
	rm -rf "$work"
}
trap cleanup EXIT

# The package directory: the shield without its tests and demo.
mkdir -p "$work/$shield"
(cd "$src" && tar -cf - --exclude=./test --exclude=./demo .) | tar -xf - -C "$work/$shield"
ln -s "$SHIRUDO_DIR/vendor" "$SHIRUDO_DIR/bpf" "$work/$shield/"

[ ! -f "$hook" ] || sh "$ci/shirudo.sh" sudo sh "$hook" before "$stage"

status=0
sh "$ci/shirudo.sh" sudo sh -c 'cd "$1" && "$2/shirudo" bpm build "$3" --version "$4" --keys-dir "$5"' \
	sh "$work" "$SHIRUDO_DIR" "$shield" "$version" "$keys" >"$stage/bpm-build.log" 2>&1 || status=$?
cat "$stage/bpm-build.log"
[ "$status" -eq 0 ] || { echo "bpm build failed with status $status" >&2; exit 1; }
bee=$(ls "$work"/*.bee)
sh "$ci/shirudo.sh" sudo chown "$(id -u):$(id -g)" "$bee"
cp "$bee" "$stage/"
# shellcheck source=/dev/null
. "$SHIRUDO_DIR/build/vm-toolchain.env"
{
	"$SHIRUDO_DIR/shirudo" bpm info "$bee"
	"$SHIRUDO_DIR/shirudo" bpm info upatches "$bee" --all
} >"$stage/bpm-info.txt" 2>&1 || :
cat "$stage/bpm-info.txt"
rm -rf "$stage/shield"
mkdir -p "$stage/shield"
tar -xzf "$bee" -C "$stage/shield"
ls -l "$stage/shield/upatches"
echo "built $(basename "$bee") into $stage/shield"
