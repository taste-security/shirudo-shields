#!/bin/sh
# SPDX-License-Identifier: BSD-2-Clause
#
# usage: shirudo.sh build
#        shirudo.sh boot <vm>
#        shirudo.sh ssh <vm> <command>
#        shirudo.sh stop <vm>
#        shirudo.sh sudo <command>...
#
# Drives a Shirudo checkout (SHIRUDO_DIR) the way Shirudo's own CI does in
# .github/scripts/tests.sh, after `tests.sh setup` made the runner a VM
# host: the build environment of build/vm-toolchain.env, the BTF of the
# staged test kernel, an unlimited memlock, and make as root.
#
#   build  the operator binaries (shirudo, shirudo-build) on the host and
#          the test VM bundle, whose fresh key pair the VM enrolls; the
#          keys land in $SHIRUDO_PRIVATE_DIR/operator-keys/keys
#   boot   an interactive test VM (make -C testing vm), which returns once
#          the target is prepared and keeps running
#   ssh    one command in the VM, as root (make -C testing vm-ssh)
#   stop   the VM
#   sudo   a command as root with the build environment
#
# SHIRUDO_DIR defaults to ./_shirudo, SHIRUDO_PRIVATE_DIR to
# $RUNNER_TEMP/shirudo-private (outside the checkout, as Shirudo needs).

set -eu

SHIRUDO_DIR=$(cd "${SHIRUDO_DIR:-_shirudo}" && pwd)
SHIRUDO_PRIVATE_DIR=${SHIRUDO_PRIVATE_DIR:-${RUNNER_TEMP:-/tmp}/shirudo-private}
cd "$SHIRUDO_DIR"

# shellcheck source=/dev/null
. build/vm-toolchain.env
BPF_VMLINUX_BTF=$SHIRUDO_DIR/artifacts/bpf-next-kernel-debs/vmlinux.btf
SHIRUDO_BUILD=$SHIRUDO_DIR/tools/shirudo-build/shirudo-build
export BPF_VMLINUX_BTF SHIRUDO_BUILD
sudo prlimit --pid "$$" --memlock=unlimited:unlimited

# sudo drops LD_LIBRARY_PATH and resets PATH; the OpenSSL 3.5 build of
# vm-toolchain.sh needs both, as tests.sh says.
as_root()
{
	sudo -E env PATH="$PATH" LD_LIBRARY_PATH="$LD_LIBRARY_PATH" \
		BPF_VMLINUX_BTF="$BPF_VMLINUX_BTF" SHIRUDO_BUILD="$SHIRUDO_BUILD" "$@"
}

vm_make()
{
	as_root make -C testing TEST_VM_HOST_PRIVATE_DIR="$SHIRUDO_PRIVATE_DIR" "$@"
}

case ${1:-} in
build)
	as_root make -j"$(nproc)"
	as_root make shirudo-build
	vm_make test-vm-bundle
	as_root test -s "$SHIRUDO_PRIVATE_DIR/operator-keys/keys/cert.der"
	;;
boot)
	[ $# -eq 2 ] || exit 2
	vm_make vm VM_NAME="$2"
	;;
ssh)
	[ $# -eq 3 ] || exit 2
	vm_make -s vm-ssh VM_NAME="$2" VM_SSH_COMMAND="$3"
	;;
stop)
	[ $# -eq 2 ] || exit 2
	vm_make vm-stop VM_NAME="$2"
	;;
sudo)
	shift
	as_root "$@"
	;;
*)
	sed -n 's/^# \{0,1\}//; 3,7p' "$0" >&2
	exit 2
	;;
esac
