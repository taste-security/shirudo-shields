# Build nginx2shell-shield

Shirudo at `9e6bde6749a96526a9cc028b72ba3ce1b21f4f5c`, on Linux, with
clang 23 (`.github/scripts/install-clang.sh` of the Shirudo tree) and
Python 3.11 or newer for `gen_policy.py`.

## 1. Shirudo's operator tools

```sh
git clone https://github.com/shirudo-dev/shirudo && cd shirudo
git checkout 9e6bde6749a96526a9cc028b72ba3ce1b21f4f5c
make && make shirudo-build
export SHIRUDO_BUILD="$PWD/tools/shirudo-build/shirudo-build"
export SHIRUDO_CLANG_PATH=/usr/lib/llvm-23/bin/clang   # when not /usr/bin/clang
SHIRUDO_SRC="$PWD"
```

`vmlinux.h` comes from the kernel the targets run: `bpftool btf dump
file /sys/kernel/btf/vmlinux format c > vmlinux.h` on the test VM, or
the one Shirudo's CI generates into `vendor/linux/`.

## 2. The libssl the guard attaches to

The builder resolves `SSL_read`, `SSL_write`, `SSL_sendfile` and
`SSL_free` in the file `H2GUARD_LIBSSL` names (`h2guard_config.h`,
default `/usr/lib/libssl.so.3`) on the build host, and records its GNU
build ID. Put the exact file nginx loads on the targets there, from the
demo image:

```sh
cid=$(docker create nginx:1.31.8-alpine-perl)
docker cp -L "$cid:/usr/lib/libssl.so.3" ./libssl.so.3
docker rm "$cid"
readelf -n ./libssl.so.3 | grep 'Build ID'     # the build refuses a file without one
sudo install -m 0644 ./libssl.so.3 /usr/lib/libssl.so.3
```

On the target, the same file must be at the same path in the mount
namespace `shirudo upatch load` runs in, and nginx must map that inode:
run nginx from an unpacked image root with that root's
`usr/lib/libssl.so.3` hard-linked to `/usr/lib/libssl.so.3`, or set
`H2GUARD_LIBSSL` to the path of the file inside the unpacked root.

## 3. Build the package

From the Shirudo checkout, so that the builder finds `vendor/` (libbpf
headers) and `vmlinux.h`, or link them into the package directory:

```sh
ln -s "$SHIRUDO_SRC/vendor" shields/nginx2shell/vendor    # if building elsewhere

"$SHIRUDO_SRC/shirudo" genkey --keys-dir keys             # once
"$SHIRUDO_SRC/shirudo" bpm build shields/nginx2shell --version 1.0.0 --keys-dir keys \
	--vmlinux vmlinux.h
"$SHIRUDO_SRC/shirudo" bpm info nginx2shell-shield-1.0.0.bee
"$SHIRUDO_SRC/shirudo" bpm info upatches nginx2shell-shield-1.0.0.bee --all
"$SHIRUDO_SRC/shirudo" bpm info data nginx2shell-shield-1.0.0.bee upatches/nginx2shell-contain.upatch
```

`upatch info` on each member lists its decoder
(`nginx2shell-contain/refused`, `nginx2shell-h2guard/h2_events`) and,
for the guard, the uprobe targets.

One upatch alone, to read the compiler and verifier output:

```sh
cd shields/nginx2shell
"$SHIRUDO_SRC/shirudo" build nginx2shell-h2guard.bpf.c --keys-dir ../../keys \
	-o nginx2shell-h2guard.upatch --emit-artifacts
"$SHIRUDO_SRC/shirudo" upatch info nginx2shell-h2guard.upatch
```

`nginx2shell-contain` takes its `sandbox_policy` from `gen_policy.py`,
which only `bpm build` runs; build it through the package.

## 4. Load on the test VM

`bpm install` takes a package from a registered repository; on the test
VM, load the signed members of the package directly:

```sh
tar xzf nginx2shell-shield-1.0.0.bee
cd nginx2shell-shield-1.0.0/upatches
shirudo-runtime upatch load nginx2shell-contain.upatch
shirudo-runtime upatch load nginx2shell-h2guard.upatch
shirudo-runtime upatch map nginx2shell-h2guard h2_events --json --peek
shirudo-runtime upatch map nginx2shell-contain refused --json --peek
shirudo-runtime upatch unload nginx2shell-h2guard.unload.upatch
shirudo-runtime upatch unload nginx2shell-contain.unload.upatch
```

Restart nginx after the load: the sandbox applies from its next
`execve()` of `/usr/sbin/nginx`, the guard to connections opened after
the load. A missing libssl fails the guard's load with
`attach_target_missing` (exit status 2), another build of it with
`binary_mismatch`.

## 5. Publish

```sh
shirudo bpm push nginx2shell-shield-1.0.0.bee oci://<registry>/<namespace>/nginx2shell-shield --keys-dir keys [--new-index]
shirudo bpm tree append nginx2shell-shield-1.0.0.bee oci://<registry>/<tree> --keys-dir keys
```
