# nginx2shell demo

A standalone demo of the Shirudo `nginx2shell-shield` package against
Nginx2Shell (CVE-2026-123007), on any Linux host that runs Shirudo as a
target. It shows, in six short steps, what the shield does and what it
leaves alone:

1. **Without the shield**, a SIMULATED post-exploit step makes a real
   nginx worker run `/bin/sh -c id` and connect out to `192.0.2.1:4444`.
   Both work.
2. **Load the shield.**
3. **The same SIMULATED step** is refused by the kernel: no shell, no
   connection out. nginx keeps serving.
4. **Normal HTTP/2 traffic** (single and parallel requests, an 8 MiB
   download, cancelled downloads) is served in full, nothing cut.
5. **The over-limit flow-control pattern**, sent only to the fixed nginx
   1.31.9, is cut by the guard before nginx answers, and the hit is in
   the shield's map.
6. **Unload the shield**: the SIMULATED step works again.

The shield does not patch nginx. Upgrade to nginx 1.31.9 or 1.30.7.

## What is simulated, and what is not

Nothing here exploits CVE-2026-123007, and nothing here can. The
"attack" is `/__simulated_rce`, a handler in nginx's embedded Perl
(`perl/SimulatedRce.pm`): nginx itself runs it in a worker, so the
worker does what code an attacker got into it would try first. Every
response, log line and narration labels it SIMULATED. `192.0.2.1` is
TEST-NET-1, reserved for documentation; nothing listens there.

The over-limit pattern is the RFC 9113 section 6.9.1 conformance check
that test suites such as h2spec send: two `WINDOW_UPDATE` frames that
push a send window past 2^31-1, plain and after a cancelled stream.
Fixed nginx answers it with `GOAWAY(FLOW_CONTROL_ERROR)`. `tools/h2probe`
sends it only when the server's own `Server` header names nginx 1.31.9
or later. Never point it at nginx 1.31.8.

## The pieces

| File | What it is |
|------|------------|
| `Dockerfile` | nginx 1.31.8 (`/usr/sbin/nginx`, port 8443) and 1.31.9 (`/usr/local/sbin/nginx`, port 9443) from the official `alpine-perl` images, pinned by digest, HTTP/2, TLS, embedded Perl, dynamic OpenSSL at `/usr/lib/libssl.so.3` |
| `nginx/`, `perl/`, `html/` | the two configurations, the SIMULATED handler, a page |
| `build.sh <archive>` | builds the image and exports its file system as a tar |
| `nginx2shell-demo.sh` | on the target: unpacks the tar into a chroot, hard-links the two nginx binaries and libssl to the paths the shield names, starts and stops both instances |
| `../test/run-all.sh` | the six steps above, as scenarios printing `PASS:` and `FAIL:` lines; `--narrate` adds the step titles |

A Shirudo target runs no Docker: Shirudo allows only signed BPF, and a
container runtime loads its own. So the image is only the way the file
system is built; on the target nginx runs in a chroot, as Shirudo's own
`upatches/app-sandbox/demo` runs Apache. The hard links matter: a policy
label set on `/usr/sbin/nginx` is on the inode the chroot executes, and
a uprobe on `/usr/lib/libssl.so.3` fires in the libssl the chroot's
nginx maps.

## Run it on a Shirudo host

You need:

- a Linux target running Shirudo (`shirudo status` reads `ok`), with
  `curl` (with HTTP/2) and `python3`, and root on it. The h2guard
  upatch is built for x86-64 unless `h2guard_config.h` names another
  architecture;
- an operator host with the key pair the target trusts, `shirudo`,
  `shirudo-build` and clang 23 (see Shirudo's
  `Documentation/start/quickstart.rst`), Docker and this repository.

On a glibc distribution the target's own libssl lives under
`/usr/lib/<triplet>/`, so `/usr/lib/libssl.so.3` is free for the
demo's. `nginx2shell-demo.sh install` refuses to replace a file already
there; if your target uses that path, change `H2GUARD_LIBSSL` in
`shields/nginx2shell/h2guard_config.h` and pass the same path as
`N2S_LIBSSL` to every command below.

### 1. Build the file system (operator host)

```sh
shields/nginx2shell/demo/build.sh nginx2shell-rootfs.tar
# for an arm64 target from an x86-64 host:
DOCKER_PLATFORM=linux/arm64 shields/nginx2shell/demo/build.sh nginx2shell-rootfs.tar
```

### 2. Build the shield package (operator host)

The h2guard upatch probes the demo's libssl, and `shirudo bpm build`
reads that same path on the operator host to find the probed functions
and record the file's build ID, which the target checks at load. Put the
image's libssl there for the build, then put things back:

```sh
mkdir -p stage && cp nginx2shell-rootfs.tar stage/rootfs.tar
sudo sh shields/nginx2shell/test/operator-hook.sh before stage

mkdir -p /tmp/n2s/nginx2shell
(cd shields/nginx2shell && tar -cf - --exclude=./test --exclude=./demo .) |
	tar -xf - -C /tmp/n2s/nginx2shell
# From a Shirudo checkout, link its headers in; an installed operator
# package needs no links.
ln -s "$SHIRUDO/vendor" "$SHIRUDO/bpf" /tmp/n2s/nginx2shell/
(cd /tmp/n2s && shirudo bpm build nginx2shell --version 1.0.0 --keys-dir "$KEYS")

sudo sh shields/nginx2shell/test/operator-hook.sh after stage
```

This writes `/tmp/n2s/nginx2shell-shield-1.0.0.bee`. You can also
publish it and `shirudo bpm install` it on the target; the demo loads
the upatches inside it directly, which is the same load.

### 3. Copy to the target and install

Copy `nginx2shell-rootfs.tar`, the `.bee` and this repository to the
target, then as root there:

```sh
mkdir -p shield && tar -xzf nginx2shell-shield-1.0.0.bee -C shield
sh shields/nginx2shell/demo/nginx2shell-demo.sh install nginx2shell-rootfs.tar
```

Install before loading the shield: a file that appears after a load is
not labeled until the next load.

### 4. Run the demo

```sh
N2S_SHIELD_DIR=$PWD/shield sh shields/nginx2shell/test/run-all.sh --narrate
```

It starts both nginx instances, runs the six steps and prints a
summary; it exits 1 if any check failed. To record it as an asciinema
v2 file:

```sh
tools/cast/record nginx2shell.cast "nginx2shell" \
	"N2S_SHIELD_DIR=$PWD/shield sh shields/nginx2shell/test/run-all.sh --narrate"
asciinema play nginx2shell.cast
```

The run stops `shirudo-map-export.timer` while it runs, so that the
maps it reads before and after a step are not drained in between, and
starts it again at the end. Results and a dump of `shirudo upatch map`
land in `/var/tmp/nginx2shell-test` (`N2S_OUT`).

### 5. Clean up

```sh
sh shields/nginx2shell/demo/nginx2shell-demo.sh remove
```

This stops nginx and removes the chroot and the three hard links,
labels and all.

## Without Shirudo: the image alone

To see the vulnerable and the fixed nginx, the SIMULATED step and the
probe's behavior on any machine with Docker:

```sh
docker build -t nginx2shell-demo shields/nginx2shell/demo
docker run -d --name n2s -p 127.0.0.1:8443:8443 -p 127.0.0.1:9443:9443 nginx2shell-demo
curl -sk --http2 https://127.0.0.1:8443/__simulated_rce
tools/h2probe/h2probe https://127.0.0.1:8443   # refused: nginx/1.31.8
tools/h2probe/h2probe https://127.0.0.1:9443   # GOAWAY FLOW_CONTROL_ERROR
tools/h2probe/h2client --big-size 8388608 https://127.0.0.1:8443
docker rm -f n2s
```

That is step 1 and the baseline of step 5: without the shield nothing
is refused.
