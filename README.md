# Shirudo shields

Taste's shields for [Shirudo](https://github.com/shirudo-dev/shirudo):
signed BPF packages that protect a running application from one
vulnerability, or one class of them, until the real fix is deployed. A
shield does not patch the application; its README says which release
does.

One Shirudo package per shield, each in its own directory:

| Shield | Protects against | CI |
|--------|------------------|----|
| [`shields/nginx2shell`](shields/nginx2shell) | Nginx2Shell, CVE-2026-123007, nginx before 1.31.9 / 1.30.7 | [`nginx2shell.yml`](.github/workflows/nginx2shell.yml) |

## Layout

```
shields/<shield>/        one Shirudo package (Beefile at its root)
  Beefile, README.md     what `shirudo bpm build` packs and `bpm info` shows
  *.bpf.c, policy files  the upatches and what generates their settings
  test/                  scenarios run on a real Shirudo target
  demo/                  a standalone demo: the application, how to run it
tools/
  ci/                    build Shirudo, its test VM and a shield; job summary
  cast/                  record a terminal run as an asciinema v2 .cast
  h2probe/               HTTP/2 conformance probe and client (stdlib Python)
.github/workflows/
  shield-ci.yml          reusable: prove one shield on a Shirudo target
  <shield>.yml           calls it for one shield
```

## How CI proves a shield

Each shield has a workflow that calls `shield-ci.yml`, which runs on a
GitHub-hosted `ubuntu-24.04` runner:

1. Checks out Shirudo at a pinned commit (`SHIRUDO_SHA`) beside this
   repository, downloads the test kernel Shirudo pins, and makes the
   runner a VM host with Shirudo's own `.github/scripts/tests.sh setup`
   (clang 23, OpenSSL 3.5, KVM, QEMU, swtpm), with Shirudo's caches.
2. Builds the operator binaries and the test VM bundle the way Shirudo's
   `make -C testing vm` does. The bundle generates a fresh key pair; the
   VM enrolls its certificate in a sealed keyring, so only packages
   signed in this run load there.
3. Builds the shield with `shirudo bpm build` into a `.bee`, signed with
   that key, and the demo's file system if the shield has one.
4. Boots a real Shirudo target: the dm-verity runtime image, a signed
   config, a software TPM, Shirudo enforcing.
5. Runs the shield's scenarios on the target over SSH, in order, under a
   terminal recorder. Each scenario prints `PASS:` and `FAIL:` lines.
   The first runs without the shield and must show the attack's effect,
   so a later block is a real block.
6. Fails the job on any `FAIL`, writes a table of the scenarios to the
   job summary, and uploads `<shield>-logs` (scenario log,
   `shirudo upatch map` output, the package, guest logs) and
   `<shield>-demo-cast` (the recording).

Actions are pinned by commit, images by digest, Shirudo by commit. No
secrets are needed or used.

## Add a shield

1. Make `shields/<shield>/` a Shirudo package: a `Beefile`, the BPF
   sources and a `README.md` that says what the shield refuses, what it
   costs, the kernels it is written for and which release really fixes
   the vulnerability. Shirudo's `Documentation/upatches/` and its
   `upatch` skill are the reference; keep the SPDX headers of anything
   adapted from Shirudo's `upatches/`.
2. Write `shields/<shield>/test/run-all.sh`, which runs on the target as
   root and runs the scenarios given as arguments, in order, printing
   `PASS: <scenario>: <check>` or `FAIL: <scenario>: <check>` per check
   and `SCENARIO <scenario> PASS|FAIL` per scenario, and `--narrate` for
   a line before each. It finds the unpacked package in `SHIELD_PKG_DIR`
   and writes results to `SHIELD_OUT`. Start with a baseline that shows
   the effect without the shield, and end with an unload that shows it
   again.
3. Optional hooks, all in the shield's directory:
   `demo/build.sh <archive>` builds a file system for the target (a
   target runs no Docker); `test/operator-hook.sh before|after <stage>`
   runs as root on the operator host around the package build;
   `test/prepare.sh <stage>` runs on the target before the scenarios.
4. Add `.github/workflows/<shield>.yml` calling `shield-ci.yml` with the
   shield's name and its scenarios; copy `nginx2shell.yml`.
5. Add a `demo/README.md` that says how to run the demo on any Linux
   host with Shirudo, with nothing else from this repository's CI.

Anything that simulates an attack says SIMULATED, in its output too, and
nothing here implements an exploit.

## Run the test VM yourself

On a Linux host with KVM, in a Shirudo checkout, Shirudo's
`Documentation/upatches/test/testing.rst` walks through booting the test
VM (`make -C testing vm VM_NAME=dev`), signing with the key it enrolled
and loading a upatch. `tools/ci/shirudo.sh` and
`tools/ci/build-shield.sh` are the same steps as CI runs them, and each
shield's `demo/README.md` has the commands for its own demo.
