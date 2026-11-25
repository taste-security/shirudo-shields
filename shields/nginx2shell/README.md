# nginx2shell-shield

The `nginx2shell-shield` package installs two upatches against
Nginx2Shell, CVE-2026-123007, a bug in nginx's HTTP/2 flow control:
when a client cancels a stream, nginx credits the data it had not sent
back to the send window without holding the window to the protocol
maximum of 2^31-1.

- `nginx2shell-h2guard` follows the HTTP/2 frames nginx reads through
  OpenSSL and ends the worker before it parses a frame that takes a
  send window past 2^31-1. That is the input the published exploit
  needs.
- `nginx2shell-contain` puts nginx in a sandbox: it executes nothing,
  connects only to the networks you name, and writes no `*.conf`,
  `*.html`, `*.js` or `*.so` file. That is what holds if the bug is
  reached some other way.

Neither patches nginx. The bug stays in the binary, and a way to it
that the guard does not see stays open, with the sandbox around what
follows. Upgrade nginx to 1.31.9 or 1.30.7, and keep the shield until
every node runs one of them.

Each upatch has a tree entry that names CVE-2026-123007 as `fixes`, so
that a backend that reads the tree counts a node that loaded it as
shielded.

## What each layer stops

| | Stops | Does not stop |
|---|---|---|
| `nginx2shell-h2guard` | A client that pushes a connection or stream send window past 2^31-1 with WINDOW_UPDATE, alone or after RST_STREAM on streams with unsent data, and a SETTINGS_INITIAL_WINDOW_SIZE past it or that takes an open stream past it. nginx never parses the frame. | HTTP/2 without TLS (h2c), nginx linked with another TLS library or with OpenSSL built in, a libssl at another path or of another build, another way to the bug than flow control, a connection that was open before the load. |
| `nginx2shell-contain` | A worker that runs attacker code starting a program (`/bin/sh` and every other file not labeled `nginx`), connecting to or sending to an address outside the networks named, opening a raw or packet socket, and creating, renaming, writing or truncating a `*.conf`, `*.html`, `*.js` or `*.so` file. | Code that stays inside the worker: reading what the worker can read (keys, configuration, other requests), answering requests, talking to the upstreams it may reach. A descriptor the worker already holds. |

## How the guard decides

The guard hooks the OpenSSL nginx uses: `SSL_read`, at its entry and
its return, sees the bytes nginx is about to parse; `SSL_write` and
`SSL_sendfile` count the DATA nginx sends; `SSL_free` forgets a
connection. It keys each connection by its `SSL *` and process, parses
the client preface and the frames from it on in both directions, with
frames that span reads or writes, and keeps:

- the connection's window as the client can have set it: 65,535, plus
  every connection WINDOW_UPDATE increment, less the DATA nginx handed
  OpenSSL;
- the window of up to 8 streams from the HEADERS that opened each:
  SETTINGS_INITIAL_WINDOW_SIZE, plus the stream's increments, less its
  DATA.

A client receives no more than nginx sent, so the window it sees is at
least the one the guard keeps: a client that keeps RFC 9113 6.9.1 never
takes the guard's window past 2^31-1, and nginx, which at most credits
back what it never sent, never has a larger one. The guard hits when:

| Reason | When |
|---|---|
| `conn_window_over_max` | a WINDOW_UPDATE on stream 0 takes the connection window past 2^31-1, which covers the cancel-and-credit loop |
| `stream_window_over_max` | a WINDOW_UPDATE takes a stream window past 2^31-1 |
| `settings_window_over_max` | SETTINGS_INITIAL_WINDOW_SIZE is past 2^31-1, or its change takes a stream window past it |

On a hit the guard sends SIGKILL to the worker from the return probe of
`SSL_read`. The signal is delivered before the worker runs another
instruction of its own, so nginx never parses the frame; the worker's
other connections end with it, and the master starts a new worker.
`H2GUARD_KILL 0` in `h2guard_config.h` makes the guard record hits
without acting.

Where it cannot follow a connection it stops checking that connection
and records why, and never guesses:

| Reason | When |
|---|---|
| `untracked_table_full` | 32,768 connections are tracked already |
| `untracked_desync` | nginx's output did not parse as HTTP/2, or a read of the buffer failed |
| `untracked_oversize` | one call handed more than 256 KiB, more than nginx does |

A connection whose first bytes are not the HTTP/2 client preface, such
as HTTP/1.1 over TLS, is not followed and not recorded.

## How the sandbox works

`nginx2shell-contain` is shirudo's `app-sandbox` upatch with a table of
what it refuses. The Beefile labels nginx's binaries with the `nginx`
policy bit, 0x100:

```toml
[[upatches.policy]]
id = "nginx"
bit = 0x100
paths = ["/usr/sbin/nginx", "/usr/local/nginx/sbin/nginx", "/usr/local/sbin/nginx"]
```

and `sandbox.toml` gives the rules of the tasks that execute one of
them, master and workers alike:

```toml
[networks]
upstreams = ["127.0.0.0/8", "10.0.0.0/8", "172.16.0.0/12", "192.168.0.0/16", "::1/128", "fc00::/7"]

[sandbox.nginx]
exec = []
network = ["@upstreams"]

[sandbox.nginx.deny]
create = ["*.conf", "*.html", "*.js", "*.so"]
rename = ["*.conf", "*.html", "*.js", "*.so"]
write = ["*.conf", "*.html", "*.js", "*.so"]
```

`app-sandbox`'s README describes every key. Link-local networks are
left out on purpose: 169.254.169.254 is the cloud metadata service.

What nginx does keeps working: the master forks its workers without an
exec, a reload (`SIGHUP`, `nginx -s reload`) reads the configuration and
forks new workers, a worker that dies is forked again, and nginx writes
its logs, pid file and temporary and cache files, none of which match a
pattern.

Every refusal is `EACCES`.

## Configure

| What | Where |
|---|---|
| The networks nginx may reach: proxy and FastCGI upstreams, the `resolver`, OCSP responders for `ssl_stapling`, syslog and mail servers | `upstreams` in `sandbox.toml` |
| The file name patterns nginx may not write | `[sandbox.nginx.deny]` in `sandbox.toml` |
| The paths of nginx's binaries | the `nginx` policy in `Beefile` |
| The libssl nginx loads | `H2GUARD_LIBSSL` in `h2guard_config.h` |
| The process name the guard follows, `nginx` | `H2GUARD_COMM` in `h2guard_config.h` |
| Kill or only record | `H2GUARD_KILL` in `h2guard_config.h` |

A change to `sandbox.toml` needs no compile: sign new rules into a
package already built, or pass them to a build.

```sh
shirudo bpm config update --base-package nginx2shell-shield-1.0.0.bee \
	--version 1.0.1 --rodata-input sandbox=<your-sandbox.toml> --keys-dir <keys>
shirudo bpm build shields/nginx2shell --version 1.0.1 --keys-dir <keys> \
	--rodata-input sandbox=<your-sandbox.toml>
```

A change to `h2guard_config.h` is a rebuild. The libssl at
`H2GUARD_LIBSSL` on the operator host must be the very file the targets
run: the build records its GNU build ID, and a target with another file
there fails the load with `binary_mismatch`. `BUILD.md` gives the
commands.

## What a load does

`nginx2shell-contain` labels each path of the `nginx` policy that
exists on the target. A task enters the sandbox at its next `execve()`
of a labeled file, so restart nginx after the first load.

`nginx2shell-h2guard` attaches to the libssl at `H2GUARD_LIBSSL`. It
follows the connections nginx opens after the load; restart nginx, or
let old connections end, to have every connection followed.

An unload of either leaves nginx running as it is, without the layer.

## Read the telemetry

```sh
shirudo upatch map nginx2shell-h2guard h2_events --json --peek
shirudo upatch map nginx2shell-contain refused --json --peek
```

Without `--peek` a read drains the table, as `shirudo-map-export.timer`
does every few seconds. Each `h2_events` record holds the reason, the
process (`tgid`, `pid`, `comm`), the connection (`conn`, its `SSL *`),
the stream, the window the frame would have made, the increment, the
number of RST_STREAM frames the connection had sent, the action
(`killed`, `kill_failed`, `recorded`) and how often it happened. Each
`refused` record holds the kind (`exec`, `connect`, `sendmsg`,
`socket`, `create`, `rename`, `write`, `truncate`), the process, the
file name or the peer address and port, and the count.

## How it is tested

CI (`.github/workflows/nginx2shell.yml`) builds this package, boots
Shirudo's test VM and runs nginx 1.31.8 (vulnerable range) and 1.31.9
(fixed) on it, both with HTTP/2, TLS and embedded Perl. The scenarios in
`test/` run in order and fail the job on any check that fails:

1. `baseline`: no shield. A SIMULATED post-exploit step, served by
   nginx's embedded Perl, makes a real 1.31.8 worker run `/bin/sh`,
   connect out and drop a `.html` and a `.txt` file; all of it works.
2. `load`: both upatches load, and the nginx binaries carry the label.
3. `contain`: the kernel refuses the shell, the connection and the
   `.html` drop; the `.txt` drop no rule denies still works.
4. `legit`: ordinary HTTP/2 (parallel requests, an 8 MiB download,
   interleaved streams cancelled with data in flight) is all served,
   with no guard hit and no worker killed.
5. `h2guard`: the over-limit flow-control pattern, sent to fixed 1.31.9
   only, is cut before nginx answers.
6. `regression`: the edges a change could break unnoticed. A window at
   exactly 2^31-1 is served and one past it is cut; five attacks in a
   row are each cut while the master survives and a fresh worker
   serves; workers forked by an nginx reload stay contained and
   guarded; HTTP/1.1 and HTTP/2 work afterwards with no hit.
7. `unload`: the SIMULATED step works again, so every refusal before
   was the shield's.

No step runs an exploit. The over-limit pattern is the RFC 9113 section
6.9.1 conformance input, and `tools/h2probe` sends it only to a server
whose `Server` header names nginx 1.31.9 or later.

## Limits

- The guard is on the TLS path of one libssl file. HTTP/2 without TLS,
  nginx with BoringSSL, LibreSSL, AWS-LC or a statically linked OpenSSL,
  and a libssl the distribution upgraded (a new file, a new build ID)
  are not guarded. Rebuild against the new libssl when it changes.
- `ssl_early_data on` lets nginx write before the handshake ends
  through a call the guard does not hook; keep it off, the default.
- An attacker who can reach the guard can make it kill workers, and
  each kill ends the other connections of that worker. That is a denial
  of service the patched nginx does not have; set `H2GUARD_KILL 0` where
  it costs more than the exposure.
- The guard checks at most 8 streams per connection at a time; a stream
  that loses its slot is not checked, and the connection window, which
  the CVE concerns, always is.
- The kernel does not run a return probe for a thread that already
  waits on 64 of them; nginx never comes near that.
- A binary upgrade (`SIGUSR2`) executes the new nginx binary from the
  master. A new file installed after the load carries no label, and the
  sandbox refuses to execute it: load the upatch again after the
  package upgrade, then upgrade the binary. The same holds for any file
  a path or pattern names.
- The file rules name files, not their contents, the network rules
  cover IPv4 and IPv6 `connect()`, `sendmsg()` and `sendto()`, and root
  outside the sandbox is not held by it. `app-sandbox`'s README gives
  the full list.

## Kernels and cost

Both upatches are written for preemptible RCU, which makes them right
on every preemption model. The sandbox reads only its rules and the
task's policy bits. The guard's per-connection state is written only by
the thread that drives the connection's `SSL *`, which OpenSSL requires
to be one at a time, and the event tables are the arena tables of
shirudo's `kernel-obs`, whose inserts are atomic.

The sandbox costs what `app-sandbox` costs: a task outside it pays one
task-storage lookup at each of its LSM hooks, a task inside a scan of
at most 128 networks or 64 patterns. A refusal adds one insert into the
`refused` table.

The guard costs a uprobe and a uretprobe on every `SSL_read`,
`SSL_write` and `SSL_sendfile` of every process that maps the libssl,
whether it is nginx or not: two traps into the kernel per call, a few
microseconds. A call by a task not named `nginx` stops after a name
compare at the entry and a map lookup at the return. For nginx, the guard reads the 9-byte header of every frame
and the payload of WINDOW_UPDATE and SETTINGS frames, and skips the
rest; it keeps about 300 bytes per HTTP/2 connection. Measure it on
your traffic with `sysctl kernel.bpf_stats_enabled=1` and
`bpftool prog show` before rolling it out widely.
