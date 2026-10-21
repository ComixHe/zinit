# zinit

[![Coverage Status](https://img.shields.io/codecov/c/github/ComixHe/zinit?style=flat-square&logo=codecov)](https://codecov.io/gh/ComixHe/zinit)

A tiny init for Linux containers: it forwards signals (to the child, or its
group with `-g`), reaps orphans, rewrites signals and exit codes (`-r`, `-e`),
handles the terminal and job control, and drives a shutdown that cannot hang.
Static, libc-less Zig, no threads, no allocation.

## Requirements

- Zig, per `minimum_zig_version` in `build.zig.zon`
- Linux

| Feature | Minimum kernel |
| --- | --- |
| Forwarding and reaping (`signalfd4`) | **2.6.27** |
| Shutdown grace (`clock_gettime`) | 2.6.16 |
| `-p` (`PR_SET_PDEATHSIG`) | 2.6.9 |
| `-s` (`PR_SET_CHILD_SUBREAPER`) | **3.4** |
| pidfd acceleration (`clone(CLONE_PIDFD)`) | 5.2 / 6.9 |

## Install

```bash
zig build -Doptimize=ReleaseSmall
```

| Prefer | How |
| --- | --- |
| `COPY --from` in your Dockerfile | `ghcr.io/comixhe/zinit:<version>` — a `scratch` image, amd64/arm64/riscv64, the bare tag is size-optimized, `-safe` keeps Zig's runtime checks |
| A file | release tarballs with `SHA256SUMS`, an SPDX SBOM and cosign bundles |
| Building | the checkout, as above |

## Usage

```bash
zinit --help
```

`--` is optional: the first non-option starts the command. Signals are numbers
(`15`) or names (`TERM`, `SIGTERM`). `-p` and `-r` take standard signals only, a
realtime signal *sent to zinit* is forwarded with its `sigqueue` value.

| Variable | Equivalent | Values |
| --- | --- | --- |
| `ZINIT_LOG_LEVEL` | `--log-level` | `error`, `warn`, `info`, `debug`, at most the build's ceiling |
| `ZINIT_SUBREAPER` | `-s` | presence |
| `ZINIT_SHUTDOWN_TIMEOUT` | `-t` | seconds |
| `ZINIT_TRACING_CHILD` | `-Dtracing-child` | `ON` / `OFF` |

### Logging

One line per event on stderr, colour only on a terminal, no timestamp of its own.

| Level | Prints |
| --- | --- |
| `error` | zinit cannot continue: usage, `clone`/`fork`/`signalfd`/`waitpid`/`execve` |
| `warn` | A setup did not take effect, or a boundary was hit: not a subreaper, terminal/job-control failure, grace exhausted (**default**) |
| `info` | The main child's exit, and every adopted descendant that died non-zero or by a signal |
| `debug` | How the child was created, each forward, the grace starting, `-e` remapping, clean adopted exits (quiet on purpose: a helper finishing is routine) |

`-Dlog-level` is the loudest level the binary can print (`info`),
`-Ddefault-log-level` is what it prints unasked (`warn`, clamped to the ceiling).
Asking at runtime for a level above the ceiling is an error, not a no-op — that
includes `ZINIT_LOG_LEVEL`, so a `ZINIT_LOG_LEVEL=debug` left over in an image
whose zinit was built with the default ceiling stops the container from starting
(`exit 1`) instead of quietly logging less. Build the binary with
`-Dlog-level=debug` or drop the variable.

## Exit Status

| Code | Meaning |
| --- | --- |
| `0` | Success, `--help`, `--version` |
| `1` | Usage or startup error |
| `126` / `127` | Child found but not executable / not found |
| otherwise | The child's code, or `128 + N` for signal `N`, `-e` maps a code to `0` |

## Setups

Nothing extra as PID 1. The rest are independent and combinable:

```bash
zinit -s -- /usr/bin/my-daemon             # subreaper: adopt orphans, outside
                                           # PID 1 they otherwise go to the real
                                           # init, and zinit warns
zinit -g -- /bin/sh -c "my-server & wait"  # forward to the child's group too,
                                           # for shells that do not pass them on
zinit -n -- /usr/bin/my-app                # new session: detach the tty,
                                           # TSTP/TTIN/TTOU become STOP
zinit -e 143 -e 130 -- java -jar app.jar   # exit codes that count as success
zinit -r TERM:INT -- /usr/bin/my-app       # rewrite a forwarded signal
zinit -r USR1:0 -- /usr/bin/my-app         # ... or drop it
zinit -p KILL -- /usr/bin/critical-service # signal the child if zinit dies
```

`-n` matters when running by hand, where job control addresses zinit, so add `-g`
when the workload is itself a shell. `-e` and `-r` are repeatable.

## Container Integration

### The runtime's `--init` hook

Docker and Podman inject an init without touching the image, the binary must be
static, which the releases are:

```bash
podman run --init --init-path ~/bin/zinit -it alpine sh
```

The runtime appends the workload as arguments, so no `--` is needed, and zinit
ends up as PID 1.

That `--init-path` is per invocation. To make zinit the runtime's init for every
container, configure the daemon instead: Podman takes `init = true` and
`init_path` in `containers.conf`, Docker takes `--init-path` on `dockerd`, or
`"init-path"` in `daemon.json` (`docker run` has only `--init`). Compose's
`init: true` then means zinit too — but a daemon-wide init-path applies to
*every* container on that daemon, so prefer the per-invocation flag or baking
zinit in.

### Baked into the image

```dockerfile
COPY --from=ghcr.io/comixhe/zinit:v0.2.1 /zinit /sbin/zinit
ENTRYPOINT ["/sbin/zinit", "--"]
CMD ["/bin/sh"]
```

Multi-arch: one Dockerfile covers amd64, arm64 and riscv64, with no
`ARG TARGETARCH` branching.

### Nix

```bash
nix build github:ComixHe/zinit
```

The flake installs the *released* artifact, not a rebuild: a fixed-output
derivation checked against `SHA256SUMS`, byte-for-byte the GitHub release. A hash
proves *what* was downloaded, not *who* published it, so see
[SECURITY.md](SECURITY.md) for that. Set
`inputs.zinit.inputs.nixpkgs.follows = "nixpkgs";` to avoid a second nixpkgs, and
use `#zinit-safe` for the safety-checked build:

```nix
dockerTools.buildImage {
  name = "my-app";
  copyToRoot = [ pkgs.zinit ];
  config.Entrypoint = [ "/bin/zinit" "--" ];
  config.Cmd = [ "/bin/my-agent" ];
}
```

### Kubernetes

There is no `--init-path`, so zinit has to be the entrypoint. **If you build the
image**, one line:

```dockerfile
FROM nginx:1.29
COPY --from=ghcr.io/comixhe/zinit:v0.2.1 /zinit /sbin/zinit
ENTRYPOINT ["/sbin/zinit", "--", "/docker-entrypoint.sh"]
```

**If you do not**, mount the artifact as an [image volume] and spell out
`command`/`args`, which replace the image's `ENTRYPOINT`/`CMD`:

```yaml
spec:
  terminationGracePeriodSeconds: 30
  containers:
    - name: app
      image: nginx:1.29
      command: ["/opt/zinit/zinit", "--", "/docker-entrypoint.sh"]
      args: ["nginx", "-g", "daemon off;"]
      volumeMounts: [{ name: zinit, mountPath: /opt/zinit, readOnly: true }]
  volumes:
    - name: zinit
      image: { reference: ghcr.io/comixhe/zinit:v0.2.1 }
```

- `-g` (or `-n`) when the workload is wrapped in a shell.
- `shareProcessNamespace: true` leaves the sandbox as PID 1, so add `-s`.
- `securityContext.runAsUser` covers both, pair it with `runAsNonRoot: true` —
  the check is against the container's own image, which runs as root by default,
  so `runAsUser` is what satisfies it. Add back the workload's capabilities.
- The image has no shell. Run a command in it through an ephemeral container
  (this prints PID 1's name, with `shareProcessNamespace` on, that is the
  sandbox, not zinit):

  ```bash
  kubectl debug -it <pod> --image=busybox --target=<container> -- cat /proc/1/comm
  ```

[image volume]: https://kubernetes.io/docs/tasks/configure-pod-container/image-volumes/

### Compose

`init: true` uses the runtime's init — zinit only once the runtime's default
init is zinit (see the hook above), otherwise that init, not zinit, is PID 1, so
a zinit below it needs `-s`. Bake zinit in, and size `stop_grace_period` above
`-t`.

### Grace period

On shutdown zinit sends TERM to the child's group, then KILL once `-t`
(`--shutdown-timeout`, default 5 s) elapses. The runtime's own stop timeout must
be **larger**, or the workload is killed before it can shut down:

| Runtime | Knob | Must be |
| --- | --- | --- |
| `docker/podman run` | `--stop-timeout` | ≥ `-t` |
| `docker/podman stop` | `-t/--time` | ≥ `-t` |
| Compose | `stop_grace_period` | ≥ `-t` |
| Kubernetes | `terminationGracePeriodSeconds` | ≥ `-t` |

### Unprivileged

zinit needs no capability of its own: it only signals and reaps processes of its
own uid, and re-parenting does not depend on uid. What matters is that **init and
workload share a uid**:

```yaml
securityContext: { runAsUser: 1000 }
```

The artifact sets no `USER` (that config would not survive `COPY --from`), so the
downstream image decides. Give the init `CAP_KILL` only when the workload must
run as another uid.

### Verify

```bash
cosign verify \
  --certificate-identity-regexp '^https://github.com/ComixHe/zinit/\.github/workflows/release\.yaml@refs/tags/' \
  --certificate-oidc-issuer https://token.actions.githubusercontent.com \
  ghcr.io/comixhe/zinit@sha256:<index-digest>
```

## Build Options

| Option | Description |
| --- | --- |
| `-Doptimize=ReleaseSmall` | Smallest binary, `ReleaseSafe` keeps runtime checks, `ReleaseFast` drops them |
| `-Dlog-level=<level>` | Loudest level the build can print (`info`), higher levels are compiled out |
| `-Ddefault-log-level=<level>` | Level printed unasked (`warn`), clamped to the ceiling |
| `-Dpie=true` | Static PIE, for ASLR on the binary, off by default, non-PIE is ~1.6 kB smaller |
| `-Dstack-traces=true` | Crash stack traces |
| `-Dtracing-child=true` | Child waits for SIGUSR1 before `exec` |
| `-Dtest-coverage=true` | Build tests for kcov into `kcov-output/` |
| `-Dsize-analysis=true` | Keep symbols in release builds, for `bloaty`/`nm` |

## How It Works

- **Signals.** Everything forwarded is blocked and read from a `signalfd`, fault
  signals keep their terminating default and TTIN/TTOU are ignored. Nothing installs
  a handler for a forwarded signal, so no `EINTR` and no async-signal-safety rules;
  the `-Dtracing-child` handshake waits on the blocked SIGUSR1 with `sigwaitinfo`
  instead of a handler.
- **Spawn.** `clone(CLONE_PIDFD)` where available (`fork` otherwise), the child
  leads its own group (and session with `-n`), and becomes the foreground group
  on a TTY. It keeps the parent's mask through all of that: the mask is cleared
  once, immediately before `execve`, so a forwarded signal waits in the queue
  instead of killing a child that is halfway through its own setup.
- **Loop.** `poll` the descriptor, forward each signal, then `waitpid(-1,
  WNOHANG)` until no reapable child is left. Only the signal read is bounded, so
  a signal flood cannot starve the reaper.
- **Job control.** A TSTP/TTIN/TTOU that ends up suspending the child suspends
  zinit with it, so a shell sees the job stopped rather than a running init
  whose child is not running; SIGCONT resumes both.
- **Shutdown.** TERM to the group, KILL when `-t` elapses, one non-blocking
  sweep, exit — an unkillable descendant cannot hang it.

## Limitations

Deliberate, the alternative costs more than it buys here.

- **A descendant that leaves the group is out of reach** (`setpgid`/`setsid`),
  only a cgroup or a PID namespace follows it, and zinit uses neither.
- **Signalling races what cannot be seen**: a group is signalled only while the
  kernel can prove it is ours (`waitid(P_PGID)`), and the fallback targets a
  number rather than a pidfd — a live child leaving the group between the check
  and the signal, with its id reused in that same microsecond, is missed.
- **zinit stops when the child does**: the job-control signals above stop the
  init itself, so with no shell left to send SIGCONT (a stop sent straight to a
  container's PID 1) the container stays stopped until something external
  resumes it. The stop is sent after the forward, so a child that exits in that
  instant leaves zinit stopped with nothing to wait for.
- **`-g` follows the child's group, not the one it was born into**: a workload
  that moves itself into another group has that group signalled, because that
  is where the kernel resolves the pidfd at the moment of the send.
- **The grace period is an upper bound**: a descendant that ignores SIGKILL, or
  escaped the group, outlives it.
- **If zinit dies, nothing is cleaned up here**, a PID namespace tears the rest
  down, without one, pass `-s`, or orphans are never re-parented.
- **Realtime payloads travel only on the pidfd path**, through `kill` the child
  gets a plain `SI_USER`. The sender it sees is zinit either way, because the
  original pid may mean nothing in a child namespace.
- **SIGCHLD is forced to its default** and handed back to the child on exec, an
  inherited `SIG_IGN` would let the kernel reap the status away.
- **Only the signalfd is close-on-exec**, other inherited descriptors pass
  through.
- **Logging is synchronous**: one `write` per line, no queue, so a stalled sink
  slows the loop with it.

## Development

```bash
zig build                              # debug build
zig build test                         # unit tests
zig build smoke                        # end-to-end checks against the built binary
zig build test -Dtest-coverage=true    # kcov into kcov-output/
zig build run -- /bin/bash
```

Tests sit at the bottom of each file under a `kcov-exclude-tests` marker, so
coverage describes the shipped code.

**Tracing the child.** With `-Dtracing-child=true` the child waits for SIGUSR1
before `exec`, so a debugger can attach and set breakpoints first:

```bash
zig build -Dtracing-child=true -Doptimize=ReleaseSafe
ZINIT_TRACING_CHILD=ON strace -f -p "$(pgrep zinit)"
kill -USR1 <child-pid>
```

## License

MIT. See [LICENSE](LICENSE).
