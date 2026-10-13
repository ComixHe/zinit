# zinit

[![Coverage Status](https://img.shields.io/codecov/c/github/ComixHe/zinit?style=flat-square&logo=codecov)](https://codecov.io/gh/ComixHe/zinit)

A tiny init process written in Zig for Linux containers, designed for signal
forwarding, orphan process collection, and safer PID 1 shutdown behavior.

## Features

- **Signal Forwarding**: Forward signals from parent process to child processes
- **Orphan Process Collection**: Reaps orphaned descendants — automatically as
  PID 1, or with `-s`/`ZINIT_SUBREAPER` otherwise
- **Parent Death Signal**: Configurable signal when parent process dies
- **Signal Rewriting**: Remap incoming signals before forwarding them
- **Exit Code Mapping**: Translate known child exit codes to success when needed
- **Terminal Control**: Properly handles terminal process groups for
  interactive applications
- **Debug Support**: Optional tracing mode for debugging child processes

## Requirements

- Zig compiler (see `minimum_zig_version` in `build.zig.zon`)
- Linux, statically linked, no libc

The kernel version needed depends on which features are used:

| Used | Minimum kernel | Syscalls / mechanism |
| ------ | ---------------- | ---------------------- |
| Always (signal forwarding, reaping) | **2.6.27** | `signalfd4`, `poll`, `fork`, `execve`, `wait4`, `kill`, `rt_sig*`, `ioctl` (termios/TTY), `setpgid` |
| Shutdown grace period | 2.6.16 | `clock_gettime` (only when the main child exits while descendants remain) |
| `-p` | 2.6.9 | `prctl(PR_SET_PDEATHSIG)` |
| `-s` / `ZINIT_SUBREAPER` | **3.4** | `prctl(PR_SET_CHILD_SUBREAPER)` |
| Automatic acceleration | 5.3 / 6.9 | `pidfd_open` (5.3) and `pidfd_send_signal` with the process-group flag (6.9) |

So a plain run as PID 1 (no `-s`) needs **Linux 2.6.27+**. Subreaper mode raises
that to **3.4+**.

## Installation

```bash
git clone <repo_url> && cd zinit
zig build -Doptimize=ReleaseSmall
```

The binary will be installed to `zig-out/bin/zinit`.

## Usage

see

``` bash
zinit --help
```

`--` is optional: the first non-option begins the command. Signals are given by
number (`15`) or name (`TERM`, `SIGTERM`).

Realtime signals are not accepted.

### Environment Variables

Because a container image usually fixes the entrypoint and arguments, the most
commonly tuned options can also be set through the environment variables.

| Variable | Equivalent | Values |
| ---------- | ----------- | -------- |
| `ZINIT_LOG_LEVEL` | `--log-level` | `error`, `warn`, `info`, `debug` |
| `ZINIT_SUBREAPER` | `-s` | presence-based (any value enables) |
| `ZINIT_SHUTDOWN_TIMEOUT` | `-t` | seconds |
| `ZINIT_TRACING_CHILD` | `-Dtracing-child` | `ON` / `OFF` |

## Exit Status

| Code | Meaning |
| ------ | --------- |
| `0` | Success, or an explicit `--help` / `--version` |
| `1` | Usage or startup error (unknown option, invalid `-r`/`-e`/`-t`, syscall failure) |
| `126` | Child found but not executable |
| `127` | Child not found (`execve` failed with `ENOENT`) |
| otherwise | The child's exit code, or `128 + N` if the child was killed by signal `N`. `-e <CODE>` maps that code to `0`. |

## Best Practices

### Run as PID 1 in Containers

When `zinit` runs as PID 1, the kernel re-parents orphaned descendants to it, so
they are reaped without any extra flag. This is the recommended usage:

```bash
# Dockerfile
COPY zinit /sbin/zinit
ENTRYPOINT ["/sbin/zinit", "--", "/bin/sh", "-c", "exec my-app"]
```

### Use `--subreaper` Outside PID 1

Subreaper mode is explicit. When running `zinit` outside of PID 1 (e.g. as a
supervisor process), pass `-s`/`--subreaper`. Otherwise orphans are re-parented
to the real init, not to zinit (zinit prints a warning in that case):

```bash
zinit -s -- /usr/bin/my-daemon
```

### Forward to the Process Group

The child is always placed in its own process group, which `zinit` uses to
terminate the whole tree on shutdown. By default a received signal is forwarded
only to the direct child. Use `-g`/`--forward-group` to forward it to the whole
process group instead — useful when a shell script does not signal its children:

```bash
zinit -g -- /bin/sh -c "my-server & wait"
```

### Use New Session

`--new-session` creates a new session and detaches from the controlling
terminal.
It also automatically rewrites job control signals (TSTP, TTOU, TTIN) to STOP to
avoid issues when running in background process groups. Combine it with `-g` if
you also want incoming signals forwarded to the whole process group:

```bash
zinit --new-session -g -- /bin/sh -c "stress-ng --cpu 4"
```

### Handle Application-Specific Exit Codes

Some applications exit with specific codes that should be treated as success:

```bash
# Java applications often exit with 143 (128 + SIGTERM)
zinit -e 143 -- java -jar app.jar

# `-e` is repeatable, so several codes can be remapped to success
zinit -e 143 -e 130 -- java -jar app.jar
```

### Rewrite Signals for Legacy Applications

Some applications expect different signals than what the container runtime
sends:

```bash
# Convert SIGTERM to SIGINT for graceful shutdown
zinit -r TERM:INT -- /bin/sh -c "trap 'exit 0' INT; sleep infinity"

# `-r` is repeatable: one OLD:NEW pair per flag
zinit -r TERM:INT -r HUP:USR1 -- /usr/bin/my-app

# Drop a signal entirely by rewriting it to 0
zinit -r USR1:0 -- /usr/bin/my-app
```

### Set Parent Death Signal

Ensure the child process receives a signal when `zinit` itself dies
unexpectedly:

```bash
zinit -p KILL -- /usr/bin/critical-service
```

## Examples

### Basic Container Init

```bash
#!/sbin/zinit -- /bin/sh
export APP_ENV=production
exec /usr/bin/my-application
```

### Multi-Process Container

```bash
zinit --new-session -- /bin/sh -c '
  nginx &
  php-fpm &
  wait
'
```

### Debug Mode

```bash
# Build with tracing support
zig build -Dtracing-child=true -Doptimize=ReleaseSafe

# Run with strace
ZINIT_TRACING_CHILD=ON strace -f -p $(pgrep zinit)
# Send SIGUSR1 to let child continue
kill -USR1 <child_pid>
```

## Configuration

### Build Options

| Option | Description |
| -------- | ------------- |
| `-Doptimize=ReleaseSmall` | Smallest binary, optimized for size |
| `-Doptimize=ReleaseSafe` | Optimized, with runtime safety checks |
| `-Doptimize=ReleaseFast` | Optimized, without runtime safety checks |
| `-Dstack-traces=true` | Include crash stack traces, **Off by default** |
| `-Dtracing-child=true` | Child waits for SIGUSR1 before exec (for debugging) |
| `-Dtest-coverage=true` | Build the tests for kcov and write `kcov-output/` |
| `-Dsize-analysis=true` | Keep symbols in release builds, for `bloaty`/`nm` |

## How It Works

1. **Signal Setup**: Blocks the signals it forwards and reads them through a
   signalfd; fault signals keep their terminating default, and TTIN/TTOU are
   ignored rather than left pending for the child
2. **Subreaper Mode**: Optional (`-s`/`--subreaper`). As PID 1 the kernel
   already re-parents orphaned descendants to us
3. **Isolate**: The child is placed in its own process group (and made the
   foreground group when attached to a TTY). `--new-session` additionally
   creates a new session
4. **Terminal Setup**: Acquires/forwards the controlling terminal for
   interactive applications
5. **Event Loop**: Polls the signalfd, using the shutdown grace period as the
   poll timeout
6. **Signal Forwarding**: Forwards signals to child (with optional rewriting)
7. **Graceful Shutdown**: On child exit, sends SIGTERM to the child's process
   group, then SIGKILL once the grace period elapses (`-t`, default 5 s). zinit
   then exits without waiting indefinitely, so an unkillable or detached
   descendant can never hang it. When running as PID 1 the kernel tears down
   the rest of the PID namespace.

## Development

```bash
# Debug build
zig build

# Run tests
zig build test

# Run with coverage
zig build test -Dtest-coverage=true

# Run application
zig build run -- /bin/bash
```

## License

MIT License. See [LICENSE](LICENSE) for details.
