# zinit

[![Coverage Status](https://img.shields.io/codecov/c/github/ComixHe/zinit?style=flat-square&logo=codecov)](https://codecov.io/gh/ComixHe/zinit)

A tiny init process written in Zig for Linux containers, designed for signal forwarding, orphan process collection, and safer PID 1 shutdown behavior.

## Features

- **Signal Forwarding**: Forward signals from parent process to child processes
- **Orphan Process Collection**: Acts as a child subreaper to collect orphaned processes
- **Parent Death Signal**: Configurable signal when parent process dies
- **Signal Rewriting**: Remap incoming signals before forwarding them
- **Exit Code Mapping**: Translate known child exit codes to success when needed
- **Terminal Control**: Properly handles terminal process groups for interactive applications
- **Debug Support**: Optional tracing mode for debugging child processes

## Requirements

- Zig compiler (>= 0.16.0-dev.2860)
- Linux >= 3.4 (for PR_SET_CHILD_SUBREAPER)
- Linux kernel with signalfd support

## Installation

```bash
git clone <repo_url> && cd zinit
zig build -Doptimize=ReleaseSafe
```

The binary will be installed to `zig-out/bin/zinit`.

## Usage

```
Usage: zinit [OPTIONS] -- <command> [args...]

Options:
  -h, --help                  Show help and exit
  -v, --version               Show version and exit
  --log-level <LEVEL>         Set log level: error, warning, info, or debug
  -p, --signal <SIGNAL>       Signal to send when parent process dies
  -s, --subreaper             Enable child subreaper mode explicitly
  -r, --rewrite <OLD:NEW>     Rewrite a signal before forwarding (can be repeated)
  -e, --expect-exit <CODE>    Treat child exit code as success (0)
  --forward-mode <MODE>       Signal forwarding mode: Child (default) or ProcessGroup

Signal formats:
  - Number: 15, 9, 2
  - Name: TERM, KILL, INT (with or without SIG prefix)
  - Realtime: RTMIN, RTMIN+1, RTMAX, RTMAX-1
```

## Best Practices

### Run as PID 1 in Containers

When `zinit` runs as PID 1, it automatically enables child subreaper mode to properly reap orphaned descendant processes. This is the recommended usage:

```bash
# Dockerfile
COPY zinit /sbin/zinit
ENTRYPOINT ["/sbin/zinit", "--", "/bin/sh", "-c", "exec my-app"]
```

### Use `--subreaper` Outside PID 1

When running `zinit` outside of PID 1 (e.g., as a supervisor process), explicitly enable subreaper mode:

```bash
zinit --subreaper -- /usr/bin/my-daemon
```

### Forward Signals to Process Groups

For applications that spawn worker processes, use `ProcessGroup` mode to ensure all processes receive signals:

```bash
zinit --forward-mode ProcessGroup -- /bin/sh -c "stress-ng --cpu 4"
```

### Handle Application-Specific Exit Codes

Some applications exit with specific codes that should be treated as success:

```bash
# Java applications often exit with 143 (128 + SIGTERM)
zinit -e 143 -- java -jar app.jar
```

### Rewrite Signals for Legacy Applications

Some applications expect different signals than what the container runtime sends:

```bash
# Convert SIGTERM to SIGINT for graceful shutdown
zinit -r TERM:INT -- /bin/sh -c "trap 'exit 0' INT; sleep infinity"
```

### Set Parent Death Signal

Ensure the child process receives a signal when `zinit` itself dies unexpectedly:

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
zinit --forward-mode ProcessGroup -- /bin/sh -c '
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

### Environment Variables

| Variable | Values | Description |
|----------|--------|-------------|
| `ZINIT_TRACING_CHILD` | `ON`, `OFF` | Override build-time tracing configuration |

### Build Options

| Option | Description |
|--------|-------------|
| `-Dtracing-child=true` | Child waits for SIGUSR1 before exec (for debugging) |
| `-Doptimize=ReleaseSafe` | Build with safety checks and optimizations |
| `-Doptimize=ReleaseFast` | Build with maximum optimizations |
| `-Doptimize=ReleaseSmall` | Build for minimal binary size |

## How It Works

1. **Signal Setup**: Blocks all signals and creates a signalfd for synchronous signal handling
2. **Subreaper Mode**: Enables child subreaper (automatic when PID 1, or with `--subreaper`)
3. **Fork**: Creates child process with new session and process group
4. **Terminal Setup**: Sets up controlling terminal for interactive applications
5. **Event Loop**: Polls signalfd and timerfd for events
6. **Signal Forwarding**: Forwards signals to child (with optional rewriting)
7. **Graceful Shutdown**: On child exit, sends SIGTERM to descendants, then SIGKILL after 5 seconds

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
