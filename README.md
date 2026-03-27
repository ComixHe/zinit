# zinit

A tiny init process written in Zig for Linux containers, designed for signal forwarding and orphan process collection.

## Features

- **Signal Forwarding**: Forward signals from parent process to child processes
- **Orphan Process Collection**: Acts as a child subreaper to collect orphaned processes
- **Parent Death Signal**: Configurable signal when parent process dies
- **Terminal Control**: Properly handles terminal process groups for interactive applications
- **Debug Support**: Optional tracing mode for debugging child processes

## Requirements

- Zig compiler (>= 0.16.0-dev.2860)
- Linux >= 3.4 (for PR_SET_CHILD_SUBREAPER)
- Linux kernel with signalfd support

## Installation

### From Source

```bash
git clone <repo_url> && cd zinit
zig build -Doptimize=ReleaseSafe
```

### Build Options

- `-Dtracing-child=true`: Enable tracing mode (child waits for SIGUSR1 before exec)

## Usage

```Text
Usage: zinit [OPTIONS] -- <command> [args...]

Options:
  -h, --help                  Show help and exit
  -v, --version               Show version and exit
  -s, --signal <SIGNAL>       The triggered signal when parent process dies
  --forward-mode <MODE>       The mode of forwarding signals to child processes

Forward Modes:
  Child         Forward signals to the main child process (default)
  ProcessGroup  Forward signals to the entire process group
```

## Examples

### Basic Usage

```bash
# Run a simple command
zinit -- /bin/bash -c "echo hello"

# With signal forwarding
zinit -s TERM -- /bin/sh -c "sleep 100"
```

### As a Container Init Process

```bash
#!/path/to/zinit -- /bin/bash
export YOUR_ENV=SOME_VALUE
# do some preparing
exec my-binary
```

### Signal Forwarding to Process Group

```bash
# Forward signals to all processes in the group
zinit --forward-mode ProcessGroup -- /bin/sh -c "stress-ng --cpu 4"
```

## Configuration

### Environment Variables

- `ZINIT_TRACING_CHILD=ON|OFF`: Override build-time tracing configuration
  - When `ON`, child process waits for SIGUSR1 before executing
  - Useful for debugging with `strace` or similar tools

### Build Configuration

```bash
# Build with tracing enabled
zig build -Dtracing-child=true -Doptimize=ReleaseSafe
```

## How It Works

1. **Initialization**: Sets up signal handling and becomes a child subreaper
2. **Fork**: Creates a child process in a new process group
3. **Signal Loop**: Waits for signals using signalfd
4. **Signal Forwarding**: Forwards received signals to child processes
5. **Process Collection**: Collects exited child processes and handles orphaned processes

## Development

### Building for Development

```bash
# Debug build
zig build

# Run tests
zig build test

# Run with arguments
zig build run -- /bin/bash
```

### Project Structure

```
├── src/
│   └── main.zig      # Main application logic
├── build.zig         # Build configuration
├── build.zig.zon     # Package metadata
└── LICENSE           # MIT License
```

## License

This project is licensed under the MIT License. See the `LICENSE` file for details.
