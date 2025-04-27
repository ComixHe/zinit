# zinit

A tiny init written in Zig for linux container, which for forwarding signal and recycling dead processes.

## Requirements

- Zig compiler (>= 0.14.0)
- Linux >= 3.4 (for PR_SET_CHILD_SUBREAPER)
- Linux kernel supports signalfd

## Installation & Build

```bash
git clone <repo_url> && cd <project_dir>
zig build --release=safe
```

## Command‑Line Options

```Text
Usage: zinit [OPTIONS] -- <command> [args...]

Options:
  -h, --help                  Show help and exit
  -v, --version               Show version and exit
  -s, --signal <SIGNAL>       The triggered signal when parent process dies
  --forward-mode <MODE>       The mode of forwarding signals to child processes
```

- `<command>`: The binary to execute.
- `[args...]`: Arguments passed to the child process.

## Examples

```bash
#!/path/to/zinit /bin/bash
export YOUR_ENV=SOME_VALUE
# do some preparing
exec my-binary
```

## Configuration & Environment Variables

you can build from source with '-Dtracing-child=true' or set **ZINIT_TRACING_CHILD=ON** at runtime to make child process waiting before execvpe.

The priority of **ZINIT_TRACING_CHILD** is higher than build config, you can set this to **ON** or **OFF** to override config value.

One usage is using strace to tracing child process.

## License

This project is licensed under the MIT License. See the `LICENSE` file for details.
