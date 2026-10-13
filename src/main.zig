// SPDX-FileCopyrightText: 2025 - 2026 YuMing He <ComixHe1895@outlook.com>
//
// SPDX-License-Identifier: MIT

//! A tiny, allocation-free, libc-less init for Linux
//! containers, focused on signal forwarding and orphan reaping.
//!
//! Deliberate deviations from a typical Zig program, all in service of binary
//! size and runtime footprint:
//!
//! - Raw `std.os.linux` syscalls instead of `std.posix`, because the latter
//!   discards errors for `sigaction`/`sigprocmask` and pulls in machinery we do
//!   not need.
//! - A compile-time formatter (`fmt.put`/`fmt.parse`) instead of `std.fmt`, and a
//!   small logger instead of `std.log`.
//! - Only the standard signals (1..=31) are forwarded; realtime signals are not.
//! - `std_options` keeps the `networking` and `signal_stack_size` machinery, and
//!   the debug `Io`, out of the binary unless `-Dstack-traces` asks for them.

const std = @import("std");
const builtin = @import("builtin");
const config = @import("config");

/// Opt-in crash diagnostics (`-Dstack-traces`). Off by default: they pull in
/// ~120 KB of std.debug/ELF debug-info code, and leaving them off turns any
/// accidental `std.debug` use into a compile error.
const stack_traces = config.stack_traces;

pub const std_options: std.Options = .{
    .signal_stack_size = null,
    .networking = false,
    .enable_segfault_handler = stack_traces,
};

/// Debug needs std.debug's Io (std's own safety paths reach for it).
/// release builds only carry it with `-Dstack-traces`.
const debug_io_enabled = stack_traces or builtin.mode == .debug;

pub const std_options_debug_threaded_io: ?*std.Io.Threaded = if (debug_io_enabled)
    std.Io.Threaded.global_single_threaded
else
    null;

pub const panic = if (stack_traces)
    std.debug.FullPanic(std.debug.defaultPanic)
else
    minimalPanic;

fn minimalPanic(msg: []const u8, _: ?*std.builtin.StackTrace, _: ?usize) noreturn {
    const prefix = "zinit panic: ";
    const stderr_fd = std.os.linux.STDERR_FILENO;

    _ = std.os.linux.write(stderr_fd, prefix, prefix.len);
    _ = std.os.linux.write(stderr_fd, msg.ptr, msg.len);
    _ = std.os.linux.write(stderr_fd, "\n", 1);

    std.os.linux.exit(1);
}

const log_state = struct {
    var level: std.log.Level = .info;
    var color: bool = false;
};

fn logInit() void {
    var termios: std.os.linux.termios = undefined;
    const rc = std.os.linux.tcgetattr(std.os.linux.STDERR_FILENO, &termios);
    log_state.color = std.os.linux.errno(rc) == .SUCCESS;
}

fn setLogLevel(level: std.log.Level) void {
    log_state.level = level;
}

fn writeAll(fd: std.os.linux.fd_t, bytes: []const u8) void {
    var offset: usize = 0;
    while (offset < bytes.len) {
        const rc = std.os.linux.write(fd, bytes.ptr + offset, bytes.len - offset);
        switch (std.os.linux.errno(rc)) {
            // A zero-length result would spin forever; treat it as a short write.
            .SUCCESS => {
                if (rc == 0) return;
                offset += @intCast(rc);
            },
            .INTR => continue,
            else => return,
        }
    }
}

/// Minimal compile-time formatter, replacing `std.fmt` (whose machinery is far
/// too large for a size-first init).
const fmt = struct {
    const Piece = union(enum) {
        literal: []const u8,
        arg: enum { str, dec, hex },
    };

    fn parse(comptime format: []const u8) []const Piece {
        var pieces: [format.len]Piece = undefined;
        var n: usize = 0;
        var i: usize = 0;

        while (i < format.len) {
            if (format[i] != '{') {
                var j = i;
                while (j < format.len and format[j] != '{') : (j += 1) {}
                pieces[n] = .{ .literal = format[i..j] };
                n += 1;
                i = j;
            } else {
                var j = i + 1;
                while (format[j] != '}') : (j += 1) {}
                const spec = format[i + 1 .. j];
                pieces[n] = .{ .arg = if (std.mem.eql(u8, spec, "s"))
                    .str
                else if (std.mem.eql(u8, spec, "d"))
                    .dec
                else if (std.mem.eql(u8, spec, "x"))
                    .hex
                else
                    @compileError("unsupported format spec: {" ++ spec ++ "}") };

                n += 1;
                i = j + 1;
            }
        }

        return pieces[0..n];
    }

    fn put(buf: []u8, comptime format: []const u8, args: anytype) []u8 {
        const pieces = comptime parse(format);
        var out: usize = 0;
        comptime var arg_i: usize = 0;

        inline for (pieces) |piece| {
            switch (piece) {
                .literal => |lit| out = putBytes(buf, out, lit),
                .arg => |kind| {
                    out = switch (kind) {
                        .str => putBytes(buf, out, args[arg_i]),
                        .dec => putInt(buf, out, args[arg_i], 10),
                        .hex => putInt(buf, out, args[arg_i], 16),
                    };

                    arg_i += 1;
                },
            }
        }

        return buf[0..out];
    }

    noinline fn putBytes(buf: []u8, out: usize, bytes: []const u8) usize {
        if (out >= buf.len) return out;

        const n = @min(bytes.len, buf.len - out);
        @memcpy(buf[out..][0..n], bytes[0..n]);
        return out + n;
    }

    noinline fn putInt(buf: []u8, out: usize, value: u64, base: u8) usize {
        const digits = "0123456789abcdef";
        var v: u64 = value;
        var tmp: [20]u8 = undefined;
        var n: usize = 0;

        if (v == 0) {
            tmp[0] = '0';
            n = 1;
        } else {
            while (v != 0) : (v /= base) {
                tmp[n] = digits[@intCast(v % base)];
                n += 1;
            }
        }

        var written: usize = 0;
        while (written < n and out + written < buf.len) : (written += 1) {
            buf[out + written] = tmp[n - 1 - written];
        }

        return out + written;
    }
};

/// Byte search without `std.mem`'s vectorized `findScalarPos`: every needle
/// here is a single byte in a short string, no need to pull in the whole SIMD machinery
/// for binary size.
fn indexOfByte(s: []const u8, c: u8) ?usize {
    for (s, 0..) |b, i| {
        if (b == c) return i;
    }

    return null;
}

/// Short name for the errno values zinit's syscalls can plausibly return.
/// The names here are plain string literals, so the huge @tagName(std.os.linux.E)
/// table is never emitted; anything outside this set prints as a number instead.
fn errName(e: std.os.linux.E) []const u8 {
    var errno_scratch: [24]u8 = undefined;

    const name: []const u8 = switch (e) {
        .PERM => "EPERM",
        .NOENT => "ENOENT",
        .SRCH => "ESRCH",
        .INTR => "EINTR",
        .IO => "EIO",
        .NXIO => "ENXIO",
        .@"2BIG" => "E2BIG",
        .NOEXEC => "ENOEXEC",
        .BADF => "EBADF",
        .CHILD => "ECHILD",
        .AGAIN => "EAGAIN",
        .NOMEM => "ENOMEM",
        .ACCES => "EACCES",
        .FAULT => "EFAULT",
        .BUSY => "EBUSY",
        .EXIST => "EEXIST",
        .NOTDIR => "ENOTDIR",
        .ISDIR => "EISDIR",
        .INVAL => "EINVAL",
        .NFILE => "ENFILE",
        .MFILE => "EMFILE",
        .NOTTY => "ENOTTY",
        .TXTBSY => "ETXTBSY",
        .FBIG => "EFBIG",
        .NOSPC => "ENOSPC",
        .SPIPE => "ESPIPE",
        .ROFS => "EROFS",
        .MLINK => "EMLINK",
        .PIPE => "EPIPE",
        .NAMETOOLONG => "ENAMETOOLONG",
        .NOSYS => "ENOSYS",
        .LOOP => "ELOOP",
        else => fmt.put(&errno_scratch, "errno {d}", .{@backingInt(e)}),
    };

    return name;
}

/// Minimal logger: applies the runtime level, prefixes and writes to stderr
/// with no allocation and no dependency on `std.log`.
const log = struct {
    fn emit(level: std.log.Level, msg: []const u8) void {
        if (@backingInt(level) > @backingInt(log_state.level)) return;

        const prefix: []const u8 = if (log_state.color) switch (level) {
            .err => "\x1b[31m[zinit] ERROR:\x1b[0m ",
            .warn => "\x1b[33m[zinit] WARN:\x1b[0m ",
            .info => "\x1b[32m[zinit] INFO:\x1b[0m ",
            .debug => "\x1b[36m[zinit] DEBUG:\x1b[0m ",
        } else switch (level) {
            .err => "[zinit] ERROR: ",
            .warn => "[zinit] WARN: ",
            .info => "[zinit] INFO: ",
            .debug => "[zinit] DEBUG: ",
        };

        var buf: [512]u8 = undefined;
        const text = fmt.put(&buf, "{s}{s}\n", .{ prefix, msg });
        writeAll(std.os.linux.STDERR_FILENO, text);
    }

    fn print(comptime level: std.log.Level, comptime format: []const u8, args: anytype) void {
        var buf: [512]u8 = undefined;
        const msg = fmt.put(&buf, format, args);
        emit(level, msg);
    }

    fn err(comptime format: []const u8, args: anytype) void {
        print(.err, format, args);
    }

    fn warn(comptime format: []const u8, args: anytype) void {
        print(.warn, format, args);
    }

    fn info(comptime format: []const u8, args: anytype) void {
        print(.info, format, args);
    }

    fn debug(comptime format: []const u8, args: anytype) void {
        print(.debug, format, args);
    }

    fn exitedProcess(pid: usize, status: WaitStatus, is_main: bool) void {
        var buf: [128]u8 = undefined;
        const what: []const u8 = if (is_main) "child process" else "orphaned process";
        const code = std.os.linux.W.EXITSTATUS(status.raw);
        const signal_number: u64 = @intCast(@backingInt(std.os.linux.W.TERMSIG(status.raw)));
        const msg = switch (status.class()) {
            .exited => fmt.put(&buf, "{s} {d} exited with code {d}.", .{ what, pid, code }),
            .signaled => fmt.put(&buf, "{s} {d} exited with signal {d}.", .{
                what, pid, signal_number,
            }),
            .unknown => fmt.put(&buf, "{s} {d} exited with unknown status", .{ what, pid }),
        };

        emit(.info, msg);
    }
};

const Sig = std.os.linux.SIG;

fn lookupSignal(name: []const u8) ?u32 {
    const map = comptime std.StaticStringMap(Sig).initEnum();
    return if (map.get(name)) |s| @backingInt(s) else null;
}

fn parseDecimal(comptime T: type, s: []const u8) error{ InvalidCharacter, Overflow }!T {
    if (s.len == 0) return error.InvalidCharacter;
    var v: u64 = 0;
    for (s) |c| {
        if (c < '0' or c > '9') return error.InvalidCharacter;
        v = v * 10 + (c - '0');
        if (v > std.math.maxInt(T)) return error.Overflow;
    }

    return @intCast(v);
}

fn parseLogLevel(s: []const u8) ?std.log.Level {
    if (std.ascii.eqlIgnoreCase(s, "error")) return .err;
    if (std.ascii.eqlIgnoreCase(s, "warn")) return .warn;
    if (std.ascii.eqlIgnoreCase(s, "info")) return .info;
    if (std.ascii.eqlIgnoreCase(s, "debug")) return .debug;
    return null;
}

const ZinitError = error{
    InvalidSignal,
    InvalidParams,
    InvalidRewrite,
    InvalidExitCode,
    SysCallError,
    DuplicateSignal,
    CycleRewrite,
};

const ExitCodeSet = std.StaticBitSet(256);

/// Standard (non-realtime) signals are 1..=31; realtime signals start at
/// SIGRTMIN (32) and are deliberately not supported.
const standard_signal_max: u32 = std.os.linux.sigrtmin() - 1;

fn isStandardSignal(sig: u32) bool {
    return sig > 0 and sig <= standard_signal_max;
}

/// Parse a signal from a number or a name (`TERM`, `SIGTERM`).
/// Realtime signals are deliberately rejected.
fn parseSignal(s: []const u8) !u32 {
    if (s.len == 0) return ZinitError.InvalidParams;

    if (s[0] >= '0' and s[0] <= '9') {
        if (parseDecimal(u32, s)) |sig_num| {
            if (isStandardSignal(sig_num)) return sig_num;
            return ZinitError.InvalidSignal;
        } else |_| {}
    }

    const name_to_check = if (std.ascii.startsWithIgnoreCase(s, "SIG"))
        s[3..]
    else
        s;

    if (name_to_check.len == 0 or name_to_check.len > 15) return ZinitError.InvalidSignal;

    var buf: [16]u8 = undefined;
    const upper_name = std.ascii.upperString(&buf, name_to_check);

    const sig = lookupSignal(upper_name) orelse return ZinitError.InvalidSignal;
    if (!isStandardSignal(sig)) return ZinitError.InvalidSignal;
    return sig;
}

/// Signal rewrites applied to forwarded signals
const RewriteMap = struct {
    /// Sentinel value indicating no rewrite is defined.
    /// `0` is a valid stored value: it means "drop the signal".
    const unset: u32 = std.math.maxInt(u32);

    entries: [std.os.linux.NSIG]u32,

    fn init() RewriteMap {
        return .{ .entries = @splat(unset) };
    }

    fn reset(self: *RewriteMap) void {
        self.entries = @splat(unset);
    }

    fn get(self: *const RewriteMap, sig: u32) u32 {
        return self.entries[sig];
    }

    fn has(self: *const RewriteMap, sig: u32) bool {
        return self.entries[sig] != unset;
    }

    fn set(self: *RewriteMap, old_sig: u32, new_sig: u32) void {
        self.entries[old_sig] = new_sig;
    }

    fn apply(rewrites: ?RewriteMap, signo: u32) u32 {
        if (rewrites) |m| {
            if (m.has(signo)) return m.get(signo);
        }

        return signo;
    }

    fn parse(self: *RewriteMap, value: []const u8) !void {
        const sep = indexOfByte(value, ':') orelse return ZinitError.InvalidRewrite;
        const old = value[0..sep];
        const old_sig = try parseSignal(old);

        const rest = value[sep + 1 ..];
        const rest_sep = indexOfByte(rest, ':');
        const new = if (rest_sep) |s| rest[0..s] else rest;
        const new_sig = try parseRewriteTarget(new);

        if (rest_sep != null) return ZinitError.InvalidRewrite;

        if (old_sig == new_sig) return ZinitError.DuplicateSignal;

        if (new_sig != 0 and try self.reaches(new_sig, old_sig)) return ZinitError.CycleRewrite;

        if (self.has(old_sig)) return ZinitError.DuplicateSignal;

        self.set(old_sig, new_sig);
    }

    fn reaches(self: *const RewriteMap, from: u32, to: u32) ZinitError!bool {
        if (!(from > 0 and from < std.os.linux.NSIG)) return ZinitError.InvalidParams;

        var current = from;
        var steps: usize = 0;
        while (self.has(current)) {
            const next_node = self.get(current);
            if (next_node == to) return true;
            if (next_node == 0) return false;

            steps += 1;
            if (steps >= std.os.linux.NSIG) return true;

            current = next_node;
        }

        return false;
    }
};

fn parseRewriteTarget(s: []const u8) !u32 {
    if (std.mem.eql(u8, s, "0")) return 0;
    return parseSignal(s);
}

fn printHelp(fd: std.os.linux.fd_t) void {
    writeAll(fd,
        \\zinit - A tiny init for linux containers.
        \\
        \\Usage: zinit [options] <ARG>...
        \\
        \\Options:
        \\  -h, --help                                                   Display this help and exit
        \\  -V, --version                                                Output version information and exit
        \\      --log-level <LEVEL> (Env: ZINIT_LOG_LEVEL)               Set log level: error, warn, info (default), or debug
        \\  -p, --signal <SIGNAL>                                        The triggered signal when parent process dies
        \\  -s, --subreaper (Env: ZINIT_SUBREAPER)                       Enable child subreaper mode explicitly
        \\  -n, --new-session                                            Enable new session mode explicitly
        \\  -g, --forward-group                                          Forward signals to the whole process group
        \\  -t, --shutdown-timeout <SECS> (Env: ZINIT_SHUTDOWN_TIMEOUT)  Grace period before SIGKILL on shutdown (default 5)
        \\  -r, --rewrite <OLD:NEW>...                                   Rewrite a forwarded signal before sending to the child
        \\                                                               (repeatable; use "0" as NEW to drop the signal)
        \\  -e, --expect-exit <CODE>...                                  Map child exit codes to 0 (repeatable)
        \\
        \\Environment variables:
        \\
        \\  ZINIT_TRACING_CHILD: If set, zinit will wait for SIGUSR1 to continue executing child process
        \\
        \\Full help or any issues, please visit https://github.com/ComixHe/zinit
        \\
    );
}

fn printVersion() void {
    var buf: [64]u8 = undefined;
    const text = fmt.put(&buf, "{d}.{d}.{d}\n", .{
        config.version.major,
        config.version.minor,
        config.version.patch,
    });

    writeAll(std.os.linux.STDOUT_FILENO, text);
}

const Args = struct {
    log_level: std.log.Level,
    pdeath_signal: ?u32,
    rewrites: ?RewriteMap,
    expected_exit: ExitCodeSet,
    subreaper: bool,
    new_session: bool,
    forward_group: bool,
    is_terminal: bool,
    tracing_child: bool,
    /// Grace between SIGTERM and SIGKILL when tearing down the process group.
    shutdown_timeout_ns: u64,
    /// Borrowed suffix of the kernel argv.
    argv: [*:null]const ?[*:0]const u8,
    envs: [:null]const ?[*:0]const u8,

    const Action = union(enum) {
        run: Args,
        help,
        version,
    };

    fn parse(init: std.process.Init.Minimal) !Action {
        var args_iter = init.args.iterate();
        defer args_iter.deinit();
        _ = args_iter.skip();

        var rewrite_map: ?RewriteMap = null;

        var log_level_opt: ?std.log.Level = null;
        var pdeath_signal: ?u32 = null;
        var subreaper_flag = false;
        var forward_group = false;
        var shutdown_timeout_s: ?u64 = null;
        var expected_exit: ExitCodeSet = .empty;
        var new_session = false;
        var has_help = false;
        var has_version = false;
        var child_start: ?usize = null;

        while (args_iter.next()) |arg| {
            if (std.mem.eql(u8, arg, "--")) {
                const next = init.args.vector.len - args_iter.inner.remaining.len;
                if (next < init.args.vector.len) child_start = next;
                break;
            }

            if (std.mem.eql(u8, arg, "-h") or std.mem.eql(u8, arg, "--help")) {
                has_help = true;
                continue;
            }

            if (std.mem.eql(u8, arg, "-V") or std.mem.eql(u8, arg, "--version")) {
                has_version = true;
                continue;
            }

            if (std.mem.eql(u8, arg, "-n") or std.mem.eql(u8, arg, "--new-session")) {
                new_session = true;
                continue;
            }

            if (std.mem.eql(u8, arg, "-s") or std.mem.eql(u8, arg, "--subreaper")) {
                subreaper_flag = true;
                continue;
            }

            if (std.mem.eql(u8, arg, "-g") or std.mem.eql(u8, arg, "--forward-group")) {
                forward_group = true;
                continue;
            }

            if (std.mem.eql(u8, arg, "-t") or std.mem.eql(u8, arg, "--shutdown-timeout")) {
                const v = args_iter.next() orelse return ZinitError.InvalidParams;
                shutdown_timeout_s = parseDecimal(u64, v) catch return ZinitError.InvalidParams;
                continue;
            }

            if (std.mem.eql(u8, arg, "--log-level")) {
                const v = args_iter.next() orelse return ZinitError.InvalidParams;
                log_level_opt = parseLogLevel(v) orelse return ZinitError.InvalidParams;
                continue;
            }

            if (std.mem.eql(u8, arg, "-p") or std.mem.eql(u8, arg, "--signal")) {
                if (pdeath_signal != null) return ZinitError.InvalidParams;
                const v = args_iter.next() orelse return ZinitError.InvalidParams;
                pdeath_signal = try parseSignal(v);
                continue;
            }

            if (std.mem.eql(u8, arg, "-r") or std.mem.eql(u8, arg, "--rewrite")) {
                if (rewrite_map == null) rewrite_map = .init();
                try rewrite_map.?.parse(args_iter.next() orelse return ZinitError.InvalidRewrite);
                continue;
            }

            if (std.mem.eql(u8, arg, "-e") or std.mem.eql(u8, arg, "--expect-exit")) {
                const v = args_iter.next() orelse return ZinitError.InvalidExitCode;
                const code = parseDecimal(u8, v) catch return ZinitError.InvalidExitCode;
                expected_exit.set(code);
                continue;
            }

            if (arg.len > 0 and arg[0] == '-') return ZinitError.InvalidParams;

            // First non-option: it begins the child argv suffix.
            child_start = init.args.vector.len - args_iter.inner.remaining.len - 1;
            break;
        }

        if (has_help and has_version) return ZinitError.InvalidParams;
        if (has_help) return .help;
        if (has_version) return .version;

        // A trailing `--` (or no command at all) used to leave `start` one past
        // the last argument, which then dereferenced the argv NULL terminator.
        const start = child_start orelse return ZinitError.InvalidParams;

        const log_level: std.log.Level = log_level_opt orelse blk: {
            const v = init.environ.getPosix("ZINIT_LOG_LEVEL") orelse break :blk .info;
            break :blk parseLogLevel(v) orelse return ZinitError.InvalidParams;
        };

        const shutdown_timeout_s_final: u64 = shutdown_timeout_s orelse blk: {
            const v = init.environ.getPosix("ZINIT_SHUTDOWN_TIMEOUT") orelse
                break :blk default_shutdown_timeout_s;
            break :blk parseDecimal(u64, v) catch return ZinitError.InvalidParams;
        };

        const subreaper = subreaper_flag or init.environ.getPosix("ZINIT_SUBREAPER") != null;

        const tracing_child = blk: {
            const v = init.environ.getPosix("ZINIT_TRACING_CHILD") orelse
                break :blk config.tracing_child;
            if (std.ascii.eqlIgnoreCase(v, "OFF")) break :blk false;
            if (std.ascii.eqlIgnoreCase(v, "ON")) break :blk true;
            break :blk config.tracing_child;
        };

        if (new_session) {
            if (rewrite_map == null) rewrite_map = .init();

            const stop = @backingInt(Sig.STOP);
            const tstp = @backingInt(Sig.TSTP);
            const ttou = @backingInt(Sig.TTOU);
            const ttin = @backingInt(Sig.TTIN);

            if (!rewrite_map.?.has(tstp)) rewrite_map.?.set(tstp, stop);
            if (!rewrite_map.?.has(ttou)) rewrite_map.?.set(ttou, stop);
            if (!rewrite_map.?.has(ttin)) rewrite_map.?.set(ttin, stop);
        }

        var termios: std.os.linux.termios = undefined;
        const termios_rc = std.os.linux.tcgetattr(std.os.linux.STDIN_FILENO, &termios);
        const is_terminal = std.os.linux.errno(termios_rc) == .SUCCESS;

        const argv_base: [*:null]const ?[*:0]const u8 = @ptrCast(init.args.vector.ptr);

        return .{
            .run = .{
                .log_level = log_level,
                .pdeath_signal = pdeath_signal,
                .rewrites = rewrite_map,
                .expected_exit = expected_exit,
                .subreaper = subreaper,
                .new_session = new_session,
                .forward_group = forward_group,
                .is_terminal = is_terminal,
                .tracing_child = tracing_child,
                .shutdown_timeout_ns = shutdown_timeout_s_final * std.time.ns_per_s,
                .argv = argv_base + start,
                .envs = init.environ.block.slice,
            },
        };
    }

    fn spawn(self: *const Args, sig_conf: *SigConf) !usize {
        if (self.new_session and self.is_terminal) {
            const rc = std.os.linux.ioctl(std.os.linux.STDIN_FILENO, std.os.linux.T.IOCNOTTY, 0);
            const err = std.os.linux.errno(rc);
            if (err != .SUCCESS) {
                log.debug("unable to detach from terminal: {s}", .{errName(err)});
            } else {
                if (std.os.linux.getsid(0) == std.os.linux.getpid()) {
                    sig_conf.ignore_detached_sig = true;
                    log.debug(
                        "detaching from controlling terminal, ignoring initial HUP/CONT",
                        .{},
                    );
                } else {
                    log.debug(
                        "detached from controlling terminal, but was not session leader",
                        .{},
                    );
                }
            }
        }

        const pid = std.os.linux.fork();
        const err = std.os.linux.errno(pid);
        if (err != .SUCCESS) {
            log.err("unable to fork: {s}", .{errName(err)});
            return ZinitError.SysCallError;
        }

        if (pid != 0) return @intCast(pid);

        // Terminal/process-group setup must happen before restoring the child's
        // TTIN/TTOU dispositions: tcsetpgrp relies on SIGTTOU still being ignored.
        self.setupChildTerminal();
        sig_conf.restoreChild();

        if (self.pdeath_signal) |sig| {
            const option = @backingInt(std.os.linux.PR.SET_PDEATHSIG);
            const ret = std.os.linux.prctl(option, sig, 0, 0, 0);
            switch (std.os.linux.errno(ret)) {
                .SUCCESS => {},
                else => |e| childErrorExit(1, &.{
                    "unable to set parent death signal: ", errName(e),
                }),
            }
        }

        if (self.tracing_child) waitForTracer();

        execChild(self.argv, self.envs);
    }

    fn setupChildTerminal(self: Args) void {
        // Always isolate the child into its own process group so that shutdown can
        // signal the whole subtree.
        if (self.new_session) {
            const sid = std.os.linux.setsid();
            const err = std.os.linux.errno(sid);
            if (err != .SUCCESS) {
                childErrorExit(1, &.{ "unable to create session: ", errName(err) });
            }
        } else {
            const rc = std.os.linux.setpgid(0, 0);
            const err = std.os.linux.errno(rc);
            if (err != .SUCCESS) {
                childErrorExit(1, &.{ "unable to create process group: ", errName(err) });
            }
        }

        if (!self.is_terminal) return;

        if (self.new_session) {
            const rc = std.os.linux.ioctl(std.os.linux.STDIN_FILENO, std.os.linux.T.IOCSCTTY, 0);
            const err = std.os.linux.errno(rc);
            if (err != .SUCCESS) {
                log.debug("unable to acquire controlling tty: {s}", .{errName(err)});
            }
        }

        // Make the child's group the foreground group, otherwise an interactive
        // program reading the terminal would be stopped by SIGTTIN.
        // This must run while SIGTTOU is still SIG_IGN (i.e. before restoring child signals):
        // the kernel refuses to change the foreground group for a background caller
        // unless SIGTTOU is ignored.
        if (builtin.mode == .debug) std.debug.assert(signalIsIgnored(Sig.TTOU));
        const pgrp: std.os.linux.pid_t = std.os.linux.getpid();
        switch (std.os.linux.errno(std.os.linux.tcsetpgrp(std.os.linux.STDIN_FILENO, &pgrp))) {
            .SUCCESS, .NOTTY, .NXIO => {},
            else => |e| log.debug("unable to set foreground process group: {s}", .{errName(e)}),
        }
    }
};

const default_shutdown_timeout_s: u64 = 5;

const SigConf = struct {
    old_set: std.os.linux.sigset_t,
    current_set: std.os.linux.sigset_t,
    ttin_action: std.os.linux.Sigaction,
    ttou_action: std.os.linux.Sigaction,
    ignore_detached_sig: bool = false,

    fn init(comptime sig_list: []const Sig) !SigConf {
        var set = std.os.linux.sigfillset();
        for (sig_list) |sig| std.os.linux.sigdelset(&set, sig);

        var old_set: std.os.linux.sigset_t = undefined;
        var ret = std.os.linux.sigprocmask(Sig.SETMASK, &set, &old_set);
        switch (std.os.linux.errno(ret)) {
            .SUCCESS => {},
            else => {
                log.err("unable to set signal mask: {s}", .{errName(std.os.linux.errno(ret))});
                return ZinitError.SysCallError;
            },
        }

        const ignored = std.os.linux.Sigaction{
            .handler = .{ .handler = Sig.IGN },
            .mask = std.os.linux.sigemptyset(),
            .flags = 0,
        };

        var old_ttin_action: std.os.linux.Sigaction = undefined;
        ret = std.os.linux.sigaction(Sig.TTIN, &ignored, &old_ttin_action);
        switch (std.os.linux.errno(ret)) {
            .SUCCESS => {},
            else => |e| {
                log.err("unable to set signal action for TTIN: {s}", .{errName(e)});
                return ZinitError.SysCallError;
            },
        }

        var old_ttou_action: std.os.linux.Sigaction = undefined;
        ret = std.os.linux.sigaction(Sig.TTOU, &ignored, &old_ttou_action);
        switch (std.os.linux.errno(ret)) {
            .SUCCESS => {},
            else => |e| {
                log.err("unable to set signal action for TTOU: {s}", .{errName(e)});
                return ZinitError.SysCallError;
            },
        }

        return .{
            .old_set = old_set,
            .current_set = set,
            .ttin_action = old_ttin_action,
            .ttou_action = old_ttou_action,
        };
    }

    fn restoreChild(self: *const SigConf) void {
        var ret = std.os.linux.sigprocmask(Sig.SETMASK, &self.old_set, null);
        switch (std.os.linux.errno(ret)) {
            .SUCCESS => {},
            else => |e| childErrorExit(1, &.{ "unable to restore signal mask: ", errName(e) }),
        }

        var unblock_all = std.os.linux.sigfillset();
        ret = std.os.linux.sigprocmask(Sig.UNBLOCK, &unblock_all, null);
        switch (std.os.linux.errno(ret)) {
            .SUCCESS => {},
            else => |e| childErrorExit(1, &.{ "unable to unblock signals: ", errName(e) }),
        }

        ret = std.os.linux.sigaction(Sig.TTIN, &self.ttin_action, null);
        switch (std.os.linux.errno(ret)) {
            .SUCCESS => {},
            else => |e| childErrorExit(1, &.{
                "unable to restore signal action for TTIN: ", errName(e),
            }),
        }

        ret = std.os.linux.sigaction(Sig.TTOU, &self.ttou_action, null);
        switch (std.os.linux.errno(ret)) {
            .SUCCESS => {},
            else => |e| childErrorExit(1, &.{
                "unable to restore signal action for TTOU: ", errName(e),
            }),
        }
    }
};

fn childErrorExit(code: u8, parts: []const []const u8) noreturn {
    var buf: [512]u8 = undefined;
    var out: usize = 0;
    out = fmt.putBytes(&buf, out, "zinit child error: ");
    for (parts) |p| out = fmt.putBytes(&buf, out, p);
    out = fmt.putBytes(&buf, out, "\n");
    _ = std.os.linux.write(std.os.linux.STDERR_FILENO, buf[0..out].ptr, out);
    std.os.linux.exit(code);
}

fn execExitCode(e: std.os.linux.E) u8 {
    return switch (e) {
        .NOENT => 127,
        .ACCES, .NOEXEC => 126,
        else => 1,
    };
}

fn signalIsIgnored(sig: Sig) bool {
    var act: std.os.linux.Sigaction = undefined;
    if (std.os.linux.errno(std.os.linux.sigaction(sig, null, &act)) != .SUCCESS) return false;
    return act.handler.handler == Sig.IGN;
}

/// Default search path used when `PATH` is unset (mirrors execvp).
const default_path = "/usr/local/bin:/usr/bin:/bin";

fn envValue(envp: [*:null]const ?[*:0]const u8, name: []const u8) ?[]const u8 {
    var i: usize = 0;
    while (envp[i]) |entry| : (i += 1) {
        const s = std.mem.span(entry);
        if (s.len > name.len and s[name.len] == '=' and std.mem.eql(u8, s[0..name.len], name)) {
            return s[name.len + 1 ..];
        }
    }

    return null;
}

fn execChild(argv: [*:null]const ?[*:0]const u8, envp: [*:null]const ?[*:0]const u8) noreturn {
    var path_buf: [std.os.linux.PATH_MAX]u8 = undefined;
    const file = std.mem.span(argv[0].?);

    if (indexOfByte(file, '/') != null) {
        const e = std.os.linux.errno(std.os.linux.execve(argv[0].?, argv, envp));
        childErrorExit(execExitCode(e), &.{ "unable to execve ", file, ": ", errName(e) });
    }

    const path = envValue(envp, "PATH") orelse default_path;
    var last_errno: std.os.linux.E = .NOENT;
    var rest = path;
    while (true) {
        const colon = indexOfByte(rest, ':');
        const dir = if (colon) |c| rest[0..c] else rest;

        const candidate: ?[*:0]const u8 = blk: {
            // An empty PATH entry means the current directory.
            if (dir.len == 0) break :blk argv[0].?;
            if (dir.len + 1 + file.len >= path_buf.len) break :blk null; // won't fit
            @memcpy(path_buf[0..dir.len], dir);
            path_buf[dir.len] = '/';
            @memcpy(path_buf[dir.len + 1 ..][0..file.len], file);
            path_buf[dir.len + 1 + file.len] = 0;
            break :blk @ptrCast(&path_buf);
        };

        if (candidate) |c| {
            const e = std.os.linux.errno(std.os.linux.execve(c, argv, envp));
            switch (e) {
                .SUCCESS => unreachable,
                .ACCES, .NOENT, .NOTDIR, .NAMETOOLONG, .LOOP => last_errno = e,
                else => childErrorExit(execExitCode(e), &.{
                    "unable to execve ", file, ": ", errName(e),
                }),
            }
        }

        const adv = colon orelse break;
        rest = rest[adv + 1 ..];
    }

    childErrorExit(execExitCode(last_errno), &.{
        "unable to execve ", file, ": ", errName(last_errno),
    });
}

/// Block until the tracer sends SIGUSR1, so a debugger can attach before `exec`.
fn waitForTracer() void {
    const dummy_handler = struct {
        fn handler(_: Sig) callconv(.c) void {}
    }.handler;

    const usr1_act: std.os.linux.Sigaction = .{
        .handler = .{ .handler = dummy_handler },
        .mask = std.os.linux.sigemptyset(),
        .flags = 0,
    };

    var old_act: std.os.linux.Sigaction = undefined;
    switch (std.os.linux.errno(std.os.linux.sigaction(Sig.USR1, &usr1_act, &old_act))) {
        .SUCCESS => {},
        else => |e| {
            log.debug("failed to set signal action for USR1: {s}", .{errName(e)});
            return;
        },
    }

    _ = std.os.linux.pause();

    switch (std.os.linux.errno(std.os.linux.sigaction(Sig.USR1, &old_act, null))) {
        .SUCCESS => {},
        else => |e| log.debug("failed to restore signal action for USR1: {s}", .{errName(e)}),
    }
}

const WaitStatus = struct {
    raw: u32,

    const Class = enum { exited, signaled, unknown };

    fn class(self: WaitStatus) Class {
        if (std.os.linux.W.IFEXITED(self.raw)) return .exited;
        if (std.os.linux.W.IFSIGNALED(self.raw)) return .signaled;
        return .unknown;
    }

    fn exitCode(self: WaitStatus) u8 {
        if (std.os.linux.W.IFEXITED(self.raw)) return std.os.linux.W.EXITSTATUS(self.raw);
        if (std.os.linux.W.IFSIGNALED(self.raw)) {
            return @intCast(128 + @backingInt(std.os.linux.W.TERMSIG(self.raw)));
        }

        return 0;
    }
};

const DrainResult = struct {
    main_code: ?u8 = null,
    no_children: bool,
};

fn drainChildren(main_pid: ?usize, expected_exit: ExitCodeSet) !DrainResult {
    var status: i32 = 0;
    var main_exit_code: ?u8 = null;
    while (true) {
        const ret = std.os.linux.waitpid(-1, &status, std.os.linux.W.NOHANG);
        if (ret == 0) return .{ .main_code = main_exit_code, .no_children = false };

        const err = std.os.linux.errno(ret);
        switch (err) {
            .INTR => continue,
            .SUCCESS => {
                const pid: usize = @intCast(ret);
                const is_main = if (main_pid) |mp| pid == mp else false;
                const wait_status = WaitStatus{ .raw = @intCast(status) };
                log.exitedProcess(pid, wait_status, is_main);

                if (is_main) {
                    const ec = wait_status.exitCode();
                    main_exit_code = if (expected_exit.isSet(ec)) 0 else ec;
                }
            },
            .CHILD => return .{ .main_code = main_exit_code, .no_children = true },
            else => {
                log.debug("unable to waitpid: {s}", .{errName(err)});
                return ZinitError.SysCallError;
            },
        }
    }
}

const GroupSendKind = enum { delivered, gone, unsupported_fell_back, failed };

const GroupSendOutcome = struct {
    kind: GroupSendKind,
    errno: std.os.linux.E = .SUCCESS,
};

/// Signal the child's process group, preferring the race-free pidfd path
/// (`PIDFD_SIGNAL_PROCESS_GROUP`, Linux >= 6.9) and falling back to `kill(-pgid)`.
/// Both syscalls are injectable so the fallback is testable on any kernel.
const ProcessGroupSignaller = struct {
    /// `null` until the first attempt, then whether the running kernel honours
    /// PIDFD_SIGNAL_PROCESS_GROUP. When `false`, pidfd is skipped entirely.
    support: ?bool = null,
    pidfd_send: *const fn (pidfd: std.os.linux.fd_t, sig: u32) std.os.linux.E = pidfdSendGroup,
    kill_group: *const fn (pgid: usize, sig: u32) std.os.linux.E = killProcessGroup,

    /// `pidfd_send_signal(2)` scope flag selecting the target process group.
    /// Added in Linux 6.9: older kernels reject the unknown flag with EINVAL,
    /// and kernels without the syscall at all with ENOSYS.
    const PIDFD_SIGNAL_PROCESS_GROUP: u32 = 1 << 2;

    fn pidfdSendGroup(pidfd: std.os.linux.fd_t, sig: u32) std.os.linux.E {
        const rc = std.os.linux.pidfd_send_signal(
            pidfd,
            @fromBackingInt(@intCast(sig)),
            null,
            PIDFD_SIGNAL_PROCESS_GROUP,
        );

        return std.os.linux.errno(rc);
    }

    fn killProcessGroup(pgid: usize, sig: u32) std.os.linux.E {
        const target: std.os.linux.pid_t = @intCast(pgid);
        const rc = std.os.linux.kill(-target, @fromBackingInt(@intCast(sig)));
        return std.os.linux.errno(rc);
    }

    fn signal(
        self: *ProcessGroupSignaller,
        pidfd: std.os.linux.fd_t,
        pgid: usize,
        sig: u32,
    ) GroupSendOutcome {
        if (pidfd >= 0 and self.support != false) {
            switch (self.pidfd_send(pidfd, sig)) {
                .SUCCESS => {
                    self.support = true;
                    return .{ .kind = .delivered };
                },
                .NOSYS, .INVAL => self.support = false,
                .SRCH => {
                    self.support = true;
                    return .{ .kind = .gone };
                },
                else => |e| return .{ .kind = .failed, .errno = e },
            }
        }

        return switch (self.kill_group(pgid, sig)) {
            .SUCCESS => .{
                .kind = if (self.support == false) .unsupported_fell_back else .delivered,
            },
            .SRCH => .{ .kind = .gone },
            else => |e| .{ .kind = .failed, .errno = e },
        };
    }
};

/// Process-wide capability cache; zinit is single-threaded, so no locking.
var process_group_signaller: ProcessGroupSignaller = .{};

const ProcessState = struct {
    child: usize,
    child_pidfd: std.os.linux.fd_t = -1,
    expected_exit: ExitCodeSet,
    rewrites: ?RewriteMap,
    sigfd: std.os.linux.fd_t,
    shutdown: ?ShutdownState = null,
    forward_group: bool,
    shutdown_timeout_ns: u64,
    ignore_hup: bool = false,
    ignore_cont: bool = false,

    fn signalChild(self: *const ProcessState, sig: u32) void {
        if (self.child_pidfd >= 0) {
            const rc = std.os.linux.pidfd_send_signal(
                self.child_pidfd,
                @fromBackingInt(@intCast(sig)),
                null,
                0,
            );

            switch (std.os.linux.errno(rc)) {
                .SUCCESS => return,
                .SRCH => {
                    log.debug("no process to send signal {d} for pid {d}", .{ sig, self.child });
                    return;
                },
                else => |e| {
                    log.err("unable to send signal to child: {s}", .{errName(e)});
                    return;
                },
            }
        }

        const target: std.os.linux.pid_t = @intCast(self.child);
        const ret = std.os.linux.kill(target, @fromBackingInt(@intCast(sig)));
        switch (std.os.linux.errno(ret)) {
            .SUCCESS => {},
            .SRCH => log.debug("no process to send signal {d} for pid {d}", .{ sig, self.child }),
            else => |e| log.err("unable to send signal to child: {s}", .{errName(e)}),
        }
    }

    fn signalProcessGroup(self: *const ProcessState, sig: u32) void {
        const outcome = process_group_signaller.signal(self.child_pidfd, self.child, sig);
        switch (outcome.kind) {
            .delivered => {},
            .unsupported_fell_back => log.debug(
                "pidfd process-group signalling unsupported, falling back to kill for {d}",
                .{sig},
            ),
            .gone => log.debug("no process group for signal {d} (pid {d})", .{ sig, self.child }),
            .failed => log.err("unable to send signal {d} to process group: {s}", .{
                sig, errName(outcome.errno),
            }),
        }
    }

    fn forwardSignal(self: *ProcessState, signo: u32) void {
        if (self.ignore_hup and signo == @backingInt(Sig.HUP)) {
            self.ignore_hup = false;
            return;
        }

        if (self.ignore_cont and signo == @backingInt(Sig.CONT)) {
            self.ignore_cont = false;
            return;
        }

        const signal_to_send = RewriteMap.apply(self.rewrites, signo);
        if (signal_to_send == 0) {
            log.debug("dropping signal {d}", .{signo});
            return;
        }

        log.debug("forwarding signal {d} as {d}", .{ signo, signal_to_send });
        if (self.forward_group) {
            self.signalProcessGroup(signal_to_send);
        } else {
            self.signalChild(signal_to_send);
        }
    }

    fn handleSignalEvent(self: *ProcessState) ?u8 {
        while (true) {
            var sig_info: std.os.linux.signalfd_siginfo = undefined;
            const info_bytes = std.mem.asBytes(&sig_info);
            const ret = std.os.linux.read(self.sigfd, info_bytes, info_bytes.len);

            switch (std.os.linux.errno(ret)) {
                .SUCCESS => {},
                .INTR => continue,
                .AGAIN => return null,
                else => |e| {
                    log.err("unable to read sigfd: {s}", .{errName(e)});
                    return 1;
                },
            }

            log.debug("receive signal: {d}", .{sig_info.signo});

            if (sig_info.signo != @backingInt(Sig.CHLD)) {
                if (isStandardSignal(sig_info.signo)) {
                    self.forwardSignal(sig_info.signo);
                } else {
                    log.debug("ignoring non-standard signal: {d}", .{sig_info.signo});
                }

                continue;
            }

            const reap = drainChildren(self.child, self.expected_exit) catch |err| {
                log.err("waitpid failed: {s}", .{@errorName(err)});
                return 1;
            };

            if (reap.main_code) |code| {
                if (reap.no_children) return code;
                if (self.shutdown == null) return self.beginShutdown(code);
            } else if (self.shutdown != null and reap.no_children) {
                return self.shutdown.?.exit_code;
            }
        }
    }

    fn beginShutdown(self: *ProcessState, exit_code: u8) ?u8 {
        const deadline = monotonicNs() + self.shutdown_timeout_ns;
        self.shutdown = .{ .exit_code = exit_code, .deadline_ns = deadline };
        self.signalProcessGroup(@backingInt(Sig.TERM));
        return null;
    }

    fn onShutdownTimeout(self: *ProcessState) ?u8 {
        const sd = &(self.shutdown orelse return null);

        self.signalProcessGroup(@backingInt(Sig.KILL));

        // Reap whatever has already died, but never wait indefinitely:
        // a descendant that is unkillable (e.g. in uninterruptible sleep) or that
        // escaped the process group must not keep zinit alive.
        // When running as PID 1 the kernel tears down the rest of the PID namespace on exit.
        _ = drainChildren(null, .empty) catch |err| {
            log.err("waitpid failed: {s}", .{@errorName(err)});
            return sd.exit_code;
        };

        return sd.exit_code;
    }
};

const ShutdownState = struct {
    exit_code: u8,
    /// CLOCK_MONOTONIC deadline (ns) at which the process group gets SIGKILLed.
    deadline_ns: u64,

    fn remainingMs(self: *const ShutdownState) i32 {
        const now = monotonicNs();
        if (now >= self.deadline_ns) return 0;
        const remaining_ns = self.deadline_ns - now;
        const ms = (remaining_ns + std.time.ns_per_ms - 1) / std.time.ns_per_ms;
        return @intCast(@min(ms, std.math.maxInt(i32)));
    }
};

fn monotonicNs() u64 {
    var ts: std.os.linux.timespec = undefined;
    // Raw syscall: avoids the vDSO fast-path setup that `std.os.linux.clock_gettime`
    // pulls in (we call this at most twice, so the vDSO is not worth its size).
    const clock = @as(u32, @bitCast(std.os.linux.CLOCK.MONOTONIC));
    _ = std.os.linux.syscall2(.clock_gettime, clock, @intFromPtr(&ts));
    return @as(u64, @intCast(ts.sec)) * std.time.ns_per_s + @as(u64, @intCast(ts.nsec));
}

fn tryClose(fd: std.os.linux.fd_t) void {
    if (fd < 0) return;

    while (true) {
        const close_rc = std.os.linux.close(fd);
        switch (std.os.linux.errno(close_rc)) {
            .SUCCESS => return,
            .INTR => continue,
            else => |err| {
                log.err("unable to close fd {d}: {s}", .{ @as(u64, @intCast(fd)), errName(err) });
                break;
            },
        }
    }
}

// The tests come in two layers. Unit tests (white-box, next to the code they
// cover) pin down behaviour and branch coverage of the module's entry points and
// helpers, and inject failures to reach paths a black-box caller cannot trigger
// (see the injectable syscalls in the pidfd fallback tests below). The CLI
// behaviour itself is covered black-box by `zig build test` running the binary.
test tryClose {
    tryClose(-1);
    const fd = std.os.linux.openat(
        std.os.linux.AT.FDCWD,
        "/dev/null",
        .{ .ACCMODE = .WRONLY },
        0o600,
    );

    try std.testing.expectEqual(std.os.linux.errno(fd), .SUCCESS);
    tryClose(@intCast(fd));
}

pub fn main(init: std.process.Init.Minimal) u8 {
    logInit();

    const args = switch (Args.parse(init) catch |err| {
        log.err("unable to parse arguments: {s}", .{@errorName(err)});
        // Usage shown because of an error is a diagnostic: send it to stderr,
        // keeping stdout for the program's requested output.
        printHelp(std.os.linux.STDERR_FILENO);
        return 1;
    }) {
        .run => |args| args,
        .help => {
            printHelp(std.os.linux.STDOUT_FILENO);
            return 0;
        },
        .version => {
            printVersion();
            return 0;
        },
    };

    setLogLevel(args.log_level);

    const unblocked_sigs = [_]Sig{ .ABRT, .BUS, .FPE, .ILL, .SEGV, .SYS, .TRAP, .TTIN, .TTOU };
    var sig_conf = SigConf.init(&unblocked_sigs) catch |err| {
        log.err("unable to handle signals: {s}", .{@errorName(err)});
        return 1;
    };

    // Subreaper mode is explicit: as PID 1 the kernel already
    // re-parents orphaned descendants to us, so nothing is needed. As any other
    // process we only adopt them when asked with `-s`. Warn when neither holds,
    // because then orphans are reaped by the real init, not here.
    if (args.subreaper) {
        const option = @backingInt(std.os.linux.PR.SET_CHILD_SUBREAPER);
        const ret = std.os.linux.prctl(option, 1, 0, 0, 0);
        switch (std.os.linux.errno(ret)) {
            .SUCCESS => {},
            else => |e| {
                log.err("unable to enable child subreaper mode: {s}", .{errName(e)});
                return 1;
            },
        }
    } else if (std.os.linux.getpid() != 1) {
        log.warn(
            \\not PID 1 and not a subreaper: orphaned descendants will not be reaped here,
            \\pass -s/--subreaper to adopt them
        ,
            .{},
        );
    }

    const child = args.spawn(&sig_conf) catch {
        log.err("failed to start child process", .{});
        return 1;
    };

    const child_pidfd: std.os.linux.fd_t = blk: {
        const raw = std.os.linux.pidfd_open(@intCast(child), 0);
        switch (std.os.linux.errno(raw)) {
            .SUCCESS => break :blk @intCast(raw),
            else => |e| {
                log.debug("pidfd_open failed ({s}), falling back to kill", .{errName(e)});
                break :blk -1;
            },
        }
    };
    defer if (child_pidfd >= 0) tryClose(child_pidfd);

    const sfd_flags = std.os.linux.SFD.NONBLOCK | std.os.linux.SFD.CLOEXEC;
    const sigfd = std.os.linux.signalfd(-1, &sig_conf.current_set, sfd_flags);
    switch (std.os.linux.errno(sigfd)) {
        .SUCCESS => {},
        else => |err| {
            log.err("unable to create signalfd: {s}", .{errName(err)});
            return 1;
        },
    }
    defer {
        log.debug("close signalfd", .{});
        tryClose(@intCast(sigfd));
    }

    var sig_pollfd = std.os.linux.pollfd{
        .fd = @intCast(sigfd),
        .events = std.os.linux.POLL.IN,
        .revents = 0,
    };

    var process_state = ProcessState{
        .child = child,
        .child_pidfd = child_pidfd,
        .expected_exit = args.expected_exit,
        .rewrites = args.rewrites,
        .sigfd = @intCast(sigfd),
        .forward_group = args.forward_group,
        .shutdown_timeout_ns = args.shutdown_timeout_ns,
        .ignore_cont = sig_conf.ignore_detached_sig,
        .ignore_hup = sig_conf.ignore_detached_sig,
    };

    while (true) {
        // While shutting down, bound the wait with poll's timeout:
        // infinite before the main child exits, the remaining grace period afterwards.
        const timeout: i32 = if (process_state.shutdown) |*sd| sd.remainingMs() else -1;
        const count = std.os.linux.poll(@ptrCast(&sig_pollfd), 1, timeout);
        switch (std.os.linux.errno(count)) {
            .SUCCESS => {},
            else => |e| {
                log.err("poll failed: {s}", .{errName(e)});
                return 1;
            },
        }

        if (count == 0) {
            // Grace period elapsed with no further events: SIGKILL and exit.
            if (process_state.onShutdownTimeout()) |exit_code| return exit_code;
            continue;
        }

        const poll_errors = std.os.linux.POLL.ERR | std.os.linux.POLL.HUP | std.os.linux.POLL.NVAL;
        if (sig_pollfd.revents & poll_errors != 0) {
            const revents: u64 = @intCast(sig_pollfd.revents);
            log.err("poll error on signalfd: revents=0x{x}", .{revents});
            continue;
        }

        if (sig_pollfd.revents & std.os.linux.POLL.IN != 0) {
            if (process_state.handleSignalEvent()) |exit_code| return exit_code;
        }
    }
}

test "parseSignal accepts numbers and names, rejects realtime and junk" {
    try std.testing.expectEqual(15, parseSignal("15") catch unreachable);
    try std.testing.expectEqual(15, parseSignal("SIGTERM") catch unreachable);
    try std.testing.expectEqual(15, parseSignal("TERM") catch unreachable);
    try std.testing.expectEqual(9, parseSignal("SIGKILL") catch unreachable);
    // Realtime signals are intentionally not supported.
    try std.testing.expectError(ZinitError.InvalidSignal, parseSignal("SIGRTMIN"));
    try std.testing.expectError(ZinitError.InvalidSignal, parseSignal("SIGRTMIN+2"));
    try std.testing.expectError(ZinitError.InvalidSignal, parseSignal("RTMAX-1"));
    try std.testing.expectError(ZinitError.InvalidSignal, parseSignal("34"));
    try std.testing.expectError(ZinitError.InvalidSignal, parseSignal("64"));
    try std.testing.expectError(ZinitError.InvalidSignal, parseSignal("UNKNOWN"));
    try std.testing.expectError(ZinitError.InvalidSignal, parseSignal("999"));
    try std.testing.expectError(ZinitError.InvalidSignal, parseSignal("0"));
    try std.testing.expectError(ZinitError.InvalidParams, parseSignal(""));
    try std.testing.expectError(ZinitError.InvalidSignal, parseSignal("SIG"));
    try std.testing.expectError(ZinitError.InvalidSignal, parseSignal("A"));
    const long_name = "SIG" ++ "AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA";
    try std.testing.expectError(ZinitError.InvalidSignal, parseSignal(long_name));
}

test "RewriteMap.parse rejects malformed, duplicate and cyclic rewrites" {
    var map: RewriteMap = .init();
    try map.parse("TERM:INT");
    const new_sig = map.get(15);
    try std.testing.expectEqual(2, new_sig);

    var emap: RewriteMap = .init();
    try std.testing.expectError(ZinitError.InvalidRewrite, emap.parse("TERM"));
    try std.testing.expectError(ZinitError.InvalidSignal, emap.parse("TERM:BAD"));
    try std.testing.expectError(ZinitError.DuplicateSignal, emap.parse("TERM:TERM"));
    try emap.parse("TERM:INT");
    try std.testing.expectError(ZinitError.DuplicateSignal, emap.parse("TERM:HUP"));
    emap.reset();
    try std.testing.expectError(ZinitError.InvalidRewrite, emap.parse("TERM:INT:EXTRA"));
    emap.set(1, 2);
    emap.set(2, 9);
    emap.set(9, 1);
    try std.testing.expectError(ZinitError.CycleRewrite, emap.parse("TERM:1"));

    // A two-node cycle is rejected when its closing edge is added, not only when
    // an already-cyclic map is probed.
    var cmap: RewriteMap = .init();
    try cmap.parse("TERM:INT");
    try std.testing.expectError(ZinitError.CycleRewrite, cmap.parse("INT:TERM"));

    // The closing edge may be "hidden" behind a longer chain: A->B->C, add C->A.
    var lmap: RewriteMap = .init();
    try lmap.parse("TERM:INT");
    try lmap.parse("INT:HUP");
    try std.testing.expectError(ZinitError.CycleRewrite, lmap.parse("HUP:TERM"));

    // Rewriting to 0 drops the signal: valid target, terminal (never a cycle),
    // and not accepted as a source.
    var dmap: RewriteMap = .init();
    try dmap.parse("TERM:0");
    try std.testing.expect(dmap.has(15));
    try std.testing.expectEqual(@as(u32, 0), dmap.get(15));
    try std.testing.expectError(ZinitError.InvalidSignal, dmap.parse("0:TERM"));
}

test "RewriteMap.reaches follows rewrite chains to a target" {
    var map: RewriteMap = .init();
    map.set(15, 2);
    try std.testing.expect(try map.reaches(15, 2));
    try std.testing.expect(!try map.reaches(15, 1));
    map.set(2, 9);
    try std.testing.expect(try map.reaches(15, 9));
    try std.testing.expect(!try map.reaches(15, 1));
    map.set(9, 15);
    try std.testing.expect(try map.reaches(2, 15));
    try std.testing.expect(try map.reaches(9, 1)); // loops -> defensive true

    map.reset();
    map.set(15, 0);
    try std.testing.expect(!try map.reaches(15, 2));

    try std.testing.expectError(ZinitError.InvalidParams, map.reaches(0, 2));
}

test "RewriteMap.apply maps, drops or passes a signal through" {
    var map: RewriteMap = .init();
    map.set(15, 2);
    try std.testing.expectEqual(2, RewriteMap.apply(map, 15));
    try std.testing.expectEqual(9, RewriteMap.apply(map, 9));
    try std.testing.expectEqual(15, RewriteMap.apply(null, 15));
    map.set(2, 0); // 0 means drop
    try std.testing.expectEqual(0, RewriteMap.apply(map, 2));
}

/// Fake syscall backend so the pidfd process-group fallback can be exercised
/// regardless of what the running kernel supports.
const FakePidfd = struct {
    var pidfd_calls: usize = 0;
    var kill_calls: usize = 0;
    var pidfd_errno: std.os.linux.E = .SUCCESS;

    fn pidfdSend(_: std.os.linux.fd_t, _: u32) std.os.linux.E {
        pidfd_calls += 1;
        return pidfd_errno;
    }

    fn killGroup(_: usize, _: u32) std.os.linux.E {
        kill_calls += 1;
        return .SUCCESS;
    }

    fn signaller() ProcessGroupSignaller {
        pidfd_calls = 0;
        kill_calls = 0;
        pidfd_errno = .SUCCESS;
        return .{ .pidfd_send = pidfdSend, .kill_group = killGroup };
    }
};

test "process group signaller falls back to kill when the pidfd flag is unsupported" {
    for ([_]std.os.linux.E{ .INVAL, .NOSYS }) |err| {
        var s = FakePidfd.signaller();
        FakePidfd.pidfd_errno = err;

        const outcome = s.signal(3, 4242, 15);
        try std.testing.expectEqual(GroupSendKind.unsupported_fell_back, outcome.kind);
        try std.testing.expectEqual(@as(?bool, false), s.support);
        try std.testing.expectEqual(@as(usize, 1), FakePidfd.pidfd_calls);
        try std.testing.expectEqual(@as(usize, 1), FakePidfd.kill_calls);

        // The cached `false` prevents any further pidfd attempts.
        _ = s.signal(3, 4242, 9);
        try std.testing.expectEqual(@as(usize, 1), FakePidfd.pidfd_calls);
        try std.testing.expectEqual(@as(usize, 2), FakePidfd.kill_calls);
    }
}

test "process group signaller uses pidfd when supported" {
    var s = FakePidfd.signaller();
    const outcome = s.signal(3, 4242, 15);
    try std.testing.expectEqual(GroupSendKind.delivered, outcome.kind);
    try std.testing.expectEqual(@as(?bool, true), s.support);
    try std.testing.expectEqual(@as(usize, 1), FakePidfd.pidfd_calls);
    try std.testing.expectEqual(@as(usize, 0), FakePidfd.kill_calls);
}

test "process group signaller skips pidfd without a descriptor" {
    var s = FakePidfd.signaller();
    const outcome = s.signal(-1, 4242, 15);
    try std.testing.expectEqual(GroupSendKind.delivered, outcome.kind);
    try std.testing.expectEqual(@as(usize, 0), FakePidfd.pidfd_calls);
    try std.testing.expectEqual(@as(usize, 1), FakePidfd.kill_calls);
    try std.testing.expectEqual(@as(?bool, null), s.support);
}

test "process group signaller classifies gone and failed" {
    // pidfd understands the flag but the process group is already gone.
    var s = FakePidfd.signaller();
    FakePidfd.pidfd_errno = .SRCH;
    var outcome = s.signal(3, 4242, 15);
    try std.testing.expectEqual(GroupSendKind.gone, outcome.kind);
    try std.testing.expectEqual(@as(?bool, true), s.support);
    try std.testing.expectEqual(@as(usize, 0), FakePidfd.kill_calls);

    // An unexpected error keeps the cache untouched.
    var s2 = FakePidfd.signaller();
    FakePidfd.pidfd_errno = .PERM;
    outcome = s2.signal(3, 4242, 15);
    try std.testing.expectEqual(GroupSendKind.failed, outcome.kind);
    try std.testing.expectEqual(std.os.linux.E.PERM, outcome.errno);
    try std.testing.expectEqual(@as(?bool, null), s2.support);
}

test "signalIsIgnored reflects the installed disposition" {
    const ign = std.os.linux.Sigaction{
        .handler = .{ .handler = Sig.IGN },
        .mask = std.os.linux.sigemptyset(),
        .flags = 0,
    };

    const dfl = std.os.linux.Sigaction{
        .handler = .{ .handler = Sig.DFL },
        .mask = std.os.linux.sigemptyset(),
        .flags = 0,
    };

    var saved: std.os.linux.Sigaction = undefined;
    const rc = std.os.linux.sigaction(Sig.USR2, &ign, &saved);
    try std.testing.expectEqual(std.os.linux.E.SUCCESS, std.os.linux.errno(rc));
    defer _ = std.os.linux.sigaction(Sig.USR2, &saved, null);

    try std.testing.expect(signalIsIgnored(Sig.USR2));
    const rc2 = std.os.linux.sigaction(Sig.USR2, &dfl, null);
    try std.testing.expectEqual(std.os.linux.E.SUCCESS, std.os.linux.errno(rc2));
    try std.testing.expect(!signalIsIgnored(Sig.USR2));
}

test "Args.parse maps argv, environment and options" {
    const allocator = std.testing.allocator;
    var env_map: std.process.Environ.Map = .init(allocator);
    defer env_map.deinit();
    try env_map.put("ZINIT_TEST_KEY", "1");
    const environ: std.process.Environ = .{ .block = try env_map.createPosixBlock(allocator, .{}) };
    defer environ.block.deinit(allocator);

    const vector = [_][*:0]const u8{
        "zinit", "--log-level", "debug", "-s",
        "-n",    "-p",          "TERM",  "-e",
        "143",   "-e",          "130",   "--",
        "foo",   "--bar=x",
    };
    const init: std.process.Init.Minimal = .{
        .args = .{ .vector = &vector },
        .environ = environ,
    };

    const args = switch (try Args.parse(init)) {
        .run => |a| a,
        else => return error.TestUnexpectedResult,
    };

    try std.testing.expectEqual(std.log.Level.debug, args.log_level);
    try std.testing.expectEqual(@as(?u32, 15), args.pdeath_signal);
    try std.testing.expect(args.expected_exit.isSet(143));
    try std.testing.expect(args.expected_exit.isSet(130));
    try std.testing.expect(!args.expected_exit.isSet(1));
    try std.testing.expect(args.subreaper);
    try std.testing.expect(args.new_session);

    try std.testing.expectEqualStrings("foo", std.mem.span(args.argv[0].?));
    try std.testing.expectEqualStrings("--bar=x", std.mem.span(args.argv[1].?));

    var found_env = false;
    for (args.envs) |entry| {
        const raw = entry orelse continue;
        if (std.mem.eql(u8, std.mem.span(raw), "ZINIT_TEST_KEY=1")) found_env = true;
    }

    try std.testing.expect(found_env);
}

test "Args.parse rejects a missing command" {
    const env = [_:null]?[*:0]const u8{};
    const environ: std.process.Environ = .{ .block = .{ .slice = &env } };

    const argvs = [_][]const [*:0]const u8{
        &.{"zinit"}, &.{ "zinit", "--" }, &.{ "zinit", "-s", "--" },
    };
    for (argvs) |argv| {
        const init: std.process.Init.Minimal = .{ .args = .{ .vector = argv }, .environ = environ };
        try std.testing.expectError(ZinitError.InvalidParams, Args.parse(init));
    }
}

test "group forwarding: -g is independent of --new-session" {
    const allocator = std.testing.allocator;
    var env_map: std.process.Environ.Map = .init(allocator);
    defer env_map.deinit();
    const environ: std.process.Environ = .{ .block = try env_map.createPosixBlock(allocator, .{}) };
    defer environ.block.deinit(allocator);

    const cases = [_]struct { argv: []const [*:0]const u8, group: bool, session: bool }{
        .{ .argv = &.{ "zinit", "--", "cmd" }, .group = false, .session = false },
        .{ .argv = &.{ "zinit", "-g", "--", "cmd" }, .group = true, .session = false },
        .{ .argv = &.{ "zinit", "--new-session", "--", "cmd" }, .group = false, .session = true },
    };

    for (cases) |c| {
        const init: std.process.Init.Minimal = .{
            .args = .{ .vector = c.argv },
            .environ = environ,
        };

        const args = switch (try Args.parse(init)) {
            .run => |a| a,
            else => return error.TestUnexpectedResult,
        };

        try std.testing.expectEqual(c.group, args.forward_group);
        try std.testing.expectEqual(c.session, args.new_session);
    }
}

test "-r is repeatable (one OLD:NEW per flag)" {
    const allocator = std.testing.allocator;
    var env_map: std.process.Environ.Map = .init(allocator);
    defer env_map.deinit();
    const environ: std.process.Environ = .{ .block = try env_map.createPosixBlock(allocator, .{}) };
    defer environ.block.deinit(allocator);

    {
        const V = [_][*:0]const u8{ "zinit", "-r", "TERM:INT", "-r", "HUP:USR1", "--", "cmd" };
        const init: std.process.Init.Minimal = .{ .args = .{ .vector = &V }, .environ = environ };
        const args = switch (try Args.parse(init)) {
            .run => |a| a,
            else => return error.TestUnexpectedResult,
        };

        const rm = args.rewrites orelse return error.TestUnexpectedResult;
        try std.testing.expectEqual(@as(u32, 2), rm.get(15)); // TERM -> INT
        try std.testing.expectEqual(@as(u32, 10), rm.get(1)); // HUP -> USR1
    }

    {
        // The same source signal twice is still rejected.
        const V = [_][*:0]const u8{ "zinit", "-r", "TERM:INT", "-r", "TERM:HUP", "--", "cmd" };
        const init: std.process.Init.Minimal = .{ .args = .{ .vector = &V }, .environ = environ };
        try std.testing.expectError(ZinitError.DuplicateSignal, Args.parse(init));
    }
}

test "-V and --version are recognized" {
    const allocator = std.testing.allocator;
    var env_map: std.process.Environ.Map = .init(allocator);
    defer env_map.deinit();
    const environ: std.process.Environ = .{ .block = try env_map.createPosixBlock(allocator, .{}) };
    defer environ.block.deinit(allocator);

    for ([_][]const [*:0]const u8{ &.{ "zinit", "-V" }, &.{ "zinit", "--version" } }) |argv| {
        const init: std.process.Init.Minimal = .{ .args = .{ .vector = argv }, .environ = environ };
        switch (try Args.parse(init)) {
            .version => {},
            else => return error.TestUnexpectedResult,
        }
    }
}

test "WaitStatus.exitCode maps wait statuses to exit codes" {
    try std.testing.expectEqual(@as(u8, 42), (WaitStatus{ .raw = @as(u32, 42) << 8 }).exitCode());
    try std.testing.expectEqual(@as(u8, 128 + 9), (WaitStatus{ .raw = 9 }).exitCode());
    try std.testing.expectEqual(@as(u8, 0), (WaitStatus{ .raw = 0x1FF }).exitCode());
}

test execExitCode {
    try std.testing.expectEqual(@as(u8, 127), execExitCode(.NOENT));
    try std.testing.expectEqual(@as(u8, 126), execExitCode(.ACCES));
    try std.testing.expectEqual(@as(u8, 126), execExitCode(.NOEXEC));
    try std.testing.expectEqual(@as(u8, 1), execExitCode(.INVAL));
}
