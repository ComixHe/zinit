// SPDX-FileCopyrightText: 2026 YuMing He <ComixHe1895@outlook.com>
//
// SPDX-License-Identifier: MIT

//! Command line: what the options mean, and the messages that explain them.

const std = @import("std");

const errors = @import("errors.zig");
const str = @import("str.zig");
const signal = @import("signal.zig");
const rewrite = @import("rewrite.zig");
const wait = @import("wait.zig");
const io = @import("io.zig");
const fmt = @import("fmt.zig");
const log = @import("log.zig");
const config = @import("config");

const ZinitError = errors.ZinitError;
const Sig = signal.Sig;
const writeAll = io.writeAll;
const ExitCodeSet = wait.ExitCodeSet;

const default_shutdown_timeout_s: u64 = 5;

fn shutdownTimeoutFrom(environ: std.process.Environ, explicit: ?u64) ?u64 {
    if (explicit) |seconds| return seconds;

    const text = environ.getPosix("ZINIT_SHUTDOWN_TIMEOUT") orelse return default_shutdown_timeout_s;
    return str.parseDecimal(u64, text) catch null;
}

fn tracingChildFrom(environ: std.process.Environ) bool {
    const text = environ.getPosix("ZINIT_TRACING_CHILD") orelse return config.tracing_child;
    if (std.ascii.eqlIgnoreCase(text, "OFF")) return false;
    if (std.ascii.eqlIgnoreCase(text, "ON")) return true;
    return config.tracing_child;
}

fn applySessionRewrites(session_rewrites: *?rewrite.Map) void {
    if (session_rewrites.* == null) session_rewrites.* = .init();

    const stop = @backingInt(Sig.STOP);
    const to_stop = [_]u32{ @backingInt(Sig.TSTP), @backingInt(Sig.TTOU), @backingInt(Sig.TTIN) };
    for (to_stop) |from| {
        if (session_rewrites.*.?.target(from) == null) session_rewrites.*.?.set(from, stop);
    }
}

fn parseLogLevel(text: []const u8) ?std.log.Level {
    if (std.ascii.eqlIgnoreCase(text, "error")) return .err;
    if (std.ascii.eqlIgnoreCase(text, "warn")) return .warn;
    if (std.ascii.eqlIgnoreCase(text, "info")) return .info;
    if (std.ascii.eqlIgnoreCase(text, "debug")) return .debug;
    return null;
}

/// `parseLogLevel` back, in the spelling the command line uses (the enum tag is `err`).
fn logLevelText(level: std.log.Level) [:0]const u8 {
    return switch (level) {
        .err => "error",
        .warn => "warn",
        .info => "info",
        .debug => "debug",
    };
}

fn stdinIsTerminal() bool {
    var termios: std.os.linux.termios = undefined;
    const rc = std.os.linux.tcgetattr(std.os.linux.STDIN_FILENO, &termios);
    return std.os.linux.errno(rc) == .SUCCESS;
}

pub const Args = struct {
    log_level: std.log.Level,
    pdeath_signal: ?u32,
    rewrites: ?rewrite.Map,
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

    const help_text =
        \\zinit - A tiny init for linux containers.
        \\
        \\Usage: zinit [options] <ARG>...
        \\
        \\Options:
        \\  -h, --help                                                   Display this help and exit
        \\  -V, --version                                                Output version information and exit
        \\      --log-level <LEVEL> (Env: ZINIT_LOG_LEVEL)               Set log level: error, warn, info, or debug (default {s})
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
    ;

    pub fn printHelp(fd: std.os.linux.fd_t) void {
        var buf: [help_text.len + 8]u8 = undefined;
        writeAll(fd, fmt.bufPrint(&buf, help_text, .{logLevelText(log.defaultLevel())}));
    }

    pub fn printVersion(fd: std.os.linux.fd_t) void {
        var buf: [64]u8 = undefined;
        const text = fmt.bufPrint(&buf, "{d}.{d}.{d}\n", .{
            config.version.major,
            config.version.minor,
            config.version.patch,
        });

        writeAll(fd, text);
    }

    fn reject(err: ZinitError, problem: []const u8, token: []const u8) ZinitError {
        log.err("{s}: {s}", .{ problem, token });
        return err;
    }

    /// Every option this CLI knows, so the loop below is a table lookup rather than one
    /// comparison per option.
    const Option = enum {
        help,
        version,
        log_level,
        signal,
        subreaper,
        new_session,
        forward_group,
        shutdown_timeout,
        rewrite,
        expect_exit,
    };

    /// `short` is the letter after `-`, or `0` when the option has no short form.
    const OptionSpec = struct { long: []const u8, short: u8, kind: Option };

    const option_specs = [_]OptionSpec{
        .{ .long = "--help", .short = 'h', .kind = .help },
        .{ .long = "--version", .short = 'V', .kind = .version },
        .{ .long = "--log-level", .short = 0, .kind = .log_level },
        .{ .long = "--signal", .short = 'p', .kind = .signal },
        .{ .long = "--subreaper", .short = 's', .kind = .subreaper },
        .{ .long = "--new-session", .short = 'n', .kind = .new_session },
        .{ .long = "--forward-group", .short = 'g', .kind = .forward_group },
        .{ .long = "--shutdown-timeout", .short = 't', .kind = .shutdown_timeout },
        .{ .long = "--rewrite", .short = 'r', .kind = .rewrite },
        .{ .long = "--expect-exit", .short = 'e', .kind = .expect_exit },
    };

    /// The option an argument names, if it names one.
    fn lookup(arg: []const u8) ?Option {
        for (option_specs) |spec| {
            if (str.eql(arg, spec.long)) return spec.kind;
            if (arg.len == 2 and arg[0] == '-' and arg[1] == spec.short) return spec.kind;
        }

        return null;
    }

    /// The value after an option, or a refusal naming the option.
    fn take(iter: *std.process.Args.Iterator, arg: []const u8, err: ZinitError) ZinitError![:0]const u8 {
        return iter.next() orelse return reject(err, "missing value for", arg);
    }

    /// What was asked for, or the build's default; refused when above its ceiling.
    fn resolveLogLevel(init: std.process.Init.Minimal, from_flag: ?std.log.Level) ZinitError!std.log.Level {
        const requested: ?std.log.Level = from_flag orelse blk: {
            const text = init.environ.getPosix("ZINIT_LOG_LEVEL") orelse break :blk null;
            break :blk parseLogLevel(text) orelse
                return reject(ZinitError.InvalidParams, "unknown ZINIT_LOG_LEVEL", text);
        };
        const level = requested orelse log.defaultLevel();

        if (requested != null and @backingInt(level) > @backingInt(config.max_log_level)) {
            const ceiling = logLevelText(@fromBackingInt(@intCast(@backingInt(config.max_log_level))));
            const asked = logLevelText(level);
            log.err("this build prints up to {s}; rebuild with -Dlog-level={s} for {s}", .{
                ceiling, asked, asked,
            });

            return ZinitError.InvalidParams;
        }

        return level;
    }

    pub fn parse(init: std.process.Init.Minimal) !Action {
        var args_iter = init.args.iterate();
        defer args_iter.deinit();
        _ = args_iter.skip();

        var rewrite_map: ?rewrite.Map = null;

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
            if (str.eql(arg, "--")) {
                const next = init.args.vector.len - args_iter.inner.remaining.len;
                if (next < init.args.vector.len) child_start = next;
                break;
            }

            const option = lookup(arg) orelse {
                if (arg.len > 0 and arg[0] == '-') {
                    return reject(ZinitError.InvalidParams, "unknown option", arg);
                }

                child_start = init.args.vector.len - args_iter.inner.remaining.len - 1;
                break;
            };

            switch (option) {
                .help => has_help = true,
                .version => has_version = true,
                .new_session => new_session = true,
                .subreaper => subreaper_flag = true,
                .forward_group => forward_group = true,
                .shutdown_timeout => {
                    const v = try take(&args_iter, arg, ZinitError.InvalidParams);
                    shutdown_timeout_s = str.parseDecimal(u64, v) catch
                        return reject(ZinitError.InvalidParams, "invalid --shutdown-timeout value", v);
                },
                .log_level => {
                    const v = try take(&args_iter, arg, ZinitError.InvalidParams);
                    log_level_opt = parseLogLevel(v) orelse
                        return reject(ZinitError.InvalidParams, "unknown log level", v);
                },
                .signal => {
                    if (pdeath_signal != null) {
                        return reject(ZinitError.InvalidParams, "duplicate option", arg);
                    }
                    const v = try take(&args_iter, arg, ZinitError.InvalidParams);
                    pdeath_signal = signal.parse(v) catch |e| return reject(e, "unknown signal", v);
                },
                .rewrite => {
                    if (rewrite_map == null) rewrite_map = rewrite.Map.init();
                    const v = try take(&args_iter, arg, ZinitError.InvalidRewrite);
                    rewrite_map.?.parse(v) catch |e| return reject(e, "invalid --rewrite value", v);
                },
                .expect_exit => {
                    const v = try take(&args_iter, arg, ZinitError.InvalidExitCode);
                    const code = str.parseDecimal(u8, v) catch
                        return reject(ZinitError.InvalidExitCode, "invalid --expect-exit code", v);
                    expected_exit.set(code);
                },
            }
        }

        if (has_help and has_version) {
            log.err("cannot combine: -h/--help and -V/--version", .{});
            return ZinitError.InvalidParams;
        }
        if (has_help) return .help;
        if (has_version) return .version;

        const start = child_start orelse {
            log.err("no command to run", .{});
            return ZinitError.MissingCommand;
        };

        const log_level = try resolveLogLevel(init, log_level_opt);

        const shutdown_timeout_s_final = shutdownTimeoutFrom(init.environ, shutdown_timeout_s) orelse {
            log.err("invalid ZINIT_SHUTDOWN_TIMEOUT value: expected seconds", .{});
            return ZinitError.InvalidParams;
        };

        if (shutdown_timeout_s_final > std.math.maxInt(u64) / std.time.ns_per_s) {
            log.err("shutdown timeout is too large", .{});
            return ZinitError.InvalidParams;
        }

        const subreaper = subreaper_flag or init.environ.getPosix("ZINIT_SUBREAPER") != null;
        const tracing_child = tracingChildFrom(init.environ);

        if (new_session) applySessionRewrites(&rewrite_map);
        const is_terminal = stdinIsTerminal();

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
};

// kcov-exclude-tests (everything below is test-only).
test "Args.parse maps argv, environment and options" {
    const allocator = std.testing.allocator;
    var env_map: std.process.Environ.Map = .init(allocator);
    defer env_map.deinit();
    try env_map.put("ZINIT_TEST_KEY", "1");
    const environ: std.process.Environ = .{ .block = try env_map.createPosixBlock(allocator, .{}) };
    defer environ.block.deinit(allocator);

    const ceiling = comptime logLevelText(@fromBackingInt(@intCast(@backingInt(config.max_log_level))));
    const vector = [_][*:0]const u8{
        "zinit", "--log-level", ceiling, "-s",
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

    try std.testing.expectEqual(@backingInt(config.max_log_level), @backingInt(args.log_level));
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
        if (str.eql(std.mem.span(raw), "ZINIT_TEST_KEY=1")) found_env = true;
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
        try std.testing.expectError(ZinitError.MissingCommand, Args.parse(init));
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

test "session mode rewrites the job control signals, unless -r overrides" {
    const allocator = std.testing.allocator;
    var env_map: std.process.Environ.Map = .init(allocator);
    defer env_map.deinit();
    const environ: std.process.Environ = .{ .block = try env_map.createPosixBlock(allocator, .{}) };
    defer environ.block.deinit(allocator);

    const stop = @backingInt(Sig.STOP);
    const tstp = @backingInt(Sig.TSTP);
    const ttou = @backingInt(Sig.TTOU);
    const ttin = @backingInt(Sig.TTIN);

    {
        // A new session is the tty's "suspend" reaching a child that cannot catch it.
        const V = [_][*:0]const u8{ "zinit", "--new-session", "--", "cmd" };
        const init: std.process.Init.Minimal = .{ .args = .{ .vector = &V }, .environ = environ };
        const args = switch (try Args.parse(init)) {
            .run => |a| a,
            else => return error.TestUnexpectedResult,
        };

        const rm = args.rewrites orelse return error.TestUnexpectedResult;
        try std.testing.expectEqual(@as(?u32, stop), rm.target(tstp));
        try std.testing.expectEqual(@as(?u32, stop), rm.target(ttou));
        try std.testing.expectEqual(@as(?u32, stop), rm.target(ttin));
    }

    {
        // Without it the child stays in our session and gets the terminal signals directly.
        const V = [_][*:0]const u8{ "zinit", "--", "cmd" };
        const init: std.process.Init.Minimal = .{ .args = .{ .vector = &V }, .environ = environ };
        const args = switch (try Args.parse(init)) {
            .run => |a| a,
            else => return error.TestUnexpectedResult,
        };

        try std.testing.expect(args.rewrites == null);
    }

    {
        // A rewrite the user asked for stands, and only that one.
        const V = [_][*:0]const u8{ "zinit", "--new-session", "-r", "TSTP:CONT", "--", "cmd" };
        const init: std.process.Init.Minimal = .{ .args = .{ .vector = &V }, .environ = environ };
        const args = switch (try Args.parse(init)) {
            .run => |a| a,
            else => return error.TestUnexpectedResult,
        };

        const rm = args.rewrites orelse return error.TestUnexpectedResult;
        try std.testing.expectEqual(@as(?u32, @backingInt(Sig.CONT)), rm.target(tstp));
        try std.testing.expectEqual(@as(?u32, stop), rm.target(ttou));
        try std.testing.expectEqual(@as(?u32, stop), rm.target(ttin));
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
        try std.testing.expectEqual(@as(?u32, 2), rm.target(15)); // TERM -> INT
        try std.testing.expectEqual(@as(?u32, 10), rm.target(1)); // HUP -> USR1
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

test "a rejected argument is named, not left to the usage text" {
    // Read what the logger wrote: in a test the sink starts silent.
    var pipe: [2]std.os.linux.fd_t = undefined;
    try std.testing.expectEqual(
        std.os.linux.E.SUCCESS,
        std.os.linux.errno(std.os.linux.pipe2(&pipe, .{ .NONBLOCK = true })),
    );

    defer io.tryClose(pipe[0]);
    defer io.tryClose(pipe[1]);
    log.init(pipe[1]);
    defer log.init(log.default_sink);
    log.setLevel(.err);
    defer log.setLevel(.warn);

    const env = [_:null]?[*:0]const u8{};
    const environ: std.process.Environ = .{ .block = .{ .slice = &env } };
    var buf: [256]u8 = undefined;

    const cases = [_]struct { argv: []const [*:0]const u8, says: []const u8 }{
        // The `--opt=value` spelling this CLI does not take: the token is still the answer.
        .{ .argv = &.{ "zinit", "-Z", "--", "true" }, .says = "unknown option: -Z" },
        .{ .argv = &.{ "zinit", "--log-level=debug", "--", "true" }, .says = "unknown option: --log-level=debug" },
        // A value an option cannot take is named with the value, not just the option.
        .{ .argv = &.{ "zinit", "--log-level", "loud", "--", "true" }, .says = "unknown log level: loud" },
    };

    for (cases) |case| {
        try std.testing.expectError(
            ZinitError.InvalidParams,
            Args.parse(.{ .args = .{ .vector = case.argv }, .environ = environ }),
        );

        const named = std.posix.read(pipe[0], &buf) catch 0;
        try std.testing.expect(std.mem.indexOf(u8, buf[0..named], case.says) != null);
    }

    // The environment holds the same values and is named the same way.
    const allocator = std.testing.allocator;
    var env_map: std.process.Environ.Map = .init(allocator);
    defer env_map.deinit();
    try env_map.put("ZINIT_LOG_LEVEL", "loud");
    const from_env: std.process.Environ = .{ .block = try env_map.createPosixBlock(allocator, .{}) };
    defer from_env.block.deinit(allocator);

    const argv = [_][*:0]const u8{ "zinit", "--", "true" };
    try std.testing.expectError(
        ZinitError.InvalidParams,
        Args.parse(.{ .args = .{ .vector = &argv }, .environ = from_env }),
    );
    const named = std.posix.read(pipe[0], &buf) catch 0;
    try std.testing.expect(std.mem.indexOf(u8, buf[0..named], "unknown ZINIT_LOG_LEVEL: loud") != null);
}

test "-t/--shutdown-timeout is parsed, and the first non-option needs no --" {
    const env = [_:null]?[*:0]const u8{};
    const environ: std.process.Environ = .{ .block = .{ .slice = &env } };

    const argv = [_][*:0]const u8{ "zinit", "-t", "7", "foo", "--bar" };
    const args = switch (try Args.parse(.{ .args = .{ .vector = &argv }, .environ = environ })) {
        .run => |a| a,
        else => return error.TestUnexpectedResult,
    };

    try std.testing.expectEqual(7 * std.time.ns_per_s, args.shutdown_timeout_ns);
    // The first non-option starts the child argv, with no `--` needed.
    try std.testing.expectEqualStrings("foo", std.mem.span(args.argv[0].?));
    try std.testing.expectEqualStrings("--bar", std.mem.span(args.argv[1].?));

    const bad = [_][*:0]const u8{ "zinit", "-t", "soon", "--", "true" };
    try std.testing.expectError(ZinitError.InvalidParams, Args.parse(.{
        .args = .{ .vector = &bad },
        .environ = environ,
    }));
}

test "help and version together are a usage error" {
    const env = [_:null]?[*:0]const u8{};
    const environ: std.process.Environ = .{ .block = .{ .slice = &env } };

    const both = [_][*:0]const u8{ "zinit", "-h", "-V" };
    try std.testing.expectError(ZinitError.InvalidParams, Args.parse(.{ .args = .{ .vector = &both }, .environ = environ }));
}

test "an unrepresentable shutdown timeout is rejected, not overflowed" {
    const env = [_:null]?[*:0]const u8{};
    const environ: std.process.Environ = .{ .block = .{ .slice = &env } };

    // Too many digits for the u64 parser.
    const huge_digits = [_][*:0]const u8{ "zinit", "-t", "99999999999999999999", "--", "true" };
    try std.testing.expectError(ZinitError.InvalidParams, Args.parse(.{
        .args = .{ .vector = &huge_digits },
        .environ = environ,
    }));

    // Parses fine as seconds, but overflows seconds→ns.
    const huge_seconds = [_][*:0]const u8{ "zinit", "-t", "20000000000", "--", "true" };
    try std.testing.expectError(ZinitError.InvalidParams, Args.parse(.{
        .args = .{ .vector = &huge_seconds },
        .environ = environ,
    }));

    // The same guard applies to the environment variable.
    const allocator = std.testing.allocator;
    var env_map: std.process.Environ.Map = .init(allocator);
    defer env_map.deinit();
    try env_map.put("ZINIT_SHUTDOWN_TIMEOUT", "99999999999999999999");
    const env_environ: std.process.Environ = .{ .block = try env_map.createPosixBlock(allocator, .{}) };
    defer env_environ.block.deinit(allocator);

    const runnable = [_][*:0]const u8{ "zinit", "--", "true" };
    try std.testing.expectError(ZinitError.InvalidParams, Args.parse(.{
        .args = .{ .vector = &runnable },
        .environ = env_environ,
    }));

    const edge = [_][*:0]const u8{
        "zinit", "-t", "18446744073", "--", "true",
    };
    const args = switch (try Args.parse(.{ .args = .{ .vector = &edge }, .environ = environ })) {
        .run => |a| a,
        else => return error.TestUnexpectedResult,
    };

    try std.testing.expectEqual(18446744073 * std.time.ns_per_s, args.shutdown_timeout_ns);
}

test "ZINIT_SUBREAPER is presence-only, ZINIT_TRACING_CHILD takes ON/OFF" {
    const allocator = std.testing.allocator;
    const argv = [_][*:0]const u8{ "zinit", "--", "true" };

    const Case = struct { key: []const u8, value: []const u8, subreaper: bool, tracing: bool };
    const cases = [_]Case{
        .{ .key = "ZINIT_SUBREAPER", .value = "OFF", .subreaper = true, .tracing = config.tracing_child },
        .{ .key = "ZINIT_TRACING_CHILD", .value = "OFF", .subreaper = false, .tracing = false },
        .{ .key = "ZINIT_TRACING_CHILD", .value = "ON", .subreaper = false, .tracing = true },
        // Anything else is not a yes: it leaves the build's own default in place.
        .{ .key = "ZINIT_TRACING_CHILD", .value = "MAYBE", .subreaper = false, .tracing = config.tracing_child },
    };

    for (cases) |case| {
        var env_map: std.process.Environ.Map = .init(allocator);
        defer env_map.deinit();
        try env_map.put(case.key, case.value);
        const environ: std.process.Environ = .{ .block = try env_map.createPosixBlock(allocator, .{}) };
        defer environ.block.deinit(allocator);

        const args = switch (try Args.parse(.{ .args = .{ .vector = &argv }, .environ = environ })) {
            .run => |a| a,
            else => return error.TestUnexpectedResult,
        };
        try std.testing.expectEqual(case.subreaper, args.subreaper);
        try std.testing.expectEqual(case.tracing, args.tracing_child);
        try std.testing.expectEqualStrings("true", std.mem.span(args.argv[0].?));
    }
}

test "Args.parse never panics on arbitrary argv and environment" {
    // Any input yields an Action or an error, never a panic; `=` also makes an env entry.
    const Context = struct {
        fn testOne(_: @This(), smith: *std.testing.Smith) anyerror!void {
            var raw: [512]u8 = undefined;
            const n: usize = smith.slice(&raw);

            var text: [raw.len + 1]u8 = undefined;
            @memcpy(text[0..n], raw[0..n]);
            text[n] = 0;

            var vector: [64][*:0]const u8 = undefined;
            vector[0] = "zinit";
            var count: usize = 1;

            var env_bytes: [4096]u8 = undefined;
            var env_fba = std.heap.FixedBufferAllocator.init(&env_bytes);
            var env_map: std.process.Environ.Map = .init(env_fba.allocator());

            var tokens = std.mem.splitScalar(u8, text[0..n], 0);
            while (tokens.next()) |token| {
                if (count < vector.len) {
                    vector[count] = @ptrCast(token.ptr);
                    count += 1;
                }

                if (std.mem.indexOfScalar(u8, token, '=')) |eq| {
                    if (eq > 0 and env_map.count() < 8) {
                        env_map.put(token[0..eq], token[eq + 1 ..]) catch {};
                    }
                }
            }

            const environ: std.process.Environ = .{
                .block = env_map.createPosixBlock(env_fba.allocator(), .{}) catch
                    std.process.Environ.empty.block,
            };

            _ = Args.parse(.{
                .args = .{ .vector = vector[0..count] },
                .environ = environ,
            }) catch {};
        }
    };

    return std.testing.fuzz(Context{}, Context.testOne, .{ .corpus = &.{
        "-t\x0031",
        "--log-level\x00debug",
        "-p\x00TERM",
        "-r\x00TERM:INT",
        "-e\x00143\x00-e\x00130",
        "-s\x00-n\x00-g",
        "--\x00/bin/true",
        "ZINIT_SUBREAPER=1",
        "ZINIT_TRACING_CHILD=ON",
        "ZINIT_LOG_LEVEL=debug",
        "ZINIT_SHUTDOWN_TIMEOUT=18446744073",
    } });
}

test "a log level above the build ceiling is rejected" {
    // Nothing is above the ceiling in a build configured for `debug`.
    if (config.max_log_level == .debug) return;

    const env = [_:null]?[*:0]const u8{};
    const environ: std.process.Environ = .{ .block = .{ .slice = &env } };
    const above = if (config.max_log_level == .info) "debug" else "info";
    const argv = [_][*:0]const u8{ "zinit", "--log-level", above, "--", "true" };

    // Refused rather than silently ignored: the binary cannot print it.
    try std.testing.expectError(
        ZinitError.InvalidParams,
        Args.parse(.{ .args = .{ .vector = &argv }, .environ = environ }),
    );
}

test "the runtime default is the build's default, clamped to its ceiling" {
    const env = [_:null]?[*:0]const u8{};
    const environ: std.process.Environ = .{ .block = .{ .slice = &env } };
    const argv = [_][*:0]const u8{ "zinit", "--", "true" };

    const args = switch (try Args.parse(.{ .args = .{ .vector = &argv }, .environ = environ })) {
        .run => |a| a,
        else => return error.TestUnexpectedResult,
    };

    const expected = @min(
        @backingInt(config.default_log_level),
        @backingInt(config.max_log_level),
    );

    try std.testing.expectEqual(expected, @backingInt(args.log_level));
}
