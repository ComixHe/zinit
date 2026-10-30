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
const log = @import("log.zig");
const config = @import("config");

const ConfigError = errors.ConfigError;
const Sig = signal.Sig;
const writeAll = io.writeAll;
const ExitCodeSet = wait.ExitCodeSet;

const default_shutdown_timeout_s: u64 = 5;

fn shutdownTimeoutFrom(environ: std.process.Environ, explicit: ?u64) ?u64 {
    if (explicit) |seconds| return seconds;

    const text = environ.getPosix("ZINIT_SHUTDOWN_TIMEOUT") orelse
        return default_shutdown_timeout_s;
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
    const map = &session_rewrites.*.?;

    const to_stop = [_]u32{ @backingInt(Sig.TSTP), @backingInt(Sig.TTOU), @backingInt(Sig.TTIN) };
    for (to_stop) |from| {
        if ((map.target(from) catch unreachable) == null)
            map.set(from, @backingInt(Sig.STOP)) catch unreachable;
    }
}

fn parseLogLevel(text: []const u8) ?std.log.Level {
    if (std.ascii.eqlIgnoreCase(text, "error")) return .err;
    if (std.ascii.eqlIgnoreCase(text, "warn")) return .warn;
    if (std.ascii.eqlIgnoreCase(text, "info")) return .info;
    if (std.ascii.eqlIgnoreCase(text, "debug")) return .debug;
    return null;
}

fn logLevelText(level: std.log.Level) [:0]const u8 {
    return switch (level) {
        .err => "error",
        .warn => "warn",
        .info => "info",
        .debug => "debug",
    };
}

pub const Args = struct {
    log_level: std.log.Level,
    pdeath_signal: ?u32,
    rewrites: ?rewrite.Map,
    expected_exit: ExitCodeSet,
    subreaper: bool,
    new_session: bool,
    forward_group: bool,
    tracing_child: bool,
    shutdown_timeout_ns: u64,
    argv: [*:null]const ?[*:0]const u8,
    envs: [:null]const ?[*:0]const u8,

    const Action = union(enum) {
        run: Args,
        help,
        version,
    };

    /// What the option scan collected. Cross-option checks and environment
    /// merging happen in `resolve`, so `scan` stays a pure argv pass.
    const Scanned = struct {
        rewrite_map: ?rewrite.Map = null,
        log_level: ?std.log.Level = null,
        pdeath_signal: ?u32 = null,
        expected_exit: ExitCodeSet = .empty,
        shutdown_timeout_s: ?u64 = null,
        child_start: ?usize = null,
        subreaper: bool = false,
        new_session: bool = false,
        forward_group: bool = false,
        help: bool = false,
        version: bool = false,
    };

    // Verbatim help output: breaking a line here would change what --help prints.
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
        \\  -t, --shutdown-timeout <SECS> (Env: ZINIT_SHUTDOWN_TIMEOUT)  Descendant cleanup grace after exit (default 5)
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
        const text = comptime blk: {
            @setEvalBranchQuota(20_000);
            break :blk std.fmt.comptimePrint(help_text, .{logLevelText(log.default_level)});
        };

        _ = writeAll(fd, text);
    }

    pub fn printVersion(fd: std.os.linux.fd_t) void {
        _ = writeAll(fd, config.version ++ "\n");
    }

    fn reject(err: ConfigError, problem: []const u8, token: []const u8) ConfigError {
        log.err("{s}: {s}", .{ problem, token });
        return err;
    }

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

    fn lookup(arg: []const u8) ?Option {
        for (option_specs) |spec| {
            if (str.eql(arg, spec.long)) return spec.kind;
            if (arg.len == 2 and arg[0] == '-' and arg[1] == spec.short) return spec.kind;
        }

        return null;
    }

    /// Inlined: `err` is a constant at every call site, so the missing-value path
    /// is specialized instead of going through one shared copy.
    inline fn takeValue(
        vector: []const [*:0]const u8,
        index: *usize,
        arg: []const u8,
        err: ConfigError,
    ) ConfigError![:0]const u8 {
        index.* += 1;
        if (index.* >= vector.len) return reject(err, "missing value for", arg);
        return std.mem.span(vector[index.*]);
    }

    fn resolveLogLevel(
        init: std.process.Init.Minimal,
        from_flag: ?std.log.Level,
    ) ConfigError!std.log.Level {
        const requested: ?std.log.Level = from_flag orelse blk: {
            const text = init.environ.getPosix("ZINIT_LOG_LEVEL") orelse break :blk null;
            break :blk parseLogLevel(text) orelse
                return reject(ConfigError.InvalidParams, "unknown ZINIT_LOG_LEVEL", text);
        };

        const level = requested orelse return log.default_level;
        if (@backingInt(level) > @backingInt(config.max_log_level)) {
            const ceiling = comptime logLevelText(
                @fromBackingInt(@intCast(@backingInt(config.max_log_level))),
            );

            const asked = logLevelText(level);
            log.err("this build prints up to {s}; rebuild with -Dlog-level={s} for {s}", .{
                ceiling, asked, asked,
            });

            return ConfigError.InvalidParams;
        }

        return level;
    }

    /// Walks argv once and records the options. Each value is validated where
    /// it is parsed; the combination is checked by `resolve`.
    fn scan(vector: []const [*:0]const u8) ConfigError!Scanned {
        var options: Scanned = .{};

        var i: usize = 1;
        while (i < vector.len) : (i += 1) {
            const arg = std.mem.span(vector[i]);

            if (str.eql(arg, "--")) {
                i += 1;
                if (i < vector.len) options.child_start = i;
                break;
            }

            const option = lookup(arg) orelse {
                if (arg.len > 0 and arg[0] == '-') {
                    @branchHint(.unlikely);
                    return reject(ConfigError.InvalidParams, "unknown option", arg);
                }

                options.child_start = i;
                break;
            };

            switch (option) {
                .help => options.help = true,
                .version => options.version = true,
                .new_session => options.new_session = true,
                .subreaper => options.subreaper = true,
                .forward_group => options.forward_group = true,
                .shutdown_timeout => {
                    const v = try takeValue(vector, &i, arg, ConfigError.InvalidParams);
                    options.shutdown_timeout_s = str.parseDecimal(u64, v) catch
                        return reject(
                            ConfigError.InvalidParams,
                            "invalid --shutdown-timeout value",
                            v,
                        );
                },
                .log_level => {
                    const v = try takeValue(vector, &i, arg, ConfigError.InvalidParams);
                    options.log_level = parseLogLevel(v) orelse
                        return reject(ConfigError.InvalidParams, "unknown log level", v);
                },
                .signal => {
                    if (options.pdeath_signal != null) {
                        return reject(ConfigError.InvalidParams, "duplicate option", arg);
                    }

                    const v = try takeValue(vector, &i, arg, ConfigError.InvalidParams);
                    options.pdeath_signal = signal.parse(v) catch |e|
                        return reject(e, "unknown signal", v);
                },
                .rewrite => {
                    if (options.rewrite_map == null) options.rewrite_map = rewrite.Map.init();
                    const v = try takeValue(vector, &i, arg, ConfigError.InvalidRewrite);
                    options.rewrite_map.?.parse(v) catch |e|
                        return reject(e, "invalid --rewrite value", v);
                },
                .expect_exit => {
                    const v = try takeValue(vector, &i, arg, ConfigError.InvalidExitCode);
                    const code = str.parseDecimal(u8, v) catch
                        return reject(
                            ConfigError.InvalidExitCode,
                            "invalid --expect-exit code",
                            v,
                        );

                    options.expected_exit.set(code);
                },
            }
        }

        return options;
    }

    /// Merges the environment, validates the combination and builds the action.
    fn resolve(init: std.process.Init.Minimal, options: Scanned) ConfigError!Action {
        if (options.help and options.version) {
            @branchHint(.unlikely);
            log.err("cannot combine: -h/--help and -V/--version", .{});
            return ConfigError.InvalidParams;
        }

        if (options.help) return .help;

        if (options.version) return .version;

        const start = options.child_start orelse {
            @branchHint(.unlikely);
            log.err("no command to run", .{});
            return ConfigError.MissingCommand;
        };

        const log_level = try resolveLogLevel(init, options.log_level);

        const shutdown_timeout_s_final = shutdownTimeoutFrom(
            init.environ,
            options.shutdown_timeout_s,
        ) orelse {
            @branchHint(.unlikely);
            log.err("invalid ZINIT_SHUTDOWN_TIMEOUT value: expected seconds", .{});
            return ConfigError.InvalidParams;
        };

        if (shutdown_timeout_s_final > std.math.maxInt(u64) / std.time.ns_per_s) {
            @branchHint(.unlikely);
            log.err("shutdown timeout is too large", .{});
            return ConfigError.InvalidParams;
        }

        const subreaper = options.subreaper or init.environ.getPosix("ZINIT_SUBREAPER") != null;
        const tracing_child = tracingChildFrom(init.environ);

        var rewrite_map = options.rewrite_map;
        if (options.new_session) applySessionRewrites(&rewrite_map);

        const argv_base: [*:null]const ?[*:0]const u8 = @ptrCast(init.args.vector.ptr);

        return .{ .run = .{
            .log_level = log_level,
            .pdeath_signal = options.pdeath_signal,
            .rewrites = rewrite_map,
            .expected_exit = options.expected_exit,
            .subreaper = subreaper,
            .new_session = options.new_session,
            .forward_group = options.forward_group,
            .tracing_child = tracing_child,
            .shutdown_timeout_ns = shutdown_timeout_s_final * std.time.ns_per_s,
            .argv = argv_base + start,
            .envs = init.environ.block.slice,
        } };
    }

    pub fn parse(init: std.process.Init.Minimal) !Action {
        return resolve(init, try scan(init.args.vector));
    }
};

// kcov-exclude-tests (everything below is test-only).
fn asVector(items: [:null]const ?[*:0]const u8) []const [*:0]const u8 {
    return @as([*]const [*:0]const u8, @ptrCast(items.ptr))[0..items.len];
}

test "Args.parse maps argv, environment and options" {
    const allocator = std.testing.allocator;
    var env_map: std.process.Environ.Map = .init(allocator);
    defer env_map.deinit();
    try env_map.put("ZINIT_TEST_KEY", "1");
    const environ: std.process.Environ = .{ .block = try env_map.createPosixBlock(allocator, .{}) };
    defer environ.block.deinit(allocator);

    const ceiling = comptime logLevelText(@fromBackingInt(@intCast(@backingInt(config.max_log_level))));
    const vector = [_:null]?[*:0]const u8{
        "zinit", "--log-level", ceiling, "-s",
        "-n",    "-p",          "TERM",  "-e",
        "143",   "-e",          "130",   "--",
        "foo",   "--bar=x",
    };

    const init: std.process.Init.Minimal = .{
        .args = .{ .vector = asVector(&vector) },
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

    const argvs = [_][:null]const ?[*:0]const u8{
        &.{"zinit"}, &.{ "zinit", "--" }, &.{ "zinit", "-s", "--" },
    };

    for (argvs) |argv| {
        const init: std.process.Init.Minimal = .{ .args = .{ .vector = asVector(argv) }, .environ = environ };
        try std.testing.expectError(ConfigError.MissingCommand, Args.parse(init));
    }
}

test "group forwarding: -g is independent of --new-session" {
    const environ: std.process.Environ = .empty;

    const cases = [_]struct { argv: [:null]const ?[*:0]const u8, group: bool, session: bool }{
        .{ .argv = &.{ "zinit", "--", "cmd" }, .group = false, .session = false },
        .{ .argv = &.{ "zinit", "-g", "--", "cmd" }, .group = true, .session = false },
        .{ .argv = &.{ "zinit", "--new-session", "--", "cmd" }, .group = false, .session = true },
    };

    for (cases) |c| {
        const init: std.process.Init.Minimal = .{
            .args = .{ .vector = asVector(c.argv) },
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
    const environ: std.process.Environ = .empty;

    const stop = @backingInt(Sig.STOP);
    const tstp = @backingInt(Sig.TSTP);
    const ttou = @backingInt(Sig.TTOU);
    const ttin = @backingInt(Sig.TTIN);

    {
        // A new session is the tty's "suspend" reaching a child that cannot catch it.
        const V = [_:null]?[*:0]const u8{ "zinit", "--new-session", "--", "cmd" };
        const init: std.process.Init.Minimal = .{ .args = .{ .vector = asVector(&V) }, .environ = environ };
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
        const V = [_:null]?[*:0]const u8{ "zinit", "--", "cmd" };
        const init: std.process.Init.Minimal = .{ .args = .{ .vector = asVector(&V) }, .environ = environ };
        const args = switch (try Args.parse(init)) {
            .run => |a| a,
            else => return error.TestUnexpectedResult,
        };

        try std.testing.expect(args.rewrites == null);
    }

    {
        // A rewrite the user asked for stands, and only that one.
        const V = [_:null]?[*:0]const u8{ "zinit", "--new-session", "-r", "TSTP:CONT", "--", "cmd" };
        const init: std.process.Init.Minimal = .{ .args = .{ .vector = asVector(&V) }, .environ = environ };
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
    const environ: std.process.Environ = .empty;

    {
        const V = [_:null]?[*:0]const u8{ "zinit", "-r", "TERM:INT", "-r", "HUP:USR1", "--", "cmd" };
        const init: std.process.Init.Minimal = .{ .args = .{ .vector = asVector(&V) }, .environ = environ };
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
        const V = [_:null]?[*:0]const u8{ "zinit", "-r", "TERM:INT", "-r", "TERM:HUP", "--", "cmd" };
        const init: std.process.Init.Minimal = .{ .args = .{ .vector = asVector(&V) }, .environ = environ };
        try std.testing.expectError(ConfigError.DuplicateSignal, Args.parse(init));
    }
}

test "-V and --version are recognized" {
    const environ: std.process.Environ = .empty;

    const versions = [_][:null]const ?[*:0]const u8{
        &.{ "zinit", "-V" },
        &.{ "zinit", "--version" },
    };

    for (versions) |argv| {
        const init: std.process.Init.Minimal = .{ .args = .{ .vector = asVector(argv) }, .environ = environ };
        switch (try Args.parse(init)) {
            .version => {},
            else => return error.TestUnexpectedResult,
        }
    }
}

/// Drain what the logger wrote into `buf`; a non-blocking pipe reports the
/// drained end as `WouldBlock`, which is not an error here.
fn drainLog(file: std.Io.File, test_io: std.Io, buf: []u8) ![]u8 {
    var total: usize = 0;
    while (total < buf.len) {
        var iov = [_][]u8{buf[total..]};
        const n = file.readStreaming(test_io, &iov) catch |err| switch (err) {
            error.WouldBlock => break,
            else => return err,
        };

        if (n == 0) break;
        total += n;
    }
    return buf[0..total];
}

test "a rejected argument is named, not left to the usage text" {
    const test_io = std.testing.io;
    const fds = try std.Io.Threaded.pipe2(.{ .NONBLOCK = true });
    const reader = std.Io.File{ .handle = fds[0], .flags = .{ .nonblocking = true } };
    const writer = std.Io.File{ .handle = fds[1], .flags = .{ .nonblocking = true } };
    defer reader.close(test_io);
    defer writer.close(test_io);

    defer log.deinit();
    log.setRuntimeLevel(.err);
    defer log.setRuntimeLevel(.warn);

    const env = [_:null]?[*:0]const u8{};
    const environ: std.process.Environ = .{ .block = .{ .slice = &env } };
    var buf: [256]u8 = undefined;

    const cases = [_]struct { argv: [:null]const ?[*:0]const u8, kind: []const u8, token: []const u8 }{
        // The `--opt=value` spelling this CLI does not take: the token is still the answer.
        .{ .argv = &.{ "zinit", "-Z", "--", "true" }, .kind = "option", .token = "-Z" },
        .{ .argv = &.{ "zinit", "--log-level=debug", "--", "true" }, .kind = "option", .token = "--log-level=debug" },
        // A value an option cannot take is named with the value, not just the option.
        .{ .argv = &.{ "zinit", "--log-level", "loud", "--", "true" }, .kind = "log level", .token = "loud" },
    };

    for (cases) |case| {
        try log.init(writer.handle);

        try std.testing.expectError(
            ConfigError.InvalidParams,
            Args.parse(.{ .args = .{ .vector = asVector(case.argv) }, .environ = environ }),
        );

        const named = try drainLog(reader, test_io, &buf);
        try std.testing.expect(std.mem.find(u8, named, case.kind) != null);
        try std.testing.expect(std.mem.find(u8, named, case.token) != null);
    }

    const allocator = std.testing.allocator;
    var env_map: std.process.Environ.Map = .init(allocator);
    defer env_map.deinit();
    try env_map.put("ZINIT_LOG_LEVEL", "loud");
    const from_env: std.process.Environ = .{ .block = try env_map.createPosixBlock(allocator, .{}) };
    defer from_env.block.deinit(allocator);

    try log.init(writer.handle);

    const argv = [_:null]?[*:0]const u8{ "zinit", "--", "true" };
    try std.testing.expectError(
        ConfigError.InvalidParams,
        Args.parse(.{ .args = .{ .vector = asVector(&argv) }, .environ = from_env }),
    );

    const named = try drainLog(reader, test_io, &buf);
    try std.testing.expect(std.mem.find(u8, named, "ZINIT_LOG_LEVEL") != null);
    try std.testing.expect(std.mem.find(u8, named, "loud") != null);
}

test "-t is parsed, and the first non-option needs no --" {
    const env = [_:null]?[*:0]const u8{};
    const environ: std.process.Environ = .{ .block = .{ .slice = &env } };

    const argv = [_:null]?[*:0]const u8{ "zinit", "-t", "7", "foo", "--bar" };
    const args = switch (try Args.parse(.{ .args = .{ .vector = asVector(&argv) }, .environ = environ })) {
        .run => |a| a,
        else => return error.TestUnexpectedResult,
    };

    try std.testing.expectEqual(7 * std.time.ns_per_s, args.shutdown_timeout_ns);
    try std.testing.expectEqualStrings("foo", std.mem.span(args.argv[0].?));
    try std.testing.expectEqualStrings("--bar", std.mem.span(args.argv[1].?));

    const bad = [_:null]?[*:0]const u8{ "zinit", "-t", "soon", "--", "true" };
    try std.testing.expectError(ConfigError.InvalidParams, Args.parse(.{
        .args = .{ .vector = asVector(&bad) },
        .environ = environ,
    }));
}

test "help and version together are a usage error" {
    const env = [_:null]?[*:0]const u8{};
    const environ: std.process.Environ = .{ .block = .{ .slice = &env } };

    const both = [_:null]?[*:0]const u8{ "zinit", "-h", "-V" };
    try std.testing.expectError(ConfigError.InvalidParams, Args.parse(.{ .args = .{ .vector = asVector(&both) }, .environ = environ }));
}

test "an unrepresentable shutdown timeout is rejected, not overflowed" {
    const env = [_:null]?[*:0]const u8{};
    const environ: std.process.Environ = .{ .block = .{ .slice = &env } };

    const huge_digits = [_:null]?[*:0]const u8{ "zinit", "-t", "99999999999999999999", "--", "true" };
    try std.testing.expectError(ConfigError.InvalidParams, Args.parse(.{
        .args = .{ .vector = asVector(&huge_digits) },
        .environ = environ,
    }));

    const huge_seconds = [_:null]?[*:0]const u8{ "zinit", "-t", "20000000000", "--", "true" };
    try std.testing.expectError(ConfigError.InvalidParams, Args.parse(.{
        .args = .{ .vector = asVector(&huge_seconds) },
        .environ = environ,
    }));

    const allocator = std.testing.allocator;
    var env_map: std.process.Environ.Map = .init(allocator);
    defer env_map.deinit();
    try env_map.put("ZINIT_SHUTDOWN_TIMEOUT", "99999999999999999999");
    const env_environ: std.process.Environ = .{ .block = try env_map.createPosixBlock(allocator, .{}) };
    defer env_environ.block.deinit(allocator);

    const runnable = [_:null]?[*:0]const u8{ "zinit", "--", "true" };
    try std.testing.expectError(ConfigError.InvalidParams, Args.parse(.{
        .args = .{ .vector = asVector(&runnable) },
        .environ = env_environ,
    }));

    const edge = [_:null]?[*:0]const u8{
        "zinit", "-t", "18446744073", "--", "true",
    };

    const args = switch (try Args.parse(.{ .args = .{ .vector = asVector(&edge) }, .environ = environ })) {
        .run => |a| a,
        else => return error.TestUnexpectedResult,
    };

    try std.testing.expectEqual(18446744073 * std.time.ns_per_s, args.shutdown_timeout_ns);
}

test "ZINIT_SUBREAPER is presence-only, ZINIT_TRACING_CHILD takes ON/OFF" {
    const allocator = std.testing.allocator;
    const argv = [_:null]?[*:0]const u8{ "zinit", "--", "true" };

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

        const args = switch (try Args.parse(.{ .args = .{ .vector = asVector(&argv) }, .environ = environ })) {
            .run => |a| a,
            else => return error.TestUnexpectedResult,
        };

        try std.testing.expectEqual(case.subreaper, args.subreaper);
        try std.testing.expectEqual(case.tracing, args.tracing_child);
        try std.testing.expectEqualStrings("true", std.mem.span(args.argv[0].?));
    }
}

test "Args.parse never panics on arbitrary argv and environment" {
    const Context = struct {
        fn testOne(_: @This(), smith: *std.testing.Smith) anyerror!void {
            var raw: [512]u8 = undefined;
            const n: usize = smith.slice(&raw);

            var text: [raw.len + 1]u8 = undefined;
            @memcpy(text[0..n], raw[0..n]);
            text[n] = 0;

            var vector: [65]?[*:0]const u8 = undefined;
            vector[0] = "zinit";
            var count: usize = 1;

            var env_bytes: [4096]u8 = undefined;
            var env_fba = std.heap.FixedBufferAllocator.init(&env_bytes);
            var env_map: std.process.Environ.Map = .init(env_fba.allocator());

            var tokens = std.mem.splitScalar(u8, text[0..n], 0);
            while (tokens.next()) |token| {
                if (count + 1 < vector.len) {
                    vector[count] = @ptrCast(token.ptr);
                    count += 1;
                }

                if (std.mem.findScalar(u8, token, '=')) |eq| {
                    if (eq > 0 and env_map.count() < 8) {
                        env_map.put(token[0..eq], token[eq + 1 ..]) catch {};
                    }
                }
            }

            const environ: std.process.Environ = .{
                .block = env_map.createPosixBlock(env_fba.allocator(), .{}) catch
                    std.process.Environ.empty.block,
            };

            vector[count] = null;

            _ = Args.parse(.{
                .args = .{ .vector = asVector(vector[0..count :null]) },
                .environ = environ,
            }) catch {};
        }
    };

    return std.testing.fuzz(Context{}, Context.testOne, .{
        .corpus = &.{
            // The test runner feeds corpus entries as `Smith.in`, its first four
            // bytes are the little-endian payload length, not parser input.
            // Empty tokens exceed argv capacity; keep a slot for its NULL terminator.
            "\x50\x00\x00\x00" ++ @as([80]u8, @splat(0)),
            "\x05\x00\x00\x00" ++ "-t\x0031",
            "\x11\x00\x00\x00" ++ "--log-level\x00debug",
            "\x07\x00\x00\x00" ++ "-p\x00TERM",
            "\x0b\x00\x00\x00" ++ "-r\x00TERM:INT",
            "\x0d\x00\x00\x00" ++ "-e\x00143\x00-e\x00130",
            "\x08\x00\x00\x00" ++ "-s\x00-n\x00-g",
            "\x0c\x00\x00\x00" ++ "--\x00/bin/true",
            "\x11\x00\x00\x00" ++ "ZINIT_SUBREAPER=1",
            "\x16\x00\x00\x00" ++ "ZINIT_TRACING_CHILD=ON",
            "\x15\x00\x00\x00" ++ "ZINIT_LOG_LEVEL=debug",
            "\x22\x00\x00\x00" ++ "ZINIT_SHUTDOWN_TIMEOUT=18446744073",
        },
    });
}

test "a log level above the build ceiling is rejected" {
    if (config.max_log_level == .debug) return;

    const env = [_:null]?[*:0]const u8{};
    const environ: std.process.Environ = .{ .block = .{ .slice = &env } };
    const above = if (config.max_log_level == .info) "debug" else "info";
    const argv = [_:null]?[*:0]const u8{ "zinit", "--log-level", above, "--", "true" };

    try std.testing.expectError(
        ConfigError.InvalidParams,
        Args.parse(.{ .args = .{ .vector = asVector(&argv) }, .environ = environ }),
    );
}

test "the runtime default is the build's default, clamped to its ceiling" {
    const env = [_:null]?[*:0]const u8{};
    const environ: std.process.Environ = .{ .block = .{ .slice = &env } };
    const argv = [_:null]?[*:0]const u8{ "zinit", "--", "true" };

    const args = switch (try Args.parse(.{ .args = .{ .vector = asVector(&argv) }, .environ = environ })) {
        .run => |a| a,
        else => return error.TestUnexpectedResult,
    };

    const expected = @min(
        @backingInt(config.default_log_level),
        @backingInt(config.max_log_level),
    );

    try std.testing.expectEqual(expected, @backingInt(args.log_level));
}
