// SPDX-FileCopyrightText: 2026 YuMing He <ComixHe1895@outlook.com>
//
// SPDX-License-Identifier: MIT

//! Command line: what the options mean, and the messages that explain them.

const std = @import("std");
const fuzz_input = @import("fuzz_input.zig");
const checks = @import("checks.zig");

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

fn shutdownTimeoutFrom(envs: [:null]const ?[*:0]const u8, explicit: ?u64) ?u64 {
    if (explicit) |seconds| return seconds;

    const text = str.getEnv(envs, "ZINIT_SHUTDOWN_TIMEOUT") orelse
        return default_shutdown_timeout_s;
    return str.parseDecimal(u64, text) catch null;
}

fn tracingChildFrom(envs: [:null]const ?[*:0]const u8) bool {
    const text = str.getEnv(envs, "ZINIT_TRACING_CHILD") orelse return config.tracing_child;
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

    const help_text =
        \\zinit - A tiny init for linux containers.
        \\
        \\Usage: zinit [options] <ARG>...
        \\
        \\Options:
        \\  -h, --help  Display this help and exit
        \\  -V, --version  Output version information and exit
        \\  --log-level <LEVEL> (Env: ZINIT_LOG_LEVEL)  Set log level: error, warn, info, or debug (default {s})
        \\  -p, --signal <SIGNAL>  The triggered signal when parent process dies
        \\  -s, --subreaper (Env: ZINIT_SUBREAPER)  Enable child subreaper mode
        \\  -n, --new-session  Enable new session mode
        \\  -g, --forward-group  Forward signals to the whole process group
        \\  -t, --shutdown-timeout <SECS> (Env: ZINIT_SHUTDOWN_TIMEOUT)  Descendant cleanup grace after exit (default 5)
        \\  -r, --rewrite <OLD:NEW>...  Rewrite a forwarded signal before sending to the child
        \\  (repeatable; use "0" as NEW to drop the signal)
        \\  -e, --expect-exit <CODE>...  Map child exit codes to 0 (repeatable)
        \\
        \\Environment variables:
        \\  ZINIT_TRACING_CHILD: If set, zinit will wait for SIGUSR1 to continue executing child process
        \\
        \\Homepage: https://github.com/ComixHe/zinit
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

    inline fn rejectDuplicate(is_set: bool, arg: []const u8) ConfigError!void {
        if (is_set) return reject(ConfigError.InvalidParams, "duplicate option", arg);
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
            const text = str.getEnv(init.environ.block.slice, "ZINIT_LOG_LEVEL") orelse break :blk null;
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
                    @branchHint(.cold);
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
                .shutdown_timeout => try setTimeout(&options, vector, &i, arg),
                .log_level => try setLogLevel(&options, vector, &i, arg),
                .signal => try setSignal(&options, vector, &i, arg),
                .rewrite => try addRewrite(&options, vector, &i, arg),
                .expect_exit => try addExpectedExit(&options, vector, &i, arg),
            }
        }

        return options;
    }

    inline fn setTimeout(
        options: *Scanned,
        vector: []const [*:0]const u8,
        i: *usize,
        arg: []const u8,
    ) ConfigError!void {
        try rejectDuplicate(options.shutdown_timeout_s != null, arg);

        const v = try takeValue(vector, i, arg, ConfigError.InvalidParams);
        options.shutdown_timeout_s = str.parseDecimal(u64, v) catch
            return reject(ConfigError.InvalidParams, "invalid --shutdown-timeout value", v);
    }

    inline fn setLogLevel(
        options: *Scanned,
        vector: []const [*:0]const u8,
        i: *usize,
        arg: []const u8,
    ) ConfigError!void {
        try rejectDuplicate(options.log_level != null, arg);

        const v = try takeValue(vector, i, arg, ConfigError.InvalidParams);
        options.log_level = parseLogLevel(v) orelse
            return reject(ConfigError.InvalidParams, "unknown log level", v);
    }

    inline fn setSignal(
        options: *Scanned,
        vector: []const [*:0]const u8,
        i: *usize,
        arg: []const u8,
    ) ConfigError!void {
        try rejectDuplicate(options.pdeath_signal != null, arg);

        const v = try takeValue(vector, i, arg, ConfigError.InvalidParams);
        options.pdeath_signal = signal.parse(v) catch |e|
            return reject(e, "unknown signal", v);
    }

    inline fn addRewrite(
        options: *Scanned,
        vector: []const [*:0]const u8,
        i: *usize,
        arg: []const u8,
    ) ConfigError!void {
        if (options.rewrite_map == null) options.rewrite_map = rewrite.Map.init();
        const v = try takeValue(vector, i, arg, ConfigError.InvalidRewrite);
        options.rewrite_map.?.parse(v) catch |e|
            return reject(e, "invalid --rewrite value", v);
    }

    inline fn addExpectedExit(
        options: *Scanned,
        vector: []const [*:0]const u8,
        i: *usize,
        arg: []const u8,
    ) ConfigError!void {
        const v = try takeValue(vector, i, arg, ConfigError.InvalidExitCode);
        const code = str.parseDecimal(u8, v) catch
            return reject(ConfigError.InvalidExitCode, "invalid --expect-exit code", v);

        options.expected_exit.set(code);
    }

    /// Merges the environment, validates the combination and builds the action.
    fn resolve(init: std.process.Init.Minimal, options: Scanned) ConfigError!Action {
        if (options.help and options.version) {
            @branchHint(.cold);
            log.err("cannot combine: -h/--help and -V/--version", .{});
            return ConfigError.InvalidParams;
        }

        if (options.help) return .help;

        if (options.version) return .version;

        const start = options.child_start orelse {
            @branchHint(.cold);
            log.err("no command to run", .{});
            return ConfigError.MissingCommand;
        };

        checks.check(start < init.args.vector.len, "args: child command start outside the argument vector");
        const log_level = try resolveLogLevel(init, options.log_level);

        const shutdown_timeout_s_final = shutdownTimeoutFrom(
            init.environ.block.slice,
            options.shutdown_timeout_s,
        ) orelse {
            @branchHint(.cold);
            log.err("invalid ZINIT_SHUTDOWN_TIMEOUT value: expected seconds", .{});
            return ConfigError.InvalidParams;
        };

        if (shutdown_timeout_s_final > std.math.maxInt(u64) / std.time.ns_per_s) {
            @branchHint(.cold);
            log.err("shutdown timeout is too large", .{});
            return ConfigError.InvalidParams;
        }

        const subreaper = options.subreaper or str.getEnv(init.environ.block.slice, "ZINIT_SUBREAPER") != null;
        const tracing_child = tracingChildFrom(init.environ.block.slice);

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

    pub fn parse(init: std.process.Init.Minimal) ConfigError!Action {
        return resolve(init, try scan(init.args.vector));
    }
};

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

            const action = Args.parse(.{
                .args = .{ .vector = @as([*]const [*:0]const u8, @ptrCast(vector[0..count :null].ptr))[0..count] },
                .environ = environ,
            }) catch return;

            switch (action) {
                .run => |parsed| {
                    try std.testing.expect(parsed.argv[0] != null);
                    try std.testing.expectEqual(
                        @as(u64, 0),
                        parsed.shutdown_timeout_ns % std.time.ns_per_s,
                    );

                    if (parsed.pdeath_signal) |sig| {
                        try std.testing.expect(signal.isStandard(sig));
                    }

                    if (parsed.rewrites) |map| {
                        var sig: u32 = 1;
                        while (sig < std.os.linux.NSIG) : (sig += 1) {
                            const target = try map.target(sig);
                            if (target) |rewritten| {
                                try std.testing.expect(
                                    rewritten == 0 or signal.isStandard(rewritten),
                                );
                            }
                        }
                    }
                },
                .help, .version => {},
            }
        }
    };

    return std.testing.fuzz(Context{}, Context.testOne, .{
        .corpus = &.{
            // fuzz_input.slice encodes Smith's little-endian length prefix.
            // Empty tokens exceed argv capacity; keep a slot for the NULL terminator.
            fuzz_input.slice(&@as([80]u8, @splat(0))),
            fuzz_input.slice("-t\x0031"),
            fuzz_input.slice("--log-level\x00debug"),
            fuzz_input.slice("-p\x00TERM"),
            fuzz_input.slice("-r\x00TERM:INT"),
            fuzz_input.slice("-e\x00143\x00-e\x00130"),
            fuzz_input.slice("-s\x00-n\x00-g"),
            fuzz_input.slice("--\x00/bin/true"),
            fuzz_input.slice("-t\x005\x00--\x00/bin/true"),
            fuzz_input.slice("-s\x00--\x00/bin/true"),
            fuzz_input.slice("-r\x00TERM:INT\x00--\x00/bin/true"),
            fuzz_input.slice("--log-level\x00info\x00--\x00/bin/true"),
            fuzz_input.slice("ZINIT_SUBREAPER=1"),
            fuzz_input.slice("ZINIT_TRACING_CHILD=ON"),
            fuzz_input.slice("ZINIT_LOG_LEVEL=debug"),
            fuzz_input.slice("ZINIT_SHUTDOWN_TIMEOUT=18446744073"),
            fuzz_input.slice("-n\x00--\x00/bin/true"),
            fuzz_input.slice("-n\x00-r\x00TSTP:INT\x00--\x00/bin/true"),
            fuzz_input.slice("-n\x00-r\x00TTIN:0\x00--\x00/bin/true"),
            fuzz_input.slice("-n\x00-r\x00TSTP:0\x00--\x00/bin/true"),
            fuzz_input.slice("-p\x00SIGTERM\x00--\x00/bin/true"),
            fuzz_input.slice("-p\x00sigterm\x00--\x00/bin/true"),
            fuzz_input.slice("-p\x0034\x00--\x00/bin/true"),
            fuzz_input.slice("-p\x0099999999999999999999\x00--\x00/bin/true"),
            fuzz_input.slice("--log-level\x00junk"),
            fuzz_input.slice("ZINIT_LOG_LEVEL=junk"),
            fuzz_input.slice("ZINIT_TRACING_CHILD=MAYBE"),
            fuzz_input.slice("ZINIT_SHUTDOWN_TIMEOUT=junk"),
            fuzz_input.slice("ZINIT_SHUTDOWN_TIMEOUT=18446744073709551616"),
            fuzz_input.slice("-h"),
            fuzz_input.slice("-h\x00-V"),
            fuzz_input.slice(""),
            fuzz_input.slice("-t\x001\x00-t\x002"),
            fuzz_input.slice("--log-level\x00info\x00--log-level\x00info"),
            fuzz_input.slice("-t"),
            fuzz_input.slice("-t\x0018446744073709551616"),
            fuzz_input.slice("-r\x00TERM"),
            fuzz_input.slice("-r\x00TERM:"),
            fuzz_input.slice("-r\x00TERM:INTRA"),
            fuzz_input.slice("-e\x00300"),
            fuzz_input.slice("--log-level\x00junk\x00--\x00/bin/true"),
            fuzz_input.slice("ZINIT_LOG_LEVEL=junk\x00--\x00/bin/true"),
            fuzz_input.slice("ZINIT_TRACING_CHILD=MAYBE\x00--\x00/bin/true"),
            fuzz_input.slice("ZINIT_TRACING_CHILD=OFF\x00--\x00/bin/true"),
            fuzz_input.slice("ZINIT_TRACING_CHILD=ON\x00--\x00/bin/true"),
            fuzz_input.slice("ZINIT_SHUTDOWN_TIMEOUT=junk\x00--\x00/bin/true"),
            fuzz_input.slice("ZINIT_SHUTDOWN_TIMEOUT=18446744073709551616\x00--\x00/bin/true"),
            fuzz_input.slice("ZINIT_SUBREAPER=1\x00--\x00/bin/true"),
            fuzz_input.slice("--log-level\x00warn\x00--\x00/bin/true"),
            fuzz_input.slice("--log-level\x00error\x00--\x00/bin/true"),
            fuzz_input.slice("-p\x000\x00--\x00/bin/true"),
            fuzz_input.slice("-p\x0032\x00--\x00/bin/true"),
            fuzz_input.slice("-p\x0065\x00--\x00/bin/true"),
            fuzz_input.slice("-p\x00SIGRTMIN\x00--\x00/bin/true"),
            fuzz_input.slice("-p\x00SIGSIGTERM\x00--\x00/bin/true"),
            fuzz_input.slice("-p\x00\x00--\x00/bin/true"),
        },
    });
}
