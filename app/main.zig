// SPDX-FileCopyrightText: 2025 - 2026 YuMing He <ComixHe1895@outlook.com>
//
// SPDX-License-Identifier: MIT

//! A tiny, allocation-free, libc-less init for Linux containers: signal forwarding and
//! orphan reaping. Raw `std.os.linux` syscalls, a comptime formatter and a small logger
//! instead of `std.posix`/`std.fmt`/`std.log`, all in service of binary size.

const std = @import("std");
const builtin = @import("builtin");

const lib = @import("zinit");

const stack_traces = @import("config").stack_traces;

const io = lib.io;
const log = lib.log;
const tryClose = io.tryClose;
const Sig = lib.signal.Sig;
const Args = lib.args.Args;
const child = lib.child;
const supervisor = lib.supervisor;

pub const std_options: std.Options = .{
    .signal_stack_size = null,
    .networking = false,
    .enable_segfault_handler = stack_traces,
};

/// Debug builds need std.debug's Io; release builds only carry it with `-Dstack-traces`.
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
    const stderr = std.os.linux.STDERR_FILENO;

    io.writeAll(stderr, prefix);
    io.writeAll(stderr, msg);
    io.writeAll(stderr, "\n");

    std.os.linux.exit(1);
}

const ParsedBehavior = union(enum) {
    run: Args,
    exit: u8,
};

fn parseArgs(init: std.process.Init.Minimal, out: std.os.linux.fd_t, err: std.os.linux.fd_t) ParsedBehavior {
    const action = Args.parse(init) catch |e| {
        @branchHint(.cold);
        if (e == lib.errors.ZinitError.MissingCommand) Args.printHelp(err);
        return .{ .exit = 1 };
    };

    return switch (action) {
        .run => |args| .{ .run = args },
        .help => blk: {
            Args.printHelp(out);
            break :blk .{ .exit = 0 };
        },
        .version => blk: {
            Args.printVersion(out);
            break :blk .{ .exit = 0 };
        },
    };
}

pub fn main(init: std.process.Init.Minimal) u8 {
    log.init(std.os.linux.STDERR_FILENO);
    const args = switch (parseArgs(init, std.os.linux.STDOUT_FILENO, std.os.linux.STDERR_FILENO)) {
        .run => |args| args,
        .exit => |code| return code,
    };

    log.setLevel(args.log_level);

    const unblocked_sigs = [_]Sig{ .ABRT, .BUS, .FPE, .ILL, .SEGV, .SYS, .TRAP, .TTIN, .TTOU };
    const signal_config = lib.signalfd.Config.init(&unblocked_sigs) catch {
        @branchHint(.cold);
        return 1;
    };

    supervisor.setupSubreaper(args.subreaper) catch {
        @branchHint(.cold);
        return 1;
    };

    const spec: child.SpawnSpec = .{
        .argv = args.argv,
        .envs = args.envs,
        .new_session = args.new_session,
        .is_terminal = args.is_terminal,
        .pdeath_signal = args.pdeath_signal,
        .tracing_child = args.tracing_child,
    };

    // Before the fork: the kernel queues one HUP and one CONT for zinit itself, which
    // the workload never caused and must not be handed.
    const detached = child.detachFromTerminal(spec);

    const spawned = child.spawn(spec, &signal_config) catch {
        @branchHint(.cold);
        return 1;
    };

    const policy: supervisor.Policy = .{
        .expected_exit = args.expected_exit,
        .rewrites = args.rewrites,
        .forward_group = args.forward_group,
        .shutdown_timeout_ns = args.shutdown_timeout_ns,
        .ignore_initial_hup_cont = detached,
    };

    return supervisor.supervise(policy, &signal_config, spawned);
}

// kcov-exclude-tests (everything below is test-only).
test "dispatch routes help/version to out and a usage error to err" {
    var out_pipe: [2]std.os.linux.fd_t = undefined;
    var err_pipe: [2]std.os.linux.fd_t = undefined;
    try std.testing.expectEqual(std.os.linux.E.SUCCESS, std.os.linux.errno(std.os.linux.pipe2(&out_pipe, .{ .NONBLOCK = true })));
    defer tryClose(out_pipe[0]);
    defer tryClose(out_pipe[1]);
    try std.testing.expectEqual(std.os.linux.E.SUCCESS, std.os.linux.errno(std.os.linux.pipe2(&err_pipe, .{ .NONBLOCK = true })));
    defer tryClose(err_pipe[0]);
    defer tryClose(err_pipe[1]);
    const out = out_pipe[1];
    const err = err_pipe[1];

    var buf: [16 * 1024]u8 = undefined;

    const env = [_:null]?[*:0]const u8{};
    const environ: std.process.Environ = .{ .block = .{ .slice = &env } };
    const argv_help = [_][*:0]const u8{ "zinit", "--help" };
    const argv_version = [_][*:0]const u8{ "zinit", "-V" };
    const argv_bad = [_][*:0]const u8{"zinit"};
    const argv_run = [_][*:0]const u8{ "zinit", "--", "true" };

    const init_bad: std.process.Init.Minimal = .{ .args = .{ .vector = &argv_bad }, .environ = environ };
    try std.testing.expectEqual(@as(u8, 1), switch (parseArgs(init_bad, out, err)) {
        .run => return error.TestUnexpectedResult,
        .exit => |code| code,
    });
    try std.testing.expectEqual(@as(usize, 0), drain(out_pipe[0], &buf));
    try std.testing.expect(drain(err_pipe[0], &buf) > 0);

    const init_help: std.process.Init.Minimal = .{ .args = .{ .vector = &argv_help }, .environ = environ };
    try std.testing.expectEqual(@as(u8, 0), switch (parseArgs(init_help, out, err)) {
        .run => return error.TestUnexpectedResult,
        .exit => |code| code,
    });
    try std.testing.expect(drain(out_pipe[0], &buf) > 0);

    const init_version: std.process.Init.Minimal = .{ .args = .{ .vector = &argv_version }, .environ = environ };
    try std.testing.expectEqual(@as(u8, 0), switch (parseArgs(init_version, out, err)) {
        .run => return error.TestUnexpectedResult,
        .exit => |code| code,
    });
    try std.testing.expect(drain(out_pipe[0], &buf) > 0);

    const init_run: std.process.Init.Minimal = .{ .args = .{ .vector = &argv_run }, .environ = environ };
    switch (parseArgs(init_run, out, err)) {
        .run => |args| try std.testing.expectEqualStrings("true", std.mem.span(args.argv[0].?)),
        .exit => return error.TestUnexpectedResult,
    }

    const argv_typo = [_][*:0]const u8{ "zinit", "--log-level=debug", "--", "true" };
    const init_typo: std.process.Init.Minimal = .{ .args = .{ .vector = &argv_typo }, .environ = environ };
    try std.testing.expectEqual(@as(u8, 1), switch (parseArgs(init_typo, out, err)) {
        .run => return error.TestUnexpectedResult,
        .exit => |code| code,
    });

    try std.testing.expectEqual(@as(usize, 0), drain(err_pipe[0], &buf));
}

fn drain(fd: std.posix.fd_t, buf: []u8) usize {
    return std.posix.read(fd, buf) catch |err| switch (err) {
        error.WouldBlock => 0,
        else => unreachable,
    };
}
