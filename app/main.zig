// SPDX-FileCopyrightText: 2025 - 2026 YuMing He <ComixHe1895@outlook.com>
//
// SPDX-License-Identifier: MIT

//! A tiny, allocation-free, libc-less init for Linux containers: signal forwarding and
//! orphan reaping.

const std = @import("std");
const builtin = @import("builtin");
const lib = @import("zinit");

const log = lib.log;
const Sig = lib.signal.Sig;
const Args = lib.args.Args;
const supervisor = lib.supervisor;

const config = @import("config");
const stack_traces = config.stack_traces;

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

fn minimalPanic(msg: []const u8, _: ?*std.lang.StackTrace, _: ?usize) noreturn {
    @branchHint(.cold);
    const prefix = "zinit panic: ";
    const iov = [_]std.posix.iovec_const{
        .{ .base = prefix, .len = prefix.len },
        .{ .base = msg.ptr, .len = msg.len },
        .{ .base = "\n", .len = 1 },
    };

    _ = std.os.linux.writev(std.os.linux.STDERR_FILENO, &iov, 3);
    std.os.linux.exit(1);
}

const ParsedBehavior = union(enum) {
    run: Args,
    exit: u8,
};

fn run(args: Args, ctx: lib.io.Context) u8 {
    log.setRuntimeLevel(args.log_level);

    const unblocked_sigs = [_]Sig{ .ABRT, .BUS, .FPE, .ILL, .SEGV, .SYS, .TRAP };
    const signal_config = lib.signalfd.Config.install(&unblocked_sigs) catch {
        @branchHint(.unlikely);
        return 1;
    };

    supervisor.setupSubreaper(args.subreaper) catch {
        @branchHint(.unlikely);
        return 1;
    };

    // A fresh PTY is not our controlling terminal yet, but the new session can
    // acquire it. Prefer our controlling terminal when one is available.
    var tty_fd: ?std.os.linux.fd_t = null;
    for ([_]std.os.linux.fd_t{ ctx.in, ctx.out, ctx.err }) |fd| {
        if (lib.tty.isControlTerminal(fd)) {
            tty_fd = fd;
            break;
        }

        if (args.new_session and tty_fd == null and lib.tty.isTty(fd))
            tty_fd = fd;
    }

    const spec: supervisor.SpawnSpec = .{
        .argv = args.argv,
        .envs = args.envs,
        .new_session = args.new_session,
        .ctty = tty_fd,
        .pdeath_signal = args.pdeath_signal,
        .tracing_child = args.tracing_child,
    };

    // Before the fork: the kernel queues one HUP and one CONT for zinit itself,
    // which the workload never caused and must not be handed. Only a new session
    // transfers the terminal, and only if there is one to let go of.
    const detached = blk: {
        if (!args.new_session) break :blk false;
        const fd = tty_fd orelse break :blk false;
        break :blk lib.tty.isControlTerminal(fd) and lib.tty.detachFromControlTerminal(fd);
    };

    var spawned = supervisor.spawn(spec, &signal_config) catch {
        @branchHint(.unlikely);
        return 1;
    };

    const policy: supervisor.Policy = .{
        .expected_exit = args.expected_exit,
        .rewrites = args.rewrites,
        .forward_group = args.forward_group,
        .shutdown_timeout_ns = args.shutdown_timeout_ns,
        .ignore_initial_hup_cont = detached,
        .ctty = tty_fd,
    };

    return switch (supervisor.supervise(policy, &signal_config, &spawned)) {
        .exited => |code| code,
        .failed => 1,
    };
}

fn dispatch(init: std.process.Init.Minimal, ctx: lib.io.Context) ParsedBehavior {
    const action = Args.parse(init) catch |e| {
        @branchHint(.unlikely);
        if (e == lib.errors.ZinitError.MissingCommand) Args.printHelp(ctx.err);
        return .{ .exit = 1 };
    };

    return switch (action) {
        .run => |args| .{ .run = args },
        .help => blk: {
            Args.printHelp(ctx.out);
            break :blk .{ .exit = 0 };
        },
        .version => blk: {
            Args.printVersion(ctx.out);
            break :blk .{ .exit = 0 };
        },
    };
}

pub fn main(init: std.process.Init.Minimal) u8 {
    const ctx: lib.io.Context = .{
        .in = std.os.linux.STDIN_FILENO,
        .out = std.os.linux.STDOUT_FILENO,
        .err = std.os.linux.STDERR_FILENO,
    };

    log.init(ctx.err) catch unreachable;

    return switch (dispatch(init, ctx)) {
        .run => |args| run(args, ctx),
        .exit => |code| code,
    };
}

// kcov-exclude-tests (everything below is test-only).
test "dispatch selects the action and routes help, version and usage output" {
    const test_io = std.testing.io;

    const cases = [_]struct {
        name: []const u8,
        argv: [:null]const ?[*:0]const u8,
        exit: ?u8,
        stdout: bool = false,
        stderr: bool = false,
        version: bool = false,
    }{
        .{ .name = "usage", .argv = &.{"zinit"}, .exit = 1, .stderr = true },
        .{ .name = "help", .argv = &.{ "zinit", "--help" }, .exit = 0, .stdout = true },
        .{ .name = "version", .argv = &.{ "zinit", "-V" }, .exit = 0, .stdout = true, .version = true },
        .{ .name = "run", .argv = &.{ "zinit", "--", "true" }, .exit = null },
        .{ .name = "invalid option", .argv = &.{ "zinit", "--log-level=debug", "--", "true" }, .exit = 1 },
    };

    for (cases) |case| {
        errdefer std.debug.print("dispatch case: {s}\n", .{case.name});

        const out_fds = try std.Io.Threaded.pipe2(.{ .NONBLOCK = true });
        const err_fds = try std.Io.Threaded.pipe2(.{ .NONBLOCK = true });
        const out_read = std.Io.File{ .handle = out_fds[0], .flags = .{ .nonblocking = true } };
        const out_write = std.Io.File{ .handle = out_fds[1], .flags = .{ .nonblocking = true } };
        const err_read = std.Io.File{ .handle = err_fds[0], .flags = .{ .nonblocking = true } };
        const err_write = std.Io.File{ .handle = err_fds[1], .flags = .{ .nonblocking = true } };
        defer out_read.close(test_io);
        defer out_write.close(test_io);
        defer err_read.close(test_io);
        defer err_write.close(test_io);

        const ctx: lib.io.Context = .{
            .out = out_write.handle,
            .err = err_write.handle,
        };

        const init: std.process.Init.Minimal = .{
            .args = .{ .vector = @as([*]const [*:0]const u8, @ptrCast(case.argv.ptr))[0..case.argv.len] },
            .environ = .empty,
        };

        switch (dispatch(init, ctx)) {
            .run => |args| {
                try std.testing.expectEqual(@as(?u8, null), case.exit);
                try std.testing.expectEqualStrings("true", std.mem.span(args.argv[0].?));
            },
            .exit => |code| try std.testing.expectEqual(case.exit, @as(?u8, code)),
        }

        var out_text: [16 * 1024]u8 = undefined;
        const out = try drainPipe(out_read, test_io, &out_text);
        try std.testing.expectEqual(case.stdout, out.len > 0);

        var err_text: [16 * 1024]u8 = undefined;
        const err = try drainPipe(err_read, test_io, &err_text);
        try std.testing.expectEqual(case.stderr, err.len > 0);

        if (case.version)
            try std.testing.expectEqualStrings(config.version ++ "\n", out);
    }
}

/// Drain a non-blocking pipe into `buf`; an empty pipe reports `WouldBlock`.
fn drainPipe(file: std.Io.File, test_io: std.Io, buf: []u8) ![]u8 {
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
