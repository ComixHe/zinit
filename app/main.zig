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

/// Debug builds need std.debug's Io, release builds carry it only when stack
/// traces are enabled, which `ReleaseSmall` is not.
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

    lib.crash.writeAndExit(&iov);
}

const ParsedBehavior = union(enum) {
    run: Args,
    exit: u8,
};

fn run(args: Args, ctx: lib.io.Context) u8 {
    log.setRuntimeLevel(args.log_level);

    const unblocked_sigs = [_]Sig{ .ABRT, .BUS, .FPE, .ILL, .SEGV, .SYS, .TRAP };
    const signal_config = lib.signalfd.Config.install(&unblocked_sigs) catch {
        @branchHint(.cold);
        return 1;
    };

    supervisor.setupSubreaper(args.subreaper) catch {
        @branchHint(.cold);
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

    // Before the fork: only a new session transfers the terminal, and the kernel
    // then queues one HUP and one CONT for the foreground group (usually zinit).
    // The workload never caused them and must not receive them.
    const detached = blk: {
        if (!args.new_session) break :blk false;
        const fd = tty_fd orelse break :blk false;
        break :blk lib.tty.isControlTerminal(fd) and lib.tty.detachFromControlTerminal(fd);
    };

    lib.crash.setPhase(.spawn);

    var spawned = supervisor.spawn(spec, &signal_config) catch {
        @branchHint(.cold);
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

    lib.crash.setPhase(.supervise);

    return switch (supervisor.supervise(policy, &signal_config, &spawned)) {
        .exited => |code| code,
        .failed => 1,
    };
}

fn dispatch(init: std.process.Init.Minimal, ctx: lib.io.Context) ParsedBehavior {
    const action = Args.parse(init) catch |e| {
        @branchHint(.cold);
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

    // Without std.debug's crash reporter, install the minimal one so a fault
    // still names the program counter; the address is symbolized offline.
    if (comptime !stack_traces) lib.crash.install(config.pie);

    return switch (dispatch(init, ctx)) {
        .run => |args| run(args, ctx),
        .exit => |code| code,
    };
}
