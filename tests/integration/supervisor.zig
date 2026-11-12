// SPDX-FileCopyrightText: 2026 YuMing He <ComixHe1895@outlook.com>
//
// SPDX-License-Identifier: MIT

//! Supervisor behavior through the public Policy, Outcome and supervise interface.

const std = @import("std");
const zinit = @import("zinit");

const supervisor = zinit.supervisor;
const wait = zinit.wait;
const Sig = zinit.signal.Sig;
const SignalConfig = zinit.signalfd.Config;
const ExitCodeSet = wait.ExitCodeSet;
const Policy = zinit.supervisor.Policy;
const Outcome = zinit.supervisor.Outcome;
const supervise = zinit.supervisor.supervise;
const closeQuietly = zinit.io.closeQuietly;

const sleeper: supervisor.SpawnSpec = .{
    .argv = &[_:null]?[*:0]const u8{ "/bin/sleep", "30" },
};

test "integration: a signalfd failure kills the child instead of leaking it" {
    const signal_config = try SignalConfig.install(&[_]Sig{});
    defer _ = signal_config.restoreParent();

    var spawned = try supervisor.spawn(sleeper, &signal_config);
    defer spawned.close();

    const original = try std.posix.getrlimit(.NOFILE);
    defer std.posix.setrlimit(.NOFILE, original) catch {};
    try std.posix.setrlimit(.NOFILE, .{ .cur = 3, .max = original.max });
    const outcome = supervise(.{
        .expected_exit = .empty,
        .rewrites = null,
        .forward_group = false,
        .shutdown_timeout_ns = 0,
        .ignore_initial_hup_cont = false,
    }, &signal_config, &spawned);
    try std.posix.setrlimit(.NOFILE, original);

    try std.testing.expectEqual(Outcome.failed, outcome);

    const status = try wait.waitForExit(std.testing.io, spawned.pid);
    try std.testing.expectEqual(
        @as(u32, @intCast(@backingInt(Sig.KILL))),
        status.signalNumber(),
    );
}

test "integration: a child that ignores a forwarded TSTP does not stop zinit" {
    const signal_config = try SignalConfig.install(&[_]Sig{});
    defer _ = signal_config.restoreParent();

    var ready: [2]std.os.linux.fd_t = undefined;
    if (std.os.linux.errno(std.os.linux.pipe2(&ready, .{ .NONBLOCK = true })) != .SUCCESS)
        return error.TestUnexpectedResult;
    defer closeQuietly(ready[0]);

    const driver = std.os.linux.fork();
    if (std.os.linux.errno(driver) != .SUCCESS) {
        closeQuietly(ready[1]);
        return error.TestUnexpectedResult;
    }

    if (driver == 0) {
        _ = std.os.linux.close(ready[0]);

        var script_buf: [128]u8 = undefined;
        const script = std.mem.printSentinel(
            &script_buf,
            "trap '' TSTP; echo ready >&{d}; sleep 0.2; exit 7",
            .{ready[1]},
            0,
        ) catch std.os.linux.exit(1);

        const policy: Policy = .{
            .expected_exit = .empty,
            .rewrites = null,
            .forward_group = false,
            .shutdown_timeout_ns = 0,
            .ignore_initial_hup_cont = false,
        };

        var spawned = supervisor.spawn(.{
            .argv = &[_:null]?[*:0]const u8{ "/bin/sh", "-c", script.ptr },
        }, &signal_config) catch std.os.linux.exit(1);

        std.os.linux.exit(switch (supervise(policy, &signal_config, &spawned)) {
            .exited => |code| code,
            .failed => 1,
        });
    }

    _ = std.os.linux.close(ready[1]);
    const driver_pid: std.os.linux.pid_t = @intCast(driver);

    const status = blk: {
        errdefer wait.killAndReap(std.testing.io, driver_pid);
        try waitForByte(ready[0]);
        std.posix.kill(driver_pid, Sig.TSTP) catch unreachable;
        const event = try wait.waitForEvent(std.testing.io, driver_pid, std.os.linux.W.UNTRACED);
        if (std.os.linux.W.IFSTOPPED(@intCast(event))) return error.TestUnexpectedResult;
        break :blk event;
    };

    try std.testing.expect(std.os.linux.W.IFEXITED(@intCast(status)));
    try std.testing.expectEqual(@as(u8, 7), std.os.linux.W.EXITSTATUS(@intCast(status)));
}

fn waitForByte(fd: std.os.linux.fd_t) !void {
    const io = std.testing.io;
    const deadline = std.Io.Clock.now(.awake, io).toNanoseconds() + 5 * std.time.ns_per_s;
    var byte: [1]u8 = undefined;
    while (true) {
        const rc = std.os.linux.read(fd, &byte, 1);
        switch (std.os.linux.errno(rc)) {
            .SUCCESS => {
                if (rc == 1) return;
                return error.TestUnexpectedResult;
            },
            .AGAIN, .INTR => {},
            else => return error.TestUnexpectedResult,
        }

        if (std.Io.Clock.now(.awake, io).toNanoseconds() >= deadline)
            return error.TestUnexpectedResult;
        try std.Io.sleep(io, .fromMilliseconds(1), .awake);
    }
}

test "integration: a user's HUP reaches the workload through supervise" {
    const signal_config = try SignalConfig.install(&[_]Sig{});
    defer _ = signal_config.restoreParent();

    const policy: Policy = .{
        .expected_exit = .empty,
        .rewrites = null,
        .forward_group = false,
        .shutdown_timeout_ns = 0,
        .ignore_initial_hup_cont = true,
    };

    var spawned = try supervisor.spawn(sleeper, &signal_config);
    std.posix.kill(std.os.linux.getpid(), Sig.HUP) catch unreachable;
    try expectExit(128 + @backingInt(Sig.HUP), supervise(policy, &signal_config, &spawned));
}

test "integration: a rewrite maps a forwarded signal before it reaches the child" {
    const io = std.testing.io;
    var ready: [2]std.os.linux.fd_t = undefined;
    if (std.os.linux.errno(std.os.linux.pipe2(&ready, .{})) != .SUCCESS)
        return error.TestUnexpectedResult;
    defer closeQuietly(ready[0]);

    var original: std.os.linux.sigset_t = undefined;
    std.posix.sigprocmask(Sig.SETMASK, null, &original);
    var with_int = original;
    std.posix.sigdelset(&with_int, Sig.INT);
    std.posix.sigprocmask(Sig.SETMASK, &with_int, null);
    defer std.posix.sigprocmask(Sig.SETMASK, &original, null);

    const driver = std.os.linux.fork();
    if (std.os.linux.errno(driver) != .SUCCESS) {
        closeQuietly(ready[1]);
        return error.TestUnexpectedResult;
    }

    if (driver == 0) {
        _ = std.os.linux.close(ready[0]);
        const signal_config = SignalConfig.install(&[_]Sig{}) catch std.os.linux.exit(1);
        var rewrites = zinit.rewrite.Map.init();
        rewrites.parse("TERM:INT") catch std.os.linux.exit(1);

        var script_buf: [128]u8 = undefined;
        const script = std.mem.printSentinel(
            &script_buf,
            "trap 'exit 42' INT; printf r >&{d}; while :; do sleep 1; done",
            .{ready[1]},
            0,
        ) catch std.os.linux.exit(1);

        var spawned = supervisor.spawn(.{
            .argv = &[_:null]?[*:0]const u8{ "/bin/sh", "-c", script.ptr },
        }, &signal_config) catch std.os.linux.exit(1);

        const policy: Policy = .{
            .expected_exit = .empty,
            .rewrites = rewrites,
            .forward_group = false,
            .shutdown_timeout_ns = 0,
            .ignore_initial_hup_cont = false,
        };

        std.os.linux.exit(switch (supervise(policy, &signal_config, &spawned)) {
            .exited => |code| code,
            .failed => 1,
        });
    }

    _ = std.os.linux.close(ready[1]);
    const driver_pid: std.os.linux.pid_t = @intCast(driver);

    const status = blk: {
        errdefer wait.killAndReap(io, driver_pid);
        try waitForByte(ready[0]);
        std.posix.kill(driver_pid, Sig.TERM) catch unreachable;
        break :blk try wait.waitForExit(io, driver_pid);
    };

    try std.testing.expectEqual(wait.WaitStatus.Class.exited, status.class());
    try std.testing.expectEqual(@as(u8, 42), status.exitCode());
}

fn expectExit(expected: u8, outcome: Outcome) !void {
    switch (outcome) {
        .exited => |code| try std.testing.expectEqual(expected, code),
        .failed => return error.TestUnexpectedResult,
    }
}

test "integration: an expected exit code becomes 0, for a code and for a signal" {
    const signal_config = try SignalConfig.install(&[_]Sig{});
    defer _ = signal_config.restoreParent();

    const coded: supervisor.SpawnSpec = .{
        .argv = &[_:null]?[*:0]const u8{ "/bin/sh", "-c", "exit 7" },
    };

    const base: Policy = .{
        .expected_exit = .empty,
        .rewrites = null,
        .forward_group = false,
        .shutdown_timeout_ns = 0,
        .ignore_initial_hup_cont = false,
    };

    var plain = try supervisor.spawn(coded, &signal_config);
    try expectExit(7, supervise(base, &signal_config, &plain));

    var expect_seven = ExitCodeSet.empty;
    expect_seven.set(7);
    var mapped = base;
    mapped.expected_exit = expect_seven;
    var mapped_child = try supervisor.spawn(coded, &signal_config);
    try expectExit(0, supervise(mapped, &signal_config, &mapped_child));

    var signalled = try supervisor.spawn(sleeper, &signal_config);
    std.posix.kill(signalled.pid, Sig.TERM) catch unreachable;
    try expectExit(128 + @backingInt(Sig.TERM), supervise(base, &signal_config, &signalled));

    var expect_term = ExitCodeSet.empty;
    expect_term.set(128 + @backingInt(Sig.TERM));
    var mapped_term = base;
    mapped_term.expected_exit = expect_term;
    var killed = try supervisor.spawn(sleeper, &signal_config);
    std.posix.kill(killed.pid, Sig.TERM) catch unreachable;
    try expectExit(0, supervise(mapped_term, &signal_config, &killed));
}
