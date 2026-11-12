// SPDX-FileCopyrightText: 2026 YuMing He <ComixHe1895@outlook.com>
//
// SPDX-License-Identifier: MIT

//! Linux integration checks for signal install/restore.

const std = @import("std");
const zinit = @import("zinit");

const Config = zinit.signalfd.Config;
const Source = zinit.signalfd.Source;
const Event = zinit.signal.Event;
const Sig = zinit.signal.Sig;

var chld_hits: usize = 0;

fn countChld(_: Sig) callconv(.c) void {
    @as(*volatile usize, &chld_hits).* += 1;
}

const ChldEnv = struct {
    action: std.os.linux.Sigaction,
    mask: std.os.linux.sigset_t,
};

fn beginChldTest(handler: *const std.os.linux.Sigaction) ChldEnv {
    var old_action: std.os.linux.Sigaction = undefined;
    std.posix.sigaction(Sig.CHLD, handler, &old_action);

    var original: std.os.linux.sigset_t = undefined;
    std.posix.sigprocmask(Sig.SETMASK, null, &original);
    return .{ .action = old_action, .mask = original };
}

const mask_allowing_chld = blk: {
    var mask = std.posix.sigfillset();
    std.posix.sigdelset(&mask, Sig.CHLD);
    break :blk mask;
};

const chld_only: std.os.linux.sigset_t = blk: {
    var set = std.posix.sigemptyset();
    std.posix.sigaddset(&set, Sig.CHLD);
    break :blk set;
};

fn drainPending(set: *const std.os.linux.sigset_t) void {
    const zero = std.os.linux.timespec{ .sec = 0, .nsec = 0 };
    var info: std.os.linux.siginfo_t = undefined;

    while (true) {
        const rc = std.os.linux.syscall4(
            .rt_sigtimedwait,
            @intFromPtr(set),
            @intFromPtr(&info),
            @intFromPtr(&zero),
            std.os.linux.NSIG / 8,
        );

        if (std.os.linux.errno(rc) != .SUCCESS) break;
    }
}

test "integration: restoreParent restores the handler before a pending SIGCHLD is delivered" {
    const handler = comptime std.os.linux.Sigaction{
        .handler = .{ .handler = countChld },
        .mask = std.posix.sigemptyset(),
        .flags = 0,
    };

    const env = beginChldTest(&handler);
    defer {
        std.posix.sigaction(Sig.CHLD, &env.action, null);
        std.posix.sigprocmask(Sig.SETMASK, &env.mask, null);
    }

    std.posix.sigprocmask(Sig.SETMASK, &mask_allowing_chld, null);

    chld_hits = 0;
    var config = try Config.install(&[_]Sig{});
    defer _ = config.restoreParent();

    drainPending(&chld_only);
    std.posix.kill(std.os.linux.getpid(), Sig.CHLD) catch unreachable;

    try std.testing.expectEqual(@as(usize, 0), chld_hits);
    try std.testing.expect(config.restoreParent() == null);

    try std.testing.expectEqual(@as(usize, 1), chld_hits);
}

test "integration: restoreParent keeps SIGCHLD blocked when that was the caller's state" {
    const handler = comptime std.os.linux.Sigaction{
        .handler = .{ .handler = countChld },
        .mask = std.posix.sigemptyset(),
        .flags = 0,
    };

    const env = beginChldTest(&handler);
    defer {
        std.posix.sigaction(Sig.CHLD, &env.action, null);
        std.posix.sigprocmask(Sig.SETMASK, &env.mask, null);
    }

    const blocked = comptime std.os.linux.sigfillset();
    std.posix.sigprocmask(Sig.SETMASK, &blocked, null);

    chld_hits = 0;
    var config = try Config.install(&[_]Sig{});
    defer _ = config.restoreParent();

    drainPending(&chld_only);
    std.posix.kill(std.os.linux.getpid(), Sig.CHLD) catch unreachable;

    try std.testing.expectEqual(@as(usize, 0), chld_hits);
    try std.testing.expect(config.restoreParent() == null);

    try std.testing.expectEqual(@as(usize, 0), chld_hits);

    std.posix.sigprocmask(Sig.SETMASK, &mask_allowing_chld, null);
    try std.testing.expectEqual(@as(usize, 1), chld_hits);
}

test "integration: install sets the parent state, and restoreParent puts it back" {
    const ignored = comptime std.os.linux.Sigaction{
        .handler = .{ .handler = Sig.IGN },
        .mask = std.posix.sigemptyset(),
        .flags = 0,
    };

    const default_action = comptime std.os.linux.Sigaction{
        .handler = .{ .handler = Sig.DFL },
        .mask = std.posix.sigemptyset(),
        .flags = 0,
    };

    var ttin_before: std.os.linux.Sigaction = undefined;
    var ttou_before: std.os.linux.Sigaction = undefined;
    var chld_before: std.os.linux.Sigaction = undefined;
    std.posix.sigaction(Sig.TTIN, &default_action, &ttin_before);
    std.posix.sigaction(Sig.TTOU, &default_action, &ttou_before);
    std.posix.sigaction(Sig.CHLD, &ignored, &chld_before);

    defer {
        std.posix.sigaction(Sig.TTIN, &ttin_before, null);
        std.posix.sigaction(Sig.TTOU, &ttou_before, null);
        std.posix.sigaction(Sig.CHLD, &chld_before, null);
    }

    var mask_before: std.os.linux.sigset_t = undefined;
    std.posix.sigprocmask(Sig.SETMASK, null, &mask_before);

    var signal_config = try Config.install(&[_]Sig{.TERM});
    defer _ = signal_config.restoreParent();

    var installed_mask: std.os.linux.sigset_t = undefined;
    std.posix.sigprocmask(Sig.SETMASK, null, &installed_mask);
    try std.testing.expect(!std.posix.sigismember(&installed_mask, Sig.TERM));
    try std.testing.expect(std.posix.sigismember(&installed_mask, Sig.HUP));
    var after: std.os.linux.Sigaction = undefined;
    std.posix.sigaction(Sig.CHLD, null, &after);
    try std.testing.expect(after.handler.handler == Sig.DFL);
    std.posix.sigaction(Sig.TTIN, null, &after);
    try std.testing.expect(after.handler.handler == Sig.IGN);
    std.posix.sigaction(Sig.TTOU, null, &after);
    try std.testing.expect(after.handler.handler == Sig.IGN);

    try std.testing.expect(signal_config.restoreParent() == null);

    var mask_after: std.os.linux.sigset_t = undefined;
    std.posix.sigprocmask(Sig.SETMASK, null, &mask_after);
    try std.testing.expect(std.mem.eql(u8, std.mem.asBytes(&mask_before), std.mem.asBytes(&mask_after)));

    std.posix.sigaction(Sig.CHLD, null, &after);
    try std.testing.expect(after.handler.handler == Sig.IGN);
    std.posix.sigaction(Sig.TTIN, null, &after);
    try std.testing.expect(after.handler.handler == Sig.DFL);
    std.posix.sigaction(Sig.TTOU, null, &after);
    try std.testing.expect(after.handler.handler == Sig.DFL);
}

test "integration: waitBatch waits for its timeout and returns nothing" {
    const io = std.testing.io;
    const config = try Config.install(&[_]Sig{});
    defer _ = config.restoreParent();

    drainPending(&config.current_set);

    var source = try Source.open(&config);
    defer source.close();

    var out: [1]Event = undefined;
    const start = std.Io.Clock.now(.awake, io).toNanoseconds();
    try std.testing.expectEqual(@as(usize, 0), try source.waitBatch(&out, 30));
    const elapsed_ms = @divTrunc(
        std.Io.Clock.now(.awake, io).toNanoseconds() - start,
        std.time.ns_per_ms,
    );

    try std.testing.expect(elapsed_ms >= 10);
}

fn openFdCount(io: std.Io) !usize {
    var dir = try std.Io.Dir.openDirAbsolute(io, "/proc/self/fd", .{ .iterate = true });
    defer dir.close(io);

    var count: usize = 0;
    var it = dir.iterate();
    while (try it.next(io)) |entry| {
        if (std.mem.eql(u8, entry.name, ".") or std.mem.eql(u8, entry.name, "..")) continue;
        count += 1;
    }

    return count;
}

test "integration: opening and closing a signal source does not leak descriptors" {
    const config = try Config.install(&[_]Sig{.TERM});
    defer _ = config.restoreParent();

    const before = try openFdCount(std.testing.io);
    var i: usize = 0;
    while (i < 32) : (i += 1) {
        var source = try Source.open(&config);
        source.close();
    }

    try std.testing.expectEqual(before, try openFdCount(std.testing.io));
}
