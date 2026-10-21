// SPDX-FileCopyrightText: 2026 YuMing He <ComixHe1895@outlook.com>
//
// SPDX-License-Identifier: MIT

//! The parent-side signal setup the child inherits: the blocked mask, the SIGCHLD/TTIN/TTOU
//! dispositions, and the signalfd that reads them.

const std = @import("std");

const errors = @import("errors.zig");
const log = @import("log.zig");
const signal = @import("signal.zig");

const ZinitError = errors.ZinitError;
const Sig = signal.Sig;

pub const Config = struct {
    current_set: std.os.linux.sigset_t,
    ttin_action: std.os.linux.Sigaction,
    ttou_action: std.os.linux.Sigaction,
    chld_action: std.os.linux.Sigaction,

    pub fn init(comptime unblocked: []const Sig) !Config {
        var set = std.os.linux.sigfillset();
        for (unblocked) |sig| std.os.linux.sigdelset(&set, sig);

        const rc = std.os.linux.sigprocmask(Sig.SETMASK, &set, null);
        switch (std.os.linux.errno(rc)) {
            .SUCCESS => {},
            else => |errno| {
                @branchHint(.cold);
                log.err("unable to set signal mask: {e}", .{errno});
                return ZinitError.SysCallError;
            },
        }

        const ignored = std.os.linux.Sigaction{
            .handler = .{ .handler = Sig.IGN },
            .mask = std.os.linux.sigemptyset(),
            .flags = 0,
        };

        var old_ttin_action: std.os.linux.Sigaction = undefined;
        try checkAction("TTIN", std.os.linux.sigaction(Sig.TTIN, &ignored, &old_ttin_action));
        var old_ttou_action: std.os.linux.Sigaction = undefined;
        try checkAction("TTOU", std.os.linux.sigaction(Sig.TTOU, &ignored, &old_ttou_action));

        // Reaping needs the child to stay a zombie, and an inherited SIG_IGN/SA_NOCLDWAIT
        // would suppress SIGCHLD: set DFL and hand the child back what we found.
        const default_action = std.os.linux.Sigaction{
            .handler = .{ .handler = Sig.DFL },
            .mask = std.os.linux.sigemptyset(),
            .flags = 0,
        };
        var old_chld_action: std.os.linux.Sigaction = undefined;
        try checkAction("CHLD", std.os.linux.sigaction(Sig.CHLD, &default_action, &old_chld_action));

        return .{
            .current_set = set,
            .ttin_action = old_ttin_action,
            .ttou_action = old_ttou_action,
            .chld_action = old_chld_action,
        };
    }

    fn checkAction(name: []const u8, rc: usize) !void {
        switch (std.os.linux.errno(rc)) {
            .SUCCESS => {},
            else => |errno| {
                @branchHint(.cold);
                log.err("unable to set signal action for {s}: {e}", .{ name, errno });
                return ZinitError.SysCallError;
            },
        }
    }

    pub fn openFd(self: *const Config) !std.os.linux.fd_t {
        const flags = std.os.linux.SFD.NONBLOCK | std.os.linux.SFD.CLOEXEC;
        const fd = std.os.linux.signalfd(-1, &self.current_set, flags);
        return switch (std.os.linux.errno(fd)) {
            .SUCCESS => @intCast(fd),
            else => |e| {
                log.err("unable to create signalfd: {e}", .{e});
                return ZinitError.SysCallError;
            },
        };
    }

    pub const Step = enum { ttin, ttou, chld };

    pub const RestoreFailure = struct {
        step: Step,
        errno: std.os.linux.E,
    };

    pub fn restoreChild(self: *const Config) ?RestoreFailure {
        if (failed(.ttin, std.os.linux.sigaction(Sig.TTIN, &self.ttin_action, null))) |f| return f;
        if (failed(.ttou, std.os.linux.sigaction(Sig.TTOU, &self.ttou_action, null))) |f| return f;
        if (failed(.chld, std.os.linux.sigaction(Sig.CHLD, &self.chld_action, null))) |f| return f;
        return null;
    }

    fn failed(step: Step, rc: usize) ?RestoreFailure {
        const errno = std.os.linux.errno(rc);
        return if (errno == .SUCCESS) null else .{ .step = step, .errno = errno };
    }
};

// kcov-exclude-tests (everything below is test-only).
test "Config.init establishes the SIGCHLD disposition it depends on" {
    const ignored = std.os.linux.Sigaction{
        .handler = .{ .handler = Sig.IGN },
        .mask = std.os.linux.sigemptyset(),
        .flags = 0,
    };
    var before: std.os.linux.Sigaction = undefined;
    try std.testing.expectEqual(std.os.linux.E.SUCCESS, std.os.linux.errno(std.os.linux.sigaction(Sig.CHLD, &ignored, &before)));

    var mask_before: std.os.linux.sigset_t = undefined;
    _ = std.os.linux.sigprocmask(Sig.SETMASK, null, &mask_before);

    const signal_config = try Config.init(&[_]Sig{.TERM});

    _ = std.os.linux.sigprocmask(Sig.SETMASK, &mask_before, null);

    var after: std.os.linux.Sigaction = undefined;
    try std.testing.expectEqual(std.os.linux.E.SUCCESS, std.os.linux.errno(std.os.linux.sigaction(Sig.CHLD, null, &after)));
    try std.testing.expect(after.handler.handler == Sig.DFL);

    try std.testing.expect(signal_config.chld_action.handler.handler == Sig.IGN);
    _ = std.os.linux.sigaction(Sig.CHLD, &before, null);
}
