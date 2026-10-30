// SPDX-FileCopyrightText: 2026 YuMing He <ComixHe1895@outlook.com>
//
// SPDX-License-Identifier: MIT

//! The parent-side signal setup the child inherits

const std = @import("std");
const io = @import("io.zig");
const checks = @import("checks.zig");
const log = @import("log.zig");
const signal = @import("signal.zig");
const SysCallError = @import("errors.zig").SysCallError;

pub const Config = struct {
    current_set: std.os.linux.sigset_t,
    /// The mask as it was before `install`, so the parent side can be put back.
    previous_set: std.os.linux.sigset_t,
    ttin_action: std.os.linux.Sigaction,
    ttou_action: std.os.linux.Sigaction,
    chld_action: std.os.linux.Sigaction,

    /// Installs the process-wide mask and dispositions the supervisor relies on.
    /// On failure the process signal state may be partly changed: the caller must
    /// not continue to run the workload (main exits).
    pub fn install(comptime unblocked: []const signal.Sig) !Config {
        const set = comptime mask: {
            var result = std.os.linux.sigfillset();
            for (unblocked) |sig| std.os.linux.sigdelset(&result, sig);
            break :mask result;
        };

        var previous_set: std.os.linux.sigset_t = undefined;
        const rc = std.os.linux.sigprocmask(signal.Sig.SETMASK, &set, &previous_set);
        switch (io.syscallErrno(rc)) {
            .SUCCESS => {},
            else => |errno| {
                @branchHint(.unlikely);
                log.err("unable to set signal mask: {e}", .{errno});
                return error.SysCallError;
            },
        }

        const ignored = comptime std.os.linux.Sigaction{
            .handler = .{ .handler = signal.Sig.IGN },
            .mask = std.os.linux.sigemptyset(),
            .flags = 0,
        };

        var config: Config = .{
            .current_set = set,
            .previous_set = previous_set,
            .ttin_action = undefined,
            .ttou_action = undefined,
            .chld_action = undefined,
        };

        try setActionOrLog(.ttin, signal.Sig.TTIN, &ignored, &config.ttin_action);
        try setActionOrLog(.ttou, signal.Sig.TTOU, &ignored, &config.ttou_action);

        // Reaping needs the child to stay a zombie, and an inherited SIG_IGN/SA_NOCLDWAIT
        // would suppress SIGCHLD: set DFL and hand the child back what we found.
        const default = comptime std.os.linux.Sigaction{
            .handler = .{ .handler = signal.Sig.DFL },
            .mask = std.os.linux.sigemptyset(),
            .flags = 0,
        };
        try setActionOrLog(.chld, signal.Sig.CHLD, &default, &config.chld_action);

        return config;
    }

    fn setAction(sig: signal.Sig, action: *const std.os.linux.Sigaction, old: ?*std.os.linux.Sigaction) ?std.os.linux.E {
        const errno = io.syscallErrno(std.os.linux.sigaction(sig, action, old));
        return if (errno == .SUCCESS) null else errno;
    }

    const Step = enum { ttin, ttou, chld, mask };

    fn setActionOrLog(comptime step: Step, sig: signal.Sig, action: *const std.os.linux.Sigaction, old: ?*std.os.linux.Sigaction) SysCallError!void {
        if (step == .mask) {
            @compileError("mask isn't an action step.");
        }

        if (setAction(sig, action, old)) |errno| {
            @branchHint(.unlikely);
            log.err("unable to set signal action for {s}: {e}", .{ @tagName(step), errno });
            return error.SysCallError;
        }
    }

    const RestoreFailure = struct {
        step: Step,
        errno: std.os.linux.E,
    };

    pub fn restoreActions(self: *const Config) ?RestoreFailure {
        if (setAction(signal.Sig.TTIN, &self.ttin_action, null)) |errno|
            return .{ .step = .ttin, .errno = errno };
        if (setAction(signal.Sig.TTOU, &self.ttou_action, null)) |errno|
            return .{ .step = .ttou, .errno = errno };
        if (setAction(signal.Sig.CHLD, &self.chld_action, null)) |errno|
            return .{ .step = .chld, .errno = errno };
        return null;
    }

    pub fn restoreMask(self: *const Config) ?RestoreFailure {
        const errno = io.syscallErrno(std.os.linux.sigprocmask(signal.Sig.SETMASK, &self.previous_set, null));
        return if (errno == .SUCCESS) null else .{ .step = .mask, .errno = errno };
    }

    /// This method is only for testing.
    pub fn restoreParent(self: *const Config) ?RestoreFailure {
        if (self.restoreActions()) |failure| return failure;
        return self.restoreMask();
    }

    pub fn restoreChild(self: *const Config) ?RestoreFailure {
        return self.restoreActions();
    }
};

/// Where the supervisor gets delivered signals from.
pub const Source = struct {
    fd: std.os.linux.fd_t,

    /// Realtime signals queue, so one read can carry a backlog.
    pub const batch_max = 8;

    pub fn open(config: *const Config) SysCallError!Source {
        const flags = std.os.linux.SFD.NONBLOCK | std.os.linux.SFD.CLOEXEC;
        const fd = std.os.linux.signalfd(-1, &config.current_set, flags);
        return switch (io.syscallErrno(fd)) {
            .SUCCESS => .{ .fd = @intCast(fd) },
            else => |e| {
                @branchHint(.unlikely);
                log.err("unable to create signalfd: {e}", .{e});
                return error.SysCallError;
            },
        };
    }

    pub fn close(self: *Source) void {
        io.closeQuietly(self.fd);
        self.* = undefined;
    }

    pub fn waitBatch(self: *Source, out: []signal.Event, timeout_ms: i32) SysCallError!usize {
        checks.check(out.len > 0);
        checks.check(out.len <= batch_max);

        if (timeout_ms != 0) {
            var pfd = [_]std.os.linux.pollfd{.{
                .fd = self.fd,
                .events = std.os.linux.POLL.IN,
                .revents = 0,
            }};

            switch (io.syscallErrno(std.os.linux.poll(&pfd, 1, timeout_ms))) {
                .SUCCESS => {},
                .INTR => unreachable,
                else => |e| {
                    @branchHint(.cold);
                    log.err("poll failed: {e}", .{e});
                    return error.SysCallError;
                },
            }
            if (pfd[0].revents == 0) return 0; // timeout

            const poll_errors = std.os.linux.POLL.ERR | std.os.linux.POLL.HUP | std.os.linux.POLL.NVAL;
            if (pfd[0].revents & poll_errors != 0) {
                const revents: u64 = @intCast(pfd[0].revents);
                log.err("poll error on signalfd: revents=0x{x}", .{revents});
                return error.SysCallError;
            }

            if (pfd[0].revents & std.os.linux.POLL.IN == 0) return 0;
        }

        return self.readBatch(out);
    }

    fn readBatch(self: *Source, out: []signal.Event) SysCallError!usize {
        var raw: [batch_max]std.os.linux.signalfd_siginfo = undefined;
        const bytes = std.mem.sliceAsBytes(raw[0..out.len]);
        const rc = std.os.linux.read(self.fd, bytes.ptr, bytes.len);
        switch (io.syscallErrno(rc)) {
            .SUCCESS => {},
            .INTR => unreachable,
            .AGAIN => return 0,
            else => |e| {
                @branchHint(.cold);
                log.err("unable to read sigfd: {e}", .{e});
                return error.SysCallError;
            },
        }

        const got = rc / @sizeOf(std.os.linux.signalfd_siginfo);
        // The kernel writes whole records and never more than the buffer holds.
        checks.check(rc % @sizeOf(std.os.linux.signalfd_siginfo) == 0);
        checks.check(got <= out.len);
        for (raw[0..got], out[0..got]) |raw_info, *event| {
            event.* = .{
                .signo = raw_info.signo,
                .code = raw_info.code,
                .value = raw_info.ptr,
            };
        }

        return got;
    }
};
