// SPDX-FileCopyrightText: 2026 YuMing He <ComixHe1895@outlook.com>
//
// SPDX-License-Identifier: MIT

//! The child side of the fork: what runs between clone/fork and exec, and what
//! happens if exec fails.

const std = @import("std");
const io = @import("io.zig");
const log = @import("log.zig");
const fmt = @import("fmt.zig");
const str = @import("str.zig");
const signal = @import("signal.zig");
const signalfd = @import("signalfd.zig");

const Sig = signal.Sig;
const SignalConfig = signalfd.Config;

/// What the child needs to run
pub const SpawnSpec = struct {
    argv: [*:null]const ?[*:0]const u8,
    envs: [:null]const ?[*:0]const u8,
    new_session: bool,
    ctty: ?std.os.linux.fd_t,
    pdeath_signal: ?u32,
    tracing_child: bool,
};

/// Report and hand back the code: this side has no panic machinery set up.
fn reportFailure(code: u8, parts: []const []const u8, errno: std.os.linux.E) u8 {
    var buf: [512]u8 = undefined;
    var out: usize = 0;
    out = fmt.appendBytes(&buf, out, "zinit child error: ");
    for (parts) |p| out = fmt.appendBytes(&buf, out, p);
    out = fmt.appendErrno(&buf, out, errno);
    log.err("{s}", .{buf[0..out]});
    return code;
}

fn execExitCode(errno: std.os.linux.E) u8 {
    return switch (errno) {
        .NOENT, .NOTDIR => 127,
        .ACCES, .NOEXEC => 126,
        else => 1,
    };
}

fn signalIsIgnored(sig: Sig) bool {
    var act: std.os.linux.Sigaction = undefined;
    if (io.syscallErrno(std.os.linux.sigaction(sig, null, &act)) != .SUCCESS) return false;
    return act.handler.handler == Sig.IGN;
}

/// Default search path used when `PATH` is unset (mirrors execvp).
const default_path = "/usr/local/bin:/usr/bin:/bin";

fn pathCandidate(dir: []const u8, file: []const u8, file_z: [*:0]const u8, buf: []u8) ?[*:0]const u8 {
    if (dir.len == 0) return file_z;
    if (dir.len + 1 + file.len >= buf.len) return null;

    @memcpy(buf[0..dir.len], dir);
    buf[dir.len] = '/';
    @memcpy(buf[dir.len + 1 ..][0..file.len], file);
    buf[dir.len + 1 + file.len] = 0;
    return @ptrCast(buf.ptr);
}

fn reportExec(file: []const u8, errno: std.os.linux.E) u8 {
    return reportFailure(execExitCode(errno), &.{ "unable to execve ", file, ": " }, errno);
}

fn execChild(argv: [*:null]const ?[*:0]const u8, envp: [*:null]const ?[*:0]const u8) u8 {
    const unblock_all = comptime std.os.linux.sigfillset();
    switch (io.syscallErrno(std.os.linux.sigprocmask(Sig.UNBLOCK, &unblock_all, null))) {
        .SUCCESS => {},
        else => |e| return reportFailure(1, &.{
            "unable to restore child signal state (unblock): ",
        }, e),
    }

    var path_buf: [std.os.linux.PATH_MAX]u8 = undefined;
    const file = std.mem.span(argv[0].?);

    if (str.indexOfByte(file, '/') != null) {
        const e = io.syscallErrno(std.os.linux.execve(argv[0].?, argv, envp));
        return reportExec(file, e);
    }

    const environ: std.process.Environ = .{ .block = .{ .slice = std.mem.span(envp) } };
    const path = environ.getPosix("PATH") orelse default_path;
    var last_errno: std.os.linux.E = .NOENT;
    var denied_errno: ?std.os.linux.E = null;
    var rest = path;

    while (true) {
        const colon = str.indexOfByte(rest, ':');
        const dir = if (colon) |cc| rest[0..cc] else rest;

        if (pathCandidate(dir, file, argv[0].?, &path_buf)) |candidate| {
            const e = io.syscallErrno(std.os.linux.execve(candidate, argv, envp));
            switch (e) {
                .SUCCESS => unreachable, // a successful exec replaces the process
                .ACCES => {
                    // Present but not executable: remember it, but keep searching.
                    denied_errno = e;
                    last_errno = e;
                },
                // A candidate that exists and is executable but has an unusable
                // format is a hard failure: trying another program with the same
                // name would run something the caller did not ask for.
                .NOEXEC => return reportExec(file, e),
                .NOENT, .NOTDIR, .NAMETOOLONG, .LOOP => last_errno = e,
                else => return reportExec(file, e),
            }
        }

        const adv = colon orelse break;
        rest = rest[adv + 1 ..];
    }

    const final_errno = denied_errno orelse last_errno;
    return reportExec(file, final_errno);
}

fn waitForTracer(signal_config: *const SignalConfig) ?u8 {
    std.debug.assert(std.os.linux.sigismember(&signal_config.current_set, Sig.USR1));

    const usr1 = comptime blk: {
        var set = std.os.linux.sigemptyset();
        std.os.linux.sigaddset(&set, Sig.USR1);
        break :blk set;
    };

    while (true) {
        const rc = std.os.linux.syscall4(
            .rt_sigtimedwait,
            @intFromPtr(&usr1),
            0,
            0,
            std.os.linux.NSIG / 8,
        );

        switch (io.syscallErrno(rc)) {
            .SUCCESS => return null,
            // STOP/CONT can interrupt the wait even though USR1 stays blocked.
            // Returning here would exec the workload before the tracer releases it.
            // see: https://man7.org/linux/man-pages/man2/rt_sigtimedwait.2.html#NOTES
            .INTR => continue,
            else => |e| {
                @branchHint(.unlikely);
                return reportFailure(1, &.{"failed to wait for USR1: "}, e);
            },
        }
    }
}

fn parentIsForeground(tty_fd: std.os.linux.fd_t) bool {
    var foreground: std.os.linux.pid_t = 0;
    if (io.syscallErrno(std.os.linux.tcgetpgrp(tty_fd, &foreground)) != .SUCCESS) {
        @branchHint(.unlikely);
        return false;
    }

    const raw_pgrp = std.os.linux.getpgid(std.os.linux.getppid());
    if (io.syscallErrno(raw_pgrp) != .SUCCESS) {
        @branchHint(.unlikely);
        return false;
    }

    const parent_pgrp: std.os.linux.pid_t = @intCast(raw_pgrp);
    return foreground == parent_pgrp;
}

fn setupTerminal(spec: SpawnSpec) ?u8 {
    if (spec.new_session) {
        const sid = std.os.linux.setsid();
        const err = io.syscallErrno(sid);
        if (err != .SUCCESS) {
            @branchHint(.unlikely);
            return reportFailure(1, &.{"unable to create session: "}, err);
        }
    } else {
        const rc = std.os.linux.setpgid(0, 0);
        const err = io.syscallErrno(rc);
        if (err != .SUCCESS) {
            @branchHint(.unlikely);
            return reportFailure(1, &.{"unable to create process group: "}, err);
        }
    }

    const tty_fd = spec.ctty orelse return null;

    if (spec.new_session) {
        const rc = std.os.linux.ioctl(tty_fd, std.os.linux.T.IOCSCTTY, 0);
        switch (io.syscallErrno(rc)) {
            .SUCCESS => {},
            .PERM, .NOTTY, .NXIO => |e| log.debug("{s}: {e}", .{ "unable to acquire controlling tty", e }),
            else => |e| log.warn("{s}: {e}", .{ "unable to acquire controlling tty", e }),
        }
    }

    // Only inherit the foreground when zinit itself owned it. A background
    // `zinit -- ... < /dev/null &` must not steal the shell's terminal just because
    // stdout/stderr still names the controlling tty. `-n` is the explicit case
    // where a new session acquires the tty and takes it over.
    if (spec.new_session or parentIsForeground(tty_fd)) {
        // The child's group has to be foreground or a program reading the terminal is
        // stopped by SIGTTIN; this must run while SIGTTOU is still ignored.
        std.debug.assert(signalIsIgnored(Sig.TTOU));
        const pgrp: std.os.linux.pid_t = std.os.linux.getpid();
        switch (io.syscallErrno(std.os.linux.tcsetpgrp(tty_fd, &pgrp))) {
            .SUCCESS, .NOTTY, .NXIO => {},
            // Anything but the no-terminal cases leaves the child in the background.
            else => |e| log.warn("{s}: {e}", .{ "unable to set foreground process group", e }),
        }
    }

    return null;
}

/// Runs in the forked child and never returns to the parent's code path: it
/// either execs the workload or exits with the failure code.
pub fn run(spec: SpawnSpec, signal_config: *const SignalConfig, parent: std.os.linux.pid_t) u8 {
    if (setupTerminal(spec)) |code| return code;

    if (signal_config.restoreChild()) |failure| return reportFailure(1, &.{
        "unable to restore child signal state (", @tagName(failure.step), "): ",
    }, failure.errno);

    if (spec.pdeath_signal) |sig| {
        const option = @backingInt(std.os.linux.PR.SET_PDEATHSIG);
        const rc = std.os.linux.prctl(option, sig, 0, 0, 0);
        switch (io.syscallErrno(rc)) {
            .SUCCESS => {
                // PDEATHSIG only trigger for a death after it is set. If the parent is
                // already gone, nobody will ever tell us, so die the way it promised,
                // the signal is still blocked here and lands before `execve`.
                if (std.os.linux.getppid() != parent) {
                    _ = std.os.linux.kill(std.os.linux.getpid(), @fromBackingInt(@intCast(sig)));
                }
            },
            else => |e| return reportFailure(1, &.{
                "unable to set parent death signal: ",
            }, e),
        }
    }

    if (spec.tracing_child) {
        if (waitForTracer(signal_config)) |code| return code;
    }

    return execChild(spec.argv, spec.envs);
}

// kcov-exclude-tests (everything below is test-only).
// Real fork/exec/PATH checks live in tests/integration/process.zig; this is the
// pure mapping that stays in the unit target.
test "execExitCode maps an errno to an exit code" {
    try std.testing.expectEqual(@as(u8, 127), execExitCode(.NOENT));
    try std.testing.expectEqual(@as(u8, 127), execExitCode(.NOTDIR));
    try std.testing.expectEqual(@as(u8, 126), execExitCode(.ACCES));
    try std.testing.expectEqual(@as(u8, 126), execExitCode(.NOEXEC));
    try std.testing.expectEqual(@as(u8, 1), execExitCode(.INVAL));
}
