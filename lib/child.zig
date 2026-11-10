// SPDX-FileCopyrightText: 2026 YuMing He <ComixHe1895@outlook.com>
//
// SPDX-License-Identifier: MIT

//! The child side of the fork: what runs between clone/fork and exec, and what
//! happens if exec fails.

const std = @import("std");
const checks = @import("checks.zig");
const io = @import("io.zig");
const log = @import("log.zig");
const fmt = @import("fmt.zig");
const str = @import("str.zig");
const signal = @import("signal.zig");
const signalfd = @import("signalfd.zig");
const exec_error = @import("exec_error.zig");

const Sig = signal.Sig;
const SignalConfig = signalfd.Config;

pub const SpawnSpec = struct {
    argv: [*:null]const ?[*:0]const u8,
    envs: [:null]const ?[*:0]const u8 = &.{},
    new_session: bool = false,
    ctty: ?std.os.linux.fd_t = null,
    pdeath_signal: ?u32 = null,
    tracing_child: bool = false,
};

fn formatFailure(buf: []u8, parts: []const []const u8, errno: std.os.linux.E) []const u8 {
    var out: usize = 0;
    out = fmt.appendBytes(buf, out, "zinit child error: ");
    for (parts) |p| out = fmt.appendBytes(buf, out, p);
    out = fmt.appendErrno(buf, out, errno);
    return buf[0..out];
}

/// Reports a failure and exits: this side has no panic machinery. Callers
/// block the forwarded signals, so a broken stderr cannot turn the report into
/// SIGPIPE's 141.
fn reportFailure(parts: []const []const u8, errno: std.os.linux.E) noreturn {
    checks.checkLazy(signalIsBlocked, .{Sig.PIPE}, "child: the failure report must run with signals blocked");

    var buf: [exec_error.max_message]u8 = undefined;
    log.err("{s}", .{formatFailure(&buf, parts, errno)});
    std.os.linux.exit(1);
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

fn signalIsBlocked(sig: Sig) bool {
    var current: std.os.linux.sigset_t = undefined;
    if (io.syscallErrno(std.os.linux.sigprocmask(Sig.BLOCK, null, &current)) != .SUCCESS) return false;
    return std.os.linux.sigismember(&current, sig);
}

/// Default search path used when `PATH` is unset (mirrors execvp).
const default_path = "/usr/local/bin:/usr/bin:/bin";

fn pathCandidate(
    dir: []const u8,
    file: []const u8,
    file_z: [*:0]const u8,
    buf: []u8,
) ?[*:0]const u8 {
    if (dir.len == 0) return file_z;
    if (dir.len + 1 + file.len >= buf.len) {
        @branchHint(.unlikely);
        return null;
    }

    @memcpy(buf[0..dir.len], dir);
    buf[dir.len] = '/';
    @memcpy(buf[dir.len + 1 ..][0..file.len], file);
    buf[dir.len + 1 + file.len] = 0;
    return @ptrCast(buf.ptr);
}

fn reportExec(exec_error_fd: std.os.linux.fd_t, file: []const u8, errno: std.os.linux.E) u8 {
    var buf: [exec_error.max_message]u8 = undefined;
    exec_error.write(exec_error_fd, formatFailure(&buf, &.{ "unable to execve ", file, ": " }, errno));
    return execExitCode(errno);
}

/// Runs one `execve` under the mask zinit inherited. `execve` preserves the
/// mask, so the workload must not start with the supervisor's blocked one.
/// Failure re-blocks everything before the search and report continue; a
/// pending signal is delivered at the restore.
noinline fn execWithRestoredMask(
    signal_config: *const SignalConfig,
    file: [*:0]const u8,
    argv: [*:null]const ?[*:0]const u8,
    envp: [*:null]const ?[*:0]const u8,
) std.os.linux.E {
    const restore = io.syscallErrno(std.os.linux.sigprocmask(
        Sig.SETMASK,
        &signal_config.previous_set,
        null,
    ));
    if (restore != .SUCCESS) return restore;

    const errno = io.syscallErrno(std.os.linux.execve(file, argv, envp));
    const all = comptime std.os.linux.sigfillset();
    _ = std.os.linux.sigprocmask(Sig.BLOCK, &all, null);
    return errno;
}

fn execChild(
    signal_config: *const SignalConfig,
    exec_error_fd: std.os.linux.fd_t,
    argv: [*:null]const ?[*:0]const u8,
    envp: [*:null]const ?[*:0]const u8,
) u8 {
    var path_buf: [std.os.linux.PATH_MAX]u8 = undefined;
    const file = std.mem.span(argv[0].?);

    if (str.indexOfByte(file, '/') != null) {
        return reportExec(
            exec_error_fd,
            file,
            execWithRestoredMask(signal_config, argv[0].?, argv, envp),
        );
    }

    const path = str.getEnv(std.mem.span(envp), "PATH") orelse default_path;
    var last_errno: std.os.linux.E = .NOENT;
    var denied_errno: ?std.os.linux.E = null;
    var rest = path;

    while (true) {
        const colon = str.indexOfByte(rest, ':');
        const dir = if (colon) |cc| rest[0..cc] else rest;

        if (pathCandidate(dir, file, argv[0].?, &path_buf)) |candidate| {
            const e = execWithRestoredMask(signal_config, candidate, argv, envp);
            switch (e) {
                .SUCCESS => unreachable, // a successful exec replaces the process
                .ACCES => {
                    @branchHint(.unlikely);
                    denied_errno = e;
                },
                .NOEXEC => {
                    @branchHint(.cold);
                    return reportExec(exec_error_fd, file, e);
                },
                .NOENT, .NOTDIR, .NAMETOOLONG, .LOOP => {
                    @branchHint(.unlikely);
                    last_errno = e;
                },
                else => {
                    @branchHint(.cold);
                    return reportExec(exec_error_fd, file, e);
                },
            }
        }

        const adv = colon orelse break;
        rest = rest[adv + 1 ..];
    }

    const final_errno = denied_errno orelse last_errno;
    return reportExec(exec_error_fd, file, final_errno);
}

fn waitForTracer(signal_config: *const SignalConfig) ?u8 {
    checks.check(std.os.linux.sigismember(&signal_config.current_set, Sig.USR1), "child: SIGUSR1 must be blocked while waiting for the tracer");

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
                @branchHint(.cold);
                reportFailure(&.{"failed to wait for USR1: "}, e);
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
            @branchHint(.cold);
            reportFailure(&.{"unable to create session: "}, err);
        }
    } else {
        const rc = std.os.linux.setpgid(0, 0);
        const err = io.syscallErrno(rc);
        if (err != .SUCCESS) {
            @branchHint(.cold);
            reportFailure(&.{"unable to create process group: "}, err);
        }
    }

    const tty_fd = spec.ctty orelse return null;

    if (spec.new_session) {
        // TIOCSCTTY makes this new session's process group the foreground group,
        // so no tcsetpgrp is needed here.
        const rc = std.os.linux.ioctl(tty_fd, std.os.linux.T.IOCSCTTY, 0);
        switch (io.syscallErrno(rc)) {
            .SUCCESS => {},
            .PERM, .NOTTY, .NXIO => |e| log.debug(
                "{s}: {e}",
                .{ "unable to acquire controlling tty", e },
            ),
            else => |e| log.warn("{s}: {e}", .{ "unable to acquire controlling tty", e }),
        }
    } else if (parentIsForeground(tty_fd)) {
        // Only take the foreground when zinit owned it: a background zinit must
        // not steal the shell's terminal just because stdio still names it.
        // The child's group has to be foreground or a program reading the
        // terminal is stopped by SIGTTIN, this must run while SIGTTOU is still
        // ignored.
        checks.checkLazy(signalIsIgnored, .{Sig.TTOU}, "child: SIGTTOU must stay ignored while taking the terminal");
        const pgrp: std.os.linux.pid_t = std.os.linux.getpid();
        switch (io.syscallErrno(std.os.linux.tcsetpgrp(tty_fd, &pgrp))) {
            .SUCCESS, .NOTTY, .NXIO => {},
            else => |e| log.warn("{s}: {e}", .{ "unable to set foreground process group", e }),
        }
    }

    return null;
}

pub fn run(
    spec: SpawnSpec,
    signal_config: *const SignalConfig,
    parent: std.os.linux.pid_t,
    exec_error_fd: std.os.linux.fd_t,
) u8 {
    checks.check(spec.argv[0] != null, "child: spawn spec has no program name");
    checks.check(parent > 0, "child: parent pid must be positive in the child");
    if (spec.ctty) |fd| checks.check(fd >= 0, "child: controlling terminal descriptor is negative");
    if (setupTerminal(spec)) |code| return code;

    if (signal_config.restoreChild()) |failure| {
        @branchHint(.cold);
        reportFailure(&.{
            "unable to restore child signal state (", @tagName(failure.step), "): ",
        }, failure.errno);
    }

    if (spec.pdeath_signal) |sig| {
        const option = @backingInt(std.os.linux.PR.SET_PDEATHSIG);
        const rc = std.os.linux.prctl(option, sig, 0, 0, 0);
        switch (io.syscallErrno(rc)) {
            .SUCCESS => {
                // PDEATHSIG only triggers for a death after it is set. If the parent is
                // already gone, nobody will ever tell us, so send it ourselves. It is
                // still blocked here and is delivered when the first exec attempt
                // restores the caller's mask; if that mask blocks it, the workload
                // inherits it pending instead.
                if (std.os.linux.getppid() != parent) {
                    @branchHint(.unlikely);
                    _ = std.os.linux.kill(std.os.linux.getpid(), @fromBackingInt(@intCast(sig)));
                }
            },
            else => |e| {
                @branchHint(.cold);
                reportFailure(&.{
                    "unable to set parent death signal: ",
                }, e);
            },
        }
    }

    if (spec.tracing_child) {
        if (waitForTracer(signal_config)) |code| return code;
    }

    return execChild(signal_config, exec_error_fd, spec.argv, spec.envs);
}

// kcov-exclude-tests (everything below is test-only).
// Real fork/exec/PATH checks live in tests/integration/process.zig; this is the
// pure mapping that stays in the unit target.
test "pathCandidate keeps a bare name for an empty entry and skips an overlong path" {
    var buf: [16]u8 = undefined;

    const bare = pathCandidate("", "prog", "prog", &buf) orelse return error.TestUnexpectedResult;
    try std.testing.expectEqualStrings("prog", std.mem.span(bare));

    const joined = pathCandidate("d", "prog", "prog", &buf) orelse return error.TestUnexpectedResult;
    try std.testing.expectEqualStrings("d/prog", std.mem.span(joined));

    // dir + '/' + file + NUL no longer fits: skipped, never truncated.
    try std.testing.expect(pathCandidate("123456789012345", "prog", "prog", &buf) == null);
}

test "execExitCode maps an errno to an exit code" {
    try std.testing.expectEqual(@as(u8, 127), execExitCode(.NOENT));
    try std.testing.expectEqual(@as(u8, 127), execExitCode(.NOTDIR));
    try std.testing.expectEqual(@as(u8, 126), execExitCode(.ACCES));
    try std.testing.expectEqual(@as(u8, 126), execExitCode(.NOEXEC));
    try std.testing.expectEqual(@as(u8, 1), execExitCode(.INVAL));
}
