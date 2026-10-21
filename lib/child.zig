// SPDX-FileCopyrightText: 2026 YuMing He <ComixHe1895@outlook.com>
//
// SPDX-License-Identifier: MIT

//! The child side of the fork: setup before exec, and what happens if exec fails.

const std = @import("std");
const builtin = @import("builtin");

const errors = @import("errors.zig");
const log = @import("log.zig");
const fmt = @import("fmt.zig");
const io = @import("io.zig");
const str = @import("str.zig");
const signal = @import("signal.zig");
const signalfd = @import("signalfd.zig");

const ZinitError = errors.ZinitError;
const Sig = signal.Sig;
const SignalConfig = signalfd.Config;
const tryClose = io.tryClose;
const wait = @import("wait.zig");
const WaitStatus = wait.WaitStatus;

/// What the child needs to run, narrowed so new CLI options never reach this file.
pub const SpawnSpec = struct {
    argv: [*:null]const ?[*:0]const u8,
    envs: [:null]const ?[*:0]const u8,
    new_session: bool,
    is_terminal: bool,
    pdeath_signal: ?u32,
    tracing_child: bool,
};

/// Report and hand back the code: this side has no panic machinery set up.
fn reportFailure(code: u8, parts: []const []const u8, errno: ?std.os.linux.E) u8 {
    var buf: [512]u8 = undefined;
    var out: usize = 0;
    out = fmt.appendBytes(&buf, out, "zinit child error: ");
    for (parts) |p| out = fmt.appendBytes(&buf, out, p);
    if (errno) |e| out = fmt.appendErrno(&buf, out, e);
    log.err("{s}", .{buf[0..out]});
    return code;
}

fn execExitCode(errno: std.os.linux.E) u8 {
    return switch (errno) {
        .NOENT => 127,
        .ACCES, .NOEXEC => 126,
        else => 1,
    };
}

fn signalIsIgnored(sig: Sig) bool {
    var act: std.os.linux.Sigaction = undefined;
    if (std.os.linux.errno(std.os.linux.sigaction(sig, null, &act)) != .SUCCESS) return false;
    return act.handler.handler == Sig.IGN;
}

/// Default search path used when `PATH` is unset (mirrors execvp).
const default_path = "/usr/local/bin:/usr/bin:/bin";

fn envValue(envp: [*:null]const ?[*:0]const u8, name: []const u8) ?[]const u8 {
    var i: usize = 0;
    while (envp[i]) |entry| : (i += 1) {
        const entry_text = std.mem.span(entry);
        if (entry_text.len > name.len and entry_text[name.len] == '=' and str.eql(entry_text[0..name.len], name)) {
            return entry_text[name.len + 1 ..];
        }
    }

    return null;
}

fn pathCandidate(dir: []const u8, file: []const u8, file_z: [*:0]const u8, buf: []u8) ?[*:0]const u8 {
    if (dir.len == 0) return file_z;
    if (dir.len + 1 + file.len >= buf.len) return null;

    @memcpy(buf[0..dir.len], dir);
    buf[dir.len] = '/';
    @memcpy(buf[dir.len + 1 ..][0..file.len], file);
    buf[dir.len + 1 + file.len] = 0;
    return @ptrCast(buf.ptr);
}

fn execChild(argv: [*:null]const ?[*:0]const u8, envp: [*:null]const ?[*:0]const u8) u8 {
    var unblock_all = std.os.linux.sigfillset();
    switch (std.os.linux.errno(std.os.linux.sigprocmask(Sig.UNBLOCK, &unblock_all, null))) {
        .SUCCESS => {},
        else => |e| return reportFailure(1, &.{
            "unable to restore child signal state (unblock): ",
        }, e),
    }

    var path_buf: [std.os.linux.PATH_MAX]u8 = undefined;
    const file = std.mem.span(argv[0].?);

    if (str.indexOfByte(file, '/') != null) {
        const e = std.os.linux.errno(std.os.linux.execve(argv[0].?, argv, envp));
        return reportFailure(execExitCode(e), &.{ "unable to execve ", file, ": " }, e);
    }

    const path = envValue(envp, "PATH") orelse default_path;
    var last_errno: std.os.linux.E = .NOENT;
    var rest = path;
    while (true) {
        const colon = str.indexOfByte(rest, ':');
        const dir = if (colon) |cc| rest[0..cc] else rest;

        if (pathCandidate(dir, file, argv[0].?, &path_buf)) |candidate| {
            const e = std.os.linux.errno(std.os.linux.execve(candidate, argv, envp));
            switch (e) {
                .SUCCESS => unreachable, // a successful exec replaces the process
                .ACCES, .NOENT, .NOTDIR, .NAMETOOLONG, .LOOP => last_errno = e,
                else => return reportFailure(execExitCode(e), &.{
                    "unable to execve ", file, ": ",
                }, e),
            }
        }

        const adv = colon orelse break;
        rest = rest[adv + 1 ..];
    }

    return reportFailure(execExitCode(last_errno), &.{
        "unable to execve ", file, ": ",
    }, last_errno);
}

fn waitForTracer(signal_config: *const SignalConfig) void {
    // A signal must be blocked to be waited for this way
    // the parent blocks this one with everything else it forwards,
    // and nothing since has changed the mask.
    if (builtin.mode == .debug) {
        std.debug.assert(std.os.linux.sigismember(&signal_config.current_set, Sig.USR1));
    }

    var usr1 = std.os.linux.sigemptyset();
    std.os.linux.sigaddset(&usr1, Sig.USR1);

    while (true) {
        const rc = std.os.linux.syscall4(
            .rt_sigtimedwait,
            @intFromPtr(&usr1),
            0,
            0,
            std.os.linux.NSIG / 8,
        );

        switch (std.os.linux.errno(rc)) {
            .SUCCESS => return,
            .INTR => unreachable,
            else => |e| {
                log.warn("{s}: {e}", .{ "failed to wait for USR1", e });
                return;
            },
        }
    }
}

inline fn childEntry(spec: SpawnSpec, signal_config: *const SignalConfig, parent: std.os.linux.pid_t) u8 {
    if (setupTerminal(spec)) |code| return code;

    if (signal_config.restoreChild()) |failure| return reportFailure(1, &.{
        "unable to restore child signal state (", @tagName(failure.step), "): ",
    }, failure.errno);

    if (spec.pdeath_signal) |sig| {
        const option = @backingInt(std.os.linux.PR.SET_PDEATHSIG);
        const rc = std.os.linux.prctl(option, sig, 0, 0, 0);
        switch (std.os.linux.errno(rc)) {
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

    if (spec.tracing_child) waitForTracer(signal_config);

    return execChild(spec.argv, spec.envs);
}

/// pid is unconditional (it tells the child apart and, without a pidfd, is what is
/// signalled). pidfd is an extra mechanism, null before Linux 5.2. Neither can be
/// recycled while the child, or any group member, holds its `struct pid`.
pub const ProcessHandle = struct {
    pid: std.os.linux.pid_t,
    pidfd: ?std.os.linux.fd_t,

    pub fn close(self: ProcessHandle) void {
        if (self.pidfd) |fd| tryClose(fd);
    }
};

pub fn spawn(spec: SpawnSpec, signal_config: *const SignalConfig) !ProcessHandle {
    const self_pid = std.os.linux.getpid();
    const flags: u32 = @backingInt(Sig.CHLD) | std.os.linux.CLONE.PIDFD;
    var pidfd: std.os.linux.fd_t = -1;
    const rc = std.os.linux.syscall5(.clone, flags, 0, @intFromPtr(&pidfd), 0, 0);

    const pid = switch (std.os.linux.errno(rc)) {
        .SUCCESS => rc,
        .INVAL, .NOSYS => blk: {
            const forked = std.os.linux.fork();
            switch (std.os.linux.errno(forked)) {
                .SUCCESS => break :blk forked,
                else => |e| {
                    @branchHint(.cold);
                    log.err("unable to fork: {e}", .{e});
                    return ZinitError.SysCallError;
                },
            }
        },
        else => |e| {
            @branchHint(.cold);
            log.err("unable to clone: {e}", .{e});
            return ZinitError.SysCallError;
        },
    };

    if (pid != 0) {
        if (!spec.new_session) {
            const child_pid: std.os.linux.pid_t = @intCast(pid);
            _ = std.os.linux.setpgid(child_pid, child_pid);
        }

        log.debug("spawned child {d} ({s})", .{ pid, if (pidfd >= 0) "pidfd" else "fork" });
        return .{
            .pid = @intCast(pid),
            .pidfd = if (pidfd >= 0) pidfd else null,
        };
    }

    std.os.linux.exit(childEntry(spec, signal_config, self_pid));
}

pub fn detachFromTerminal(spec: SpawnSpec) bool {
    if (!(spec.new_session and spec.is_terminal)) return false;

    const rc = std.os.linux.ioctl(std.os.linux.STDIN_FILENO, std.os.linux.T.IOCNOTTY, 0);
    switch (std.os.linux.errno(rc)) {
        .SUCCESS => {},
        .NOTTY, .NXIO, .PERM => |e| {
            log.debug("{s}: {e}", .{ "unable to detach from terminal", e });
            return false;
        },
        else => |e| {
            log.warn("{s}: {e}", .{ "unable to detach from terminal", e });
            return false;
        },
    }

    if (std.os.linux.getsid(0) != std.os.linux.getpid()) {
        log.debug("detached from controlling terminal, but was not session leader", .{});
        return false;
    }

    log.debug("detaching from controlling terminal, ignoring initial HUP/CONT", .{});
    return true;
}

fn setupTerminal(spec: SpawnSpec) ?u8 {
    // Its own group, so shutdown can signal the whole subtree.
    if (spec.new_session) {
        const sid = std.os.linux.setsid();
        const err = std.os.linux.errno(sid);
        if (err != .SUCCESS) {
            return reportFailure(1, &.{"unable to create session: "}, err);
        }
    } else {
        const rc = std.os.linux.setpgid(0, 0);
        const err = std.os.linux.errno(rc);
        if (err != .SUCCESS) {
            return reportFailure(1, &.{"unable to create process group: "}, err);
        }
    }

    if (!spec.is_terminal) return null;

    if (spec.new_session) {
        const rc = std.os.linux.ioctl(std.os.linux.STDIN_FILENO, std.os.linux.T.IOCSCTTY, 0);
        switch (std.os.linux.errno(rc)) {
            .SUCCESS => {},
            .PERM, .NOTTY, .NXIO => |e| log.debug("{s}: {e}", .{ "unable to acquire controlling tty", e }),
            else => |e| log.warn("{s}: {e}", .{ "unable to acquire controlling tty", e }),
        }
    }

    // The child's group has to be foreground or a program reading the terminal is
    // stopped by SIGTTIN; this must run while SIGTTOU is still ignored.
    if (builtin.mode == .debug) std.debug.assert(signalIsIgnored(Sig.TTOU));
    const pgrp: std.os.linux.pid_t = std.os.linux.getpid();
    switch (std.os.linux.errno(std.os.linux.tcsetpgrp(std.os.linux.STDIN_FILENO, &pgrp))) {
        .SUCCESS, .NOTTY, .NXIO => {},
        // Anything but the no-terminal cases leaves the child in the background.
        else => |e| log.warn("{s}: {e}", .{ "unable to set foreground process group", e }),
    }

    return null;
}

// kcov-exclude-tests (everything below is test-only).
test "execExitCode maps an errno to an exit code" {
    try std.testing.expectEqual(@as(u8, 127), execExitCode(.NOENT));
    try std.testing.expectEqual(@as(u8, 126), execExitCode(.ACCES));
    try std.testing.expectEqual(@as(u8, 126), execExitCode(.NOEXEC));
    try std.testing.expectEqual(@as(u8, 1), execExitCode(.INVAL));
}

/// Spawns one child and reaps it, so a test can assert on its exit code.
/// Bounded, so a child that never exits fails the test instead of hanging the runner.
fn waitForExit(pid: std.os.linux.pid_t) !WaitStatus {
    var status: i32 = 0;
    var spins: usize = 0;
    while (true) : (spins += 1) {
        const rc = std.os.linux.waitpid(pid, &status, std.os.linux.W.NOHANG);
        if (rc == @as(usize, @intCast(pid))) return WaitStatus.fromRaw(status);
        if (spins > 1_000_000) return error.TestUnexpectedResult;
        _ = std.os.linux.sched_yield();
    }
}

fn spawnAndWait(spec: SpawnSpec) !u8 {
    const signal_config = try SignalConfig.init(&[_]Sig{.TERM});
    const child_handle = try spawn(spec, &signal_config);
    defer child_handle.close();

    return (try waitForExit(child_handle.pid)).exitCode();
}

test "the child resolves a relative command through PATH" {
    // The first entry does not exist, so the search has to keep going.
    const code = try spawnAndWait(.{
        .argv = &[_:null]?[*:0]const u8{"true"},
        .envs = &[_:null]?[*:0]const u8{"PATH=/nonexistent-zinit-dir:/bin:/usr/bin"},
        .new_session = false,
        .is_terminal = false,
        .pdeath_signal = null,
        .tracing_child = false,
    });

    try std.testing.expectEqual(@as(u8, 0), code);
}

test "a command that cannot be exec'd exits through the child error path" {
    // The sink is poisoned so the child's diagnostic does not reach the test log.
    log.init(-1);
    defer log.init(log.default_sink);

    const code = try spawnAndWait(.{
        .argv = &[_:null]?[*:0]const u8{"/nonexistent-zinit-prog"},
        .envs = &[_:null]?[*:0]const u8{},
        .new_session = false,
        .is_terminal = false,
        .pdeath_signal = null,
        .tracing_child = false,
    });

    try std.testing.expectEqual(@as(u8, 127), code);
}

test "a bare name that no PATH entry holds fails the same way" {
    log.init(-1);
    defer log.init(log.default_sink);

    // No slash: every directory is tried, and the last errno decides the code.
    const code = try spawnAndWait(.{
        .argv = &[_:null]?[*:0]const u8{"nonexistent-zinit-prog"},
        .envs = &[_:null]?[*:0]const u8{"PATH=/bin:/usr/bin"},
        .new_session = false,
        .is_terminal = false,
        .pdeath_signal = null,
        .tracing_child = false,
    });

    try std.testing.expectEqual(@as(u8, 127), code);
}

test "a new session claiming a terminal still execs without one" {
    // `is_terminal` is only a claim; with no tty the ioctls report NOTTY/NXIO.
    const code = try spawnAndWait(.{
        .argv = &[_:null]?[*:0]const u8{"/bin/true"},
        .envs = &[_:null]?[*:0]const u8{},
        .new_session = true,
        .is_terminal = true,
        .pdeath_signal = null,
        .tracing_child = false,
    });

    try std.testing.expectEqual(@as(u8, 0), code);
}

test "a relative command is found on the default path when PATH is unset" {
    // `execvp` falls back to a built-in path, and so does this.
    const code = try spawnAndWait(.{
        .argv = &[_:null]?[*:0]const u8{"true"},
        .envs = &[_:null]?[*:0]const u8{},
        .new_session = false,
        .is_terminal = false,
        .pdeath_signal = null,
        .tracing_child = false,
    });

    try std.testing.expectEqual(@as(u8, 0), code);
}

test "a tracing child waits for SIGUSR1 before it execs" {
    const signal_config = try SignalConfig.init(&[_]Sig{});
    const spawned = try spawn(.{
        .argv = &[_:null]?[*:0]const u8{"/bin/true"},
        .envs = &[_:null]?[*:0]const u8{},
        .new_session = false,
        .is_terminal = false,
        .pdeath_signal = null,
        .tracing_child = true,
    }, &signal_config);
    defer spawned.close();

    _ = std.os.linux.kill(spawned.pid, Sig.USR1);

    const status = waitForExit(spawned.pid) catch |err| {
        _ = std.os.linux.kill(spawned.pid, Sig.KILL);
        return err;
    };

    try std.testing.expectEqual(@as(u8, 0), status.exitCode());
}
