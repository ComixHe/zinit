// SPDX-FileCopyrightText: 2026 YuMing He <ComixHe1895@outlook.com>
//
// SPDX-License-Identifier: MIT

//! The parent side: reaping, signalling, forwarding and the shutdown grace period.

const std = @import("std");

const errors = @import("errors.zig");
const log = @import("log.zig");
const io = @import("io.zig");
const wait = @import("wait.zig");
const signal = @import("signal.zig");
const rewrite = @import("rewrite.zig");
const signalfd = @import("signalfd.zig");
const child = @import("child.zig");

const ZinitError = errors.ZinitError;
const Sig = signal.Sig;
const ExitCodeSet = wait.ExitCodeSet;
const tryClose = io.tryClose;
const WaitStatus = wait.WaitStatus;
const RewriteMap = rewrite.Map;
const SignalConfig = signalfd.Config;

const signal_quota: usize = 32;

/// Realtime signals queue, so one read can carry a backlog.
const signal_batch: usize = 8;

/// A queued signal's value: `kill` drops it, and for a realtime signal it is the content.
const Payload = struct { value: u64 };

/// The one `si_code` that means "carries a payload"; the kernel refuses any other from user space.
const SI_QUEUE: i32 = -1;

/// What the kernel stamps on a signal it raised itself (a timer, a terminal going away):
/// no sender, unlike `SI_USER`/`SI_QUEUE`/`SI_TKILL`, which always name one.
const SI_KERNEL: i32 = 0x80;

/// The sender the child sees is zinit: the original pid may mean nothing, or someone else, in a child namespace.
fn queuedInfo(sig: u32, payload: Payload) std.os.linux.siginfo_t {
    var info = std.mem.zeroes(std.os.linux.siginfo_t);
    info.signo = @fromBackingInt(@intCast(sig));
    info.code = SI_QUEUE;
    info.fields.common.first.piduid.pid = @intCast(std.os.linux.getpid());
    info.fields.common.first.piduid.uid = @intCast(std.os.linux.getuid());
    // Zero must take the int view: the pointer view of zero is a null pointer.
    if (payload.value == 0) {
        info.fields.common.second.value.int = 0;
    } else {
        info.fields.common.second.value.ptr = @ptrFromInt(payload.value);
    }

    return info;
}

const DrainResult = struct {
    main_code: ?u8 = null,
    no_children: bool,
};

pub const Policy = struct {
    expected_exit: ExitCodeSet,
    rewrites: ?RewriteMap,
    forward_group: bool,
    shutdown_timeout_ns: u64,
    ignore_initial_hup_cont: bool,
};

/// The 6.9 process-group scope flag; `unknown` until the first attempt, and no locking: single-threaded.
const PIDFD_SIGNAL_PROCESS_GROUP: u32 = 1 << 2;
const GroupFlag = enum { unknown, supported, unsupported };
var group_flag: GroupFlag = .unknown;

const ProcessState = struct {
    child: child.ProcessHandle,
    /// Once the main child is reaped it can receive nothing, and its number is free again.
    child_reaped: bool = false,
    sigfd: std.os.linux.fd_t,
    policy: Policy,
    shutdown: ?ShutdownState = null,
    ignore_hup: bool = false,
    ignore_cont: bool = false,

    fn init(policy: Policy, spawned: child.ProcessHandle, sigfd: std.os.linux.fd_t) ProcessState {
        return .{
            .child = spawned,
            .sigfd = sigfd,
            .policy = policy,
            .ignore_cont = policy.ignore_initial_hup_cont,
            .ignore_hup = policy.ignore_initial_hup_cont,
        };
    }

    fn signalChild(self: *const ProcessState, sig: u32, payload: ?Payload) bool {
        if (self.child_reaped) {
            log.debug("not signalling {d}: the child's exit was already reported", .{sig});
            return false;
        }

        const target: Sig = @fromBackingInt(@intCast(sig));
        const fd = self.child.pidfd orelse
            return self.reportChildSend(std.os.linux.kill(self.child.pid, target), sig);

        if (payload) |p| {
            var info = queuedInfo(sig, p);
            const rc = std.os.linux.pidfd_send_signal(fd, target, &info, 0);
            switch (std.os.linux.errno(rc)) {
                .SUCCESS => return true,
                .INVAL, .PERM => {},
                else => return self.reportChildSend(rc, sig),
            }
        }

        return self.reportChildSend(std.os.linux.pidfd_send_signal(fd, target, null, 0), sig);
    }

    fn reportChildSend(self: *const ProcessState, rc: usize, sig: u32) bool {
        switch (std.os.linux.errno(rc)) {
            .SUCCESS => return true,
            .SRCH => log.debug("no process to send signal {d} for pid {d}", .{ sig, @as(u32, @intCast(self.child.pid)) }),
            else => |errno| log.err("unable to send signal to child: {e}", .{errno}),
        }

        return false;
    }

    fn signalProcessGroup(self: *const ProcessState, sig: u32, payload: ?Payload) bool {
        const sent = if (group_flag == .unsupported)
            self.signalGroupByNumber(sig)
        else
            self.signalGroupByPidfd(sig, payload);

        return sent or self.signalChild(sig, payload);
    }

    fn signalGroupByPidfd(self: *const ProcessState, sig: u32, payload: ?Payload) bool {
        const fd = self.child.pidfd orelse return self.signalGroupByNumber(sig);
        const target: Sig = @fromBackingInt(@intCast(sig));

        if (payload) |p| {
            var info = queuedInfo(sig, p);
            const rc = std.os.linux.pidfd_send_signal(fd, target, &info, PIDFD_SIGNAL_PROCESS_GROUP);
            switch (std.os.linux.errno(rc)) {
                .SUCCESS => {
                    group_flag = .supported;
                    return true;
                },
                .NOSYS => {
                    group_flag = .unsupported;
                    return self.signalGroupByNumber(sig);
                },
                // No payload this time; the plain send below is the fallback.
                .INVAL, .PERM => {},
                // No such group: the caller falls back to the child itself.
                .SRCH => {
                    group_flag = .supported;
                    return false;
                },
                else => |errno| {
                    reportGroupFailure(errno, sig);
                    return false;
                },
            }
        }

        const rc = std.os.linux.pidfd_send_signal(fd, target, null, PIDFD_SIGNAL_PROCESS_GROUP);
        switch (std.os.linux.errno(rc)) {
            .SUCCESS => {
                group_flag = .supported;
                return true;
            },
            // Added in Linux 6.9: older kernels reject the flag or the syscall.
            .NOSYS, .INVAL => {
                group_flag = .unsupported;
                return self.signalGroupByNumber(sig);
            },
            .SRCH => {
                group_flag = .supported;
                return false;
            },
            else => |errno| {
                reportGroupFailure(errno, sig);
                return false;
            },
        }
    }

    /// Without the 6.9 flag the raw ID is all there is, so waitid has to prove the
    /// group is still ours: a hit means its `struct pid` is still in the idr.
    fn signalGroupByNumber(self: *const ProcessState, sig: u32) bool {
        const flags = std.os.linux.W.EXITED | std.os.linux.W.NOHANG | std.os.linux.W.NOWAIT;
        var info: std.os.linux.siginfo_t = undefined;
        switch (std.os.linux.errno(std.os.linux.waitid(.PGID, self.child.pid, &info, flags, null))) {
            .SUCCESS => {},
            else => {
                log.debug("not signalling {d}: no child of ours is left in that group", .{sig});
                return false;
            },
        }

        const pgid: usize = @intCast(self.child.pid);
        const rc = std.os.linux.kill(-self.child.pid, @fromBackingInt(@intCast(sig)));
        switch (std.os.linux.errno(rc)) {
            .SUCCESS => return true,
            .SRCH => log.debug("no process group for signal {d} (pgid {d})", .{ sig, pgid }),
            else => |errno| reportGroupFailure(errno, sig),
        }

        return false;
    }

    fn reportGroupFailure(errno: std.os.linux.E, sig: u32) void {
        log.err("unable to send signal {d} to process group: {e}", .{ sig, errno });
    }

    fn forwardSignal(self: *ProcessState, sig_info: *const std.os.linux.signalfd_siginfo) void {
        const signo = sig_info.signo;

        // Giving up the terminal queues one HUP and one CONT for us, and the kernel is the
        // one who sent them: no sender. A HUP from a user is a different event and must
        // reach the child like any other, even if it is the first one we see.
        const from_kernel = sig_info.code == SI_KERNEL;

        if (from_kernel and self.ignore_hup and signo == @backingInt(Sig.HUP)) {
            self.ignore_hup = false;
            return;
        }

        if (from_kernel and self.ignore_cont and signo == @backingInt(Sig.CONT)) {
            self.ignore_cont = false;
            return;
        }

        const signal_to_send = RewriteMap.apply(if (self.policy.rewrites) |*m| m else null, signo);
        if (signal_to_send == 0) {
            log.debug("dropping signal {d}", .{signo});
            return;
        }

        // Only a queued signal carries a value, anything else would hand the child a meaningless one.
        const payload: ?Payload = if (sig_info.code == SI_QUEUE) .{ .value = sig_info.ptr } else null;
        if (signal_to_send == signo) {
            log.debug("forwarding signal {d}", .{signo});
        } else {
            log.debug("forwarding signal {d} as {d}", .{ signo, signal_to_send });
        }

        const delivered = if (self.policy.forward_group)
            self.signalProcessGroup(signal_to_send, payload)
        else
            self.signalChild(signal_to_send, payload);

        // A shell watches us, not the child: a stop has to stop us too, and only when it delivered.
        if (stopsSelf(signo, signal_to_send, delivered)) {
            // An init stopping itself is surprising enough to be worth a trace.
            log.debug("stopping to stay in step with the child's {d}", .{signal_to_send});
            _ = std.os.linux.kill(std.os.linux.getpid(), Sig.STOP);
        }
    }

    /// Follows the signal the child ends up with, not the one we were handed: a rewrite
    /// such as `TSTP:CONT` asks for a running child, and stopping then would strand the shell.
    fn stopsSelf(original: u32, target: u32, delivered: bool) bool {
        if (!delivered or !isJobControl(original)) return false;
        return suspends(target);
    }

    fn isJobControl(sig: u32) bool {
        return sig == @backingInt(Sig.TSTP) or
            sig == @backingInt(Sig.TTIN) or
            sig == @backingInt(Sig.TTOU);
    }

    fn suspends(sig: u32) bool {
        return sig == @backingInt(Sig.STOP) or
            sig == @backingInt(Sig.TSTP) or
            sig == @backingInt(Sig.TTIN) or
            sig == @backingInt(Sig.TTOU);
    }

    pub fn handleSignalEvent(self: *ProcessState) ?u8 {
        var budget: usize = signal_quota;

        while (budget > 0) {
            var batch: [signal_batch]std.os.linux.signalfd_siginfo = undefined;
            const batch_bytes = std.mem.asBytes(&batch);
            const room = @as(usize, @min(budget, batch.len)) * @sizeOf(std.os.linux.signalfd_siginfo);
            const rc = std.os.linux.read(self.sigfd, batch_bytes.ptr, room);

            switch (std.os.linux.errno(rc)) {
                .SUCCESS => {},
                .INTR => unreachable,
                .AGAIN => return null,
                else => |e| {
                    @branchHint(.cold);
                    log.err("unable to read sigfd: {e}", .{e});
                    return 1;
                },
            }

            const got = rc / @sizeOf(std.os.linux.signalfd_siginfo);
            for (batch[0..got]) |*sig_info| {
                budget -= 1;

                // Realtime signals are forwarded like any other, or their values would be lost.
                // SIGCHLD needs no line of its own: the reap below reports the exit.
                if (sig_info.signo != @backingInt(Sig.CHLD)) {
                    @branchHint(.unpredictable);
                    log.debug("receive signal: {d}", .{sig_info.signo});
                    self.forwardSignal(sig_info);
                    continue;
                }

                // `drain` already reported the errno; the error name would only bury it.
                const reap = drain(self.child.pid, self.policy.expected_exit, self.child_reaped) catch {
                    @branchHint(.cold);
                    return 1;
                };

                if (reap.main_code != null) self.child_reaped = true;

                if (reap.main_code) |code| {
                    if (reap.no_children) return code;
                    if (self.shutdown == null) return self.beginShutdown(code);
                } else if (self.shutdown != null and reap.no_children) {
                    return self.shutdown.?.exit_code;
                }
            }
        }

        return null;
    }

    fn beginShutdown(self: *ProcessState, exit_code: u8) ?u8 {
        const deadline = monotonicNs() +| self.policy.shutdown_timeout_ns;
        self.shutdown = .{ .exit_code = exit_code, .deadline_ns = deadline };
        log.debug("child exited, {d}ms grace for descendants before SIGKILL", .{
            self.policy.shutdown_timeout_ns / std.time.ns_per_ms,
        });

        _ = self.signalProcessGroup(@backingInt(Sig.TERM), null);
        return null;
    }

    pub fn onShutdownTimeout(self: *ProcessState) ?u8 {
        const sd = &(self.shutdown orelse return null);

        log.warn("grace period elapsed, descendants still running: sending SIGKILL", .{});
        _ = self.signalProcessGroup(@backingInt(Sig.KILL), null);

        // Reap what has died, but never wait: an unkillable descendant must not keep zinit
        // alive. `drain` reports its own errno.
        _ = drain(self.child.pid, .empty, self.child_reaped) catch return sd.exit_code;

        return sd.exit_code;
    }
};

const ShutdownState = struct {
    exit_code: u8,
    /// CLOCK_MONOTONIC deadline (ns) at which the process group gets SIGKILLed.
    deadline_ns: u64,

    pub fn remainingMs(self: *const ShutdownState) i32 {
        const now = monotonicNs();
        if (now >= self.deadline_ns) return 0;
        const remaining_ns = self.deadline_ns - now;
        const ms = (remaining_ns +| (std.time.ns_per_ms - 1)) / std.time.ns_per_ms;
        return @intCast(@min(ms, std.math.maxInt(i32)));
    }
};

fn drain(child_pid: std.os.linux.pid_t, expected_exit: ExitCodeSet, main_reaped: bool) !DrainResult {
    var result: DrainResult = .{ .no_children = false };
    var status: i32 = 0;

    while (true) {
        const rc = std.os.linux.waitpid(-1, &status, std.os.linux.W.NOHANG);
        if (rc == 0) return result; // children remain

        switch (std.os.linux.errno(rc)) {
            .SUCCESS => {
                const pid: std.os.linux.pid_t = @intCast(rc);
                const wait_status = WaitStatus.fromRaw(status);
                if (!main_reaped and pid == child_pid) {
                    log.processExited(pid, wait_status, .main);
                    const code = wait_status.exitCode();
                    if (expected_exit.isSet(code)) {
                        if (code != 0) log.debug("exit code {d} mapped to 0 by --expect-exit", .{code});
                        result.main_code = 0;
                    } else {
                        result.main_code = code;
                    }
                } else {
                    log.processExited(pid, wait_status, .orphaned);
                }
            },
            .CHILD => {
                result.no_children = true;
                return result;
            },
            else => |errno| {
                log.err("unable to reap a child: {e}", .{errno});
                return ZinitError.SysCallError;
            },
        }
    }
}

pub fn setupSubreaper(subreaper: bool) !void {
    if (subreaper) {
        const option = @backingInt(std.os.linux.PR.SET_CHILD_SUBREAPER);
        switch (std.os.linux.errno(std.os.linux.prctl(option, 1, 0, 0, 0))) {
            .SUCCESS => {},
            else => |e| {
                @branchHint(.cold);
                log.err("unable to enable child subreaper mode: {e}", .{e});
                return ZinitError.SysCallError;
            },
        }
    } else if (std.os.linux.getpid() != 1) {
        log.warn(
            "not PID 1 and not a subreaper: orphaned descendants will not be reaped here, pass -s/--subreaper to adopt them",
            .{},
        );
    }
}

fn monotonicNs() u64 {
    var ts = std.mem.zeroes(std.os.linux.timespec);
    // Raw syscall: the std wrapper drags in the vDSO lookup for about a kilobyte.
    const clock = @as(u32, @bitCast(std.os.linux.CLOCK.MONOTONIC));
    _ = std.os.linux.syscall2(.clock_gettime, clock, @intFromPtr(&ts));
    return @as(u64, @intCast(ts.sec)) * std.time.ns_per_s + @as(u64, @intCast(ts.nsec));
}

pub fn supervise(policy: Policy, signal_config: *const SignalConfig, spawned: child.ProcessHandle) u8 {
    defer spawned.close();

    const sigfd = signal_config.openFd() catch {
        @branchHint(.cold);
        // Nothing can be forwarded or reaped without the descriptor, and nothing this
        // early may outlive us: the group first (it exists by now), then the child for the
        // case where it has none yet.
        _ = std.os.linux.kill(-spawned.pid, Sig.KILL);
        _ = std.os.linux.kill(spawned.pid, Sig.KILL);
        return 1;
    };
    defer {
        log.debug("close signalfd", .{});
        tryClose(sigfd);
    }

    var state = ProcessState.init(policy, spawned, sigfd);

    var sig_pollfd = [_]std.os.linux.pollfd{.{
        .fd = sigfd,
        .events = std.os.linux.POLL.IN,
        .revents = 0,
    }};

    while (true) {
        if (state.shutdown) |*sd| {
            if (sd.remainingMs() == 0) {
                if (state.onShutdownTimeout()) |exit_code| return exit_code;
                continue;
            }
        }

        const timeout: i32 = if (state.shutdown) |*sd| sd.remainingMs() else -1;
        const count = std.os.linux.poll(@ptrCast(&sig_pollfd), 1, timeout);
        switch (std.os.linux.errno(count)) {
            .SUCCESS => {},
            .INTR => unreachable,
            else => |e| {
                @branchHint(.cold);
                log.err("poll failed: {e}", .{e});
                return 1;
            },
        }

        if (count == 0) {
            if (state.onShutdownTimeout()) |exit_code| return exit_code;
            continue;
        }

        const poll_errors = std.os.linux.POLL.ERR | std.os.linux.POLL.HUP | std.os.linux.POLL.NVAL;
        if (sig_pollfd[0].revents & poll_errors != 0) {
            const revents: u64 = @intCast(sig_pollfd[0].revents);
            log.err("poll error on signalfd: revents=0x{x}", .{revents});
            continue;
        }

        if (sig_pollfd[0].revents & std.os.linux.POLL.IN != 0) {
            if (state.handleSignalEvent()) |exit_code| return exit_code;
        }
    }
}

// kcov-exclude-tests (everything below is test-only).
test "a shutdown grace that cannot be added to the clock degrades to never" {
    const policy: Policy = .{
        .expected_exit = .empty,
        .rewrites = null,
        .forward_group = false,
        .shutdown_timeout_ns = std.math.maxInt(u64) - 1,
        .ignore_initial_hup_cont = false,
    };
    var state = ProcessState.init(policy, .{ .pid = 4242, .pidfd = null }, -1);

    _ = state.beginShutdown(7);

    const shutdown = state.shutdown orelse return error.TestUnexpectedResult;
    try std.testing.expectEqual(std.math.maxInt(u64), shutdown.deadline_ns);
    try std.testing.expect(shutdown.remainingMs() > 0);
}

test "zinit stops itself only when the child it forwarded to ends up suspended" {
    // Session mode's own rewrites: the job control signals become SIGSTOP.
    try std.testing.expect(ProcessState.stopsSelf(@backingInt(Sig.TSTP), @backingInt(Sig.STOP), true));
    try std.testing.expect(ProcessState.stopsSelf(@backingInt(Sig.TTIN), @backingInt(Sig.STOP), true));
    try std.testing.expect(ProcessState.stopsSelf(@backingInt(Sig.TTOU), @backingInt(Sig.STOP), true));
    // Unchanged forwarding: the child suspends, so we do too.
    try std.testing.expect(ProcessState.stopsSelf(@backingInt(Sig.TSTP), @backingInt(Sig.TSTP), true));

    // A rewrite that keeps the child running must keep us running as well.
    try std.testing.expect(!ProcessState.stopsSelf(@backingInt(Sig.TSTP), @backingInt(Sig.CONT), true));
    try std.testing.expect(!ProcessState.stopsSelf(@backingInt(Sig.TSTP), @backingInt(Sig.TERM), true));

    // Not a job control signal, or never delivered: nothing to match.
    try std.testing.expect(!ProcessState.stopsSelf(@backingInt(Sig.TERM), @backingInt(Sig.STOP), true));
    try std.testing.expect(!ProcessState.stopsSelf(@backingInt(Sig.TSTP), @backingInt(Sig.STOP), false));
}

test "a group send with no group falls back to the child" {
    const signal_config = try SignalConfig.init(&[_]Sig{});
    const sigfd: std.os.linux.fd_t = @intCast(try signal_config.openFd());
    defer tryClose(sigfd);

    const forked = std.os.linux.fork();
    if (std.os.linux.errno(forked) != .SUCCESS) return error.TestUnexpectedResult;
    if (forked == 0) {
        // The parent has TERM blocked for its own signalfd; this child must be killable.
        var empty = std.os.linux.sigemptyset();
        _ = std.os.linux.sigprocmask(Sig.SETMASK, &empty, null);
        _ = std.os.linux.pause();
        std.os.linux.exit(0);
    }

    const pid: std.os.linux.pid_t = @intCast(forked);
    const raw = std.os.linux.pidfd_open(pid, 0);
    if (std.os.linux.errno(raw) != .SUCCESS) {
        _ = std.os.linux.kill(pid, Sig.KILL);
        _ = try waitForExit(pid);
        std.debug.print("  skip the no-group fallback check: no pidfd\n", .{});
        return;
    }

    var state = ProcessState.init(.{
        .expected_exit = .empty,
        .rewrites = null,
        .forward_group = true,
        .shutdown_timeout_ns = 0,
        .ignore_initial_hup_cont = false,
    }, .{ .pid = pid, .pidfd = @intCast(raw) }, sigfd);
    defer state.child.close();

    try std.testing.expect(state.signalProcessGroup(@backingInt(Sig.TERM), null));
    try std.testing.expectEqual(@as(u32, @backingInt(Sig.TERM)), (try waitForExit(pid)).signalNumber());
}

test "an unsupported group flag falls back to the number, not to nothing" {
    // The path every kernel below 6.9 takes for `-g` and for the shutdown TERM/KILL:
    // with the flag forced unsupported, the signal still has to arrive.
    const signal_config = try SignalConfig.init(&[_]Sig{});
    const sigfd: std.os.linux.fd_t = @intCast(try signal_config.openFd());
    defer tryClose(sigfd);

    const base: Policy = .{
        .expected_exit = .empty,
        .rewrites = null,
        .forward_group = true,
        .shutdown_timeout_ns = 0,
        .ignore_initial_hup_cont = false,
    };

    const spawned = try spawnSleeper(&signal_config);
    defer spawned.close();
    var state = ProcessState.init(base, spawned, sigfd);

    group_flag = .unsupported;
    defer group_flag = .unknown;

    try std.testing.expect(state.signalProcessGroup(@backingInt(Sig.TERM), null));
    try std.testing.expectEqual(GroupFlag.unsupported, group_flag);
    try std.testing.expectEqual(
        @as(u32, @backingInt(Sig.TERM)),
        (try waitForExit(spawned.pid)).signalNumber(),
    );

    // The group is empty now: the proof fails, and nothing is signalled.
    try std.testing.expect(!state.signalGroupByNumber(@backingInt(Sig.TERM)));
    try std.testing.expect(!state.signalProcessGroup(@backingInt(Sig.TERM), null));
}

fn spawnSleeper(signal_config: *const SignalConfig) !child.ProcessHandle {
    return child.spawn(.{
        .argv = &[_:null]?[*:0]const u8{ "/bin/sleep", "30" },
        .envs = &[_:null]?[*:0]const u8{},
        .new_session = false,
        .is_terminal = false,
        .pdeath_signal = null,
        .tracing_child = false,
    }, signal_config);
}

fn statusIfReaped(pid: std.os.linux.pid_t) ?WaitStatus {
    var status: i32 = 0;
    if (std.os.linux.waitpid(pid, &status, std.os.linux.W.NOHANG) != @as(usize, @intCast(pid))) return null;
    return WaitStatus.fromRaw(status);
}

fn childEvent(pid: std.os.linux.pid_t, flags: u32) bool {
    var status: i32 = 0;
    const rc = std.os.linux.waitpid(pid, &status, flags | std.os.linux.W.NOHANG);
    return rc == @as(usize, @intCast(pid));
}

/// kcov traces the tests with ptrace, and a traced child's stop/continue reports go
/// to the tracer.
fn underTracer() bool {
    const raw = std.os.linux.openat(std.os.linux.AT.FDCWD, "/proc/self/status", .{ .ACCMODE = .RDONLY }, 0);
    if (std.os.linux.errno(raw) != .SUCCESS) return true;
    const fd: std.os.linux.fd_t = @intCast(raw);
    defer _ = std.os.linux.close(fd);

    var buf: [4096]u8 = undefined;
    const n = std.os.linux.read(fd, &buf, buf.len);
    if (std.os.linux.errno(n) != .SUCCESS) return true;

    const text = buf[0..n];
    const marker = "TracerPid:";
    const at = std.mem.indexOf(u8, text, marker) orelse return true;
    var i = at + marker.len;
    while (i < text.len and (text[i] == ' ' or text[i] == '\t')) i += 1;
    return i >= text.len or text[i] != '0';
}

/// Bounded: a state change is not visible to the next syscall.
fn expectChildEvent(pid: std.os.linux.pid_t, flags: u32) !void {
    var spins: usize = 0;
    while (!childEvent(pid, flags)) : (spins += 1) {
        if (spins > 1_000_000) return error.TestUnexpectedResult;
        _ = std.os.linux.sched_yield();
    }
}

/// Bounded, so a child that never dies fails the test instead of hanging the runner.
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

fn killAndReap(pid: std.os.linux.pid_t) void {
    _ = std.os.linux.kill(pid, Sig.KILL);
    _ = waitForExit(pid) catch {};
}

test "the continue a detach queues is swallowed, a user's continue reaches the child" {
    // Only an untraced child reports a stop, and that stop is what this asserts.
    if (underTracer()) {
        std.debug.print("skip the detach's continue check: a tracer owns the stop/continue events\n", .{});
        return;
    }

    const signal_config = try SignalConfig.init(&[_]Sig{});
    const sigfd: std.os.linux.fd_t = @intCast(try signal_config.openFd());
    defer tryClose(sigfd);

    const base: Policy = .{
        .expected_exit = .empty,
        .rewrites = null,
        .forward_group = false,
        .shutdown_timeout_ns = 0,
        .ignore_initial_hup_cont = true,
    };

    // Stopped first: a continue is then an event only this test can cause.
    const spawned = try spawnSleeper(&signal_config);
    defer spawned.close();
    const pid = spawned.pid;
    // A stopped child is not reapable: leave nothing behind.
    defer killAndReap(pid);

    _ = std.os.linux.kill(pid, Sig.STOP);
    try expectChildEvent(pid, std.os.linux.W.UNTRACED);

    var state = ProcessState.init(base, spawned, sigfd);

    var cont = std.mem.zeroes(std.os.linux.signalfd_siginfo);
    cont.signo = @backingInt(Sig.CONT);
    cont.code = SI_KERNEL;
    state.forwardSignal(&cont);
    try std.testing.expect(!childEvent(pid, std.os.linux.W.CONTINUED));

    // A continue someone sends is not the kernel's and must reach the child.
    cont.code = 0; // SI_USER
    cont.pid = 1;
    state.forwardSignal(&cont);
    try expectChildEvent(pid, std.os.linux.W.CONTINUED);
}

test "the HUP a detach queues is swallowed, a user's HUP reaches the child" {
    const signal_config = try SignalConfig.init(&[_]Sig{});
    const sigfd: std.os.linux.fd_t = @intCast(try signal_config.openFd());
    defer tryClose(sigfd);

    const base: Policy = .{
        .expected_exit = .empty,
        .rewrites = null,
        .forward_group = false,
        .shutdown_timeout_ns = 0,
        .ignore_initial_hup_cont = true,
    };

    const spawned = try spawnSleeper(&signal_config);
    defer spawned.close();
    const pid = spawned.pid;
    defer killAndReap(pid);

    var state = ProcessState.init(base, spawned, sigfd);

    var hup = std.mem.zeroes(std.os.linux.signalfd_siginfo);
    hup.signo = @backingInt(Sig.HUP);
    hup.code = SI_KERNEL;
    state.forwardSignal(&hup);
    try std.testing.expect(statusIfReaped(pid) == null);

    hup.code = 0; // SI_USER
    hup.pid = 1;
    state.forwardSignal(&hup);
    try std.testing.expectEqual(@as(u32, @backingInt(Sig.HUP)), (try waitForExit(pid)).signalNumber());
}

test "handleSignalEvent forwards a pending signal according to the policy" {
    // Everything is blocked, so our own signal stays pending for the signalfd.
    const signal_config = try SignalConfig.init(&[_]Sig{});
    const sigfd: std.os.linux.fd_t = @intCast(try signal_config.openFd());
    defer tryClose(sigfd);

    const base: Policy = .{
        .expected_exit = .empty,
        .rewrites = null,
        .forward_group = false,
        .shutdown_timeout_ns = 0,
        .ignore_initial_hup_cont = true,
    };

    // The contract is the child's survival, whatever the call returns.
    const hup_child = try spawnSleeper(&signal_config);
    defer hup_child.close();
    var state = ProcessState.init(base, hup_child, sigfd);
    _ = std.os.linux.kill(std.os.linux.getpid(), Sig.HUP);
    _ = state.handleSignalEvent();
    try std.testing.expect(statusIfReaped(hup_child.pid) == null);

    // The next HUP is forwarded and kills the sleeper; whether its SIGCHLD is drained
    // before the call returns is the scheduler's business.
    state.ignore_hup = false;
    _ = std.os.linux.kill(std.os.linux.getpid(), Sig.HUP);
    if (state.handleSignalEvent()) |code| {
        try std.testing.expectEqual(@as(u8, 128 + @backingInt(Sig.HUP)), code);
    } else {
        const hup_status = try waitForExit(hup_child.pid);
        try std.testing.expectEqual(WaitStatus.Class.signaled, hup_status.class());
        try std.testing.expectEqual(@as(u32, @backingInt(Sig.HUP)), hup_status.signalNumber());
    }

    // Rewriting to 0 drops the signal instead of forwarding it.
    const drop_child = try spawnSleeper(&signal_config);
    defer drop_child.close();
    var rewrites = RewriteMap.init();
    rewrites.set(@backingInt(Sig.TERM), 0);
    var drop_policy = base;
    drop_policy.rewrites = rewrites;
    var dropping = ProcessState.init(drop_policy, drop_child, sigfd);
    _ = std.os.linux.kill(std.os.linux.getpid(), Sig.TERM);
    _ = dropping.handleSignalEvent();
    try std.testing.expect(statusIfReaped(drop_child.pid) == null);
    killAndReap(drop_child.pid);

    // The group exists as soon as `spawn` returns: the parent sets it on the child's
    // behalf, so a `-g` signal cannot land before the child's own `setpgid`.
    const group_child = try spawnSleeper(&signal_config);
    defer group_child.close();
    var group_policy = base;
    group_policy.forward_group = true;
    group_policy.ignore_initial_hup_cont = false;
    var grouped = ProcessState.init(group_policy, group_child, sigfd);
    _ = std.os.linux.kill(std.os.linux.getpid(), Sig.TERM);
    if (grouped.handleSignalEvent()) |code| {
        try std.testing.expectEqual(@as(u8, 128 + @backingInt(Sig.TERM)), code);
    } else {
        try std.testing.expectEqual(@as(u32, @backingInt(Sig.TERM)), (try waitForExit(group_child.pid)).signalNumber());
    }

    // Nothing left pending: the loop is told there was nothing to read.
    try std.testing.expectEqual(@as(?u8, null), grouped.handleSignalEvent());
}

test "an expected exit code becomes 0, for a code and for a signal" {
    const signal_config = try SignalConfig.init(&[_]Sig{});

    const coded: child.SpawnSpec = .{
        .argv = &[_:null]?[*:0]const u8{ "/bin/sh", "-c", "exit 7" },
        .envs = &[_:null]?[*:0]const u8{},
        .new_session = false,
        .is_terminal = false,
        .pdeath_signal = null,
        .tracing_child = false,
    };
    const sleeper: child.SpawnSpec = .{
        .argv = &[_:null]?[*:0]const u8{ "/bin/sleep", "30" },
        .envs = &[_:null]?[*:0]const u8{},
        .new_session = false,
        .is_terminal = false,
        .pdeath_signal = null,
        .tracing_child = false,
    };
    const base: Policy = .{
        .expected_exit = .empty,
        .rewrites = null,
        .forward_group = false,
        .shutdown_timeout_ns = 0,
        .ignore_initial_hup_cont = false,
    };

    // Without a mapping, the child's own code is what comes back.
    try std.testing.expectEqual(
        @as(u8, 7),
        supervise(base, &signal_config, try child.spawn(coded, &signal_config)),
    );

    var expect_seven = ExitCodeSet.empty;
    expect_seven.set(7);
    var mapped = base;
    mapped.expected_exit = expect_seven;
    try std.testing.expectEqual(
        @as(u8, 0),
        supervise(mapped, &signal_config, try child.spawn(coded, &signal_config)),
    );

    // The README's case: a signalled child, and 143 is 128 + SIGTERM.
    const signalled = try child.spawn(sleeper, &signal_config);
    _ = std.os.linux.kill(signalled.pid, Sig.TERM);
    try std.testing.expectEqual(
        @as(u8, 128 + @backingInt(Sig.TERM)),
        supervise(base, &signal_config, signalled),
    );

    var expect_term = ExitCodeSet.empty;
    expect_term.set(128 + @backingInt(Sig.TERM));
    var mapped_term = base;
    mapped_term.expected_exit = expect_term;
    const killed = try child.spawn(sleeper, &signal_config);
    _ = std.os.linux.kill(killed.pid, Sig.TERM);
    try std.testing.expectEqual(@as(u8, 0), supervise(mapped_term, &signal_config, killed));
}
