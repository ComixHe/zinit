// SPDX-FileCopyrightText: 2026 YuMing He <ComixHe1895@outlook.com>
//
// SPDX-License-Identifier: MIT

//! Internal workload state machine: signal delivery, child observations and shutdown.
//! The caller owns waiting for signal events; State owns the consumed child handle.

const std = @import("std");
const builtin = @import("builtin");
const config = @import("config");

const errors = @import("errors.zig");
const log = @import("log.zig");
const io = @import("io.zig");
const checks = @import("checks.zig");
const wait = @import("wait.zig");
const signal = @import("signal.zig");
const rewrite = @import("rewrite.zig");
const signalfd = @import("signalfd.zig");

const Sig = signal.Sig;
const ExitCodeSet = wait.ExitCodeSet;
const closeQuietly = io.closeQuietly;
const WaitStatus = wait.WaitStatus;
const RewriteMap = rewrite.Map;
const SignalConfig = signalfd.Config;

const signal_quota: usize = 32;

/// Signals are dequeued in batches of at most this many at a time.
const signal_batch: usize = signalfd.Source.batch_max;

/// A queued signal's value: `kill` drops it, and for a realtime signal it is the content.
const Payload = struct { value: u64 };

/// The sender the child sees is zinit: the original pid may mean nothing, or someone else, in a child namespace.
fn queuedInfo(sig: u32, payload: Payload) std.os.linux.siginfo_t {
    var info = std.mem.zeroes(std.os.linux.siginfo_t);
    info.signo = @fromBackingInt(@intCast(sig));
    info.code = signal.SI.QUEUE;
    info.fields.common.first.piduid.pid = @intCast(std.os.linux.getpid());
    info.fields.common.first.piduid.uid = @intCast(std.os.linux.getuid());

    if (payload.value == 0) {
        info.fields.common.second.value.int = 0;
    } else {
        info.fields.common.second.value.ptr = @ptrFromInt(payload.value);
    }

    return info;
}

/// The last event observed for the main child in one drain round. A single value,
/// updated in kernel order, so "stop, continue, stop" ends stopped and an exit
/// supersedes everything: a later stop can never resurrect a dead child.
const MainObservation = union(enum) {
    unchanged,
    stopped,
    continued,
    exited: u8,
};

const DrainResult = struct {
    main: MainObservation = .unchanged,
    no_children: bool,
};

pub const Policy = struct {
    expected_exit: ExitCodeSet,
    rewrites: ?RewriteMap,
    forward_group: bool,
    shutdown_timeout_ns: u64,
    ignore_initial_hup_cont: bool,
    ctty: ?std.os.linux.fd_t = null,
};

/// Distinguishes a workload's own exit status from the supervisor giving up.
pub const Outcome = union(enum) {
    exited: u8,
    failed,
};

/// The running workload's identity, handed from `spawn` to the state machine.
/// pid is unconditional (it tells the child apart and, without a pidfd, is what is
/// signalled). pidfd is an extra mechanism, null before Linux 5.2. Neither can be
/// recycled while the child, or any group member, holds its `struct pid`.
pub const ProcessHandle = struct {
    pid: std.os.linux.pid_t,
    pidfd: ?std.os.linux.fd_t,

    /// Closes the pidfd, if any, and clears it: a second close is then a no-op
    /// instead of closing a descriptor number the kernel has since reused. The pid
    /// stays for logging, it is only a number again once the child has been reaped.
    pub fn close(self: *ProcessHandle) void {
        if (self.pidfd) |fd| {
            io.closeQuietly(fd);
            self.pidfd = null;
        }
    }

    pub fn take(self: *ProcessHandle) ProcessHandle {
        const taken = self.*;
        self.pidfd = null;
        return taken;
    }
};

/// The 6.9 process-group scope flag, `unknown` until the first attempt. It lives in
/// the supervision state, not in the module: a test or a future second instance must
/// not inherit another run's capability guess.
/// https://github.com/torvalds/linux/blob/c339f4010dea8b0d754f84ace70cd1b089878ef8/include/uapi/linux/pidfd.h#L22
const PIDFD_SIGNAL_PROCESS_GROUP: u32 = 1 << 2;

pub const State = struct {
    child: ProcessHandle,
    /// Set after the kernel rejects the pidfd group scope, all later group sends
    /// use the numeric fallback. The default is the pidfd-capable path.
    group_number_only: bool = false,
    /// Once the main child is reaped it can receive nothing, and its number is free again.
    child_reaped: bool = false,
    policy: Policy,
    shutdown: ?ShutdownState = null,
    ignore_hup: bool = false,
    ignore_cont: bool = false,

    pub fn init(policy: Policy, spawned: ProcessHandle) State {
        checks.check(spawned.pid > 0);
        if (spawned.pidfd) |fd| checks.check(fd >= 0);
        return .{
            .child = spawned,
            .policy = policy,
            .ignore_cont = policy.ignore_initial_hup_cont,
            .ignore_hup = policy.ignore_initial_hup_cont,
        };
    }

    pub fn deinit(self: *State) void {
        self.child.close();
    }

    pub fn deadline(self: *const State) ?i32 {
        const sd = if (self.shutdown) |*s| s else return -1;
        const now = monotonicNs() catch return null;
        return sd.remainingMs(now);
    }

    pub fn onTimeout(self: *State) ?Outcome {
        const sd = if (self.shutdown) |*s| s else return null;
        const now = monotonicNs() catch {
            @branchHint(.cold);
            return .{ .exited = self.onClockFailure(sd) };
        };

        if (sd.remainingMs(now) != 0) return null;
        return .{ .exited = self.onShutdownTimeout(sd) };
    }

    fn sendPidfd(
        fd: std.os.linux.fd_t,
        target: Sig,
        payload: ?Payload,
        flags: u32,
    ) usize {
        if (payload) |p| {
            var info = queuedInfo(@intCast(@backingInt(target)), p);
            const rc = std.os.linux.pidfd_send_signal(fd, target, &info, flags);
            return switch (io.syscallErrno(rc)) {
                .INVAL, .PERM => |errno| blk: {
                    log.debug("dropping queued value for signal {d}: pidfd_send_signal refused the siginfo ({e})", .{
                        @backingInt(target), errno,
                    });
                    break :blk std.os.linux.pidfd_send_signal(fd, target, null, flags);
                },
                else => rc,
            };
        }

        return std.os.linux.pidfd_send_signal(fd, target, null, flags);
    }

    fn signalChild(self: *const State, sig: u32, payload: ?Payload) bool {
        if (self.child_reaped) {
            log.debug("not signalling {d}: the child's exit was already reported", .{sig});
            return false;
        }

        const target: Sig = @fromBackingInt(@intCast(sig));
        const fd = self.child.pidfd orelse
            return self.reportChildSend(self.sendChildByNumber(target, payload), sig);

        const rc = sendPidfd(fd, target, payload, 0);
        return self.reportChildSend(if (io.syscallErrno(rc) == .NOSYS)
            self.sendChildByNumber(target, payload)
        else
            rc, sig);
    }

    fn sendChildByNumber(self: *const State, target: Sig, payload: ?Payload) usize {
        if (payload) |p| {
            var info = queuedInfo(@intCast(@backingInt(target)), p);
            const rc = std.os.linux.syscall3(.rt_sigqueueinfo, @intCast(self.child.pid), @backingInt(target), @intFromPtr(&info));
            switch (io.syscallErrno(rc)) {
                .NOSYS, .INVAL, .PERM => |errno| log.debug(
                    "dropping queued value for signal {d}: rt_sigqueueinfo unavailable ({e})",
                    .{ @backingInt(target), errno },
                ),
                else => return rc,
            }
        }

        return std.os.linux.kill(self.child.pid, target);
    }

    fn reportChildSend(self: *const State, rc: usize, sig: u32) bool {
        switch (io.syscallErrno(rc)) {
            .SUCCESS => return true,
            .SRCH => log.debug("no process to send signal {d} for pid {d}", .{ sig, @as(u32, @intCast(self.child.pid)) }),
            else => |errno| log.err("unable to send signal to child: {e}", .{errno}),
        }

        return false;
    }

    fn signalProcessGroup(self: *State, sig: u32, payload: ?Payload) bool {
        const sent = if (self.group_number_only) blk: {
            if (payload != null) log.debug(
                "dropping queued value for signal {d}: numeric group send cannot carry it",
                .{sig},
            );
            break :blk self.signalGroupByNumber(sig);
        } else self.signalGroupByPidfd(sig, payload);

        return sent or self.signalChild(sig, payload);
    }

    fn signalGroupByPidfd(self: *State, sig: u32, payload: ?Payload) bool {
        const fd = self.child.pidfd orelse {
            if (payload != null) log.debug(
                "dropping queued value for signal {d}: no pidfd for the process group",
                .{sig},
            );
            return self.signalGroupByNumber(sig);
        };
        const target: Sig = @fromBackingInt(@intCast(sig));

        switch (io.syscallErrno(sendPidfd(fd, target, payload, PIDFD_SIGNAL_PROCESS_GROUP))) {
            .SUCCESS => return true,
            .NOSYS => {
                if (payload != null) log.debug(
                    "dropping queued value for signal {d}: pidfd_send_signal is unavailable",
                    .{sig},
                );
                self.group_number_only = true;
                return self.signalGroupByNumber(sig);
            },
            .INVAL => {
                self.group_number_only = true;
                return self.signalGroupByNumber(sig);
            },
            .SRCH => return false,
            else => |errno| {
                reportGroupFailure(errno, sig);
                return false;
            },
        }
    }

    fn signalGroupByNumber(self: *const State, sig: u32) bool {
        const flags = std.os.linux.W.EXITED | std.os.linux.W.NOHANG | std.os.linux.W.NOWAIT;
        var info: std.os.linux.siginfo_t = undefined;
        switch (io.syscallErrno(std.os.linux.waitid(.PGID, self.child.pid, &info, flags, null))) {
            .SUCCESS => {},
            else => {
                log.debug("not signalling {d}: no child of ours is left in that group", .{sig});
                return false;
            },
        }

        const pgid: usize = @intCast(self.child.pid);
        const rc = std.os.linux.kill(-self.child.pid, @fromBackingInt(@intCast(sig)));
        switch (io.syscallErrno(rc)) {
            .SUCCESS => return true,
            .SRCH => log.debug("no process group for signal {d} (pgid {d})", .{ sig, pgid }),
            else => |errno| reportGroupFailure(errno, sig),
        }

        return false;
    }

    fn reportGroupFailure(errno: std.os.linux.E, sig: u32) void {
        log.err("unable to send signal {d} to process group: {e}", .{ sig, errno });
    }

    fn restoreForeground(self: *State) void {
        const tty_fd = self.policy.ctty orelse return;
        if (self.child_reaped) return;

        var foreground: std.os.linux.pid_t = 0;
        if (io.syscallErrno(std.os.linux.tcgetpgrp(tty_fd, &foreground)) != .SUCCESS) return;

        const raw_own = std.os.linux.getpgid(0);
        if (io.syscallErrno(raw_own) != .SUCCESS) return;
        const own: std.os.linux.pid_t = @intCast(raw_own);
        if (foreground != own) return;

        const child_pgrp: std.os.linux.pid_t = self.child.pid;
        switch (io.syscallErrno(std.os.linux.tcsetpgrp(tty_fd, &child_pgrp))) {
            .SUCCESS, .NOTTY, .NXIO => {},
            else => |e| log.warn("unable to restore the workload's foreground group: {e}", .{e}),
        }
    }

    fn forwardSignal(self: *State, event: signal.Event) void {
        const signo = event.signo;
        // signalfd only reports numbers below NSIG, which is what the rewrite
        // table is sized for; an out-of-range value would be a kernel ABI bug.
        checks.check(signo > 0 and signo < std.os.linux.NSIG);

        // Giving up the terminal queues one HUP and one CONT for us, and the kernel is the
        // one who sent them: no sender. A HUP from a user is a different event and must
        // reach the child like any other, even if it is the first one we see.
        //
        // `SI_KERNEL` is the generic kernel code, not `code > 0`: positive
        // signal-specific codes belong to other signals. It also cannot tell the
        // detach-queued pair from a later kernel HUP/CONT, since neither names a
        // sender. These one-shot flags therefore swallow the first kernel HUP/CONT
        // in the detach-to-spawn window; a genuine one arriving there would be
        // mistaken for the queued pair.
        const from_kernel = event.code == signal.SI.KERNEL;

        if (from_kernel and self.ignore_hup and signo == @backingInt(Sig.HUP)) {
            self.ignore_hup = false;
            return;
        }

        if (from_kernel and self.ignore_cont and signo == @backingInt(Sig.CONT)) {
            self.ignore_cont = false;
            return;
        }

        // The assert above keeps `signo` inside the table. The fallback stays for
        // ReleaseSmall, where asserts are compiled out: a wrong number would only
        // mean the signal is forwarded unrewritten.
        const signal_to_send = (if (self.policy.rewrites) |m| m.apply(signo) catch null else null) orelse signo;
        if (signal_to_send == 0) {
            log.debug("dropping signal {d}", .{signo});
            return;
        }

        // Only a queued signal carries a value, anything else would hand the child a meaningless one.
        const payload: ?Payload = if (event.code == signal.SI.QUEUE) .{ .value = event.value } else null;
        if (signal_to_send == signo) {
            log.debug("forwarding signal {d}", .{signo});
        } else {
            log.debug("forwarding signal {d} as {d}", .{ signo, signal_to_send });
        }

        if (signo == @backingInt(Sig.CONT) and signal_to_send == @backingInt(Sig.CONT)) {
            self.restoreForeground();
        }

        if (self.policy.forward_group) {
            _ = self.signalProcessGroup(signal_to_send, payload);
        } else {
            _ = self.signalChild(signal_to_send, payload);
        }
    }

    pub fn handleSignalEvent(self: *State, source: *signalfd.Source, first: []const signal.Event) ?Outcome {
        // The caller hands over at most one signalfd batch.
        checks.check(first.len <= signal_batch);
        var batch: [signal_batch]signal.Event = undefined;
        var events = first;
        var budget: usize = signal_quota;

        while (true) {
            budget -= @min(budget, events.len);

            for (events) |event| {
                if (event.signo != @backingInt(Sig.CHLD)) {
                    @branchHint(.unpredictable);
                    log.debug("receive signal: {d}", .{event.signo});
                    self.forwardSignal(event);
                }
            }

            if (budget == 0) break;
            const got = source.waitBatch(batch[0..@min(budget, batch.len)], 0) catch {
                @branchHint(.cold);
                return self.abortSupervision();
            };

            if (got == 0) break;
            events = batch[0..got];
        }

        return self.reapAndReport();
    }

    fn reapAndReport(self: *State) ?Outcome {
        const reap = drain(self.child.pid, self.policy.expected_exit, &self.child_reaped) catch {
            @branchHint(.unlikely);
            return self.abortSupervision();
        };

        // A stop is mirrored only after the kernel reports it. A stop and a continue
        // observed in the same round cancel out: the child is running by the time we
        // would stop, and stopping then would strand zinit with nothing to wait for.
        if (shouldStopSelf(reap)) {
            log.debug("child is stopped; stopping with it", .{});
            _ = std.os.linux.kill(std.os.linux.getpid(), Sig.STOP);
        }

        switch (reap.main) {
            .exited => |code| {
                if (reap.no_children) return .{ .exited = code };
                if (self.shutdown == null) {
                    self.beginShutdown(code);
                    return null;
                }
            },
            else => if (self.shutdown != null and reap.no_children) {
                return .{ .exited = self.shutdown.?.exit_code };
            },
        }

        return null;
    }

    pub fn abortSupervision(self: *State) Outcome {
        _ = self.signalProcessGroup(@backingInt(Sig.KILL), null);
        _ = self.signalChild(@backingInt(Sig.KILL), null);
        _ = drain(self.child.pid, .empty, &self.child_reaped) catch {};
        return .failed;
    }

    fn beginShutdown(self: *State, exit_code: u8) void {
        const now = monotonicNs() catch {
            @branchHint(.unlikely);
            self.shutdown = ShutdownState.init(exit_code, 0, 0);
            _ = self.signalProcessGroup(@backingInt(Sig.TERM), null);
            return;
        };

        self.shutdown = ShutdownState.init(exit_code, now, self.policy.shutdown_timeout_ns);
        log.debug("child exited, {d}ms grace for descendants before SIGKILL", .{
            self.policy.shutdown_timeout_ns / std.time.ns_per_ms,
        });

        _ = self.signalProcessGroup(@backingInt(Sig.TERM), null);
    }

    fn onShutdownTimeout(self: *State, sd: *ShutdownState) u8 {
        log.warn("grace period elapsed, descendants still running: sending SIGKILL", .{});
        return self.finishShutdown(sd.exit_code);
    }

    fn onClockFailure(self: *State, sd: *ShutdownState) u8 {
        log.err("cannot read the monotonic clock: sending SIGKILL without the grace period", .{});
        return self.finishShutdown(sd.exit_code);
    }

    fn finishShutdown(self: *State, exit_code: u8) u8 {
        _ = self.signalProcessGroup(@backingInt(Sig.KILL), null);
        _ = drain(self.child.pid, .empty, &self.child_reaped) catch {};

        return exit_code;
    }
};

const ShutdownState = struct {
    exit_code: u8,
    /// CLOCK_MONOTONIC deadline (ns) at which the process group gets SIGKILLed.
    deadline_ns: u64,

    fn init(exit_code: u8, now_ns: u64, timeout_ns: u64) ShutdownState {
        return .{ .exit_code = exit_code, .deadline_ns = now_ns +| timeout_ns };
    }

    pub fn remainingMs(self: *const ShutdownState, now_ns: u64) i32 {
        if (now_ns >= self.deadline_ns) return 0;
        const remaining_ns = self.deadline_ns - now_ns;
        const ms = (remaining_ns +| (std.time.ns_per_ms - 1)) / std.time.ns_per_ms;
        return @intCast(@min(ms, std.math.maxInt(i32)));
    }
};

const MainEvent = union(enum) {
    stopped,
    continued,
    exited: u8,
};

fn applyMainEvent(result: *DrainResult, event: MainEvent) void {
    switch (event) {
        .stopped => if (result.main != .exited) {
            result.main = .stopped;
        },
        .continued => if (result.main != .exited) {
            result.main = .continued;
        },
        .exited => |code| result.main = .{ .exited = code },
    }
}

fn shouldStopSelf(reap: DrainResult) bool {
    return reap.main == .stopped;
}

fn drain(child_pid: std.os.linux.pid_t, expected_exit: ExitCodeSet, main_reaped: *bool) errors.SysCallError!DrainResult {
    var result: DrainResult = .{ .no_children = false };
    var status: i32 = 0;

    while (true) {
        const flags = std.os.linux.W.NOHANG | std.os.linux.W.UNTRACED | std.os.linux.W.CONTINUED;
        const rc = std.os.linux.waitpid(-1, &status, flags);
        if (rc == 0) return result; // children remain

        switch (io.syscallErrno(rc)) {
            .SUCCESS => {
                const pid: std.os.linux.pid_t = @intCast(rc);
                const wait_status = WaitStatus.fromRaw(status);
                const is_main = !main_reaped.* and pid == child_pid;

                switch (wait_status.kind()) {
                    .continued => if (is_main) {
                        applyMainEvent(&result, .continued);
                        continue;
                    },
                    .stopped => if (is_main) {
                        applyMainEvent(&result, .stopped);
                        continue;
                    },
                    else => {},
                }

                if (is_main) {
                    main_reaped.* = true;
                    log.processExited(pid, wait_status, .main);
                    const code = wait_status.exitCode();
                    const final_code = if (expected_exit.isSet(code)) blk: {
                        if (code != 0) log.debug("exit code {d} mapped to 0 by --expect-exit", .{code});
                        break :blk 0;
                    } else code;

                    applyMainEvent(&result, .{ .exited = final_code });
                } else if (wait_status.class() != .unknown) {
                    log.processExited(pid, wait_status, .orphaned);
                }
            },
            .CHILD => {
                result.no_children = true;
                return result;
            },
            else => |errno| {
                log.err("unable to reap a child: {e}", .{errno});
                return error.SysCallError;
            },
        }
    }
}

fn monotonicNs() errors.SysCallError!u64 {
    var ts = std.mem.zeroes(std.os.linux.timespec);
    // Raw syscall: the std wrapper drags in the vDSO lookup for about a kilobyte.
    const clock = @as(u32, @bitCast(std.os.linux.CLOCK.MONOTONIC));
    const rc = std.os.linux.syscall2(.clock_gettime, clock, @intFromPtr(&ts));
    switch (io.syscallErrno(rc)) {
        .SUCCESS => {},
        else => |e| {
            @branchHint(.unlikely);
            log.err("clock_gettime failed: {e}", .{e});
            return error.SysCallError;
        },
    }

    if (ts.sec < 0 or ts.nsec < 0) return error.SysCallError;
    return @as(u64, @intCast(ts.sec)) * std.time.ns_per_s + @as(u64, @intCast(ts.nsec));
}

// kcov-exclude-tests (everything below is test-only).
comptime {
    if (builtin.is_test and config.include_private_integration_tests) _ = integration_tests;
}

// State/deadline checks also run in the unit target.
test "a shutdown grace that cannot be added to the clock degrades to never" {
    const shutdown = ShutdownState.init(7, 1_000, std.math.maxInt(u64) - 1);

    try std.testing.expectEqual(std.math.maxInt(u64), shutdown.deadline_ns);
    try std.testing.expect(shutdown.remainingMs(1_000) > 0);
    try std.testing.expectEqual(@as(u8, 7), shutdown.exit_code);
}

test "the grace deadline is absolute, and a clamped wait does not end it" {
    const ms = std.time.ns_per_ms;
    const start: u64 = 10 * std.time.ns_per_s;

    // Half a millisecond is still a millisecond of waiting.
    const immediate = ShutdownState.init(0, start, 1);
    try std.testing.expectEqual(@as(i32, 1), immediate.remainingMs(start));

    // Already due, and exactly due, both mean "no time left".
    const done = ShutdownState.init(0, start, 5 * ms);
    try std.testing.expectEqual(@as(i32, 0), done.remainingMs(start + 5 * ms));
    try std.testing.expectEqual(@as(i32, 0), done.remainingMs(start + 6 * ms));

    // Longer than one poll can express: the first wait is clamped, the deadline is not.
    const long_ns = (@as(u64, std.math.maxInt(i32)) + 1_000) * ms;
    const long = ShutdownState.init(0, start, long_ns);
    try std.testing.expectEqual(@as(i32, std.math.maxInt(i32)), long.remainingMs(start));
    try std.testing.expectEqual(@as(i32, 1_000), long.remainingMs(start + @as(u64, std.math.maxInt(i32)) * ms));
    try std.testing.expectEqual(@as(i32, 0), long.remainingMs(start + long_ns));
}

test "the main-event reducer follows order, and exit is terminal" {
    const idle: DrainResult = .{ .no_children = false };
    try std.testing.expect(!shouldStopSelf(idle));

    // STOP -> CONT.
    var stop_cont: DrainResult = .{ .no_children = false };
    applyMainEvent(&stop_cont, .stopped);
    try std.testing.expectEqual(MainObservation.stopped, stop_cont.main);
    try std.testing.expect(shouldStopSelf(stop_cont));
    applyMainEvent(&stop_cont, .continued);
    try std.testing.expectEqual(MainObservation.continued, stop_cont.main);
    try std.testing.expect(!shouldStopSelf(stop_cont));

    // CONT -> STOP.
    applyMainEvent(&stop_cont, .stopped);
    try std.testing.expectEqual(MainObservation.stopped, stop_cont.main);
    try std.testing.expect(shouldStopSelf(stop_cont));

    // STOP -> CONT -> STOP
    applyMainEvent(&stop_cont, .continued);
    applyMainEvent(&stop_cont, .stopped);
    try std.testing.expect(shouldStopSelf(stop_cont));

    // STOP -> EXIT
    applyMainEvent(&stop_cont, .{ .exited = 137 });
    try std.testing.expectEqual(MainObservation{ .exited = 137 }, stop_cont.main);
    try std.testing.expect(!shouldStopSelf(stop_cont));

    // S stray stop after an exit cannot undo it.
    applyMainEvent(&stop_cont, .stopped);
    try std.testing.expectEqual(MainObservation{ .exited = 137 }, stop_cont.main);

    // The direct STOP -> EXIT path.
    var direct: DrainResult = .{ .no_children = false };
    applyMainEvent(&direct, .stopped);
    applyMainEvent(&direct, .{ .exited = 9 });
    try std.testing.expectEqual(MainObservation{ .exited = 9 }, direct.main);
    try std.testing.expect(!shouldStopSelf(direct));
}

const integration_tests = struct {
    const supervisor = @import("supervisor.zig");
    fn waitForWaitid(test_io: std.Io, pid: std.os.linux.pid_t, flags: u32) !void {
        const deadline = std.Io.Clock.now(.awake, test_io).toNanoseconds() + 5 * std.time.ns_per_s;
        while (true) {
            var info = std.mem.zeroes(std.os.linux.siginfo_t);
            const rc = std.os.linux.waitid(.PID, pid, &info, flags | std.os.linux.W.NOHANG, null);
            try std.testing.expectEqual(std.os.linux.E.SUCCESS, io.syscallErrno(rc));
            if (info.fields.common.first.piduid.pid == pid) return;

            if (std.Io.Clock.now(.awake, test_io).toNanoseconds() >= deadline)
                return error.TestUnexpectedResult;
            try std.Io.sleep(test_io, .fromMilliseconds(1), .awake);
        }
    }

    test "integration: a previously stopped workload is reaped without stopping zinit" {
        const test_io = std.testing.io;
        // Integration check: a stopped child that is then killed is reaped normally and
        // leaves no self-stop behind. The same-round event ORDER is pinned by the reducer
        // test above: once the child is a zombie the kernel may report exit first.
        if (underTracer(test_io)) return error.SkipZigTest;

        const signal_config = try SignalConfig.install(&[_]Sig{});
        defer _ = signal_config.restoreParent();

        var spawned = try spawnSleeper(&signal_config);
        defer spawned.close();
        defer killAndReap(test_io, spawned.pid);
        const pid = spawned.pid;

        _ = std.os.linux.kill(pid, Sig.STOP);
        try waitForWaitid(test_io, pid, std.os.linux.W.STOPPED | std.os.linux.W.NOWAIT);

        _ = std.os.linux.kill(pid, Sig.KILL);
        // Leave the exit pending without reaping it; drain must consume the exit.
        try waitForWaitid(test_io, pid, std.os.linux.W.EXITED | std.os.linux.W.NOWAIT);

        var reaped = false;
        const reap = try drain(pid, .empty, &reaped);

        try std.testing.expectEqual(MainObservation{ .exited = 137 }, reap.main);
        try std.testing.expect(reaped);
        try std.testing.expect(!shouldStopSelf(reap));
    }

    /// Read the kernel's state letter for a workload without consuming its wait
    /// status.
    fn workloadStopped(test_io: std.Io, pid: std.os.linux.pid_t) ?bool {
        var path_buf: [64]u8 = undefined;
        const path = std.mem.print(&path_buf, "/proc/{d}/stat", .{pid}) catch return null;

        const file = std.Io.Dir.openFileAbsolute(test_io, path, .{}) catch return null;
        defer file.close(test_io);

        var buf: [512]u8 = undefined;
        var iov = [_][]u8{&buf};
        const n = file.readStreaming(test_io, &iov) catch return null;
        if (n == 0) return null;

        const stat = buf[0..n];
        const comm_end = std.mem.findScalarLast(u8, stat, ')') orelse return null;
        if (comm_end + 2 >= stat.len) return null;
        if (stat[comm_end + 2] == 'Z' or stat[comm_end + 2] == 'X') return null;
        return stat[comm_end + 2] == 'T' or stat[comm_end + 2] == 't';
    }

    /// Runs in a forked driver so a wrong mid-batch self-stop cannot suspend the
    /// test runner. It leaves the real stop status unconsumed, then calls
    /// `handleSignalEvent` once with controlled CHLD/CONT records. This pins the
    /// input order without depending on signalfd's kernel ordering.
    /// 0: the workload runs again; 3: setup failed;
    /// 4: it is still stopped.
    fn chldContBatchDriver(test_io: std.Io, ready_fd: std.os.linux.fd_t) u8 {
        const signal_config = SignalConfig.install(&[_]Sig{}) catch return 3;
        defer _ = signal_config.restoreParent();

        var spawned = supervisor.spawn(.{
            .argv = &[_:null]?[*:0]const u8{ "/bin/sleep", "30" },
            .envs = &[_:null]?[*:0]const u8{},
            .new_session = false,
            .ctty = null,
            .pdeath_signal = null,
            .tracing_child = false,
        }, &signal_config) catch return 3;
        defer spawned.close();
        const pid = spawned.pid;
        defer killAndReap(test_io, pid);

        // Publish the identity before it can stop, so the parent can clean up even
        // if this driver is suspended by the code under test.
        var pid_buf: [4]u8 = undefined;
        std.mem.writeInt(u32, &pid_buf, @intCast(pid), .little);
        if (io.syscallErrno(std.os.linux.write(ready_fd, &pid_buf, pid_buf.len)) != .SUCCESS) return 3;

        _ = std.os.linux.kill(pid, Sig.STOP);

        // The kernel must have stopped the workload, but drain must still own its
        // wait status. Only the event batch is synthetic; signalling and wait
        // handling still exercise the real child.
        waitForWaitid(test_io, pid, std.os.linux.W.STOPPED | std.os.linux.W.NOWAIT) catch return 3;
        const batch = [_]signal.Event{
            .{ .signo = @backingInt(Sig.CHLD), .code = signal.SI.USER, .value = 0 },
            .{ .signo = @backingInt(Sig.CONT), .code = signal.SI.USER, .value = 0 },
        };

        const policy: Policy = .{
            .expected_exit = .empty,
            .rewrites = null,
            .forward_group = false,
            .shutdown_timeout_ns = 0,
            .ignore_initial_hup_cont = false,
        };
        var state = State.init(policy, spawned.take());
        defer state.child.close();

        // The batch below is synthetic; this source is real, so the drain also
        // observes the SIGCHLD the stop queued and reports there is nothing else.
        var source = signalfd.Source.open(&signal_config) catch return 3;
        defer source.close();
        if (state.handleSignalEvent(&source, &batch) != null) return 4;
        return if (workloadStopped(test_io, pid) orelse return 3) 4 else 0;
    }

    /// Kill the driver and the workload only through kernel identities. On the
    /// failure this test targets the workload is stopped and unreaped, so a pidfd
    /// is available; its number cannot be recycled while the descriptor is open.
    fn cleanupBatchDriver(test_io: std.Io, driver_pid: std.os.linux.pid_t, workload: std.os.linux.pid_t) void {
        const raw = std.os.linux.pidfd_open(workload, 0);
        if (io.syscallErrno(raw) == .SUCCESS) {
            const w_fd: std.os.linux.fd_t = @intCast(raw);
            _ = std.os.linux.pidfd_send_signal(w_fd, .KILL, null, 0);
            var pfd = [_]std.os.linux.pollfd{.{
                .fd = w_fd,
                .events = std.os.linux.POLL.IN,
                .revents = 0,
            }};
            _ = std.os.linux.poll(&pfd, 1, 2_000);
            closeQuietly(w_fd);
        }

        _ = std.os.linux.kill(driver_pid, Sig.KILL);
        _ = waitForExit(test_io, driver_pid) catch {};
    }

    test "integration: a CHLD and CONT read in one batch resumes the stopped workload" {
        const test_io = std.testing.io;
        // G01: the CHLD must not drain and self-stop while a later CONT record in
        // the same read is still unprocessed. A pipe fixes the input order as
        // CHLD then CONT; the real workload's stop status is left pending. A single
        // `handleSignalEvent` must forward the CONT before it drains.
        if (underTracer(test_io)) return error.SkipZigTest; // the tracer owns the stop event

        var ready: [2]std.os.linux.fd_t = undefined;
        if (io.syscallErrno(std.os.linux.pipe2(&ready, .{ .NONBLOCK = true })) != .SUCCESS)
            return error.TestUnexpectedResult;
        defer closeQuietly(ready[0]);

        const driver = std.os.linux.fork();
        if (io.syscallErrno(driver) != .SUCCESS) {
            closeQuietly(ready[1]);
            return error.TestUnexpectedResult;
        }
        if (driver == 0) {
            _ = std.os.linux.close(ready[0]);
            const code = chldContBatchDriver(test_io, ready[1]);
            closeQuietly(ready[1]);
            std.os.linux.exit(code);
        }

        _ = std.os.linux.close(ready[1]);
        const driver_pid: std.os.linux.pid_t = @intCast(driver);

        const status = blk: {
            var workload: std.os.linux.pid_t = 0;
            // This scope owns the driver until wait consumes its terminal status.
            errdefer cleanupBatchDriver(test_io, driver_pid, workload);

            var pid_buf: [4]u8 = undefined;
            const deadline = std.Io.Clock.now(.awake, test_io).toNanoseconds() + 5 * std.time.ns_per_s;
            while (true) {
                const got = std.os.linux.read(ready[0], &pid_buf, pid_buf.len);
                if (got == pid_buf.len) break;
                if (io.syscallErrno(got) != .AGAIN or
                    std.Io.Clock.now(.awake, test_io).toNanoseconds() >= deadline)
                    return error.TestUnexpectedResult;

                try std.Io.sleep(test_io, .fromMilliseconds(1), .awake);
            }
            workload = @intCast(std.mem.readInt(u32, &pid_buf, .little));

            const event = try wait.waitForEvent(test_io, driver_pid, std.os.linux.W.UNTRACED);
            // Old behaviour: the mid-batch drain stopped zinit before it forwarded
            // the CONT it had already read. The stopped driver still needs cleanup.
            if (std.os.linux.W.IFSTOPPED(@intCast(event))) return error.TestUnexpectedResult;
            break :blk event;
        };

        try std.testing.expect(std.os.linux.W.IFEXITED(@intCast(status)));
        try std.testing.expectEqual(@as(u8, 0), std.os.linux.W.EXITSTATUS(@intCast(status)));
    }

    test "integration: a group send with no group falls back to the child" {
        const test_io = std.testing.io;
        const signal_config = try SignalConfig.install(&[_]Sig{});
        defer _ = signal_config.restoreParent();
        const forked = std.os.linux.fork();
        if (io.syscallErrno(forked) != .SUCCESS) return error.TestUnexpectedResult;
        if (forked == 0) {
            // The parent has TERM blocked for its own signalfd; this child must be killable.
            const empty = comptime std.os.linux.sigemptyset();
            _ = std.os.linux.sigprocmask(Sig.SETMASK, &empty, null);
            _ = std.os.linux.pause();
            std.os.linux.exit(0);
        }

        const pid: std.os.linux.pid_t = @intCast(forked);
        defer killAndReap(test_io, pid);
        const raw = std.os.linux.pidfd_open(pid, 0);
        if (io.syscallErrno(raw) != .SUCCESS) {
            _ = std.os.linux.kill(pid, Sig.KILL);
            _ = try waitForExit(test_io, pid);
            // A skip has to show up as a skip in the test report, not as a pass.
            std.debug.print("skip the no-group fallback check: no pidfd\n", .{});
            return error.SkipZigTest;
        }

        var state = State.init(.{
            .expected_exit = .empty,
            .rewrites = null,
            .forward_group = true,
            .shutdown_timeout_ns = 0,
            .ignore_initial_hup_cont = false,
        }, .{ .pid = pid, .pidfd = @intCast(raw) });
        defer state.child.close();

        try std.testing.expect(state.signalProcessGroup(@backingInt(Sig.TERM), null));
        try std.testing.expectEqual(@as(u32, @backingInt(Sig.TERM)), (try waitForExit(test_io, pid)).signalNumber());
    }

    test "integration: the numeric group path delivers the signal to the group" {
        const test_io = std.testing.io;
        // The path every kernel below 6.9 takes for `-g` and for the shutdown TERM/KILL.
        // Assert the group send itself: going through `signalProcessGroup` would also
        // pass when the child-only fallback delivered the signal, hiding a broken
        // numeric group send. The NOSYS/INVAL trigger that enters this mode is not
        // covered here; only the mode's behaviour is.
        const signal_config = try SignalConfig.install(&[_]Sig{});
        defer _ = signal_config.restoreParent();
        const base: Policy = .{
            .expected_exit = .empty,
            .rewrites = null,
            .forward_group = true,
            .shutdown_timeout_ns = 0,
            .ignore_initial_hup_cont = false,
        };

        var spawned = try spawnSleeper(&signal_config);
        defer spawned.close();
        defer killAndReap(test_io, spawned.pid);
        var state = State.init(base, spawned.take());
        defer state.child.close();

        try std.testing.expect(state.signalGroupByNumber(@backingInt(Sig.TERM)));
        const reaped_status = try waitForExit(test_io, spawned.pid);
        try std.testing.expectEqual(@as(u32, @backingInt(Sig.TERM)), reaped_status.signalNumber());
        // External waitForExit consumed the identity; mirror what drain does before
        // testing the numeric fallback, or a send could target a recycled pid.
        state.child_reaped = true;

        // The group is empty now: the proof fails, and nothing is signalled.
        try std.testing.expect(!state.signalGroupByNumber(@backingInt(Sig.TERM)));
    }

    fn spawnSleeper(signal_config: *const SignalConfig) !ProcessHandle {
        return supervisor.spawn(.{
            .argv = &[_:null]?[*:0]const u8{ "/bin/sleep", "30" },
            .envs = &[_:null]?[*:0]const u8{},
            .new_session = false,
            .ctty = null,
            .pdeath_signal = null,
            .tracing_child = false,
        }, signal_config);
    }

    fn childEvent(pid: std.os.linux.pid_t, flags: u32) !bool {
        var status: i32 = 0;
        const rc = std.os.linux.waitpid(pid, &status, flags | std.os.linux.W.NOHANG);
        if (rc == @as(usize, @intCast(pid))) return true;
        return switch (io.syscallErrno(rc)) {
            .SUCCESS => false, // still running, or the state change has not happened yet
            .CHILD => error.ChildAlreadyReaped,
            else => |e| {
                std.debug.print("waitpid({d}) failed: {t}\n", .{ pid, e });
                return error.TestUnexpectedResult;
            },
        };
    }

    const underTracer = wait.underTracer;

    /// Bounded by the monotonic clock, not by loop iterations: a state change is not
    /// visible to the next syscall, and yield counts mean different wall times.
    fn expectChildEvent(test_io: std.Io, pid: std.os.linux.pid_t, flags: u32) !void {
        _ = try wait.waitForEvent(test_io, pid, flags);
    }

    const waitForExit = wait.waitForExit;
    const killAndReap = wait.killAndReap;

    test "integration: the continue a detach queues is swallowed, a user's continue reaches the child" {
        const test_io = std.testing.io;
        // Only an untraced child reports a stop, and that stop is what this asserts.
        if (underTracer(test_io)) {
            std.debug.print("skip the detach's continue check: a tracer owns the stop/continue events\n", .{});
            return error.SkipZigTest;
        }

        const signal_config = try SignalConfig.install(&[_]Sig{});
        defer _ = signal_config.restoreParent();
        const base: Policy = .{
            .expected_exit = .empty,
            .rewrites = null,
            .forward_group = false,
            .shutdown_timeout_ns = 0,
            .ignore_initial_hup_cont = true,
        };

        // Stopped first: a continue is then an event only this test can cause.
        var spawned = try spawnSleeper(&signal_config);
        defer spawned.close();
        const pid = spawned.pid;
        // A stopped child is not reapable: leave nothing behind.
        defer killAndReap(test_io, pid);

        _ = std.os.linux.kill(pid, Sig.STOP);
        try expectChildEvent(test_io, pid, std.os.linux.W.UNTRACED);

        var state = State.init(base, spawned.take());
        defer state.child.close();

        var cont: signal.Event = .{ .signo = @backingInt(Sig.CONT), .code = signal.SI.KERNEL, .value = 0 };
        state.forwardSignal(cont);
        try std.testing.expect(!(try childEvent(pid, std.os.linux.W.CONTINUED)));

        // A continue someone sends is not the kernel's and must reach the child.
        cont.code = signal.SI.USER;
        state.forwardSignal(cont);
        try expectChildEvent(test_io, pid, std.os.linux.W.CONTINUED);
    }

    test "integration: a kernel HUP is ignored before releasing the workload" {
        const test_io = std.testing.io;
        const signal_config = try SignalConfig.install(&[_]Sig{});
        defer _ = signal_config.restoreParent();
        const base: Policy = .{
            .expected_exit = .empty,
            .rewrites = null,
            .forward_group = false,
            .shutdown_timeout_ns = 0,
            .ignore_initial_hup_cont = true,
        };

        // Hold HUP blocked until forwarding has finished. An incorrectly queued
        // HUP must terminate the child when the tracing gate releases its mask,
        // before /bin/true can exit. User HUP delivery is covered through supervise.
        var spawned = try supervisor.spawn(.{
            .argv = &[_:null]?[*:0]const u8{"/bin/true"},
            .envs = &[_:null]?[*:0]const u8{},
            .new_session = false,
            .ctty = null,
            .pdeath_signal = null,
            .tracing_child = true,
        }, &signal_config);
        defer spawned.close();
        const pid = spawned.pid;
        defer killAndReap(test_io, pid);

        var state = State.init(base, spawned.take());
        defer state.child.close();

        const hup: signal.Event = .{ .signo = @backingInt(Sig.HUP), .code = signal.SI.KERNEL, .value = 0 };
        state.forwardSignal(hup);
        try std.testing.expectEqual(std.os.linux.E.SUCCESS, io.syscallErrno(std.os.linux.kill(pid, Sig.USR1)));
        const status = try waitForExit(test_io, pid);
        state.child_reaped = true;
        try std.testing.expectEqual(WaitStatus.Class.exited, status.class());
        try std.testing.expectEqual(@as(u8, 0), status.exitCode());
    }

    test "integration: a rewrite to 0 drops the signal instead of forwarding it" {
        const test_io = std.testing.io;
        // Everything is blocked, so our own signal stays pending for the source.
        const signal_config = try SignalConfig.install(&[_]Sig{});
        defer _ = signal_config.restoreParent();
        var source = try signalfd.Source.open(&signal_config);
        defer source.close();
        var rewrites = RewriteMap.init();
        try rewrites.set(@backingInt(Sig.TERM), 0);
        const policy: Policy = .{
            .expected_exit = .empty,
            .rewrites = rewrites,
            .forward_group = false,
            .shutdown_timeout_ns = 0,
            .ignore_initial_hup_cont = true,
        };

        // Keep TERM blocked in the child until the forwarding call has returned.
        // Releasing the tracing gate then delivers any wrongly queued TERM before
        // /bin/true can exit. No scheduling-dependent "still alive" window is needed.
        var spawned = try supervisor.spawn(.{
            .argv = &[_:null]?[*:0]const u8{"/bin/true"},
            .envs = &[_:null]?[*:0]const u8{},
            .new_session = false,
            .ctty = null,
            .pdeath_signal = null,
            .tracing_child = true,
        }, &signal_config);
        defer spawned.close();
        defer killAndReap(test_io, spawned.pid);
        var state = State.init(policy, spawned.take());
        defer state.child.close();

        _ = std.os.linux.kill(std.os.linux.getpid(), Sig.TERM);
        var batch: [signalfd.Source.batch_max]signal.Event = undefined;
        const got = try source.waitBatch(&batch, 0);
        try std.testing.expectEqual(@as(usize, 1), got);
        try std.testing.expectEqual(@as(?Outcome, null), state.handleSignalEvent(&source, batch[0..got]));

        // Nothing left pending: the drain reports no more events.
        try std.testing.expectEqual(@as(?Outcome, null), state.handleSignalEvent(&source, &.{}));
        try std.testing.expectEqual(std.os.linux.E.SUCCESS, io.syscallErrno(std.os.linux.kill(spawned.pid, Sig.USR1)));
        const status = try waitForExit(test_io, spawned.pid);
        state.child_reaped = true;
        try std.testing.expectEqual(WaitStatus.Class.exited, status.class());
        try std.testing.expectEqual(@as(u8, 0), status.exitCode());
    }
};
