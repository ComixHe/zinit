// SPDX-FileCopyrightText: 2026 YuMing He <ComixHe1895@outlook.com>
//
// SPDX-License-Identifier: MIT

//! The parent process: setup, starting the workload, and the supervision loop.

const std = @import("std");
const io = @import("io.zig");
const errors = @import("errors.zig");
const log = @import("log.zig");
const signalfd = @import("signalfd.zig");
const workload = @import("workload.zig");
const child = @import("child.zig");
const signal = @import("signal.zig");

const Sig = signal.Sig;
const SignalConfig = signalfd.Config;

pub const Policy = workload.Policy;
pub const Outcome = workload.Outcome;
pub const ProcessHandle = workload.ProcessHandle;

/// The spawn contract lives where it is consumed, re-exported so callers keep
/// naming it through the module that starts the process.
pub const SpawnSpec = child.SpawnSpec;

pub fn spawn(
    spec: SpawnSpec,
    signal_config: *const SignalConfig,
) errors.SysCallError!ProcessHandle {
    const self_pid = std.os.linux.getpid();
    const flags: u32 = @backingInt(Sig.CHLD) | std.os.linux.CLONE.PIDFD;
    var pidfd: std.os.linux.fd_t = -1;
    const rc = std.os.linux.syscall5(.clone, flags, 0, @intFromPtr(&pidfd), 0, 0);

    const pid = switch (io.syscallErrno(rc)) {
        .SUCCESS => rc,
        .INVAL, .NOSYS => blk: {
            const forked = std.os.linux.fork();
            switch (io.syscallErrno(forked)) {
                .SUCCESS => break :blk forked,
                else => |e| {
                    @branchHint(.unlikely);
                    log.err("unable to fork: {e}", .{e});
                    return error.SysCallError;
                },
            }
        },
        else => |e| {
            @branchHint(.unlikely);
            log.err("unable to clone: {e}", .{e});
            return error.SysCallError;
        },
    };

    if (pid != 0) {
        const child_pid: std.os.linux.pid_t = @intCast(pid);
        if (!spec.new_session) {
            _ = std.os.linux.setpgid(child_pid, child_pid);
        }

        log.debug("spawned child {d} ({s})", .{ pid, if (pidfd >= 0) "pidfd" else "fork" });
        return .{
            .pid = child_pid,
            .pidfd = if (pidfd >= 0) pidfd else null,
        };
    }

    std.os.linux.exit(child.run(spec, signal_config, self_pid));
}

pub fn setupSubreaper(subreaper: bool) errors.SysCallError!void {
    if (subreaper) {
        const option = @backingInt(std.os.linux.PR.SET_CHILD_SUBREAPER);
        switch (io.syscallErrno(std.os.linux.prctl(option, 1, 0, 0, 0))) {
            .SUCCESS => {},
            else => |e| {
                @branchHint(.unlikely);
                log.err("unable to enable child subreaper mode: {e}", .{e});
                return error.SysCallError;
            },
        }
    } else if (std.os.linux.getpid() != 1) {
        log.warn(
            "not PID 1 and not a subreaper: orphaned descendants will not be reaped " ++
                "here, pass -s/--subreaper to adopt them",
            .{},
        );
    }
}

/// Runs the supervision loop. Consumes `spawned`: the handle is closed on return and
/// its pidfd cleared, so the caller must not close it again or use the pidfd after
/// this returns.
pub fn supervise(
    policy: Policy,
    signal_config: *const SignalConfig,
    spawned: *ProcessHandle,
) Outcome {
    defer spawned.close();

    var source = signalfd.Source.open(signal_config) catch {
        @branchHint(.unlikely);
        // Nothing can be forwarded or reaped without the source, and nothing this
        // early may outlive us: the group first (it exists by now), then the child for
        // the case where it has none yet.
        _ = std.os.linux.kill(-spawned.pid, Sig.KILL);
        _ = std.os.linux.kill(spawned.pid, Sig.KILL);
        return .failed;
    };
    defer source.close();

    var state = workload.State.init(policy, spawned.take());
    defer state.deinit();

    var batch: [signalfd.Source.batch_max]signal.Event = undefined;
    while (true) {
        if (state.reapPending()) {
            if (state.handleSignalEvent(&source, &.{})) |outcome| return outcome;
        } else {
            const timeout_ms: ?i32 = switch (state.nextWait()) {
                .infinite => -1,
                .remaining_ms => |remaining| if (remaining != 0) remaining else null,
                .clock_failed => null,
            };

            if (timeout_ms) |timeout| {
                const got = source.waitBatch(&batch, timeout) catch {
                    @branchHint(.unlikely);
                    return state.abortSupervision();
                };

                if (got != 0) {
                    if (state.handleSignalEvent(&source, batch[0..got])) |outcome| return outcome;
                }
            }
        }

        if (state.onTimeout()) |outcome| return outcome;
    }
}
