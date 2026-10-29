// SPDX-FileCopyrightText: 2026 YuMing He <ComixHe1895@outlook.com>
//
// SPDX-License-Identifier: MIT

//! Terminal descriptor semantics, split from process creation: is a stream a
//! tty, is it our controlling terminal, and how the parent lets go of it
//! before the child starts a new session.

const std = @import("std");
const io = @import("io.zig");

const log = @import("log.zig");

/// Whether a terminal is attached to `fd`.
pub fn isTty(fd: std.os.linux.fd_t) bool {
    var termios: std.os.linux.termios = undefined;
    return io.syscallErrno(std.os.linux.tcgetattr(fd, &termios)) == .SUCCESS;
}

/// Whether `fd` is this session's controlling terminal, regardless of whether
/// zinit's process group is in the foreground. `tcgetpgrp` also rejects non-tty fds.
pub fn isControlTerminal(fd: std.os.linux.fd_t) bool {
    var pgrp: std.os.linux.pid_t = undefined;
    return io.syscallErrno(std.os.linux.tcgetpgrp(fd, &pgrp)) == .SUCCESS;
}

/// Runs in the parent, before spawning a child into a new session: drop our
/// controlling terminal so the kernel's HUP/CONT land here and not on the
/// child-to-be. Returns whether the detach really happened and zinit was the
/// session leader, which tells the caller to ignore the initial HUP/CONT.
pub fn detachFromControlTerminal(fd: std.os.linux.fd_t) bool {
    const rc = std.os.linux.ioctl(fd, std.os.linux.T.IOCNOTTY, 0);
    switch (io.syscallErrno(rc)) {
        .SUCCESS => {},
        .NOTTY, .NXIO, .PERM => |e| {
            log.debug("{s}: {e}", .{ "unable to detach from terminal", e });
            return false;
        },
        else => |e| {
            @branchHint(.unlikely);
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
