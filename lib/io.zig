// SPDX-FileCopyrightText: 2026 YuMing He <ComixHe1895@outlook.com>
//
// SPDX-License-Identifier: MIT

//! Raw descriptor helpers: straight to the syscalls, and the bottom of the stack.

const std = @import("std");
const checks = @import("checks.zig");
const builtin = @import("builtin");

pub const Context = struct {
    in: std.os.linux.fd_t = -1,
    out: std.os.linux.fd_t = -1,
    err: std.os.linux.fd_t = -1,
};

pub const syscallErrno = if (builtin.cpu.arch == .x86_64)
    sharedSyscallErrno
else
    inlineSyscallErrno;

inline fn inlineSyscallErrno(rc: usize) std.os.linux.E {
    return std.os.linux.errno(rc);
}

noinline fn sharedSyscallErrno(rc: usize) std.os.linux.E {
    return std.os.linux.errno(rc);
}

/// Null means every byte was written. A zero-progress write of a nonempty
/// remainder is an I/O failure, even when the filesystem returned no errno.
pub fn writeAll(fd: std.os.linux.fd_t, bytes: []const u8) ?std.os.linux.E {
    checks.check(fd >= 0, "io: writeAll needs a valid descriptor");

    var offset: usize = 0;
    while (offset < bytes.len) {
        const rc = std.os.linux.write(fd, bytes.ptr + offset, bytes.len - offset);
        switch (std.os.linux.errno(rc)) {
            .SUCCESS => {
                if (rc == 0) {
                    @branchHint(.unlikely);
                    return .IO;
                }

                checks.check(rc <= bytes.len - offset, "io: write reported more bytes than requested");
                offset += rc;
            },
            // report errno to caller, even though EINTR
            // let caller decides what's going on.
            else => |errno| return errno,
        }
    }

    return null;
}

pub fn closeQuietly(fd: std.os.linux.fd_t) void {
    // Linux releases the descriptor even when close reports EINTR/EIO.
    // So we no need to retry (even shouldn't for data race)
    _ = std.os.linux.close(fd);
}

pub fn isTty(fd: std.os.linux.fd_t) bool {
    checks.check(fd >= 0, "tty: isTty needs a valid descriptor");
    var termios: std.os.linux.termios = undefined;
    return syscallErrno(std.os.linux.tcgetattr(fd, &termios)) == .SUCCESS;
}
