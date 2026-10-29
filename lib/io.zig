// SPDX-FileCopyrightText: 2026 YuMing He <ComixHe1895@outlook.com>
//
// SPDX-License-Identifier: MIT

//! Raw descriptor helpers: straight to the syscalls, and the bottom of the stack.

const std = @import("std");
const builtin = @import("builtin");

pub const Context = struct {
    in: std.os.linux.fd_t = -1,
    out: std.os.linux.fd_t = -1,
    err: std.os.linux.fd_t = -1,
};

pub const syscallErrno = if (builtin.cpu.arch == .x86_64) sharedSyscallErrno else inlineSyscallErrno;

inline fn inlineSyscallErrno(rc: usize) std.os.linux.E {
    return std.os.linux.errno(rc);
}

noinline fn sharedSyscallErrno(rc: usize) std.os.linux.E {
    return std.os.linux.errno(rc);
}

pub fn writeAll(fd: std.os.linux.fd_t, bytes: []const u8) void {
    var offset: usize = 0;
    while (offset < bytes.len) {
        const rc = std.os.linux.write(fd, bytes.ptr + offset, bytes.len - offset);
        switch (std.os.linux.errno(rc)) {
            .SUCCESS => {
                if (rc == 0) {
                    return;
                }

                offset += rc;
            },
            .INTR => {},
            else => return, // we can't do anything, just return
        }
    }
}

pub fn closeQuietly(fd: std.os.linux.fd_t) void {
    // nothing a caller could do about a failing close.
    _ = std.os.linux.close(fd);
}
