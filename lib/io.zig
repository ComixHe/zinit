// SPDX-FileCopyrightText: 2026 YuMing He <ComixHe1895@outlook.com>
//
// SPDX-License-Identifier: MIT

//! Raw descriptor helpers: straight to the syscalls, and the bottom of the stack.

const std = @import("std");

pub fn writeAll(fd: std.os.linux.fd_t, bytes: []const u8) void {
    var offset: usize = 0;
    while (offset < bytes.len) {
        const rc = std.os.linux.write(fd, bytes.ptr + offset, bytes.len - offset);
        switch (std.os.linux.errno(rc)) {
            // A short write may legally be zero
            .SUCCESS => {
                if (rc == 0) return;
                offset += @intCast(rc);
            },
            .INTR => {},
            else => return,
        }
    }
}

pub inline fn tryClose(fd: std.os.linux.fd_t) void {
    // nothing a caller could do about a failing close.
    _ = std.os.linux.close(fd);
}

// kcov-exclude-tests (everything below is test-only).
test "writeAll gives up quietly on a bad descriptor" {
    // -1 is not a descriptor: the write fails with EBADF and must not spin.
    writeAll(-1, "hello");
}
