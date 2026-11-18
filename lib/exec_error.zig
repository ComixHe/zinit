// SPDX-FileCopyrightText: 2026 YuMing He <ComixHe1895@outlook.com>
//
// SPDX-License-Identifier: MIT

//! The CLOEXEC pipe that carries a child's exec failure to the supervisor.
//!
//! The child formats one line and writes it; the supervisor reads it after the
//! reap and writes it to the log. The report therefore does not depend on the
//! process that failed to become the workload: a forwarded signal or a broken
//! stderr cannot take it with them, and the child never touches a sink.

const std = @import("std");
const checks = @import("checks.zig");

/// One formatted line, including the `zinit child error: ` prefix. The child
/// removes the rest of the text it cannot fit, and a single pipe write this
/// small is atomic and cannot block on an empty pipe.
pub const max_message = 512;

comptime {
    // Linux's PIPE_BUF is 4096 on the supported architectures.
    // https://github.com/torvalds/linux/blob/20eef29b7c8465ac98d7dd6d6f2ac07a8d8056ca/include/uapi/linux/limits.h#L14
    checks.comptimeCheck(max_message > 0 and max_message <= 4096, "exec_error: the report must fit one atomic pipe write");
}

pub fn write(fd: std.os.linux.fd_t, text: []const u8) void {
    checks.check(fd >= 0, "exec_error: the write end must be a valid descriptor");
    checks.check(text.len <= max_message, "exec_error: the message exceeds the pipe record");
    _ = std.os.linux.write(fd, text.ptr, text.len);
}
