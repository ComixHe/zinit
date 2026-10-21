// SPDX-FileCopyrightText: 2026 YuMing He <ComixHe1895@outlook.com>
//
// SPDX-License-Identifier: MIT

//! Decoding a `waitpid` status into the class and the code or signal to report.

const std = @import("std");

/// Which exit codes count as success; `-e` sets the bits.
pub const ExitCodeSet = std.StaticBitSet(256);

pub const WaitStatus = struct {
    raw: u32,

    pub fn fromRaw(status: i32) WaitStatus {
        return .{ .raw = @intCast(status) };
    }

    pub const Class = enum { exited, signaled, unknown };

    pub fn class(self: WaitStatus) Class {
        if (std.os.linux.W.IFEXITED(self.raw)) return .exited;
        if (std.os.linux.W.IFSIGNALED(self.raw)) return .signaled;
        return .unknown;
    }

    pub inline fn exitCode(self: WaitStatus) u8 {
        if (std.os.linux.W.IFEXITED(self.raw)) return std.os.linux.W.EXITSTATUS(self.raw);
        if (std.os.linux.W.IFSIGNALED(self.raw)) {
            return @intCast(128 + @backingInt(std.os.linux.W.TERMSIG(self.raw)));
        }

        return 0;
    }

    pub inline fn signalNumber(self: WaitStatus) u32 {
        return @intCast(@backingInt(std.os.linux.W.TERMSIG(self.raw)));
    }
};

// kcov-exclude-tests (everything below is test-only).
test "WaitStatus.exitCode maps wait statuses to exit codes" {
    try std.testing.expectEqual(@as(u8, 42), (WaitStatus{ .raw = @as(u32, 42) << 8 }).exitCode());
    try std.testing.expectEqual(@as(u8, 128 + 9), (WaitStatus{ .raw = 9 }).exitCode());
    try std.testing.expectEqual(@as(u8, 0), (WaitStatus{ .raw = 0x1FF }).exitCode());

    // The class decides which message the supervisor logs.
    try std.testing.expectEqual(WaitStatus.Class.exited, (WaitStatus{ .raw = @as(u32, 42) << 8 }).class());
    try std.testing.expectEqual(WaitStatus.Class.signaled, (WaitStatus{ .raw = 9 }).class());
    try std.testing.expectEqual(@as(u32, 9), (WaitStatus{ .raw = 9 }).signalNumber());
    // Neither exited nor signalled (a stopped status): the message admits to not knowing.
    try std.testing.expectEqual(WaitStatus.Class.unknown, (WaitStatus{ .raw = 0x1FF }).class());
}
