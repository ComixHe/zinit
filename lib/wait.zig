// SPDX-FileCopyrightText: 2026 YuMing He <ComixHe1895@outlook.com>
//
// SPDX-License-Identifier: MIT

//! Decoding a `waitpid` status into the class and the code or signal to report.

const std = @import("std");
const io = @import("io.zig");

/// Which exit codes count as success; `-e` sets the bits.
pub const ExitCodeSet = std.bit_set.Static(256);

pub const WaitStatus = struct {
    raw: u32,

    pub fn fromRaw(status: i32) WaitStatus {
        return .{ .raw = @intCast(status) };
    }

    pub const Class = enum { exited, signaled, unknown };

    pub const Kind = enum { exited, signaled, stopped, continued, unknown };

    /// `class`, `kind` and `exitCode` are inlined so the raw-status masks fold
    /// into each caller's `switch`; the three out-of-line copies together cost
    /// more than the folded code does.
    pub inline fn class(self: WaitStatus) Class {
        return switch (self.kind()) {
            .exited => .exited,
            .signaled => .signaled,
            else => .unknown,
        };
    }

    pub inline fn kind(self: WaitStatus) Kind {
        if (std.os.linux.W.IFEXITED(self.raw)) return .exited;
        if (std.os.linux.W.IFSIGNALED(self.raw)) return .signaled;
        if ((self.raw & 0xffff) == 0xffff) return .continued;
        if (std.os.linux.W.IFSTOPPED(self.raw)) return .stopped;
        return .unknown;
    }

    pub inline fn exitCode(self: WaitStatus) u8 {
        if (std.os.linux.W.IFEXITED(self.raw)) return std.os.linux.W.EXITSTATUS(self.raw);
        if (std.os.linux.W.IFSIGNALED(self.raw)) {
            return @intCast(128 + @backingInt(std.os.linux.W.TERMSIG(self.raw)));
        }

        return 0;
    }

    pub fn signalNumber(self: WaitStatus) u32 {
        return @intCast(@backingInt(std.os.linux.W.TERMSIG(self.raw)));
    }
};

// kcov-exclude-tests (everything below is test-only).

/// What one non-blocking look at a child says. "Not reaped yet" and "cannot be
/// reaped any more" are different facts and must not collapse into one `null`.
const Polled = union(enum) {
    running,
    exited: WaitStatus,
    /// ECHILD: this process already reaped it, or never owned it.
    gone,
    failed: std.os.linux.E,
};

fn pollChild(pid: std.os.linux.pid_t) Polled {
    var status: i32 = 0;
    const rc = std.os.linux.waitpid(pid, &status, std.os.linux.W.NOHANG);
    if (rc == @as(usize, @intCast(pid))) return .{ .exited = WaitStatus.fromRaw(status) };
    return switch (io.syscallErrno(rc)) {
        .SUCCESS => .running, // waitpid returned 0: state changed, nothing reaped.
        .CHILD => .gone,
        else => |e| .{ .failed = e },
    };
}

/// Wait for one child event selected by `flags`, bounded by the monotonic clock.
/// The raw status is returned so callers keep their own stopped/exited assertions.
/// `waitpid` stays a raw call: no std wrapper exposes WUNTRACED/WCONTINUED or the
/// ECHILD distinction these tests rely on.
pub fn waitForEvent(test_io: std.Io, pid: std.os.linux.pid_t, flags: u32) !i32 {
    const timeout_ns: i96 = 5 * std.time.ns_per_s;
    const deadline = std.Io.Clock.now(.awake, test_io).toNanoseconds() + timeout_ns;

    while (true) {
        var status: i32 = 0;
        const rc = std.os.linux.waitpid(pid, &status, flags | std.os.linux.W.NOHANG);
        if (rc == @as(usize, @intCast(pid))) return status;
        switch (io.syscallErrno(rc)) {
            .SUCCESS => {},
            .CHILD => return error.ChildAlreadyReaped,
            else => return error.TestUnexpectedResult,
        }

        if (std.Io.Clock.now(.awake, test_io).toNanoseconds() >= deadline) return error.TestTimeout;
        try std.Io.sleep(test_io, .fromMilliseconds(1), .awake);
    }
}

/// Reap one child within a real deadline. This is the no-stop-event form of
/// `waitForEvent`, retaining the ECHILD distinction for reaped identities.
pub fn waitForExit(test_io: std.Io, pid: std.os.linux.pid_t) !WaitStatus {
    return WaitStatus.fromRaw(try waitForEvent(test_io, pid, 0));
}

/// Kill and reap a child a test owns. Does nothing once it is gone: signalling a
/// reaped number can hit an unrelated process that recycled the pid.
pub fn killAndReap(test_io: std.Io, pid: std.os.linux.pid_t) void {
    switch (pollChild(pid)) {
        .running => {},
        .exited, .gone, .failed => return,
    }

    std.posix.kill(pid, .KILL) catch {};
    _ = waitForExit(test_io, pid) catch {};
}

/// Whether a tracer (kcov, a debugger) owns this process's stop/continue events.
/// Tests that need those events must skip rather than fail when one does.
pub fn underTracer(test_io: std.Io) bool {
    const file = std.Io.Dir.openFileAbsolute(test_io, "/proc/self/status", .{}) catch return true;
    defer file.close(test_io);

    var buf: [4096]u8 = undefined;
    var iov = [_][]u8{&buf};
    const n = file.readStreaming(test_io, &iov) catch return true;

    const text = buf[0..n];
    const marker = "TracerPid:";
    const at = std.mem.find(u8, text, marker) orelse return true;
    var i = at + marker.len;
    while (i < text.len and (text[i] == ' ' or text[i] == '\t')) i += 1;
    return i >= text.len or text[i] != '0';
}

test "a continued status is a continue, not a stop" {
    const Kind = WaitStatus.Kind;
    const Class = WaitStatus.Class;

    // 0xffff is the kernel's continued marker; W.IFSTOPPED also matches it, so
    // `kind` checks continued first. `class` remains termination-only.
    try std.testing.expectEqual(Kind.continued, (WaitStatus{ .raw = 0xffff }).kind());
    try std.testing.expectEqual(Class.unknown, (WaitStatus{ .raw = 0xffff }).class());

    const stopped: u32 = (@as(u32, @backingInt(std.os.linux.SIG.TSTP)) << 8) | 0x7f;
    try std.testing.expectEqual(Kind.stopped, (WaitStatus{ .raw = stopped }).kind());

    try std.testing.expectEqual(Kind.exited, (WaitStatus{ .raw = @as(u32, 42) << 8 }).kind());
    try std.testing.expectEqual(Kind.signaled, (WaitStatus{ .raw = 9 }).kind());
}

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
