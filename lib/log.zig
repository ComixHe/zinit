// SPDX-FileCopyrightText: 2026 YuMing He <ComixHe1895@outlook.com>
//
// SPDX-License-Identifier: MIT

//! Minimal logger: no allocation, no `std.log`, one mutable global for sink and level.

const std = @import("std");
const builtin = @import("builtin");
const tty = @import("tty.zig");
const fmt = @import("fmt.zig");
const io = @import("io.zig");
const wait = @import("wait.zig");
const WaitStatus = wait.WaitStatus;
const config = @import("config");

/// The level to print at when nothing chose one at runtime: the build's own default,
/// clamped to its ceiling so a quiet build never defaults to a level it cannot print.
pub const default_level: std.log.Level = @fromBackingInt(@min(
    @backingInt(config.default_log_level),
    @backingInt(config.max_log_level),
));

/// The program's only mutable global: threading a sink through every call would cost more.
const State = struct {
    sink: std.os.linux.fd_t = -1,
    level: std.log.Level = if (builtin.is_test) .warn else default_level,
    color: bool = false,
};

var state: State = .{};

pub fn init(sink_fd: std.os.linux.fd_t) !void {
    if (sink_fd < 0) {
        @branchHint(.unlikely);
        return error.InvalidSink;
    }

    state.sink = sink_fd;
    state.color = tty.isTty(state.sink);
}

pub fn deinit() void {
    state.sink = -1;
    state.color = false;
}

pub fn setRuntimeLevel(level: std.log.Level) void {
    state.level = level;
}

fn dropped(level: std.log.Level) bool {
    return @backingInt(level) > @backingInt(state.level);
}

fn aboveCeiling(comptime level: std.log.Level) bool {
    return @backingInt(level) > @backingInt(config.max_log_level);
}

fn emit(level: std.log.Level, msg: []const u8) void {
    const prefix: []const u8 = if (state.color) switch (level) {
        .err => "\x1b[31m[zinit] ERROR:\x1b[0m ",
        .warn => "\x1b[33m[zinit] WARN:\x1b[0m ",
        .info => "\x1b[32m[zinit] INFO:\x1b[0m ",
        .debug => "\x1b[36m[zinit] DEBUG:\x1b[0m ",
    } else switch (level) {
        .err => "[zinit] ERROR: ",
        .warn => "[zinit] WARN: ",
        .info => "[zinit] INFO: ",
        .debug => "[zinit] DEBUG: ",
    };

    var buf: [512]u8 = undefined;
    // One byte is kept back for the newline
    const text = fmt.bufPrint(buf[0 .. buf.len - 1], "{s}{s}", .{ prefix, msg });
    buf[text.len] = '\n';
    io.writeAll(state.sink, buf[0 .. text.len + 1]);
}

fn print(comptime level: std.log.Level, comptime format: []const u8, args: anytype) void {
    if (comptime aboveCeiling(level)) return;

    if (dropped(level)) return;

    var buf: [512]u8 = undefined;
    const msg = fmt.bufPrint(&buf, format, args);
    emit(level, msg);
}

pub fn err(comptime format: []const u8, args: anytype) void {
    print(.err, format, args);
}

pub fn warn(comptime format: []const u8, args: anytype) void {
    print(.warn, format, args);
}

pub fn debug(comptime format: []const u8, args: anytype) void {
    print(.debug, format, args);
}

pub const Role = enum { main, orphaned };

fn exitLevel(status: WaitStatus, role: Role) std.log.Level {
    if (role == .main) return .info;

    return switch (status.class()) {
        .exited => if (status.exitCode() == 0) .debug else .info,
        else => .info,
    };
}

pub fn processExited(pid: std.os.linux.pid_t, status: WaitStatus, role: Role) void {
    if (comptime aboveCeiling(.info)) return;

    const level = exitLevel(status, role);
    if (dropped(level)) return;

    const what: []const u8 = switch (role) {
        .main => "child process",
        .orphaned => "orphaned process",
    };

    var buf: [128]u8 = undefined;
    var at: usize = 0;
    at = fmt.appendBytes(&buf, at, what);
    at = fmt.appendBytes(&buf, at, " ");
    at = fmt.appendInt(&buf, at, @intCast(pid), .dec);
    at = fmt.appendBytes(&buf, at, " exited with ");

    switch (status.class()) {
        .exited => {
            at = fmt.appendBytes(&buf, at, "code ");
            at = fmt.appendInt(&buf, at, status.exitCode(), .dec);
            at = fmt.appendBytes(&buf, at, ".");
        },
        .signaled => {
            at = fmt.appendBytes(&buf, at, "signal ");
            at = fmt.appendInt(&buf, at, status.signalNumber(), .dec);
            at = fmt.appendBytes(&buf, at, ".");
        },
        .unknown => at = fmt.appendBytes(&buf, at, "unknown status"),
    }

    emit(level, buf[0..at]);
}

// kcov-exclude-tests (everything below is test-only).
const Sink = struct {
    pipe: [2]std.os.linux.fd_t = undefined,

    fn open() !Sink {
        var sink: Sink = .{};
        try std.testing.expectEqual(
            std.os.linux.E.SUCCESS,
            io.syscallErrno(std.os.linux.pipe2(&sink.pipe, .{ .NONBLOCK = true })),
        );

        try init(sink.pipe[1]);
        return sink;
    }

    fn close(self: Sink) void {
        deinit();

        io.closeQuietly(self.pipe[0]);
        io.closeQuietly(self.pipe[1]);
    }

    fn read(self: Sink, allocator: std.mem.Allocator) ![]u8 {
        var text: std.ArrayList(u8) = .empty;
        errdefer text.deinit(allocator);

        var chunk: [256]u8 = undefined;
        while (true) {
            const size = std.posix.read(self.pipe[0], &chunk) catch |read_error| switch (read_error) {
                error.WouldBlock => break, // the non-blocking pipe is drained
                else => |other| return other,
            };
            if (size == 0) break;

            try text.appendSlice(allocator, chunk[0..size]);
        }

        return text.toOwnedSlice(allocator);
    }
};

test "processExited words every class of exit" {
    if (comptime @backingInt(config.max_log_level) < @backingInt(std.log.Level.info))
        return error.SkipZigTest; // this build compiles the level out

    const sink = try Sink.open();
    defer sink.close();

    setRuntimeLevel(.info);
    defer setRuntimeLevel(.warn);

    const cases = [_]struct {
        pid: std.os.linux.pid_t,
        status: WaitStatus,
        role: Role,
        tokens: []const []const u8,
    }{
        .{ .pid = 42, .status = .{ .raw = @as(u32, 7) << 8 }, .role = .main, .tokens = &.{ "child", "42", "code 7" } },
        .{ .pid = 43, .status = .{ .raw = 9 }, .role = .orphaned, .tokens = &.{ "orphaned", "43", "signal 9" } },
        .{ .pid = 44, .status = .{ .raw = 0x1ff }, .role = .orphaned, .tokens = &.{ "orphaned", "44", "unknown" } },
    };

    const allocator = std.testing.allocator;

    for (cases) |case| {
        processExited(case.pid, case.status, case.role);
        const text = try sink.read(allocator);
        defer allocator.free(text);

        try std.testing.expect(std.mem.find(u8, text, "INFO:") != null);
        for (case.tokens) |token| try std.testing.expect(std.mem.find(u8, text, token) != null);
    }
}

test "a clean orphan exit is routine, not a line at info" {
    if (comptime @backingInt(config.max_log_level) < @backingInt(std.log.Level.info))
        return error.SkipZigTest; // this build compiles the level out

    const sink = try Sink.open();
    defer sink.close();

    setRuntimeLevel(.info);
    defer setRuntimeLevel(.warn);

    const allocator = std.testing.allocator;

    // A helper that did its job and left: nothing worth a line.
    processExited(50, .{ .raw = 0 }, .orphaned);
    const nothing = try sink.read(allocator);
    defer allocator.free(nothing);
    try std.testing.expectEqual(@as(usize, 0), nothing.len);

    // The same exit with a code is the record that something happened to it.
    processExited(51, .{ .raw = @as(u32, 7) << 8 }, .orphaned);
    const nonzero = try sink.read(allocator);
    defer allocator.free(nonzero);
    for ([_][]const u8{ "INFO:", "orphaned", "51", "code 7" }) |token|
        try std.testing.expect(std.mem.find(u8, nonzero, token) != null);

    if (comptime @backingInt(config.max_log_level) >= @backingInt(std.log.Level.debug)) {
        setRuntimeLevel(.debug);
        processExited(52, .{ .raw = 0 }, .orphaned);

        const clean = try sink.read(allocator);
        defer allocator.free(clean);

        for ([_][]const u8{ "DEBUG:", "orphaned", "52", "code 0" }) |token|
            try std.testing.expect(std.mem.find(u8, clean, token) != null);
    }
}
