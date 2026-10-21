// SPDX-FileCopyrightText: 2026 YuMing He <ComixHe1895@outlook.com>
//
// SPDX-License-Identifier: MIT

//! Minimal logger: no allocation, no `std.log`, one mutable global for sink and level.

const std = @import("std");
const builtin = @import("builtin");

const fmt = @import("fmt.zig");
const io = @import("io.zig");
const wait = @import("wait.zig");
const WaitStatus = wait.WaitStatus;
const config = @import("config");

/// Where lines go before `init` chooses a sink. A test starts silent (a descriptor
/// that is not one) and passes its own pipe to `init` when it wants to read them.
pub const default_sink: std.os.linux.fd_t = if (builtin.is_test) -1 else std.os.linux.STDERR_FILENO;

/// The level to print at when nothing chose one at runtime: the build's own default,
/// clamped to its ceiling so a quiet build never defaults to a level it cannot print.
pub fn defaultLevel() std.log.Level {
    return @fromBackingInt(@intCast(@min(@backingInt(config.default_log_level), @backingInt(config.max_log_level))));
}

/// The program's only mutable global: threading a sink through every call would cost more.
const State = struct {
    sink: std.os.linux.fd_t = default_sink,
    level: std.log.Level = if (builtin.is_test) .warn else defaultLevel(),
    color: bool = false,
};

var state: State = .{};

pub fn init(sink_fd: std.os.linux.fd_t) void {
    var termios: std.os.linux.termios = undefined;
    const rc = std.os.linux.tcgetattr(sink_fd, &termios);
    state.color = std.os.linux.errno(rc) == .SUCCESS;
    state.sink = sink_fd;
}

pub fn setLevel(level: std.log.Level) void {
    state.level = level;
}

/// Ahead of the formatting: a line that is going to be dropped must not be built first.
fn dropped(level: std.log.Level) bool {
    return @backingInt(level) > @backingInt(state.level);
}

fn aboveCeiling(comptime level: std.log.Level) bool {
    return @backingInt(level) > @backingInt(config.max_log_level);
}

fn emit(level: std.log.Level, msg: []const u8) void {
    if (dropped(level)) return;

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
/// Which process the exit belongs to: the main child decides zinit's own code.
pub const Role = enum { main, orphaned };

/// The main child's exit is why the container stops; a clean orphan exit is routine.
fn exitLevel(status: WaitStatus, role: Role) std.log.Level {
    if (role == .main) return .info;

    return switch (status.class()) {
        .exited => if (status.exitCode() == 0) .debug else .info,
        else => .info,
    };
}

pub fn processExited(pid: std.os.linux.pid_t, status: WaitStatus, role: Role) void {
    // The level test sits ahead of the formatting: this is the reap path's hot line.
    if (comptime aboveCeiling(.info)) return;

    const level = exitLevel(status, role);
    if (dropped(level)) return;

    const pid_number: u32 = @intCast(pid);
    var buf: [128]u8 = undefined;
    const what: []const u8 = switch (role) {
        .main => "child process",
        .orphaned => "orphaned process",
    };

    const code = status.exitCode();
    const signal_number = status.signalNumber();
    const msg = switch (status.class()) {
        .exited => fmt.bufPrint(&buf, "{s} {d} exited with code {d}.", .{ what, pid_number, code }),
        .signaled => fmt.bufPrint(&buf, "{s} {d} exited with signal {d}.", .{
            what, pid_number, signal_number,
        }),
        .unknown => fmt.bufPrint(&buf, "{s} {d} exited with unknown status", .{ what, pid_number }),
    };

    emit(level, msg);
}

// kcov-exclude-tests (everything below is test-only).
const Sink = struct {
    pipe: [2]std.os.linux.fd_t = undefined,

    fn open() !Sink {
        var sink: Sink = .{};
        try std.testing.expectEqual(
            std.os.linux.E.SUCCESS,
            std.os.linux.errno(std.os.linux.pipe2(&sink.pipe, .{ .NONBLOCK = true })),
        );
        init(sink.pipe[1]);
        return sink;
    }

    fn close(self: Sink) void {
        init(default_sink);
        io.tryClose(self.pipe[0]);
        io.tryClose(self.pipe[1]);
    }

    fn read(self: Sink, buf: []u8) []u8 {
        return buf[0..(std.posix.read(self.pipe[0], buf) catch 0)];
    }
};

test "processExited words every class of exit" {
    if (comptime @backingInt(config.max_log_level) < @backingInt(std.log.Level.info)) return;

    const sink = try Sink.open();
    defer sink.close();
    setLevel(.info);
    defer setLevel(.warn);

    processExited(42, .{ .raw = @as(u32, 42) << 8 }, .main);
    processExited(43, .{ .raw = 9 }, .orphaned);
    processExited(44, .{ .raw = 0x1FF }, .orphaned);

    var buf: [256]u8 = undefined;
    const text = sink.read(&buf);
    try std.testing.expect(std.mem.indexOf(u8, text, "child process 42 exited with code 42.") != null);
    try std.testing.expect(std.mem.indexOf(u8, text, "orphaned process 43 exited with signal 9.") != null);
    try std.testing.expect(std.mem.indexOf(u8, text, "orphaned process 44 exited with unknown status") != null);
}

test "a clean orphan exit is routine, not a line at info" {
    if (comptime @backingInt(config.max_log_level) < @backingInt(std.log.Level.info)) return;

    const sink = try Sink.open();
    defer sink.close();
    setLevel(.info);
    defer setLevel(.warn);

    var buf: [256]u8 = undefined;

    // A helper that did its job and left: nothing worth a line.
    processExited(50, .{ .raw = 0 }, .orphaned);
    try std.testing.expectEqual(@as(usize, 0), sink.read(&buf).len);

    // The same exit with a code is the record that something happened to it.
    processExited(51, .{ .raw = @as(u32, 7) << 8 }, .orphaned);
    try std.testing.expect(std.mem.indexOf(u8, sink.read(&buf), "orphaned process 51 exited with code 7.") != null);

    if (comptime @backingInt(config.max_log_level) >= @backingInt(std.log.Level.debug)) {
        setLevel(.debug);
        processExited(52, .{ .raw = 0 }, .orphaned);
        try std.testing.expect(std.mem.indexOf(u8, sink.read(&buf), "orphaned process 52 exited with code 0.") != null);
    }
}
