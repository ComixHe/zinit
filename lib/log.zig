// SPDX-FileCopyrightText: 2026 YuMing He <ComixHe1895@outlook.com>
//
// SPDX-License-Identifier: MIT

//! Minimal logger: no allocation, no `std.log`, one mutable global for sink and level.

const std = @import("std");
const checks = @import("checks.zig");
const builtin = @import("builtin");
const fmt = @import("fmt.zig");
const io = @import("io.zig");
const wait = @import("wait.zig");
const WaitStatus = wait.WaitStatus;
const config = @import("config");

var state: State = .{};

pub const default_level: std.log.Level = @fromBackingInt(@min(
    @backingInt(config.default_log_level),
    @backingInt(config.max_log_level),
));

const SinkKind = enum {
    stream,
    nonblocking,
    socket,
};

const State = struct {
    sink: std.os.linux.fd_t = -1,
    /// Only a separately opened nonblocking sink is owned. Stderr is borrowed.
    owned: bool = false,
    kind: SinkKind = .stream,
    level: std.log.Level = if (builtin.is_test) .warn else default_level,
    color: bool = false,
};

fn classifySink(fd: std.os.linux.fd_t) SinkKind {
    var socket_type: i32 = 0;
    var socket_len: std.os.linux.socklen_t = @sizeOf(i32);
    if (io.syscallErrno(std.os.linux.getsockopt(
        fd,
        std.os.linux.SOL.SOCKET,
        std.os.linux.SO.TYPE,
        std.mem.asBytes(&socket_type).ptr,
        &socket_len,
    )) == .SUCCESS) return .socket;

    if (io.syscallErrno(std.os.linux.lseek(fd, 0, std.os.linux.SEEK.CUR)) == .SUCCESS)
        return .stream;

    return .nonblocking;
}

pub fn init(sink_fd: std.os.linux.fd_t) error{ InvalidSink, AlreadyInitialized }!void {
    if (sink_fd < 0) {
        @branchHint(.unlikely);
        return error.InvalidSink;
    }

    if (state.sink >= 0) {
        @branchHint(.unlikely);
        return error.AlreadyInitialized;
    }

    const kind = classifySink(sink_fd);

    var fd = sink_fd;
    var owned = false;
    if (kind == .nonblocking) {
        var buf: [fdPathLen:0]u8 = undefined;
        fdPath(sink_fd, &buf);
        fd = openNonBlocking(buf[0..]) orelse {
            @branchHint(.unlikely);
            return;
        };

        owned = true;
    }

    state = .{
        .sink = fd,
        .owned = owned,
        .kind = kind,
        .level = state.level,
        .color = io.isTty(fd),
    };
}

pub fn deinit() void {
    if (state.owned) io.closeQuietly(state.sink);
    state = .{ .level = state.level, .sink = -1 };
}

fn UnsignedPositiveType(comptime T: type) type {
    const info = @typeInfo(T);
    comptime {
        checks.comptimeCheck(info == .int, "log: expected an integer type");
    }

    if (info.int.signedness == .unsigned) return T;

    const target_bits = info.int.bits - 1;
    return @Int(.unsigned, target_bits);
}

fn decimalLen(comptime T: type) usize {
    comptime {
        const info = @typeInfo(T);
        checks.comptimeCheck(info == .int, "log: expected an integer type");
        checks.comptimeCheck(info.int.signedness == .unsigned, "log: expected an unsigned type");
    }

    const max_val = std.math.maxInt(T);

    var len: usize = 0;
    var temp = max_val;
    while (temp > 0) {
        len += 1;
        temp /= 10;
    }

    return len;
}

const selfProcFd = "/proc/self/fd/";
const fdPathLen = selfProcFd.len + decimalLen(UnsignedPositiveType(std.os.linux.fd_t));

fn fdPath(fd: std.os.linux.fd_t, buf: *[fdPathLen]u8) void {
    // We are not concerned with whether `/proc` is a valid proc filesystem or
    // with any potential attacks based on filesystem paths.
    // This is not our security boundary.
    @memcpy(buf[0..selfProcFd.len], selfProcFd);
    const at = fmt.appendInt(buf, selfProcFd.len, @intCast(fd), .dec);
    buf[at] = 0;
}

fn openNonBlocking(path: [:0]const u8) ?std.os.linux.fd_t {
    const raw = std.os.linux.openat(
        std.os.linux.AT.FDCWD,
        path,
        .{ .ACCMODE = .WRONLY, .NONBLOCK = true, .CLOEXEC = true, .NOCTTY = true },
        0,
    );

    if (io.syscallErrno(raw) != .SUCCESS) return null;
    return @intCast(raw);
}

const WriteResult = enum {
    complete,
    /// No bytes accepted: another event may use the same sink later.
    dropped,
    /// The sink failed or may contain a partial line. Disable it before the
    /// next event so the next prefix cannot be appended to an unfinished line.
    failed,
};

fn writeBestEffort(kind: SinkKind, fd: std.os.linux.fd_t, bytes: []const u8) WriteResult {
    if (kind == .stream) {
        if (io.writeAll(fd, bytes) != null) return .failed;
        return .complete;
    }

    const rc = if (kind == .socket)
        std.os.linux.sendto(
            fd,
            bytes.ptr,
            bytes.len,
            std.os.linux.MSG.DONTWAIT | std.os.linux.MSG.NOSIGNAL,
            null,
            0,
        )
    else
        std.os.linux.write(fd, bytes.ptr, bytes.len);

    return switch (io.syscallErrno(rc)) {
        .SUCCESS => blk: {
            checks.check(rc <= bytes.len, "log: sink accepted more bytes than requested");
            break :blk if (rc == bytes.len) .complete else .failed;
        },
        .INTR, .AGAIN => .dropped,
        else => .failed,
    };
}

/// Async-signal-safe, diagnostic-only attempt on the already prepared sink.
/// Pipe/FIFO sinks have an independent nonblocking open description, socket
/// sends use per-call flags. A disabled sink is left disabled. The caller must
/// block SIGPIPE before entering, and must not use the formatter or normal logs.
pub fn writeFatal(iov: []const std.posix.iovec_const) void {
    if (state.sink < 0) return;
    if (state.kind == .socket) {
        const message: std.os.linux.msghdr_const = .{
            .name = null,
            .namelen = 0,
            .iov = iov.ptr,
            .iovlen = iov.len,
            .control = null,
            .controllen = 0,
            .flags = 0,
        };
        _ = std.os.linux.sendmsg(
            state.sink,
            &message,
            std.os.linux.MSG.DONTWAIT | std.os.linux.MSG.NOSIGNAL,
        );
    } else {
        // No retry, including EINTR/EAGAIN: exit takes priority over diagnostics.
        _ = std.os.linux.writev(state.sink, iov.ptr, iov.len);
    }
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

inline fn emit(level: std.log.Level, message: fmt.Message) void {
    emitParts(level, message.text, message.values);
}

fn emitParts(level: std.log.Level, text: []const u8, values: @FieldType(fmt.Message, "values")) void {
    if (state.sink < 0) return;

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

    const at = fmt.appendBytes(buf[0 .. buf.len - 1], 0, prefix);
    const remaining = buf[at .. buf.len - 1];
    const message: fmt.Message = .{ .text = text, .values = values };
    const length = at + message.render(remaining).len;
    buf[length] = '\n';

    switch (writeBestEffort(state.kind, state.sink, buf[0 .. length + 1])) {
        .complete, .dropped => {},
        .failed => deinit(),
    }
}

fn write(comptime level: std.log.Level, comptime format: []const u8, args: anytype) void {
    if (comptime aboveCeiling(level)) return;

    if (dropped(level)) return;

    // A literal needs no formatting buffer, and a single `{s}` is already the
    // text `emit` wants. Both are common enough to be worth the direct path.
    if (comptime @typeInfo(@TypeOf(args)).@"struct".field_names.len == 0) {
        emit(level, .literal(format));
        return;
    }

    if (comptime std.mem.eql(u8, format, "{s}")) {
        emit(level, .literal(args[0]));
        return;
    }

    emitFormatted(level, format, args);
}

fn emitFormatted(level: std.log.Level, comptime format: []const u8, args: anytype) void {
    const prepared = fmt.prepare(format, args);
    emit(level, prepared.message());
}

pub fn err(comptime format: []const u8, args: anytype) void {
    write(.err, format, args);
}

pub fn warn(comptime format: []const u8, args: anytype) void {
    write(.warn, format, args);
}

pub fn debug(comptime format: []const u8, args: anytype) void {
    write(.debug, format, args);
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

    var buf: [128]u8 = undefined;
    var at: usize = 0;
    const what: []const u8 = switch (role) {
        .main => "child process",
        .orphaned => "orphaned process",
    };

    at = fmt.appendBytes(&buf, at, what);
    at = fmt.appendBytes(&buf, at, " ");
    at = fmt.appendInt(&buf, at, @intCast(pid), .dec);
    at = fmt.appendBytes(&buf, at, " exited with ");
    const class = status.class();
    if (class == .unknown) {
        at = fmt.appendBytes(&buf, at, "unknown status");
    } else {
        at = fmt.appendBytes(&buf, at, if (class == .exited) "code " else "signal ");
        const value = if (class == .exited) status.exitCode() else status.signalNumber();
        at = fmt.appendInt(&buf, at, value, .dec);
        at = fmt.appendBytes(&buf, at, ".");
    }
    emit(level, .literal(buf[0..at]));
}
