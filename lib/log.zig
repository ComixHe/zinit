// SPDX-FileCopyrightText: 2026 YuMing He <ComixHe1895@outlook.com>
//
// SPDX-License-Identifier: MIT

//! Minimal logger: no allocation, no `std.log`, one mutable global for sink and level.

const std = @import("std");
const checks = @import("checks.zig");
const builtin = @import("builtin");
const tty = @import("tty.zig");
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
    owned: bool = false,
    kind: SinkKind = .stream,
    level: std.log.Level = if (builtin.is_test) .warn else default_level,
    color: bool = false,
};

pub fn init(sink_fd: std.os.linux.fd_t) error{ InvalidSink, AlreadyInitialized }!void {
    if (sink_fd < 0) {
        @branchHint(.unlikely);
        return error.InvalidSink;
    }

    if (state.sink >= 0) {
        @branchHint(.unlikely);
        return error.AlreadyInitialized;
    }

    var metadata: std.os.linux.Statx = undefined;
    if (io.syscallErrno(std.os.linux.statx(
        sink_fd,
        "",
        std.os.linux.AT.EMPTY_PATH | std.os.linux.AT.STATX_DONT_SYNC,
        .{ .TYPE = true },
        &metadata,
    )) != .SUCCESS or !metadata.mask.TYPE) {
        @branchHint(.unlikely);
        return;
    }

    const kind: SinkKind = switch (metadata.mode & std.os.linux.S.IFMT) {
        std.os.linux.S.IFIFO, std.os.linux.S.IFCHR => .nonblocking,
        std.os.linux.S.IFSOCK => .socket,
        std.os.linux.S.IFREG => .stream,
        else => return,
    };

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
        .color = tty.isTty(fd),
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

fn writeSink(kind: SinkKind, fd: std.os.linux.fd_t, bytes: []const u8) ?std.os.linux.E {
    if (kind == .stream) return io.writeAll(fd, bytes);

    while (true) {
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

        switch (io.syscallErrno(rc)) {
            .INTR => continue,
            .SUCCESS, .AGAIN => return null,
            else => |errno| return errno,
        }
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

fn emit(level: std.log.Level, msg: []const u8) void {
    if (state.sink < 0) return; // disabled logging if sink is closed or not available.

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

    const text = fmt.bufPrint(buf[0 .. buf.len - 1], "{s}{s}", .{ prefix, msg });
    buf[text.len] = '\n';

    if (writeSink(state.kind, state.sink, buf[0 .. text.len + 1])) |errno| {
        if (errno == .PIPE or errno == .IO or errno == .CONNRESET) deinit();
    }
}

fn write(comptime level: std.log.Level, comptime format: []const u8, args: anytype) void {
    if (comptime aboveCeiling(level)) return;

    if (dropped(level)) return;

    // A literal needs no formatting buffer, and a single `{s}` is already the
    // text `emit` wants. Both are common enough to be worth the direct path.
    if (comptime @typeInfo(@TypeOf(args)).@"struct".field_names.len == 0) {
        emit(level, format);
        return;
    }

    if (comptime std.mem.eql(u8, format, "{s}")) {
        emit(level, args[0]);
        return;
    }

    var buf: [512]u8 = undefined;
    const msg = fmt.bufPrint(&buf, format, args);
    emit(level, msg);
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

const ExitReport = struct {
    role: Role,
    pid: std.os.linux.pid_t,
    outcome: union(enum) {
        exited: u8,
        signaled: u32,
        unknown,
    },
};

fn exitReport(pid: std.os.linux.pid_t, status: WaitStatus, role: Role) ExitReport {
    return .{
        .role = role,
        .pid = pid,
        .outcome = switch (status.class()) {
            .exited => .{ .exited = status.exitCode() },
            .signaled => .{ .signaled = status.signalNumber() },
            .unknown => .unknown,
        },
    };
}

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
    emit(level, formatExited(&buf, exitReport(pid, status, role)));
}

fn formatExited(buf: []u8, report: ExitReport) []const u8 {
    const what: []const u8 = switch (report.role) {
        .main => "child process",
        .orphaned => "orphaned process",
    };

    var at: usize = 0;
    at = fmt.appendBytes(buf, at, what);
    at = fmt.appendBytes(buf, at, " ");
    at = fmt.appendInt(buf, at, @intCast(report.pid), .dec);
    at = fmt.appendBytes(buf, at, " exited with ");

    switch (report.outcome) {
        .exited => |code| {
            at = fmt.appendBytes(buf, at, "code ");
            at = fmt.appendInt(buf, at, code, .dec);
            at = fmt.appendBytes(buf, at, ".");
        },
        .signaled => |sig| {
            at = fmt.appendBytes(buf, at, "signal ");
            at = fmt.appendInt(buf, at, sig, .dec);
            at = fmt.appendBytes(buf, at, ".");
        },
        .unknown => at = fmt.appendBytes(buf, at, "unknown status"),
    }

    return buf[0..at];
}
