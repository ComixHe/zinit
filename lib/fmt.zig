// SPDX-FileCopyrightText: 2026 YuMing He <ComixHe1895@outlook.com>
//
// SPDX-License-Identifier: MIT

//! Compile-time formatting for a deliberately small subset: `{s}` string, `{d}`
//! unsigned decimal, `{x}` unsigned hex, `{e}` errno name. There is no width,
//! alignment, sign or escape form; output is truncated at the end of the buffer.
//! Placeholder count is checked against the argument tuple at compile time, and an
//! unclosed `{` is a compile error rather than an index-out-of-bounds in the parser.

const std = @import("std");

const Piece = union(enum) {
    literal: []const u8,
    arg: enum { str, dec, hex, errno },
};

fn parse(format: []const u8, argument_count: usize) []const Piece {
    @setEvalBranchQuota(10_000);

    var pieces: [format.len]Piece = undefined;
    var n: usize = 0;
    var i: usize = 0;
    var placeholders: usize = 0;

    while (i < format.len) {
        if (format[i] != '{') {
            var j = i;
            while (j < format.len and format[j] != '{') : (j += 1) {}
            pieces[n] = .{ .literal = format[i..j] };
            n += 1;
            i = j;
        } else {
            var j = i + 1;
            while (j < format.len and format[j] != '}') : (j += 1) {}
            if (j == format.len) @compileError("unclosed format placeholder in: " ++ format);
            const spec = format[i + 1 .. j];

            pieces[n] = .{ .arg = if (std.mem.eql(u8, spec, "s"))
                .str
            else if (std.mem.eql(u8, spec, "d"))
                .dec
            else if (std.mem.eql(u8, spec, "x"))
                .hex
            else if (std.mem.eql(u8, spec, "e"))
                .errno
            else
                @compileError("unsupported format spec: {" ++ spec ++ "}") };

            placeholders += 1;
            n += 1;
            i = j + 1;
        }
    }

    if (placeholders != argument_count) {
        @compileError("format placeholders and arguments differ in: " ++ format);
    }

    return pieces[0..n];
}

pub fn bufPrint(buf: []u8, comptime format: []const u8, args: anytype) []u8 {
    const pieces = comptime parse(format, @typeInfo(@TypeOf(args)).@"struct".field_names.len);

    var at: usize = 0;
    comptime var arg_i: usize = 0;

    inline for (pieces) |piece| {
        switch (piece) {
            .literal => |lit| at = appendBytes(buf, at, lit),
            .arg => |kind| {
                at = switch (kind) {
                    .str => appendBytes(buf, at, args[arg_i]),
                    .dec => appendInt(buf, at, args[arg_i], .dec),
                    .hex => appendInt(buf, at, args[arg_i], .hex),
                    .errno => appendErrno(buf, at, args[arg_i]),
                };

                arg_i += 1;
            },
        }
    }

    return buf[0..at];
}

pub fn appendBytes(buf: []u8, at: usize, bytes: []const u8) usize {
    if (at >= buf.len) return at;

    const n = @min(bytes.len, buf.len - at);
    @memcpy(buf[at..][0..n], bytes[0..n]);
    return at + n;
}

/// A NUL-separated blob plus a per-number offset: a `switch` or `@tagName` over this
/// sparse enum costs several times more.
const errno_lookup = blk: {
    const entries = [_]struct { number: u32, text: []const u8 }{
        .{ .number = @backingInt(std.os.linux.E.PERM), .text = "EPERM" },
        .{ .number = @backingInt(std.os.linux.E.NOENT), .text = "ENOENT" },
        .{ .number = @backingInt(std.os.linux.E.SRCH), .text = "ESRCH" },
        .{ .number = @backingInt(std.os.linux.E.INTR), .text = "EINTR" },
        .{ .number = @backingInt(std.os.linux.E.IO), .text = "EIO" },
        .{ .number = @backingInt(std.os.linux.E.NXIO), .text = "ENXIO" },
        .{ .number = @backingInt(std.os.linux.E.@"2BIG"), .text = "E2BIG" },
        .{ .number = @backingInt(std.os.linux.E.NOEXEC), .text = "ENOEXEC" },
        .{ .number = @backingInt(std.os.linux.E.BADF), .text = "EBADF" },
        .{ .number = @backingInt(std.os.linux.E.CHILD), .text = "ECHILD" },
        .{ .number = @backingInt(std.os.linux.E.AGAIN), .text = "EAGAIN" },
        .{ .number = @backingInt(std.os.linux.E.NOMEM), .text = "ENOMEM" },
        .{ .number = @backingInt(std.os.linux.E.ACCES), .text = "EACCES" },
        .{ .number = @backingInt(std.os.linux.E.FAULT), .text = "EFAULT" },
        .{ .number = @backingInt(std.os.linux.E.NOTDIR), .text = "ENOTDIR" },
        .{ .number = @backingInt(std.os.linux.E.INVAL), .text = "EINVAL" },
        .{ .number = @backingInt(std.os.linux.E.NFILE), .text = "ENFILE" },
        .{ .number = @backingInt(std.os.linux.E.MFILE), .text = "EMFILE" },
        .{ .number = @backingInt(std.os.linux.E.NOTTY), .text = "ENOTTY" },
        .{ .number = @backingInt(std.os.linux.E.TXTBSY), .text = "ETXTBSY" },
        .{ .number = @backingInt(std.os.linux.E.FBIG), .text = "EFBIG" },
        .{ .number = @backingInt(std.os.linux.E.NOSPC), .text = "ENOSPC" },
        .{ .number = @backingInt(std.os.linux.E.PIPE), .text = "EPIPE" },
        .{ .number = @backingInt(std.os.linux.E.NAMETOOLONG), .text = "ENAMETOOLONG" },
        .{ .number = @backingInt(std.os.linux.E.NOSYS), .text = "ENOSYS" },
        .{ .number = @backingInt(std.os.linux.E.LOOP), .text = "ELOOP" },
    };

    var widest: u32 = 0;
    for (entries) |e| widest = @max(widest, e.number);

    var offsets: [widest + 1]u8 = @splat(0);
    var names: []const u8 = "";
    for (entries) |e| {
        offsets[e.number] = @intCast(names.len + 1);
        names = names ++ e.text ++ "\x00";
    }

    break :blk .{ .offsets = offsets, .names = names };
};

/// The short name, or `errno <n>`, written straight into `buf`. One body for every
/// `{e}` site: each would otherwise carry its own copy of the scan.
pub fn appendErrno(buf: []u8, at: usize, errno: std.os.linux.E) usize {
    const number = @backingInt(errno);
    if (number < errno_lookup.offsets.len) {
        const start = errno_lookup.offsets[number];
        if (start != 0) {
            const text = errno_lookup.names[start - 1 ..];
            var len: usize = 0;
            while (text[len] != 0) : (len += 1) {}
            return appendBytes(buf, at, text[0..len]);
        }
    }

    var scratch: [24]u8 = undefined;
    return appendBytes(buf, at, bufPrint(&scratch, "errno {d}", .{number}));
}

/// The radices the formatter emits. An enum rather than a `u8`: `0` divides by
/// zero, `1` never converges, and anything above 16 indexes past `digits`.
pub const Base = enum(u8) { dec = 10, hex = 16 };

pub fn appendInt(buf: []u8, at: usize, value: u64, base: Base) usize {
    const radix: u8 = @backingInt(base);
    const digits = "0123456789abcdef";
    var v: u64 = value;
    var tmp: [20]u8 = undefined;
    var n: usize = 0;

    if (v == 0) {
        tmp[0] = '0';
        n = 1;
    } else {
        while (v != 0) : (v /= radix) {
            tmp[n] = digits[@intCast(v % radix)];
            n += 1;
        }
    }

    var written: usize = 0;
    while (written < n and at + written < buf.len) : (written += 1) {
        buf[at + written] = tmp[n - 1 - written];
    }

    return at + written;
}

// kcov-exclude-tests (everything below is test-only).
test "bufPrint renders strings, decimals and hex, and truncates rather than overruns" {
    // The expectation comes from std's formatter, so the two are cross-checked.
    var expected_buf: [16]u8 = undefined;
    const expected = try std.mem.print(&expected_buf, "{s} {d} {x}", .{ "a", 42, 255 });

    var buf: [16]u8 = undefined;
    try std.testing.expectEqualStrings(expected, bufPrint(&buf, "{s} {d} {x}", .{ "a", 42, 255 }));

    var tiny: [2]u8 = undefined;
    try std.testing.expectEqualStrings("a ", bufPrint(&tiny, "{s} {d}", .{ "a", 42 }));

    var zero_buf: [4]u8 = undefined;
    try std.testing.expectEqualStrings("0", bufPrint(&zero_buf, "{d}", .{0}));

    // A number cut mid-way keeps the leading digits, in order.
    var cut: [3]u8 = undefined;
    try std.testing.expectEqualStrings("123", bufPrint(&cut, "{d}", .{12345}));

    // `{e}` is the errno's short name, so no caller needs its own appender.
    var errno_buf: [16]u8 = undefined;
    try std.testing.expectEqualStrings("failed: ENOENT", bufPrint(&errno_buf, "failed: {e}", .{.NOENT}));
}

test "bufPrint handles an empty buffer and the largest integers" {
    var empty: [0]u8 = .{};
    try std.testing.expectEqualStrings("", bufPrint(&empty, "{d}", .{std.math.maxInt(u64)}));

    var buf: [20]u8 = undefined;

    try std.testing.expectEqualStrings(
        "18446744073709551615",
        bufPrint(&buf, "{d}", .{std.math.maxInt(u64)}),
    );

    try std.testing.expectEqualStrings(
        "ffffffffffffffff",
        bufPrint(&buf, "{x}", .{std.math.maxInt(u64)}),
    );
}

test "appendErrno names the common errnos and falls back to a number" {
    var buf: [32]u8 = undefined;
    try std.testing.expectEqualStrings("ENOENT", buf[0..appendErrno(&buf, 0, .NOENT)]);
    try std.testing.expectEqualStrings("EAGAIN", buf[0..appendErrno(&buf, 0, .AGAIN)]);

    const unknown: std.os.linux.E = @fromBackingInt(65535);
    var expected_buf: [24]u8 = undefined;
    const expected = try std.mem.print(&expected_buf, "errno {d}", .{@backingInt(unknown)});
    try std.testing.expectEqualStrings(expected, buf[0..appendErrno(&buf, 0, unknown)]);
}
