// SPDX-FileCopyrightText: 2026 YuMing He <ComixHe1895@outlook.com>
//
// SPDX-License-Identifier: MIT

//! Project-specific, allocation-free formatting: `{s}` byte slice, `{d}` unsigned
//! decimal, `{x}` unsigned lowercase hex, `{e}` Linux errno name or `errno N`.

const std = @import("std");
const fuzz_input = @import("fuzz_input.zig");
const checks = @import("checks.zig");

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
        const parsed = if (format[i] == '{')
            parsePlaceholder(format, i)
        else
            parseLiteral(format, i);

        pieces[n] = parsed.piece;
        n += 1;

        if (parsed.placeholder) placeholders += 1;
        i = parsed.next;
    }

    if (placeholders != argument_count) {
        @compileError("format placeholders and arguments differ in: " ++ format);
    }

    std.debug.assert(n <= pieces.len);
    return pieces[0..n];
}

const Parsed = struct {
    piece: Piece,
    next: usize,
    placeholder: bool = false,
};

fn parseLiteral(format: []const u8, start: usize) Parsed {
    var end = start;
    while (end < format.len and format[end] != '{') : (end += 1) {}
    return .{ .piece = .{ .literal = format[start..end] }, .next = end };
}

fn parsePlaceholder(format: []const u8, start: usize) Parsed {
    var end = start + 1;
    while (end < format.len and format[end] != '}') : (end += 1) {}
    if (end == format.len) @compileError("unclosed format placeholder in: " ++ format);

    const spec = format[start + 1 .. end];
    const kind: Piece = .{ .arg = if (std.mem.eql(u8, spec, "s"))
        .str
    else if (std.mem.eql(u8, spec, "d"))
        .dec
    else if (std.mem.eql(u8, spec, "x"))
        .hex
    else if (std.mem.eql(u8, spec, "e"))
        .errno
    else
        @compileError("unsupported format spec: {" ++ spec ++ "}") };

    return .{ .piece = kind, .next = end + 1, .placeholder = true };
}

pub fn bufPrint(buf: []u8, comptime format: []const u8, args: anytype) []u8 {
    const args_info = @typeInfo(@TypeOf(args));
    if (args_info != .@"struct" or !args_info.@"struct".is_tuple) {
        @compileError("fmt: expected argument tuple, found " ++ @typeName(@TypeOf(args)));
    }
    const pieces = comptime parse(format, args_info.@"struct".field_names.len);

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

    checks.check(at <= buf.len, "fmt: bufPrint position past the end of the buffer");
    return buf[0..at];
}

pub noinline fn appendBytes(buf: []u8, at: usize, bytes: []const u8) usize {
    checks.check(at <= buf.len, "fmt: appendBytes position past the end of the buffer");
    if (at >= buf.len) return at;

    const n = @min(bytes.len, buf.len - at);
    @memcpy(buf[at..][0..n], bytes[0..n]);
    const end = at + n;
    checks.check(end <= buf.len, "fmt: appendBytes end past the end of the buffer");
    return end;
}

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

pub fn appendErrno(buf: []u8, at: usize, errno: std.os.linux.E) usize {
    checks.check(at <= buf.len, "fmt: appendErrno position past the end of the buffer");
    if (at == buf.len) return at;
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

    const next = appendBytes(buf, at, "errno ");
    return appendInt(buf, next, number, .dec);
}

pub const Base = enum(u8) { dec = 10, hex = 16 };

pub fn appendInt(buf: []u8, at: usize, value: u64, base: Base) usize {
    checks.check(at <= buf.len, "fmt: appendInt position past the end of the buffer");
    if (at == buf.len) return at;
    const radix: u8 = @backingInt(base);
    const digits = "0123456789abcdef";
    var v: u64 = value;
    var tmp: [20]u8 = undefined;
    var index: usize = tmp.len;

    while (true) {
        index -= 1;
        tmp[index] = digits[@intCast(v % radix)];
        v /= radix;
        if (v == 0) break;
    }

    return appendBytes(buf, at, tmp[index..]);
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

    var cut: [3]u8 = undefined;
    try std.testing.expectEqualStrings("123", bufPrint(&cut, "{d}", .{12345}));

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
    const named = [_]std.os.linux.E{
        .PERM,   .NOENT, .SRCH,        .INTR,  .IO,    .NXIO,   .@"2BIG",
        .NOEXEC, .BADF,  .CHILD,       .AGAIN, .NOMEM, .ACCES,  .FAULT,
        .NOTDIR, .INVAL, .NFILE,       .MFILE, .NOTTY, .TXTBSY, .FBIG,
        .NOSPC,  .PIPE,  .NAMETOOLONG, .NOSYS, .LOOP,
    };

    for (named) |errno| {
        var expected_buf: [16]u8 = undefined;
        const expected = try std.mem.print(&expected_buf, "E{s}", .{@tagName(errno)});
        try expectErrnoPrefixes(errno, expected);
    }

    const unnamed = [_]std.os.linux.E{ .SUCCESS, .BUSY, @fromBackingInt(65535) };
    for (unnamed) |errno| {
        var expected_buf: [24]u8 = undefined;
        const expected = try std.mem.print(&expected_buf, "errno {d}", .{@backingInt(errno)});
        try expectErrnoPrefixes(errno, expected);
    }
}

test "appendInt preserves prefixes around decimal and hexadecimal digit boundaries" {
    for ([_]Base{ .dec, .hex }) |base| {
        const radix: u64 = @backingInt(base);
        var power: u64 = 1;
        while (true) {
            for ([_]u64{ power - 1, power, power + 1 }) |value| {
                try expectIntPrefixes(value, base);
            }
            if (power > std.math.maxInt(u64) / radix) break;
            power *= radix;
        }

        try expectIntPrefixes(std.math.maxInt(u64), base);
    }
}

test "append primitives never overrun, and truncate only at the buffer end" {
    const Context = struct {
        fn testOne(_: @This(), smith: *std.testing.Smith) anyerror!void {
            var buf: [24]u8 = undefined;

            const at = smith.index(buf.len + 1);
            var payload: [16]u8 = undefined;
            const payload_len: usize = smith.slice(&payload);

            @memset(&buf, 0xAA);
            const bytes_end = appendBytes(&buf, at, payload[0..payload_len]);
            const bytes_copied = @min(payload_len, buf.len - at);
            try std.testing.expectEqual(at + bytes_copied, bytes_end);
            try std.testing.expectEqualSlices(u8, payload[0..bytes_copied], buf[at..bytes_end]);
            try expectUntouched(&buf, at, bytes_end);

            const value = smith.value(u64);
            const base: Base = if (smith.value(bool)) .dec else .hex;
            var expected_buf: [20]u8 = undefined; // Enough for any u64 in either radix.
            const expected = if (base == .dec)
                try std.mem.print(&expected_buf, "{d}", .{value})
            else
                try std.mem.print(&expected_buf, "{x}", .{value});

            const int_at = smith.index(buf.len + 1);
            @memset(&buf, 0xAA);
            const int_end = appendInt(&buf, int_at, value, base);
            const int_copied = @min(expected.len, buf.len - int_at);
            try std.testing.expectEqual(int_at + int_copied, int_end);
            try std.testing.expectEqualStrings(expected[0..int_copied], buf[int_at..int_end]);
            try expectUntouched(&buf, int_at, int_end);

            const errno = smith.value(std.os.linux.E);
            var full_buf: [24]u8 = undefined;
            const full = full_buf[0..appendErrno(&full_buf, 0, errno)];
            try expectErrnoShape(full);

            const errno_at = smith.index(buf.len + 1);
            @memset(&buf, 0xAA);
            const errno_end = appendErrno(&buf, errno_at, errno);
            const errno_copied = @min(full.len, buf.len - errno_at);
            try std.testing.expectEqual(errno_at + errno_copied, errno_end);
            try std.testing.expectEqualStrings(full[0..errno_copied], buf[errno_at..errno_end]);
            try expectUntouched(&buf, errno_at, errno_end);
        }
    };

    return std.testing.fuzz(Context{}, Context.testOne, .{
        .corpus = &.{
            fuzz_input.slice("01234567"),
            fuzz_input.slice("\xff\xff\xff\xff\xff\xff\xff\xff\xff\xff\xff\xff\xff\xff\xff\xff"),
        },
    });
}

fn expectUntouched(buf: []const u8, at: usize, end: usize) !void {
    for (buf[0..at]) |byte| try std.testing.expectEqual(@as(u8, 0xAA), byte);
    for (buf[end..]) |byte| try std.testing.expectEqual(@as(u8, 0xAA), byte);
}

fn expectErrnoPrefixes(errno: std.os.linux.E, expected: []const u8) !void {
    const at = 3;
    for (0..expected.len + 2) |capacity| {
        var buf: [32]u8 = @splat(0xAA);
        const end = appendErrno(buf[0 .. at + capacity], at, errno);
        try std.testing.expectEqual(at + @min(capacity, expected.len), end);
        try std.testing.expectEqualStrings(expected[0 .. end - at], buf[at..end]);
        try expectUntouched(&buf, at, end);
    }
}

fn expectIntPrefixes(value: u64, base: Base) !void {
    var expected_buf: [20]u8 = undefined;
    const expected = if (base == .dec)
        try std.mem.print(&expected_buf, "{d}", .{value})
    else
        try std.mem.print(&expected_buf, "{x}", .{value});

    const at = 3;
    for (0..expected.len + 2) |capacity| {
        var buf: [32]u8 = @splat(0xAA);
        const end = appendInt(buf[0 .. at + capacity], at, value, base);
        try std.testing.expectEqual(at + @min(capacity, expected.len), end);
        try std.testing.expectEqualStrings(expected[0 .. end - at], buf[at..end]);
        try expectUntouched(&buf, at, end);
    }
}

fn expectErrnoShape(text: []const u8) !void {
    try std.testing.expect(text.len > 0);
    if (std.mem.startsWith(u8, text, "errno ")) return;

    try std.testing.expect(text[0] == 'E');
    for (text[1..]) |byte| {
        try std.testing.expect((byte >= 'A' and byte <= 'Z') or (byte >= '0' and byte <= '9'));
    }
}
