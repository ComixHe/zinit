// SPDX-FileCopyrightText: 2026 YuMing He <ComixHe1895@outlook.com>
//
// SPDX-License-Identifier: MIT

//! Text primitives: the byte search and decimal parser the argument and signal parsers share.

const std = @import("std");

/// Byte search without `std.mem`'s vectorized `findScalarPos`: every needle here is
/// one byte in a short string, not worth the SIMD machinery in binary size.
pub fn indexOfByte(text: []const u8, byte: u8) ?usize {
    for (text, 0..) |b, i| {
        if (b == byte) return i;
    }

    return null;
}

pub fn parseDecimal(comptime T: type, text: []const u8) error{ InvalidCharacter, Overflow }!T {
    if (text.len == 0) return error.InvalidCharacter;

    const max: u64 = std.math.maxInt(T);
    var value: u64 = 0;

    for (text) |byte| {
        if (byte < '0' or byte > '9') return error.InvalidCharacter;
        const digit: u64 = byte - '0';
        if (value > (max - digit) / 10) return error.Overflow;
        value = value * 10 + digit;
    }

    return @intCast(value);
}

/// Inline because most call sites compare against a literal, which folds the length check
/// and the compares away. `std.mem.eql` is a vectorized function several times this size.
pub inline fn eql(a: []const u8, b: []const u8) bool {
    if (a.len != b.len) return false;
    for (a, b) |x, y| {
        if (x != y) return false;
    }

    return true;
}

// kcov-exclude-tests (everything below is test-only).
test "parseDecimal agrees with std on arbitrary bytes, and never panics" {
    const Context = struct {
        fn testOne(_: @This(), smith: *std.testing.Smith) anyerror!void {
            var buf: [40]u8 = undefined;
            const bytes = buf[0..smith.slice(&buf)];

            const digits = for (bytes) |byte| {
                if (byte < '0' or byte > '9') break false;
            } else bytes.len > 0;

            if (!digits) {
                try std.testing.expectError(error.InvalidCharacter, parseDecimal(u64, bytes));
                return;
            }

            const expected = std.fmt.parseInt(u64, bytes, 10) catch |err| switch (err) {
                error.Overflow => {
                    try std.testing.expectError(error.Overflow, parseDecimal(u64, bytes));
                    return;
                },
                else => return err,
            };

            try std.testing.expectEqual(expected, try parseDecimal(u64, bytes));
        }
    };

    return std.testing.fuzz(Context{}, Context.testOne, .{});
}

test "parseDecimal rejects an overflow before the accumulator wraps" {
    // The u64 boundary and one past it: the overflow must be reported, not wrapped.
    try std.testing.expectEqual(
        std.math.maxInt(u64),
        try parseDecimal(u64, "18446744073709551615"),
    );

    try std.testing.expectError(error.Overflow, parseDecimal(u64, "18446744073709551616"));
    try std.testing.expectError(error.Overflow, parseDecimal(u64, "99999999999999999999"));
    try std.testing.expectError(error.Overflow, parseDecimal(u64, "999999999999999999999999999999"));

    try std.testing.expectEqual(@as(u8, 255), try parseDecimal(u8, "255"));
    try std.testing.expectError(error.Overflow, parseDecimal(u8, "256"));
    try std.testing.expectEqual(@as(u32, 31), try parseDecimal(u32, "31"));

    try std.testing.expectError(error.InvalidCharacter, parseDecimal(u64, ""));
    try std.testing.expectError(error.InvalidCharacter, parseDecimal(u64, "12a"));
}
