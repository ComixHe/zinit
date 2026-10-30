// SPDX-FileCopyrightText: 2026 YuMing He <ComixHe1895@outlook.com>
//
// SPDX-License-Identifier: MIT

//! Text primitives: the byte search and decimal parser the argument and signal parsers share.

const std = @import("std");

/// Byte search without `std.mem`'s vectorized `findScalarPos`: every needle here is
/// one byte in a short string, not worth the SIMD machinery in binary size.
/// Inlined because every caller passes a literal needle: the inlined copy folds
/// the byte comparison to a constant instead of loading it from a parameter.
pub inline fn indexOfByte(text: []const u8, byte: u8) ?usize {
    for (text, 0..) |b, i| {
        if (b == byte) return i;
    }

    return null;
}

pub fn parseDecimal(comptime T: type, text: []const u8) error{ InvalidCharacter, Overflow }!T {
    const info = @typeInfo(T);
    if (info != .int or info.int.signedness != .unsigned) {
        @compileError("parseDecimal supports unsigned integers only");
    }

    if (text.len == 0) return error.InvalidCharacter;

    const Wide = @Int(.unsigned, @max(info.int.bits, 8));
    const max: Wide = std.math.maxInt(T);
    var value: Wide = 0;

    for (text) |byte| {
        if (byte < '0' or byte > '9') return error.InvalidCharacter;
        const digit: Wide = byte - '0';
        if (digit > max) return error.Overflow;
        if (value > (max - digit) / 10) return error.Overflow;
        value = value * 10 + digit;
    }

    return @intCast(value);
}

/// Without std.mem's vectorized machinery for binary size.
/// The right-hand sides are literals, so the length check
/// and the element loop fold into one fixed-size comparison.
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
                // A non-digit may follow an already-overflowing prefix. Both
                // InvalidCharacter and Overflow are valid rejection orders here.
                _ = parseDecimal(u64, bytes) catch |err| {
                    try std.testing.expect(err == error.InvalidCharacter or err == error.Overflow);
                    return;
                };

                return error.TestUnexpectedResult;
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

    return std.testing.fuzz(Context{}, Context.testOne, .{
        // `Smith.in` starts with a four-byte little-endian slice length.
        .corpus = &.{"\x15\x00\x00\x00" ++ "18446744073709551616x"},
    });
}

test "parseDecimal covers the width it advertises, including u1 and u128" {
    try std.testing.expectEqual(@as(u1, 1), try parseDecimal(u1, "1"));
    try std.testing.expectEqual(@as(u1, 0), try parseDecimal(u1, "0"));
    try std.testing.expectError(error.Overflow, parseDecimal(u1, "2"));

    // The accumulator is the target type, not a fixed u64.
    try std.testing.expectEqual(
        std.math.maxInt(u128),
        try parseDecimal(u128, "340282366920938463463374607431768211455"),
    );

    try std.testing.expectError(
        error.Overflow,
        parseDecimal(u128, "340282366920938463463374607431768211456"),
    );
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
