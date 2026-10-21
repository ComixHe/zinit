// SPDX-FileCopyrightText: 2026 YuMing He <ComixHe1895@outlook.com>
//
// SPDX-License-Identifier: MIT

//! Signal identity: the standard names and numbers, and what the command line accepts.

const std = @import("std");

const errors = @import("errors.zig");
const str = @import("str.zig");

const ZinitError = errors.ZinitError;

pub const Sig = std.os.linux.SIG;

/// Standard signals are 1..=31; realtime ones start at 32 and are deliberately not supported.
const standard_signal_max: u32 = std.os.linux.sigrtmin() - 1;

/// NUL-separated in numeric order, so the position is the number minus one; plain `.rodata`.
const standard_names: []const u8 = blk: {
    var all: []const u8 = "";
    var number: u32 = 1;
    while (number <= standard_signal_max) : (number += 1) {
        all = all ++ @tagName(@as(Sig, @fromBackingInt(@intCast(number)))) ++ "\x00";
    }

    break :blk all;
};

/// Case-insensitive against the uppercase table, with no copy and no second pass.
fn lookupStandardSignal(name: []const u8) ?u32 {
    var number: u32 = 1;
    var rest = standard_names;
    while (rest.len > 0) : (number += 1) {
        const end = str.indexOfByte(rest, 0) orelse rest.len;
        const candidate = rest[0..end];
        if (candidate.len == name.len) {
            var same = true;
            for (candidate, name) |upper, given| {
                if (std.ascii.toUpper(given) != upper) {
                    same = false;
                    break;
                }
            }
            if (same) return number;
        }

        rest = rest[end + 1 ..];
    }

    return null;
}

pub fn isStandard(sig: u32) bool {
    return sig > 0 and sig <= standard_signal_max;
}

pub fn parse(text: []const u8) !u32 {
    if (text.len == 0) return ZinitError.InvalidParams;

    if (text[0] >= '0' and text[0] <= '9') {
        if (str.parseDecimal(u32, text)) |sig_num| {
            if (isStandard(sig_num)) return sig_num;
            return ZinitError.InvalidSignal;
        } else |_| return ZinitError.InvalidSignal;
    }

    const name_to_check = if (std.ascii.startsWithIgnoreCase(text, "SIG"))
        text[3..]
    else
        text;

    if (name_to_check.len == 0 or name_to_check.len > 15) return ZinitError.InvalidSignal;

    // The table covers 1..=max, so a hit is standard by construction.
    return lookupStandardSignal(name_to_check) orelse ZinitError.InvalidSignal;
}

// kcov-exclude-tests (everything below is test-only).
test "parse accepts numbers and names, rejects realtime and junk" {
    try std.testing.expectEqual(15, parse("15") catch unreachable);
    try std.testing.expectEqual(15, parse("SIGTERM") catch unreachable);
    try std.testing.expectEqual(15, parse("TERM") catch unreachable);
    try std.testing.expectEqual(9, parse("SIGKILL") catch unreachable);

    try std.testing.expectError(ZinitError.InvalidSignal, parse("SIGRTMIN"));
    try std.testing.expectError(ZinitError.InvalidSignal, parse("SIGRTMIN+2"));
    try std.testing.expectError(ZinitError.InvalidSignal, parse("RTMAX-1"));
    try std.testing.expectError(ZinitError.InvalidSignal, parse("34"));
    try std.testing.expectError(ZinitError.InvalidSignal, parse("64"));
    try std.testing.expectError(ZinitError.InvalidSignal, parse("UNKNOWN"));
    try std.testing.expectError(ZinitError.InvalidSignal, parse("999"));
    try std.testing.expectError(ZinitError.InvalidSignal, parse("0"));
    try std.testing.expectError(ZinitError.InvalidParams, parse(""));
    try std.testing.expectError(ZinitError.InvalidSignal, parse("SIG"));
    try std.testing.expectError(ZinitError.InvalidSignal, parse("A"));
    const long_name = "SIG" ++ "AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA";
    try std.testing.expectError(ZinitError.InvalidSignal, parse(long_name));
}
