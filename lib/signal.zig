// SPDX-FileCopyrightText: 2026 YuMing He <ComixHe1895@outlook.com>
//
// SPDX-License-Identifier: MIT

//! Signal identity: the standard names and numbers, and what the command line accepts.

const std = @import("std");
const ConfigError = @import("errors.zig").ConfigError;
const str = @import("str.zig");

pub const Sig = std.os.linux.SIG;

/// `si_code` values the supervisor distinguishes.
/// https://github.com/torvalds/linux/blob/c339f4010dea8b0d754f84ace70cd1b089878ef8/include/uapi/asm-generic/siginfo.h#L174
pub const SI = struct {
    /// Sent by `kill`/`raise`: names a sender, carries no payload.
    pub const USER: i32 = 0;
    /// Sent by `rt_sigqueueinfo`/`sigqueue`: carries a value.
    pub const QUEUE: i32 = -1;
    /// Raised by the kernel itself (timer, terminal hangup): no sender.
    pub const KERNEL: i32 = 0x80;
};

/// One delivered signal, narrowed to what the supervisor acts on.
pub const Event = struct {
    signo: u32,
    code: i32,
    value: u64,
};

const standard_signal_max: u32 = std.os.linux.sigrtmin() - 1;

/// Names in numeric order with compile-time boundaries, avoiding a length scan at lookup.
const standard_names = blk: {
    var text: []const u8 = "";
    var offsets: [standard_signal_max + 1]u8 = undefined;
    offsets[0] = 0;

    for (1..standard_signal_max + 1) |number| {
        text = text ++ @tagName(@as(Sig, @fromBackingInt(@intCast(number))));
        offsets[number] = @intCast(text.len);
    }

    break :blk .{ .text = text, .offsets = offsets };
};

/// Case-insensitive against the uppercase table
fn lookupStandardSignal(name: []const u8) ?u32 {
    for (0..standard_signal_max) |i| {
        const candidate = standard_names.text[standard_names.offsets[i]..standard_names.offsets[i + 1]];
        if (std.ascii.eqlIgnoreCase(candidate, name)) return @intCast(i + 1);
    }

    return null;
}

pub inline fn isStandard(sig: u32) bool {
    return sig > 0 and sig <= standard_signal_max;
}

pub fn parse(text: []const u8) ConfigError!u32 {
    if (text.len == 0) return ConfigError.InvalidParams;

    if (text[0] >= '0' and text[0] <= '9') {
        const sig_num = str.parseDecimal(u32, text) catch return ConfigError.InvalidSignal;
        return if (isStandard(sig_num)) sig_num else ConfigError.InvalidSignal;
    }

    const name_to_check = if (std.ascii.startsWithIgnoreCase(text, "SIG"))
        text[3..]
    else
        text;

    if (name_to_check.len == 0 or name_to_check.len > 15) return ConfigError.InvalidSignal;

    // The table covers 1..=max, so a hit is standard by construction.
    return lookupStandardSignal(name_to_check) orelse ConfigError.InvalidSignal;
}

// kcov-exclude-tests (everything below is test-only).
test "parse accepts numbers and names, rejects realtime and junk" {
    for (1..std.os.linux.sigrtmin()) |number| {
        const sig: Sig = @fromBackingInt(@intCast(number));
        try std.testing.expectEqual(@as(u32, @intCast(number)), try parse(@tagName(sig)));
    }

    try std.testing.expectEqual(15, parse("15") catch unreachable);
    try std.testing.expectEqual(15, parse("SIGTERM") catch unreachable);
    try std.testing.expectEqual(15, parse("TERM") catch unreachable);
    try std.testing.expectEqual(15, try parse("sigterm"));
    try std.testing.expectEqual(15, try parse("tErM"));
    try std.testing.expectEqual(9, parse("SIGKILL") catch unreachable);

    try std.testing.expectError(ConfigError.InvalidSignal, parse("SIGRTMIN"));
    try std.testing.expectError(ConfigError.InvalidSignal, parse("SIGRTMIN+2"));
    try std.testing.expectError(ConfigError.InvalidSignal, parse("RTMAX-1"));
    try std.testing.expectError(ConfigError.InvalidSignal, parse("34"));
    try std.testing.expectError(ConfigError.InvalidSignal, parse("64"));
    try std.testing.expectError(ConfigError.InvalidSignal, parse("UNKNOWN"));
    try std.testing.expectError(ConfigError.InvalidSignal, parse("999"));
    try std.testing.expectError(ConfigError.InvalidSignal, parse("0"));
    try std.testing.expectError(ConfigError.InvalidParams, parse(""));
    try std.testing.expectError(ConfigError.InvalidSignal, parse("SIG"));
    try std.testing.expectError(ConfigError.InvalidSignal, parse("A"));
    const long_name = "SIG" ++ "AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA";
    try std.testing.expectError(ConfigError.InvalidSignal, parse(long_name));
}
