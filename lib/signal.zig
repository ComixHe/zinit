// SPDX-FileCopyrightText: 2026 YuMing He <ComixHe1895@outlook.com>
//
// SPDX-License-Identifier: MIT

//! Signal identity: the standard names and numbers, and what the command line accepts.

const std = @import("std");
const checks = @import("checks.zig");
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
    sender: std.os.linux.pid_t = 0,
};

pub fn queueInfo(signo: u32, value: u64) std.os.linux.siginfo_t {
    checks.check(signo > 0, "signal: queueInfo needs a positive signal number");
    checks.check(signo < std.os.linux.NSIG, "signal: queueInfo signal number out of range");

    var info = std.mem.zeroes(std.os.linux.siginfo_t);
    info.signo = @fromBackingInt(@intCast(signo));
    info.code = SI.QUEUE;
    info.fields.common.first.piduid.pid = @intCast(std.os.linux.getpid());
    info.fields.common.first.piduid.uid = @intCast(std.os.linux.getuid());

    if (value == 0) {
        info.fields.common.second.value.int = 0;
    } else {
        info.fields.common.second.value.ptr = @ptrFromInt(value);
    }

    return info;
}

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
        const start = standard_names.offsets[i];
        const end = standard_names.offsets[i + 1];
        const candidate = standard_names.text[start..end];
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
        if (!isStandard(sig_num)) return ConfigError.InvalidSignal;
        return sig_num;
    }

    const name_to_check = if (std.ascii.startsWithIgnoreCase(text, "SIG"))
        text[3..]
    else
        text;

    if (name_to_check.len == 0 or name_to_check.len > 15) return ConfigError.InvalidSignal;

    // The table covers 1..=max, so a hit is standard by construction.
    return lookupStandardSignal(name_to_check) orelse return ConfigError.InvalidSignal;
}
