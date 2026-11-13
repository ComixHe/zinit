// SPDX-FileCopyrightText: 2026 YuMing He <ComixHe1895@outlook.com>
//
// SPDX-License-Identifier: MIT

//! The `-r` table: which forwarded signal becomes which, and why a rewrite is refused.

const std = @import("std");
const fuzz_input = @import("fuzz_input.zig");
const checks = @import("checks.zig");

const errors = @import("errors.zig");
const signal = @import("signal.zig");
const str = @import("str.zig");

const ConfigError = errors.ConfigError;

pub const Map = struct {
    /// No rewrite defined; `0` is a real value and means "drop the signal".
    const unset: u32 = std.math.maxInt(u32);

    entries: [std.os.linux.NSIG]u32,

    pub fn init() Map {
        return .{ .entries = @splat(unset) };
    }

    /// `null` = no rewrite, `0` = drop, otherwise the validated target signal.
    pub fn target(self: *const Map, sig: u32) ConfigError!?u32 {
        if (sig >= self.entries.len) {
            @branchHint(.unlikely);
            return ConfigError.InvalidSignal;
        }

        const stored = self.entries[sig];
        return if (stored == unset) null else stored;
    }

    pub fn set(self: *Map, old_sig: u32, new_sig: u32) ConfigError!void {
        if (old_sig >= self.entries.len or new_sig >= self.entries.len) {
            @branchHint(.unlikely);
            return ConfigError.InvalidSignal;
        }

        self.entries[old_sig] = new_sig;
    }

    /// Inlined so `target` and the error union are resolved against the one
    /// caller instead of through a call boundary.
    pub inline fn apply(rewrites: *const Map, signo: u32) ConfigError!u32 {
        checks.check(signo > 0, "rewrite: apply needs a positive signal number");
        checks.check(signo < std.os.linux.NSIG, "rewrite: apply signal number out of range");
        return if (try rewrites.target(signo)) |rewritten| rewritten else signo;
    }

    pub fn parse(self: *Map, value: []const u8) ConfigError!void {
        const sep = str.indexOfByte(value, ':') orelse return ConfigError.InvalidRewrite;
        const old = value[0..sep];
        const old_sig = try signal.parse(old);

        // These can never reach the forwarder: KILL/STOP cannot be blocked or
        // observed, and SIGCHLD is consumed by the reaper.
        if (old_sig == @backingInt(signal.Sig.KILL) or
            old_sig == @backingInt(signal.Sig.STOP) or
            old_sig == @backingInt(signal.Sig.CHLD))
        {
            @branchHint(.cold);
            return ConfigError.InvalidRewrite;
        }

        const rest = value[sep + 1 ..];
        if (str.indexOfByte(rest, ':') != null) {
            @branchHint(.cold);
            return ConfigError.InvalidRewrite;
        }

        const new_sig = try parseTarget(rest);

        if (old_sig == new_sig) {
            @branchHint(.cold);
            return ConfigError.DuplicateSignal;
        }

        if (new_sig != 0 and (self.reaches(new_sig, old_sig) catch unreachable)) {
            @branchHint(.cold);
            return ConfigError.CycleRewrite;
        }

        if ((self.target(old_sig) catch unreachable) != null) {
            @branchHint(.cold);
            return ConfigError.DuplicateSignal;
        }

        self.set(old_sig, new_sig) catch unreachable;
        checks.check((self.target(old_sig) catch unreachable) == new_sig, "rewrite: stored target does not read back");
    }

    /// Not a plain reachability query: an existing cycle also counts, so `parse`
    /// refuses closing a loop it did not create.
    fn reaches(self: *const Map, from: u32, to: u32) ConfigError!bool {
        if (from == 0 or from >= self.entries.len) {
            @branchHint(.unlikely);
            return ConfigError.InvalidParams;
        }

        var current = from;
        var steps: usize = 0;
        while (self.target(current) catch unreachable) |next_node| {
            if (next_node == to) return true;
            if (next_node == 0) return false;

            steps += 1;
            if (steps >= std.os.linux.NSIG) return true;

            current = next_node;
        }

        return false;
    }

    fn parseTarget(text: []const u8) ConfigError!u32 {
        if (str.eql(text, "0")) return 0;
        return signal.parse(text);
    }
};

test "Map stays acyclic and atomic over arbitrary rewrite sequences" {
    const Context = struct {
        fn testOne(_: @This(), smith: *std.testing.Smith) anyerror!void {
            var buf: [256]u8 = undefined;
            const n: usize = smith.slice(&buf);
            var rest: []const u8 = buf[0..n];

            var map: Map = .init();
            while (rest.len > 0) {
                const end = str.indexOfByte(rest, 0) orelse rest.len;
                const record = rest[0..end];
                rest = if (end < rest.len) rest[end + 1 ..] else rest[0..0];

                const before = map;
                if (map.parse(record)) |_| {
                    try expectAcyclic(map);
                } else |_| {
                    try expectSameTargets(before, map);
                }
            }

            try expectApplyMatchesTargets(map);
        }
    };

    return std.testing.fuzz(Context{}, Context.testOne, .{
        .corpus = &.{
            fuzz_input.slice("TERM:INT"),
            fuzz_input.slice("INT:HUP"),
            fuzz_input.slice("HUP:0"),
            fuzz_input.slice("TERM:9"),
            fuzz_input.slice("9:TERM"),
            fuzz_input.slice("TERM:INT\x00INT:HUP\x00HUP:0"),
            fuzz_input.slice("USR1:USR2\x00USR2:TERM"),
            fuzz_input.slice(":"),
            fuzz_input.slice("TERM:"),
            fuzz_input.slice(":INT"),
            fuzz_input.slice("TERM:INTRA"),
            fuzz_input.slice("0:INT"),
            fuzz_input.slice("TERM:INT\x00INT:TERM"),
            fuzz_input.slice("INT:INT"),
            fuzz_input.slice("term:int"),
            fuzz_input.slice("TSTP:STOP:EXTRA"),
            fuzz_input.slice("TERM:0\x00INT:HUP"),
        },
    });
}

fn expectAcyclic(map: Map) !void {
    var start: u32 = 1;
    while (start < std.os.linux.NSIG) : (start += 1) {
        if (try map.target(start) == null) continue;

        var seen: std.bit_set.Static(std.os.linux.NSIG) = .empty;
        seen.set(start);
        var current = start;
        while (try map.target(current)) |next| {
            if (next == 0) break;
            if (!signal.isStandard(next)) return error.RewriteTargetOutOfDomain;
            if (seen.isSet(next)) return error.RewriteCycle;
            seen.set(next);
            current = next;
        }
    }
}

/// `apply` must be exactly `target` with an identity fallback, for every signal.
fn expectApplyMatchesTargets(map: Map) !void {
    var sig: u32 = 1;
    while (sig < std.os.linux.NSIG) : (sig += 1) {
        const target = try map.target(sig);
        try std.testing.expectEqual(target orelse sig, try Map.apply(&map, sig));
    }
}

/// A rejected record must leave the public mapping unchanged. Compare targets,
/// not the backing array: a different representation with the same behavior is valid.
fn expectSameTargets(before: Map, after: Map) !void {
    var sig: u32 = 1;
    while (sig < std.os.linux.NSIG) : (sig += 1) {
        try std.testing.expectEqual(before.target(sig), after.target(sig));
    }
}
