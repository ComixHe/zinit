// SPDX-FileCopyrightText: 2026 YuMing He <ComixHe1895@outlook.com>
//
// SPDX-License-Identifier: MIT

//! The `-r` table: which forwarded signal becomes which, and why a rewrite is refused.

const std = @import("std");

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

    pub fn reset(self: *Map) void {
        self.entries = @splat(unset);
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
            @branchHint(.unlikely);
            return ConfigError.InvalidRewrite;
        }

        const rest = value[sep + 1 ..];
        if (str.indexOfByte(rest, ':') != null) {
            @branchHint(.unlikely);
            return ConfigError.InvalidRewrite;
        }

        const new_sig = try parseTarget(rest);

        if (old_sig == new_sig) {
            @branchHint(.unlikely);
            return ConfigError.DuplicateSignal;
        }

        if (new_sig != 0 and (self.reaches(new_sig, old_sig) catch unreachable)) {
            @branchHint(.unlikely);
            return ConfigError.CycleRewrite;
        }

        if ((self.target(old_sig) catch unreachable) != null) {
            @branchHint(.unlikely);
            return ConfigError.DuplicateSignal;
        }

        self.set(old_sig, new_sig) catch unreachable;
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

    fn parseTarget(text: []const u8) !u32 {
        if (str.eql(text, "0")) return 0;
        return signal.parse(text);
    }
};

// kcov-exclude-tests (everything below is test-only).
test "Map.set rejects out-of-range signals without changing the mapping" {
    var map: Map = .init();
    try map.set(15, 2);
    const before = map;

    const invalid = [_][2]u32{
        .{ std.os.linux.NSIG, 15 },
        .{ std.math.maxInt(u32), 15 },
        .{ 15, std.os.linux.NSIG },
        .{ 15, std.math.maxInt(u32) },
    };

    for (invalid) |pair| {
        try std.testing.expectError(ConfigError.InvalidSignal, map.set(pair[0], pair[1]));
        try expectSameTargets(before, map);
    }

    const last = std.os.linux.NSIG - 1;
    try map.set(last, last);
    try std.testing.expectEqual(@as(?u32, last), try map.target(last));
}

test "Map.parse accepts a mapping and rejects malformed rewrites" {
    var map: Map = .init();
    try map.parse("TERM:INT");
    try std.testing.expectEqual(@as(?u32, 2), try map.target(15));

    var emap: Map = .init();
    try std.testing.expectError(ConfigError.InvalidRewrite, emap.parse("TERM"));
    try std.testing.expectError(ConfigError.InvalidSignal, emap.parse("TERM:BAD"));
    try std.testing.expectError(ConfigError.InvalidRewrite, emap.parse("TERM:INT:EXTRA"));
}

test "Map.parse rejects self rewrites and duplicate sources" {
    var emap: Map = .init();
    try std.testing.expectError(ConfigError.DuplicateSignal, emap.parse("TERM:TERM"));
    try emap.parse("TERM:INT");
    try std.testing.expectError(ConfigError.DuplicateSignal, emap.parse("TERM:HUP"));
}

test "Map.parse rejects closing cycles, including directly constructed graphs" {
    var emap: Map = .init();
    try emap.set(1, 2);
    try emap.set(2, 9);
    try emap.set(9, 1);
    try std.testing.expectError(ConfigError.CycleRewrite, emap.parse("TERM:1"));

    // A two-node cycle is caught on the closing edge, not only on a later probe.
    var cmap: Map = .init();
    try cmap.parse("TERM:INT");
    try std.testing.expectError(ConfigError.CycleRewrite, cmap.parse("INT:TERM"));

    // The closing edge may be "hidden" behind a longer chain: A->B->C, add C->A.
    var lmap: Map = .init();
    try lmap.parse("TERM:INT");
    try lmap.parse("INT:HUP");
    try std.testing.expectError(ConfigError.CycleRewrite, lmap.parse("HUP:TERM"));
}

test "Map.parse accepts a drop target but refuses zero as a source" {
    // To 0 is terminal, never a cycle, and not accepted as a source.
    var dmap: Map = .init();
    try dmap.parse("TERM:0");
    try std.testing.expectEqual(@as(?u32, 0), dmap.target(15));
    try std.testing.expectError(ConfigError.InvalidSignal, dmap.parse("0:TERM"));
}

test "Map.parse refuses sources that never reach the forwarder" {
    var map: Map = .init();
    // KILL/STOP cannot be blocked or observed; SIGCHLD is the reaper's.
    try std.testing.expectError(ConfigError.InvalidRewrite, map.parse("KILL:TERM"));
    try std.testing.expectError(ConfigError.InvalidRewrite, map.parse("STOP:TERM"));
    try std.testing.expectError(ConfigError.InvalidRewrite, map.parse("CHLD:TERM"));
}

test "Map.reaches follows rewrite chains to a target" {
    var map: Map = .init();
    try map.set(15, 2);
    try std.testing.expect(try map.reaches(15, 2));
    try std.testing.expect(!try map.reaches(15, 1));
    try map.set(2, 9);
    try std.testing.expect(try map.reaches(15, 9));
    try std.testing.expect(!try map.reaches(15, 1));
    try map.set(9, 15);
    try std.testing.expect(try map.reaches(2, 15));
    try std.testing.expect(try map.reaches(9, 1)); // loops -> defensive true
    map.reset();

    try map.set(15, 0);
    try std.testing.expect(!try map.reaches(15, 2));

    try std.testing.expectError(ConfigError.InvalidParams, map.reaches(0, 2));
}

test "Map.apply maps, drops or passes a signal through" {
    var map: Map = .init();
    try map.set(15, 2);
    try std.testing.expectEqual(2, Map.apply(&map, 15));
    try std.testing.expectEqual(9, Map.apply(&map, 9));
    try map.set(2, 0);
    try std.testing.expectEqual(0, Map.apply(&map, 2));
    try std.testing.expectEqual(2, Map.apply(&map, 15));
}

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
        }
    };

    return std.testing.fuzz(Context{}, Context.testOne, .{
        // The test runner feeds corpus entries as `Smith.in`; its first four
        // bytes are the little-endian payload length, not parser input.
        .corpus = &.{
            "\x08\x00\x00\x00" ++ "TERM:INT",
            "\x07\x00\x00\x00" ++ "INT:HUP",
            "\x05\x00\x00\x00" ++ "HUP:0",
            "\x06\x00\x00\x00" ++ "TERM:9",
            "\x06\x00\x00\x00" ++ "9:TERM",
            "\x16\x00\x00\x00" ++ "TERM:INT\x00INT:HUP\x00HUP:0",
            "\x13\x00\x00\x00" ++ "USR1:USR2\x00USR2:TERM",
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

/// A rejected record must leave the public mapping unchanged. Compare targets,
/// not the backing array: a different representation with the same behavior is valid.
fn expectSameTargets(before: Map, after: Map) !void {
    var sig: u32 = 1;
    while (sig < std.os.linux.NSIG) : (sig += 1) {
        try std.testing.expectEqual(before.target(sig), after.target(sig));
    }
}
