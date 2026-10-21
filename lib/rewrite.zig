// SPDX-FileCopyrightText: 2026 YuMing He <ComixHe1895@outlook.com>
//
// SPDX-License-Identifier: MIT

//! The `-r` table: which forwarded signal becomes which, and why a rewrite is refused.

const std = @import("std");

const errors = @import("errors.zig");
const signal = @import("signal.zig");
const str = @import("str.zig");

const ZinitError = errors.ZinitError;

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

    /// `null` when not rewritten; `0` is a real target.
    pub inline fn target(self: *const Map, sig: u32) ?u32 {
        const stored = self.entries[sig];
        return if (stored == unset) null else stored;
    }

    pub fn set(self: *Map, old_sig: u32, new_sig: u32) void {
        self.entries[old_sig] = new_sig;
    }

    /// The rewritten signal, or `signo`; by pointer, because by value it copied 260 bytes per signal.
    pub fn apply(rewrites: ?*const Map, signo: u32) u32 {
        if (rewrites) |m| {
            if (m.target(signo)) |rewritten| return rewritten;
        }

        return signo;
    }

    pub fn parse(self: *Map, value: []const u8) !void {
        const sep = str.indexOfByte(value, ':') orelse return ZinitError.InvalidRewrite;
        const old = value[0..sep];
        const old_sig = try signal.parse(old);

        const rest = value[sep + 1 ..];
        if (str.indexOfByte(rest, ':') != null) return ZinitError.InvalidRewrite;

        const new_sig = try parseTarget(rest);

        if (old_sig == new_sig) return ZinitError.DuplicateSignal;

        if (new_sig != 0 and try self.reaches(new_sig, old_sig)) return ZinitError.CycleRewrite;

        if (self.target(old_sig) != null) return ZinitError.DuplicateSignal;

        self.set(old_sig, new_sig);
    }

    pub fn reaches(self: *const Map, from: u32, to: u32) ZinitError!bool {
        if (!(from > 0 and from < std.os.linux.NSIG)) return ZinitError.InvalidParams;

        var current = from;
        var steps: usize = 0;
        while (self.target(current)) |next_node| {
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
test "Map.parse rejects malformed, duplicate and cyclic rewrites" {
    var map: Map = .init();
    try map.parse("TERM:INT");
    try std.testing.expectEqual(@as(?u32, 2), map.target(15));

    var emap: Map = .init();
    try std.testing.expectError(ZinitError.InvalidRewrite, emap.parse("TERM"));
    try std.testing.expectError(ZinitError.InvalidSignal, emap.parse("TERM:BAD"));
    try std.testing.expectError(ZinitError.DuplicateSignal, emap.parse("TERM:TERM"));
    try emap.parse("TERM:INT");
    try std.testing.expectError(ZinitError.DuplicateSignal, emap.parse("TERM:HUP"));
    emap.reset();

    try std.testing.expectError(ZinitError.InvalidRewrite, emap.parse("TERM:INT:EXTRA"));
    emap.set(1, 2);
    emap.set(2, 9);
    emap.set(9, 1);
    try std.testing.expectError(ZinitError.CycleRewrite, emap.parse("TERM:1"));

    // A two-node cycle is caught on the closing edge, not only on a later probe.
    var cmap: Map = .init();
    try cmap.parse("TERM:INT");
    try std.testing.expectError(ZinitError.CycleRewrite, cmap.parse("INT:TERM"));

    // The closing edge may be "hidden" behind a longer chain: A->B->C, add C->A.
    var lmap: Map = .init();
    try lmap.parse("TERM:INT");
    try lmap.parse("INT:HUP");
    try std.testing.expectError(ZinitError.CycleRewrite, lmap.parse("HUP:TERM"));

    // To 0 is terminal, never a cycle, and not accepted as a source.
    var dmap: Map = .init();
    try dmap.parse("TERM:0");
    try std.testing.expectEqual(@as(?u32, 0), dmap.target(15));
    try std.testing.expectError(ZinitError.InvalidSignal, dmap.parse("0:TERM"));
}

test "Map.reaches follows rewrite chains to a target" {
    var map: Map = .init();
    map.set(15, 2);
    try std.testing.expect(try map.reaches(15, 2));
    try std.testing.expect(!try map.reaches(15, 1));
    map.set(2, 9);
    try std.testing.expect(try map.reaches(15, 9));
    try std.testing.expect(!try map.reaches(15, 1));
    map.set(9, 15);
    try std.testing.expect(try map.reaches(2, 15));
    try std.testing.expect(try map.reaches(9, 1)); // loops -> defensive true
    map.reset();

    map.set(15, 0);
    try std.testing.expect(!try map.reaches(15, 2));

    try std.testing.expectError(ZinitError.InvalidParams, map.reaches(0, 2));
}

test "Map.apply maps, drops or passes a signal through" {
    var map: Map = .init();
    map.set(15, 2);
    try std.testing.expectEqual(2, Map.apply(&map, 15));
    try std.testing.expectEqual(9, Map.apply(&map, 9));
    try std.testing.expectEqual(15, Map.apply(null, 15));
    map.set(2, 0); // 0 means drop
    try std.testing.expectEqual(0, Map.apply(&map, 2));
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
                    try std.testing.expectEqualSlices(u32, &before.entries, &map.entries);
                }
            }
        }
    };

    return std.testing.fuzz(Context{}, Context.testOne, .{
        .corpus = &.{
            "TERM:INT",
            "INT:HUP",
            "HUP:0",
            "TERM:9",
            "9:TERM",
            "TERM:INT\x00INT:HUP\x00HUP:0",
            "USR1:USR2\x00USR2:TERM",
        },
    });
}

fn expectAcyclic(map: Map) !void {
    var start: u32 = 1;
    while (start < std.os.linux.NSIG) : (start += 1) {
        if (map.target(start) == null) continue;

        var seen: std.StaticBitSet(std.os.linux.NSIG) = .empty;
        seen.set(start);
        var current = start;
        while (map.target(current)) |next| {
            if (next == 0) break;
            if (!signal.isStandard(next)) return error.RewriteTargetOutOfDomain;
            if (seen.isSet(next)) return error.RewriteCycle;
            seen.set(next);
            current = next;
        }
    }
}
