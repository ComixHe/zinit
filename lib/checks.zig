// SPDX-FileCopyrightText: 2026 YuMing He <ComixHe1895@outlook.com>
//
// SPDX-License-Identifier: MIT

//! Invariant checks. Active where runtime safety is on (Debug and ReleaseSafe)
//! and compiled out everywhere else: `std.debug.assert` incurs additional
//! overhead under ReleaseSmall, so it is not free in the size-optimized build.

const builtin = @import("builtin");

pub const enabled = builtin.mode == .debug or builtin.mode == .safe;

pub inline fn check(ok: bool, comptime reason: []const u8) void {
    if (comptime !enabled) return;
    if (!ok) @panic(reason);
}
