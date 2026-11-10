// SPDX-FileCopyrightText: 2026 YuMing He <ComixHe1895@outlook.com>
//
// SPDX-License-Identifier: MIT

//! Invariant checks. Active where runtime safety is on (Debug and ReleaseSafe)
//! and compiled out everywhere else: `std.debug.assert` incurs additional
//! overhead under ReleaseSmall, so it is not free in the size-optimized build.

const builtin = @import("builtin");

pub const enabled = builtin.mode == .debug or builtin.mode == .safe;

/// Runtime invariant with a pure predicate.
pub inline fn check(ok: bool, comptime reason: []const u8) void {
    if (comptime !enabled) return;
    if (!ok) @panic(reason);
}

/// Runtime invariant whose predicate has side effects.
/// The predicate is not evaluated when checks are compiled out.
pub inline fn checkLazy(comptime predicate: anytype, args: anytype, comptime reason: []const u8) void {
    if (comptime !enabled) return;
    if (!@call(.auto, predicate, args)) @panic(reason);
}

/// Compile-time invariant. Unlike `check`, this is evaluated in every build.
pub inline fn comptimeCheck(comptime ok: bool, comptime reason: []const u8) void {
    if (!ok) @compileError(reason);
}
