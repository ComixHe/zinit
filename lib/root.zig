// SPDX-FileCopyrightText: 2026 YuMing He <ComixHe1895@outlook.com>
//
// SPDX-License-Identifier: MIT

//! Library root: exposes the modules and pulls their tests into the `test` target.

const std = @import("std");

pub const errors = @import("errors.zig");
pub const io = @import("io.zig");
pub const fmt = @import("fmt.zig");
pub const log = @import("log.zig");
pub const str = @import("str.zig");
pub const signal = @import("signal.zig");
pub const rewrite = @import("rewrite.zig");
pub const signalfd = @import("signalfd.zig");
pub const wait = @import("wait.zig");
pub const args = @import("args.zig");
pub const child = @import("child.zig");
pub const supervisor = @import("supervisor.zig");

// kcov-exclude-tests (everything below is test-only).
test {
    std.testing.refAllDecls(@This());
}
