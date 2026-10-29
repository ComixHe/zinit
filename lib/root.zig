// SPDX-FileCopyrightText: 2026 YuMing He <ComixHe1895@outlook.com>
//
// SPDX-License-Identifier: MIT

//! Library root: exposes the modules and pulls their in-process tests into the `test`
//! target. Public-interface and private workload integration checks run from
//! separate module roots under the same test-integration build step.

const std = @import("std");

pub const errors = @import("errors.zig");
pub const io = @import("io.zig");
pub const tty = @import("tty.zig");
pub const fmt = @import("fmt.zig");
pub const log = @import("log.zig");
pub const str = @import("str.zig");
pub const signal = @import("signal.zig");
pub const rewrite = @import("rewrite.zig");
pub const signalfd = @import("signalfd.zig");
pub const wait = @import("wait.zig");
pub const args = @import("args.zig");
pub const supervisor = @import("supervisor.zig");

// kcov-exclude-tests (everything below is test-only).
test {
    std.testing.refAllDecls(@This());
    // Collect internal modules' unit checks without exporting them to callers.
    _ = @import("workload.zig");
    _ = @import("child.zig");
}
