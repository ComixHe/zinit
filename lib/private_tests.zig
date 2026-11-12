// SPDX-FileCopyrightText: 2026 YuMing He <ComixHe1895@outlook.com>
//
// SPDX-License-Identifier: MIT

//! Private integration test root: these checks use real kernel resources and
//! process-wide state (signal masks, signalfds, pipe sinks), so they stay out
//! of the process-free unit target.

comptime {
    _ = @import("workload.zig");
    _ = @import("signalfd.zig");
    _ = @import("log.zig");
}
