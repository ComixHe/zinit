// SPDX-FileCopyrightText: 2026 YuMing He <ComixHe1895@outlook.com>
//
// SPDX-License-Identifier: MIT

//! Public-interface integration tests: real children, signals, wait and process state.

test {
    _ = @import("integration/process.zig");
    _ = @import("integration/signalfd.zig");
    _ = @import("integration/supervisor.zig");
}
