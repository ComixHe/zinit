// SPDX-FileCopyrightText: 2026 YuMing He <ComixHe1895@outlook.com>
//
// SPDX-License-Identifier: MIT

//! Dedicated fuzz root: only the pure parsers, formatters and status decoder.
//! The retained non-fuzz property checks live in the same modules and run once
//! in this target; the E2E suite does not compile any of them.

test {
    _ = @import("args.zig");
    _ = @import("str.zig");
    _ = @import("rewrite.zig");
    _ = @import("fmt.zig");
    _ = @import("wait.zig");
}
