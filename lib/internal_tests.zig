// SPDX-FileCopyrightText: 2026 YuMing He <ComixHe1895@outlook.com>
//
// SPDX-License-Identifier: MIT

//! Entry point for `test-internal`: the retained property checks and named
//! fault reproductions. They may import the library and are deliberately
//! implementation-specific. The E2E suite lives in `tests/e2e.zig` and never
//! imports this file or any runtime module.

test {
    // The modules keep their retained checks next to the code they exercise.
    _ = @import("args.zig");
    _ = @import("str.zig");
    _ = @import("rewrite.zig");
    _ = @import("fmt.zig");
    _ = @import("wait.zig");
    _ = @import("workload.zig");
}
