// SPDX-FileCopyrightText: 2026 YuMing He <ComixHe1895@outlook.com>
//
// SPDX-License-Identifier: MIT

//! Test-only helper for building Smith inputs. The fuzz runner reads a
//! little-endian u32 slice length before the payload, so keep that encoding in
//! one place instead of spelling it out in every corpus entry.

const std = @import("std");

pub fn slice(comptime payload: []const u8) []const u8 {
    const bytes = comptime blk: {
        var bytes: [4 + payload.len]u8 = undefined;
        std.mem.writeInt(u32, bytes[0..4], @intCast(payload.len), .little);
        @memcpy(bytes[4..], payload);
        break :blk bytes;
    };

    return &bytes;
}
