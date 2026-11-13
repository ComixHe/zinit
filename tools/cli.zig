// SPDX-FileCopyrightText: 2026 YuMing He <ComixHe1895@outlook.com>
//
// SPDX-License-Identifier: MIT

const std = @import("std");

pub fn hasHelp(args: std.process.Args) bool {
    var iter = args.iterate();
    _ = iter.skip();
    while (iter.next()) |arg| {
        if (std.mem.eql(u8, arg, "--help")) return true;
    }

    return false;
}

pub fn value(iter: anytype, usage: []const u8) []const u8 {
    return iter.next() orelse usageAndExit(usage);
}

pub fn mark(seen: anytype, field: anytype, usage: []const u8) void {
    if (seen.contains(field)) usageAndExit(usage);
    seen.insert(field);
}

pub fn usageAndExit(usage: []const u8) noreturn {
    std.debug.print("{s}", .{usage});
    std.process.exit(2);
}

pub fn invalid(usage: []const u8) error{InvalidArguments} {
    std.debug.print("{s}", .{usage});
    return error.InvalidArguments;
}

pub fn printStdout(io: std.Io, comptime format: []const u8, args: anytype) !void {
    var buffer: [512]u8 = undefined;
    const text = try std.mem.print(&buffer, format, args);
    try std.Io.File.stdout().writeStreamingAll(io, text);
}
