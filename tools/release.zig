// SPDX-FileCopyrightText: 2026 YuMing He <ComixHe1895@outlook.com>
//
// SPDX-License-Identifier: MIT

//! Assembles one release artifact, plus the SPDX SBOM when asked for.
//! Invoked by `zig build release`.
//!
//! The archive goes through std only — `tar.Writer` (mtime 0, uid/gid 0, no
//! uname/gname) over `compress.flate`, whose gzip header is a constant
//! `1f8b 08 00 00000000 00 03` (no mtime) — so the bytes depend on the inputs
//! and the Zig version alone, never on the host's tar or gzip. That is what
//! makes the whole payload, not just the binary inside it, reproducible.
//!
//! Usage:
//!   release-tool --binary <path> --name <stem> [--out-dir <dir>]
//!                [--license <path>] [--readme <path>]
//!                [--sbom --version <v> --zig <version> [--commit <sha>]]

const std = @import("std");

const usage =
    \\usage: release-tool --binary <path> --name <stem> [--out-dir <dir>]
    \\                    [--license <path>] [--readme <path>]
    \\                    [--sbom --version <v> --zig <version> [--commit <sha>]]
    \\
;

pub fn main(init: std.process.Init) !void {
    const arena = init.arena.allocator();
    const io = init.io;
    const cwd = std.Io.Dir.cwd();

    const options = try Options.parse(init.minimal.args);

    try cwd.createDirPath(io, options.out_dir);
    try assembleArchive(arena, cwd, io, options);
    std.debug.print("{s}/{s}.tar.gz\n", .{ options.out_dir, options.name });

    if (options.sbom) |sbom| {
        const path = try std.fmt.allocPrint(arena, "{s}/zinit-v{s}.spdx.json", .{ options.out_dir, sbom.version });
        const document = try sbom.render(arena, init.environ_map);
        try cwd.writeFile(io, .{ .sub_path = path, .data = document });
        std.debug.print("{s}\n", .{path});
    }
}

const Options = struct {
    binary: []const u8 = "",
    name: []const u8 = "",
    out_dir: []const u8 = ".",
    license: []const u8 = "LICENSE",
    readme: []const u8 = "README.md",
    sbom: ?Sbom = null,

    fn parse(args: std.process.Args) !Options {
        var options: Options = .{};
        var iter = args.iterate();
        _ = iter.skip();
        while (iter.next()) |arg| {
            if (std.mem.eql(u8, arg, "--binary")) {
                options.binary = value(&iter);
            } else if (std.mem.eql(u8, arg, "--name")) {
                options.name = value(&iter);
            } else if (std.mem.eql(u8, arg, "--out-dir")) {
                options.out_dir = value(&iter);
            } else if (std.mem.eql(u8, arg, "--license")) {
                options.license = value(&iter);
            } else if (std.mem.eql(u8, arg, "--readme")) {
                options.readme = value(&iter);
            } else if (std.mem.eql(u8, arg, "--sbom")) {
                options.sbom = .{ .version = "" };
            } else if (std.mem.eql(u8, arg, "--version")) {
                sbomField(&options, "version").* = value(&iter);
            } else if (std.mem.eql(u8, arg, "--zig")) {
                sbomField(&options, "zig_version").* = value(&iter);
            } else if (std.mem.eql(u8, arg, "--commit")) {
                sbomField(&options, "commit").* = value(&iter);
            } else {
                usageAndExit();
            }
        }

        if (options.binary.len == 0 or options.name.len == 0) usageAndExit();
        return options;
    }

    /// The SBOM fields are only meaningful once `--sbom` has been seen; taking a
    /// pointer keeps the assignment in one place whatever the flag order is.
    fn sbomField(options: *Options, comptime field: []const u8) *[]const u8 {
        const sbom = &(options.sbom orelse usageAndExit());
        return &@field(sbom, field);
    }
};

fn value(iter: anytype) []const u8 {
    return iter.next() orelse usageAndExit();
}

/// Writes the deterministic `.tar.gz`.
/// A release archive is a few tens of kilobytes, so it is assembled in memory and written once.
fn assembleArchive(arena: std.mem.Allocator, cwd: std.Io.Dir, io: std.Io, options: Options) !void {
    const binary = try cwd.readFileAlloc(io, options.binary, arena, .limited(1 << 26));
    const license = try cwd.readFileAlloc(io, options.license, arena, .limited(1 << 20));
    const readme = try cwd.readFileAlloc(io, options.readme, arena, .limited(1 << 20));

    var out = try std.Io.Writer.Allocating.initCapacity(arena, 64 * 1024);
    const window = try arena.alloc(u8, std.compress.flate.max_window_len);
    var flate = try std.compress.flate.Compress.init(&out.writer, window, .gzip, .default);

    var tar: std.tar.Writer = .{ .underlying_writer = &flate.writer };
    try tar.writeDir(options.name, .{ .mode = 0o755 });
    tar.prefix = options.name;
    try tar.writeFileBytes("zinit", binary, .{ .mode = 0o755 });
    try tar.writeFileBytes("LICENSE", license, .{ .mode = 0o644 });
    try tar.writeFileBytes("README.md", readme, .{ .mode = 0o644 });
    try tar.finishPedantically();
    try flate.finish();

    const path = try std.fmt.allocPrint(arena, "{s}/{s}.tar.gz", .{ options.out_dir, options.name });
    try cwd.writeFile(io, .{ .sub_path = path, .data = out.written() });
}

const Sbom = struct {
    version: []const u8,
    zig_version: []const u8 = "unknown",
    commit: []const u8 = "unknown",

    fn render(self: Sbom, arena: std.mem.Allocator, environ: *std.process.Environ.Map) ![]u8 {
        const document: Document = .{
            .name = try std.fmt.allocPrint(arena, "zinit-{s}", .{self.version}),
            .documentNamespace = try std.fmt.allocPrint(arena, "https://github.com/ComixHe/zinit/spdx/{s}", .{self.commit}),
            .creationInfo = .{ .created = try self.createdAt(arena, environ), .creators = &.{"Tool: zinit-release"} },
            .packages = &.{
                .{
                    .SPDXID = "SPDXRef-Package-zinit",
                    .name = "zinit",
                    .versionInfo = self.version,
                    .downloadLocation = try std.fmt.allocPrint(arena, "https://github.com/ComixHe/zinit/releases/tag/v{s}", .{self.version}),
                    .licenseConcluded = "MIT",
                    .licenseDeclared = "MIT",
                    .copyrightText = "2025-2026 YuMing He <ComixHe1895@outlook.com>",
                    .primaryPackagePurpose = "APPLICATION",
                },
                .{
                    .SPDXID = "SPDXRef-Package-zig-standard-library",
                    .name = "Zig standard library",
                    .versionInfo = self.zig_version,
                    .downloadLocation = "https://ziglang.org/download/",
                    .licenseConcluded = "MIT",
                    .licenseDeclared = "MIT",
                },
            },
            .relationships = &.{
                .{ .spdxElementId = "SPDXRef-DOCUMENT", .relationshipType = "DESCRIBES", .relatedSpdxElement = "SPDXRef-Package-zinit" },
                .{ .spdxElementId = "SPDXRef-Package-zinit", .relationshipType = "DEPENDS_ON", .relatedSpdxElement = "SPDXRef-Package-zig-standard-library" },
            },
        };

        return std.json.Stringify.valueAlloc(arena, document, .{ .whitespace = .indent_2 });
    }

    /// SOURCE_DATE_EPOCH keeps the document reproducible; unset means the epoch.
    fn createdAt(self: Sbom, arena: std.mem.Allocator, environ: *std.process.Environ.Map) ![]const u8 {
        _ = self;
        const raw = environ.get("SOURCE_DATE_EPOCH") orelse "0";
        const seconds = std.fmt.parseInt(u64, raw, 10) catch 0;

        const day_seconds = std.time.epoch.EpochSeconds{ .secs = seconds };
        const year_day = day_seconds.getEpochDay().calculateYearDay();
        const month_day = year_day.calculateMonthDay();
        const time = day_seconds.getDaySeconds();

        return std.fmt.allocPrint(arena, "{d:0>4}-{d:0>2}-{d:0>2}T{d:0>2}:{d:0>2}:{d:0>2}Z", .{
            year_day.year,
            month_day.month.numeric(),
            month_day.day_index + 1,
            time.getHoursIntoDay(),
            time.getMinutesIntoHour(),
            time.getSecondsIntoMinute(),
        });
    }
};

const Document = struct {
    spdxVersion: []const u8 = "SPDX-2.3",
    dataLicense: []const u8 = "CC0-1.0",
    SPDXID: []const u8 = "SPDXRef-DOCUMENT",
    name: []const u8,
    documentNamespace: []const u8,
    creationInfo: CreationInfo,
    packages: []const Package,
    relationships: []const Relationship,
};

const CreationInfo = struct {
    created: []const u8,
    creators: []const []const u8,
};

const Package = struct {
    SPDXID: []const u8,
    name: []const u8,
    versionInfo: []const u8,
    downloadLocation: []const u8,
    filesAnalyzed: bool = false,
    licenseConcluded: []const u8 = "MIT",
    licenseDeclared: []const u8 = "MIT",
    copyrightText: ?[]const u8 = null,
    primaryPackagePurpose: ?[]const u8 = null,
};

const Relationship = struct {
    spdxElementId: []const u8,
    relationshipType: []const u8,
    relatedSpdxElement: []const u8,
};

fn usageAndExit() noreturn {
    std.debug.print("{s}", .{usage});
    std.process.exit(2);
}
