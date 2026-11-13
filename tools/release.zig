// SPDX-FileCopyrightText: 2026 YuMing He <ComixHe1895@outlook.com>
//
// SPDX-License-Identifier: MIT

const std = @import("std");
const cli = @import("cli");

const json_options: std.json.Stringify.Options = .{
    .whitespace = .indent_2,
    .emit_null_optional_fields = false,
};

const usage =
    \\usage: release-tool --binary <path> --name <stem> [--out-dir <dir>]
    \\                    [--archive <path>] [--license <path>] [--readme <path>]
    \\                    [--debug-symbols <path> [--debug-archive <path>]]
    \\                    [--sbom [--sbom-out <path>] --version <v> --zig <version> [--commit <sha>]
    \\                    [--epoch <seconds>]
    \\
;

const max_source_date_epoch: u64 = 253_402_300_799;

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
    homepage: ?[]const u8 = null,
    filesAnalyzed: bool = false,
    licenseConcluded: []const u8 = "MIT",
    licenseDeclared: []const u8 = "MIT",
    copyrightText: ?[]const u8 = null,
    primaryPackagePurpose: ?[]const u8 = null,
    supplier: ?[]const u8 = null,
    checksums: ?[]const Checksum = null,
    externalRefs: ?[]const ExternalRef = null,
};

const ExternalRef = struct {
    referenceCategory: []const u8,
    referenceType: []const u8,
    referenceLocator: []const u8,
};

const Checksum = struct {
    algorithm: []const u8,
    checksumValue: []const u8,
};

const Relationship = struct {
    spdxElementId: []const u8,
    relationshipType: []const u8,
    relatedSpdxElement: []const u8,
};

fn isSafeStem(name: []const u8) bool {
    return name.len > 0 and
        !std.mem.eql(u8, name, ".") and
        !std.mem.eql(u8, name, "..") and
        !std.fs.path.isAbsolute(name) and
        std.mem.findAny(u8, name, "/\\\x00") == null;
}

fn parseSourceDate(raw: []const u8) !u64 {
    const seconds = std.fmt.parseInt(u64, raw, 10) catch return 0;
    if (seconds > max_source_date_epoch) return error.InvalidSourceDateEpoch;
    return seconds;
}

fn sourceDateSeconds(environ: *std.process.Environ.Map, epoch: ?[]const u8) !u64 {
    if (epoch) |value| return parseSourceDate(value);
    return parseSourceDate(environ.get("SOURCE_DATE_EPOCH") orelse "0");
}

pub fn main(init: std.process.Init) !void {
    const arena = init.arena.allocator();
    const io = init.io;
    const cwd = std.Io.Dir.cwd();

    if (cli.hasHelp(init.minimal.args)) {
        try cli.printStdout(io, "{s}", .{usage});
        return;
    }

    const options = try Options.parse(init.minimal.args);

    // Validate before writing anything: a bad timestamp must not leave a
    // half-written release (the archive is written before the SBOM).
    const epoch = try sourceDateSeconds(init.environ_map, options.epoch);
    const paths = try options.paths(arena);
    const binary_sha256 = try assembleArchive(arena, cwd, io, options, paths);
    try cli.printStdout(io, "{s}\n", .{paths.archive});
    if (paths.debug_archive) |path| try cli.printStdout(io, "{s}\n", .{path});

    if (options.sbom) |sbom| {
        const path = paths.sbom.?;
        const document = try sbom.render(arena, epoch, options.name, &binary_sha256);
        try ensureParent(cwd, io, path);
        try cwd.writeFile(io, .{ .sub_path = path, .data = document });
        try cli.printStdout(io, "{s}\n", .{path});
    }
}

const Options = struct {
    binary: []const u8 = "",
    name: []const u8 = "",
    out_dir: []const u8 = ".",
    archive: ?[]const u8 = null,
    debug_archive: ?[]const u8 = null,
    sbom_out: ?[]const u8 = null,
    license: []const u8 = "LICENSE",
    readme: []const u8 = "README.md",
    debug_symbols: ?[]const u8 = null,
    sbom: ?Sbom = null,
    epoch: ?[]const u8 = null,

    const Field = enum {
        binary,
        name,
        out_dir,
        archive,
        debug_archive,
        sbom_out,
        license,
        readme,
        debug_symbols,
        sbom,
        version,
        zig,
        commit,
        epoch,
    };

    fn parse(args: std.process.Args) !Options {
        var seen: std.EnumSet(Field) = .empty;
        var options: Options = .{};
        var iter = args.iterate();
        _ = iter.skip();
        while (iter.next()) |arg| {
            if (std.mem.eql(u8, arg, "--binary")) {
                cli.mark(&seen, .binary, usage);
                options.binary = cli.value(&iter, usage);
            } else if (std.mem.eql(u8, arg, "--name")) {
                cli.mark(&seen, .name, usage);
                options.name = cli.value(&iter, usage);
            } else if (std.mem.eql(u8, arg, "--out-dir")) {
                cli.mark(&seen, .out_dir, usage);
                options.out_dir = cli.value(&iter, usage);
            } else if (std.mem.eql(u8, arg, "--archive")) {
                cli.mark(&seen, .archive, usage);
                options.archive = cli.value(&iter, usage);
            } else if (std.mem.eql(u8, arg, "--debug-archive")) {
                cli.mark(&seen, .debug_archive, usage);
                options.debug_archive = cli.value(&iter, usage);
            } else if (std.mem.eql(u8, arg, "--sbom-out")) {
                cli.mark(&seen, .sbom_out, usage);
                options.sbom_out = cli.value(&iter, usage);
            } else if (std.mem.eql(u8, arg, "--license")) {
                cli.mark(&seen, .license, usage);
                options.license = cli.value(&iter, usage);
            } else if (std.mem.eql(u8, arg, "--readme")) {
                cli.mark(&seen, .readme, usage);
                options.readme = cli.value(&iter, usage);
            } else if (std.mem.eql(u8, arg, "--debug-symbols")) {
                cli.mark(&seen, .debug_symbols, usage);
                options.debug_symbols = cli.value(&iter, usage);
            } else if (std.mem.eql(u8, arg, "--sbom")) {
                cli.mark(&seen, .sbom, usage);
                options.sbom = .{ .version = "" };
            } else if (std.mem.eql(u8, arg, "--version")) {
                cli.mark(&seen, .version, usage);
                sbomField(&options, "version").* = cli.value(&iter, usage);
            } else if (std.mem.eql(u8, arg, "--zig")) {
                cli.mark(&seen, .zig, usage);
                sbomField(&options, "zig_version").* = cli.value(&iter, usage);
            } else if (std.mem.eql(u8, arg, "--commit")) {
                cli.mark(&seen, .commit, usage);
                sbomField(&options, "commit").* = cli.value(&iter, usage);
            } else if (std.mem.eql(u8, arg, "--epoch")) {
                cli.mark(&seen, .epoch, usage);
                options.epoch = cli.value(&iter, usage);
            } else {
                cli.usageAndExit(usage);
            }
        }

        if (options.binary.len == 0 or options.name.len == 0 or options.out_dir.len == 0)
            cli.usageAndExit(usage);
        if (!isSafeStem(options.name)) cli.usageAndExit(usage);
        if (options.debug_archive != null and options.debug_symbols == null) cli.usageAndExit(usage);
        if (options.sbom_out != null and options.sbom == null) cli.usageAndExit(usage);
        if (options.sbom) |sbom| {
            if (sbom.version.len == 0 or sbom.zig_version.len == 0 or sbom.commit.len == 0)
                cli.usageAndExit(usage);
        }
        return options;
    }

    fn sbomField(options: *Options, comptime field: []const u8) *[]const u8 {
        const sbom = &(options.sbom orelse cli.usageAndExit(usage));
        return &@field(sbom, field);
    }

    fn paths(self: Options, arena: std.mem.Allocator) !Paths {
        return .{
            .archive = self.archive orelse
                try arena.print("{s}/{s}.tar.gz", .{ self.out_dir, self.name }),
            .debug_archive = blk: {
                if (self.debug_symbols == null) break :blk null;
                break :blk self.debug_archive orelse
                    try arena.print("{s}/{s}-dbg.tar.gz", .{ self.out_dir, self.name });
            },
            .sbom = blk: {
                if (self.sbom == null) break :blk null;
                break :blk self.sbom_out orelse
                    try arena.print("{s}/{s}.spdx.json", .{ self.out_dir, self.name });
            },
        };
    }
};

const Paths = struct {
    archive: []const u8,
    debug_archive: ?[]const u8,
    sbom: ?[]const u8,
};

fn ensureParent(cwd: std.Io.Dir, io: std.Io, path: []const u8) !void {
    const parent = std.fs.path.dirname(path) orelse return;
    if (parent.len == 0) return;
    try cwd.createDirPath(io, parent);
}

fn assembleArchive(
    arena: std.mem.Allocator,
    cwd: std.Io.Dir,
    io: std.Io,
    options: Options,
    paths: Paths,
) ![64]u8 {
    const binary = try cwd.readFileAlloc(io, options.binary, arena, .limited(1 << 26));

    var digest: [32]u8 = undefined;
    std.crypto.hash.sha2.Sha256.hash(binary, &digest, .{});
    const build_id = std.fmt.bytesToHex(digest, .lower);
    const license = try cwd.readFileAlloc(io, options.license, arena, .limited(1 << 20));
    const readme = try cwd.readFileAlloc(io, options.readme, arena, .limited(1 << 20));

    try ensureParent(cwd, io, paths.archive);
    try writeTarball(arena, cwd, io, paths.archive, options.name, &.{
        .{ .name = "zinit", .data = binary, .mode = 0o755 },
        .{ .name = "LICENSE", .data = license, .mode = 0o644 },
        .{ .name = "README.md", .data = readme, .mode = 0o644 },
    });

    if (paths.debug_archive) |dbg_path| {
        const symbols = try cwd.readFileAlloc(io, options.debug_symbols.?, arena, .limited(1 << 27));
        const dbg_name = try arena.print("{s}-dbg", .{options.name});
        try ensureParent(cwd, io, dbg_path);
        try writeTarball(arena, cwd, io, dbg_path, dbg_name, &.{
            .{ .name = "zinit.dbg", .data = symbols, .mode = 0o644 },
            // The debug archive is path-dependent (DWARF records the build
            // root). This SHA-256 of the stripped runtime binary is what binds
            // it to the archive users actually run.
            .{ .name = "BUILD-ID", .data = build_id[0..], .mode = 0o644 },
        });
    }

    return build_id;
}

const Entry = struct {
    name: []const u8,
    data: []const u8,
    mode: u32,
};

fn writeTarball(
    arena: std.mem.Allocator,
    cwd: std.Io.Dir,
    io: std.Io,
    path: []const u8,
    dir_name: []const u8,
    entries: []const Entry,
) !void {
    var out = try std.Io.Writer.Allocating.initCapacity(arena, 64 * 1024);
    const window = try arena.alloc(u8, std.compress.flate.max_window_len);
    var flate = try std.compress.flate.Compress.init(&out.writer, window, .gzip, .default);

    var tar: std.tar.Writer = .{ .underlying_writer = &flate.writer };
    try tar.writeDir(dir_name, .{ .mode = 0o755 });
    tar.prefix = dir_name;
    for (entries) |entry| try tar.writeFileBytes(entry.name, entry.data, .{ .mode = entry.mode });
    try tar.finishPedantically();
    try flate.finish();

    try cwd.writeFile(io, .{ .sub_path = path, .data = out.written() });
}

const Sbom = struct {
    version: []const u8,
    zig_version: []const u8 = "",
    commit: []const u8 = "unknown",

    fn render(
        self: Sbom,
        arena: std.mem.Allocator,
        epoch_seconds: u64,
        document_name: []const u8,
        binary_sha256: []const u8,
    ) ![]u8 {
        var document: Document = .{
            .name = document_name,
            .documentNamespace = "",
            .creationInfo = .{
                .created = try formatRfc3339(arena, epoch_seconds),
                .creators = &.{ "Person: YuMing He <ComixHe1895@outlook.com>", "Tool: zinit-release" },
            },
            .packages = &.{
                .{
                    .SPDXID = "SPDXRef-Package-zinit",
                    .name = "zinit",
                    .versionInfo = self.version,
                    .downloadLocation = try arena.print("https://github.com/ComixHe/zinit/releases/tag/v{s}", .{self.version}),
                    .licenseConcluded = "MIT",
                    .licenseDeclared = "MIT",
                    .copyrightText = "2025-2026 YuMing He <ComixHe1895@outlook.com>",
                    .primaryPackagePurpose = "APPLICATION",
                    .supplier = "Person: YuMing He <ComixHe1895@outlook.com>",
                    .checksums = &.{.{
                        .algorithm = "SHA256",
                        .checksumValue = binary_sha256,
                    }},
                    .externalRefs = &.{.{
                        .referenceCategory = "PACKAGE-MANAGER",
                        .referenceType = "purl",
                        .referenceLocator = try arena.print("pkg:github/ComixHe/zinit@{s}", .{self.version}),
                    }},
                },
                .{
                    .SPDXID = "SPDXRef-Package-zig-standard-library",
                    .name = "Zig standard library",
                    .versionInfo = self.zig_version,
                    .downloadLocation = "https://ziglang.org/download/",
                    .homepage = "https://codeberg.org/ziglang/zig",
                    .licenseConcluded = "MIT",
                    .licenseDeclared = "MIT",
                    .copyrightText = "2015-2026 Zig contributors",
                    .supplier = "Organization: Zig Software Foundation",
                },
            },
            .relationships = &.{
                .{ .spdxElementId = "SPDXRef-DOCUMENT", .relationshipType = "DESCRIBES", .relatedSpdxElement = "SPDXRef-Package-zinit" },
                .{ .spdxElementId = "SPDXRef-Package-zinit", .relationshipType = "DEPENDS_ON", .relatedSpdxElement = "SPDXRef-Package-zig-standard-library" },
            },
        };

        var hash_buffer: [1024]u8 = undefined;
        var hash: std.Io.Writer.Hashing(std.crypto.hash.sha2.Sha256) = .init(&hash_buffer);
        try hash.writer.writeAll(self.commit);
        try hash.writer.writeByte(0);
        try std.json.Stringify.value(document, json_options, &hash.writer);
        try hash.writer.flush();
        const digest = std.fmt.bytesToHex(hash.hasher.finalResult(), .lower);
        document.documentNamespace = try arena.print("https://github.com/ComixHe/zinit/spdx/{s}/{s}", .{ self.commit, digest });
        return std.json.Stringify.valueAlloc(arena, document, json_options);
    }
};

fn formatRfc3339(arena: std.mem.Allocator, seconds: u64) ![]const u8 {
    const day_seconds = std.time.epoch.EpochSeconds{ .secs = seconds };
    const year_day = day_seconds.getEpochDay().calculateYearDay();
    const month_day = year_day.calculateMonthDay();
    const time = day_seconds.getDaySeconds();

    return arena.print("{d:0>4}-{d:0>2}-{d:0>2}T{d:0>2}:{d:0>2}:{d:0>2}Z", .{
        year_day.year,
        month_day.month.numeric(),
        month_day.day_index + 1,
        time.getHoursIntoDay(),
        time.getMinutesIntoHour(),
        time.getSecondsIntoMinute(),
    });
}

test "release names are safe stems" {
    try std.testing.expect(isSafeStem("zinit-0.3.0-x86_64-linux"));
    try std.testing.expect(isSafeStem("a.b+c"));
    try std.testing.expect(!isSafeStem(""));
    try std.testing.expect(!isSafeStem("."));
    try std.testing.expect(!isSafeStem(".."));
    try std.testing.expect(!isSafeStem("../evil"));
    try std.testing.expect(!isSafeStem("/abs"));
    try std.testing.expect(!isSafeStem("a/b"));
    try std.testing.expect(!isSafeStem("a\\b"));
}

test "SOURCE_DATE_EPOCH is bounded before std.time.epoch sees it" {
    try std.testing.expectEqual(@as(u64, 0), try parseSourceDate("junk"));
    try std.testing.expectEqual(@as(u64, 0), try parseSourceDate(""));
    try std.testing.expectEqual(@as(u64, 1), try parseSourceDate("1"));
    try std.testing.expectEqual(max_source_date_epoch, try parseSourceDate("253402300799"));
    try std.testing.expectError(error.InvalidSourceDateEpoch, parseSourceDate("253402300800"));
    try std.testing.expectError(error.InvalidSourceDateEpoch, parseSourceDate("18446744073709551615"));
}

test "explicit output paths override the out-dir defaults" {
    var arena_state = std.heap.ArenaAllocator.init(std.testing.allocator);
    defer arena_state.deinit();
    const arena = arena_state.allocator();

    const derived = try (Options{ .binary = "b", .name = "zinit-x", .out_dir = "out" }).paths(arena);
    try std.testing.expectEqualStrings("out/zinit-x.tar.gz", derived.archive);
    try std.testing.expectEqual(@as(?[]const u8, null), derived.debug_archive);
    try std.testing.expectEqual(@as(?[]const u8, null), derived.sbom);

    const explicit = try (Options{
        .binary = "b",
        .name = "zinit-x",
        .out_dir = "ignored",
        .archive = "a.tar.gz",
        .debug_symbols = "s.dbg",
        .debug_archive = "d.tar.gz",
        .sbom = .{ .version = "1" },
        .sbom_out = "s.json",
    }).paths(arena);
    try std.testing.expectEqualStrings("a.tar.gz", explicit.archive);
    try std.testing.expectEqualStrings("d.tar.gz", explicit.debug_archive.?);
    try std.testing.expectEqualStrings("s.json", explicit.sbom.?);

    const with_symbols = try (Options{ .binary = "b", .name = "n", .debug_symbols = "s" }).paths(arena);
    try std.testing.expectEqualStrings("./n-dbg.tar.gz", with_symbols.debug_archive.?);
    const with_sbom = try (Options{ .binary = "b", .name = "n", .sbom = .{ .version = "1" } }).paths(arena);
    try std.testing.expectEqualStrings("./n.spdx.json", with_sbom.sbom.?);
}

test "an explicit epoch overrides the environment" {
    var env: std.process.Environ.Map = .init(std.testing.allocator);
    defer env.deinit();
    try env.put("SOURCE_DATE_EPOCH", "1");

    try std.testing.expectEqual(@as(u64, 2), try sourceDateSeconds(&env, "2"));
    try std.testing.expectEqual(@as(u64, 1), try sourceDateSeconds(&env, null));
}

test "an SBOM renders past the hashing buffer and pins the timestamp" {
    var arena_state = std.heap.ArenaAllocator.init(std.testing.allocator);
    defer arena_state.deinit();
    const arena = arena_state.allocator();

    const checksum: [64]u8 = @splat('a');
    const document = try (Sbom{
        .version = "0.3.0",
        .zig_version = "0.18.0",
        .commit = "abc123",
    }).render(arena, 0, "zinit-0.3.0-x86_64-linux", &checksum);

    try std.testing.expect(document.len > 1024);
    try std.testing.expect(std.mem.find(u8, document, "\"created\": \"1970-01-01T00:00:00Z\"") != null);
    try std.testing.expect(std.mem.find(u8, document, "\"documentNamespace\": \"https://github.com/ComixHe/zinit/spdx/abc123/") != null);
    try std.testing.expect(std.mem.find(u8, document, "\"versionInfo\": \"0.3.0\"") != null);
    try std.testing.expect(std.mem.find(u8, document, "\"versionInfo\": \"0.18.0\"") != null);

    const parsed = try std.json.parseFromSlice(std.json.Value, arena, document, .{});
    defer parsed.deinit();
    try std.testing.expectEqual(@as(usize, 2), parsed.value.object.get("packages").?.array.items.len);
}
