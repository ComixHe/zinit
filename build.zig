// SPDX-FileCopyrightText: 2025 - 2026 YuMing He <ComixHe1895@outlook.com>
//
// SPDX-License-Identifier: MIT

const std = @import("std");

pub fn build(b: *std.Build) void {
    const config = Config.init(b);

    const exe = addZinit(b, config);
    installAndRun(b, exe);
    addReleaseStep(b, exe, config);
    addTestStep(b, exe, config);
}

const Config = struct {
    target: std.Build.ResolvedTarget,
    optimize: std.builtin.OptimizeMode,
    manifest: Manifest,
    size_analysis: bool,
    coverage: bool,

    fn init(b: *std.Build) Config {
        return .{
            .target = b.standardTargetOptions(.{ .default_target = .{ .os_tag = .linux } }),
            .optimize = b.standardOptimizeOption(.{}),
            .manifest = readManifest(b),
            .size_analysis = b.option(bool, "size-analysis", "Keep symbols in release builds for bloaty analysis") orelse false,
            .coverage = b.option(bool, "test-coverage", "Generate coverage reports") orelse false,
        };
    }

    fn isRelease(self: Config) bool {
        return self.optimize != .debug;
    }

    fn version(self: Config) std.SemanticVersion {
        return std.SemanticVersion.parse(self.manifest.version) catch |err|
            std.debug.panic("invalid version {s} in build.zig.zon: {s}", .{ self.manifest.version, @errorName(err) });
    }

    /// `0.2.0`
    fn versionString(self: Config, b: *std.Build) []const u8 {
        const v = self.version();

        return b.fmt("{d}.{d}.{d}", .{ v.major, v.minor, v.patch });
    }

    fn shortTarget(self: Config, b: *std.Build) []const u8 {
        return b.fmt("{s}-{s}", .{
            @tagName(self.target.result.cpu.arch),
            @tagName(self.target.result.os.tag),
        });
    }

    fn optimizeName(self: Config) []const u8 {
        return switch (self.optimize) {
            .Debug => "Debug",
            .ReleaseSafe => "ReleaseSafe",
            .ReleaseSmall => "ReleaseSmall",
            .ReleaseFast => "ReleaseFast",
        };
    }
};

const Manifest = struct {
    version: []const u8,
    minimum_zig_version: []const u8 = "",
};

fn readManifest(b: *std.Build) Manifest {
    var diagnostics: std.zon.parse.Diagnostics = undefined;

    return std.zon.parse.fromSlice(Manifest, .{
        .gpa = b.allocator,
        .arena = b.allocator,
        .source = @embedFile("build.zig.zon"),
        .diagnostics = &diagnostics,
        .ignore_unknown_fields = true,
    }) catch |err| {
        diagnostics.log("build.zig.zon");
        std.debug.panic("unable to parse build.zig.zon: {s}", .{@errorName(err)});
    };
}

fn addZinit(b: *std.Build, config: Config) *std.Build.Step.Compile {
    const is_release = config.isRelease();

    const exe_mod = b.createModule(.{
        .root_source_file = b.path("src/main.zig"),
        .target = config.target,
        .optimize = config.optimize,
        .strip = is_release and !config.size_analysis,
        .omit_frame_pointer = is_release,
        .single_threaded = true,
        .unwind_tables = if (is_release) .none else .sync,
        .pic = true,
    });

    const exe = b.addExecutable(.{
        .name = "zinit",
        .root_module = exe_mod,
        .version = config.version(),
    });

    // Leave the ELF stack-size hint at 0. The linker's default makes
    // `std.start` raise RLIMIT_STACK at startup, which the child would then
    // inherit; 0 keeps the container's own limit intact and drops the
    // `prlimit64` dependency.
    exe.stack_size = 0;

    const options = b.addOptions();
    options.addOption(std.SemanticVersion, "version", config.version());
    options.addOption(bool, "tracing_child", b.option(bool, "tracing-child", "zinit will wait for SIGUSR1 to continue executing child process") orelse false);
    options.addOption(bool, "stack_traces", b.option(bool, "stack-traces", "Include crash stack traces (segfault handler + std.debug panic). Opt-in, off by default.") orelse false);
    exe.root_module.addOptions("config", options);

    return exe;
}

fn installAndRun(b: *std.Build, exe: *std.Build.Step.Compile) void {
    b.installArtifact(exe);

    const run_cmd = b.addRunArtifact(exe);
    run_cmd.step.dependOn(b.getInstallStep());
    run_cmd.addPassthruArgs();

    b.step("run", "Run the app").dependOn(&run_cmd.step);
}

fn addReleaseStep(b: *std.Build, exe: *std.Build.Step.Compile, config: Config) void {
    const step = b.step("release", "Assemble the release archive for -Dtarget/-Doptimize");
    const sbom = b.option(bool, "sbom", "Also write the SPDX SBOM next to the archive") orelse false;
    const commit = b.option([]const u8, "commit", "Source commit recorded in the SBOM") orelse "";

    const packer = b.addExecutable(.{
        .name = "release-tool",
        .root_module = b.createModule(.{
            .root_source_file = b.path("tools/release.zig"),
            .target = b.graph.host,
            .optimize = .Debug,
        }),
    });

    const archive_name = b.fmt("zinit-{s}-{s}-{s}", .{
        config.versionString(b),
        config.shortTarget(b),
        config.optimizeName(),
    });

    const pack = b.addRunArtifact(packer);
    pack.addArg("--binary");
    pack.addFileArg(exe.getEmittedBin());
    pack.addArgs(&.{ "--name", archive_name, "--out-dir", "zig-out/artifacts" });
    pack.addArg("--license");
    pack.addFileArg(b.path("LICENSE"));
    pack.addArg("--readme");
    pack.addFileArg(b.path("README.md"));
    if (sbom) {
        pack.addArgs(&.{
            "--sbom",
            "--version",
            config.versionString(b),
            "--zig",
            config.manifest.minimum_zig_version,
            "--commit",
            commit,
        });
    }

    step.dependOn(&pack.step);
}

fn addTestStep(b: *std.Build, exe: *std.Build.Step.Compile, config: Config) void {
    const unit_tests = b.addTest(.{
        .root_module = exe.root_module,
        .use_llvm = config.coverage,
        .use_lld = config.coverage,
    });

    const run_unit_tests = b.addRunArtifact(unit_tests);
    if (config.coverage) {
        const system_kcov = b.addSystemCommand(&.{ "kcov", "--clean", "--include-path=./src", "kcov-output" });
        system_kcov.addArtifactArg(unit_tests);
        run_unit_tests.step.dependOn(&system_kcov.step);
    }

    b.step("test", "Run unit tests").dependOn(&run_unit_tests.step);
}
