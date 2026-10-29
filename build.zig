// SPDX-FileCopyrightText: 2025 - 2026 YuMing He <ComixHe1895@outlook.com>
//
// SPDX-License-Identifier: MIT

const std = @import("std");
const builtin = @import("builtin");

pub fn build(b: *std.Build) void {
    const config = Config.init(b);

    const config_mod = addConfig(b, config, false);
    const lib = addLibrary(b, config, config_mod);
    const app = addApp(b, config, config_mod, lib);
    const exe = addExecutable(b, config, app);

    installAndRun(b, exe);
    addTestStep(b, config, lib, app);
    addFuzzStep(b, config, config_mod);
    addSmokeStep(b, exe);
    addReleaseStep(b, exe, config);
}

fn moduleOptions(config: Config) std.Build.Module.CreateOptions {
    const is_release = config.isRelease();

    return .{
        .target = config.target,
        .optimize = config.optimize,
        .strip = is_release and !config.size_analysis,
        .omit_frame_pointer = is_release,
        .single_threaded = true,
        .unwind_tables = if (is_release) .none else .sync,
        .pic = true,
    };
}

fn addConfig(b: *std.Build, config: Config, include_private_integration_tests: bool) *std.Build.Module {
    const options = b.addOptions();

    options.addOption([]const u8, "version", config.manifest.version);
    options.addOption(bool, "tracing_child", config.tracing_child);
    options.addOption(bool, "stack_traces", config.stack_traces);
    options.addOption(std.log.Level, "max_log_level", config.max_log_level);
    options.addOption(std.log.Level, "default_log_level", config.default_log_level);
    options.addOption(bool, "include_private_integration_tests", include_private_integration_tests);

    return options.createModule();
}

fn addLibrary(b: *std.Build, config: Config, config_mod: *std.Build.Module) *std.Build.Module {
    var options = moduleOptions(config);
    options.root_source_file = b.path("lib/root.zig");
    options.imports = &.{.{ .name = "config", .module = config_mod }};

    return b.createModule(options);
}

fn addApp(
    b: *std.Build,
    config: Config,
    config_mod: *std.Build.Module,
    lib: *std.Build.Module,
) *std.Build.Module {
    var options = moduleOptions(config);
    options.root_source_file = b.path("app/main.zig");
    options.imports = &.{
        .{ .name = "config", .module = config_mod },
        .{ .name = "zinit", .module = lib },
    };

    return b.createModule(options);
}

fn addExecutable(b: *std.Build, config: Config, app: *std.Build.Module) *std.Build.Step.Compile {
    const exe = b.addExecutable(.{
        .name = "zinit",
        .root_module = app,
        .version = config.version(),
    });

    // 0 keeps the linker from making `std.start` raise RLIMIT_STACK, which the child
    // would inherit.
    exe.stack_size = 0;
    exe.pie = config.pie;

    if (config.isRelease()) exe.lto = .thin;

    return exe;
}

fn installAndRun(b: *std.Build, exe: *std.Build.Step.Compile) void {
    b.installArtifact(exe);

    const run_cmd = b.addRunArtifact(exe);
    run_cmd.step.dependOn(b.getInstallStep());
    run_cmd.addPassthruArgs();

    b.step("run", "Run the app").dependOn(&run_cmd.step);
}

fn addSmokeStep(b: *std.Build, exe: *std.Build.Step.Compile) void {
    const step = b.step("smoke", "Run the built binary end to end");

    const smoke = b.addExecutable(.{
        .name = "smoke",
        .root_module = b.createModule(.{
            .root_source_file = b.path("tests/smoke.zig"),
            .target = b.graph.host,
            .optimize = .Debug,
        }),
    });

    const run = b.addRunArtifact(smoke);
    run.addArg("--zinit");
    run.addFileArg(exe.getEmittedBin());
    step.dependOn(&run.step);
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
        config.manifest.version,
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
            config.manifest.version,
            "--zig",
            builtin.zig_version_string,
            "--commit",
            commit,
        });
    }

    step.dependOn(&pack.step);
}

fn addFuzzStep(b: *std.Build, config: Config, config_mod: *std.Build.Module) void {
    var options = moduleOptions(config);
    options.root_source_file = b.path("lib/root.zig");
    options.imports = &.{.{ .name = "config", .module = config_mod }};
    // The fuzz runtime is not single-threaded: with it the rebuilt binary segfaults in its own fuzzer.
    options.single_threaded = false;

    const fuzz_tests = b.addTest(.{ .root_module = b.createModule(options) });
    const run_fuzz = b.addRunArtifact(fuzz_tests);

    b.step("fuzz", "Fuzz the pure parsers (needs --fuzz on the command line)")
        .dependOn(&run_fuzz.step);
}

fn addTestStep(
    b: *std.Build,
    config: Config,
    lib: *std.Build.Module,
    app: *std.Build.Module,
) void {
    const lib_tests = b.addTest(.{
        .root_module = lib,
        .use_llvm = config.coverage,
        .use_lld = config.coverage,
    });

    const app_tests = b.addTest(.{
        .root_module = app,
        .use_llvm = config.coverage,
        .use_lld = config.coverage,
    });

    const test_step = b.step("test", "Run unit tests");
    if (config.coverage) {
        // kcov traces one binary at a time, so both roots are merged into one report.
        // Test bodies are excluded so the number describes the shipped code.
        const excludes = "--exclude-region=kcov-exclude-tests:never-matches";
        const wiring = "--exclude-path=./lib/root.zig";
        const lib_cov = b.addSystemCommand(&.{
            "kcov", "--clean", "--dump-summary", excludes, wiring, "--include-path=./lib,./app", "kcov-output-lib",
        });
        lib_cov.addArtifactArg(lib_tests);

        const app_cov = b.addSystemCommand(&.{
            "kcov", "--clean", "--dump-summary", excludes, wiring, "--include-path=./lib,./app", "kcov-output-app",
        });
        app_cov.addArtifactArg(app_tests);

        const merge = b.addSystemCommand(&.{
            "kcov", "--merge", "--cobertura-only", "--dump-summary", excludes, wiring, "kcov-output", "kcov-output-lib", "kcov-output-app",
        });
        merge.step.dependOn(&lib_cov.step);
        merge.step.dependOn(&app_cov.step);

        test_step.dependOn(&merge.step);
    } else {
        const run_lib_tests = b.addRunArtifact(lib_tests);
        const run_app_tests = b.addRunArtifact(app_tests);
        test_step.dependOn(&run_lib_tests.step);
        test_step.dependOn(&run_app_tests.step);
    }
}

const Config = struct {
    target: std.Build.ResolvedTarget,
    optimize: std.lang.Optimize,
    manifest: Manifest,
    size_analysis: bool,
    coverage: bool,
    tracing_child: bool,
    stack_traces: bool,
    max_log_level: std.log.Level,
    default_log_level: std.log.Level,
    pie: bool,

    fn init(b: *std.Build) Config {
        return .{
            .target = b.standardTargetOptions(.{ .default_target = .{ .os_tag = .linux } }),
            .optimize = b.standardOptimizeOption(.{}),
            .manifest = readManifest(b),
            .size_analysis = b.option(bool, "size-analysis", "Keep symbols in builds") orelse false,
            .coverage = b.option(bool, "test-coverage", "Generate coverage reports") orelse false,
            .tracing_child = b.option(bool, "tracing-child", "zinit will wait for SIGUSR1 to continue executing child process") orelse false,
            .stack_traces = b.option(bool, "stack-traces", "Include crash stack traces (segfault handler + std.debug panic). Opt-in, off by default.") orelse false,
            .pie = b.option(bool, "pie", "Build a position-independent executable, for ASLR on the binary itself. Off by default: the init is one short-lived process inside a container's own PID namespace, where the smaller non-PIE build is worth more than ASLR on the image's own binary.") orelse false,
            .max_log_level = parseLogLevelOption("log-level", b.option([]const u8, "log-level", "Highest log level this build can print: error, warn, info (the default) or debug. Levels above it are compiled out, and --log-level cannot ask for one.") orelse "info"),
            .default_log_level = parseLogLevelOption("default-log-level", b.option([]const u8, "default-log-level", "Level printed when neither --log-level nor ZINIT_LOG_LEVEL says anything: error, warn (the default), info or debug. Clamped to the compile-time ceiling.") orelse "warn"),
        };
    }

    fn isRelease(self: Config) bool {
        return self.optimize != .debug;
    }

    fn version(self: Config) std.SemanticVersion {
        return std.SemanticVersion.parse(self.manifest.version) catch |err|
            std.debug.panic("invalid version {s} in build.zig.zon: {s}", .{ self.manifest.version, @errorName(err) });
    }

    fn shortTarget(self: Config, b: *std.Build) []const u8 {
        return b.fmt("{s}-{s}", .{
            @tagName(self.target.result.cpu.arch),
            @tagName(self.target.result.os.tag),
        });
    }

    fn optimizeName(self: Config) []const u8 {
        return switch (self.optimize) {
            .debug => "Debug",
            .safe => "ReleaseSafe",
            .small => "ReleaseSmall",
            .fast => "ReleaseFast",
        };
    }
};

const Manifest = struct {
    version: []const u8,
};

fn parseLogLevelOption(option: []const u8, name: []const u8) std.log.Level {
    if (std.mem.eql(u8, name, "error")) return .err;
    if (std.mem.eql(u8, name, "warn")) return .warn;
    if (std.mem.eql(u8, name, "info")) return .info;
    if (std.mem.eql(u8, name, "debug")) return .debug;
    std.debug.panic("unknown -D{s} {s}: expected error, warn, info or debug", .{ option, name });
}

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
