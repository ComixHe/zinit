// SPDX-FileCopyrightText: 2025 - 2026 YuMing He <ComixHe1895@outlook.com>
//
// SPDX-License-Identifier: MIT

const std = @import("std");
const builtin = @import("builtin");

pub fn build(b: *std.Build) void {
    const config = Config.init(b);
    const runtime_config = config.forRuntime(b);

    const config_mod = addConfig(b, config);
    // One module for the shared CLI helpers: a second instance would compile the
    // same file twice (`cli` vs `cli0`) and Zig rejects it in one module graph.
    const cli_module = addCliModule(b);
    const release_module = addReleaseModule(b, cli_module);
    const strip_module = addStripModule(b, cli_module);
    const lib = addLibrary(b, runtime_config, config_mod);
    const app = addApp(b, runtime_config, config_mod, lib);
    const exe = addExecutable(b, runtime_config, app);

    installAndRun(b, exe);
    const test_config = config.forTests(b);
    const test_exe = if (test_config.optimize == config.optimize) exe else blk: {
        const test_runtime = test_config.forRuntime(b);
        const test_lib = addLibrary(b, test_runtime, config_mod);
        break :blk addExecutable(b, test_runtime, addApp(b, test_runtime, config_mod, test_lib));
    };

    const e2e_tool = addHostTool(b, "e2e", "tests/e2e.zig");
    const e2e_run = addE2eStep(b, e2e_tool, test_exe, test_config);
    const internal_step = addInternalStep(b, test_config, config_mod);
    const tools_step = addToolsStep(b, release_module, strip_module);
    const pid1_step = addPid1Step(b, test_config, test_exe);

    const test_step = b.step("test", "Run the E2E suite, internal checks, tools and PID 1");
    test_step.dependOn(&e2e_run.step);
    test_step.dependOn(internal_step);
    test_step.dependOn(tools_step);
    test_step.dependOn(pid1_step);

    addFuzzStep(b, test_config, config_mod);
    const symbols = addSymbolPair(b, runtime_config, config_mod, strip_module);
    addSymbolsStep(b, symbols);

    addSizeStep(b, exe);
    const packer = addReleaseTool(b, release_module);
    addReleaseStep(b, exe, config, symbols, packer);
}

fn moduleOptions(config: Config) std.Build.Module.CreateOptions {
    const is_release = config.isRelease();

    return .{
        .target = config.target,
        .optimize = config.optimize,
        // FullPanic needs debug info, frame pointers and unwind tables. Keep
        // them when stack traces are explicitly requested, even in a release.
        .strip = is_release and !config.size_analysis and !config.stack_traces,
        .omit_frame_pointer = is_release and !config.stack_traces,
        .single_threaded = true,
        .unwind_tables = if (config.stack_traces or !is_release) .sync else .none,
    };
}

fn addConfig(b: *std.Build, config: Config) *std.Build.Module {
    const options = b.addOptions();

    options.addOption([]const u8, "version", config.manifest.version);
    options.addOption(bool, "tracing_child", config.tracing_child);
    options.addOption(bool, "stack_traces", config.stack_traces);
    options.addOption(bool, "pie", config.pie);
    options.addOption(std.log.Level, "max_log_level", config.max_log_level);
    options.addOption(std.log.Level, "default_log_level", config.default_log_level);

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

fn addHostTool(b: *std.Build, name: []const u8, path: []const u8) *std.Build.Step.Compile {
    return b.addExecutable(.{
        .name = name,
        .root_module = b.createModule(.{
            .root_source_file = b.path(path),
            .target = b.graph.host,
            .optimize = .safe,
        }),
    });
}

fn boundTestRun(b: *std.Build, run: *std.Build.Step.Run, limit: []const u8) *std.Build.Step.Run {
    run.argv.insertSlice(b.allocator, 0, &.{
        .{ .bytes = "/bin/sh" },
        .{ .lazy_path = .{
            .prefix = "",
            .suffix = "",
            .lazy_path = b.path("tools/run_test.sh"),
            .make_absolute = true,
        } },
        .{ .bytes = limit },
    }) catch @panic("OOM");
    run.has_side_effects = true;
    return run;
}

fn boundUnitRun(b: *std.Build, run: *std.Build.Step.Run) *std.Build.Step.Run {
    run.argv.insertSlice(b.allocator, 0, &.{
        .{ .bytes = "timeout" },
        .{ .bytes = "--signal=KILL" },
        .{ .bytes = "60s" },
    }) catch @panic("OOM");
    run.has_side_effects = true;
    return run;
}

fn addE2eStep(
    b: *std.Build,
    tool: *std.Build.Step.Compile,
    exe: *std.Build.Step.Compile,
    config: Config,
) *std.Build.Step.Run {
    const install_runner = b.addInstallArtifact(tool, .{ .dest_sub_path = "e2e" });
    b.step("e2e-runner", "Build the E2E runner without selecting a zinit binary")
        .dependOn(&install_runner.step);

    const override = b.option([]const u8, "e2e-zinit", "Run E2E against this binary instead of the built one");
    // seccomp filters and process observation only mean something when the
    // runner and the binary under test share the host kernel ABI. qemu-user is
    // explicitly not a substitute for a native behavioral run.
    const native_guard = if (override == null) nativeTargetGuard(b, config, "test-e2e") else null;

    const health_run = boundTestRun(b, b.addRunArtifact(tool), "60s");
    addE2eTarget(health_run, override, exe);
    health_run.addArgs(&.{ "--expect-version", config.manifest.version, "--health" });
    if (native_guard) |guard| health_run.step.dependOn(guard);
    b.step("smoke", "Run the artifact health gate on the built binary").dependOn(&health_run.step);

    const e2e_run = boundTestRun(b, b.addRunArtifact(tool), "120s");
    addE2eTarget(e2e_run, override, exe);
    e2e_run.addArgs(&.{
        "--expect-version", config.manifest.version,
        "--max-log-level",  @tagName(config.max_log_level),
    });

    if (native_guard) |guard| e2e_run.step.dependOn(guard);
    b.step("test-e2e", "Run the full CLI behavior matrix (signals, PTY, orphans, exec)")
        .dependOn(&e2e_run.step);

    return e2e_run;
}

fn addE2eTarget(
    run: *std.Build.Step.Run,
    override: ?[]const u8,
    exe: *std.Build.Step.Compile,
) void {
    run.addArg("--zinit");
    if (override) |path| {
        run.addArg(path);
    } else {
        run.addFileArg(exe.getEmittedBin());
    }
}

fn nativeTargetGuard(b: *std.Build, config: Config, step: []const u8) ?*std.Build.Step {
    const host = b.graph.host.result;
    if (config.target.result.cpu.arch == host.cpu.arch and
        config.target.result.os.tag == host.os.tag) return null;

    return &b.addFail(b.fmt(
        "{s} requires a native target: requested {s}-{s}, host is {s}-{s}. " ++
            "Run the suite on the target architecture; qemu-user cannot make seccomp or " ++
            "process-observation checks meaningful. For a prebuilt binary, use " ++
            "-De2e-zinit=<path> with the native runner.",
        .{
            step,
            @tagName(config.target.result.cpu.arch),
            @tagName(config.target.result.os.tag),
            @tagName(host.cpu.arch),
            @tagName(host.os.tag),
        },
    )).step;
}

fn addFuzzStep(b: *std.Build, config: Config, config_mod: *std.Build.Module) void {
    var options = moduleOptions(config);
    options.root_source_file = b.path("lib/fuzz_tests.zig");
    options.imports = &.{.{ .name = "config", .module = config_mod }};
    // The fuzz runtime is not single-threaded: with it the rebuilt binary segfaults in its own fuzzer.
    options.single_threaded = false;
    // Optimized fuzz builds still need symbols for coverage and crash reports.
    options.strip = false;
    options.omit_frame_pointer = false;
    options.unwind_tables = .sync;

    const fuzz_tests = b.addTest(.{ .root_module = b.createModule(options) });
    const run_fuzz = boundTestRun(b, b.addRunArtifact(fuzz_tests), "40m");

    b.step("fuzz", "Fuzz the pure parsers, formatters and status decoding (--fuzz=100K)")
        .dependOn(&run_fuzz.step);
}

fn addTestArtifact(
    b: *std.Build,
    root_module: *std.Build.Module,
    filters: []const []const u8,
    name: []const u8,
) *std.Build.Step.Compile {
    return b.addTest(.{
        .name = name,
        .root_module = root_module,
        .filters = filters,
    });
}

fn addInternalStep(
    b: *std.Build,
    config: Config,
    config_mod: *std.Build.Module,
) *std.Build.Step {
    var options = moduleOptions(config);
    options.root_source_file = b.path("lib/internal_tests.zig");
    options.imports = &.{.{ .name = "config", .module = config_mod }};

    const artifact = addTestArtifact(b, b.createModule(options), &.{}, "internal");
    const step = b.step("test-internal", "Run retained property checks and internal fault reproductions");
    step.dependOn(&boundUnitRun(b, b.addRunArtifact(artifact)).step);
    return step;
}

fn addToolsStep(
    b: *std.Build,
    release_module: *std.Build.Module,
    strip_module: *std.Build.Module,
) *std.Build.Step {
    const step = b.step("test-tools", "Run the host-side release and strip tool tests");
    for (
        [_]*std.Build.Module{ release_module, strip_module },
        [_][]const u8{ "release-unit", "strip-unit" },
    ) |module, name| {
        const artifact = b.addTest(.{ .name = name, .root_module = module });
        step.dependOn(&boundUnitRun(b, b.addRunArtifact(artifact)).step);
    }
    return step;
}

/// zinit must be PID 1 for these checks: a normal test process is not. The
/// script creates its own PID namespace, so a lack of permission is an error,
/// not a silent pass.
fn addPid1Step(b: *std.Build, config: Config, exe: *std.Build.Step.Compile) *std.Build.Step {
    const native_guard = nativeTargetGuard(b, config, "test-pid1");
    const run = b.addSystemCommand(&.{ "/bin/sh", "tools/pid1.sh", "--bounded" });
    run.addFileArg(exe.getEmittedBin());
    if (native_guard) |guard| run.step.dependOn(guard);
    const step = b.step("test-pid1", "Run zinit as PID 1 in disposable PID namespaces");
    step.dependOn(&run.step);
    return step;
}

fn addCliModule(b: *std.Build) *std.Build.Module {
    return b.createModule(.{
        .root_source_file = b.path("tools/cli.zig"),
        .target = b.graph.host,
        .optimize = .safe,
    });
}

fn addReleaseModule(b: *std.Build, cli_module: *std.Build.Module) *std.Build.Module {
    return b.createModule(.{
        .root_source_file = b.path("tools/release.zig"),
        .target = b.graph.host,
        .optimize = .safe,
        .imports = &.{.{ .name = "cli", .module = cli_module }},
    });
}

fn addReleaseTool(b: *std.Build, release_module: *std.Build.Module) *std.Build.Step.Compile {
    return b.addExecutable(.{ .name = "release-tool", .root_module = release_module });
}

const SymbolPair = struct {
    stripped: std.Build.LazyPath,
    dbg: std.Build.LazyPath,
};

/// `-fstrip` changes code layout by a few bytes, so rebuilding with debug info
/// cannot symbolize an already-stripped artifact. Build the same source once
/// with debug info, keep that file as the symbol source, and strip a copy: the
/// `.dbg` and the shipped binary then describe the same addresses.
fn addSymbolPair(
    b: *std.Build,
    runtime_config: Config,
    config_mod: *std.Build.Module,
    strip_module: *std.Build.Module,
) SymbolPair {
    var debug_config = runtime_config;
    debug_config.size_analysis = true;

    const lib = addLibrary(b, debug_config, config_mod);
    const app = addApp(b, debug_config, config_mod, lib);
    const exe = addExecutable(b, debug_config, app);

    const strip = b.addRunArtifact(addStripTool(b, strip_module));
    strip.addFileArg(exe.getEmittedBin());
    const stripped = strip.addOutputFileArg("zinit");

    return .{ .stripped = stripped, .dbg = exe.getEmittedBin() };
}

/// Host-side ELF64 section stripper. `zig objcopy` does not implement
/// `--strip-all`/`--only-keep-debug` for ELF, and a host binutils often cannot
/// strip a cross-compiled aarch64/riscv64 artifact, so the step is local.
fn addStripModule(b: *std.Build, cli_module: *std.Build.Module) *std.Build.Module {
    return b.createModule(.{
        .root_source_file = b.path("tools/strip.zig"),
        .target = b.graph.host,
        .optimize = .safe,
        .imports = &.{.{ .name = "cli", .module = cli_module }},
    });
}

fn addStripTool(b: *std.Build, strip_module: *std.Build.Module) *std.Build.Step.Compile {
    return b.addExecutable(.{ .name = "strip", .root_module = strip_module });
}

fn addSymbolsStep(b: *std.Build, pair: SymbolPair) void {
    const install_bin = b.addInstallFileWithDir(pair.stripped, .{ .custom = "dbg" }, "zinit");
    const install_dbg = b.addInstallFileWithDir(pair.dbg, .{ .custom = "dbg" }, "zinit.dbg");

    const step = b.step("symbols", "Build the stripped binary and the matching .dbg for crash symbolization");
    step.dependOn(&install_bin.step);
    step.dependOn(&install_dbg.step);
}

fn addReleaseStep(
    b: *std.Build,
    exe: *std.Build.Step.Compile,
    config: Config,
    symbols: SymbolPair,
    packer: *std.Build.Step.Compile,
) void {
    const step = b.step("release", "Assemble the release archive for -Dtarget/-Doptimize");
    const sbom = b.option(bool, "sbom", "Also write the SPDX SBOM next to the archive") orelse false;
    const commit = b.option([]const u8, "commit", "Source commit recorded in the SBOM") orelse "unknown";
    // SOURCE_DATE_EPOCH is an input, not an ambient side effect: pass it to the
    // packer as an argument so the Run step's cache key includes it.
    const epoch = b.option([]const u8, "epoch", "SOURCE_DATE_EPOCH recorded in the SBOM") orelse
        b.graph.environ_map.get("SOURCE_DATE_EPOCH");

    const archive_name = b.fmt("zinit-{s}-{s}-{s}", .{
        config.manifest.version,
        config.shortTarget(b),
        config.optimizeName(),
    });
    const archive_file = b.fmt("{s}.tar.gz", .{archive_name});
    const debug_file = b.fmt("{s}-dbg.tar.gz", .{archive_name});
    const sbom_file = b.fmt("{s}.spdx.json", .{archive_name});

    // Declared outputs keep the archive in the build graph instead of writing
    // to a hardcoded directory behind the build's back.
    const pack = b.addRunArtifact(packer);
    pack.addArg("--binary");
    if (config.stack_traces) {
        pack.addFileArg(exe.getEmittedBin());
    } else {
        // No runtime DWARF to keep: ship the stripped copy and a separate
        // symbols archive built from the same link for offline symbolization.
        pack.addFileArg(symbols.stripped);
        pack.addArgs(&.{"--debug-symbols"});
        pack.addFileArg(symbols.dbg);
    }
    pack.addArgs(&.{ "--name", archive_name, "--archive" });
    const archive = pack.addOutputFileArg(archive_file);
    const debug_archive: ?std.Build.LazyPath = if (config.stack_traces) null else blk: {
        pack.addArg("--debug-archive");
        break :blk pack.addOutputFileArg(debug_file);
    };
    if (epoch) |seconds| pack.addArgs(&.{ "--epoch", seconds });
    pack.addArg("--license");
    pack.addFileArg(b.path("LICENSE"));
    pack.addArg("--readme");
    pack.addFileArg(b.path("README.md"));

    const sbom_artifact: ?std.Build.LazyPath = if (sbom) blk: {
        pack.addArgs(&.{ "--sbom", "--sbom-out" });
        const path = pack.addOutputFileArg(sbom_file);
        pack.addArgs(&.{
            "--version",
            config.manifest.version,
            "--zig",
            builtin.zig_version_string,
            "--commit",
            commit,
        });
        break :blk path;
    } else null;

    const install_archive = b.addInstallFileWithDir(archive, .{ .custom = "artifacts" }, archive_file);
    step.dependOn(&install_archive.step);

    if (debug_archive) |path| {
        const install = b.addInstallFileWithDir(path, .{ .custom = "artifacts" }, debug_file);
        step.dependOn(&install.step);
    }
    if (sbom_artifact) |path| {
        const install = b.addInstallFileWithDir(path, .{ .custom = "artifacts" }, sbom_file);
        step.dependOn(&install.step);
    }
}

fn addSizeStep(b: *std.Build, exe: *std.Build.Step.Compile) void {
    const script =
        "size=$(stat -c%s \"$1\")\n" ++
        "echo \"zinit: $size bytes (budget 21504)\"\n" ++
        "test \"$size\" -le 21504";
    const run = b.addSystemCommand(&.{ "/bin/sh", "-c", script, "size-check" });
    run.addFileArg(exe.getEmittedBin());
    b.step("check-size", "Assert the built binary stays within the 21 KiB budget")
        .dependOn(&run.step);
}

const Config = struct {
    target: std.Build.ResolvedTarget,
    optimize: std.lang.Optimize,
    manifest: Manifest,
    size_analysis: bool,
    tracing_child: bool,
    stack_traces: bool,
    max_log_level: std.log.Level,
    default_log_level: std.log.Level,
    pie: bool,

    fn forTests(self: Config, b: *std.Build) Config {
        var tests = self;
        // Preserve the ordinary build's default and explicit -Doptimize or
        // --release choices, while making test commands safe by default.
        if (!b.user_input_options.contains("optimize") and b.graph.release_mode == .off)
            tests.optimize = .safe;
        return tests;
    }

    /// Host kernel detection and an explicit newer -Dtarget must not remove the
    /// shipped binary's compatibility paths. The architectures began at different
    /// Linux versions; tests/tools retain the compiler's development baseline.
    fn forRuntime(self: Config, b: *std.Build) Config {
        var runtime = self;
        var query = self.target.query;
        query.os_version_min = .{ .semver = .{ .major = 4, .minor = 19, .patch = 0 } };
        runtime.target = b.resolveTargetQuery(query);
        return runtime;
    }

    fn init(b: *std.Build) Config {
        const optimize = b.standardOptimizeOption(.{});
        return .{
            .target = b.standardTargetOptions(.{ .default_target = .{ .os_tag = .linux } }),
            .optimize = optimize,
            .manifest = readManifest(b),
            .size_analysis = b.option(bool, "size-analysis", "Keep symbols in builds") orelse false,
            .tracing_child = b.option(bool, "tracing-child", "zinit will wait for SIGUSR1 to continue executing child process") orelse false,
            // ReleaseSmall is the size-constrained variant: keep its panic message-only.
            // Every other optimize mode keeps the crash reporter unless explicitly disabled.
            .stack_traces = b.option(bool, "stack-traces", "Include crash stack traces (segfault handler + std.debug panic). On by default for every optimize mode except ReleaseSmall; keeps debug info and unwind data, so those binaries are much larger.") orelse (optimize != .small),
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
