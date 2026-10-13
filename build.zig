const std = @import("std");

fn packageVersion(b: *std.Build) std.SemanticVersion {
    const Manifest = struct { version: []const u8 };

    var diagnostics: std.zon.parse.Diagnostics = undefined;
    const manifest = std.zon.parse.fromSlice(Manifest, .{
        .gpa = b.allocator,
        .arena = b.allocator,
        .source = @embedFile("build.zig.zon"),
        .diagnostics = &diagnostics,
        .ignore_unknown_fields = true,
    }) catch |err| {
        diagnostics.log("build.zig.zon");
        std.debug.panic("unable to parse build.zig.zon: {s}", .{@errorName(err)});
    };

    return std.SemanticVersion.parse(manifest.version) catch |err| {
        std.debug.panic("invalid version {s} in build.zig.zon: {s}", .{ manifest.version, @errorName(err) });
    };
}

pub fn build(b: *std.Build) void {
    const target = b.standardTargetOptions(.{ .default_target = .{
        .os_tag = .linux,
    } });
    const optimize = b.standardOptimizeOption(.{});

    const is_release = optimize != .debug;
    const size_analysis = b.option(bool, "size-analysis", "Keep symbols in release builds for bloaty analysis") orelse false;
    const coverage = b.option(bool, "test-coverage", "Generate coverage reports") orelse false;

    const exe_mod = b.createModule(.{ .root_source_file = b.path("src/main.zig"), .target = target, .optimize = optimize, .strip = is_release and !size_analysis, .omit_frame_pointer = is_release, .single_threaded = true, .unwind_tables = if (is_release) .none else .sync, .pic = true });

    const exe = b.addExecutable(.{
        .name = "zinit",
        .root_module = exe_mod,
        .version = packageVersion(b),
    });

    // Leave the ELF stack-size hint at 0. The linker's default makes
    // `std.start` raise RLIMIT_STACK at startup, which the child would then
    // inherit; 0 keeps the container's own limit intact and drops the
    // `prlimit64` dependency.
    exe.stack_size = 0;

    const config = b.addOptions();
    const tracing_child = b.option(bool, "tracing-child", "zinit will wait for SIGUSR1 to continue executing child process") orelse false;
    const stack_traces = b.option(bool, "stack-traces", "Include crash stack traces (segfault handler + std.debug panic); ~120 KB of std.debug/ELF code. Opt-in, off by default.") orelse false;
    config.addOption(std.SemanticVersion, "version", exe.version orelse unreachable);
    config.addOption(bool, "tracing_child", tracing_child);
    config.addOption(bool, "stack_traces", stack_traces);
    exe.root_module.addOptions("config", config);

    b.installArtifact(exe);

    const run_cmd = b.addRunArtifact(exe);
    run_cmd.step.dependOn(b.getInstallStep());
    run_cmd.addPassthruArgs();

    const run_step = b.step("run", "Run the app");
    run_step.dependOn(&run_cmd.step);

    const exe_unit_tests = b.addTest(.{ .root_module = exe_mod, .use_llvm = coverage, .use_lld = coverage });

    const run_exe_unit_tests = b.addRunArtifact(exe_unit_tests);
    if (coverage) {
        const system_kcov = b.addSystemCommand(&.{ "kcov", "--clean", "--include-path=./src", "kcov-output" });
        system_kcov.addArtifactArg(exe_unit_tests);
        run_exe_unit_tests.step.dependOn(&system_kcov.step);
    }

    const test_step = b.step("test", "Run unit tests");
    test_step.dependOn(&run_exe_unit_tests.step);
}
