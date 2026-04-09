const std = @import("std");

pub fn build(b: *std.Build) void {
    // only support linux for now
    const target = b.standardTargetOptions(.{ .default_target = .{
        .os_tag = .linux,
        .abi = .musl,
    } });
    const optimize = b.standardOptimizeOption(.{});

    const is_release = optimize != .Debug;
    const size_analysis = b.option(bool, "size-analysis", "Keep symbols in release builds for bloaty analysis") orelse false;
    const coverage = b.option(bool, "test-coverage", "Generate coverage reports") orelse false;

    const exe_mod = b.createModule(.{
        .root_source_file = b.path("src/main.zig"),
        .target = target,
        .optimize = optimize,
        .strip = is_release and !size_analysis,
        .omit_frame_pointer = is_release,
        .single_threaded = true,
        .unwind_tables = if (is_release) .none else .sync,
        .link_libc = false,
        .link_libcpp = false,
        .error_tracing = !is_release,
    });

    const exe = b.addExecutable(.{
        .name = "zinit",
        .root_module = exe_mod,
        .version = .{
            .major = 0,
            .minor = 1,
            .patch = 0,
        },
    });

    const clap = b.dependency("clap", .{});
    exe.root_module.addImport("clap", clap.module("clap"));

    const config = b.addOptions();
    const tracing_child = b.option(bool, "tracing-child", "zinit will wait for SIGUSR1 to continue executing child process") orelse false;
    config.addOption(std.SemanticVersion, "version", exe.version orelse unreachable);
    config.addOption(bool, "tracing_child", tracing_child);
    exe.root_module.addOptions("config", config);

    b.installArtifact(exe);

    const run_cmd = b.addRunArtifact(exe);
    run_cmd.step.dependOn(b.getInstallStep());

    if (b.args) |args| {
        run_cmd.addArgs(args);
    }

    const run_step = b.step("run", "Run the app");
    run_step.dependOn(&run_cmd.step);

    const exe_unit_tests = b.addTest(.{
        .root_module = exe_mod,
        .use_llvm = coverage,
        .use_lld = coverage,
    });

    if (coverage) {
        exe_unit_tests.setExecCmd(&[_]?[]const u8{
            "kcov",
            "--clean",
            "--include-path=./src",
            "kcov-output",
            null,
        });
    }

    const run_exe_unit_tests = b.addRunArtifact(exe_unit_tests);
    const test_step = b.step("test", "Run unit tests");
    test_step.dependOn(&run_exe_unit_tests.step);
}
