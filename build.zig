const std = @import("std");

pub fn build(b: *std.Build) void {
    const target = b.standardTargetOptions(.{});
    const optimize = b.standardOptimizeOption(.{});
    const is_release = optimize != .Debug;

    const exe_mod = b.createModule(.{
        .root_source_file = b.path("src/main.zig"),
        .target = target,
        .optimize = optimize,
        .pic = true,
        .strip = is_release,
        .omit_frame_pointer = is_release,
        .single_threaded = true,
    });

    const exe = b.addExecutable(.{
        .name = "zinit",
        .root_module = exe_mod,
        .version = .{
            .major = 0,
            .minor = 0,
            .patch = 1,
        },
    });

    const clap = b.dependency("clap", .{});
    exe.root_module.addImport("clap", clap.module("clap"));

    const tracing_child = b.option(bool, "tracing-child", "zinit will wait for SIGUSR1 to continue executing child process") orelse false;

    const config = b.addOptions();
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
    });
    const run_exe_unit_tests = b.addRunArtifact(exe_unit_tests);

    const test_step = b.step("test", "Run unit tests");
    test_step.dependOn(&run_exe_unit_tests.step);
}
