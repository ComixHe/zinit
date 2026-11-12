// SPDX-FileCopyrightText: 2026 YuMing He <ComixHe1895@outlook.com>
//
// SPDX-License-Identifier: MIT

//! Linux integration checks for the child side

const std = @import("std");
const zinit = @import("zinit");

const supervisor = zinit.supervisor;
const log = zinit.log;
const wait = zinit.wait;
const Sig = zinit.signal.Sig;
const SignalConfig = zinit.signalfd.Config;

const waitForExit = wait.waitForExit;

fn waitForEvent(pid: std.os.linux.pid_t, flags: u32) !i32 {
    return wait.waitForEvent(std.testing.io, pid, flags);
}

fn spawnAndWait(spec: supervisor.SpawnSpec) !u8 {
    const signal_config = try SignalConfig.install(&[_]Sig{.TERM});
    defer _ = signal_config.restoreParent();
    var child_handle = try supervisor.spawn(spec, &signal_config);
    defer child_handle.close();
    errdefer wait.killAndReap(std.testing.io, child_handle.pid);

    const status = try waitForExit(std.testing.io, child_handle.pid);
    return status.exitCode();
}

test "integration: the child resolves a relative command through PATH" {
    const code = try spawnAndWait(.{
        .argv = &[_:null]?[*:0]const u8{"true"},
        .envs = &[_:null]?[*:0]const u8{"PATH=/nonexistent-zinit-dir:/bin:/usr/bin"},
    });

    try std.testing.expectEqual(@as(u8, 0), code);
}

test "integration: a command that cannot be exec'd exits through the child error path" {
    const code = try spawnAndWait(.{
        .argv = &[_:null]?[*:0]const u8{"/nonexistent-zinit-prog"},
    });

    try std.testing.expectEqual(@as(u8, 127), code);
}

test "integration: a bare name that no PATH entry holds fails the same way" {
    const code = try spawnAndWait(.{
        .argv = &[_:null]?[*:0]const u8{"nonexistent-zinit-prog"},
        .envs = &[_:null]?[*:0]const u8{"PATH=/bin:/usr/bin"},
    });

    try std.testing.expectEqual(@as(u8, 127), code);
}

/// Counts the entries in `/proc/self/fd`; the directory's own descriptor is
/// present in both samples, so only growth matters.
fn openFdCount(io: std.Io) !usize {
    var dir = try std.Io.Dir.openDirAbsolute(io, "/proc/self/fd", .{ .iterate = true });
    defer dir.close(io);

    var count: usize = 0;
    var it = dir.iterate();
    while (try it.next(io)) |entry| {
        if (std.mem.eql(u8, entry.name, ".") or std.mem.eql(u8, entry.name, "..")) continue;
        count += 1;
    }
    return count;
}

test "integration: spawning and reaping does not leak descriptors" {
    const io = std.testing.io;
    const before = try openFdCount(io);

    var i: usize = 0;
    while (i < 32) : (i += 1) {
        const code = try spawnAndWait(.{
            .argv = &[_:null]?[*:0]const u8{"/bin/true"},
        });
        try std.testing.expectEqual(@as(u8, 0), code);
    }

    // pidfd, the exec-failure pipe and the signal source must not survive a
    // reap; a leak here accumulates for the life of PID 1.
    try std.testing.expectEqual(before, try openFdCount(io));
}

/// Waits until the child has replaced its image and `/proc/<pid>/status` shows
/// `blocked` set and `cleared` unset. The supervisor blocks every forwarded
/// signal, so this only holds once `execve` restored the caller's mask.
fn waitForSignalMask(pid: std.os.linux.pid_t, blocked: Sig, cleared: Sig) !void {
    const blocked_bit = @as(u64, 1) << @intCast(@backingInt(blocked) - 1);
    const cleared_bit = @as(u64, 1) << @intCast(@backingInt(cleared) - 1);
    const io = std.testing.io;
    const deadline = std.Io.Clock.now(.awake, io).toNanoseconds() + 5 * std.time.ns_per_s;
    var path_buf: [64]u8 = undefined;
    const path = try std.mem.print(&path_buf, "/proc/{d}/status", .{pid});

    while (true) {
        const file = std.Io.Dir.openFileAbsolute(io, path, .{}) catch null;
        if (file) |f| {
            var buf: [4096]u8 = undefined;
            var iov = [_][]u8{&buf};
            const n = f.readStreaming(io, &iov) catch 0;
            f.close(io);

            if (n > 0) {
                const text = buf[0..n];
                if (std.mem.find(u8, text, "SigBlk:")) |at| {
                    const rest = text[at + "SigBlk:".len ..];
                    const end = std.mem.findScalar(u8, rest, '\n') orelse rest.len;
                    const value = std.mem.trim(u8, rest[0..end], " \t");
                    const mask = std.fmt.parseInt(u64, value, 16) catch
                        return error.TestUnexpectedResult;
                    if (mask & blocked_bit != 0 and mask & cleared_bit == 0) return;
                }
            }
        }

        if (std.Io.Clock.now(.awake, io).toNanoseconds() >= deadline)
            return error.TestUnexpectedResult;
        try std.Io.sleep(io, .fromMilliseconds(1), .awake);
    }
}

test "integration: the workload gets the caller's mask, not the supervisor's" {
    const io = std.testing.io;

    // Neither empty nor the supervisor's: the caller keeps SIGUSR2 blocked.
    var caller: std.os.linux.sigset_t = std.os.linux.sigemptyset();
    std.os.linux.sigaddset(&caller, Sig.USR2);
    var saved: std.os.linux.sigset_t = undefined;
    if (zinit.io.syscallErrno(std.os.linux.sigprocmask(Sig.BLOCK, &caller, &saved)) != .SUCCESS)
        return error.TestUnexpectedResult;
    defer _ = std.os.linux.sigprocmask(Sig.SETMASK, &saved, null);

    // Everything forwarded is blocked here, and inherited by the child.
    const signal_config = try SignalConfig.install(&[_]Sig{});
    defer _ = signal_config.restoreParent();

    var spawned = try supervisor.spawn(.{
        .argv = &[_:null]?[*:0]const u8{ "/bin/sleep", "10" },
    }, &signal_config);
    defer spawned.close();
    defer wait.killAndReap(io, spawned.pid);

    // SIGUSR2 comes from the caller; SIGTERM is blocked only by the supervisor,
    // so the mask is right only after `execve` restored `previous_set`.
    try waitForSignalMask(spawned.pid, .USR2, .TERM);
    std.posix.kill(spawned.pid, .TERM) catch return error.TestUnexpectedResult;

    const status = try waitForExit(io, spawned.pid);
    try std.testing.expectEqual(
        @as(u32, @intCast(@backingInt(Sig.TERM))),
        status.signalNumber(),
    );
}

test "integration: a PATH entry that is a file returns 127" {
    const code = try spawnAndWait(.{
        .argv = &[_:null]?[*:0]const u8{"missing-zinit-notdir-command"},
        .envs = &[_:null]?[*:0]const u8{"PATH=/bin/true"},
    });

    try std.testing.expectEqual(@as(u8, 127), code);
}

test "integration: ENOTDIR in an explicit command path returns 127" {
    const code = try spawnAndWait(.{
        .argv = &[_:null]?[*:0]const u8{"/bin/true/missing-zinit-notdir-command"},
    });

    try std.testing.expectEqual(@as(u8, 127), code);
}

test "integration: a relative command is found on the default path when PATH is unset" {
    const code = try spawnAndWait(.{
        .argv = &[_:null]?[*:0]const u8{"true"},
    });

    try std.testing.expectEqual(@as(u8, 0), code);
}

/// Wait until the child is blocked in `number`, so STOP/CONT land inside its
/// wait. This synchronizes the fixture; it is not a product contract (the tracer
/// release itself is covered behaviorally by the smoke suite).
fn waitForSyscall(pid: std.os.linux.pid_t, number: i64) !void {
    const io = std.testing.io;
    const deadline = std.Io.Clock.now(.awake, io).toNanoseconds() + 5 * std.time.ns_per_s;
    var path_buf: [64]u8 = undefined;
    const path = try std.mem.print(&path_buf, "/proc/{d}/syscall", .{pid});

    while (true) {
        const file = std.Io.Dir.openFileAbsolute(io, path, .{}) catch null;
        if (file) |f| {
            var buf: [128]u8 = undefined;
            var iov = [_][]u8{&buf};
            const n = f.readStreaming(io, &iov) catch 0;
            f.close(io);

            if (n > 0) {
                const text = buf[0..n];
                const space = std.mem.findScalar(u8, text, ' ') orelse text.len;
                const current = std.fmt.parseInt(i64, text[0..space], 10) catch -1;
                if (current == number) return;
            }
        }

        if (std.Io.Clock.now(.awake, io).toNanoseconds() >= deadline)
            return error.TestUnexpectedResult;
        try std.Io.sleep(io, .fromMilliseconds(1), .awake);
    }
}

test "integration: a tracing child keeps waiting through STOP and CONT" {
    // Under kcov's ptrace the stop/continue events go to the tracer, not to this test.
    if (wait.underTracer(std.testing.io)) {
        std.debug.print("skip the STOP/CONT check: a tracer owns the events\n", .{});
        return error.SkipZigTest;
    }

    const signal_config = try SignalConfig.install(&[_]Sig{});
    defer _ = signal_config.restoreParent();
    var spawned = try supervisor.spawn(.{
        .argv = &[_:null]?[*:0]const u8{"/bin/true"},
        .tracing_child = true,
    }, &signal_config);
    defer spawned.close();
    const pid = spawned.pid;
    defer wait.killAndReap(std.testing.io, pid);

    const sigtimedwait = @as(i64, @intCast(@backingInt(std.os.linux.SYS.rt_sigtimedwait)));

    try waitForSyscall(pid, sigtimedwait);

    for (0..2) |_| {
        std.posix.kill(pid, Sig.STOP) catch unreachable;
        const stop_status = try waitForEvent(pid, std.os.linux.W.UNTRACED);
        try std.testing.expect(std.os.linux.W.IFSTOPPED(@intCast(stop_status)));

        std.posix.kill(pid, Sig.CONT) catch unreachable;
        const cont_status = try waitForEvent(pid, std.os.linux.W.CONTINUED);
        try std.testing.expectEqual(@as(u32, 0xffff), @as(u32, @intCast(cont_status)) & 0xffff);

        try waitForSyscall(pid, sigtimedwait);
    }

    std.posix.kill(pid, Sig.USR1) catch unreachable;
    const status = try waitForExit(std.testing.io, pid);

    try std.testing.expectEqual(@as(u8, 0), status.exitCode());
}

test "integration: a present but non-executable PATH entry is 126, not 127" {
    var dir_buf: [64]u8 = undefined;
    const dir = try makeTestDir(std.testing.io, &dir_buf, "/tmp/zinit-path-{d}", .{std.os.linux.getpid()});
    defer removeTestDir(std.testing.io, dir);

    var file_buf: [96]u8 = undefined;
    const file = try writeTestFile(&file_buf, dir, "denied", "#!/bin/sh\n", 0o644);
    defer unlinkFile(std.testing.io, file);

    var env_buf: [160]u8 = undefined;
    const env_line = try std.mem.printSentinel(&env_buf, "PATH={s}:/nonexistent-zinit-dir", .{dir}, 0);

    const code = try spawnAndWait(.{
        .argv = &[_:null]?[*:0]const u8{"denied"},
        .envs = &[_:null]?[*:0]const u8{env_line.ptr},
    });

    try std.testing.expectEqual(@as(u8, 126), code);
}

fn makeTestDir(io: std.Io, buf: []u8, comptime format: []const u8, args: anytype) ![:0]const u8 {
    const dir = try std.mem.printSentinel(buf, format, args, 0);
    std.Io.Dir.createDirAbsolute(io, dir, .fromMode(0o700)) catch
        return error.TestUnexpectedResult;
    return dir;
}

fn removeTestDir(io: std.Io, dir: []const u8) void {
    std.Io.Dir.cwd().deleteTree(io, dir) catch {};
}

fn unlinkFile(io: std.Io, path: []const u8) void {
    std.Io.Dir.cwd().deleteFile(io, path) catch {};
}

fn writeTestFile(
    path_buf: []u8,
    dir: []const u8,
    name: []const u8,
    content: []const u8,
    mode: u32,
) ![:0]const u8 {
    const path = try std.mem.printSentinel(path_buf, "{s}/{s}", .{ dir, name }, 0);
    const cwd = std.Io.Dir.cwd();
    const file = try cwd.createFile(std.testing.io, path, .{
        .exclusive = true,
        .permissions = .fromMode(mode),
    });
    errdefer cwd.deleteFile(std.testing.io, path) catch {};
    defer file.close(std.testing.io);
    try file.writeStreamingAll(std.testing.io, content);
    return path;
}

// Serial: this test changes the process-wide working directory for its duration.
test "integration: an empty PATH element and an empty PATH use the working directory" {
    const pid = std.os.linux.getpid();

    var dir_buf: [64]u8 = undefined;
    const dir = try makeTestDir(std.testing.io, &dir_buf, "/tmp/zinit-path-empty-{d}", .{pid});
    defer removeTestDir(std.testing.io, dir);

    var prog_buf: [96]u8 = undefined;
    const prog = try writeTestFile(&prog_buf, dir, "prog", "#!/bin/sh\nexit 0\n", 0o755);
    defer unlinkFile(std.testing.io, prog);

    // execvp reads an empty element, and an empty PATH, as the working directory;
    // the lookup runs in the child, so move the test process for its duration.
    var cwd_buf: [std.os.linux.PATH_MAX]u8 = undefined;
    const n = std.os.linux.getcwd(&cwd_buf, cwd_buf.len);
    if (std.os.linux.errno(n) != .SUCCESS) return error.TestUnexpectedResult;
    const saved: [:0]const u8 = cwd_buf[0 .. n - 1 :0];
    try std.Io.Threaded.chdir(dir);
    defer std.Io.Threaded.chdir(saved) catch {};

    for ([_][]const u8{ "", ":/bin", "/bin:" }) |path_value| {
        var env_buf: [32]u8 = undefined;
        const env_line = try std.mem.printSentinel(&env_buf, "PATH={s}", .{path_value}, 0);

        const code = try spawnAndWait(.{
            .argv = &[_:null]?[*:0]const u8{"prog"},
            .envs = &[_:null]?[*:0]const u8{env_line.ptr},
        });

        try std.testing.expectEqual(@as(u8, 0), code);
    }
}

test "integration: an ENOEXEC candidate is reported, not skipped for another PATH entry" {
    const pid = std.os.linux.getpid();

    var a_buf: [64]u8 = undefined;
    const a = try makeTestDir(std.testing.io, &a_buf, "/tmp/zinit-enoexec-a-{d}", .{pid});
    defer removeTestDir(std.testing.io, a);
    var b_buf: [64]u8 = undefined;
    const b = try makeTestDir(std.testing.io, &b_buf, "/tmp/zinit-enoexec-b-{d}", .{pid});
    defer removeTestDir(std.testing.io, b);

    var bad_buf: [96]u8 = undefined;
    const bad = try writeTestFile(&bad_buf, a, "probe", "not an executable format\n", 0o755);
    defer unlinkFile(std.testing.io, bad);

    var good_buf: [96]u8 = undefined;
    const good = try writeTestFile(&good_buf, b, "probe", "#!/bin/sh\nexit 23\n", 0o755);
    defer unlinkFile(std.testing.io, good);

    var env_buf: [200]u8 = undefined;
    const env_line = try std.mem.printSentinel(&env_buf, "PATH={s}:{s}", .{ a, b }, 0);

    const code = try spawnAndWait(.{
        .argv = &[_:null]?[*:0]const u8{"probe"},
        .envs = &[_:null]?[*:0]const u8{env_line.ptr},
    });

    try std.testing.expectEqual(@as(u8, 126), code);
}

test "integration: the child restores TTIN and TTOU instead of inheriting the ignore" {
    // Under kcov's ptrace the stop events go to the tracer, not to this test.
    if (wait.underTracer(std.testing.io)) {
        std.debug.print("skip the TTIN/TTOU restore check: a tracer owns the stop events\n", .{});
        return error.SkipZigTest;
    }

    // zinit ignores TTIN/TTOU in the parent. A child that inherited SIG_IGN would
    // skip the stop and reach `exit 7`, so a stop event proves the restore.
    const signal_config = try SignalConfig.install(&[_]Sig{});
    defer _ = signal_config.restoreParent();

    for ([_][]const u8{ "TTIN", "TTOU" }) |name| {
        var script_buf: [64]u8 = undefined;
        const script = try std.mem.printSentinel(&script_buf, "kill -{s} $$; exit 7", .{name}, 0);

        var spawned = try supervisor.spawn(.{
            .argv = &[_:null]?[*:0]const u8{ "/bin/sh", "-c", script },
        }, &signal_config);
        defer spawned.close();
        const pid = spawned.pid;
        defer wait.killAndReap(std.testing.io, pid);

        const status = try waitForEvent(pid, std.os.linux.W.UNTRACED);
        try std.testing.expect(std.os.linux.W.IFSTOPPED(@intCast(status)));
        std.posix.kill(pid, Sig.KILL) catch unreachable;
        _ = try waitForExit(std.testing.io, pid);
    }
}

test "integration: an oversized environment reports E2BIG and exits 1" {
    const io = std.testing.io;
    const allocator = std.testing.allocator;

    // The supervisor logs the exec error the child sent through the CLOEXEC
    // pipe; point the shared sink at a pipe so the test observes the output.
    const fds = try std.Io.Threaded.pipe2(.{ .NONBLOCK = true });
    const reader = std.Io.File{ .handle = fds[0], .flags = .{ .nonblocking = true } };
    const writer = std.Io.File{ .handle = fds[1], .flags = .{ .nonblocking = true } };
    defer reader.close(io);
    defer writer.close(io);
    try log.init(writer.handle);
    defer log.deinit();

    // One string above MAX_ARG_STRLEN (128 KiB) makes execve fail with E2BIG.
    const huge = try allocator.alloc(u8, 200_000);
    defer allocator.free(huge);
    @memset(huge, 'x');
    const env_line = try allocator.allocSentinel(u8, "BIG=".len + huge.len, 0);
    defer allocator.free(env_line);
    @memcpy(env_line[0.."BIG=".len], "BIG=");
    @memcpy(env_line["BIG=".len..][0..huge.len], huge);

    // Run the real supervisor, not a direct spawn: it is the component that
    // turns the child's CLOEXEC record into the log line this test observes.
    const signal_config = try SignalConfig.install(&[_]Sig{.TERM});
    defer _ = signal_config.restoreParent();
    var spawned = try supervisor.spawn(.{
        .argv = &[_:null]?[*:0]const u8{"/bin/true"},
        .envs = &[_:null]?[*:0]const u8{env_line.ptr},
    }, &signal_config);

    const code = switch (supervisor.supervise(.{
        .expected_exit = .empty,
        .rewrites = null,
        .forward_group = false,
        .shutdown_timeout_ns = 0,
        .ignore_initial_hup_cont = false,
    }, &signal_config, &spawned)) {
        .exited => |exit_code| exit_code,
        .failed => return error.TestUnexpectedResult,
    };
    try std.testing.expectEqual(@as(u8, 1), code);

    var buf: [1024]u8 = undefined;
    var iov = [_][]u8{&buf};
    const n = reader.readStreaming(io, &iov) catch 0;
    const text = buf[0..n];
    try std.testing.expect(text.len > 0);
    try std.testing.expect(std.mem.find(u8, text, "E2BIG") != null);
}
