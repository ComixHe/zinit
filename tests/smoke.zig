// SPDX-FileCopyrightText: 2026 YuMing He <ComixHe1895@outlook.com>
//
// SPDX-License-Identifier: MIT

//! End-to-end checks against the real binary: signal delivery, exit status and
//! shutdown, which the unit tests cannot see because they script syscall results
//! instead of asking a kernel. Invoked by `zig build smoke`.
//!
//! The forwarding checks need Linux 5.3 (`pidfd_open`) to queue a signal with a value.
//!
//! Usage: smoke --zinit <path>
//!        smoke --responder <rt|plain>   (run by zinit as its child)

const std = @import("std");

const rt_signal: std.os.linux.SIG = @fromBackingInt(@intCast(std.os.linux.sigrtmin() + 2));

const deadline: std.Io.Timeout = .{ .duration = .{ .raw = .fromSeconds(10), .clock = .awake } };

pub fn main(init: std.process.Init) !void {
    const argv = init.minimal.args;

    if (hasArg(argv, "--responder")) std.process.exit(try responder(argv));

    const arena = init.arena.allocator();

    var env = try init.environ_map.clone(arena);
    try env.put("ZINIT_TRACING_CHILD", "OFF");

    var suite: Suite = .{ .io = init.io, .arena = arena, .env = &env };
    const zinit = positional(argv, "--zinit");
    const self_exe = argv0(argv);

    suite.check("exit code", &.{
        zinit, "--", "/bin/sh", "-c", "exit 7",
    }, .{ .code = 7 });

    // `exec`, not a second `sleep`: a forked one can win the race against the forwarded
    // signal, outlive zinit and hold these pipes open until the deadline, which reads as
    // a timeout instead of a failed forward.
    suite.check("signal forwarding", &.{
        zinit, "--", "/bin/sh", "-c", "sleep 0.2; kill -TERM $PPID; exec sleep 30",
    }, .{ .code = 128 + @backingInt(std.posix.SIG.TERM) });

    suite.check("realtime payload", &.{
        zinit, "--", self_exe, "--responder", "rt",
    }, .{ .code = 0, .has = &.{ "code=-1", "sender_is_self=false", "value=57005" } });

    suite.check("plain signal", &.{
        zinit, "--", self_exe, "--responder", "plain",
    }, .{ .code = 0, .has = &.{ "code=0", "sender_is_self=false" } });

    suite.check("expected exit mapping", &.{
        zinit, "-e", "143", "--", "/bin/sh", "-c", "kill -TERM $$",
    }, .{ .code = 0 });

    suite.check("an adopted descendant does not hold the exit", &.{
        zinit, "-s", "-t", "1", "--", "/bin/sh", "-c", "/bin/sh -c \"sleep 30\" & exit 0",
    }, .{ .code = 0 });

    suite.check("a TERM-ignoring descendant cannot outlast the grace period", &.{
        zinit, "-s", "-t", "1", "--", "/bin/sh", "-c", "trap '' TERM; sleep 30 & sleep 0.5; exit 0",
    }, .{ .code = 0 });

    suite.check("fails when it cannot get a descriptor", &.{
        "/bin/sh", "-c", "ulimit -n 3; exec \"$0\" -- /bin/true", zinit,
    }, .{ .code = 1 });

    suite.check("gives up when the signalfd cannot be created", &.{
        "/bin/sh", "-c", "ulimit -n 4; exec \"$0\" -- /bin/sleep 30", zinit,
    }, .{ .code = 1 });

    suite.check("exec failure", &.{
        zinit, "--", "/nonexistent-zinit-prog",
    }, .{ .code = 127 });

    try suite.tracing(zinit);
    try suite.orphanSurvives(zinit);

    if (suite.failures != 0) {
        std.debug.print("smoke: {d} failed\n", .{suite.failures});
        std.process.exit(1);
    }

    std.debug.print("smoke: all checks passed\n", .{});
}

const Expect = struct {
    code: u8,
    has: []const []const u8 = &.{},
};

const Suite = struct {
    io: std.Io,
    arena: std.mem.Allocator,
    env: *const std.process.Environ.Map,
    failures: usize = 0,

    fn check(self: *Suite, name: []const u8, argv: []const []const u8, expect: Expect) void {
        const result = std.process.run(self.arena, self.io, .{
            .argv = argv,
            .environ_map = self.env,
            .timeout = deadline,
        }) catch |err| return self.fail(name, "{t}", .{err});

        const code: u8 = switch (result.term) {
            .exited => |exit_code| exit_code,
            else => 255,
        };

        var has = true;
        for (expect.has) |text| {
            const found = std.mem.indexOf(u8, result.stdout, text) != null or
                std.mem.indexOf(u8, result.stderr, text) != null;
            if (!found) has = false;
        }

        if (code == expect.code and has) {
            std.debug.print("  ok   {s}\n", .{name});
            return;
        }

        self.failures += 1;
        std.debug.print("  FAIL {s}: expected exit {d}", .{ name, expect.code });
        for (expect.has) |text| std.debug.print(" and output containing \"{s}\"", .{text});
        std.debug.print("\n    got     {f}\n    stdout  {s}\n    stderr  {s}\n", .{
            result.term, result.stdout, result.stderr,
        });
    }

    fn tracing(self: *Suite, zinit: []const u8) !void {
        const name = "tracing holds the child until SIGUSR1";

        var on = try self.env.clone(self.arena);
        try on.put("ZINIT_TRACING_CHILD", "ON");

        var child = std.process.spawn(self.io, .{
            .argv = &.{ zinit, "--", "/bin/sh", "-c", "exit 3" },
            .environ_map = &on,
            .stdin = .ignore,
            .stdout = .ignore,
            .stderr = .ignore,
        }) catch |err| return self.fail(name, "{t}", .{err});

        try std.Io.sleep(self.io, .fromSeconds(1), .awake);

        const pid: std.posix.pid_t = @intCast(child.id.?);
        var status: i32 = 0;
        if (std.os.linux.waitpid(pid, &status, std.os.linux.W.NOHANG) != 0)
            return self.fail(name, "zinit left before the release: the child was not held", .{});

        std.posix.kill(pid, .USR1) catch |err|
            return self.fail(name, "nothing left to release ({t})", .{err});

        // `Child.wait` has no deadline, so a zinit that never exits would hang the suite
        // until the job's own timeout. Give the release five seconds instead.
        var spins: usize = 0;
        while (std.os.linux.waitpid(pid, &status, std.os.linux.W.NOHANG) != @as(usize, @intCast(pid))) {
            spins += 1;
            if (spins > 500) {
                child.kill(self.io);
                return self.fail(name, "zinit did not exit within 5s of the release", .{});
            }
            try std.Io.sleep(self.io, .fromMilliseconds(10), .awake);
        }
        child.id = null;

        const raw: u32 = @intCast(status);
        const code: ?u8 = if (std.os.linux.W.IFEXITED(raw))
            std.os.linux.W.EXITSTATUS(raw)
        else
            null;

        if (code == 3) {
            std.debug.print("  ok   {s}\n", .{name});
            return;
        }

        self.failures += 1;
        std.debug.print("  FAIL {s}: expected the released child to exit 3, got {?d}\n", .{ name, code });
    }

    fn orphanSurvives(self: *Suite, zinit: []const u8) !void {
        const name = "without -s, a grandchild is not zinit's to reap";

        const result = std.process.run(self.arena, self.io, .{
            .argv = &.{
                zinit,                                        "--", "/bin/sh", "-c",
                "sleep 30 >/dev/null 2>&1 & echo $!; exit 0",
            },
            .environ_map = self.env,
            .timeout = deadline,
        }) catch |err| return self.fail(name, "{t}", .{err});

        const code: u8 = switch (result.term) {
            .exited => |exit_code| exit_code,
            else => 255,
        };
        if (code != 0) return self.fail(name, "expected exit 0, got {d}", .{code});

        const pid = std.fmt.parseInt(std.posix.pid_t, std.mem.trim(u8, result.stdout, " \n"), 10) catch
            return self.fail(name, "no pid in the child's output: {s}", .{result.stdout});

        const alive = processAlive(pid);
        _ = std.posix.kill(pid, .KILL) catch {};
        if (!alive) return self.fail(name, "zinit tore the orphan down anyway", .{});

        std.debug.print("  ok   {s}\n", .{name});
    }

    fn fail(self: *Suite, name: []const u8, comptime format: []const u8, args: anytype) void {
        self.failures += 1;
        std.debug.print("  FAIL {s}: " ++ format ++ "\n", .{name} ++ args);
    }
};

fn processAlive(pid: std.posix.pid_t) bool {
    return std.os.linux.errno(std.os.linux.kill(pid, @fromBackingInt(@as(u32, 0)))) == .SUCCESS;
}

fn responder(args: std.process.Args) !u8 {
    var iter = args.iterate();
    while (iter.next()) |arg| {
        if (!std.mem.eql(u8, arg, "--responder")) continue;

        const kind = iter.next() orelse return 2;
        if (std.mem.eql(u8, kind, "rt")) {
            arm(rt_signal);
            try queueToParent(rt_signal);
        } else {
            arm(std.posix.SIG.TERM);
            _ = std.os.linux.kill(std.os.linux.getppid(), std.posix.SIG.TERM);
        }

        while (!@as(*volatile bool, &answered).*) _ = std.os.linux.pause();
        return report();
    }

    return 2;
}

var answered: bool = false;
var received: std.os.linux.siginfo_t = undefined;

fn onSignal(_: std.os.linux.SIG, info: *const std.os.linux.siginfo_t, _: ?*anyopaque) callconv(.c) void {
    received = info.*;
    @as(*volatile bool, &answered).* = true;
}

fn arm(sig: std.os.linux.SIG) void {
    const action: std.os.linux.Sigaction = .{
        .handler = .{ .sigaction = onSignal },
        .mask = std.os.linux.sigemptyset(),
        .flags = std.os.linux.SA.SIGINFO,
    };

    std.posix.sigaction(sig, &action, null);
}

fn queueToParent(sig: std.os.linux.SIG) !void {
    const raw = std.os.linux.pidfd_open(std.os.linux.getppid(), 0);
    if (std.os.linux.errno(raw) != .SUCCESS) return error.NoPidfd;

    var info = std.mem.zeroes(std.os.linux.siginfo_t);
    info.signo = sig;
    info.code = -1; // SI_QUEUE
    info.fields.common.second.value.int = 0xdead;
    if (std.os.linux.errno(std.os.linux.pidfd_send_signal(@intCast(raw), sig, &info, 0)) != .SUCCESS) {
        return error.SendFailed;
    }
}

fn report() u8 {
    const self_pid: i32 = @intCast(std.os.linux.getpid());
    var buf: [96]u8 = undefined;
    const text = std.fmt.bufPrint(&buf, "code={d} sender_is_self={} value={d}\n", .{
        received.code,
        received.fields.common.first.piduid.pid == self_pid,
        received.fields.common.second.value.int,
    }) catch return 2;

    _ = std.os.linux.write(std.os.linux.STDOUT_FILENO, text.ptr, text.len);
    return 0;
}

fn argv0(args: std.process.Args) []const u8 {
    var iter = args.iterate();
    return iter.next() orelse usage();
}

fn hasArg(args: std.process.Args, needle: []const u8) bool {
    var iter = args.iterate();
    while (iter.next()) |arg| {
        if (std.mem.eql(u8, arg, needle)) return true;
    }

    return false;
}

fn positional(args: std.process.Args, name: []const u8) []const u8 {
    var iter = args.iterate();
    while (iter.next()) |arg| {
        if (std.mem.eql(u8, arg, name)) return iter.next() orelse usage();
    }

    usage();
}

fn usage() noreturn {
    std.debug.print("usage: smoke --zinit <path>\n", .{});
    std.process.exit(2);
}
