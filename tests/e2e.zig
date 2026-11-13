// SPDX-FileCopyrightText: 2026 YuMing He <ComixHe1895@outlook.com>
//
// SPDX-License-Identifier: MIT

//! E2E checks against an arbitrary zinit binary. One executable carries every
//! profile so the responder, mask, group and PTY fixtures live once:
//!
//!   --health   artifact health gate (`zig build smoke`): version, help, one
//!              workload, one exit code, SIGTERM, no PATH.
//!   (default)  the full E2E matrix (`zig build test-e2e`): CLI, exec, signals,
//!              inheritance, PTYs, orphans, logging and option dispatch.
//!
//! The suite assumes Linux 5.10+ (pidfd_open and /proc) and a disposable process
//! namespace or an external runner timeout; it does not skip when those are
//! unavailable. A hard-killed run may leave a workload for that outer layer.
//!
//! Usage: e2e --zinit <path> --expect-version <v> [--health] [--max-log-level <l>]
//!        e2e --responder <plain|rt0|rtwide>          (run by zinit as its child)
//!        e2e --grace-responder <pid> <ready> <term>
//!        e2e --mask-child <marker>                   (reports the inherited mask)
//!        e2e --self-stop <TTIN|TTOU> --marker <m>    (reports an ignored stop)
//!        e2e --join-parent-group --ready <p> --marker <m>
//!        e2e --pty-child <marker>                    (run under a pty by the suite)
//!        e2e --pty-child-out <marker>                (stdin redirected, stdout pty)
//!        e2e --pty-bg-driver <marker> <zinit>        (driver for the background check)
//!        e2e --pty-fg-driver <marker> <zinit>        (driver for the fg/CONT check)
//!        e2e --pty-bg-child <ready>                  (workload for the background check)
//!        e2e --pty-fg-child <marker>                 (workload for the fg/CONT check)

const std = @import("std");

const rt_signal: std.os.linux.SIG = @fromBackingInt(@intCast(std.os.linux.sigrtmin() + 2));

/// The 6.9 pidfd process-group scope. Unlike a numeric PGID, it resolves the
/// group through the pidfd's kernel object; if that group is gone it is ESRCH.
const pidfd_process_group: u32 = 1 << 2;

const DriverStage = enum(u8) {
    usage = 2,
    setsid = 3,
    ctty = 4,
    spawn = 5,
    discover = 6,
    foreground = 7,
    stopped = 8,
    resumed = 9,
    cont = 10,
    wait = 11,
    status = 12,
    marker = 13,
    signal = 14,
};

const PtyPair = struct {
    master: std.os.linux.fd_t,
    slave: std.os.linux.fd_t = -1,

    fn open() !PtyPair {
        const master = std.posix.openat(
            std.posix.AT.FDCWD,
            "/dev/ptmx",
            .{ .ACCMODE = .RDWR, .NOCTTY = true, .CLOEXEC = true },
            0,
        ) catch return error.OpenPtyMaster;
        errdefer std.Io.Threaded.closeFd(master);

        var unlock: i32 = 0;
        if (std.os.linux.errno(std.os.linux.ioctl(master, std.os.linux.T.IOCSPTLCK, @intFromPtr(&unlock))) != .SUCCESS)
            return error.UnlockPty;

        var number: u32 = 0;
        if (std.os.linux.errno(std.os.linux.ioctl(master, std.os.linux.T.IOCGPTN, @intFromPtr(&number))) != .SUCCESS)
            return error.PtyNumber;

        var path_buf: [64]u8 = undefined;
        const path = std.mem.printSentinel(&path_buf, "/dev/pts/{d}", .{number}, 0) catch
            return error.PtyPath;

        const slave = std.posix.openat(
            std.posix.AT.FDCWD,
            path,
            .{ .ACCMODE = .RDWR, .NOCTTY = true, .CLOEXEC = true },
            0,
        ) catch return error.OpenPtySlave;

        return .{ .master = master, .slave = slave };
    }

    fn slaveFile(self: *const PtyPair) std.Io.File {
        return .{ .handle = self.slave, .flags = .{ .nonblocking = false } };
    }

    fn closeSlave(self: *PtyPair) void {
        if (self.slave >= 0) {
            std.Io.Threaded.closeFd(self.slave);
            self.slave = -1;
        }
    }

    fn close(self: *PtyPair) void {
        self.closeSlave();
        if (self.master >= 0) {
            std.Io.Threaded.closeFd(self.master);
            self.master = -1;
        }
    }
};

const deadline: std.Io.Timeout = .{ .duration = .{ .raw = .fromSeconds(10), .clock = .awake } };

pub fn main(init: std.process.Init) !void {
    const argv = init.minimal.args;

    if (hasArg(argv, "--responder")) std.process.exit(try responder(init.io, argv));
    if (hasArg(argv, "--mask-child")) std.process.exit(try maskChild(init.io, argv));
    if (hasArg(argv, "--self-stop")) std.process.exit(try selfStopChild(init.io, argv));
    if (hasArg(argv, "--join-parent-group")) std.process.exit(try joinGroupChild(init.io, argv));
    if (hasArg(argv, "--seccomp-numeric"))
        std.process.exit(try seccompNumericLauncher(init.minimal.args, init.minimal.environ));
    if (hasArg(argv, "--grace-responder")) std.process.exit(try graceResponder(init.io, argv));
    if (hasArg(argv, "--pty-child") or hasArg(argv, "--pty-child-out"))
        std.process.exit(try ptyChild(init.io, argv));
    if (hasArg(argv, "--pty-bg-driver"))
        std.process.exit(try ptyBgDriver(init.io, argv, init.environ_map));
    if (hasArg(argv, "--pty-fg-driver"))
        std.process.exit(try ptyFgDriver(init.io, argv, init.environ_map));
    if (hasArg(argv, "--pty-bg-child")) std.process.exit(try ptyBgChild(init.io, argv));
    if (hasArg(argv, "--pty-fg-child")) std.process.exit(try ptyFgChild(init.io, argv));

    const arena = init.arena.allocator();
    var env = try init.environ_map.clone(arena);

    var i: usize = 0;
    while (i < env.keys().len) {
        const key = env.keys()[i];
        if (std.mem.startsWith(u8, key, "ZINIT_") and env.swapRemove(key)) continue;
        i += 1;
    }

    try env.put("ZINIT_TRACING_CHILD", "OFF");
    try env.put("PATH", "/usr/local/bin:/usr/bin:/bin");

    var diag_buf: [96]u8 = undefined;
    const diag_path = try std.mem.printSentinel(&diag_buf, "/tmp/zinit-e2e-stderr-{d}-{x}", .{
        std.os.linux.getpid(), randomTag(init.io),
    }, 0);
    defer unlinkPath(init.io, diag_path);

    var suite: Suite = .{ .io = init.io, .arena = arena, .env = &env, .diag_path = diag_path };
    const zinit = try std.Io.Dir.cwd().realPathFileAlloc(init.io, positional(argv, "--zinit"), arena);
    const self_exe = argv0(argv);
    const version = positional(argv, "--expect-version");
    const max_log_level = optionValue(argv, "--max-log-level");

    const profile: Profile = if (hasArg(argv, "--health")) .health else .full;

    switch (profile) {
        .health => try suite.healthChecks(zinit, version),
        .full => {
            try suite.healthChecks(zinit, version);
            try suite.cliChecks(zinit, self_exe, version, max_log_level);
        },
    }

    std.process.exit(suite.summarize());
}

const Profile = enum { health, full };

fn maskChild(io: std.Io, args: std.process.Args) !u8 {
    const marker = positional(args, "--mask-child");

    var mask: std.os.linux.sigset_t = undefined;
    std.posix.sigprocmask(std.os.linux.SIG.SETMASK, null, &mask);
    if (!std.posix.sigismember(&mask, .USR2) or std.posix.sigismember(&mask, .TERM)) return 7;

    try writeFile(io, marker, "ok");
    return 0;
}

fn selfStopChild(io: std.Io, args: std.process.Args) !u8 {
    const which = positional(args, "--self-stop");
    const marker = positional(args, "--marker");
    const sig: std.posix.SIG = if (std.mem.eql(u8, which, "TTIN")) .TTIN else .TTOU;

    _ = std.posix.kill(std.os.linux.getpid(), sig) catch {};
    const file = try std.Io.Dir.cwd().createFile(io, marker, .{});
    defer file.close(io);
    try file.writeStreamingAll(io, "still running");
    return 7;
}

fn joinGroupChild(io: std.Io, args: std.process.Args) !u8 {
    const ready = positional(args, "--ready");
    const marker = positional(args, "--marker");

    const forked = std.os.linux.fork();
    if (std.os.linux.errno(forked) != .SUCCESS) return 3;
    if (forked == 0) {
        if (std.os.linux.errno(std.os.linux.setpgid(0, 0)) != .SUCCESS) std.os.linux.exit(4);
        while (true) _ = std.os.linux.pause();
    }

    const helper: std.os.linux.pid_t = @intCast(forked);
    defer {
        std.posix.kill(helper, .KILL) catch {};
        var status: i32 = 0;
        _ = std.os.linux.waitpid(helper, &status, 0);
    }

    const group_deadline = std.Io.Clock.now(.awake, io).toNanoseconds() + 5 * std.time.ns_per_s;
    while (true) {
        const pgid_raw = std.os.linux.getpgid(helper);
        if (std.os.linux.errno(pgid_raw) == .SUCCESS and @as(std.os.linux.pid_t, @intCast(pgid_raw)) == helper) break;
        if (std.Io.Clock.now(.awake, io).toNanoseconds() >= group_deadline) return 5;
        try std.Io.sleep(io, .fromMilliseconds(1), .awake);
    }

    if (std.os.linux.errno(std.os.linux.setpgid(0, helper)) != .SUCCESS) return 6;

    const own_raw = std.os.linux.getpgid(0);
    if (std.os.linux.errno(own_raw) != .SUCCESS) return 7;
    const own_pgid: std.os.linux.pid_t = @intCast(own_raw);
    if (own_pgid != helper or own_pgid == std.os.linux.getpid()) return 8;

    var term: std.os.linux.sigset_t = std.os.linux.sigemptyset();
    std.os.linux.sigaddset(&term, .TERM);
    std.posix.sigprocmask(std.os.linux.SIG.BLOCK, &term, null);

    try writeFile(io, ready, "ready");

    while (true) {
        var info: std.os.linux.siginfo_t = undefined;
        const rc = std.os.linux.syscall4(
            .rt_sigtimedwait,
            @intFromPtr(&term),
            @intFromPtr(&info),
            0,
            std.os.linux.NSIG / 8,
        );

        switch (std.os.linux.errno(rc)) {
            .SUCCESS => break,
            .INTR => continue,
            else => return 9,
        }
    }

    try writeFile(io, marker, "got");
    return 0;
}

fn seccompNumericLauncher(args: std.process.Args, environ: std.process.Environ) !u8 {
    const vector = args.vector;
    var separator: ?usize = null;
    for (vector, 0..) |arg, index| {
        if (std.mem.eql(u8, std.mem.span(arg), "--")) {
            separator = index;
            break;
        }
    }

    const at = separator orelse return 2;
    if (at + 1 >= vector.len) return 2;

    const no_new_privs = std.os.linux.prctl(@backingInt(std.os.linux.PR.SET_NO_NEW_PRIVS), 1, 0, 0, 0);
    if (std.os.linux.errno(no_new_privs) != .SUCCESS) return 125;

    var filter = [_]SockFilter{
        .{ .code = bpf_ld_w_abs, .jt = 0, .jf = 0, .k = 0 },
        .{ .code = bpf_jmp_jeq_k, .jt = 0, .jf = 1, .k = @intCast(@backingInt(std.os.linux.SYS.pidfd_send_signal)) },
        .{
            .code = bpf_ret_k,
            .jt = 0,
            .jf = 0,
            .k = std.os.linux.SECCOMP.RET.ERRNO |
                @as(u32, @intCast(@backingInt(std.os.linux.E.NOSYS))),
        },
        .{ .code = bpf_ret_k, .jt = 0, .jf = 0, .k = std.os.linux.SECCOMP.RET.ALLOW },
    };

    var program: SockFprog = .{ .len = filter.len, .filter = &filter };
    const installed = std.os.linux.seccomp(
        std.os.linux.SECCOMP.SET_MODE_FILTER,
        0,
        &program,
    );
    if (std.os.linux.errno(installed) != .SUCCESS) return 125;

    var argvz: [64]?[*:0]const u8 = undefined;
    var argc: usize = 0;
    for (vector[at + 1 ..]) |arg| {
        if (argc + 1 >= argvz.len) return 2;
        argvz[argc] = arg;
        argc += 1;
    }
    argvz[argc] = null;

    _ = std.os.linux.execve(vector[at + 1], argvz[0..argc :null].ptr, environ.block.slice.ptr);
    return 127;
}

const SockFilter = extern struct {
    code: u16,
    jt: u8,
    jf: u8,
    k: u32,
};

const SockFprog = extern struct {
    len: u16,
    filter: [*]SockFilter,
};

const bpf_ld_w_abs: u16 = 0x20; // BPF_LD | BPF_W | BPF_ABS
const bpf_jmp_jeq_k: u16 = 0x15; // BPF_JMP | BPF_JEQ | BPF_K
const bpf_ret_k: u16 = 0x06; // BPF_RET | BPF_K

const ScriptHandshake = struct {
    finish: [:0]const u8,
    require: ?[:0]const u8 = null,
};

const ScriptCaseOptions = struct {
    name: []const u8,
    argv: []const []const u8,
    signal: std.posix.SIG,
    marker: [:0]const u8,
    ready: [:0]const u8,
    expected_exit: ?u8 = null,
    pin_descendant: bool = false,
    handshake: ?ScriptHandshake = null,
};

const Expect = struct {
    code: u8,
    has: []const []const u8 = &.{},
    absent: []const []const u8 = &.{},
};

const pass_prefix = "  ok   ";
const fail_prefix = "  FAIL ";
const suite_prefix = "e2e: ";

const Suite = struct {
    io: std.Io,
    arena: std.mem.Allocator,
    env: *const std.process.Environ.Map,
    diag_path: [:0]const u8,
    failures: usize = 0,

    fn check(self: *Suite, name: []const u8, argv: []const []const u8, expect: Expect) void {
        self.checkWithEnv(name, argv, expect, self.env);
    }

    fn checkWithEnv(
        self: *Suite,
        name: []const u8,
        argv: []const []const u8,
        expect: Expect,
        env: *const std.process.Environ.Map,
    ) void {
        self.checkWithOptions(name, argv, expect, env, null);
    }

    fn checkWithOptions(
        self: *Suite,
        name: []const u8,
        argv: []const []const u8,
        expect: Expect,
        env: ?*const std.process.Environ.Map,
        cwd: ?[]const u8,
    ) void {
        const result = std.process.run(self.arena, self.io, .{
            .argv = argv,
            .environ_map = env,
            .cwd = if (cwd) |path| .{ .path = path } else .inherit,
            .timeout = deadline,
        }) catch |err| return self.fail(name, "{t}", .{err});

        const code: u8 = switch (result.term) {
            .exited => |exit_code| exit_code,
            else => 255,
        };

        var has = true;
        for (expect.has) |text| {
            const found = std.mem.find(u8, result.stdout, text) != null or
                std.mem.find(u8, result.stderr, text) != null;
            if (!found) has = false;
        }

        for (expect.absent) |text| {
            if (std.mem.find(u8, result.stdout, text) != null or
                std.mem.find(u8, result.stderr, text) != null) has = false;
        }

        if (code == expect.code and has) {
            self.pass(name);
            return;
        }

        self.failures += 1;
        std.debug.print(fail_prefix ++ "{s}: expected exit {d}", .{ name, expect.code });
        for (expect.has) |text| std.debug.print(" and output containing \"{s}\"", .{text});
        for (expect.absent) |text| std.debug.print(" and output without \"{s}\"", .{text});
        std.debug.print("\n    got     {f}\n    stdout  {s}\n    stderr  {s}\n", .{
            result.term, result.stdout, result.stderr,
        });
    }

    fn healthChecks(self: *Suite, zinit: []const u8, version: []const u8) !void {
        self.check("--version prints the version", &.{ zinit, "--version" }, .{ .code = 0, .has = &.{version} });
        self.check("--help prints usage", &.{ zinit, "--help" }, .{
            .code = 0,
            .has = &.{ "Usage: zinit", "--shutdown-timeout" },
        });
        self.check("starts and reaps a workload", &.{ zinit, "--", "/bin/true" }, .{ .code = 0 });
        self.check("exit code", &.{ zinit, "--", "/bin/sh", "-c", "exit 7" }, .{ .code = 7 });
        self.check("signal forwarding", &.{
            zinit, "--", "/bin/sh", "-c", "kill -TERM $PPID; exec sleep 30",
        }, .{ .code = 128 + @backingInt(std.posix.SIG.TERM) });
        try self.emptyEnvironment(zinit);
    }

    fn emptyEnvironment(self: *Suite, zinit: []const u8) !void {
        var env: std.process.Environ.Map = .init(self.arena);
        try env.put("ZINIT_TRACING_CHILD", "OFF");
        self.checkWithEnv("runs without PATH", &.{ zinit, "--", "/bin/true" }, .{ .code = 0 }, &env);
    }

    fn cliChecks(self: *Suite, zinit: []const u8, self_exe: []const u8, version: []const u8, max_log_level: ?[]const u8) !void {
        self.check("no arguments prints usage", &.{zinit}, .{ .code = 1, .has = &.{"Usage: zinit"} });

        self.check("a rejected option is named", &.{ zinit, "--log-level=debug", "--", "/bin/true" }, .{
            .code = 1,
            .has = &.{ "unknown option", "--log-level=debug" },
        });

        self.check("an invalid option value is named", &.{ zinit, "--log-level", "loud", "--", "/bin/true" }, .{
            .code = 1,
            .has = &.{ "unknown log level", "loud" },
        });

        self.check("an invalid environment value is named", &.{
            "/bin/sh", "-c", "ZINIT_LOG_LEVEL=loud exec \"$0\" -- /bin/true", zinit,
        }, .{ .code = 1, .has = &.{ "unknown ZINIT_LOG_LEVEL", "loud" } });

        self.check("-n runs without a terminal", &.{ zinit, "-n", "--", "/bin/true" }, .{ .code = 0 });

        self.check("realtime zero payload", &.{
            zinit, "--", self_exe, "--responder", "rt0",
        }, .{ .code = 0, .has = &.{ "code=-1", "sender_is_parent=true", "value=0x0" } });

        self.check("realtime wide payload", &.{
            zinit, "--", self_exe, "--responder", "rtwide",
        }, .{ .code = 0, .has = &.{ "code=-1", "sender_is_parent=true", "value=0x123456789abcdef0" } });

        self.check("plain signal", &.{
            zinit, "--", self_exe, "--responder", "plain",
        }, .{ .code = 0, .has = &.{ "code=0", "sender_is_parent=true" } });

        self.check("expected exit mapping", &.{
            zinit, "-e", "143", "--", "/bin/sh", "-c", "kill -TERM $$",
        }, .{ .code = 0 });

        self.check("every -e code maps to 0", &.{
            zinit, "-e", "1", "-e", "2", "--", "/bin/sh", "-c", "exit 2",
        }, .{ .code = 0 });

        self.check("-e leaves an unlisted code alone", &.{
            zinit, "-e", "1", "--", "/bin/sh", "-c", "exit 3",
        }, .{ .code = 3 });

        try self.gracePhase(zinit, self_exe);
        try self.zeroGrace(zinit);

        self.check("fails when it cannot get a descriptor", &.{
            "/bin/sh", "-c", "ulimit -n 3; exec \"$0\" -- /bin/true", zinit,
        }, .{ .code = 1 });

        self.check("exec failure", &.{
            zinit, "--", "/nonexistent-zinit-prog",
        }, .{ .code = 127 });

        self.check("the workload inherits only stdio", &.{
            zinit,                                                                                         "--", "/bin/sh", "-c",
            "for f in 0 1 2 3 4; do [ -e \"/proc/self/fd/$f\" ] && printf 'fd%s\\n' \"$f\"; done; exit 0",
        }, .{ .code = 0, .has = &.{ "fd0", "fd1", "fd2" }, .absent = &.{ "fd3", "fd4" } });

        try self.optionSignals(zinit);
        try self.brokenSink(zinit);
        try self.fullSink(zinit);
        try self.execFailureBrokenSink(zinit);
        try self.ptySession(zinit, self_exe);
        try self.tracing(zinit);
        try self.orphanChecks(zinit);
        try self.optionMatrix(zinit, version);
        try self.execContracts(zinit);
        try self.inheritanceContracts(zinit, self_exe);
        try self.rewriteContracts(zinit);
        try self.groupFallback(zinit, self_exe);
        try self.numericGroupSignal(zinit, self_exe);
        try self.reapPressure(zinit);
        try self.logContracts(zinit, max_log_level);
    }

    fn runWithBrokenSink(self: *Suite, name: []const u8, argv: []const []const u8, expected: u8) !void {
        const fds = std.Io.Threaded.pipe2(.{ .CLOEXEC = true }) catch
            return self.fail(name, "cannot create the sink pipe", .{});
        std.Io.Threaded.closeFd(fds[0]);
        defer std.Io.Threaded.closeFd(fds[1]);

        var child = std.process.spawn(self.io, .{
            .argv = argv,
            .environ_map = self.env,
            .stdin = .ignore,
            .stdout = .ignore,
            .stderr = .{ .file = .{ .handle = fds[1], .flags = .{ .nonblocking = false } } },
        }) catch |err| return self.fail(name, "{t}", .{err});
        defer terminateAndReap(self.io, &child);

        const status = waitForPid(self.io, child.id, 5_000) orelse
            return self.fail(name, "zinit did not exit", .{});
        child.id = null;

        const raw: u32 = @intCast(status);
        if (!std.os.linux.W.IFEXITED(raw) or std.os.linux.W.EXITSTATUS(raw) != expected)
            return self.fail(name, "expected {d}, got status 0x{x}", .{ expected, raw });
        self.pass(name);
    }

    const FullSinkKind = enum { pipe, fifo, socket };

    fn fullSink(self: *Suite, zinit: []const u8) !void {
        for ([_]FullSinkKind{ .pipe, .fifo, .socket }) |kind|
            try self.fullSinkCase(zinit, kind);
    }

    fn fullSinkCase(self: *Suite, zinit: []const u8, kind: FullSinkKind) !void {
        const name = switch (kind) {
            .pipe => "a full stderr pipe does not block shutdown",
            .fifo => "a full stderr FIFO does not block shutdown",
            .socket => "a full stderr socket does not block shutdown",
        };

        var dir_buf: [128]u8 = undefined;
        const dir = try makeTempDir(self.io, &dir_buf, "full-sink");
        defer removeTempDir(self.io, dir);
        var script_buf: [160]u8 = undefined;
        const script = try pathIn(&script_buf, dir, "script");
        var ready_buf: [160]u8 = undefined;
        const ready = try pathIn(&ready_buf, dir, "ready");
        var pid_buf: [160]u8 = undefined;
        const pid_path = try pathIn(&pid_buf, dir, "pid");
        var inner_buf: [160]u8 = undefined;
        const inner_ready = try pathIn(&inner_buf, dir, "inner-ready");
        var ack_buf: [160]u8 = undefined;
        const ack = try pathIn(&ack_buf, dir, "ack");
        var fifo_buf: [160]u8 = undefined;
        const fifo = try pathIn(&fifo_buf, dir, "sink.fifo");
        defer unlinkPath(self.io, script);
        defer unlinkPath(self.io, ready);
        defer unlinkPath(self.io, pid_path);
        defer unlinkPath(self.io, inner_ready);
        defer unlinkPath(self.io, ack);
        defer unlinkPath(self.io, fifo);

        var fds: [2]std.os.linux.fd_t = undefined;
        switch (kind) {
            .pipe => {
                fds = std.Io.Threaded.pipe2(.{ .CLOEXEC = true }) catch
                    return self.fail(name, "cannot create the sink pair", .{});
            },
            .socket => {
                const rc = std.os.linux.socketpair(std.os.linux.AF.UNIX, std.os.linux.SOCK.STREAM | std.os.linux.SOCK.CLOEXEC, 0, &fds);
                if (std.os.linux.errno(rc) != .SUCCESS)
                    return self.fail(name, "cannot create the sink pair", .{});
            },
            .fifo => {
                if (std.os.linux.errno(std.os.linux.mknod(fifo, std.os.linux.S.IFIFO | 0o600, 0)) != .SUCCESS)
                    return self.fail(name, "cannot create the FIFO", .{});
                const read_fd = std.posix.openat(
                    std.posix.AT.FDCWD,
                    fifo,
                    .{ .ACCMODE = .RDONLY, .NONBLOCK = true, .CLOEXEC = true },
                    0,
                ) catch return self.fail(name, "cannot open the FIFO reader", .{});
                fds[0] = read_fd;
                const write_fd = std.posix.openat(
                    std.posix.AT.FDCWD,
                    fifo,
                    .{ .ACCMODE = .WRONLY, .CLOEXEC = true },
                    0,
                ) catch {
                    std.Io.Threaded.closeFd(fds[0]);
                    return self.fail(name, "cannot open the FIFO writer", .{});
                };
                fds[1] = write_fd;
            },
        }
        defer std.Io.Threaded.closeFd(fds[0]);
        defer std.Io.Threaded.closeFd(fds[1]);

        const flags = std.os.linux.fcntl(fds[1], std.os.linux.F.GETFL, 0);
        if (std.os.linux.errno(flags) != .SUCCESS)
            return self.fail(name, "cannot read the sink flags", .{});
        const nonblock: usize = @as(u32, @bitCast(std.os.linux.O{ .NONBLOCK = true }));
        if (flags & nonblock != 0)
            return self.fail(name, "the fixture writer must start in blocking mode", .{});
        if (std.os.linux.errno(std.os.linux.fcntl(fds[1], std.os.linux.F.SETFL, flags | nonblock)) != .SUCCESS)
            return self.fail(name, "cannot make the sink non-blocking", .{});
        var chunk: [4096]u8 = @splat('x');
        var fill_size: usize = chunk.len;
        while (true) {
            const rc = std.os.linux.write(fds[1], &chunk, fill_size);
            switch (std.os.linux.errno(rc)) {
                .SUCCESS => if (rc == 0) return self.fail(name, "sink fill made no progress", .{}),
                .INTR => {},
                .AGAIN => if (fill_size == 1) break else {
                    fill_size = 1;
                },
                else => return self.fail(name, "cannot fill the sink pipe", .{}),
            }
        }
        if (std.os.linux.errno(std.os.linux.fcntl(fds[1], std.os.linux.F.SETFL, flags)) != .SUCCESS)
            return self.fail(name, "cannot restore the sink flags", .{});

        const body =
            "/bin/sh -c 'trap \"\" TERM; : >\"$1\"; exec /bin/sleep 30' helper \"$3\" &\n" ++
            "pid=$!\n" ++
            "while [ ! -e \"$3\" ]; do sleep 0.01; done\n" ++
            "printf '%d' \"$pid\" > \"$2\"\n" ++
            "printf ready > \"$1\"\n" ++
            "while [ ! -e \"$4\" ]; do sleep 0.01; done\n";
        writeFile(self.io, script, body) catch
            return self.fail(name, "cannot publish the helper script", .{});

        const argv = [_][]const u8{
            zinit, "-s", "-t", "0", "--", "/bin/sh", script, ready, pid_path, inner_ready, ack,
        };
        var child = std.process.spawn(self.io, .{
            .argv = &argv,
            .environ_map = self.env,
            .stdin = .ignore,
            .stdout = .ignore,
            .stderr = .{ .file = .{ .handle = fds[1], .flags = .{ .nonblocking = false } } },
        }) catch |err| return self.fail(name, "{t}", .{err});
        defer terminateAndReap(self.io, &child);

        if (!self.waitForPath(ready, 5_000))
            return self.fail(name, "the workload did not become ready", .{});

        const descendant = readPid(self.io, pid_path) orelse
            return self.fail(name, "invalid descendant pid", .{});
        const pinned = std.os.linux.pidfd_open(descendant, 0);
        if (std.os.linux.errno(pinned) != .SUCCESS)
            return self.fail(name, "cannot pin the descendant", .{});
        const descendant_fd: std.os.linux.fd_t = @intCast(pinned);
        defer {
            _ = std.os.linux.pidfd_send_signal(descendant_fd, .KILL, null, 0);
            std.Io.Threaded.closeFd(descendant_fd);
        }
        writeFile(self.io, ack, "ack") catch
            return self.fail(name, "cannot release the main workload", .{});

        const read_flags = std.os.linux.fcntl(fds[0], std.os.linux.F.GETFL, 0);
        if (std.os.linux.errno(read_flags) == .SUCCESS) {
            const drain_nonblock: usize = @as(u32, @bitCast(std.os.linux.O{ .NONBLOCK = true }));
            _ = std.os.linux.fcntl(fds[0], std.os.linux.F.SETFL, read_flags | drain_nonblock);
        }
        _ = drainFd(fds[0]);

        const status = waitForPid(self.io, child.id, 5_000) orelse
            return self.fail(name, "zinit blocked on the full sink", .{});
        child.id = null;
        const raw: u32 = @intCast(status);
        if (!std.os.linux.W.IFEXITED(raw) or std.os.linux.W.EXITSTATUS(raw) != 0)
            return self.fail(name, "zinit exited with status 0x{x}", .{raw});

        const recovered = drainFd(fds[0]);
        if (recovered == 0)
            return self.fail(name, "logging did not resume after the sink was drained", .{});

        if (waitPidfdExit(self.io, descendant_fd, 5_000) == null)
            return self.fail(name, "the descendant outlived the shutdown grace", .{});
        if (std.os.linux.fcntl(fds[1], std.os.linux.F.GETFL, 0) != flags)
            return self.fail(name, "the workload's stderr flags changed", .{});

        self.pass(name);
    }

    fn brokenSink(self: *Suite, zinit: []const u8) !void {
        const broken = "a broken stderr does not signal the workload";
        try self.runWithBrokenSink(broken, &.{ zinit, "--", "/bin/sh", "-c", "sleep 0.2; exit 7" }, 7);

        const forwarded = "SIGPIPE from another process still reaches the workload";

        var dir_buf: [128]u8 = undefined;
        const dir = try makeTempDir(self.io, &dir_buf, "sigpipe-forward");
        defer removeTempDir(self.io, dir);
        var ready_buf: [128]u8 = undefined;
        const ready = try pathIn(&ready_buf, dir, "ready");
        defer unlinkPath(self.io, ready);

        const diag = try self.diagStart();
        defer self.diagEnd(diag);

        var forwarded_child = std.process.spawn(self.io, .{
            .argv = &.{
                zinit, "--", "/bin/sh", "-c", "printf ready >\"$1\"; exec sleep 30", "sigpipe", ready,
            },
            .environ_map = self.env,
            .stdin = .ignore,
            .stdout = .ignore,
            .stderr = .{ .file = diag.file },
        }) catch |err| return self.fail(forwarded, "{t}", .{err});
        defer terminateAndReap(self.io, &forwarded_child);

        if (!self.waitForPath(ready, 5_000))
            return self.fail(forwarded, "the workload did not become ready", .{});

        const zpid = forwarded_child.id orelse return self.fail(forwarded, "no zinit pid", .{});
        std.posix.kill(zpid, .PIPE) catch
            return self.fail(forwarded, "cannot signal zinit", .{});

        const status_forwarded = waitForPid(self.io, forwarded_child.id, 5_000) orelse
            return self.fail(forwarded, "zinit did not exit after SIGPIPE", .{});
        forwarded_child.id = null;
        const raw_forwarded: u32 = @intCast(status_forwarded);
        if (!std.os.linux.W.IFEXITED(raw_forwarded) or
            std.os.linux.W.EXITSTATUS(raw_forwarded) != 128 + 13)
        {
            return self.fail(forwarded, "SIGPIPE was not forwarded: status 0x{x}", .{raw_forwarded});
        }
        self.pass(forwarded);
    }

    fn execFailureBrokenSink(self: *Suite, zinit: []const u8) !void {
        try self.runWithBrokenSink(
            "exec failure keeps 127 with a broken stderr",
            &.{ zinit, "-s", "--", "/nonexistent-zinit-prog" },
            127,
        );
    }

    fn tracing(self: *Suite, zinit: []const u8) !void {
        const name = "tracing holds the child until SIGUSR1";

        var on = try self.env.clone(self.arena);
        try on.put("ZINIT_TRACING_CHILD", "ON");

        const diag = try self.diagStart();
        defer self.diagEnd(diag);

        var child = std.process.spawn(self.io, .{
            .argv = &.{ zinit, "--", "/bin/sh", "-c", "exit 3" },
            .environ_map = &on,
            .stdin = .ignore,
            .stdout = .ignore,
            .stderr = .{ .file = diag.file },
        }) catch |err| return self.fail(name, "{t}", .{err});
        defer {
            if (child.id) |pid| {
                _ = killAndReap(self.io, pid);
                child.id = null;
            }
        }

        const pid: std.posix.pid_t = @intCast(child.id.?);
        const spawn_deadline = nowMs(self.io) + 5_000;
        var workload_pid: ?std.posix.pid_t = null;
        while (workload_pid == null) {
            workload_pid = mainChildPid(self.io, pid);
            if (workload_pid != null) break;
            if (nowMs(self.io) > spawn_deadline)
                return self.fail(name, "zinit did not spawn the traced child", .{});
            try std.Io.sleep(self.io, .fromMilliseconds(1), .awake);
        }

        const raw_workload = std.os.linux.pidfd_open(workload_pid.?, 0);
        if (std.os.linux.errno(raw_workload) != .SUCCESS)
            return self.fail(name, "cannot pin the traced child", .{});
        const workload_fd: std.os.linux.fd_t = @intCast(raw_workload);
        defer std.Io.Threaded.closeFd(workload_fd);
        const sigtimedwait = @as(i64, @intCast(@backingInt(std.os.linux.SYS.rt_sigtimedwait)));
        if (!waitForSyscall(self.io, workload_pid.?, sigtimedwait, 5_000))
            return self.fail(name, "the traced child did not enter its wait", .{});

        {
            if (std.os.linux.errno(std.os.linux.pidfd_send_signal(workload_fd, .STOP, null, 0)) != .SUCCESS)
                return self.fail(name, "cannot stop the traced child", .{});
            if (!waitForStopped(self.io, workload_pid.?, 5_000))
                return self.fail(name, "the traced child did not stop (state {c})", .{processState(self.io, workload_pid.?) orelse 'X'});
            if (std.os.linux.errno(std.os.linux.pidfd_send_signal(workload_fd, .CONT, null, 0)) != .SUCCESS)
                return self.fail(name, "cannot continue the traced child", .{});
            _ = std.posix.kill(pid, .CONT) catch {};
            if (!waitForRunning(self.io, workload_pid.?, 5_000))
                return self.fail(name, "the traced child did not continue", .{});
            if (processState(self.io, workload_pid.?) == null)
                return self.fail(name, "the traced child exited before the release", .{});
            if (!waitForSyscall(self.io, workload_pid.?, sigtimedwait, 5_000))
                return self.fail(name, "the traced child did not resume its wait", .{});
        }

        var early_status: i32 = 0;
        if (std.os.linux.waitpid(pid, &early_status, std.os.linux.W.NOHANG) != 0) {
            child.id = null;
            return self.fail(name, "zinit left before the release: the child was not held", .{});
        }

        std.posix.kill(pid, .USR1) catch |err|
            return self.fail(name, "nothing left to release ({t})", .{err});

        const status = waitForPid(self.io, child.id, 5_000) orelse
            return self.fail(name, "zinit did not exit within 5s of the release", .{});
        child.id = null;

        const raw: u32 = @intCast(status);
        const code: ?u8 = if (std.os.linux.W.IFEXITED(raw))
            std.os.linux.W.EXITSTATUS(raw)
        else
            null;

        if (code == 3) {
            self.pass(name);
            return;
        }

        self.fail(name, "expected the released child to exit 3, got {?d}", .{code});
    }

    fn optionSignals(self: *Suite, zinit: []const u8) !void {
        try self.rewriteSignal(zinit);
        try self.rewriteCase(zinit, "-r rewrites TTIN to TERM", "TTIN:TERM", .TTIN, "TERM");
        try self.rewriteCase(zinit, "-r rewrites TTOU to TERM", "TTOU:TERM", .TTOU, "TERM");
        try self.defaultSessionStop(zinit, .TTIN, false);
        try self.defaultSessionStop(zinit, .TTOU, false);
        try self.defaultSessionStop(zinit, .TTIN, true);
        try self.ignoredStop(zinit);
        try self.groupSignal(zinit);
        try self.pdeathSignal(zinit);
    }

    fn rewriteSignal(self: *Suite, zinit: []const u8) !void {
        try self.rewriteCase(zinit, "-r rewrites a forwarded signal", "TERM:USR1", .TERM, "USR1");
    }

    fn rewriteCase(
        self: *Suite,
        zinit: []const u8,
        name: []const u8,
        rule: []const u8,
        send_sig: std.posix.SIG,
        trap_signal: []const u8,
    ) !void {
        var dir_buf: [128]u8 = undefined;
        const dir = try makeTempDir(self.io, &dir_buf, "rewrite");
        defer removeTempDir(self.io, dir);

        var script_buf: [128]u8 = undefined;
        const script = try pathIn(&script_buf, dir, "script");
        var marker_buf: [128]u8 = undefined;
        const marker = try pathIn(&marker_buf, dir, "marker");
        var ready_buf: [128]u8 = undefined;
        const ready = try pathIn(&ready_buf, dir, "ready");
        defer unlinkPath(self.io, script);
        defer unlinkPath(self.io, marker);
        defer unlinkPath(self.io, ready);

        var body_buf: [256]u8 = undefined;
        const body = try std.mem.print(
            &body_buf,
            "trap 'printf got > \"$1\"; exit 0' {s}\n" ++
                "printf ready > \"$2\"\n" ++
                "while :; do sleep 0.01; done\n",
            .{trap_signal},
        );
        writeFile(self.io, script, body) catch return self.fail(name, "cannot publish the helper script", .{});

        const argv = [_][]const u8{
            zinit, "-r", rule, "--", "/bin/sh", script, marker, ready,
        };
        try self.runScriptCase(.{
            .name = name,
            .argv = &argv,
            .signal = send_sig,
            .marker = marker,
            .ready = ready,
            .expected_exit = 0,
        });
    }

    fn defaultSessionStop(
        self: *Suite,
        zinit: []const u8,
        sig: std.posix.SIG,
        cont_workload_first: bool,
    ) !void {
        const label: []const u8 = if (sig == .TTIN) "TTIN" else "TTOU";
        var name_buf: [96]u8 = undefined;
        const name = if (cont_workload_first)
            try std.mem.print(&name_buf, "-n: CONT to the workload alone does not resume zinit", .{})
        else
            try std.mem.print(&name_buf, "-n turns {s} into STOP for the workload", .{label});

        var dir_buf: [128]u8 = undefined;
        const dir = try makeTempDir(self.io, &dir_buf, "session-stop");
        defer removeTempDir(self.io, dir);
        var ready_buf: [128]u8 = undefined;
        const ready = try pathIn(&ready_buf, dir, "ready");
        defer unlinkPath(self.io, ready);

        const script = "trap '' TTIN TTOU; printf ready >\"$1\"; exec /bin/sleep 30";
        const diag = try self.diagStart();
        defer self.diagEnd(diag);

        var child = std.process.spawn(self.io, .{
            .argv = &.{ zinit, "-n", "--", "/bin/sh", "-c", script, "session-stop", ready },
            .environ_map = self.env,
            .stdin = .ignore,
            .stdout = .ignore,
            .stderr = .{ .file = diag.file },
        }) catch |err| return self.fail(name, "{t}", .{err});
        const zpid = child.id orelse return self.fail(name, "no zinit pid", .{});
        var workload_fd: ?std.os.linux.fd_t = null;

        defer {
            if (workload_fd) |fd| {
                _ = std.os.linux.pidfd_send_signal(fd, .KILL, null, 0);
                std.Io.Threaded.closeFd(fd);
            }
            if (child.id) |pid| _ = killAndReap(self.io, pid);
            child.id = null;
        }

        const spawn_deadline = nowMs(self.io) + 5_000;
        while (!fileExists(self.io, ready)) {
            if (nowMs(self.io) >= spawn_deadline) return self.fail(name, "workload did not become ready", .{});
            std.Io.sleep(self.io, .fromMilliseconds(1), .awake) catch
                return self.fail(name, "{t}", .{error.TestUnexpectedResult});
        }

        const pid = mainChildPid(self.io, zpid) orelse return self.fail(name, "cannot discover the workload", .{});
        const raw_fd = std.os.linux.pidfd_open(pid, 0);
        if (std.os.linux.errno(raw_fd) != .SUCCESS) return self.fail(name, "cannot pin the workload", .{});
        workload_fd = @intCast(raw_fd);

        _ = std.posix.kill(zpid, sig) catch return self.fail(name, "cannot signal zinit", .{});
        switch (waitForStop(self.io, zpid)) {
            .stopped => {},
            .exited => {
                child.id = null;
                return self.fail(name, "zinit exited instead of stopping", .{});
            },
            .failed => return self.fail(name, "zinit did not stop within the deadline", .{}),
        }

        if (cont_workload_first) {
            _ = std.posix.kill(pid, .CONT) catch
                return self.fail(name, "cannot continue the workload", .{});
            if (!waitForRunning(self.io, pid, 5_000))
                return self.fail(name, "CONT did not resume the workload", .{});

            const zstate = processState(self.io, zpid) orelse
                return self.fail(name, "zinit disappeared", .{});
            switch (zstate) {
                'T', 't' => {},
                else => return self.fail(name, "a workload CONT resumed zinit", .{}),
            }
        }

        _ = std.posix.kill(zpid, .CONT) catch return self.fail(name, "cannot continue zinit", .{});
        if (!waitForContinue(self.io, zpid))
            return self.fail(name, "zinit did not continue", .{});
        if (!waitForRunning(self.io, pid, 5_000))
            return self.fail(name, "one CONT did not resume the workload", .{});

        _ = std.os.linux.pidfd_send_signal(workload_fd.?, .KILL, null, 0);
        const killed_status = waitForPid(self.io, child.id, 5_000) orelse
            return self.fail(name, "zinit did not exit after the workload died", .{});
        child.id = null;
        const killed_raw: u32 = @intCast(killed_status);
        if (!std.os.linux.W.IFEXITED(killed_raw) or
            std.os.linux.W.EXITSTATUS(killed_raw) != 128 + @backingInt(std.posix.SIG.KILL))
        {
            return self.fail(name, "zinit did not report the workload's SIGKILL", .{});
        }

        self.pass(name);
    }

    fn ignoredStop(self: *Suite, zinit: []const u8) !void {
        const name = "a child that ignores TSTP leaves zinit running";

        var dir_buf: [128]u8 = undefined;
        const dir = try makeTempDir(self.io, &dir_buf, "ignored-stop");
        defer removeTempDir(self.io, dir);
        var ready_buf: [128]u8 = undefined;
        const ready = try pathIn(&ready_buf, dir, "ready");
        defer unlinkPath(self.io, ready);
        var usr1_buf: [128]u8 = undefined;
        const usr1 = try pathIn(&usr1_buf, dir, "usr1");
        defer unlinkPath(self.io, usr1);

        const script =
            "trap '' TSTP; " ++
            "trap 'printf usr1 > \"$2\"' USR1; " ++
            "printf ready > \"$1\"; " ++
            "while :; do sleep 0.05; done";
        const diag = try self.diagStart();
        defer self.diagEnd(diag);

        var child = std.process.spawn(self.io, .{
            .argv = &.{ zinit, "--", "/bin/sh", "-c", script, "ignored-stop", ready, usr1 },
            .environ_map = self.env,
            .stdin = .ignore,
            .stdout = .ignore,
            .stderr = .{ .file = diag.file },
        }) catch |err| return self.fail(name, "{t}", .{err});
        const zpid = child.id orelse return self.fail(name, "no zinit pid", .{});
        defer {
            if (child.id) |pid| _ = killAndReap(self.io, pid);
            child.id = null;
        }

        if (!self.waitForPath(ready, 5_000))
            return self.fail(name, "workload did not become ready", .{});

        _ = std.posix.kill(zpid, .TSTP) catch return self.fail(name, "cannot signal zinit", .{});
        std.Io.sleep(self.io, .fromMilliseconds(100), .awake) catch {};

        const zstate = processState(self.io, zpid) orelse
            return self.fail(name, "zinit exited after TSTP", .{});
        switch (zstate) {
            'T', 't' => return self.fail(name, "zinit stopped for an ignored TSTP", .{}),
            else => {},
        }

        _ = std.posix.kill(zpid, .USR1) catch return self.fail(name, "cannot signal zinit", .{});
        if (!self.waitForPath(usr1, 5_000))
            return self.fail(name, "zinit did not forward USR1", .{});

        _ = std.posix.kill(zpid, .TERM) catch {};
        if (waitForPid(self.io, child.id, 5_000) == null) {
            _ = std.posix.kill(zpid, .KILL) catch {};
            return self.fail(name, "zinit did not exit after TERM", .{});
        }
        child.id = null;

        self.pass(name);
    }

    fn groupSignal(self: *Suite, zinit: []const u8) !void {
        const name = "-g reaches a descendant in the child's process group";

        var dir_buf: [128]u8 = undefined;
        const dir = try makeTempDir(self.io, &dir_buf, "group");
        defer removeTempDir(self.io, dir);

        var script_buf: [128]u8 = undefined;
        const script = try pathIn(&script_buf, dir, "script");
        var marker_buf: [128]u8 = undefined;
        const marker = try pathIn(&marker_buf, dir, "marker");
        var ready_buf: [128]u8 = undefined;
        const ready = try pathIn(&ready_buf, dir, "ready");
        var inner_buf: [128]u8 = undefined;
        const inner_ready = try pathIn(&inner_buf, dir, "inner-ready");
        var finish_buf: [128]u8 = undefined;
        const finish = try pathIn(&finish_buf, dir, "finish");
        var outer_buf: [128]u8 = undefined;
        const outer = try pathIn(&outer_buf, dir, "outer-term");
        defer unlinkPath(self.io, script);
        defer unlinkPath(self.io, marker);
        defer unlinkPath(self.io, ready);
        defer unlinkPath(self.io, inner_ready);
        defer unlinkPath(self.io, finish);
        defer unlinkPath(self.io, outer);

        const body =
            "trap 'printf outer > \"$5\"' TERM\n" ++
            "/bin/sh -c 'trap \"printf got > $1; exit 0\" TERM; : > \"$2\"; while :; do sleep 0.01; done' sh \"$1\" \"$3\" &\n" ++
            "while [ ! -f \"$3\" ]; do sleep 0.01; done\n" ++
            "printf ready > \"$2\"\n" ++
            "while [ ! -f \"$4\" ]; do sleep 0.01; done\n" ++
            "exit 0\n";
        writeFile(self.io, script, body) catch return self.fail(name, "cannot publish the helper script", .{});

        const argv = [_][]const u8{
            zinit, "-g", "-t", "1", "--", "/bin/sh", script, marker, ready, inner_ready, finish, outer,
        };
        try self.runScriptCase(.{
            .name = name,
            .argv = &argv,
            .signal = .TERM,
            .marker = marker,
            .ready = ready,
            .expected_exit = 0,
            .handshake = .{ .finish = finish, .require = outer },
        });
    }

    fn pdeathSignal(self: *Suite, zinit: []const u8) !void {
        const name = "-p delivers PDEATHSIG when zinit dies";

        var dir_buf: [128]u8 = undefined;
        const dir = try makeTempDir(self.io, &dir_buf, "pdeath");
        defer removeTempDir(self.io, dir);

        var script_buf: [128]u8 = undefined;
        const script = try pathIn(&script_buf, dir, "script");
        var marker_buf: [128]u8 = undefined;
        const marker = try pathIn(&marker_buf, dir, "marker");
        var ready_buf: [128]u8 = undefined;
        const ready = try pathIn(&ready_buf, dir, "ready");
        defer unlinkPath(self.io, script);
        defer unlinkPath(self.io, marker);
        defer unlinkPath(self.io, ready);

        const body =
            "trap 'printf got > \"$1\"; exit 0' USR1\n" ++
            "printf ready > \"$2\"\n" ++
            "while :; do sleep 0.01; done\n";
        writeFile(self.io, script, body) catch return self.fail(name, "cannot publish the helper script", .{});

        const argv = [_][]const u8{
            zinit, "-p", "USR1", "--", "/bin/sh", script, marker, ready,
        };
        try self.runScriptCase(.{
            .name = name,
            .argv = &argv,
            .signal = .KILL,
            .marker = marker,
            .ready = ready,
            .pin_descendant = true,
        });
    }

    fn runScriptCase(self: *Suite, options: ScriptCaseOptions) !void {
        const name = options.name;
        const argv = options.argv;
        const send_sig = options.signal;
        const marker = options.marker;
        const ready = options.ready;
        const finish: ?[:0]const u8 = if (options.handshake) |h| h.finish else null;
        const extra_marker: ?[:0]const u8 = if (options.handshake) |h| h.require else null;
        const diag = try self.diagStart();
        defer self.diagEnd(diag);

        var child = std.process.spawn(self.io, .{
            .argv = argv,
            .environ_map = self.env,
            .stdin = .ignore,
            .stdout = .ignore,
            .stderr = .{ .file = diag.file },
        }) catch |err| return self.fail(name, "{t}", .{err});
        const zpid = child.id orelse return self.fail(name, "no zinit pid", .{});

        var descendant: ?PinnedChild = null;
        defer {
            if (descendant) |pinned| {
                _ = std.os.linux.pidfd_send_signal(pinned.fd, .KILL, null, 0);
                _ = waitPidfdExit(self.io, pinned.fd, 2_000);
                std.Io.Threaded.closeFd(pinned.fd);
            }

            if (finish) |path| writeFile(self.io, path, "finish") catch {};
            terminateAndReap(self.io, &child);
        }

        if (!self.waitForPath(ready, 5_000)) {
            return self.fail(name, "helper did not become ready", .{});
        }

        if (options.pin_descendant) {
            const pid = mainChildPid(self.io, zpid) orelse
                return self.fail(name, "cannot discover the helper", .{});
            const raw = std.os.linux.pidfd_open(pid, 0);
            if (std.os.linux.errno(raw) != .SUCCESS)
                return self.fail(name, "cannot pin the helper", .{});
            descendant = .{ .pid = pid, .fd = @intCast(raw) };
        }

        std.posix.kill(zpid, send_sig) catch |err|
            return self.fail(name, "cannot signal zinit ({t})", .{err});

        if (finish) |path| {
            if (!self.waitForPath(marker, 5_000)) {
                return self.fail(name, "the helper did not receive the expected signal", .{});
            }

            writeFile(self.io, path, "finish") catch {
                return self.fail(name, "cannot release the main shell", .{});
            };
        }

        const status = waitForPid(self.io, child.id, 5_000) orelse
            return self.fail(name, "zinit did not exit", .{});
        child.id = null;

        const raw: u32 = @intCast(status);
        if (options.expected_exit) |code| {
            if (!std.os.linux.W.IFEXITED(raw) or std.os.linux.W.EXITSTATUS(raw) != code) {
                return self.fail(name, "zinit exited with {d}", .{std.os.linux.W.EXITSTATUS(raw)});
            }
        } else if (!std.os.linux.W.IFSIGNALED(raw) or
            @backingInt(std.os.linux.W.TERMSIG(raw)) != @backingInt(send_sig))
        {
            return self.fail(name, "zinit was not terminated by the test signal", .{});
        }

        if (finish == null and !self.waitForPath(marker, 5_000)) {
            return self.fail(name, "the helper did not receive the expected signal", .{});
        }

        if (extra_marker) |path| {
            if (!fileExists(self.io, path)) {
                return self.fail(name, "the main shell did not survive the forwarded signal", .{});
            }
        }

        if (descendant) |pinned| {
            if (waitPidfdExit(self.io, pinned.fd, 5_000) == null)
                return self.fail(name, "the helper did not exit after PDEATHSIG", .{});
        }

        self.pass(name);
    }

    fn waitForPath(self: *Suite, path: [:0]const u8, timeout_ms: i64) bool {
        const deadline_ms = nowMs(self.io) + timeout_ms;
        while (nowMs(self.io) < deadline_ms) {
            if (fileExists(self.io, path)) return true;
            std.Io.sleep(self.io, .fromMilliseconds(1), .awake) catch return false;
        }

        return fileExists(self.io, path);
    }

    fn ptySession(self: *Suite, zinit: []const u8, self_exe: []const u8) !void {
        try self.ptyCase(zinit, self_exe, true);
        try self.ptyCase(zinit, self_exe, false);
        try self.ptyBackground(zinit, self_exe);
        try self.ptyForegroundResume(zinit, self_exe);
    }

    fn ptyCase(self: *Suite, zinit: []const u8, self_exe: []const u8, stdin_is_pty: bool) !void {
        const name = if (stdin_is_pty)
            "-n gives the workload a session and foreground pty"
        else
            "-n still finds the pty when stdin is redirected";

        var dir_buf: [128]u8 = undefined;
        const dir = try makeTempDir(self.io, &dir_buf, "pty");
        defer removeTempDir(self.io, dir);
        var marker_buf: [128]u8 = undefined;
        const marker = try pathIn(&marker_buf, dir, "marker");
        defer unlinkPath(self.io, marker);

        var pty = PtyPair.open() catch |err| return self.fail(name, "{t}", .{err});
        defer pty.close();
        const slave_file = pty.slaveFile();
        const stdin_stdio: std.process.SpawnOptions.StdIo = if (stdin_is_pty)
            .{ .file = slave_file }
        else
            .ignore;

        const child_arg = if (stdin_is_pty) "--pty-child" else "--pty-child-out";
        var child = std.process.spawn(self.io, .{
            .argv = &.{ zinit, "-n", "--", self_exe, child_arg, marker },
            .environ_map = self.env,
            .stdin = stdin_stdio,
            .stdout = .{ .file = slave_file },
            .stderr = .{ .file = slave_file },
        }) catch |err| return self.fail(name, "{t}", .{err});
        pty.closeSlave();

        defer terminateAndReap(self.io, &child);

        const status = waitForPid(self.io, child.id, 5_000) orelse
            return self.fail(name, "zinit did not exit", .{});
        child.id = null;

        const raw: u32 = @intCast(status);
        if (!std.os.linux.W.IFEXITED(raw) or std.os.linux.W.EXITSTATUS(raw) != 0)
            return self.fail(name, "zinit exited with {d}", .{std.os.linux.W.EXITSTATUS(raw)});
        if (!fileExists(self.io, marker))
            return self.fail(name, "workload did not see a new-session foreground pty", .{});

        self.pass(name);
    }

    fn ptyBackground(self: *Suite, zinit: []const u8, self_exe: []const u8) !void {
        try self.ptyDriver(
            "a background zinit leaves the pty foreground group alone",
            "pty-bg",
            "--pty-bg-driver",
            zinit,
            self_exe,
        );
    }

    fn ptyForegroundResume(self: *Suite, zinit: []const u8, self_exe: []const u8) !void {
        try self.ptyDriver(
            "fg restores the workload's foreground pty after a stop",
            "pty-fg",
            "--pty-fg-driver",
            zinit,
            self_exe,
        );
    }

    fn ptyDriver(
        self: *Suite,
        name: []const u8,
        prefix: []const u8,
        driver_flag: []const u8,
        zinit: []const u8,
        self_exe: []const u8,
    ) !void {
        var dir_buf: [128]u8 = undefined;
        const dir = try makeTempDir(self.io, &dir_buf, prefix);
        defer removeTempDir(self.io, dir);
        var marker_buf: [128]u8 = undefined;
        const marker = try pathIn(&marker_buf, dir, "marker");
        defer unlinkPath(self.io, marker);

        var pty = PtyPair.open() catch |err| return self.fail(name, "{t}", .{err});
        defer pty.close();
        const slave_file = pty.slaveFile();
        var child = std.process.spawn(self.io, .{
            .argv = &.{ self_exe, driver_flag, marker, zinit },
            .environ_map = self.env,
            .stdin = .{ .file = slave_file },
            .stdout = .{ .file = slave_file },
            .stderr = .{ .file = slave_file },
        }) catch |err| return self.fail(name, "{t}", .{err});
        pty.closeSlave();

        const status = waitForPid(self.io, child.id, 8_000) orelse {
            if (child.id) |pid| _ = killAndReap(self.io, pid);
            child.id = null;
            return self.fail(name, "pty driver did not exit", .{});
        };
        child.id = null;

        const raw: u32 = @intCast(status);
        if (!std.os.linux.W.IFEXITED(raw))
            return self.fail(name, "pty driver died by signal {d}", .{std.os.linux.W.TERMSIG(raw)});

        const code = std.os.linux.W.EXITSTATUS(raw);
        if (code >= @backingInt(DriverStage.usage) and code <= @backingInt(DriverStage.signal)) {
            const stage: DriverStage = @fromBackingInt(@intCast(code));
            return self.fail(name, "pty driver failed at {s}", .{@tagName(stage)});
        }

        if (code != 0)
            return self.fail(name, "pty driver failed with exit {d}", .{code});

        if (!fileExists(self.io, marker))
            return self.fail(name, "workload did not observe the expected pty behavior", .{});

        self.pass(name);
    }

    fn orphanChecks(self: *Suite, zinit: []const u8) !void {
        try self.orphanCase("without -s, a grandchild is not zinit's to reap", zinit, false);
        try self.orphanCase("-s reaps a grandchild it adopted", zinit, true);
        try self.orphanMidRun(zinit);
    }

    fn orphanMidRun(self: *Suite, zinit: []const u8) !void {
        const name = "-s reaps an adopted orphan while the main child runs";

        var dir_buf: [128]u8 = undefined;
        const dir = try makeTempDir(self.io, &dir_buf, "mid-run-orphan");
        defer removeTempDir(self.io, dir);
        var pid_buf: [96]u8 = undefined;
        const pid_path = try pathIn(&pid_buf, dir, "pid");
        defer unlinkPath(self.io, pid_path);

        const script = "(sleep 1 & printf '%d' $! >\"$1.tmp\"; mv \"$1.tmp\" \"$1\"); sleep 5";
        var child = std.process.spawn(self.io, .{
            .argv = &.{ zinit, "-s", "-t", "0", "--", "/bin/sh", "-c", script, "mid-run", pid_path },
            .environ_map = self.env,
            .stdin = .ignore,
            .stdout = .ignore,
            .stderr = .ignore,
        }) catch |err| return self.fail(name, "{t}", .{err});
        const zpid = child.id orelse return self.fail(name, "no zinit pid", .{});
        defer terminateAndReap(self.io, &child);

        if (!self.waitForPath(pid_path, 5_000))
            return self.fail(name, "the subshell did not publish its pid", .{});
        const orphan = readPid(self.io, pid_path) orelse return self.fail(name, "no orphan pid", .{});
        var pinned_orphan = PinnedProcess.pin(orphan) catch
            return self.fail(name, "cannot pin the orphan", .{});
        defer pinned_orphan.close();

        const adopt_deadline = nowMs(self.io) + 3_000;
        while (!self.hasChild(zpid, orphan)) {
            if (nowMs(self.io) >= adopt_deadline)
                return self.fail(name, "zinit did not adopt the orphan", .{});
            try std.Io.sleep(self.io, .fromMilliseconds(1), .awake);
        }

        if (!pinned_orphan.exited(self.io, 5_000))
            return self.fail(name, "the adopted orphan was never reaped", .{});
        if (processState(self.io, zpid) == null)
            return self.fail(name, "zinit exited while the main child was running", .{});

        self.pass(name);
    }

    fn hasChild(self: *Suite, zpid: std.posix.pid_t, pid: std.posix.pid_t) bool {
        var path_buf: [96]u8 = undefined;
        const path = std.mem.printSentinel(&path_buf, "/proc/{d}/task/{d}/children", .{
            zpid, zpid,
        }, 0) catch return false;
        var buf: [256]u8 = undefined;
        const text = readSmallFile(self.io, path, &buf) orelse return false;

        var tokens = std.mem.tokenizeAny(u8, text, " \n\t");
        while (tokens.next()) |token| {
            const child = std.fmt.parseInt(std.posix.pid_t, token, 10) catch continue;
            if (child == pid) return true;
        }
        return false;
    }

    fn orphanCase(self: *Suite, name: []const u8, zinit: []const u8, subreaper: bool) !void {
        const script = "sleep 30 >/dev/null 2>&1 & echo $!; exit 0";
        const argv: []const []const u8 = if (subreaper)
            &.{ zinit, "-s", "--", "/bin/sh", "-c", script }
        else
            &.{ zinit, "--", "/bin/sh", "-c", script };

        const result = std.process.run(self.arena, self.io, .{
            .argv = argv,
            .environ_map = self.env,
            .timeout = deadline,
        }) catch |err| return self.fail(name, "{t}", .{err});

        const code: u8 = switch (result.term) {
            .exited => |exit_code| exit_code,
            else => 255,
        };
        if (code != 0) return self.fail(name, "expected exit 0, got {d}: {s}", .{ code, result.stderr });

        const pid = std.fmt.parseInt(std.posix.pid_t, std.mem.trim(u8, result.stdout, " \n"), 10) catch
            return self.fail(name, "no pid in the output: {s} / {s}", .{ result.stdout, result.stderr });

        var orphan = PinnedProcess.pin(pid) catch
            return self.fail(name, "cannot pin the reported pid", .{});
        defer orphan.close();

        if (subreaper) {
            if (!orphan.exited(self.io, 5_000))
                return self.fail(name, "zinit left its adopted grandchild behind", .{});
        } else {
            if (orphan.exited(self.io, 0))
                return self.fail(name, "zinit tore the orphan down anyway", .{});
            orphan.kill();
            if (!orphan.exited(self.io, 5_000))
                return self.fail(name, "the orphan survived the test cleanup", .{});
        }

        self.pass(name);
    }

    fn zeroGrace(self: *Suite, zinit: []const u8) !void {
        const name = "a zero grace kills a TERM-ignoring descendant at once";

        var dir_buf: [128]u8 = undefined;
        const dir = try makeTempDir(self.io, &dir_buf, "zero-grace");
        defer removeTempDir(self.io, dir);
        var pid_buf: [96]u8 = undefined;
        const pid_path = try pathIn(&pid_buf, dir, "pid");
        defer unlinkPath(self.io, pid_path);
        var ready_buf: [96]u8 = undefined;
        const ready_path = try pathIn(&ready_buf, dir, "ready");
        defer unlinkPath(self.io, ready_path);

        const script =
            "(trap '' TERM; : >\"$2\"; exec sleep 30) & " ++
            "n=0; while [ ! -e \"$2\" ] && [ \"$n\" -lt 500 ]; do n=$((n+1)); sleep 0.01; done; " ++
            "printf '%d' $! >\"$1.tmp\"; mv \"$1.tmp\" \"$1\"; exit 0";

        const diag = try self.diagStart();
        defer self.diagEnd(diag);

        const started = nowMs(self.io);
        var child = std.process.spawn(self.io, .{
            .argv = &.{ zinit, "-s", "-t", "0", "--", "/bin/sh", "-c", script, "zero-grace", pid_path, ready_path },
            .environ_map = self.env,
            .stdin = .ignore,
            .stdout = .ignore,
            .stderr = .{ .file = diag.file },
        }) catch |err| return self.fail(name, "spawn: {t}", .{err});
        defer terminateAndReap(self.io, &child);

        if (!self.waitForPath(pid_path, 5_000))
            return self.fail(name, "the descendant did not publish its pid", .{});
        const pid = readPid(self.io, pid_path) orelse return self.fail(name, "no descendant pid", .{});
        var descendant = PinnedProcess.pin(pid) catch
            return self.fail(name, "cannot pin the descendant", .{});
        defer descendant.close();

        const status = waitForPid(self.io, child.id, 5_000) orelse
            return self.fail(name, "zinit did not exit", .{});
        child.id = null;
        const elapsed = nowMs(self.io) - started;

        const raw: u32 = @intCast(status);
        if (!std.os.linux.W.IFEXITED(raw) or std.os.linux.W.EXITSTATUS(raw) != 0)
            return self.fail(name, "zinit exited with 0x{x}", .{raw});
        if (elapsed >= 2_000)
            return self.fail(name, "zinit waited {d} ms for a zero grace", .{elapsed});
        if (!descendant.exited(self.io, 5_000))
            return self.fail(name, "the descendant outlived zinit", .{});

        self.pass(name);
    }

    fn gracePhase(self: *Suite, zinit: []const u8, self_exe: []const u8) !void {
        const name = "a TERM-ignoring descendant is killed after the grace period";

        var dir_buf: [128]u8 = undefined;
        const dir = try makeTempDir(self.io, &dir_buf, "grace");
        defer removeTempDir(self.io, dir);

        var pid_buf: [96]u8 = undefined;
        const pid_path = try pathIn(&pid_buf, dir, "pid");
        var ready_buf: [96]u8 = undefined;
        const ready_path = try pathIn(&ready_buf, dir, "ready");
        var term_buf: [96]u8 = undefined;
        const term_path = try pathIn(&term_buf, dir, "term");
        var ack_buf: [96]u8 = undefined;
        const ack_path = try pathIn(&ack_buf, dir, "ack");

        defer unlinkPath(self.io, pid_path);
        defer unlinkPath(self.io, ready_path);
        defer unlinkPath(self.io, term_path);
        defer unlinkPath(self.io, ack_path);
        defer unlinkIn(self.io, dir, "pid.tmp");
        defer unlinkIn(self.io, dir, "ready.tmp");
        defer unlinkIn(self.io, dir, "term.tmp");
        defer unlinkIn(self.io, dir, "ack.tmp");

        const script = try self.arena.print(
            "\"$0\" --grace-responder {s} {s} {s} & while [ ! -f {s} ]; do sleep 0.01; done; while [ ! -f {s} ]; do sleep 0.01; done; exit 0",
            .{ pid_path, ready_path, term_path, ready_path, ack_path },
        );

        var child = std.process.spawn(self.io, .{
            .argv = &.{ zinit, "-s", "-t", "1", "--", "/bin/sh", "-c", script, self_exe },
            .environ_map = self.env,
            .stdin = .ignore,
            .stdout = .ignore,
            .stderr = .ignore,
        }) catch |err| return self.fail(name, "spawn: {t}", .{err});

        const zpid = child.id orelse return self.fail(name, "no zinit pid", .{});
        var main_pid: ?std.posix.pid_t = null;
        var main_fd: ?std.os.linux.fd_t = null;
        var helper_fd: ?std.os.linux.fd_t = null;
        var reaped = false;

        defer {
            if (!reaped) {
                if (helper_fd) |fd| _ = std.os.linux.pidfd_send_signal(fd, .KILL, null, 0);
                if (main_fd) |fd| {
                    _ = std.os.linux.pidfd_send_signal(fd, .KILL, null, pidfd_process_group);
                    _ = std.os.linux.pidfd_send_signal(fd, .KILL, null, 0);
                }
            }

            if (helper_fd) |fd| std.Io.Threaded.closeFd(fd);
            if (main_fd) |fd| std.Io.Threaded.closeFd(fd);
            if (child.id) |pid| _ = killAndReap(self.io, pid);
        }

        const main_deadline = nowMs(self.io) + 5_000;
        while (main_pid == null) {
            main_pid = mainChildPid(self.io, zpid);
            if (main_pid != null) break;
            if (nowMs(self.io) > main_deadline) {
                return self.fail(name, "cannot discover the main child (requires /proc)", .{});
            }
            try std.Io.sleep(self.io, .fromMilliseconds(1), .awake);
        }
        const raw_main = std.os.linux.pidfd_open(main_pid.?, 0);
        if (std.os.linux.errno(raw_main) != .SUCCESS)
            return self.fail(name, "cannot pin the main child", .{});
        main_fd = @intCast(raw_main);

        const ready_deadline = nowMs(self.io) + 5_000;
        while (!fileExists(self.io, ready_path)) {
            if (nowMs(self.io) > ready_deadline) return self.fail(name, "helper did not publish READY", .{});
            try std.Io.sleep(self.io, .fromMilliseconds(1), .awake);
        }
        const pid = readPid(self.io, pid_path) orelse return self.fail(name, "no helper pid", .{});
        const raw_helper = std.os.linux.pidfd_open(pid, 0);
        if (std.os.linux.errno(raw_helper) != .SUCCESS)
            return self.fail(name, "cannot pin the helper", .{});
        helper_fd = @intCast(raw_helper);

        writeFile(self.io, ack_path, "ack") catch return self.fail(name, "cannot publish ACK", .{});

        const started_ns = waitPidfdExit(self.io, main_fd.?, 5_000) orelse {
            return self.fail(name, "main child did not exit", .{});
        };

        const repeat_deadline = nowMs(self.io) + 1_200;
        while (nowMs(self.io) < repeat_deadline and waitPidfdExit(self.io, helper_fd.?, 0) == null) {
            _ = std.posix.kill(zpid, .TERM) catch {};
            try std.Io.sleep(self.io, .fromMilliseconds(100), .awake);
        }

        const helper_exit_ns = waitPidfdExit(self.io, helper_fd.?, 4_000) orelse {
            return self.fail(name, "helper outlived the grace", .{});
        };
        const elapsed = @divTrunc(helper_exit_ns - started_ns, std.time.ns_per_ms);

        if (!fileExists(self.io, term_path)) return self.fail(name, "helper never saw TERM", .{});

        const status = waitForPid(self.io, child.id, 5_000) orelse {
            return self.fail(name, "zinit did not exit after the helper", .{});
        };
        reaped = true;
        child.id = null;

        const raw: u32 = @intCast(status);
        if (!std.os.linux.W.IFEXITED(raw) or std.os.linux.W.EXITSTATUS(raw) != 0) {
            return self.fail(name, "zinit exited with {d}", .{std.os.linux.W.EXITSTATUS(raw)});
        }

        if (elapsed < 500 or elapsed > 2_500) {
            return self.fail(name, "grace measured {d}ms, outside the 500..2500ms tolerance", .{elapsed});
        }

        self.passf(name, "{d}ms", .{elapsed});
    }

    fn optionMatrix(self: *Suite, zinit: []const u8, version: []const u8) !void {
        self.check("-V prints the version", &.{ zinit, "-V" }, .{ .code = 0, .has = &.{version} });
        self.check("--new-session is the long -n", &.{ zinit, "--new-session", "--", "/bin/true" }, .{ .code = 0 });
        self.check("-h prints usage", &.{ zinit, "-h" }, .{ .code = 0, .has = &.{"Usage: zinit"} });
        self.check("-g and -n can be combined", &.{ zinit, "-g", "-n", "--", "/bin/true" }, .{ .code = 0 });
        self.check("the first non-option needs no --", &.{ zinit, "-t", "1", "/bin/true" }, .{ .code = 0 });
        self.check("-- stops option parsing", &.{
            zinit, "--", "/bin/sh", "-c", "printf '%s' \"$1\"", "argv", "--version",
        }, .{ .code = 0, .has = &.{"--version"} });

        const invalid = [_]struct { name: []const u8, argv: []const []const u8 }{
            .{ .name = "a missing -t value is rejected", .argv = &.{ zinit, "-t" } },
            .{ .name = "a missing -p value is rejected", .argv = &.{ zinit, "-p" } },
            .{ .name = "a missing -r value is rejected", .argv = &.{ zinit, "-r" } },
            .{ .name = "a missing -e value is rejected", .argv = &.{ zinit, "-e" } },
            .{ .name = "a missing --log-level value is rejected", .argv = &.{ zinit, "--log-level" } },
            .{ .name = "a repeated timeout is rejected", .argv = &.{ zinit, "-t", "1", "-t", "2", "--", "/bin/true" } },
            .{ .name = "a repeated pdeath signal is rejected", .argv = &.{ zinit, "-p", "TERM", "-p", "INT", "--", "/bin/true" } },
            .{ .name = "a repeated log level is rejected", .argv = &.{ zinit, "--log-level", "warn", "--log-level", "warn", "--", "/bin/true" } },
            .{ .name = "a non-numeric timeout is rejected", .argv = &.{ zinit, "-t", "soon", "--", "/bin/true" } },
            .{ .name = "an overflowing timeout is rejected", .argv = &.{ zinit, "-t", "18446744073709551616", "--", "/bin/true" } },
            .{ .name = "an exit code above 255 is rejected", .argv = &.{ zinit, "-e", "300", "--", "/bin/true" } },
            .{ .name = "help and version together are rejected", .argv = &.{ zinit, "-h", "-V" } },
            .{ .name = "a bare name with no command is rejected", .argv = &.{ zinit, "--" } },
        };
        for (invalid) |case| self.check(case.name, case.argv, .{ .code = 1 });

        self.check("the largest representable timeout is accepted", &.{
            zinit, "-t", "18446744073", "--", "/bin/true",
        }, .{ .code = 0 });

        var overridden = try self.env.clone(self.arena);
        try overridden.put("ZINIT_LOG_LEVEL", "not-a-level");
        try overridden.put("ZINIT_SHUTDOWN_TIMEOUT", "not-seconds");
        self.checkWithEnv("an explicit option overrides invalid environment", &.{
            zinit, "-t", "1", "--log-level", "warn", "--", "/bin/true",
        }, .{ .code = 0 }, &overridden);

        var contract_env = try self.env.clone(self.arena);
        try contract_env.put("ZINIT_E2E_CONTRACT", "present");
        self.checkWithEnv("the workload receives argv and env", &.{
            zinit,                                                             "--",       "/bin/sh", "-c",
            "printf 'arg=%s,%s env=%s' \"$1\" \"$2\" \"$ZINIT_E2E_CONTRACT\"", "contract", "one",     "two",
        }, .{ .code = 0, .has = &.{ "arg=one,two", "env=present" } }, &contract_env);
    }

    fn execContracts(self: *Suite, zinit: []const u8) !void {
        var dir_buf: [128]u8 = undefined;
        const dir = try makeTempDir(self.io, &dir_buf, "exec");
        defer removeTempDir(self.io, dir);
        var second_buf: [128]u8 = undefined;
        const second = try makeTempDir(self.io, &second_buf, "exec2");
        defer removeTempDir(self.io, second);

        var found_buf: [160]u8 = undefined;
        const found = try pathIn(&found_buf, dir, "zinit-e2e-found");
        var marker_buf: [160]u8 = undefined;
        const marker = try pathIn(&marker_buf, dir, "marker");
        try writeExecutable(self.io, found, "#!/bin/sh\nprintf found >\"$1\"\n");
        defer unlinkPath(self.io, marker);
        var env = try self.env.clone(self.arena);
        try env.put("PATH", dir);
        self.checkWithEnv("PATH finds a bare command", &.{
            zinit, "--", "zinit-e2e-found", marker,
        }, .{ .code = 0 }, &env);
        if (!fileExists(self.io, marker)) return self.fail("PATH finds a bare command", "the command did not run", .{});

        self.checkWithEnv("a missing bare name is 127", &.{ zinit, "--", "zinit-no-such-command" }, .{ .code = 127 }, &env);

        var file_path_env = try self.env.clone(self.arena);
        try file_path_env.put("PATH", "/bin/true");
        self.checkWithEnv("a PATH entry that is a file is 127", &.{ zinit, "--", "zinit-no-such-command" }, .{ .code = 127 }, &file_path_env);

        self.check("an explicit ENOTDIR path is 127", &.{ zinit, "--", "/bin/true/zinit-no-such-command" }, .{ .code = 127 });

        var denied_buf: [160]u8 = undefined;
        const denied = try pathIn(&denied_buf, dir, "zinit-e2e-denied");
        try writeFile(self.io, denied, "#!/bin/sh\nexit 0\n");
        self.checkWithEnv("a non-executable candidate is 126", &.{ zinit, "--", "zinit-e2e-denied" }, .{ .code = 126 }, &env);

        var search_buf: [160]u8 = undefined;
        const search = try pathIn(&search_buf, dir, "zinit-e2e-search");
        try writeFile(self.io, search, "#!/bin/sh\nexit 0\n");
        var search_exec_buf: [160]u8 = undefined;
        const search_exec = try pathIn(&search_exec_buf, second, "zinit-e2e-search");
        try writeExecutable(self.io, search_exec, "#!/bin/sh\nprintf found >\"$1\"\n");
        var search_env = try self.env.clone(self.arena);
        var path_buf: [400]u8 = undefined;
        const search_path = try std.mem.print(&path_buf, "{s}:{s}", .{ dir, second });
        try search_env.put("PATH", search_path);
        self.checkWithEnv("EACCES continues to the next PATH entry", &.{
            zinit, "--", "zinit-e2e-search", marker,
        }, .{ .code = 0 }, &search_env);
        if (!fileExists(self.io, marker)) return self.fail("EACCES continues to the next PATH entry", "the second candidate did not run", .{});

        var a_buf: [128]u8 = undefined;
        const a = try makeTempDir(self.io, &a_buf, "enoexec-a");
        defer removeTempDir(self.io, a);
        var b_buf: [128]u8 = undefined;
        const b = try makeTempDir(self.io, &b_buf, "enoexec-b");
        defer removeTempDir(self.io, b);
        var bad_buf: [160]u8 = undefined;
        const bad = try pathIn(&bad_buf, a, "zinit-e2e-probe");
        try writeExecutable(self.io, bad, "not an executable format\n");
        var good_buf: [160]u8 = undefined;
        const good = try pathIn(&good_buf, b, "zinit-e2e-probe");
        try writeExecutable(self.io, good, "#!/bin/sh\nprintf found >\"$1\"\nexit 23\n");
        var enoexec_env = try self.env.clone(self.arena);
        var enoexec_path_buf: [400]u8 = undefined;
        const enoexec_path = try std.mem.print(&enoexec_path_buf, "{s}:{s}", .{ a, b });
        try enoexec_env.put("PATH", enoexec_path);
        unlinkPath(self.io, marker);
        self.checkWithEnv("ENOEXEC does not skip to another candidate", &.{
            zinit, "--", "zinit-e2e-probe", marker,
        }, .{ .code = 126 }, &enoexec_env);
        if (fileExists(self.io, marker)) return self.fail("ENOEXEC does not skip to another candidate", "the second candidate ran", .{});

        var no_path: std.process.Environ.Map = .init(self.arena);
        try no_path.put("ZINIT_TRACING_CHILD", "OFF");
        self.checkWithEnv("a bare name works without PATH", &.{ zinit, "--", "true" }, .{ .code = 0 }, &no_path);

        var prog_buf: [160]u8 = undefined;
        const prog = try pathIn(&prog_buf, dir, "zinit-e2e-prog");
        try writeExecutable(self.io, prog, "#!/bin/sh\nexit 0\n");
        for ([_][]const u8{ "", ":/bin", "/bin:" }) |path_value| {
            var cwd_env = try self.env.clone(self.arena);
            try cwd_env.put("PATH", path_value);
            self.checkWithOptions("an empty PATH element uses the cwd", &.{ zinit, "--", "zinit-e2e-prog" }, .{ .code = 0 }, &cwd_env, dir);
        }

        const long = try self.arena.alloc(u8, 5000);
        @memset(long, 'x');
        const long_path = try std.mem.concat(self.arena, u8, &.{ long, ":", dir });
        var long_env = try self.env.clone(self.arena);
        try long_env.put("PATH", long_path);
        unlinkPath(self.io, marker);
        self.checkWithEnv("an overlong PATH candidate is skipped", &.{ zinit, "--", "zinit-e2e-found", marker }, .{ .code = 0 }, &long_env);
    }

    fn inheritanceContracts(self: *Suite, zinit: []const u8, self_exe: []const u8) !void {
        var dir_buf: [128]u8 = undefined;
        const dir = try makeTempDir(self.io, &dir_buf, "inherit");
        defer removeTempDir(self.io, dir);
        var marker_buf: [160]u8 = undefined;
        const marker = try pathIn(&marker_buf, dir, "marker");
        defer unlinkPath(self.io, marker);

        var caller: std.os.linux.sigset_t = std.os.linux.sigemptyset();
        std.os.linux.sigaddset(&caller, .USR2);
        var saved: std.os.linux.sigset_t = undefined;
        std.posix.sigprocmask(std.os.linux.SIG.BLOCK, &caller, &saved);
        defer std.posix.sigprocmask(std.os.linux.SIG.SETMASK, &saved, null);

        self.check("the workload gets the caller's mask", &.{ zinit, "--", self_exe, "--mask-child", marker }, .{ .code = 0 });
        if (!fileExists(self.io, marker)) return self.fail("the workload gets the caller's mask", "the workload saw the supervisor mask", .{});
        std.posix.sigprocmask(std.os.linux.SIG.SETMASK, &saved, null);

        for ([_][]const u8{ "TTIN", "TTOU" }) |which| {
            try self.ttinRestoreCase(zinit, self_exe, dir, which);
        }
    }

    fn ttinRestoreCase(self: *Suite, zinit: []const u8, self_exe: []const u8, dir: []const u8, which: []const u8) !void {
        var name_buf: [96]u8 = undefined;
        const name = try std.mem.print(&name_buf, "a workload does not inherit ignored {s}", .{which});
        var mark_buf: [160]u8 = undefined;
        const marker = try pathIn(&mark_buf, dir, which);
        defer unlinkPath(self.io, marker);

        const diag = try self.diagStart();
        defer self.diagEnd(diag);
        var child = std.process.spawn(self.io, .{
            .argv = &.{ zinit, "--", self_exe, "--self-stop", which, "--marker", marker },
            .environ_map = self.env,
            .stdin = .ignore,
            .stdout = .ignore,
            .stderr = .{ .file = diag.file },
        }) catch |err| return self.fail(name, "{t}", .{err});

        const zpid = child.id orelse return self.fail(name, "no zinit pid", .{});
        var workload_fd: ?std.os.linux.fd_t = null;
        defer {
            if (workload_fd) |fd| {
                _ = std.os.linux.pidfd_send_signal(fd, .KILL, null, 0);
                std.Io.Threaded.closeFd(fd);
            }
            if (child.id) |pid| _ = killAndReap(self.io, pid);
            child.id = null;
        }

        const spawn_deadline = nowMs(self.io) + 5_000;
        while (mainChildPid(self.io, zpid) == null) {
            if (nowMs(self.io) >= spawn_deadline) return self.fail(name, "zinit did not spawn the workload", .{});
            try std.Io.sleep(self.io, .fromMilliseconds(1), .awake);
        }

        const pid = mainChildPid(self.io, zpid) orelse return self.fail(name, "cannot discover the workload", .{});
        const raw_fd = std.os.linux.pidfd_open(pid, 0);
        if (std.os.linux.errno(raw_fd) != .SUCCESS) return self.fail(name, "cannot pin the workload", .{});
        workload_fd = @intCast(raw_fd);

        const stop_deadline = nowMs(self.io) + 5_000;
        while (true) {
            if (fileExists(self.io, marker)) return self.fail(name, "the ignored disposition was inherited", .{});
            const state = processState(self.io, pid) orelse return self.fail(name, "the workload disappeared", .{});
            if (state == 'T' or state == 't') break;
            if (nowMs(self.io) >= stop_deadline) return self.fail(name, "the workload never stopped", .{});
            try std.Io.sleep(self.io, .fromMilliseconds(1), .awake);
        }

        _ = std.posix.kill(zpid, .CONT) catch {};
        _ = std.os.linux.pidfd_send_signal(workload_fd.?, .KILL, null, 0);
        workload_fd = null;
        if (waitForPid(self.io, child.id, 5_000) == null)
            return self.fail(name, "zinit did not exit after the workload died", .{});
        child.id = null;
        self.pass(name);
    }

    fn userHup(self: *Suite, zinit: []const u8) !void {
        const name = "a user HUP reaches the workload";
        var dir_buf: [128]u8 = undefined;
        const dir = try makeTempDir(self.io, &dir_buf, "user-hup");
        defer removeTempDir(self.io, dir);
        var script_buf: [160]u8 = undefined;
        const script = try pathIn(&script_buf, dir, "script");
        var marker_buf: [160]u8 = undefined;
        const marker = try pathIn(&marker_buf, dir, "marker");
        var ready_buf: [160]u8 = undefined;
        const ready = try pathIn(&ready_buf, dir, "ready");
        defer unlinkPath(self.io, script);
        defer unlinkPath(self.io, marker);
        defer unlinkPath(self.io, ready);

        const body =
            "trap 'printf got > \"$1\"; exit 0' HUP\n" ++
            "printf ready > \"$2\"\n" ++
            "while :; do sleep 0.01; done\n";
        writeFile(self.io, script, body) catch return self.fail(name, "cannot publish the helper", .{});

        const argv = [_][]const u8{ zinit, "-t", "0", "--", "/bin/sh", script, marker, ready };
        try self.runScriptCase(.{
            .name = name,
            .argv = &argv,
            .signal = .HUP,
            .marker = marker,
            .ready = ready,
            .expected_exit = 0,
        });
    }

    fn rewriteContracts(self: *Suite, zinit: []const u8) !void {
        try self.userHup(zinit);

        var dir_buf: [128]u8 = undefined;
        const dir = try makeTempDir(self.io, &dir_buf, "rewrite-contract");
        defer removeTempDir(self.io, dir);
        var script_buf: [160]u8 = undefined;
        const script = try pathIn(&script_buf, dir, "script");
        var marker_buf: [160]u8 = undefined;
        const marker = try pathIn(&marker_buf, dir, "marker");
        var ready_buf: [160]u8 = undefined;
        const ready = try pathIn(&ready_buf, dir, "ready");
        defer unlinkPath(self.io, script);
        defer unlinkPath(self.io, marker);
        defer unlinkPath(self.io, ready);

        const body =
            "trap 'printf got > \"$1\"; exit 0' INT\n" ++
            "trap 'exit 0' TERM\n" ++
            "printf ready > \"$2\"\n" ++
            "while :; do sleep 0.01; done\n";
        writeFile(self.io, script, body) catch return self.fail("multiple rewrite rules take effect", "cannot publish the helper", .{});

        const chain_argv = [_][]const u8{
            zinit, "-t", "0", "-r", "TERM:INT", "-r", "HUP:USR1", "--", "/bin/sh", script, marker, ready,
        };
        try self.runScriptCase(.{
            .name = "multiple rewrite rules take effect",
            .argv = &chain_argv,
            .signal = .TERM,
            .marker = marker,
            .ready = ready,
            .expected_exit = 0,
        });

        unlinkPath(self.io, marker);
        var drop = std.process.spawn(self.io, .{
            .argv = &.{ zinit, "-t", "0", "-r", "TERM:0", "--", "/bin/sh", script, marker, ready },
            .environ_map = self.env,
            .stdin = .ignore,
            .stdout = .ignore,
            .stderr = .ignore,
        }) catch |err| return self.fail("a rewrite to 0 drops the signal", "{t}", .{err});
        const zpid = drop.id orelse return self.fail("a rewrite to 0 drops the signal", "no zinit pid", .{});
        defer terminateAndReap(self.io, &drop);

        if (!self.waitForPath(ready, 5_000)) return self.fail("a rewrite to 0 drops the signal", "the workload did not become ready", .{});
        _ = std.posix.kill(zpid, .TERM) catch {};
        std.Io.sleep(self.io, .fromMilliseconds(200), .awake) catch {};
        if (fileExists(self.io, marker)) return self.fail("a rewrite to 0 drops the signal", "TERM was forwarded", .{});
        _ = std.posix.kill(zpid, .USR1) catch {};
        if (waitForPid(self.io, drop.id, 5_000) == null) return self.fail("a rewrite to 0 drops the signal", "zinit did not exit after USR1", .{});
        drop.id = null;
        self.pass("a rewrite to 0 drops the signal");
    }

    fn groupFallback(self: *Suite, zinit: []const u8, self_exe: []const u8) !void {
        const name = "-g falls back to the child when it has no own group";
        var dir_buf: [128]u8 = undefined;
        const dir = try makeTempDir(self.io, &dir_buf, "group-fallback");
        defer removeTempDir(self.io, dir);
        var ready_buf: [160]u8 = undefined;
        const ready = try pathIn(&ready_buf, dir, "ready");
        var marker_buf: [160]u8 = undefined;
        const marker = try pathIn(&marker_buf, dir, "marker");
        defer unlinkPath(self.io, ready);
        defer unlinkPath(self.io, marker);

        const diag = try self.diagStart();
        defer self.diagEnd(diag);
        var child = std.process.spawn(self.io, .{
            .argv = &.{ zinit, "-g", "-t", "1", "--", self_exe, "--join-parent-group", "--ready", ready, "--marker", marker },
            .environ_map = self.env,
            .stdin = .ignore,
            .stdout = .ignore,
            .stderr = .{ .file = diag.file },
        }) catch |err| return self.fail(name, "{t}", .{err});
        defer terminateAndReap(self.io, &child);

        if (!self.waitForPath(ready, 5_000)) return self.fail(name, "the workload did not join a group", .{});
        _ = std.posix.kill(child.id.?, .TERM) catch return self.fail(name, "cannot signal zinit", .{});
        if (waitForPid(self.io, child.id, 5_000) == null) return self.fail(name, "zinit did not exit", .{});
        child.id = null;
        if (!fileExists(self.io, marker)) return self.fail(name, "the fallback signal did not reach the child", .{});
        self.pass(name);
    }

    fn numericGroupSignal(self: *Suite, zinit: []const u8, self_exe: []const u8) !void {
        const name = "-g reaches a non-leader member through numeric PGID";
        var dir_buf: [128]u8 = undefined;
        const dir = try makeTempDir(self.io, &dir_buf, "numeric-group");
        defer removeTempDir(self.io, dir);
        var script_buf: [160]u8 = undefined;
        const script = try pathIn(&script_buf, dir, "script");
        var main_buf: [160]u8 = undefined;
        const main_marker = try pathIn(&main_buf, dir, "main");
        var member_buf: [160]u8 = undefined;
        const member_marker = try pathIn(&member_buf, dir, "member");
        var inner_buf: [160]u8 = undefined;
        const inner_ready = try pathIn(&inner_buf, dir, "inner-ready");
        var ready_buf: [160]u8 = undefined;
        const ready = try pathIn(&ready_buf, dir, "ready");
        defer unlinkPath(self.io, script);
        defer unlinkPath(self.io, main_marker);
        defer unlinkPath(self.io, member_marker);
        defer unlinkPath(self.io, inner_ready);
        defer unlinkPath(self.io, ready);

        const body =
            "trap 'printf main > \"$1\"; exit 0' TERM\n" ++
            "/bin/sh -c 'trap \"printf member > \\\"$2\\\"; exit 0\" TERM; : > \"$3\"; while :; do sleep 0.01; done' sh \"$1\" \"$2\" \"$3\" &\n" ++
            "while [ ! -e \"$3\" ]; do sleep 0.01; done\n" ++
            "printf ready > \"$4\"\n" ++
            "while :; do sleep 0.01; done\n";
        writeFile(self.io, script, body) catch return self.fail(name, "cannot publish the helper", .{});

        const argv = [_][]const u8{
            self_exe,    "--seccomp-numeric", "--",
            zinit,       "-g",                "-t",
            "1",         "--",                "/bin/sh",
            script,      main_marker,         member_marker,
            inner_ready, ready,
        };
        try self.runScriptCase(.{
            .name = name,
            .argv = &argv,
            .signal = .TERM,
            .marker = member_marker,
            .ready = ready,
            .expected_exit = 0,
        });

        if (!fileExists(self.io, main_marker))
            return self.fail(name, "the main workload did not receive the group TERM", .{});
    }

    fn reapPressure(self: *Suite, zinit: []const u8) !void {
        const name = "batch orphan exit does not starve signal forwarding";
        var dir_buf: [128]u8 = undefined;
        const dir = try makeTempDir(self.io, &dir_buf, "reap-pressure");
        defer removeTempDir(self.io, dir);
        var pid_buf: [160]u8 = undefined;
        const pid_path = try pathIn(&pid_buf, dir, "pids");
        var ready_buf: [160]u8 = undefined;
        const ready = try pathIn(&ready_buf, dir, "ready");
        var ack_buf: [160]u8 = undefined;
        const ack = try pathIn(&ack_buf, dir, "ack");
        var usr1_buf: [160]u8 = undefined;
        const usr1 = try pathIn(&usr1_buf, dir, "usr1");
        defer unlinkPath(self.io, pid_path);
        defer unlinkPath(self.io, ready);
        defer unlinkPath(self.io, ack);
        defer unlinkPath(self.io, usr1);

        const script =
            "trap 'printf usr1 >\"$4\"' USR1\n" ++
            "i=0; while [ $i -lt 32 ]; do (trap '' TERM; exec sleep 30) & printf '%d ' $! >> \"$1\"; i=$((i+1)); done\n" ++
            ": >\"$2\"\n" ++
            "while [ ! -e \"$3\" ]; do sleep 0.01; done\n" ++
            "exit 0";
        const argv = [_][]const u8{
            zinit, "-s", "-t", "0", "--", "/bin/sh", "-c", script, "reap", pid_path, ready, ack, usr1,
        };

        const diag = try self.diagStart();
        defer self.diagEnd(diag);
        var child = std.process.spawn(self.io, .{
            .argv = &argv,
            .environ_map = self.env,
            .stdin = .ignore,
            .stdout = .ignore,
            .stderr = .{ .file = diag.file },
        }) catch |err| return self.fail(name, "{t}", .{err});
        defer terminateAndReap(self.io, &child);

        if (!self.waitForPath(ready, 5_000)) return self.fail(name, "the workload did not become ready", .{});
        const zpid = child.id orelse return self.fail(name, "no zinit pid", .{});

        var buf: [2048]u8 = undefined;
        const text = readSmallFile(self.io, pid_path, &buf) orelse return self.fail(name, "no descendant pids", .{});
        var pinned: [32]PinnedProcess = undefined;
        var pinned_count: usize = 0;
        defer for (pinned[0..pinned_count]) |process| process.close();
        var tokens = std.mem.tokenizeAny(u8, text, " \n\t");
        while (tokens.next()) |token| {
            if (pinned_count == pinned.len) break;
            const pid = std.fmt.parseInt(std.posix.pid_t, token, 10) catch continue;
            pinned[pinned_count] = PinnedProcess.pin(pid) catch
                return self.fail(name, "cannot pin a descendant", .{});
            pinned_count += 1;
        }

        if (pinned_count != 32)
            return self.fail(name, "expected 32 descendants, saw {d}", .{pinned_count});

        _ = std.posix.kill(zpid, .USR1) catch return self.fail(name, "cannot signal zinit", .{});
        if (!self.waitForPath(usr1, 5_000)) return self.fail(name, "forwarding stalled during reaping", .{});

        writeFile(self.io, ack, "ack") catch return self.fail(name, "cannot release the workload", .{});
        if (waitForPid(self.io, child.id, 10_000) == null) return self.fail(name, "zinit did not exit", .{});
        child.id = null;

        for (pinned[0..pinned_count]) |process| {
            if (!process.exited(self.io, 5_000))
                return self.fail(name, "a descendant outlived zinit", .{});
        }

        self.passf(name, "{d} descendants", .{pinned_count});
    }

    fn logContracts(self: *Suite, zinit: []const u8, max_log_level: ?[]const u8) !void {
        const max = parseLevel(max_log_level) orelse return;

        if (@backingInt(max) >= @backingInt(std.log.Level.info)) {
            self.check("an info-level exit report is emitted", &.{
                zinit, "--log-level", "info", "--", "/bin/sh", "-c", "exit 7",
            }, .{ .code = 7, .has = &.{"exited"} });
        }

        if (@backingInt(max) < @backingInt(std.log.Level.debug)) {
            self.check("a level above the build ceiling is rejected", &.{
                zinit, "--log-level", "debug", "--", "/bin/true",
            }, .{ .code = 1 });
        } else {
            self.check("a debug level is accepted when compiled in", &.{
                zinit, "--log-level", "debug", "--", "/bin/true",
            }, .{ .code = 0 });
        }
    }

    fn parseLevel(text: ?[]const u8) ?std.log.Level {
        const value = text orelse return null;
        if (std.mem.eql(u8, value, "error")) return .err;
        if (std.mem.eql(u8, value, "warn")) return .warn;
        if (std.mem.eql(u8, value, "info")) return .info;
        if (std.mem.eql(u8, value, "debug")) return .debug;
        return null;
    }

    fn pass(self: *Suite, name: []const u8) void {
        _ = self;
        std.debug.print(pass_prefix ++ "{s}\n", .{name});
    }

    fn passf(self: *Suite, name: []const u8, comptime format: []const u8, args: anytype) void {
        _ = self;
        std.debug.print(pass_prefix ++ "{s} (" ++ format ++ ")\n", .{name} ++ args);
    }

    fn summarize(self: *const Suite) u8 {
        if (self.failures != 0) {
            std.debug.print(suite_prefix ++ "{d} failed\n", .{self.failures});
            return 1;
        }

        std.debug.print(suite_prefix ++ "all checks passed\n", .{});
        return 0;
    }

    fn fail(self: *Suite, name: []const u8, comptime format: []const u8, args: anytype) void {
        self.failures += 1;
        std.debug.print(fail_prefix ++ "{s}: " ++ format ++ "\n", .{name} ++ args);
    }

    const Diag = struct { file: std.Io.File, before: usize };

    fn diagStart(self: *Suite) !Diag {
        const file = try std.Io.Dir.cwd().createFile(self.io, self.diag_path, .{});
        return .{ .file = file, .before = self.failures };
    }

    fn diagEnd(self: *Suite, diag: Diag) void {
        diag.file.close(self.io);
        if (self.failures == diag.before) return;

        const file = std.Io.Dir.openFileAbsolute(self.io, self.diag_path, .{}) catch return;
        defer file.close(self.io);
        var buf: [4096]u8 = undefined;
        var iov = [_][]u8{&buf};
        const n = file.readStreaming(self.io, &iov) catch return;
        if (n == 0) return;
        std.debug.print("    zinit stderr: {s}", .{buf[0..n]});
    }
};

fn makeTempDir(io: std.Io, buf: []u8, prefix: []const u8) ![:0]const u8 {
    const dir = try std.mem.printSentinel(buf, "/tmp/zinit-{s}-{d}-{x}", .{
        prefix, std.os.linux.getpid(), randomTag(io),
    }, 0);
    try std.Io.Dir.cwd().createDir(io, dir, .fromMode(0o700));
    return dir;
}

fn removeTempDir(io: std.Io, dir: []const u8) void {
    std.Io.Dir.cwd().deleteTree(io, dir) catch {};
}

fn unlinkPath(io: std.Io, path: []const u8) void {
    std.Io.Dir.cwd().deleteFile(io, path) catch {};
}

fn exitStatus(term: std.process.Child.Term) u8 {
    return switch (term) {
        .exited => |code| code,
        else => 255,
    };
}

fn drainFd(fd: std.os.linux.fd_t) usize {
    var total: usize = 0;
    var chunk: [4096]u8 = undefined;
    while (true) {
        const n = std.posix.read(fd, &chunk) catch |err| switch (err) {
            error.WouldBlock => return total,
            else => return total,
        };

        if (n == 0) return total;
        total += n;
    }
}

fn readSmallFile(io: std.Io, path: []const u8, buf: []u8) ?[]u8 {
    const file = std.Io.Dir.openFileAbsolute(io, path, .{}) catch return null;
    defer file.close(io);
    var iov = [_][]u8{buf};
    const n = file.readStreaming(io, &iov) catch return null;
    return if (n == 0) null else buf[0..n];
}

fn processState(io: std.Io, pid: std.posix.pid_t) ?u8 {
    var path_buf: [64]u8 = undefined;
    const path = std.mem.printSentinel(&path_buf, "/proc/{d}/stat", .{pid}, 0) catch return null;

    var buf: [512]u8 = undefined;
    const text = readSmallFile(io, path, &buf) orelse return null;

    const comm_end = std.mem.findScalarLast(u8, text, ')') orelse return null;
    if (comm_end + 2 >= text.len) return null;
    return text[comm_end + 2];
}

fn waitForRunning(io: std.Io, pid: std.posix.pid_t, timeout_ms: i64) bool {
    const deadline_ms = nowMs(io) + timeout_ms;
    while (nowMs(io) < deadline_ms) {
        const state = processState(io, pid) orelse return false;
        if (state == 'Z' or state == 'X') return false;
        if (state != 'T' and state != 't') return true;
        std.Io.sleep(io, .fromMilliseconds(1), .awake) catch return false;
    }

    return false;
}

fn waitForStopped(io: std.Io, pid: std.posix.pid_t, timeout_ms: i64) bool {
    const deadline_ms = nowMs(io) + timeout_ms;
    while (nowMs(io) < deadline_ms) {
        const state = processState(io, pid) orelse return false;
        if (state == 'T' or state == 't') return true;
        std.Io.sleep(io, .fromMilliseconds(1), .awake) catch return false;
    }

    return false;
}

fn waitForSyscall(io: std.Io, pid: std.posix.pid_t, number: i64, timeout_ms: i64) bool {
    const deadline_ms = nowMs(io) + timeout_ms;
    var path_buf: [64]u8 = undefined;
    const path = std.mem.printSentinel(&path_buf, "/proc/{d}/syscall", .{pid}, 0) catch return false;
    var buf: [128]u8 = undefined;
    while (nowMs(io) < deadline_ms) {
        if (readSmallFile(io, path, &buf)) |text| {
            const space = std.mem.findScalar(u8, text, ' ') orelse text.len;
            if ((std.fmt.parseInt(i64, text[0..space], 10) catch -1) == number) return true;
        }

        std.Io.sleep(io, .fromMilliseconds(1), .awake) catch return false;
    }

    return false;
}

fn nowNs(io: std.Io) i96 {
    return std.Io.Clock.awake.now(io).toNanoseconds();
}

fn nowMs(io: std.Io) i64 {
    return std.Io.Clock.awake.now(io).toMilliseconds();
}

fn terminateAndReap(io: std.Io, child: *std.process.Child) void {
    const pid = child.id orelse return;
    _ = std.posix.kill(pid, .TERM) catch {};
    if (waitForPid(io, pid, 2_000) != null or killAndReap(io, pid)) {
        child.id = null;
    } else {
        std.debug.print("cleanup: could not reap child {d}\n", .{pid});
    }
}

fn killAndReap(io: std.Io, pid: std.posix.pid_t) bool {
    var status: i32 = 0;
    const rc = std.os.linux.waitpid(pid, &status, std.os.linux.W.NOHANG);
    switch (std.os.linux.errno(rc)) {
        .SUCCESS => if (rc == @as(usize, @intCast(pid))) return true,
        .CHILD => return true,
        else => return false,
    }

    _ = std.posix.kill(pid, .KILL) catch {};
    return waitForPid(io, pid, 5_000) != null;
}

fn fileExists(io: std.Io, path: []const u8) bool {
    std.Io.Dir.cwd().access(io, path, .{}) catch return false;
    return true;
}

fn randomTag(io: std.Io) u64 {
    var tag: u64 = undefined;
    io.random(std.mem.asBytes(&tag));
    return tag;
}

fn pathIn(buf: []u8, dir: []const u8, name: []const u8) ![:0]const u8 {
    return std.mem.printSentinel(buf, "{s}/{s}", .{ dir, name }, 0);
}

fn unlinkIn(io: std.Io, dir: []const u8, name: []const u8) void {
    var buf: [96]u8 = undefined;
    const path = pathIn(&buf, dir, name) catch return;
    unlinkPath(io, path);
}

fn mainChildPid(io: std.Io, zinit_pid: std.posix.pid_t) ?std.posix.pid_t {
    var path_buf: [96]u8 = undefined;
    const path = std.mem.printSentinel(&path_buf, "/proc/{d}/task/{d}/children", .{
        zinit_pid, zinit_pid,
    }, 0) catch return null;

    var buf: [128]u8 = undefined;
    const text = readSmallFile(io, path, &buf) orelse return null;

    var tokens = std.mem.tokenizeAny(u8, text, " \n\t");
    const first = tokens.next() orelse return null;
    const pid = std.fmt.parseInt(std.posix.pid_t, first, 10) catch return null;
    return if (pid > 0) pid else null;
}

fn waitPidfdExit(io: std.Io, fd: std.os.linux.fd_t, timeout_ms: i64) ?i96 {
    const deadline_ms = nowMs(io) + timeout_ms;
    while (true) {
        var pollfd = [_]std.posix.pollfd{.{
            .fd = fd,
            .events = std.posix.POLL.IN,
            .revents = 0,
        }};

        const rc = std.posix.poll(&pollfd, 10) catch return null;
        if (rc > 0 and (pollfd[0].revents & std.posix.POLL.IN) != 0) return nowNs(io);
        if (nowMs(io) >= deadline_ms) return null;
    }
}

fn readPid(io: std.Io, path: []const u8) ?std.posix.pid_t {
    var buf: [32]u8 = undefined;
    const text = readSmallFile(io, path, &buf) orelse return null;
    const pid = std.fmt.parseInt(std.posix.pid_t, std.mem.trim(u8, text, " \r\n\t"), 10) catch return null;
    return if (pid > 0) pid else null;
}

fn writeFile(io: std.Io, path: []const u8, text: []const u8) !void {
    var tmp_buf: [128]u8 = undefined;
    const tmp = try std.mem.printSentinel(&tmp_buf, "{s}.tmp", .{path}, 0);
    const cwd = std.Io.Dir.cwd();
    const file = try cwd.createFile(io, tmp, .{ .exclusive = true, .permissions = .fromMode(0o600) });
    defer file.close(io);
    defer cwd.deleteFile(io, tmp) catch {};
    try file.writeStreamingAll(io, text);
    try cwd.renamePreserve(tmp, cwd, path, io);
}

fn writeExecutable(io: std.Io, path: [:0]const u8, text: []const u8) !void {
    const cwd = std.Io.Dir.cwd();
    const file = try cwd.createFile(io, path, .{ .exclusive = true, .permissions = .fromMode(0o755) });
    defer file.close(io);
    try file.writeStreamingAll(io, text);
}

fn waitForPid(io: std.Io, pid: ?std.posix.pid_t, timeout_ms: i64) ?i32 {
    const target = pid orelse return null;
    const deadline_ms = nowMs(io) + timeout_ms;

    while (true) {
        var status: i32 = 0;
        const rc = std.os.linux.waitpid(target, &status, std.os.linux.W.NOHANG);
        if (rc == @as(usize, @intCast(target))) return status;
        switch (std.os.linux.errno(rc)) {
            .SUCCESS => {},
            .CHILD => return null,
            else => return null,
        }

        if (nowMs(io) >= deadline_ms) return null;
        std.Io.sleep(io, .fromMilliseconds(1), .awake) catch return null;
    }
}

const PinnedChild = struct {
    pid: std.os.linux.pid_t,
    fd: std.os.linux.fd_t,
};

const PinnedProcess = struct {
    pid: std.posix.pid_t,
    fd: ?std.os.linux.fd_t,

    fn pin(pid: std.posix.pid_t) !PinnedProcess {
        const raw = std.os.linux.pidfd_open(pid, 0);
        return switch (std.os.linux.errno(raw)) {
            .SUCCESS => .{ .pid = pid, .fd = @intCast(raw) },
            .SRCH => .{ .pid = pid, .fd = null },
            else => error.PinFailed,
        };
    }

    fn close(self: PinnedProcess) void {
        if (self.fd) |fd| std.Io.Threaded.closeFd(fd);
    }

    fn exited(self: PinnedProcess, io: std.Io, timeout_ms: i64) bool {
        const fd = self.fd orelse return true;
        return waitPidfdExit(io, fd, timeout_ms) != null;
    }

    fn kill(self: PinnedProcess) void {
        const fd = self.fd orelse return;
        _ = std.os.linux.pidfd_send_signal(fd, .KILL, null, 0);
    }
};

fn waitForContinue(io: std.Io, pid: std.posix.pid_t) bool {
    const deadline_ms = nowMs(io) + 5_000;
    while (true) {
        var status: i32 = 0;
        const rc = std.os.linux.waitpid(
            pid,
            &status,
            std.os.linux.W.CONTINUED | std.os.linux.W.NOHANG,
        );

        if (rc == @as(usize, @intCast(pid))) {
            return (@as(u32, @intCast(status)) & 0xffff) == 0xffff;
        }

        switch (std.os.linux.errno(rc)) {
            .SUCCESS, .INTR => {},
            else => return false,
        }

        if (nowMs(io) >= deadline_ms) return false;
        std.Io.sleep(io, .fromMilliseconds(1), .awake) catch return false;
    }
}

const StopWait = enum { stopped, exited, failed };

fn waitForStop(io: std.Io, pid: std.os.linux.pid_t) StopWait {
    const stop_deadline = nowMs(io) + 5_000;
    while (true) {
        var status: i32 = 0;
        const rc = std.os.linux.waitpid(
            pid,
            &status,
            std.os.linux.W.UNTRACED | std.os.linux.W.NOHANG,
        );

        if (rc == @as(usize, @intCast(pid))) {
            if (std.os.linux.W.IFSTOPPED(@intCast(status))) return .stopped;
            return .exited;
        }

        switch (std.os.linux.errno(rc)) {
            .SUCCESS, .INTR => {},
            .CHILD => return .exited,
            else => return .failed,
        }

        if (nowMs(io) >= stop_deadline) return .failed;
        std.Io.sleep(io, .fromMilliseconds(1), .awake) catch return .failed;
    }
}

fn ptyFgDriver(io: std.Io, args: std.process.Args, env: *const std.process.Environ.Map) !u8 {
    var iter = args.iterate();
    while (iter.next()) |arg| {
        if (!std.mem.eql(u8, arg, "--pty-fg-driver")) continue;
        const marker = iter.next() orelse return @backingInt(DriverStage.usage);
        const zinit = iter.next() orelse return @backingInt(DriverStage.usage);

        if (std.os.linux.errno(std.os.linux.setsid()) != .SUCCESS)
            return @backingInt(DriverStage.setsid);
        if (std.os.linux.errno(std.os.linux.ioctl(
            std.os.linux.STDOUT_FILENO,
            std.os.linux.T.IOCSCTTY,
            0,
        )) != .SUCCESS) return @backingInt(DriverStage.ctty);

        const ignored = comptime std.os.linux.Sigaction{
            .handler = .{ .handler = std.posix.SIG.IGN },
            .mask = std.os.linux.sigemptyset(),
            .flags = 0,
        };
        std.posix.sigaction(std.posix.SIG.TTOU, &ignored, null);

        var child = std.process.spawn(io, .{
            .argv = &.{ zinit, "--", argv0(args), "--pty-fg-child", marker },
            .environ_map = env,
            .stdin = .inherit,
            .stdout = .inherit,
            .stderr = .inherit,
            .pgid = 0,
        }) catch return @backingInt(DriverStage.spawn);
        const zpid = child.id orelse return @backingInt(DriverStage.discover);
        defer {
            if (child.id) |pid| {
                _ = killAndReap(io, pid);
                child.id = null;
            }
        }

        std.posix.tcsetpgrp(std.os.linux.STDOUT_FILENO, zpid) catch
            return @backingInt(DriverStage.foreground);

        switch (waitForStop(io, zpid)) {
            .stopped => {},
            .exited => {
                child.id = null;
                return @backingInt(DriverStage.stopped);
            },
            .failed => return @backingInt(DriverStage.stopped),
        }

        std.posix.tcsetpgrp(std.os.linux.STDOUT_FILENO, zpid) catch
            return @backingInt(DriverStage.foreground);
        _ = std.posix.kill(zpid, .CONT) catch return @backingInt(DriverStage.cont);

        const final = waitForPid(io, child.id, 5_000) orelse return @backingInt(DriverStage.wait);
        child.id = null;
        const raw: u32 = @intCast(final);
        if (!std.os.linux.W.IFEXITED(raw) or std.os.linux.W.EXITSTATUS(raw) != 0)
            return @backingInt(DriverStage.status);
        return 0;
    }

    return @backingInt(DriverStage.usage);
}

fn ptyBgDriver(io: std.Io, args: std.process.Args, env: *const std.process.Environ.Map) !u8 {
    var iter = args.iterate();
    while (iter.next()) |arg| {
        if (!std.mem.eql(u8, arg, "--pty-bg-driver")) continue;
        const marker = iter.next() orelse return @backingInt(DriverStage.usage);
        const zinit = iter.next() orelse return @backingInt(DriverStage.usage);

        if (std.os.linux.errno(std.os.linux.setsid()) != .SUCCESS)
            return @backingInt(DriverStage.setsid);
        if (std.os.linux.errno(std.os.linux.ioctl(
            std.os.linux.STDOUT_FILENO,
            std.os.linux.T.IOCSCTTY,
            0,
        )) != .SUCCESS) return @backingInt(DriverStage.ctty);

        const own_raw = std.os.linux.getpgid(0);
        if (std.os.linux.errno(own_raw) != .SUCCESS) return @backingInt(DriverStage.discover);
        const own: std.os.linux.pid_t = @intCast(own_raw);
        std.posix.tcsetpgrp(std.os.linux.STDOUT_FILENO, own) catch
            return @backingInt(DriverStage.foreground);

        var ready_buf: [256]u8 = undefined;
        const ready = try std.mem.printSentinel(&ready_buf, "{s}.ready", .{marker}, 0);
        defer unlinkPath(io, ready);

        var child = std.process.spawn(io, .{
            .argv = &.{ zinit, "--", argv0(args), "--pty-bg-child", ready },
            .environ_map = env,
            .stdin = .ignore,
            .stdout = .inherit,
            .stderr = .inherit,
            .pgid = 0,
        }) catch return @backingInt(DriverStage.spawn);
        const zpid = child.id orelse return @backingInt(DriverStage.discover);
        defer terminateAndReap(io, &child);

        const spawn_deadline = nowMs(io) + 5_000;
        while (!fileExists(io, ready)) {
            if (nowMs(io) >= spawn_deadline) return @backingInt(DriverStage.discover);
            std.Io.sleep(io, .fromMilliseconds(1), .awake) catch
                return @backingInt(DriverStage.discover);
        }

        const foreground = std.posix.tcgetpgrp(std.os.linux.STDOUT_FILENO) catch
            return @backingInt(DriverStage.foreground);
        if (foreground != own) return @backingInt(DriverStage.foreground);

        std.posix.kill(zpid, .TERM) catch return @backingInt(DriverStage.signal);
        const status = waitForPid(io, child.id, 5_000) orelse return @backingInt(DriverStage.wait);
        child.id = null;
        const raw: u32 = @intCast(status);
        if (!std.os.linux.W.IFEXITED(raw) or std.os.linux.W.EXITSTATUS(raw) != 143)
            return @backingInt(DriverStage.status);
        writeFile(io, marker, "ok") catch return @backingInt(DriverStage.marker);
        return 0;
    }

    return @backingInt(DriverStage.usage);
}

fn ptyFgChild(io: std.Io, args: std.process.Args) !u8 {
    var iter = args.iterate();
    while (iter.next()) |arg| {
        if (!std.mem.eql(u8, arg, "--pty-fg-child")) continue;
        const marker = iter.next() orelse return 2;

        _ = std.posix.kill(std.os.linux.getpid(), .STOP) catch return 2;
        const pgrp = std.posix.tcgetpgrp(std.os.linux.STDOUT_FILENO) catch return 2;
        if (pgrp != std.os.linux.getpid()) return 2;
        writeFile(io, marker, "ok") catch return 2;
        return 0;
    }
    return 2;
}

fn ptyBgChild(io: std.Io, args: std.process.Args) !u8 {
    var iter = args.iterate();
    while (iter.next()) |arg| {
        if (!std.mem.eql(u8, arg, "--pty-bg-child")) continue;
        const ready = iter.next() orelse return 2;
        writeFile(io, ready, "ready") catch return 2;
        std.Io.sleep(io, .fromSeconds(30), .awake) catch {};
        return 0;
    }

    return 2;
}

fn ptyChild(io: std.Io, args: std.process.Args) !u8 {
    var iter = args.iterate();
    while (iter.next()) |arg| {
        const use_stdout = std.mem.eql(u8, arg, "--pty-child-out");
        if (!use_stdout and !std.mem.eql(u8, arg, "--pty-child")) continue;
        const marker = iter.next() orelse return 2;
        const tty_fd: std.os.linux.fd_t = if (use_stdout)
            std.os.linux.STDOUT_FILENO
        else
            std.os.linux.STDIN_FILENO;

        _ = std.posix.tcgetattr(tty_fd) catch return 2;

        const pid = std.os.linux.getpid();
        const sid: std.os.linux.pid_t = @intCast(std.os.linux.getsid(0));
        const pgrp: std.os.linux.pid_t = @intCast(std.os.linux.getpgid(0));
        const foreground = std.posix.tcgetpgrp(tty_fd) catch return 2;
        if (sid != pid or pgrp != pid or foreground != pid) return 2;

        writeFile(io, marker, "ok") catch return 2;
        return 0;
    }
    return 2;
}

fn graceResponder(io: std.Io, args: std.process.Args) !u8 {
    var iter = args.iterate();
    while (iter.next()) |arg| {
        if (!std.mem.eql(u8, arg, "--grace-responder")) continue;

        const pid_path = iter.next() orelse return 2;
        const ready_path = iter.next() orelse return 2;
        const term_path = iter.next() orelse return 2;
        return runGraceResponder(io, pid_path, ready_path, term_path);
    }

    return 2;
}

fn signalSet(sig: std.os.linux.SIG) std.os.linux.sigset_t {
    var set = std.os.linux.sigemptyset();
    std.os.linux.sigaddset(&set, sig);
    return set;
}

fn runGraceResponder(io: std.Io, pid_path: [:0]const u8, ready_path: [:0]const u8, term_path: [:0]const u8) !u8 {
    const term = comptime signalSet(std.posix.SIG.TERM);
    std.posix.sigprocmask(std.os.linux.SIG.SETMASK, &term, null);

    var pid_buf: [32]u8 = undefined;
    const pid_text = std.mem.print(&pid_buf, "{d}\n", .{std.os.linux.getpid()}) catch return 2;
    writeFile(io, pid_path, pid_text) catch return 2;
    writeFile(io, ready_path, "ready") catch return 2;

    var info: std.os.linux.siginfo_t = undefined;
    const rc = std.os.linux.syscall4(
        .rt_sigtimedwait,
        @intFromPtr(&term),
        @intFromPtr(&info),
        0,
        std.os.linux.NSIG / 8,
    );
    if (std.os.linux.errno(rc) != .SUCCESS) return 2;
    writeFile(io, term_path, "term") catch return 2;

    while (true) _ = std.os.linux.pause();
}

fn responder(io: std.Io, args: std.process.Args) !u8 {
    var iter = args.iterate();
    while (iter.next()) |arg| {
        if (!std.mem.eql(u8, arg, "--responder")) continue;

        const kind = iter.next() orelse return 2;
        const rt = std.mem.startsWith(u8, kind, "rt");
        const sent_value: u64 = if (std.mem.eql(u8, kind, "rtwide"))
            0x1234_5678_9abc_def0
        else
            0;

        const set = if (rt) comptime signalSet(rt_signal) else comptime signalSet(std.posix.SIG.TERM);
        std.posix.sigprocmask(std.os.linux.SIG.SETMASK, &set, null);

        if (rt) {
            try queueToParent(rt_signal, sent_value);
        } else {
            std.posix.kill(std.os.linux.getppid(), .TERM) catch {};
        }

        var info: std.os.linux.siginfo_t = undefined;
        while (true) {
            const rc = std.os.linux.syscall4(
                .rt_sigtimedwait,
                @intFromPtr(&set),
                @intFromPtr(&info),
                0,
                std.os.linux.NSIG / 8,
            );

            switch (std.os.linux.errno(rc)) {
                .SUCCESS => return report(io, &info, rt, sent_value),
                .INTR => continue,
                else => return 2,
            }
        }
    }

    return 2;
}

fn queueToParent(sig: std.os.linux.SIG, value: u64) !void {
    return queueTo(@intCast(std.os.linux.getppid()), sig, value);
}

fn queueTo(pid: std.posix.pid_t, sig: std.os.linux.SIG, value: u64) !void {
    var info = std.mem.zeroes(std.os.linux.siginfo_t);
    info.signo = sig;
    info.code = -1; // SI_QUEUE
    info.fields.common.first.piduid.pid = std.os.linux.getpid();
    info.fields.common.first.piduid.uid = std.os.linux.getuid();

    if (value == 0) {
        info.fields.common.second.value.int = 0;
    } else {
        info.fields.common.second.value.ptr = @ptrFromInt(value);
    }

    const rc = std.os.linux.syscall3(.rt_sigqueueinfo, @intCast(pid), @backingInt(sig), @intFromPtr(&info));
    if (std.os.linux.errno(rc) != .SUCCESS) {
        return error.SendFailed;
    }
}

fn formatReport(
    buf: []u8,
    info: *const std.os.linux.siginfo_t,
    is_rt: bool,
    sent_value: u64,
) ?[]const u8 {
    const parent: i32 = @intCast(std.os.linux.getppid());
    const value: u64 = if (!is_rt or info.code != -1)
        0
    else if (sent_value == 0)
        @intCast(info.fields.common.second.value.int)
    else
        @intFromPtr(info.fields.common.second.value.ptr);

    return std.mem.print(buf, "code={d} sender_is_parent={} value=0x{x}\n", .{
        info.code,
        info.fields.common.first.piduid.pid == parent,
        value,
    }) catch null;
}

fn report(io: std.Io, info: *const std.os.linux.siginfo_t, is_rt: bool, sent_value: u64) u8 {
    var buf: [128]u8 = undefined;
    const text = formatReport(&buf, info, is_rt, sent_value) orelse return 2;
    std.Io.File.stdout().writeStreamingAll(io, text) catch return 2;
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

fn optionValue(args: std.process.Args, name: []const u8) ?[]const u8 {
    var iter = args.iterate();
    while (iter.next()) |arg| {
        if (std.mem.eql(u8, arg, name)) return iter.next() orelse usage();
    }

    return null;
}

fn usage() noreturn {
    std.debug.print("usage: e2e --zinit <path> --expect-version <v> [--health] [--max-log-level <l>]\n", .{});
    std.process.exit(2);
}
