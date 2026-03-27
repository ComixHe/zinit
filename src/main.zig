const std = @import("std");
const config = @import("config");
const builtin = @import("builtin");
const clap = @import("clap");

const forwardMode = enum { Child, ProcessGroup };
const FAILURE_EXIT_CODE: i32 = 1;

const Args = struct {
    signal: ?sig_t,
    mode: forwardMode,
    args: []const ?[*:0]const u8,
    arena: std.heap.ArenaAllocator,

    pub fn init(allocator: std.mem.Allocator, signal: ?sig_t, mode: forwardMode, args: []const []const u8) !Args {
        var arena = std.heap.ArenaAllocator.init(allocator);
        const arena_allocator = arena.allocator();

        const argv = try arena_allocator.alloc(?[*:0]const u8, args.len + 1);

        for (args, 0..) |arg, i| {
            argv[i] = try arena_allocator.dupeSentinel(u8, arg, 0);
        }
        argv[args.len] = null;

        return .{ .arena = arena, .signal = signal, .mode = mode, .args = argv };
    }

    pub fn deinit(self: *Args) void {
        self.arena.deinit();
    }
};

test Args {
    const allocator = std.testing.allocator;
    const p_args: []const []const u8 = &[_][]const u8{ "foo", "--bar=x", "-v", "-c" };
    var args = try Args.init(allocator, sig_t.TERM, .Child, p_args);
    defer args.deinit();

    try std.testing.expectEqual(sig_t.TERM, args.signal);
    try std.testing.expectEqual(forwardMode.Child, args.mode);

    const expected: [5]?[*:0]const u8 = [_]?[*:0]const u8{ "foo", "--bar=x", "-v", "-c", null };
    comptime {
        std.debug.assert(expected.len == p_args.len + 1);
    }

    for (expected, 0..) |sentinel_arg, i| {
        if (sentinel_arg) |arg| {
            try std.testing.expectEqualSentinel(u8, 0, std.mem.span(arg), std.mem.span(args.args[i].?));
            continue;
        }

        try std.testing.expectEqual(i, expected.len - 1);
    }
}

const Err = error{
    InvalidSignal,
    InvalidParams,
    ForkFailed,
};

const sig_t = std.posix.SIG;

//NOTE: do we need to support realtime signals?
const sig_map = std.StaticStringMap(sig_t).initComptime(.{
    .{ "HUP", sig_t.HUP },
    .{ "INT", sig_t.INT },
    .{ "QUIT", sig_t.QUIT },
    .{ "ILL", sig_t.ILL },
    .{ "TRAP", sig_t.TRAP },
    .{ "ABRT", sig_t.ABRT },
    .{ "IOT", sig_t.IOT },
    .{ "BUS", sig_t.BUS },
    .{ "FPE", sig_t.FPE },
    .{ "KILL", sig_t.KILL },
    .{ "USR1", sig_t.USR1 },
    .{ "SEGV", sig_t.SEGV },
    .{ "USR2", sig_t.USR2 },
    .{ "PIPE", sig_t.PIPE },
    .{ "ALRM", sig_t.ALRM },
    .{ "TERM", sig_t.TERM },
    .{ "STKFLT", sig_t.STKFLT },
    .{ "CHLD", sig_t.CHLD },
    .{ "CONT", sig_t.CONT },
    .{ "STOP", sig_t.STOP },
    .{ "TSTP", sig_t.TSTP },
    .{ "TTIN", sig_t.TTIN },
    .{ "TTOU", sig_t.TTOU },
    .{ "URG", sig_t.URG },
    .{ "XCPU", sig_t.XCPU },
    .{ "XFSZ", sig_t.XFSZ },
    .{ "VTALRM", sig_t.VTALRM },
    .{ "PROF", sig_t.PROF },
    .{ "WINCH", sig_t.WINCH },
    .{ "IO", sig_t.IO },
    .{ "POLL", sig_t.POLL },
    .{ "PWR", sig_t.PWR },
    .{ "SYS", sig_t.SYS },
});

fn parseSignal(s: []const u8) ?sig_t {
    if (s.len == 0) {
        return null;
    }

    // test if s could convert to integer
    if (std.fmt.parseUnsigned(u32, s, 10)) |sig_num| {
        for (sig_map.values()) |sig| {
            if (sig_num == @intFromEnum(sig)) {
                return sig;
            }
        }

        return null;
    } else |_| {}

    // test if s is a signal name
    const name_to_check = if (std.ascii.startsWithIgnoreCase(s, "SIG"))
        s[3..]
    else
        s;

    if (name_to_check.len == 0 or name_to_check.len > 15) {
        return null;
    }

    var buf: [16]u8 = undefined;
    const upper_name = std.ascii.upperString(&buf, name_to_check);

    return sig_map.get(upper_name);
}

test parseSignal {
    try std.testing.expectEqual(sig_t.TERM, parseSignal("15"));
    try std.testing.expectEqual(sig_t.TERM, parseSignal("SIGTERM"));
    try std.testing.expectEqual(sig_t.TERM, parseSignal("TERM"));
    try std.testing.expectEqual(null, parseSignal("UNKNOWN"));
    try std.testing.expectEqual(null, parseSignal("32"));
    try std.testing.expectEqual(null, parseSignal("0"));
    try std.testing.expectEqual(null, parseSignal(""));
}

fn parseArgs(io: std.Io, allocator: std.mem.Allocator, args: std.process.Args) !?Args {
    const params = comptime clap.parseParamsComptime(
        \\-h, --help
        \\-v, --version
        \\-s, --signal <SIGNAL>     "The triggered signal when parent process dies"
        \\--forward-mode <MODE>    "The mode of forwarding signals to child processes"
        \\<ARG>...                 "Arguments to be passed to the child process"
    );

    const parsers = comptime .{
        .SIGNAL = clap.parsers.string,
        .MODE = clap.parsers.enumeration(forwardMode),
        .ARG = clap.parsers.string,
    };

    var diag = clap.Diagnostic{};
    var res = clap.parse(clap.Help, &params, parsers, args, .{
        .diagnostic = &diag,
        .allocator = allocator,
    }) catch |err| {
        try diag.reportToFile(io, std.Io.File.stderr(), err);
        return Err.InvalidParams;
    };
    defer res.deinit();

    if (res.args.help != 0) {
        const out = std.Io.File.stdout();
        try out.writeStreamingAll(io, "zinit - A tiny init for linux container.\n\n");
        try clap.helpToFile(io, out, clap.Help, &params, .{
            .indent = 2,
            .description_indent = 4,
            .description_on_new_line = false,
        });

        return null;
    }

    if (res.args.version != 0) {
        var buffer: [32]u8 = undefined;
        var stdout_writer = std.Io.File.stdout().writer(io, &buffer);
        const stdout = &stdout_writer.interface;
        try config.version.format(stdout);
        try stdout.flush();

        return null;
    }

    var pd_signal: ?sig_t = null;
    if (res.args.signal) |signal| {
        pd_signal = parseSignal(signal) orelse {
            std.log.err("invalid signal name or number: '{s}'", .{signal});
            return error.InvalidSignal;
        };
    }

    return try Args.init(allocator, pd_signal, res.args.@"forward-mode" orelse .Child, res.positionals[0]);
}

const SigConf = struct {
    old_set: std.posix.sigset_t,
    current_set: std.posix.sigset_t,
    ttin_action: std.posix.Sigaction,
    ttou_action: std.posix.Sigaction,
};

fn handleSignal(comptime sig_list: anytype) SigConf {
    var set = std.posix.sigfillset();
    inline for (sig_list) |sig| {
        std.os.linux.sigdelset(&set, sig);
    }

    var old_set: std.posix.sigset_t = undefined;
    std.posix.sigprocmask(sig_t.SETMASK, &set, &old_set);

    // zinit will make child process to be foreground process
    // if zinit try to read/write message from/to terminal, zinit will be suspended
    // due to signal SIGTTIN/SIGTTOU. After resuming, read/write will failed with EINTER.
    // so we ignore SIGTTIN and SIGTTOU.
    // Related signal: https://man7.org/linux/man-pages/man7/signal.7.html
    // Setting the TOSTOP flag on tty also has an effect:
    // https://man7.org/linux/man-pages/man3/termios.3.html
    const ignored = std.posix.Sigaction{
        .handler = .{ .handler = sig_t.IGN },
        .mask = std.posix.sigemptyset(),
        .flags = 0,
    };

    var old_ttin_action: std.posix.Sigaction = undefined;
    std.posix.sigaction(sig_t.TTIN, &ignored, &old_ttin_action);

    var old_ttou_action: std.posix.Sigaction = undefined;
    std.posix.sigaction(sig_t.TTOU, &ignored, &old_ttou_action);

    return .{
        .old_set = old_set,
        .current_set = set,
        .ttin_action = old_ttin_action,
        .ttou_action = old_ttou_action,
    };
}

fn debugDump(io: std.Io, desc: []const u8, ptr: [*:null]const ?[*:0]const u8) !void {
    var buf: [1024]u8 = undefined;
    var stdout_writer = std.Io.File.stdout().writer(io, &buf);
    const stdout = &stdout_writer.interface;

    try stdout.print("{s}: [\n", .{desc});

    var i: usize = 0;
    while (ptr[i]) |arg_ptr| : (i += 1) {
        const arg_slice = std.mem.span(arg_ptr);

        try stdout.writeAll("  \"");
        try stdout.writeAll(arg_slice);
        try stdout.writeAll("\",\n");
    }

    try stdout.writeAll("]\n");
    try stdout.flush();
}

fn reportChildError(comptime fmt: []const u8, err: anytype) noreturn {
    var buf: [256]u8 = undefined;
    const msg = std.fmt.bufPrint(&buf, "zinit child error: " ++ fmt ++ "\n", .{err}) catch "zinit child error: (message too long to format)\n";
    _ = std.os.linux.write(std.posix.STDERR_FILENO, msg.ptr, msg.len);
    std.os.linux.exit(FAILURE_EXIT_CODE);
}

fn run(args: *Args, environ: std.process.Environ, sig_conf: *const SigConf) !usize {
    defer args.deinit();

    const pid = std.os.linux.fork();
    var err = std.os.linux.errno(pid);
    if (err != .SUCCESS) {
        std.log.err("unable to fork: {s}", .{@tagName(err)});
        return Err.ForkFailed;
    }

    if (pid != 0) {
        return @intCast(pid);
    }

    const raw_allocator = std.heap.page_allocator;
    var child_arena_allocator = std.heap.ArenaAllocator.init(raw_allocator);
    defer child_arena_allocator.deinit(); // actually this is not necessary

    const child_allocator = child_arena_allocator.allocator();

    const env_view = environ.block.view();
    const new_env = child_allocator.allocSentinel(?[*:0]const u8, env_view.slice.len, null) catch |e| {
        reportChildError("env alloc failed: {s}", @errorName(e));
    };

    for (env_view.slice, 0..) |raw_ptr, i| {
        new_env[i] = child_allocator.dupeSentinel(u8, std.mem.span(raw_ptr), 0) catch |e| {
            reportChildError("env copy failed: {s}", @errorName(e));
        };
    }

    // move to new process group
    // we could forward signal easily
    var ret = std.os.linux.setpgid(0, 0);
    err = std.os.linux.errno(ret);
    if (err != .SUCCESS) {
        reportChildError("unable to set process group: {s}", @tagName(err));
    }

    // let child process to be foreground process
    // so that child process could take control of controlling terminal
    std.posix.tcsetpgrp(0, std.os.linux.getpid()) catch |e| {
        if (e != std.posix.TermioSetPgrpError.NotATerminal) {
            reportChildError("tcsetpgrp failed: {s}", @errorName(e));
        }
    };

    // fork will inherit signal settings from parent process
    // so we restore signal settings within child process
    std.posix.sigprocmask(sig_t.SETMASK, &sig_conf.old_set, null);
    std.posix.sigaction(sig_t.TTIN, &sig_conf.ttin_action, null);
    std.posix.sigaction(sig_t.TTOU, &sig_conf.ttou_action, null);

    const env_ptr: [*:null]const ?[*:0]const u8 = @ptrCast(new_env.ptr);
    const args_ptr: [*:null]const ?[*:0]const u8 = @ptrCast(args.args);

    if (comptime builtin.mode == .Debug) {
        var child_threaded_io = std.Io.Threaded.init(child_allocator, .{ .environ = environ });
        const io = child_threaded_io.io();

        debugDump(io, "environment variables", env_ptr) catch |e| {
            reportChildError("unable to dump environment variables: {s}", @errorName(e));
        };

        debugDump(io, "arguments", args_ptr) catch |e| {
            reportChildError("unable to dump arguments: {s}", @errorName(e));
        };
    }

    const tracing_child = blk: {
        // for convenience
        if (environ.getPosix("ZINIT_TRACING_CHILD")) |val| {
            if (std.ascii.eqlIgnoreCase(val, "ON")) {
                break :blk true;
            }

            if (std.ascii.eqlIgnoreCase(val, "OFF")) {
                break :blk false;
            }
        }

        break :blk config.tracing_child;
    };

    if (tracing_child) {
        const dummy_handler = struct {
            pub fn handler(_: sig_t) callconv(.c) void {}
        }.handler;

        const usr1_act: std.posix.Sigaction = .{
            .handler = .{ .handler = dummy_handler },
            .mask = std.posix.sigemptyset(),
            .flags = 0,
        };

        var old_act: std.posix.Sigaction = undefined;
        std.posix.sigaction(sig_t.USR1, &usr1_act, &old_act);
        _ = std.os.linux.pause();

        std.posix.sigaction(sig_t.USR1, &old_act, null);
    }

    // This function should never return
    ret = std.os.linux.execve(args_ptr[0].?, args_ptr, env_ptr);
    reportChildError("unable to execve: {s}", @tagName(std.os.linux.errno(ret)));
}

fn handleExitedProcess(pid: usize) ?u8 {
    var status: u32 = 0;
    var main_exit_code: ?u8 = null;

    while (true) {
        const ret = std.os.linux.waitpid(-1, &status, std.posix.W.NOHANG);
        if (ret == 0) {
            break;
        }

        const err = std.os.linux.errno(ret);
        switch (err) {
            .INTR => continue,
            .SUCCESS => {},
            .CHILD => {
                // maybe we don't have any child process
                main_exit_code = main_exit_code orelse 0;
                break;
            },
            else => {
                std.log.err("waitpid failed: {s}", .{@tagName(err)});
                break;
            },
        }

        var exit_code: u8 = 0;
        if (std.posix.W.IFEXITED(status)) {
            exit_code = std.posix.W.EXITSTATUS(status);
            std.log.info("child process {d} exited with code {d}.", .{ ret, exit_code });
        } else if (std.posix.W.IFSIGNALED(status)) {
            const signal = std.posix.W.TERMSIG(status);
            std.log.info("child process {d} exited with signal {d}.", .{ ret, signal });
            exit_code = @intCast(128 + @as(u32, @intFromEnum(signal)));
        } else {
            std.log.err("child process {d} exited with unknown status", .{ret});
            exit_code = 0;
        }

        if (ret == pid) { // main child process exited
            main_exit_code = exit_code;

            // try to broadcasting SIGTERM to child process and ignore the error
            std.posix.kill(-@as(std.posix.pid_t, @intCast(pid)), sig_t.TERM) catch {};

            // continue collecting other child processes
            continue;
        }

        // collecting orphaned child process continually
    }

    return main_exit_code;
}

var debug_allocator: std.heap.DebugAllocator(.{}) = .init;

pub fn main(init: std.process.Init.Minimal) u8 {
    const allocator, const is_debug = gpa: {
        break :gpa switch (builtin.mode) {
            .Debug => .{ debug_allocator.allocator(), true },
            .ReleaseSafe, .ReleaseFast, .ReleaseSmall => .{ std.heap.page_allocator, false },
        };
    };

    defer if (is_debug) {
        _ = debug_allocator.deinit();
    };

    var threaded: std.Io.Threaded = .init(allocator, .{
        .environ = init.environ,
        .argv0 = .init(init.args),
    });
    defer threaded.deinit();
    const io = threaded.io();

    const ret = parseArgs(io, allocator, init.args) catch |err| {
        std.log.err("unable to parse arguments: {s}", .{@errorName(err)});
        return 1;
    };

    var args = ret orelse {
        return 0;
    };

    // we ignore all the signals that terminate with a core dump
    const unblocked_sigs = .{ sig_t.ABRT, sig_t.BUS, sig_t.FPE, sig_t.ILL, sig_t.SEGV, sig_t.SYS, sig_t.TRAP, sig_t.XCPU, sig_t.XFSZ, sig_t.TTIN, sig_t.TTOU };
    const sig_conf = handleSignal(unblocked_sigs);

    if (args.signal) |signal| {
        _ = std.posix.prctl(std.posix.PR.SET_PDEATHSIG, .{@intFromEnum(signal)}) catch |err| {
            std.log.err("failed to set parent death signal to {d}: {s}", .{ signal, @errorName(err) });
            return 1;
        };
    }

    // make us become child subreaper, so that we could handle orphaned process
    // https://man7.org/linux/man-pages/man2/PR_SET_CHILD_SUBREAPER.2const.html
    _ = std.posix.prctl(std.posix.PR.SET_CHILD_SUBREAPER, .{1}) catch |err| {
        std.log.err("unable to set child subreaper: {s}", .{@errorName(err)});
        return 1;
    };

    //NOTE: args ownership transfer to run function
    const child = run(&args, init.environ, &sig_conf) catch {
        std.log.err("failed to start child process", .{});
        return 1;
    };

    const sigfd = std.posix.signalfd(-1, &sig_conf.current_set, 0) catch |err| {
        std.log.err("unable to create signalfd: {s}", .{@errorName(err)});
        return 1;
    };
    defer {
        const rc = std.os.linux.close(sigfd);
        if (rc != 0) {
            std.log.err("unable to close signalfd: {s}", .{@tagName(std.os.linux.errno(rc))});
        }
    }

    var sig_info: std.os.linux.signalfd_siginfo = undefined;
    while (true) {
        _ = std.posix.read(sigfd, std.mem.asBytes(&sig_info)) catch |err| {
            std.log.err("unable to read from signalfd: {s}", .{@errorName(err)});
            return 1;
        };

        if (sig_info.signo == @intFromEnum(sig_t.CHLD)) {
            if (handleExitedProcess(child)) |code| {
                return code;
            }

            continue;
        }

        std.log.debug("forwarding signal {d}", .{sig_info.signo});
        var destination = @as(std.posix.pid_t, @intCast(child));

        if (args.mode == .ProcessGroup) {
            // send signal to process group
            destination = -destination;
        }

        std.posix.kill(destination, @enumFromInt(sig_info.signo)) catch |err| {
            std.log.err("unable to send signal to child: {s}", .{@errorName(err)});
            return 1;
        };
    }

    unreachable;
}
