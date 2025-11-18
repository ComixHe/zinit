const std = @import("std");
const config = @import("config");
const builtin = @import("builtin");
const clap = @import("clap");

const forwardMode = enum { Child, ProcessGroup };

const Args = struct {
    signal: ?sig_t,
    mode: forwardMode,
    args: std.ArrayList(?[*:0]const u8),
    allocator: std.mem.Allocator,

    pub fn init(allocator: std.mem.Allocator, signal: ?sig_t, mode: forwardMode, args: []const []const u8) !Args {
        var list = try std.ArrayList(?[*:0]const u8).initCapacity(allocator, args.len + 1);
        for (args) |arg| {
            const new_arg = try allocator.allocSentinel(u8, arg.len, 0);
            @memcpy(new_arg[0..arg.len], arg);
            list.appendAssumeCapacity(new_arg);
        }

        list.appendAssumeCapacity(null);
        return .{ .signal = signal, .mode = mode, .args = list, .allocator = allocator };
    }

    pub fn deinit(self: *Args) void {
        releasePointerList(self.allocator, &self.args);
        self.args.deinit(self.allocator);
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
            try std.testing.expectEqualSentinel(u8, 0, std.mem.span(arg), std.mem.span(args.args.items[i].?));
            continue;
        }

        try std.testing.expectEqual(i, expected.len - 1);
    }
}

const Err = error{
    InvalidSignal,
    InvalidParams,
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

fn parseSignal(allocator: std.mem.Allocator, s: []const u8) ?sig_t {
    // test if s could convert to integer
    const val = std.fmt.parseUnsigned(u32, s, 10) catch null;
    if (val) |sig_num| {
        const sig_vals = sig_map.values();

        for (sig_vals) |sig| {
            if (sig_num == @intFromEnum(sig)) {
                return sig;
            }
        }

        return null;
    }

    // test if s is a signal name
    var sig_name = s;
    if (std.ascii.startsWithIgnoreCase(s, "SIG")) {
        sig_name = std.ascii.allocUpperString(allocator, s[3..]) catch |err| {
            std.log.err("unable to allocate memory: {s}", .{@errorName(err)});
            return null;
        };
    }

    defer {
        if (sig_name.ptr != s.ptr) {
            allocator.free(sig_name);
        }
    }

    return sig_map.get(sig_name);
}

test parseSignal {
    const allocator = std.testing.allocator;
    try std.testing.expectEqual(sig_t.TERM, parseSignal(allocator, "15"));
    try std.testing.expectEqual(sig_t.TERM, parseSignal(allocator, "SIGTERM"));
    try std.testing.expectEqual(sig_t.TERM, parseSignal(allocator, "TERM"));
    try std.testing.expectEqual(null, parseSignal(allocator, "UNKNOWN"));
    try std.testing.expectEqual(null, parseSignal(allocator, "32"));
    try std.testing.expectEqual(null, parseSignal(allocator, "0"));
}

fn parseArgs(allocator: std.mem.Allocator) !Args {
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
    var res = clap.parse(clap.Help, &params, parsers, .{
        .diagnostic = &diag,
        .allocator = allocator,
    }) catch |err| {
        try diag.reportToFile(.stderr(), err);
        return Err.InvalidParams;
    };
    defer res.deinit();

    if (res.args.help != 0) {
        try std.fs.File.stdout().writeAll("zinit - A tiny init for linux container.\n\n");
        try clap.helpToFile(.stdout(), clap.Help, &params, .{
            .indent = 2,
            .description_indent = 4,
            .description_on_new_line = false,
        });

        std.process.exit(0);
    }

    if (res.args.version != 0) {
        // this function is wired, fmt and option will not be used
        var buffer: [32]u8 = undefined;
        var stdout_writer = std.fs.File.stdout().writer(&buffer);
        const stdout = &stdout_writer.interface;
        config.version.format(stdout) catch unreachable;
        try stdout.flush();
        std.process.exit(0);
    }

    var pd_signal: ?sig_t = null;
    if (res.args.signal) |signal| {
        pd_signal = parseSignal(allocator, signal) orelse {
            return Err.InvalidSignal;
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
    std.posix.sigprocmask(std.posix.SIG.SETMASK, &set, &old_set);

    // zinit will make child process to be foreground process
    // if zinit try to read/write message from/to terminal, zinit will be suspended
    // due to signal SIGTTIN/SIGTTOU. After resuming, read/write will failed with EINTER.
    // so we ignore SIGTTIN and SIGTTOU.
    // Related signal: https://man7.org/linux/man-pages/man7/signal.7.html
    // Setting the TOSTOP flag on tty also has an effect:
    // https://man7.org/linux/man-pages/man3/termios.3.html
    const ignored = std.posix.Sigaction{
        .handler = .{ .handler = sig_t.IGN },
        .mask = .{0},
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

fn debugDump(desc: []const u8, ptr: [*:null]const ?[*:0]const u8) !void {
    if (comptime builtin.mode != .Debug) {
        return;
    }

    var buf: [1024]u8 = undefined;
    var stdout_writer = std.fs.File.stdout().writer(&buf);
    const stdout = &stdout_writer.interface;

    try stdout.print("{s}:[\n", .{desc});
    var i: usize = 0;
    while (ptr[i] != null) : (i += 1) {
        const val = ptr[i].?;
        var j: usize = 0;
        try stdout.writeByte('\t');
        while (val[j] != 0) : (j += 1) {
            try stdout.writeByte(val[j]);
        }
        try stdout.writeAll(",\n");
        try stdout.flush();
    }
    try stdout.print("]\n", .{});
    try stdout.flush();
}

fn releasePointerList(allocator: std.mem.Allocator, ptr: *const std.ArrayList(?[*:0]const u8)) void {
    for (ptr.items) |item| {
        if (item != null) {
            allocator.free(std.mem.span(item.?));
        }
    }
}

fn run(allocator: std.mem.Allocator, args_ptr: [*:null]const ?[*:0]const u8, sig_conf: *const SigConf) std.posix.pid_t {
    const pid = std.posix.fork() catch |err| {
        std.log.err("unable to fork: {s}", .{@errorName(err)});
        return -1;
    };

    if (pid == 0) {
        // move to new process group
        // we could forward signal easily
        std.posix.setpgid(0, 0) catch |err| {
            std.log.err("unable to move child process into a new process group: {s}", .{@errorName(err)});
            return -1;
        };

        // let child process to be foreground process
        // so that child process could take control of controlling terminal
        std.posix.tcsetpgrp(0, std.os.linux.getpid()) catch |err| switch (err) {
            std.posix.TermioSetPgrpError.NotATerminal => {
                // not running in terminal
            },
            else => {
                std.log.err("unable to set process group: {s}", .{@errorName(err)});
                return -1;
            },
        };

        // fork will inherit signal settings from parent process
        // so we restore signal settings within child process
        std.posix.sigprocmask(std.posix.SIG.SETMASK, &sig_conf.old_set, null);
        std.posix.sigaction(sig_t.TTIN, &sig_conf.ttin_action, null);
        std.posix.sigaction(sig_t.TTOU, &sig_conf.ttou_action, null);

        var early_free = false;
        var envp = std.process.getEnvMap(allocator) catch |err| {
            std.log.err("unable to get environment variables: {s}", .{@errorName(err)});
            return -1;
        };
        defer {
            if (!early_free) {
                envp.deinit();
            }
        }

        var envp_list = std.ArrayList(?[*:0]const u8).initCapacity(allocator, envp.count() + 1) catch |err| {
            std.log.err("unable to init environment variable list: {s}", .{@errorName(err)});
            return -1;
        };

        defer {
            releasePointerList(allocator, &envp_list);
            envp_list.deinit(allocator);
        }

        var iter = envp.iterator();
        while (iter.next()) |entry| {
            var env = allocator.allocSentinel(u8, entry.key_ptr.len + entry.value_ptr.len + 1, 0) catch |err| {
                std.log.err("unable to allocate memory: {s}", .{@errorName(err)});
                return -1;
            };

            @memcpy(env, entry.key_ptr.ptr);
            env[entry.key_ptr.len] = '=';
            @memcpy(env[entry.key_ptr.len + 1 ..], entry.value_ptr.ptr);
            envp_list.appendAssumeCapacity(env);
        }
        envp_list.appendAssumeCapacity(null);

        const tracing_child = blk: {
            // for convenience
            if (envp.get("ZINIT_TRACING_CHILD")) |val| {
                if (std.mem.eql(u8, val, "ON")) {
                    break :blk true;
                }

                if (std.mem.eql(u8, val, "OFF")) {
                    break :blk false;
                }
            }

            break :blk config.tracing_child;
        };

        // we do not need envp anymore
        envp.deinit();
        early_free = true;

        const envp_ptr: [*:null]const ?[*:0]const u8 = @ptrCast(envp_list.items.ptr);
        debugDump("environment variables", envp_ptr) catch |err| {
            std.log.err("unable to dump environment variables: {s}", .{@errorName(err)});
            return -1;
        };

        debugDump("arguments", args_ptr) catch |err| {
            std.log.err("unable to dump arguments: {s}", .{@errorName(err)});
            return -1;
        };

        if (tracing_child) {
            const dummy_handler = struct {
                pub fn handler(_: sig_t) callconv(.c) void {
                    _ = std.fs.File.stdout().write("received USR1 signal, continuing\n") catch {};
                }
            }.handler;

            const usr1_act: std.posix.Sigaction = .{
                .handler = .{ .handler = dummy_handler },
                .mask = .{0},
                .flags = 0,
            };

            var old_act: std.posix.Sigaction = undefined;
            std.posix.sigaction(sig_t.USR1, &usr1_act, &old_act);
            std.log.info("waiting for USR1 signal", .{});
            _ = std.os.linux.pause();

            std.posix.sigaction(sig_t.USR1, &old_act, null);
        }

        // This function should never return
        const ret = std.posix.execvpeZ(args_ptr[0].?, args_ptr, envp_ptr);
        std.log.err("unable to execvpe: {s}", .{@errorName(ret)});
        return -1;
    }

    return pid;
}

fn handleExitedProcess(pid: std.posix.pid_t) ?u8 {
    while (true) {
        const ret = std.posix.waitpid(-1, std.posix.W.NOHANG);
        if (ret.pid == 0) {
            std.log.debug("no process to handle", .{});
            break;
        }

        std.log.debug("child process {d} exited", .{ret.pid});
        if (ret.pid == pid) { // main child process exited
            var ret_code: u8 = 0;
            if (std.posix.W.IFEXITED(ret.status)) {
                ret_code = std.posix.W.EXITSTATUS(ret.status);
                std.log.info("main child process exited with code {d}.", .{ret_code});
            } else if (std.posix.W.IFSIGNALED(ret.status)) {
                const signal = std.posix.W.TERMSIG(ret.status);
                std.log.info("main child process exited with signal {d}.", .{signal});
                ret_code = 128 + @as(u8, @intCast(signal));
            } else {
                std.log.err("child process exited with unknown status", .{});
            }

            // try to broadcasting SIGTERM to child process and ignore the error
            // zinit unable to wait the rest of child process
            //TODO: should we wait other process exit?
            std.posix.kill(-pid, sig_t.TERM) catch {};

            return ret_code;
        }

        // collecting orphaned child process continually
    }

    return null;
}

pub fn main() u8 {
    var gpa = std.heap.GeneralPurposeAllocator(.{}){};
    defer if (gpa.deinit() == .leak) {
        std.log.err("memory leak has been detected.", .{});
    };

    var args = parseArgs(gpa.allocator()) catch |err| {
        std.log.err("unable to parse arguments: {s}", .{@errorName(err)});
        return 1;
    };
    defer args.deinit();

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

    const son = run(gpa.allocator(), @ptrCast(args.args.items.ptr), &sig_conf);
    if (son == -1) {
        std.log.err("unable to run child process.", .{});
        return 1;
    }

    const sigfd = std.posix.signalfd(-1, &sig_conf.current_set, 0) catch |err| {
        std.log.err("unable to create signalfd: {s}", .{@errorName(err)});
        return 1;
    };
    defer std.posix.close(sigfd);

    var buf: [@sizeOf(std.os.linux.signalfd_siginfo)]u8 = undefined;
    while (true) {
        std.log.debug("waiting for events", .{});
        @memset(std.mem.asBytes(&buf), 0);
        _ = std.posix.read(sigfd, &buf) catch |err| {
            std.log.err("unable to read from signalfd: {s}", .{@errorName(err)});
            return 1;
        };

        const siginfo = std.mem.bytesAsValue(std.os.linux.signalfd_siginfo, &buf);
        if (siginfo.signo != @intFromEnum(sig_t.CHLD)) {
            std.log.debug("forwarding signal {d}", .{siginfo.signo});
            const destination = switch (args.mode) {
                .Child => son,
                .ProcessGroup => -son,
            };

            std.posix.kill(destination, @enumFromInt(siginfo.signo)) catch |err| {
                std.log.err("unable to send signal to child: {s}", .{@errorName(err)});
                return 1;
            };
        }

        if (handleExitedProcess(son)) |code| {
            return code;
        }
    }

    unreachable;
}
