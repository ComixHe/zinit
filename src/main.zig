const std = @import("std");
const config = @import("config");
const builtin = @import("builtin");
const clap = @import("clap");
const utils = @import("utils.zig");

const forwardMode = enum {
    Child,
    ProcessGroup,
    Broadcast,
};

const Args = struct {
    signal: ?u5,
    mode: forwardMode,
    args: std.ArrayList(?[*:0]const u8),
    allocator: std.mem.Allocator,

    pub fn init(allocator: std.mem.Allocator, signal: ?u5, mode: forwardMode, args: []const []const u8) !Args {
        var list = try std.ArrayList(?[*:0]const u8).initCapacity(allocator, args.len + 1);
        for (args) |arg| {
            const new_arg = try allocator.allocSentinel(u8, arg.len, 0);
            @memcpy(new_arg[0..arg.len], arg);
            list.appendAssumeCapacity(new_arg);
        }

        list.appendAssumeCapacity(null);
        return .{ .signal = signal, .mode = mode, .args = list, .allocator = allocator };
    }

    pub fn deinit(self: Args) void {
        releasePointeList(self.allocator, &self.args);
    }
};

const Err = error{
    InvalidSignal,
    InvalidParams,
};

const std_sig = std.posix.SIG;

const sig_map = std.StaticStringMap(u5).initComptime(.{
    .{ "BLOCK", std_sig.BLOCK },
    .{ "UNBLOCK", std_sig.UNBLOCK },
    .{ "SETMASK", std_sig.SETMASK },
    .{ "HUP", std_sig.HUP },
    .{ "INT", std_sig.INT },
    .{ "QUIT", std_sig.QUIT },
    .{ "ILL", std_sig.ILL },
    .{ "TRAP", std_sig.TRAP },
    .{ "ABRT", std_sig.ABRT },
    .{ "IOT", std_sig.IOT },
    .{ "BUS", std_sig.BUS },
    .{ "FPE", std_sig.FPE },
    .{ "KILL", std_sig.KILL },
    .{ "USR1", std_sig.USR1 },
    .{ "SEGV", std_sig.SEGV },
    .{ "USR2", std_sig.USR2 },
    .{ "PIPE", std_sig.PIPE },
    .{ "ALRM", std_sig.ALRM },
    .{ "TERM", std_sig.TERM },
    .{ "STKFLT", std_sig.STKFLT },
    .{ "CHLD", std_sig.CHLD },
    .{ "CONT", std_sig.CONT },
    .{ "STOP", std_sig.STOP },
    .{ "TSTP", std_sig.TSTP },
    .{ "TTIN", std_sig.TTIN },
    .{ "TTOU", std_sig.TTOU },
    .{ "URG", std_sig.URG },
    .{ "XCPU", std_sig.XCPU },
    .{ "XFSZ", std_sig.XFSZ },
    .{ "VTALRM", std_sig.VTALRM },
    .{ "PROF", std_sig.PROF },
    .{ "WINCH", std_sig.WINCH },
    .{ "IO", std_sig.IO },
    .{ "POLL", std_sig.POLL },
    .{ "PWR", std_sig.PWR },
    .{ "SYS", std_sig.SYS },
    .{ "UNUSED", std_sig.UNUSED },
});

// support standard signal: 1~32
fn parseSignal(allocator: std.mem.Allocator, s: []const u8) ?u5 {
    // test if s could convert to integer
    const val = std.fmt.parseUnsigned(u5, s, 10) catch null;
    if (val != null) {
        return val;
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

fn parseArgs(allocator: std.mem.Allocator) !Args {
    const params = comptime clap.parseParamsComptime(
        \\-h, --help
        \\-v, --version
        \\-s, --signal <SIGNAL>     "The triggered signal when parent process dies"
        \\--forward-mode <MODE>    "The mode to forward signal to child process"
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
        diag.report(std.io.getStdErr().writer(), err) catch |e| {
            std.log.err("unable to write error: {s}", .{@errorName(e)});
        };

        return Err.InvalidParams;
    };
    defer res.deinit();

    if (res.args.help != 0) {
        const writer = std.io.getStdOut().writer();
        try writer.writeAll("zinit - A tiny init for linux container.\n\n");
        try clap.help(writer, clap.Help, &params, .{
            .indent = 2,
            .description_indent = 4,
            .description_on_new_line = false,
        });

        std.process.exit(0);
    }

    if (res.args.version != 0) {
        // this function is wired, fmt and option will not be used
        config.version.format("", .{}, std.io.getStdOut().writer()) catch unreachable;
        std.process.exit(0);
    }

    var pd_signal: ?u5 = null;
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
    // we not use std.c.sigfillset here because it requires linking with libc
    // sigfillset(glibc) will remove two additional internal signals 'SIGCANCEL(32)' and 'SIGSETXID(33)' for pthread private usage
    // so we not unblock these two signals is ok
    // https://sourceware.org/git?p=glibc.git;a=blob;f=signal/sigfillset.c;h=393df0ec8c7303c46464fe37f5e8db7d5f1dd9db;hb=refs/heads/master#l34
    var set = std.os.linux.all_mask;
    inline for (sig_list) |sig| {
        std.os.linux.sigdelset(&set, sig);
    }

    var old_set: std.posix.sigset_t = undefined;
    std.posix.sigprocmask(std.os.linux.SIG.SETMASK, &set, &old_set);

    // zinit will make child process to be foreground process
    // if zinit try to read/write message from/to terminal, zinit will be suspended
    // due to signal SIGTTIN/SIGTTOU. After resuming, read/write will failed with EINTER.
    // so we ignore SIGTTIN and SIGTTOU.
    // Related signal: https://man7.org/linux/man-pages/man7/signal.7.html
    // Setting the TOSTOP flag on tty also has an effect:
    // https://man7.org/linux/man-pages/man3/termios.3.html
    const ignored = std.posix.Sigaction{
        .handler = .{ .handler = std_sig.IGN },
        .mask = [_]u32{0} ** 32,
        .flags = 0,
    };

    var old_ttin_action: std.posix.Sigaction = undefined;
    std.posix.sigaction(std_sig.TTIN, &ignored, &old_ttin_action);

    var old_ttou_action: std.posix.Sigaction = undefined;
    std.posix.sigaction(std_sig.TTOU, &ignored, &old_ttou_action);

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

    const writer = std.io.getStdOut().writer();
    try writer.print("{s}:[\n", .{desc});
    var i: usize = 0;
    while (ptr[i] != null) : (i += 1) {
        const val = ptr[i].?;
        var j: usize = 0;
        try writer.writeByte('\t');
        while (val[j] != 0) : (j += 1) {
            try writer.writeByte(val[j]);
        }
        try writer.writeAll(",\n");
    }
    try writer.print("]\n", .{});
}

fn releasePointeList(allocator: std.mem.Allocator, ptr: *const std.ArrayList(?[*:0]const u8)) void {
    for (ptr.items) |item| {
        if (item != null) {
            allocator.free(std.mem.span(item.?));
        }
    }

    ptr.deinit();
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
        std.posix.sigprocmask(std.os.linux.SIG.SETMASK, &sig_conf.old_set, null);
        std.posix.sigaction(std_sig.TTIN, &sig_conf.ttin_action, null);
        std.posix.sigaction(std_sig.TTOU, &sig_conf.ttou_action, null);

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
        defer releasePointeList(allocator, &envp_list);

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

        // This function should never return
        const ret = std.posix.execvpeZ(args_ptr[0].?, args_ptr, envp_ptr);
        std.log.err("unable to execvpe: {s}", .{@errorName(ret)});
        return -1;
    }

    return pid;
}

fn handleExitedProcess(pid: std.posix.pid_t) ?u8 {
    while (true) {
        const ret = std.posix.waitpid(-1, std.os.linux.W.NOHANG);
        if (ret.pid == 0) {
            std.log.debug("no process to handle", .{});
            break;
        }

        std.log.debug("child process {d} exited", .{ret.pid});
        if (ret.pid == pid) { // main child process exited
            const writer = std.io.getStdOut().writer();
            if (std.os.linux.W.IFSTOPPED(ret.status)) {
                writer.print("main child process stopped with signal {d}.\n", .{std.os.linux.W.STOPSIG(ret.status)}) catch {};
                return null;
            }

            // try to broadcasting SIGTERM to child process and ignore the error
            // zinit unable to wait the rest of child process
            std.posix.kill(-pid, std_sig.TERM) catch {};

            if (std.os.linux.W.IFEXITED(ret.status)) {
                const code = std.os.linux.W.EXITSTATUS(ret.status);
                writer.print("main child process exited with code {d} normally.\n", .{code}) catch {};
                return code;
            }

            if (std.os.linux.W.IFSIGNALED(ret.status)) {
                const signal = std.os.linux.W.TERMSIG(ret.status);
                writer.print("main child process exited with signal {d}.\n", .{signal}) catch {};
                return 128 + @as(u8, @intCast(std.os.linux.W.TERMSIG(signal)));
            }

            std.log.err("child process exited with unknown status", .{});
            return 1;
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
    const unblocked_sigs = [_]comptime_int{ std_sig.ABRT, std_sig.BUS, std_sig.FPE, std_sig.ILL, std_sig.SEGV, std_sig.SYS, std_sig.TRAP, std_sig.XCPU, std_sig.XFSZ, std_sig.TTIN, std_sig.TTOU };
    const sig_conf = handleSignal(unblocked_sigs);

    if (args.signal) |signal| {
        _ = std.posix.prctl(std.os.linux.PR.SET_PDEATHSIG, .{signal}) catch |err| {
            std.log.err("failed to set parent death signal to {d}: {s}", .{ signal, @errorName(err) });
            return 1;
        };
    }

    // make us become child subreaper, so that we could handle orphaned process
    // https://man7.org/linux/man-pages/man2/PR_SET_CHILD_SUBREAPER.2const.html
    _ = std.posix.prctl(std.os.linux.PR.SET_CHILD_SUBREAPER, .{1}) catch |err| {
        std.log.err("unable to set child subreaper: {s}", .{@errorName(err)});
        return 1;
    };

    const son = run(gpa.allocator(), @ptrCast(args.args.items.ptr), &sig_conf);
    if (son == -1) {
        std.log.err("unable to run child process.", .{});
        return 1;
    }

    const epfd = std.posix.epoll_create1(0) catch |err| {
        std.log.err("unable to create epoll: {s}", .{@errorName(err)});
        return 1;
    };

    const sigfd = std.posix.signalfd(-1, &sig_conf.current_set, 0) catch |err| {
        std.log.err("unable to create signalfd: {s}", .{@errorName(err)});
        return 1;
    };

    var ep_data = std.os.linux.epoll_event{ .events = std.os.linux.EPOLL.IN, .data = .{ .fd = sigfd } };
    std.posix.epoll_ctl(epfd, std.os.linux.EPOLL.CTL_ADD, sigfd, &ep_data) catch |err| {
        std.log.err("unable to add sigfd to epoll: {s}", .{@errorName(err)});
        return 1;
    };

    var event: [1]std.os.linux.epoll_event = undefined;
    var buf: [@sizeOf(std.os.linux.signalfd_siginfo)]u8 = undefined;
    while (true) {
        std.log.debug("waiting for events", .{});
        @memset(std.mem.asBytes(&event[0]), 0);
        if (std.posix.epoll_wait(epfd, &event, 1000) == 0) {
            std.log.debug("no event after timeout", .{});
            continue;
        }

        @memset(std.mem.asBytes(&buf), 0);
        _ = std.posix.read(sigfd, &buf) catch |err| {
            std.log.err("unable to read from signalfd: {s}", .{@errorName(err)});
            return 1;
        };

        const siginfo = std.mem.bytesAsValue(std.os.linux.signalfd_siginfo, &buf);
        if (siginfo.signo != std_sig.CHLD) {
            std.log.debug("forwarding signal {d}", .{siginfo.signo});
            const destination = switch (args.mode) {
                .Child => son,
                .ProcessGroup => -son,
                .Broadcast => -1,
            };

            std.posix.kill(destination, @intCast(siginfo.signo)) catch |err| {
                std.log.err("unable to send signal to child: {s}", .{@errorName(err)});
                return 1;
            };
        }

        std.log.debug("process orphaned child process", .{});
        if (handleExitedProcess(son)) |code| {
            return code;
        }
    }

    unreachable;
}
