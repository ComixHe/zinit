const std = @import("std");
const config = @import("config");
const clap = @import("clap");
const utils = @import("utils.zig");

const Args = struct {
    signal: ?u5,
    args: std.ArrayList(?[*:0]const u8),
    allocator: std.mem.Allocator,

    pub fn init(allocator: std.mem.Allocator, signal: ?u5, args: []const []const u8) !Args {
        var list = try std.ArrayList(?[*:0]const u8).initCapacity(allocator, args.len + 1);
        for (args) |arg| {
            const new_arg = try allocator.allocSentinel(u8, arg.len, 0);
            @memcpy(new_arg[0..arg.len], arg);
            list.appendAssumeCapacity(new_arg);
        }

        list.appendAssumeCapacity(null);
        return .{ .signal = signal, .args = list, .allocator = allocator };
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

    return sig_map.get(sig_name);
}

fn parseArgs(allocator: std.mem.Allocator) !Args {
    const params = comptime clap.parseParamsComptime(
        \\-h, --help
        \\-v, --version
        \\-s, --signal <SIGNAL>     "The triggered signal when parent process dies"
        \\<ARG>...                 "Arguments to be passed to the child process"
    );

    const parsers = comptime .{
        .SIGNAL = clap.parsers.string,
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
        config.version.format("", .{}, std.io.getStdOut().writer()) catch unreachable;
        std.process.exit(0);
    }

    var pd_signal: ?u5 = null;
    if (res.args.signal) |signal| {
        pd_signal = parseSignal(allocator, signal) orelse {
            return Err.InvalidSignal;
        };
    }

    return try Args.init(allocator, pd_signal, res.positionals[0]);
}

const oldSigConf = struct {
    sigset: std.posix.sigset_t,
    ttin_action: std.posix.Sigaction,
    tto_action: std.posix.Sigaction,
};

fn handleSignal(comptime sig_list: anytype) oldSigConf {
    // not use sigfillset and sigdelset
    // these functions are not under std.posix
    var set: std.posix.sigset_t = [_]u32{1} ** 32;
    inline for (sig_list) |sig| {
        set[sig] = 0;
    }

    var old_set: std.posix.sigset_t = [_]u32{0} ** 32;
    std.posix.sigprocmask(std.os.linux.SIG.SETMASK, &set, &old_set);

    // we will make child process to be foreground process
    // if we try to read/write message to terminal, we will be blocked
    // and get SIGTTIN/SIGTTOU, which is not what we want
    // so we ignore SIGTTIN and SIGTTOU
    // related signal: https://man7.org/linux/man-pages/man7/signal.7.html
    // flag TOSTOP: https://man7.org/linux/man-pages/man3/termios.3.html
    const ignored = std.posix.Sigaction{
        .handler = .{ .handler = std_sig.IGN },
        .mask = [_]u32{0} ** 32,
        .flags = 0,
    };

    var old_ttin_action: std.posix.Sigaction = undefined;
    std.posix.sigaction(std_sig.TTIN, &ignored, &old_ttin_action);

    var old_tto_action: std.posix.Sigaction = undefined;
    std.posix.sigaction(std_sig.TTOU, &ignored, &old_tto_action);

    return .{
        .sigset = old_set,
        .ttin_action = old_ttin_action,
        .tto_action = old_tto_action,
    };
}

fn debugDump(desc: []const u8, ptr: [*:null]const ?[*:0]const u8) !void {
    if (comptime std.log.default_level != .debug) {
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

fn run(allocator: std.mem.Allocator, args_ptr: [*:null]const ?[*:0]const u8, sig_conf: oldSigConf) std.posix.pid_t {
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
        std.posix.sigprocmask(std.os.linux.SIG.SETMASK, &sig_conf.sigset, null);
        std.posix.sigaction(std_sig.TTIN, &sig_conf.ttin_action, null);
        std.posix.sigaction(std_sig.TTOU, &sig_conf.tto_action, null);

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

fn waitAllChildren(son: std.posix.pid_t) u32 {
    const ret = std.posix.waitpid(son, 0);
    return ret.status;
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

    if (std.os.linux.getpid() != 1) {
        std.log.info("zinit is not running as PID 1.", .{});
    }

    // we ignore all the signals that terminate with a core dump
    const ignored_sigs = [_]comptime_int{ std_sig.ABRT, std_sig.BUS, std_sig.FPE, std_sig.ILL, std_sig.SEGV, std_sig.SYS, std_sig.TRAP, std_sig.XCPU, std_sig.XFSZ, std_sig.TTIN, std_sig.TTOU };
    const sig_conf = handleSignal(ignored_sigs);

    if (args.signal) |signal| {
        _ = std.posix.prctl(std.os.linux.PR.SET_PDEATHSIG, .{signal}) catch |err| {
            std.log.err("failed to set parent death signal to {d}: {s}", .{ signal, @errorName(err) });
            return 1;
        };
    }

    const son = run(gpa.allocator(), @ptrCast(args.args.items.ptr), sig_conf);
    if (son == -1) {
        std.log.err("unable to run child process.", .{});
        return 1;
    }

    while (true) {
        const status = waitAllChildren(son);
        std.log.info("child process exited with status {d}.", .{status});
        break;
    }

    return 0;
}
