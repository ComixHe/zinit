const std = @import("std");
const config = @import("config");
const builtin = @import("builtin");
const clap = @import("clap");

pub const std_options: std.Options = .{
    .signal_stack_size = null,
    .networking = false,
};

const panic = if (builtin.mode == .Debug)
    std.debug.FullPanic(std.debug.defaultPanic)
else
    minimalPanic;

fn minimalPanic(msg: []const u8, _: ?*std.builtin.StackTrace, _: ?usize) noreturn {
    const prefix = "zinit panic: ";
    const stderr_fd = std.posix.STDERR_FILENO;

    _ = std.os.linux.write(stderr_fd, prefix, prefix.len);
    _ = std.os.linux.write(stderr_fd, msg.ptr, msg.len);
    _ = std.os.linux.write(stderr_fd, "\n", 1);

    std.os.linux.exit(1);
}

const LogLevel = enum(u8) {
    err = 0,
    warn = 1,
    info = 2,
    debug = 3,
};

const Logger = struct {
    var runtime_log_level: LogLevel = .warn;
    var target_fd: std.posix.fd_t = std.posix.STDERR_FILENO;

    pub fn setTargetFd(fd: std.posix.fd_t) void {
        target_fd = fd;
    }

    pub fn shouldLog(comptime level: LogLevel) bool {
        return @intFromEnum(level) <= @intFromEnum(runtime_log_level);
    }

    pub fn setLevel(level: LogLevel) void {
        runtime_log_level = level;
    }

    pub fn err(comptime format: []const u8, args: anytype) void {
        if (!shouldLog(.err)) return;
        writeFormattedLog(.err, format, args);
    }

    pub fn warn(comptime format: []const u8, args: anytype) void {
        if (!shouldLog(.warn)) return;
        writeFormattedLog(.warn, format, args);
    }

    pub fn info(comptime format: []const u8, args: anytype) void {
        if (!shouldLog(.info)) return;
        writeFormattedLog(.info, format, args);
    }

    pub fn debug(comptime format: []const u8, args: anytype) void {
        if (!shouldLog(.debug)) return;
        writeFormattedLog(.debug, format, args);
    }

    fn rawTryWriteAll(fd: std.posix.fd_t, bytes: []const u8) void {
        if (comptime builtin.is_test) {
            return;
        }

        var offset: usize = 0;
        while (offset < bytes.len) {
            const rc = std.os.linux.write(fd, bytes.ptr + offset, bytes.len - offset);
            switch (std.os.linux.errno(rc)) {
                .SUCCESS => offset += @intCast(rc),
                .INTR => continue,
                else => return,
            }
        }
    }

    fn writeFormattedLog(comptime level: LogLevel, comptime format: []const u8, args: anytype) void {
        var buf: [512]u8 = undefined;
        const prefix = "[zinit]" ++ switch (level) {
            inline .err => "ERROR",
            inline .warn => "WARNING",
            inline .info => "INFO",
            inline .debug => "DEBUG",
        } ++ ":";

        const msg = std.fmt.bufPrint(&buf, prefix ++ format ++ "\n", args) catch prefix ++ "(log message too long)\n";
        rawTryWriteAll(target_fd, msg);
    }
};

const sig_t = std.posix.SIG;

const ZinitError = error{
    InvalidSignal,
    InvalidParams,
    InvalidRewrite,
    InvalidExitCode,
    SysCallError,
    DuplicateSignal,
    CycleRewrite,
};

const sig_map = std.StaticStringMap(u32).initComptime(.{
    .{ "HUP", @intFromEnum(sig_t.HUP) },
    .{ "INT", @intFromEnum(sig_t.INT) },
    .{ "QUIT", @intFromEnum(sig_t.QUIT) },
    .{ "ILL", @intFromEnum(sig_t.ILL) },
    .{ "TRAP", @intFromEnum(sig_t.TRAP) },
    .{ "ABRT", @intFromEnum(sig_t.ABRT) },
    .{ "IOT", @intFromEnum(sig_t.IOT) },
    .{ "BUS", @intFromEnum(sig_t.BUS) },
    .{ "FPE", @intFromEnum(sig_t.FPE) },
    .{ "KILL", @intFromEnum(sig_t.KILL) },
    .{ "USR1", @intFromEnum(sig_t.USR1) },
    .{ "SEGV", @intFromEnum(sig_t.SEGV) },
    .{ "USR2", @intFromEnum(sig_t.USR2) },
    .{ "PIPE", @intFromEnum(sig_t.PIPE) },
    .{ "ALRM", @intFromEnum(sig_t.ALRM) },
    .{ "TERM", @intFromEnum(sig_t.TERM) },
    .{ "STKFLT", @intFromEnum(sig_t.STKFLT) },
    .{ "CHLD", @intFromEnum(sig_t.CHLD) },
    .{ "CONT", @intFromEnum(sig_t.CONT) },
    .{ "STOP", @intFromEnum(sig_t.STOP) },
    .{ "TSTP", @intFromEnum(sig_t.TSTP) },
    .{ "TTIN", @intFromEnum(sig_t.TTIN) },
    .{ "TTOU", @intFromEnum(sig_t.TTOU) },
    .{ "URG", @intFromEnum(sig_t.URG) },
    .{ "XCPU", @intFromEnum(sig_t.XCPU) },
    .{ "XFSZ", @intFromEnum(sig_t.XFSZ) },
    .{ "VTALRM", @intFromEnum(sig_t.VTALRM) },
    .{ "PROF", @intFromEnum(sig_t.PROF) },
    .{ "WINCH", @intFromEnum(sig_t.WINCH) },
    .{ "IO", @intFromEnum(sig_t.IO) },
    .{ "POLL", @intFromEnum(sig_t.POLL) },
    .{ "PWR", @intFromEnum(sig_t.PWR) },
    .{ "SYS", @intFromEnum(sig_t.SYS) },
});

fn isValidU32(sig_num: u32) bool {
    return sig_num > 0 and sig_num < std.posix.NSIG;
}

fn parseRealtimeSignal(s: []const u8) ?u32 {
    const rtmin_prefixes = [_][]const u8{ "RTMIN", "SIGRTMIN" };
    inline for (rtmin_prefixes) |prefix| {
        if (std.ascii.startsWithIgnoreCase(s, prefix)) {
            const base = std.posix.sigrtmin();
            const suffix = s[prefix.len..];
            if (suffix.len == 0) return base;
            if (suffix[0] != '+') return null;

            const offset = std.fmt.parseUnsigned(u8, suffix[1..], 10) catch return null;
            const value = @as(u32, base) + offset;
            if (!isValidU32(value) or value > std.posix.sigrtmax()) return null;
            return @intCast(value);
        }
    }

    const rtmax_prefixes = [_][]const u8{ "RTMAX", "SIGRTMAX" };
    inline for (rtmax_prefixes) |prefix| {
        if (std.ascii.startsWithIgnoreCase(s, prefix)) {
            const base = std.posix.sigrtmax();
            const suffix = s[prefix.len..];
            if (suffix.len == 0) return base;
            if (suffix[0] != '-') return null;

            const offset = std.fmt.parseUnsigned(u8, suffix[1..], 10) catch return null;
            if (offset > base) return null;
            const value = @as(u32, base) - offset;
            if (!isValidU32(value)) return null;
            return @intCast(value);
        }
    }

    return null;
}

fn parseSignal(s: []const u8) !u32 {
    if (s.len == 0) {
        return ZinitError.InvalidParams;
    }

    if (std.fmt.parseUnsigned(u32, s, 10)) |sig_num| {
        if (isValidU32(sig_num)) return @intCast(sig_num);
        return ZinitError.InvalidSignal;
    } else |_| {}

    if (parseRealtimeSignal(s)) |sig_num| {
        return sig_num;
    }

    const name_to_check = if (std.ascii.startsWithIgnoreCase(s, "SIG"))
        s[3..]
    else
        s;

    if (name_to_check.len == 0 or name_to_check.len > 15) {
        return ZinitError.InvalidSignal;
    }

    var buf: [16]u8 = undefined;
    const upper_name = std.ascii.upperString(&buf, name_to_check);
    return sig_map.get(upper_name) orelse ZinitError.InvalidSignal;
}

const RewriteMap = struct {
    entries: [std.posix.NSIG]u32 = [_]u32{0} ** std.posix.NSIG,

    pub fn get(self: *const RewriteMap, sig: u32) u32 {
        return self.entries[sig];
    }

    pub fn has(self: *const RewriteMap, sig: u32) bool {
        return self.entries[sig] != 0;
    }

    pub fn set(self: *RewriteMap, old_sig: u32, new_sig: u32) void {
        self.entries[old_sig] = new_sig;
    }
};

fn hasCycle(map: *const RewriteMap, start_node: u32) bool {
    std.debug.assert(start_node > 0 and start_node < std.posix.NSIG);

    var current = start_node;
    var count: usize = 0;
    while (true) {
        const next_node = map.get(current);
        if (next_node == 0) {
            return false;
        }

        count += 1;
        if (count >= std.posix.NSIG) return true;
        current = next_node;
    }

    unreachable;
}

fn parseRewrite(map: *RewriteMap, value: []const u8) !void {
    var kv = std.mem.splitScalar(u8, value, ':');

    const old = kv.next() orelse return ZinitError.InvalidRewrite;
    const old_sig = try parseSignal(old);

    const new = kv.next() orelse return ZinitError.InvalidRewrite;
    const new_sig = try parseSignal(new);

    if (kv.peek() != null) {
        return ZinitError.InvalidRewrite;
    }

    if (old_sig == new_sig) {
        return ZinitError.DuplicateSignal;
    }

    if (hasCycle(map, new_sig)) {
        return ZinitError.CycleRewrite;
    }

    if (map.has(old_sig)) {
        return ZinitError.DuplicateSignal;
    }

    map.set(old_sig, new_sig);
}

fn mapSignal(rewrite: ?RewriteMap, signo: u32) u32 {
    if (rewrite) |m| {
        const mapped = m.get(signo);
        if (mapped != 0) return mapped;
    }

    return signo;
}

const Args = struct {
    allocator: std.mem.Allocator,
    log_level: LogLevel,
    pdeath_signal: ?u32,
    rewrites: ?RewriteMap,
    expected_exit: ?u8,
    subreaper: bool,
    new_session: bool,
    is_terminal: bool,
    tracing_child: bool,
    argv: [:null]const ?[*:0]const u8,
    envs: [:null]const ?[*:0]const u8,

    pub fn init(
        allocator: std.mem.Allocator,
        envs: [:null]const ?[*:0]const u8,
        log_level: LogLevel,
        pdeath_signal: ?u32,
        rewrites: ?RewriteMap,
        expected_exit: ?u8,
        subreaper: bool,
        new_session: bool,
        is_terminal: bool,
        tracing_child: bool,
        args: []const []const u8,
    ) !Args {
        const argv = try allocator.allocSentinel(?[*:0]const u8, args.len, null);

        for (args, 0..) |arg, i| {
            argv[i] = @as([*:0]const u8, @ptrCast(arg.ptr));
        }

        return .{
            .allocator = allocator,
            .log_level = log_level,
            .pdeath_signal = pdeath_signal,
            .rewrites = rewrites,
            .expected_exit = expected_exit,
            .subreaper = subreaper,
            .tracing_child = tracing_child,
            .argv = argv,
            .envs = envs,
            .new_session = new_session,
            .is_terminal = is_terminal,
        };
    }

    pub fn deinit(self: *Args) void {
        self.allocator.free(self.argv);
    }
};

fn parseLogLevel(value: []const u8) !LogLevel {
    if (std.ascii.eqlIgnoreCase(value, "error")) return .err;
    if (std.ascii.eqlIgnoreCase(value, "warning")) return .warn;
    if (std.ascii.eqlIgnoreCase(value, "info")) return .info;
    if (std.ascii.eqlIgnoreCase(value, "debug")) return .debug;
    return ZinitError.InvalidParams;
}

fn parseExpectedExit(value: []const u8) !u8 {
    return std.fmt.parseUnsigned(u8, value, 10) catch ZinitError.InvalidExitCode;
}

fn parseTracingChild(env_val: ?[]const u8, default: bool) bool {
    const val = env_val orelse return default;
    return if (std.ascii.eqlIgnoreCase(val, "OFF")) false else if (std.ascii.eqlIgnoreCase(val, "ON")) true else default;
}

fn printHelp(io: std.Io) !void {
    const out = std.Io.File.stdout();
    try out.writeStreamingAll(io,
        \\zinit - A tiny init for linux containers.
        \\
        \\Usage: zinit [options] <ARG>...
        \\
        \\Options:
        \\  -h, --help                     Display this help and exit
        \\  -v, --version                  Output version information and exit
        \\      --log-level <LEVEL>        Set log level: error, warn(default), info, or debug
        \\  -p, --signal <SIGNAL>          The triggered signal when parent process dies
        \\  -s, --subreaper                Enable child subreaper mode explicitly
        \\  -n, --new-session              Enable new session mode explicitly
        \\  -r, --rewrite <OLD:NEW>...     Rewrite a forwarded signal before sending to the child
        \\  -e, --expect-exit <CODE>       Map a child exit code to 0
        \\
    );
}

fn printVersion(io: std.Io) !void {
    var buffer: [16]u8 = undefined;
    var writer = std.Io.File.stdout().writer(io, buffer[0..]);
    try config.version.format(&writer.interface);
    try writer.flush();
}

fn parseArgsWithIo(io: std.Io, allocator: std.mem.Allocator, args_iter: *std.process.Args.Iterator, environ: std.process.Environ) !?Args {
    const params = [_]clap.Param(u8){
        .{ .id = 'h', .names = .{ .short = 'h', .long = "help" } },
        .{ .id = 'v', .names = .{ .short = 'v', .long = "version" } },
        .{ .id = 'L', .names = .{ .long = "log-level" }, .takes_value = .one },
        .{ .id = 'p', .names = .{ .short = 'p', .long = "signal" }, .takes_value = .one },
        .{ .id = 's', .names = .{ .short = 's', .long = "subreaper" } },
        .{ .id = 'r', .names = .{ .short = 'r', .long = "rewrite" }, .takes_value = .one },
        .{ .id = 'e', .names = .{ .short = 'e', .long = "expect-exit" }, .takes_value = .one },
        .{ .id = 'n', .names = .{ .short = 'n', .long = "new-session" } },
        .{ .id = 'A', .takes_value = .one },
    };

    var diag = clap.Diagnostic{};
    var parser = clap.streaming.Clap(u8, std.process.Args.Iterator){
        .params = &params,
        .iter = args_iter,
        .diagnostic = &diag,
    };

    var rewrite_map: ?RewriteMap = null;
    var child_args: std.ArrayListUnmanaged([]const u8) = .empty;
    defer child_args.deinit(allocator);

    var log_level: LogLevel = .warn;
    var pdeath_signal: ?u32 = null;
    var subreaper_flag = false;
    var expected_exit: ?u8 = null;
    var new_session = false;

    while (parser.next() catch |err| {
        try diag.reportToFile(io, .stderr(), err);
        return err;
    }) |arg| {
        switch (arg.param.id) {
            'h' => {
                try printHelp(io);
                return null;
            },
            'v' => {
                try printVersion(io);
                return null;
            },
            'n' => new_session = true,
            'L' => log_level = try parseLogLevel(arg.value.?),
            'p' => pdeath_signal = try parseSignal(arg.value.?),
            's' => subreaper_flag = true,
            'r' => {
                if (rewrite_map == null) rewrite_map = .{};
                try parseRewrite(&rewrite_map.?, arg.value.?);
            },
            'e' => expected_exit = try parseExpectedExit(arg.value.?),
            'A' => {
                try child_args.append(allocator, arg.value.?);

                while (args_iter.next()) |remainder| {
                    try child_args.append(allocator, remainder);
                }

                break;
            },
            else => unreachable,
        }
    }

    if (child_args.items.len == 0) return error.InvalidParams;
    const tracing_child = parseTracingChild(environ.getPosix("ZINIT_TRACING_CHILD"), config.tracing_child);

    if (new_session) {
        if (rewrite_map == null) {
            rewrite_map = .{};
        }

        const stop = @intFromEnum(sig_t.STOP);
        const tstp = @intFromEnum(sig_t.TSTP);
        const ttou = @intFromEnum(sig_t.TTOU);
        const ttin = @intFromEnum(sig_t.TTIN);

        if (!rewrite_map.?.has(tstp)) {
            rewrite_map.?.set(tstp, stop);
        }

        if (!rewrite_map.?.has(ttou)) {
            rewrite_map.?.set(ttou, stop);
        }

        if (!rewrite_map.?.has(ttin)) {
            rewrite_map.?.set(ttin, stop);
        }
    }

    return try Args.init(
        allocator,
        environ.block.slice,
        log_level,
        pdeath_signal,
        rewrite_map,
        expected_exit,
        subreaper_flag,
        new_session,
        try std.Io.File.stdout().isTty(io),
        tracing_child,
        child_args.items,
    );
}

fn parseArgs(allocator: std.mem.Allocator, init: std.process.Init.Minimal) !?Args {
    var args_iter = init.args.iterate();
    defer args_iter.deinit();
    _ = args_iter.skip(); // skip argv0

    var threaded: std.Io.Threaded = .init(allocator, .{
        .environ = init.environ,
        .argv0 = .init(init.args),
    });
    defer threaded.deinit();

    return parseArgsWithIo(threaded.io(), allocator, &args_iter, init.environ);
}

const SHUTDOWN_GRACE_PERIOD_NS: u64 = 5 * std.time.ns_per_s;

const SigConf = struct {
    old_set: std.posix.sigset_t,
    current_set: std.posix.sigset_t,
    ttin_action: std.posix.Sigaction,
    ttou_action: std.posix.Sigaction,
    ignore_detached_sig: bool = false,
};

fn handleSignal(comptime sig_list: []const sig_t) SigConf {
    var set = std.posix.sigfillset();
    for (sig_list) |sig| {
        std.posix.sigdelset(&set, sig);
    }

    var old_set: std.posix.sigset_t = undefined;
    std.posix.sigprocmask(sig_t.SETMASK, &set, &old_set);

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

fn reportChildError(comptime fmt: []const u8, args: anytype) noreturn {
    var buf: [512]u8 = undefined;
    const msg = std.fmt.bufPrint(&buf, "zinit child error: " ++ fmt ++ "\n", args) catch "zinit child error: (message too long to format)\n";
    _ = std.os.linux.write(std.posix.STDERR_FILENO, msg.ptr, msg.len);
    std.os.linux.exit(1);
}

fn restoreChildSignals(sig_conf: *const SigConf) void {
    std.posix.sigprocmask(sig_t.SETMASK, &sig_conf.old_set, null);

    var unblock_all = std.posix.sigfillset();
    std.posix.sigprocmask(sig_t.UNBLOCK, &unblock_all, null);

    std.posix.sigaction(sig_t.TTIN, &sig_conf.ttin_action, null);
    std.posix.sigaction(sig_t.TTOU, &sig_conf.ttou_action, null);
}

fn setupChildTerminal(args: Args) void {
    if (args.new_session) {
        const sid = std.os.linux.setsid();
        const err = std.os.linux.errno(sid);
        if (err != .SUCCESS) {
            reportChildError("unable to create session: {s}", .{@tagName(err)});
        }
    }

    if (!args.is_terminal) {
        return;
    }

    const rc = std.os.linux.ioctl(std.posix.STDIN_FILENO, std.posix.T.IOCSCTTY, 0);
    const err = std.os.linux.errno(rc);
    if (err != .SUCCESS) {
        Logger.debug("unable to acquire controlling tty: {s}", .{@tagName(err)});
    }
}

fn run(args: *Args, sig_conf: *SigConf) !usize {
    // detach zinit from control terminal, let child handle it
    if (args.new_session and args.is_terminal) {
        const rc = std.os.linux.ioctl(std.posix.STDIN_FILENO, std.posix.T.IOCNOTTY, 0);
        const err = std.os.linux.errno(rc);
        if (err != .SUCCESS) { // maybe the in/out has been redirected
            Logger.debug("unable to detach from terminal: {s}", .{@tagName(err)});
        } else {
            if (std.os.linux.getsid(0) == std.os.linux.getpid()) {
                // if session leader detachs from the control terminal
                // kernel will send SIGHUP and SIGCONT to the process group
                // so we should ignore the first SIGHUP/SIGCONT while forwarding signals
                sig_conf.ignore_detached_sig = true;
                Logger.debug("detaching from controlling terminal, ignoring first SIGHUP/SIGCONT", .{});
            } else {
                Logger.debug("detached from controlling terminal, but was not session leader", .{});
            }
        }
    }

    const pid = std.os.linux.fork();
    const err = std.os.linux.errno(pid);
    if (err != .SUCCESS) {
        Logger.err("unable to fork: {s}", .{@tagName(err)});
        return ZinitError.SysCallError;
    }

    if (pid != 0) {
        return @intCast(pid);
    }

    defer args.deinit();

    restoreChildSignals(sig_conf);
    setupChildTerminal(args.*);

    if (args.pdeath_signal) |sig| {
        _ = std.posix.prctl(std.posix.PR.SET_PDEATHSIG, .{sig}) catch |e| {
            reportChildError("unable to set parent death signal: {s}", .{@errorName(e)});
        };
    }

    if (args.tracing_child) {
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

    const ret = std.os.linux.execve(args.argv[0].?, args.argv, args.envs);
    reportChildError("unable to execve: {s}", .{@tagName(std.os.linux.errno(ret))});
}

const ExitStatusClass = enum { exited, signaled, unknown };

fn classifyExitStatus(status: u32) ExitStatusClass {
    if (std.posix.W.IFEXITED(status)) return .exited;
    if (std.posix.W.IFSIGNALED(status)) return .signaled;
    return .unknown;
}

fn extractExitCode(status: u32) u8 {
    if (std.posix.W.IFEXITED(status)) return std.posix.W.EXITSTATUS(status);
    if (std.posix.W.IFSIGNALED(status)) return @intCast(128 + @intFromEnum(std.posix.W.TERMSIG(status)));
    return 0;
}

fn mapExitCode(expected_exit: ?u8, exit_code: u8) u8 {
    return if (expected_exit) |c| if (c == exit_code) 0 else exit_code else exit_code;
}

const ReapResult = union(enum) {
    pid: usize,
    none_ready,
    no_children,
};

fn reapOne(flags: u32, status: *u32) !ReapResult {
    while (true) {
        const ret = std.os.linux.waitpid(-1, status, flags);
        if (ret == 0) return .none_ready;

        const err = std.os.linux.errno(ret);
        switch (err) {
            .INTR => continue,
            .SUCCESS => return .{ .pid = @intCast(ret) },
            .CHILD => return .no_children,
            else => {
                Logger.debug("unable to waitpid: {s}", .{@tagName(err)});
                return ZinitError.SysCallError;
            },
        }
    }
}

fn terminateProcessGroup(pid: usize, sig: u32) void {
    std.posix.kill(-@as(std.posix.pid_t, @intCast(pid)), @enumFromInt(sig)) catch |err| switch (err) {
        error.ProcessNotFound => {},
        else => Logger.err("unable to send signal {d} to process group: {s}", .{ sig, @errorName(err) }),
    };
}

fn logExitedProcess(pid: usize, status: u32) void {
    switch (classifyExitStatus(status)) {
        .exited => Logger.info("child process {d} exited with code {d}.", .{ pid, std.posix.W.EXITSTATUS(status) }),
        .signaled => Logger.info("child process {d} exited with signal {d}.", .{ pid, std.posix.W.TERMSIG(status) }),
        .unknown => Logger.err("child process {d} exited with unknown status", .{pid}),
    }
}

const ProcessState = struct {
    child: usize,
    expected_exit: ?u8,
    rewrites: ?RewriteMap,
    sigfd: std.posix.fd_t,
    shutdown: ?ShutdownState = null,
    new_session: bool,
    ignore_hup: bool = false,
    ignore_cont: bool = false,
};

const ShutdownState = struct {
    main_pid: usize,
    exit_code: u8,
    timerfd: std.posix.fd_t,
    kill_sent: bool = false,
};

fn handleSignalEvent(state: *ProcessState) ?u8 {
    while (true) {
        var sig_info: std.os.linux.signalfd_siginfo = undefined;
        _ = std.posix.read(state.sigfd, std.mem.asBytes(&sig_info)) catch |err| switch (err) {
            error.WouldBlock => return null,
            else => {
                Logger.err("unable to read sigfd: {s}", .{@errorName(err)});
                return 1;
            },
        };

        Logger.debug("receive signal: {d}", .{sig_info.signo});

        if (sig_info.signo != @intFromEnum(sig_t.CHLD)) {
            forwardSignal(state, sig_info.signo);
            continue;
        }

        const reap = handleExitedProcess(state.child, state.expected_exit) catch |err| {
            Logger.err("waitpid failed: {s}", .{@errorName(err)});
            return 1;
        };

        if (reap.main_exit_code) |code| {
            if (reap.no_children) return code;
            if (state.shutdown == null) {
                return startShutdown(state, code);
            }
        } else if (state.shutdown != null and reap.no_children) {
            return state.shutdown.?.exit_code;
        }
    }
}

fn getSignalDestination(new_session: bool, child_pid: usize) std.posix.pid_t {
    return if (new_session)
        -@as(std.posix.pid_t, @intCast(child_pid))
    else
        @intCast(child_pid);
}

fn forwardSignal(state: *ProcessState, signo: u32) void {
    if (state.ignore_hup and signo == @intFromEnum(sig_t.HUP)) {
        state.ignore_hup = false;
        return;
    }

    if (state.ignore_cont and signo == @intFromEnum(sig_t.CONT)) {
        state.ignore_cont = false;
        return;
    }

    const signal_to_send = mapSignal(state.rewrites, signo);
    Logger.debug("forwarding signal {d} as {d}", .{ signo, signal_to_send });

    const destination = getSignalDestination(state.new_session, state.child);

    std.posix.kill(destination, @enumFromInt(signal_to_send)) catch |err| {
        Logger.err("unable to send signal to child: {s}", .{@errorName(err)});
    };
}

fn startShutdown(state: *ProcessState, exit_code: u8) ?u8 {
    const timerfd = createShutdownTimer() catch |err| {
        Logger.err("unable to create shutdown timer: {s}", .{@errorName(err)});
        return exit_code;
    };

    state.shutdown = .{
        .main_pid = state.child,
        .exit_code = exit_code,
        .timerfd = timerfd,
    };

    terminateProcessGroup(state.child, @intFromEnum(sig_t.TERM));
    return null;
}

fn handleTimerEvent(state: *ProcessState) ?u8 {
    const shutdown_state = &(state.shutdown orelse return null);
    consumeTimer(shutdown_state.timerfd);

    if (!shutdown_state.kill_sent) {
        shutdown_state.kill_sent = true;
        terminateProcessGroup(shutdown_state.main_pid, @intFromEnum(sig_t.KILL));
    }

    if (reapShutdownChildren() catch |err| {
        Logger.err("waitpid failed during shutdown: {s}", .{@errorName(err)});
        return shutdown_state.exit_code;
    }) {
        return shutdown_state.exit_code;
    }

    return null;
}

fn createShutdownTimer() !std.posix.fd_t {
    const raw_fd = std.os.linux.timerfd_create(.MONOTONIC, .{ .CLOEXEC = true, .NONBLOCK = true });
    switch (std.os.linux.errno(raw_fd)) {
        .SUCCESS => {},
        else => |err| {
            Logger.warn("failed to create timerfd: {s}", .{@tagName(err)});
            return ZinitError.SysCallError;
        },
    }

    const timerfd: std.posix.fd_t = @intCast(raw_fd);
    errdefer tryClose(timerfd);

    const timer_spec = std.os.linux.itimerspec{
        .it_interval = .{ .sec = 0, .nsec = 0 },
        .it_value = .{
            .sec = @intCast(SHUTDOWN_GRACE_PERIOD_NS / std.time.ns_per_s),
            .nsec = @intCast(SHUTDOWN_GRACE_PERIOD_NS % std.time.ns_per_s),
        },
    };

    const set_rc = std.os.linux.timerfd_settime(timerfd, .{}, &timer_spec, null);
    switch (std.os.linux.errno(set_rc)) {
        .SUCCESS => return timerfd,
        else => |err| {
            Logger.warn("failed to set timerfd: {s}", .{@tagName(err)});
            return ZinitError.SysCallError;
        },
    }
}

fn consumeTimer(timerfd: std.posix.fd_t) void {
    var expirations: u64 = 0;
    _ = std.posix.read(timerfd, std.mem.asBytes(&expirations)) catch |err| if (err != error.WouldBlock) {
        Logger.err("unable to read timerfd: {s}", .{@errorName(err)});
    };
}

fn handleExitedProcess(pid: usize, expected_exit: ?u8) !struct { main_exit_code: ?u8, no_children: bool } {
    var status: u32 = 0;
    var main_exit_code: ?u8 = null;
    var no_children = false;

    while (true) {
        switch (try reapOne(std.posix.W.NOHANG, &status)) {
            .pid => |reaped_pid| {
                logExitedProcess(reaped_pid, status);

                if (reaped_pid == pid) {
                    main_exit_code = mapExitCode(expected_exit, extractExitCode(status));
                }
            },
            .none_ready => break,
            .no_children => {
                no_children = true;
                break;
            },
        }
    }

    return .{ .main_exit_code = main_exit_code, .no_children = no_children };
}

fn reapShutdownChildren() !bool {
    var status: u32 = 0;
    while (true) {
        switch (try reapOne(std.posix.W.NOHANG, &status)) {
            .pid => |reaped_pid| logExitedProcess(reaped_pid, status),
            .none_ready => return false,
            .no_children => return true,
        }
    }
}

fn tryClose(fd: std.posix.fd_t) void {
    if (fd < 0) {
        return;
    }

    while (true) {
        const close_rc = std.os.linux.close(fd);
        switch (std.os.linux.errno(close_rc)) {
            .SUCCESS => return,
            .INTR => continue,
            else => |err| {
                Logger.err("unable to close fd {d}: {s}", .{ fd, @tagName(err) });
                break;
            },
        }
    }
}

test tryClose {
    tryClose(-1);
    const fd = try std.posix.openat(std.posix.AT.FDCWD, "/dev/null", .{ .ACCMODE = .WRONLY }, 0o600);

    tryClose(fd);
    tryClose(5);
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

    var args = parseArgs(allocator, init) catch |err| {
        Logger.err("unable to parse arguments: {s}", .{@errorName(err)});
        return 1;
    } orelse return 0;
    defer args.deinit();
    Logger.setLevel(args.log_level);

    const unblocked_sigs = [_]sig_t{ .ABRT, .BUS, .FPE, .ILL, .SEGV, .SYS, .TRAP, .TTIN, .TTOU };
    var sig_conf = handleSignal(&unblocked_sigs);

    const should_enable_subreaper = args.subreaper or std.os.linux.getpid() != 1;
    if (should_enable_subreaper) {
        _ = std.posix.prctl(std.posix.PR.SET_CHILD_SUBREAPER, .{1}) catch |err| {
            Logger.err("unable to set child subreaper: {s}", .{@errorName(err)});
            return 1;
        };
    }

    const child = run(&args, &sig_conf) catch {
        Logger.err("failed to start child process", .{});
        return 1;
    };

    const sigfd = std.posix.signalfd(-1, &sig_conf.current_set, std.os.linux.SFD.NONBLOCK) catch |err| {
        Logger.err("unable to create signalfd: {s}", .{@errorName(err)});
        return 1;
    };
    defer {
        Logger.debug("close signalfd", .{});
        tryClose(sigfd);
    }

    var poll_fds: [2]std.posix.pollfd = undefined;
    poll_fds[0] = .{
        .fd = sigfd,
        .events = std.posix.POLL.IN,
        .revents = 0,
    };
    var poll_fds_len: usize = 1;

    var process_state = ProcessState{
        .child = child,
        .expected_exit = args.expected_exit,
        .rewrites = args.rewrites,
        .sigfd = sigfd,
        .new_session = args.new_session,
        .ignore_cont = sig_conf.ignore_detached_sig,
        .ignore_hup = sig_conf.ignore_detached_sig,
    };

    while (true) {
        Logger.debug("polling", .{});
        const count = std.posix.poll(poll_fds[0..poll_fds_len], -1) catch |err| {
            Logger.err("poll failed: {s}", .{@errorName(err)});
            return 1;
        };

        if (count == 0) {
            Logger.err("poll returned 0, continue", .{});
            continue;
        }

        for (poll_fds[0..poll_fds_len]) |*pfd| {
            if (pfd.revents == 0) continue;

            if (pfd.revents & (std.posix.POLL.ERR | std.posix.POLL.HUP | std.posix.POLL.NVAL) != 0) {
                Logger.err("poll error on fd {d}: revents=0x{x}", .{ pfd.fd, pfd.revents });
                continue;
            }

            if (pfd.fd == sigfd) {
                if (handleSignalEvent(&process_state)) |exit_code| return exit_code;
                if (process_state.shutdown) |*state| {
                    if (poll_fds_len == 1) {
                        poll_fds[1] = .{
                            .fd = state.timerfd,
                            .events = std.posix.POLL.IN,
                            .revents = 0,
                        };
                        poll_fds_len = 2;
                    }
                }
            } else if (process_state.shutdown) |*state| {
                if (pfd.fd == state.timerfd) {
                    if (handleTimerEvent(&process_state)) |exit_code| return exit_code;
                }
            }
        }
    }
}

test "Logger functions" {
    const old_level = Logger.runtime_log_level;
    defer Logger.setLevel(old_level);

    Logger.setLevel(.err);
    try std.testing.expect(Logger.shouldLog(.err));
    try std.testing.expect(!Logger.shouldLog(.warn));

    Logger.setLevel(.debug);
    try std.testing.expect(Logger.shouldLog(.debug));
}

test parseSignal {
    try std.testing.expectEqual(15, parseSignal("15") catch unreachable);
    try std.testing.expectEqual(15, parseSignal("SIGTERM") catch unreachable);
    try std.testing.expectEqual(15, parseSignal("TERM") catch unreachable);
    try std.testing.expectEqual(std.posix.sigrtmin(), parseSignal("SIGRTMIN") catch unreachable);
    try std.testing.expectEqual(std.posix.sigrtmin() + 2, parseSignal("SIGRTMIN+2") catch unreachable);
    try std.testing.expectEqual(std.posix.sigrtmax() - 1, parseSignal("RTMAX-1") catch unreachable);
    try std.testing.expectError(ZinitError.InvalidSignal, parseSignal("UNKNOWN"));
    try std.testing.expectError(ZinitError.InvalidSignal, parseSignal("999"));
    try std.testing.expectError(ZinitError.InvalidSignal, parseSignal("0"));
    try std.testing.expectError(ZinitError.InvalidParams, parseSignal(""));
}

test "parseSignal edge cases" {
    try std.testing.expectError(ZinitError.InvalidSignal, parseSignal("SIG"));
    try std.testing.expectError(ZinitError.InvalidSignal, parseSignal("A"));
    const long_name = "SIG" ++ "A" ** 20;
    try std.testing.expectError(ZinitError.InvalidSignal, parseSignal(long_name));
}

test parseRewrite {
    var map: RewriteMap = .{};

    try parseRewrite(&map, "TERM:INT");
    const new_sig = map.get(15);

    try std.testing.expectEqual(2, new_sig);
}

test "parseRewrite error cases" {
    var map: RewriteMap = .{};

    try std.testing.expectError(ZinitError.InvalidRewrite, parseRewrite(&map, "TERM"));

    try std.testing.expectError(ZinitError.InvalidSignal, parseRewrite(&map, "TERM:BAD"));

    try std.testing.expectError(ZinitError.DuplicateSignal, parseRewrite(&map, "TERM:TERM"));

    try parseRewrite(&map, "TERM:INT");
    try std.testing.expectError(ZinitError.DuplicateSignal, parseRewrite(&map, "TERM:HUP"));

    map = .{};
    try std.testing.expectError(ZinitError.InvalidRewrite, parseRewrite(&map, "TERM:INT:EXTRA"));

    map.set(1, 2);
    map.set(2, 9);
    map.set(9, 1);
    try std.testing.expectError(ZinitError.CycleRewrite, parseRewrite(&map, "TERM:1"));
}

test hasCycle {
    var map: RewriteMap = .{};

    map.set(15, 2);
    try std.testing.expect(!hasCycle(&map, 15));

    map.set(2, 9);
    try std.testing.expect(!hasCycle(&map, 15));

    map.set(9, 15);
    try std.testing.expect(hasCycle(&map, 15));
    try std.testing.expect(hasCycle(&map, 2));
    try std.testing.expect(hasCycle(&map, 9));

    map = .{};

    const rtmin = std.posix.sigrtmin();
    const rtmax = std.posix.sigrtmax();

    map.set(rtmin, @intCast(rtmin + 1));
    try std.testing.expect(!hasCycle(&map, rtmin));

    map.set(@intCast(rtmin + 1), @intCast(rtmin + 2));
    try std.testing.expect(!hasCycle(&map, rtmin));

    map.set(@intCast(rtmin + 2), rtmin);
    try std.testing.expect(hasCycle(&map, rtmin));

    if (rtmax > 60) {
        map = .{};
        map.set(@intCast(rtmax), @intCast(rtmax - 1));
        try std.testing.expect(!hasCycle(&map, rtmax));
    }
}

test mapSignal {
    var map: RewriteMap = .{};

    map.set(15, 2);

    try std.testing.expectEqual(2, mapSignal(map, 15));
    try std.testing.expectEqual(9, mapSignal(map, 9));
    try std.testing.expectEqual(15, mapSignal(null, 15));
}

test Args {
    const allocator = std.testing.allocator;
    var env_map: std.process.Environ.Map = .init(allocator);
    defer env_map.deinit();
    try env_map.put("ZINIT_TEST_KEY", "1");

    const environ: std.process.Environ = .{ .block = try env_map.createPosixBlock(allocator, .{}) };
    defer environ.block.deinit(allocator);

    const p_args: []const []const u8 = &[_][]const u8{ "foo", "--bar=x", "-v", "-c" };

    var map: RewriteMap = .{};
    map.set(15, 2);

    var args = try Args.init(allocator, environ.block.slice, .debug, 15, map, 143, true, true, true, true, p_args);
    defer args.deinit();

    try std.testing.expectEqual(LogLevel.debug, args.log_level);
    try std.testing.expectEqual(@as(?u32, 15), args.pdeath_signal);
    try std.testing.expectEqual(@as(?u8, 143), args.expected_exit);
    try std.testing.expect(args.subreaper);
    try std.testing.expect(args.tracing_child);
    try std.testing.expect(args.new_session);
    try std.testing.expect(args.is_terminal);
    try std.testing.expectEqualStrings("foo", std.mem.span(args.argv[0].?));
    try std.testing.expectEqualStrings("--bar=x", std.mem.span(args.argv[1].?));
    try std.testing.expectEqual(@as(?[*:0]const u8, null), args.argv[p_args.len]);

    var found_env = false;
    for (args.envs) |entry| {
        const raw = entry orelse continue;
        if (std.mem.eql(u8, std.mem.span(raw), "ZINIT_TEST_KEY=1")) {
            found_env = true;
            // run this loop till the end to make kcov happy
        }
    }

    try std.testing.expect(found_env);
}

test parseLogLevel {
    try std.testing.expectEqual(LogLevel.err, parseLogLevel("error") catch unreachable);
    try std.testing.expectEqual(LogLevel.warn, parseLogLevel("WARNING") catch unreachable);
    try std.testing.expectEqual(LogLevel.info, parseLogLevel("Info") catch unreachable);
    try std.testing.expectEqual(LogLevel.debug, parseLogLevel("debug") catch unreachable);
    try std.testing.expectError(ZinitError.InvalidParams, parseLogLevel("trace"));
}

test "parseExpectedExit" {
    try std.testing.expectEqual(@as(u8, 0), parseExpectedExit("0"));
    try std.testing.expectEqual(@as(u8, 255), parseExpectedExit("255"));
    try std.testing.expectError(ZinitError.InvalidExitCode, parseExpectedExit("256"));
    try std.testing.expectError(ZinitError.InvalidExitCode, parseExpectedExit("abc"));
}

test parseTracingChild {
    try std.testing.expect(parseTracingChild("ON", false));
    try std.testing.expect(parseTracingChild("on", false));
    try std.testing.expect(!parseTracingChild("OFF", true));
    try std.testing.expect(!parseTracingChild("off", true));
    try std.testing.expect(parseTracingChild(null, true));
    try std.testing.expect(!parseTracingChild(null, false));
    try std.testing.expect(parseTracingChild("INVALID", true));
}

test "Args.init without rewrite" {
    const allocator = std.testing.allocator;
    var env_map: std.process.Environ.Map = .init(allocator);
    defer env_map.deinit();

    const environ: std.process.Environ = .{ .block = try env_map.createPosixBlock(allocator, .{}) };
    defer environ.block.deinit(allocator);

    const p_args: []const []const u8 = &[_][]const u8{"test"};
    var args = try Args.init(allocator, environ.block.slice, .warn, null, null, null, false, false, false, false, p_args);
    defer args.deinit();

    try std.testing.expect(args.rewrites == null);
    try std.testing.expect(args.envs[0] == null);
}

test "Args.init with empty env" {
    const allocator = std.testing.allocator;
    var env_map: std.process.Environ.Map = .init(allocator);
    defer env_map.deinit();
    try env_map.put("TEST_KEY", "value");

    const environ: std.process.Environ = .{ .block = try env_map.createPosixBlock(allocator, .{}) };
    defer environ.block.deinit(allocator);

    const p_args: []const []const u8 = &[_][]const u8{"test"};
    var args = try Args.init(allocator, environ.block.slice, .warn, null, null, null, false, false, false, false, p_args);
    defer args.deinit();

    var found = false;
    for (args.envs) |entry| {
        if (entry) |raw| {
            if (std.mem.startsWith(u8, std.mem.span(raw), "TEST_KEY=")) {
                found = true;
                // run this loop till the end to make kcov happy
            }
        }
    }
    try std.testing.expect(found);
}

test extractExitCode {
    var status: u32 = @as(u32, 42) << 8;
    try std.testing.expectEqual(@as(u8, 42), extractExitCode(status));

    status = 9;
    try std.testing.expectEqual(@as(u8, 128 + 9), extractExitCode(status));

    status = 0x1FF;
    try std.testing.expectEqual(@as(u8, 0), extractExitCode(status));
}

test mapExitCode {
    try std.testing.expectEqual(@as(u8, 0), mapExitCode(143, 143));
    try std.testing.expectEqual(@as(u8, 143), mapExitCode(1, 143));
    try std.testing.expectEqual(@as(u8, 1), mapExitCode(null, 1));
}

test isValidU32 {
    try std.testing.expect(!isValidU32(0));
    try std.testing.expect(isValidU32(1));
    try std.testing.expect(isValidU32(15));
    try std.testing.expect(isValidU32(@as(u32, std.posix.NSIG) - 1));
    try std.testing.expect(!isValidU32(@as(u32, std.posix.NSIG)));
}

test classifyExitStatus {
    var status: u32 = @as(u32, 42) << 8;
    try std.testing.expectEqual(ExitStatusClass.exited, classifyExitStatus(status));

    status = 9;
    try std.testing.expectEqual(ExitStatusClass.signaled, classifyExitStatus(status));

    status = 0x1FF;
    try std.testing.expectEqual(ExitStatusClass.unknown, classifyExitStatus(status));
}

test getSignalDestination {
    try std.testing.expectEqual(@as(std.posix.pid_t, 100), getSignalDestination(false, 100));
    try std.testing.expectEqual(@as(std.posix.pid_t, -100), getSignalDestination(true, 100));
}

test "tryClose with invalid fd" {
    tryClose(-1);
}

test "parseRealtimeSignal edge cases" {
    try std.testing.expectEqual(null, parseRealtimeSignal("RTMIN-1"));
    try std.testing.expectEqual(null, parseRealtimeSignal("RTMAX+1"));
    try std.testing.expectEqual(null, parseRealtimeSignal("RTMIN+"));
    try std.testing.expectEqual(null, parseRealtimeSignal("RTMAX-"));
    try std.testing.expectEqual(null, parseRealtimeSignal("RTMIN+abc"));
    try std.testing.expectEqual(null, parseRealtimeSignal("RTMAX-abc"));
    try std.testing.expectEqual(null, parseRealtimeSignal("INVALID"));
}
