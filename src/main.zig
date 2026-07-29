const std = @import("std");
const config = @import("config");
const builtin = @import("builtin");

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
    const stderr_fd = std.os.linux.STDERR_FILENO;

    _ = std.os.linux.write(stderr_fd, prefix, prefix.len);
    _ = std.os.linux.write(stderr_fd, msg.ptr, msg.len);
    _ = std.os.linux.write(stderr_fd, "\n", 1);

    std.os.linux.exit(1);
}

const LogLevel = enum(u8) { err = 0, warn = 1, info = 2, debug = 3 };

const Logger = struct {
    var runtime_log_level: LogLevel = .warn;
    var target_fd: std.os.linux.fd_t = std.os.linux.STDERR_FILENO;
    var use_color: bool = false;

    pub fn init() void {
        var termios: std.os.linux.termios = undefined;
        use_color = std.os.linux.errno(std.os.linux.tcgetattr(std.os.linux.STDERR_FILENO, &termios)) == .SUCCESS;
    }

    pub fn rawTryWriteAll(fd: std.os.linux.fd_t, bytes: []const u8) void {
        if (comptime builtin.is_test) return;
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

    fn log(level: LogLevel, msg: []const u8) void {
        if (@backingInt(level) > @backingInt(runtime_log_level)) return;
        var buf: [512]u8 = undefined;
        const pfx = if (use_color) switch (level) {
            .err => "\x1b[31m[zinit] ERROR:\x1b[0m",
            .warn => "\x1b[33m[zinit] WARNING:\x1b[0m",
            .info => "\x1b[32m[zinit] INFO:\x1b[0m",
            .debug => "\x1b[36m[zinit] DEBUG:\x1b[0m",
        } else switch (level) {
            .err => "[zinit] ERROR:",
            .warn => "[zinit] WARNING:",
            .info => "[zinit] INFO:",
            .debug => "[zinit] DEBUG:",
        };
        const formatted = std.fmt.bufPrint(&buf, "{s}{s}\n", .{ pfx, msg }) catch "(log too long)\n";

        rawTryWriteAll(target_fd, formatted);
    }

    pub fn setTargetFd(fd: std.os.linux.fd_t) void {
        target_fd = fd;
    }
    pub fn setLevel(level: LogLevel) void {
        runtime_log_level = level;
    }
};

const sig_t = std.os.linux.SIG;

fn lookupSignal(name: []const u8) ?u32 {
    return if (std.meta.stringToEnum(sig_t, name)) |s| @backingInt(s) else null;
}

const ZinitError = error{
    InvalidSignal,
    InvalidParams,
    InvalidRewrite,
    InvalidExitCode,
    SysCallError,
    DuplicateSignal,
    CycleRewrite,
};

fn parseRealtimeSignal(s: []const u8) ?u32 {
    const rtmin = std.os.linux.sigrtmin();
    const rtmax = std.os.linux.sigrtmax();

    inline for (.{
        .{ .prefix = "RTMIN", .base = rtmin, .op = '+' },
        .{ .prefix = "SIGRTMIN", .base = rtmin, .op = '+' },
        .{ .prefix = "RTMAX", .base = rtmax, .op = '-' },
        .{ .prefix = "SIGRTMAX", .base = rtmax, .op = '-' },
    }) |e| {
        if (std.ascii.startsWithIgnoreCase(s, e.prefix)) {
            const suffix = s[e.prefix.len..];
            if (suffix.len == 0) return e.base;
            if (suffix[0] != e.op) return null;
            const offset = std.fmt.parseUnsigned(u8, suffix[1..], 10) catch return null;
            if (e.op == '-' and offset > rtmax) return null;
            const value = if (e.op == '+') e.base + offset else e.base - offset;
            if (value > rtmax) return null;
            return @intCast(value);
        }
    }
    return null;
}

fn parseSignal(s: []const u8) !u32 {
    if (s.len == 0) return ZinitError.InvalidParams;

    if (s[0] >= '0' and s[0] <= '9') {
        if (std.fmt.parseUnsigned(u32, s, 10)) |sig_num| {
            if (sig_num > 0 and sig_num < std.os.linux.NSIG) return @intCast(sig_num);
            return ZinitError.InvalidSignal;
        } else |_| {}
    }

    if (parseRealtimeSignal(s)) |sig_num| return sig_num;

    const name_to_check = if (std.ascii.startsWithIgnoreCase(s, "SIG"))
        s[3..]
    else
        s;

    if (name_to_check.len == 0 or name_to_check.len > 15) return ZinitError.InvalidSignal;

    var buf: [16]u8 = undefined;
    const upper_name = std.ascii.upperString(&buf, name_to_check);

    return lookupSignal(upper_name) orelse ZinitError.InvalidSignal;
}

const RewriteMap = struct {
    entries: [std.os.linux.NSIG]u32,

    pub fn init() RewriteMap {
        return .{ .entries = @splat(0) };
    }

    pub fn reset(self: *RewriteMap) void {
        self.entries = @splat(0);
    }

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

fn hasCycle(map: *const RewriteMap, start_node: u32) ZinitError!bool {
    if (!(start_node > 0 and start_node < std.os.linux.NSIG)) return ZinitError.InvalidParams;

    var current = start_node;
    var count: usize = 0;
    while (true) {
        const next_node = map.get(current);
        if (next_node == 0) return false;

        count += 1;
        if (count >= std.os.linux.NSIG) return true;
        current = next_node;
    }
}

fn parseRewrite(map: *RewriteMap, value: []const u8) !void {
    var kv = std.mem.splitScalar(u8, value, ':');

    const old = kv.next() orelse return ZinitError.InvalidRewrite;
    const old_sig = try parseSignal(old);

    const new = kv.next() orelse return ZinitError.InvalidRewrite;
    const new_sig = try parseSignal(new);

    if (kv.peek() != null) return ZinitError.InvalidRewrite;

    if (old_sig == new_sig) return ZinitError.DuplicateSignal;

    if (try hasCycle(map, new_sig)) return ZinitError.CycleRewrite;

    if (map.has(old_sig)) return ZinitError.DuplicateSignal;

    map.set(old_sig, new_sig);
}

fn mapSignal(rewrite: ?RewriteMap, signo: u32) u32 {
    if (rewrite) |m| {
        const mapped = m.get(signo);
        if (mapped != 0) return mapped;
    }
    return signo;
}

fn printHelp() void {
    Logger.rawTryWriteAll(std.os.linux.STDOUT_FILENO,
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

fn printVersion() void {
    var buf: [64]u8 = undefined;
    const text = std.fmt.bufPrint(&buf, "{d}.{d}.{d}\n", .{
        config.version.major,
        config.version.minor,
        config.version.patch,
    }) catch "unknown\n";
    Logger.rawTryWriteAll(std.os.linux.STDOUT_FILENO, text);
}

fn parseArgs(allocator: std.mem.Allocator, init: std.process.Init.Minimal) !?Args {
    var args_iter = init.args.iterate();
    defer args_iter.deinit();
    _ = args_iter.skip();

    var rewrite_map: ?RewriteMap = null;
    var child_args: std.ArrayListUnmanaged([]const u8) = .empty;
    defer child_args.deinit(allocator);

    var log_level: LogLevel = .warn;
    var pdeath_signal: ?u32 = null;
    var subreaper_flag = false;
    var expected_exit: ?u8 = null;
    var new_session = false;
    var has_help = false;
    var has_version = false;

    while (args_iter.next()) |arg| {
        if (std.mem.eql(u8, arg, "--")) {
            while (args_iter.next()) |rest| try child_args.append(allocator, rest);
            break;
        }

        if (std.mem.eql(u8, arg, "-h") or std.mem.eql(u8, arg, "--help")) {
            has_help = true;
            continue;
        }
        if (std.mem.eql(u8, arg, "-v") or std.mem.eql(u8, arg, "--version")) {
            has_version = true;
            continue;
        }
        if (std.mem.eql(u8, arg, "-n") or std.mem.eql(u8, arg, "--new-session")) {
            new_session = true;
            continue;
        }
        if (std.mem.eql(u8, arg, "-s") or std.mem.eql(u8, arg, "--subreaper")) {
            subreaper_flag = true;
            continue;
        }

        if (std.mem.eql(u8, arg, "--log-level")) {
            const v = args_iter.next() orelse return ZinitError.InvalidParams;
            if (std.ascii.eqlIgnoreCase(v, "error")) {
                log_level = .err;
                continue;
            }
            if (std.ascii.eqlIgnoreCase(v, "warning")) {
                log_level = .warn;
                continue;
            }
            if (std.ascii.eqlIgnoreCase(v, "info")) {
                log_level = .info;
                continue;
            }
            if (std.ascii.eqlIgnoreCase(v, "debug")) {
                log_level = .debug;
                continue;
            }
            return ZinitError.InvalidParams;
        }
        if (std.mem.eql(u8, arg, "-p") or std.mem.eql(u8, arg, "--signal")) {
            if (pdeath_signal != null) return ZinitError.InvalidParams;
            pdeath_signal = try parseSignal(args_iter.next() orelse return ZinitError.InvalidParams);
            continue;
        }
        if (std.mem.eql(u8, arg, "-r") or std.mem.eql(u8, arg, "--rewrite")) {
            if (rewrite_map != null) return ZinitError.InvalidParams;
            rewrite_map = .init();
            const val = args_iter.next() orelse return ZinitError.InvalidRewrite;
            var it = std.mem.splitScalar(u8, val, ',');
            while (it.next()) |part| try parseRewrite(&rewrite_map.?, part);
            continue;
        }
        if (std.mem.eql(u8, arg, "-e") or std.mem.eql(u8, arg, "--expect-exit")) {
            if (expected_exit != null) return ZinitError.InvalidParams;
            expected_exit = std.fmt.parseUnsigned(u8, args_iter.next() orelse return ZinitError.InvalidExitCode, 10) catch return ZinitError.InvalidExitCode;
            continue;
        }

        if (arg.len > 0 and arg[0] == '-') return ZinitError.InvalidParams;

        try child_args.append(allocator, arg);
        while (args_iter.next()) |rest| try child_args.append(allocator, rest);
        break;
    }

    if (has_help and has_version) return ZinitError.InvalidParams;
    if (has_help) {
        printHelp();
        return null;
    }
    if (has_version) {
        printVersion();
        return null;
    }
    if (child_args.items.len == 0) return error.InvalidParams;
    const tracing_child = blk: {
        const v = init.environ.getPosix("ZINIT_TRACING_CHILD");
        if (v) |val| {
            if (std.ascii.eqlIgnoreCase(val, "OFF")) break :blk false;
            if (std.ascii.eqlIgnoreCase(val, "ON")) break :blk true;
        }
        break :blk config.tracing_child;
    };

    if (new_session) {
        if (rewrite_map == null) rewrite_map = .init();
        const stop = @backingInt(sig_t.STOP);
        const tstp = @backingInt(sig_t.TSTP);
        const ttou = @backingInt(sig_t.TTOU);
        const ttin = @backingInt(sig_t.TTIN);
        if (!rewrite_map.?.has(tstp)) rewrite_map.?.set(tstp, stop);
        if (!rewrite_map.?.has(ttou)) rewrite_map.?.set(ttou, stop);
        if (!rewrite_map.?.has(ttin)) rewrite_map.?.set(ttin, stop);
    }

    var termios: std.os.linux.termios = undefined;
    const is_terminal = std.os.linux.errno(std.os.linux.tcgetattr(std.os.linux.STDIN_FILENO, &termios)) == .SUCCESS;

    return try Args.init(allocator, init.environ.block.slice, log_level, pdeath_signal, rewrite_map, expected_exit, subreaper_flag, new_session, is_terminal, tracing_child, child_args.items);
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
        for (args, 0..) |arg, i| argv[i] = @as([*:0]const u8, @ptrCast(arg.ptr));
        return .{ .allocator = allocator, .log_level = log_level, .pdeath_signal = pdeath_signal, .rewrites = rewrites, .expected_exit = expected_exit, .subreaper = subreaper, .tracing_child = tracing_child, .argv = argv, .envs = envs, .new_session = new_session, .is_terminal = is_terminal };
    }

    pub fn deinit(self: *Args) void {
        self.allocator.free(self.argv);
    }
};

const SHUTDOWN_GRACE_PERIOD_NS: u64 = 5 * std.time.ns_per_s;

const SigConf = struct {
    old_set: std.os.linux.sigset_t,
    current_set: std.os.linux.sigset_t,
    ttin_action: std.os.linux.Sigaction,
    ttou_action: std.os.linux.Sigaction,
    ignore_detached_sig: bool = false,
};

fn handleSignal(comptime sig_list: []const sig_t) !SigConf {
    var set = std.os.linux.sigfillset();
    for (sig_list) |sig| std.os.linux.sigdelset(&set, sig);

    var old_set: std.os.linux.sigset_t = undefined;
    var ret = std.os.linux.sigprocmask(sig_t.SETMASK, &set, &old_set);
    switch (std.os.linux.errno(ret)) {
        .SUCCESS => {},
        else => {
            var _b: [128]u8 = undefined;
            Logger.log(.err, std.fmt.bufPrint(&_b, "unable to set signal mask: {s}", .{@tagName(std.os.linux.errno(ret))}) catch "?");
            return ZinitError.SysCallError;
        },
    }

    const ignored = std.os.linux.Sigaction{
        .handler = .{ .handler = sig_t.IGN },
        .mask = std.os.linux.sigemptyset(),
        .flags = 0,
    };

    var old_ttin_action: std.os.linux.Sigaction = undefined;
    ret = std.os.linux.sigaction(sig_t.TTIN, &ignored, &old_ttin_action);
    switch (std.os.linux.errno(ret)) {
        .SUCCESS => {},
        else => {
            var _b: [128]u8 = undefined;
            Logger.log(.err, std.fmt.bufPrint(&_b, "unable to set signal action for TTIN: {s}", .{@tagName(std.os.linux.errno(ret))}) catch "?");
            return ZinitError.SysCallError;
        },
    }

    var old_ttou_action: std.os.linux.Sigaction = undefined;
    ret = std.os.linux.sigaction(sig_t.TTOU, &ignored, &old_ttou_action);
    switch (std.os.linux.errno(ret)) {
        .SUCCESS => {},
        else => {
            var _b: [128]u8 = undefined;
            Logger.log(.err, std.fmt.bufPrint(&_b, "unable to set signal action for TTOU: {s}", .{@tagName(std.os.linux.errno(ret))}) catch "?");
            return ZinitError.SysCallError;
        },
    }

    return .{ .old_set = old_set, .current_set = set, .ttin_action = old_ttin_action, .ttou_action = old_ttou_action };
}

fn childErrorExit(msg: []const u8) noreturn {
    var buf: [512]u8 = undefined;
    const formatted = std.fmt.bufPrint(&buf, "zinit child error: {s}\n", .{msg}) catch "zinit child error: (message too long to format)\n";
    _ = std.os.linux.write(std.os.linux.STDERR_FILENO, formatted.ptr, formatted.len);
    std.os.linux.exit(1);
}

fn restoreChildSignals(sig_conf: *const SigConf) void {
    var _b: [128]u8 = undefined;
    var ret = std.os.linux.sigprocmask(sig_t.SETMASK, &sig_conf.old_set, null);
    switch (std.os.linux.errno(ret)) {
        .SUCCESS => {},
        else => |e| childErrorExit(std.fmt.bufPrint(&_b, "unable to restore signal mask: {s}", .{@tagName(e)}) catch "?"),
    }

    var unblock_all = std.os.linux.sigfillset();
    ret = std.os.linux.sigprocmask(sig_t.UNBLOCK, &unblock_all, null);
    switch (std.os.linux.errno(ret)) {
        .SUCCESS => {},
        else => |e| childErrorExit(std.fmt.bufPrint(&_b, "unable to unblock signals: {s}", .{@tagName(e)}) catch "?"),
    }

    ret = std.os.linux.sigaction(sig_t.TTIN, &sig_conf.ttin_action, null);
    switch (std.os.linux.errno(ret)) {
        .SUCCESS => {},
        else => |e| childErrorExit(std.fmt.bufPrint(&_b, "unable to restore signal action for TTIN: {s}", .{@tagName(e)}) catch "?"),
    }

    ret = std.os.linux.sigaction(sig_t.TTOU, &sig_conf.ttou_action, null);
    switch (std.os.linux.errno(ret)) {
        .SUCCESS => {},
        else => |e| childErrorExit(std.fmt.bufPrint(&_b, "unable to restore signal action for TTOU: {s}", .{@tagName(e)}) catch "?"),
    }
}

fn setupChildTerminal(args: Args) void {
    var _b: [128]u8 = undefined;
    if (args.new_session) {
        const sid = std.os.linux.setsid();
        const err = std.os.linux.errno(sid);
        if (err != .SUCCESS) childErrorExit(std.fmt.bufPrint(&_b, "unable to create session: {s}", .{@tagName(err)}) catch "?");
    }

    if (!args.is_terminal) return;

    const rc = std.os.linux.ioctl(std.os.linux.STDIN_FILENO, std.os.linux.T.IOCSCTTY, 0);
    const err = std.os.linux.errno(rc);
    if (err != .SUCCESS) Logger.log(.debug, std.fmt.bufPrint(&_b, "unable to acquire controlling tty: {s}", .{@tagName(err)}) catch "?");
}

fn run(args: *Args, sig_conf: *SigConf) !usize {
    var _b: [128]u8 = undefined;
    if (args.new_session and args.is_terminal) {
        const rc = std.os.linux.ioctl(std.os.linux.STDIN_FILENO, std.os.linux.T.IOCNOTTY, 0);
        const err = std.os.linux.errno(rc);
        if (err != .SUCCESS) {
            Logger.log(.debug, std.fmt.bufPrint(&_b, "unable to detach from terminal: {s}", .{@tagName(err)}) catch "?");
        } else {
            if (std.os.linux.getsid(0) == std.os.linux.getpid()) {
                sig_conf.ignore_detached_sig = true;
                Logger.log(.debug, "detaching from controlling terminal, ignoring first SIGHUP/SIGCONT");
            } else {
                Logger.log(.debug, "detached from controlling terminal, but was not session leader");
            }
        }
    }

    const pid = std.os.linux.fork();
    const err = std.os.linux.errno(pid);
    if (err != .SUCCESS) {
        Logger.log(.err, std.fmt.bufPrint(&_b, "unable to fork: {s}", .{@tagName(err)}) catch "?");
        return ZinitError.SysCallError;
    }

    if (pid != 0) return @intCast(pid);

    defer args.deinit();

    restoreChildSignals(sig_conf);
    setupChildTerminal(args.*);

    if (args.pdeath_signal) |sig| {
        const ret = std.os.linux.prctl(@backingInt(std.os.linux.PR.SET_PDEATHSIG), sig, 0, 0, 0);
        switch (std.os.linux.errno(ret)) {
            .SUCCESS => {},
            else => |e| childErrorExit(std.fmt.bufPrint(&_b, "unable to set parent death signal: {s}", .{@tagName(e)}) catch "?"),
        }
    }

    while (args.tracing_child) {
        const dummy_handler = struct {
            pub fn handler(_: sig_t) callconv(.c) void {}
        }.handler;

        const usr1_act: std.os.linux.Sigaction = .{
            .handler = .{ .handler = dummy_handler },
            .mask = std.os.linux.sigemptyset(),
            .flags = 0,
        };

        var old_act: std.os.linux.Sigaction = undefined;
        var ret = std.os.linux.sigaction(sig_t.USR1, &usr1_act, &old_act);
        switch (std.os.linux.errno(ret)) {
            .SUCCESS => {},
            else => |e| {
                Logger.log(.debug, std.fmt.bufPrint(&_b, "failed to set signal action for USR1: {s}", .{@tagName(e)}) catch "?");
                break;
            },
        }

        _ = std.os.linux.pause();
        ret = std.os.linux.sigaction(sig_t.USR1, &old_act, null);
        switch (std.os.linux.errno(ret)) {
            .SUCCESS => {},
            else => |e| Logger.log(.debug, std.fmt.bufPrint(&_b, "failed to restore signal action for USR1: {s}", .{@tagName(e)}) catch "?"),
        }
        break;
    }

    const ret = std.os.linux.execve(args.argv[0].?, args.argv, args.envs);
    childErrorExit(std.fmt.bufPrint(&_b, "unable to execve: {s}", .{@tagName(std.os.linux.errno(ret))}) catch "?");
}

const ExitStatusClass = enum { exited, signaled, unknown };

fn classifyExitStatus(status: u32) ExitStatusClass {
    if (std.os.linux.W.IFEXITED(status)) return .exited;
    if (std.os.linux.W.IFSIGNALED(status)) return .signaled;
    return .unknown;
}

fn extractExitCode(status: u32) u8 {
    if (std.os.linux.W.IFEXITED(status)) return std.os.linux.W.EXITSTATUS(status);
    if (std.os.linux.W.IFSIGNALED(status)) return @intCast(128 + @backingInt(std.os.linux.W.TERMSIG(status)));
    return 0;
}

fn drainChildren(main_pid: ?usize, expected_exit: ?u8) !struct { main_code: ?u8, no_children: bool } {
    var status: i32 = 0;
    var main_exit_code: ?u8 = null;
    while (true) {
        const ret = std.os.linux.waitpid(-1, &status, std.os.linux.W.NOHANG);
        if (ret == 0) return .{ .main_code = main_exit_code, .no_children = false };

        const err = std.os.linux.errno(ret);
        switch (err) {
            .INTR => continue,
            .SUCCESS => {
                const pid: usize = @intCast(ret);
                logExitedProcess(pid, @intCast(status));
                if (main_pid) |mp| if (pid == mp) {
                    main_exit_code = if (expected_exit) |c| blk: {
                        const ec = extractExitCode(@intCast(status));
                        break :blk if (c == ec) 0 else ec;
                    } else extractExitCode(@intCast(status));
                };
            },
            .CHILD => return .{ .main_code = main_exit_code, .no_children = true },
            else => {
                var _b: [128]u8 = undefined;
                Logger.log(.debug, std.fmt.bufPrint(&_b, "unable to waitpid: {s}", .{@tagName(err)}) catch "?");
                return ZinitError.SysCallError;
            },
        }
    }
}

fn terminateProcessGroup(pid: usize, sig: u32) void {
    var _b: [128]u8 = undefined;
    const ret = std.os.linux.kill(-@as(std.os.linux.pid_t, @intCast(pid)), @fromBackingInt(@intCast(sig)));
    switch (std.os.linux.errno(ret)) {
        .SUCCESS => {},
        .SRCH => Logger.log(.debug, std.fmt.bufPrint(&_b, "no process group to send signal {d} for pid {d}", .{ sig, pid }) catch "?"),
        else => |e| {
            var _b2: [128]u8 = undefined;
            Logger.log(.err, std.fmt.bufPrint(&_b2, "unable to send signal {d} to process group: {s}", .{ sig, @tagName(e) }) catch "?");
        },
    }
}

fn logExitedProcess(pid: usize, status: u32) void {
    var _b: [128]u8 = undefined;
    switch (classifyExitStatus(status)) {
        .exited => Logger.log(.info, std.fmt.bufPrint(&_b, "child process {d} exited with code {d}.", .{ pid, std.os.linux.W.EXITSTATUS(status) }) catch "?"),
        .signaled => Logger.log(.info, std.fmt.bufPrint(&_b, "child process {d} exited with signal {d}.", .{ pid, @as(u64, @intCast(@backingInt(std.os.linux.W.TERMSIG(status)))) }) catch "?"),
        .unknown => Logger.log(.err, std.fmt.bufPrint(&_b, "child process {d} exited with unknown status", .{pid}) catch "?"),
    }
}

const ProcessState = struct {
    child: usize,
    expected_exit: ?u8,
    rewrites: ?RewriteMap,
    sigfd: std.os.linux.fd_t,
    shutdown: ?ShutdownState = null,
    new_session: bool,
    ignore_hup: bool = false,
    ignore_cont: bool = false,
};

const ShutdownState = struct {
    main_pid: usize,
    exit_code: u8,
    timerfd: std.os.linux.fd_t,
    kill_sent: bool = false,
};

fn handleSignalEvent(state: *ProcessState) ?u8 {
    while (true) {
        var sig_info: std.os.linux.signalfd_siginfo = undefined;
        const ret = std.os.linux.read(state.sigfd, std.mem.asBytes(&sig_info), @sizeOf(std.os.linux.signalfd_siginfo));
        switch (std.os.linux.errno(ret)) {
            .SUCCESS => {},
            .INTR => continue,
            .AGAIN => return null,
            else => |e| {
                var _b: [128]u8 = undefined;
                Logger.log(.err, std.fmt.bufPrint(&_b, "unable to read sigfd: {s}", .{@tagName(e)}) catch "?");
                return 1;
            },
        }

        {
            var _b: [128]u8 = undefined;
            Logger.log(.debug, std.fmt.bufPrint(&_b, "receive signal: {d}", .{sig_info.signo}) catch "?");
        }

        if (sig_info.signo != @backingInt(sig_t.CHLD)) {
            forwardSignal(state, sig_info.signo);
            continue;
        }

        const reap = drainChildren(state.child, state.expected_exit) catch |err| {
            var _b: [128]u8 = undefined;
            Logger.log(.err, std.fmt.bufPrint(&_b, "waitpid failed: {s}", .{@errorName(err)}) catch "?");
            return 1;
        };

        if (reap.main_code) |code| {
            if (reap.no_children) return code;
            if (state.shutdown == null) return beginShutdown(state, code);
        } else if (state.shutdown != null and reap.no_children) {
            return state.shutdown.?.exit_code;
        }
    }
}

fn forwardSignal(state: *ProcessState, signo: u32) void {
    if (state.ignore_hup and signo == @backingInt(sig_t.HUP)) {
        state.ignore_hup = false;
        return;
    }
    if (state.ignore_cont and signo == @backingInt(sig_t.CONT)) {
        state.ignore_cont = false;
        return;
    }

    const signal_to_send = mapSignal(state.rewrites, signo);
    var _b: [128]u8 = undefined;
    Logger.log(.debug, std.fmt.bufPrint(&_b, "forwarding signal {d} as {d}", .{ signo, signal_to_send }) catch "?");

    const destination = if (state.new_session) -@as(std.os.linux.pid_t, @intCast(state.child)) else @as(std.os.linux.pid_t, @intCast(state.child));

    const ret = std.os.linux.kill(destination, @fromBackingInt(@intCast(signal_to_send)));
    switch (std.os.linux.errno(ret)) {
        .SUCCESS => {},
        .SRCH => {
            Logger.log(.debug, std.fmt.bufPrint(&_b, "no process to send signal {d} for pid {d}", .{ signal_to_send, @as(u64, @intCast(destination)) }) catch "?");
        },
        else => |err| {
            var _b2: [128]u8 = undefined;
            Logger.log(.err, std.fmt.bufPrint(&_b2, "unable to send signal to child: {s}", .{@tagName(err)}) catch "?");
        },
    }
}

fn beginShutdown(state: *ProcessState, exit_code: u8) ?u8 {
    const raw_fd = std.os.linux.timerfd_create(.MONOTONIC, .{ .CLOEXEC = true, .NONBLOCK = true });
    switch (std.os.linux.errno(raw_fd)) {
        .SUCCESS => {},
        else => |err| {
            var _b: [128]u8 = undefined;
            Logger.log(.warn, std.fmt.bufPrint(&_b, "failed to create timerfd: {s}", .{@tagName(err)}) catch "?");
            return exit_code;
        },
    }
    const timerfd: std.os.linux.fd_t = @intCast(raw_fd);
    errdefer tryClose(timerfd);

    const timer_spec = std.os.linux.itimerspec{
        .it_interval = .{ .sec = 0, .nsec = 0 },
        .it_value = .{ .sec = @intCast(SHUTDOWN_GRACE_PERIOD_NS / std.time.ns_per_s), .nsec = @intCast(SHUTDOWN_GRACE_PERIOD_NS % std.time.ns_per_s) },
    };
    switch (std.os.linux.errno(std.os.linux.timerfd_settime(timerfd, .{}, &timer_spec, null))) {
        .SUCCESS => {},
        else => |err| {
            var _b: [128]u8 = undefined;
            Logger.log(.warn, std.fmt.bufPrint(&_b, "failed to set timerfd: {s}", .{@tagName(err)}) catch "?");
            return exit_code;
        },
    }

    state.shutdown = .{ .main_pid = state.child, .exit_code = exit_code, .timerfd = timerfd };
    terminateProcessGroup(state.child, @backingInt(sig_t.TERM));
    return null;
}

fn onShutdownTimer(state: *ProcessState) ?u8 {
    const sd = &(state.shutdown orelse return null);

    var expirations: u64 = 0;
    while (true) {
        const ret = std.os.linux.read(sd.timerfd, std.mem.asBytes(&expirations), @sizeOf(u64));
        switch (std.os.linux.errno(ret)) {
            .SUCCESS, .INTR => continue,
            .AGAIN => break,
            else => |err| {
                var _b: [128]u8 = undefined;
                Logger.log(.err, std.fmt.bufPrint(&_b, "unable to read timerfd: {s}", .{@tagName(err)}) catch "?");
            },
        }
    }

    if (!sd.kill_sent) {
        sd.kill_sent = true;
        terminateProcessGroup(sd.main_pid, @backingInt(sig_t.KILL));
    }

    if ((drainChildren(null, null) catch |err| {
        var _b: [128]u8 = undefined;
        Logger.log(.err, std.fmt.bufPrint(&_b, "waitpid failed: {s}", .{@errorName(err)}) catch "?");
        return sd.exit_code;
    }).no_children) return sd.exit_code;
    return null;
}

fn tryClose(fd: std.os.linux.fd_t) void {
    if (fd < 0) return;
    while (true) {
        const close_rc = std.os.linux.close(fd);
        switch (std.os.linux.errno(close_rc)) {
            .SUCCESS => return,
            .INTR => continue,
            else => |err| {
                var _b: [128]u8 = undefined;
                Logger.log(.err, std.fmt.bufPrint(&_b, "unable to close fd {d}: {s}", .{ @as(u64, @intCast(fd)), @tagName(err) }) catch "?");
                break;
            },
        }
    }
}

test tryClose {
    tryClose(-1);
    const fd = std.os.linux.openat(std.os.linux.AT.FDCWD, "/dev/null", .{ .ACCMODE = .WRONLY }, 0o600);
    try std.testing.expectEqual(std.os.linux.errno(fd), .SUCCESS);
    tryClose(@intCast(fd));
    tryClose(5);
}

var debug_allocator: std.heap.DebugAllocator(.{}) = .init;
pub fn main(init: std.process.Init.Minimal) u8 {
    Logger.init();
    const allocator, const is_debug = gpa: {
        break :gpa switch (builtin.mode) {
            .Debug => .{ debug_allocator.allocator(), true },
            .ReleaseSafe, .ReleaseFast, .ReleaseSmall => .{ std.heap.page_allocator, false },
        };
    };

    if (is_debug) {
        defer _ = debug_allocator.deinit();
    }

    var args = parseArgs(allocator, init) catch |err| {
        printHelp();
        var _b: [128]u8 = undefined;
        Logger.log(.err, std.fmt.bufPrint(&_b, "unable to parse arguments: {s}", .{@errorName(err)}) catch "?");
        return 255;
    } orelse return 0;
    defer args.deinit();
    Logger.setLevel(args.log_level);

    const unblocked_sigs = [_]sig_t{ .ABRT, .BUS, .FPE, .ILL, .SEGV, .SYS, .TRAP, .TTIN, .TTOU };
    var sig_conf = handleSignal(&unblocked_sigs) catch |err| {
        var _b: [128]u8 = undefined;
        Logger.log(.err, std.fmt.bufPrint(&_b, "unable to handle signals: {s}", .{@errorName(err)}) catch "?");
        return 1;
    };

    const should_enable_subreaper = args.subreaper or std.os.linux.getpid() != 1;
    if (should_enable_subreaper) {
        const ret = std.os.linux.prctl(@backingInt(std.os.linux.PR.SET_CHILD_SUBREAPER), 1, 0, 0, 0);
        switch (std.os.linux.errno(ret)) {
            .SUCCESS => {},
            else => |e| {
                var _b: [128]u8 = undefined;
                Logger.log(.err, std.fmt.bufPrint(&_b, "unable to enable child subreaper mode: {s}", .{@tagName(e)}) catch "?");
                return 1;
            },
        }
    }

    const child = run(&args, &sig_conf) catch {
        Logger.log(.err, "failed to start child process");
        return 1;
    };

    const sigfd = std.os.linux.signalfd(-1, &sig_conf.current_set, std.os.linux.SFD.NONBLOCK | std.os.linux.SFD.CLOEXEC);
    switch (std.os.linux.errno(sigfd)) {
        .SUCCESS => {},
        else => |err| {
            var _b: [128]u8 = undefined;
            Logger.log(.err, std.fmt.bufPrint(&_b, "unable to create signalfd: {s}", .{@tagName(err)}) catch "?");
            return 1;
        },
    }
    defer {
        Logger.log(.debug, "close signalfd");
        tryClose(@intCast(sigfd));
    }

    var poll_fds: [2]std.os.linux.pollfd = undefined;
    poll_fds[0] = .{ .fd = @intCast(sigfd), .events = std.os.linux.POLL.IN, .revents = 0 };
    var poll_fds_len: usize = 1;

    var process_state = ProcessState{ .child = child, .expected_exit = args.expected_exit, .rewrites = args.rewrites, .sigfd = @intCast(sigfd), .new_session = args.new_session, .ignore_cont = sig_conf.ignore_detached_sig, .ignore_hup = sig_conf.ignore_detached_sig };

    while (true) {
        Logger.log(.debug, "polling");
        const count = std.os.linux.poll(&poll_fds, poll_fds_len, -1);
        switch (std.os.linux.errno(count)) {
            .SUCCESS => {},
            else => |e| {
                var _b: [128]u8 = undefined;
                Logger.log(.err, std.fmt.bufPrint(&_b, "poll failed: {s}", .{@tagName(e)}) catch "?");
                return 1;
            },
        }

        if (count == 0) {
            Logger.log(.err, "poll returned 0, continue");
            continue;
        }

        for (poll_fds[0..poll_fds_len]) |*pfd| {
            if (pfd.revents == 0) continue;

            if (pfd.revents & (std.os.linux.POLL.ERR | std.os.linux.POLL.HUP | std.os.linux.POLL.NVAL) != 0) {
                var _b: [128]u8 = undefined;
                Logger.log(.err, std.fmt.bufPrint(&_b, "poll error on fd {d}: revents=0x{x}", .{ @as(u64, @intCast(pfd.fd)), @as(u64, @intCast(pfd.revents)) }) catch "?");
                continue;
            }

            if (pfd.fd == sigfd) {
                if (handleSignalEvent(&process_state)) |exit_code| return exit_code;
                if (process_state.shutdown) |*state| {
                    if (poll_fds_len == 1) {
                        poll_fds[1] = .{ .fd = state.timerfd, .events = std.os.linux.POLL.IN, .revents = 0 };
                        poll_fds_len = 2;
                    }
                }
            } else if (process_state.shutdown) |*state| {
                if (pfd.fd == state.timerfd) {
                    if (onShutdownTimer(&process_state)) |exit_code| return exit_code;
                }
            }
        }
    }
}

test parseSignal {
    try std.testing.expectEqual(15, parseSignal("15") catch unreachable);
    try std.testing.expectEqual(15, parseSignal("SIGTERM") catch unreachable);
    try std.testing.expectEqual(15, parseSignal("TERM") catch unreachable);
    try std.testing.expectEqual(std.os.linux.sigrtmin(), parseSignal("SIGRTMIN") catch unreachable);
    try std.testing.expectEqual(std.os.linux.sigrtmin() + 2, parseSignal("SIGRTMIN+2") catch unreachable);
    try std.testing.expectEqual(std.os.linux.sigrtmax() - 1, parseSignal("RTMAX-1") catch unreachable);
    try std.testing.expectError(ZinitError.InvalidSignal, parseSignal("UNKNOWN"));
    try std.testing.expectError(ZinitError.InvalidSignal, parseSignal("999"));
    try std.testing.expectError(ZinitError.InvalidSignal, parseSignal("0"));
    try std.testing.expectError(ZinitError.InvalidParams, parseSignal(""));
    try std.testing.expectError(ZinitError.InvalidSignal, parseSignal("SIG"));
    try std.testing.expectError(ZinitError.InvalidSignal, parseSignal("A"));
    const long_name = "SIG" ++ "AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA";
    try std.testing.expectError(ZinitError.InvalidSignal, parseSignal(long_name));
}

test parseRewrite {
    var map: RewriteMap = .init();
    try parseRewrite(&map, "TERM:INT");
    const new_sig = map.get(15);
    try std.testing.expectEqual(2, new_sig);

    var emap: RewriteMap = .init();
    try std.testing.expectError(ZinitError.InvalidRewrite, parseRewrite(&emap, "TERM"));
    try std.testing.expectError(ZinitError.InvalidSignal, parseRewrite(&emap, "TERM:BAD"));
    try std.testing.expectError(ZinitError.DuplicateSignal, parseRewrite(&emap, "TERM:TERM"));
    try parseRewrite(&emap, "TERM:INT");
    try std.testing.expectError(ZinitError.DuplicateSignal, parseRewrite(&emap, "TERM:HUP"));
    emap.reset();
    try std.testing.expectError(ZinitError.InvalidRewrite, parseRewrite(&emap, "TERM:INT:EXTRA"));
    emap.set(1, 2);
    emap.set(2, 9);
    emap.set(9, 1);
    try std.testing.expectError(ZinitError.CycleRewrite, parseRewrite(&emap, "TERM:1"));
}

test hasCycle {
    var map: RewriteMap = .init();
    map.set(15, 2);
    try std.testing.expect(!try hasCycle(&map, 15));
    map.set(2, 9);
    try std.testing.expect(!try hasCycle(&map, 15));
    map.set(9, 15);
    try std.testing.expect(try hasCycle(&map, 15));
    try std.testing.expect(try hasCycle(&map, 2));
    try std.testing.expect(try hasCycle(&map, 9));
    map.reset();
    const rtmin = std.os.linux.sigrtmin();
    const rtmax = std.os.linux.sigrtmax();
    map.set(rtmin, @intCast(rtmin + 1));
    try std.testing.expect(!try hasCycle(&map, rtmin));
    map.set(@intCast(rtmin + 1), @intCast(rtmin + 2));
    try std.testing.expect(!try hasCycle(&map, rtmin));
    map.set(@intCast(rtmin + 2), rtmin);
    try std.testing.expect(try hasCycle(&map, rtmin));
    if (rtmax > 60) {
        map.reset();
        map.set(@intCast(rtmax), @intCast(rtmax - 1));
        try std.testing.expect(!try hasCycle(&map, rtmax));
    }
}

test mapSignal {
    var map: RewriteMap = .init();
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
    var map: RewriteMap = .init();
    map.set(15, 2);
    var args: Args = try .init(allocator, environ.block.slice, .debug, 15, map, 143, true, true, true, true, p_args);
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
        }
    }
    try std.testing.expect(found_env);
}

test extractExitCode {
    var status: u32 = @as(u32, 42) << 8;
    try std.testing.expectEqual(@as(u8, 42), extractExitCode(status));
    status = 9;
    try std.testing.expectEqual(@as(u8, 128 + 9), extractExitCode(status));
    status = 0x1FF;
    try std.testing.expectEqual(@as(u8, 0), extractExitCode(status));
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
