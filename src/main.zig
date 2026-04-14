const std = @import("std");
const config = @import("config");
const builtin = @import("builtin");
const clap = @import("clap");

pub const std_options: std.Options = .{
    .enable_segfault_handler = false,
    .signal_stack_size = null,
    .allow_stack_tracing = false,
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

var debug_allocator: std.heap.DebugAllocator(.{}) = .init;

const LogLevel = enum(u8) {
    err = 0,
    warn = 1,
    info = 2,
    debug = 3,
};

const Logger = struct {
    var runtime_log_level: LogLevel = .warn;
    var target_fd: std.os.linux.fd_t = std.os.linux.STDERR_FILENO;

    pub fn setTargetFd(fd: std.os.linux.fd_t) void {
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

    fn rawTryWriteAll(fd: std.os.linux.fd_t, bytes: []const u8) void {
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
    return sig_num > 0 and sig_num < std.os.linux.NSIG;
}

fn parseRealtimeSignal(s: []const u8) ?u32 {
    const rtmin_prefixes = [_][]const u8{ "RTMIN", "SIGRTMIN" };
    inline for (rtmin_prefixes) |prefix| {
        if (std.ascii.startsWithIgnoreCase(s, prefix)) {
            const base = std.os.linux.sigrtmin();
            const suffix = s[prefix.len..];
            if (suffix.len == 0) return base;
            if (suffix[0] != '+') return null;

            const offset = std.fmt.parseUnsigned(u8, suffix[1..], 10) catch return null;
            const value = @as(u32, base) + offset;
            if (!isValidU32(value) or value > std.os.linux.sigrtmax()) return null;
            return @intCast(value);
        }
    }

    const rtmax_prefixes = [_][]const u8{ "RTMAX", "SIGRTMAX" };
    inline for (rtmax_prefixes) |prefix| {
        if (std.ascii.startsWithIgnoreCase(s, prefix)) {
            const base = std.os.linux.sigrtmax();
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

fn parseSignal(s: []const u8) ?u32 {
    if (s.len == 0) {
        return null;
    }

    if (std.fmt.parseUnsigned(u32, s, 10)) |sig_num| {
        if (isValidU32(sig_num)) return @intCast(sig_num);
        return null;
    } else |_| {}

    if (parseRealtimeSignal(s)) |sig_num| {
        return sig_num;
    }

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

const RewriteMap = std.AutoArrayHashMapUnmanaged(u32, u32);

fn hasCycle(map: *const RewriteMap, start_node: u32) bool {
    var visited = std.StaticBitSet(std.posix.NSIG).initEmpty();
    std.debug.assert(start_node > 0 and start_node < std.posix.NSIG);

    visited.set(start_node);
    var current = start_node;
    while (map.get(current)) |next_node| {
        if (visited.isSet(next_node)) {
            return true;
        }

        visited.set(next_node);
        current = next_node;
    }

    return false;
}

fn parseRewrite(map: *RewriteMap, value: []const u8) !void {
    var kv = std.mem.splitScalar(u8, value, ':');

    const old = kv.next() orelse return ZinitError.InvalidRewrite;
    const old_sig = parseSignal(old) orelse return ZinitError.InvalidSignal;

    const new = kv.next() orelse return ZinitError.InvalidRewrite;
    const new_sig = parseSignal(new) orelse return ZinitError.InvalidSignal;

    if (old_sig == new_sig) {
        return ZinitError.DuplicateSignal;
    }

    if (map.contains(old_sig)) {
        return ZinitError.DuplicateSignal;
    }

    if (hasCycle(map, new_sig)) {
        return ZinitError.CycleRewrite;
    }

    if (kv.peek() != null) {
        return ZinitError.InvalidRewrite;
    }

    const result = map.getOrPutAssumeCapacity(old_sig);
    if (result.found_existing) {
        return ZinitError.DuplicateSignal;
    }

    result.value_ptr.* = new_sig;
}

fn buildRewriteMap(allocator: std.mem.Allocator, rewrites: []const []const u8) !?RewriteMap {
    if (rewrites.len == 0) return null;

    var map = RewriteMap.empty;
    try map.ensureTotalCapacity(allocator, rewrites.len);
    errdefer map.deinit(allocator);

    for (rewrites) |value| {
        parseRewrite(&map, value) catch {
            Logger.err("unable to parse rewrite: {s}", .{value});
            return ZinitError.InvalidRewrite;
        };
    }

    map.shrinkAndFree(allocator, map.count());
    return map;
}

fn mapSignal(rewrite: ?RewriteMap, signo: u32) u32 {
    return if (rewrite) |m| m.get(signo) orelse signo else signo;
}

const forwardMode = enum { Child, ProcessGroup };

const Args = struct {
    log_level: LogLevel,
    pdeath_signal: ?u32,
    mode: forwardMode,
    rewrite: ?RewriteMap,
    expected_exit: ?u8,
    subreaper: bool,
    tracing_child: bool,
    argv: [:null]const ?[*:0]const u8,
    envp: [:null]const ?[*:0]const u8,
    arena: std.heap.ArenaAllocator,

    pub fn init(
        allocator: std.mem.Allocator,
        environ: std.process.Environ,
        log_level: LogLevel,
        pdeath_signal: ?u32,
        mode: forwardMode,
        rewrites: []const []const u8,
        expected_exit: ?u8,
        subreaper: bool,
        tracing_child: bool,
        args: []const []const u8,
    ) !Args {
        var arena = std.heap.ArenaAllocator.init(allocator);
        errdefer arena.deinit();
        const arena_allocator = arena.allocator();

        const argv = try arena_allocator.allocSentinel(?[*:0]const u8, args.len, null);
        for (args, 0..) |arg, i| {
            argv[i] = try arena_allocator.dupeSentinel(u8, arg, 0);
        }

        const env_view = environ.block.view();
        const envp = try arena_allocator.allocSentinel(?[*:0]const u8, env_view.slice.len, null);
        for (env_view.slice, 0..) |raw_ptr, i| {
            envp[i] = raw_ptr;
        }

        const rewrite_map = try buildRewriteMap(arena_allocator, rewrites);

        return .{
            .arena = arena,
            .log_level = log_level,
            .pdeath_signal = pdeath_signal,
            .mode = mode,
            .rewrite = rewrite_map,
            .expected_exit = expected_exit,
            .subreaper = subreaper,
            .tracing_child = tracing_child,
            .argv = argv,
            .envp = envp,
        };
    }

    pub fn deinit(self: *Args) void {
        self.arena.deinit();
    }
};

fn parseLogLevel(value: []const u8) ?LogLevel {
    if (std.ascii.eqlIgnoreCase(value, "error")) return .err;
    if (std.ascii.eqlIgnoreCase(value, "warning")) return .warn;
    if (std.ascii.eqlIgnoreCase(value, "info")) return .info;
    if (std.ascii.eqlIgnoreCase(value, "debug")) return .debug;
    return null;
}

fn parseExpectedExit(value: []const u8) !u8 {
    return std.fmt.parseUnsigned(u8, value, 10) catch ZinitError.InvalidExitCode;
}

fn parseTracingChild(env_val: ?[]const u8, default: bool) bool {
    const val = env_val orelse return default;
    return if (std.ascii.eqlIgnoreCase(val, "OFF")) false else if (std.ascii.eqlIgnoreCase(val, "ON")) true else default;
}

fn parseArgsWithIo(io: std.Io, allocator: std.mem.Allocator, args: std.process.Args, environ: std.process.Environ) !?Args {
    const params = comptime clap.parseParamsComptime(
        \\-h, --help
        \\-v, --version
        \\--log-level <LEVEL>            "Set log level: error, warning, info, or debug"
        \\-p, --signal <SIGNAL>          "The triggered signal when parent process dies"
        \\-s, --subreaper                "Enable child subreaper mode explicitly"
        \\-r, --rewrite <OLD:NEW>...     "Rewrite a forwarded signal before sending to the child"
        \\-e, --expect-exit <CODE>       "Map a child exit code to 0"
        \\--forward-mode <MODE>          "The mode of forwarding signals to child processes"
        \\<ARG>...                       "Arguments to be passed to the child process"
    );

    const parsers = comptime .{
        .LEVEL = clap.parsers.string,
        .SIGNAL = clap.parsers.string,
        .MODE = clap.parsers.enumeration(forwardMode),
        .@"OLD:NEW" = clap.parsers.string,
        .CODE = clap.parsers.string,
        .ARG = clap.parsers.string,
    };

    var diag = clap.Diagnostic{};
    var res = clap.parse(clap.Help, &params, parsers, args, .{
        .diagnostic = &diag,
        .allocator = allocator,
    }) catch |err| {
        try diag.reportToFile(io, .stderr(), err);
        return ZinitError.InvalidParams;
    };
    defer res.deinit();

    if (res.args.help != 0) {
        const out = std.Io.File.stdout();
        try out.writeStreamingAll(io, "zinit - A tiny init for linux containers.\n\n");
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

    const log_level = if (res.args.@"log-level") |value|
        parseLogLevel(value) orelse {
            Logger.err("invalid log level: '{s}'", .{value});
            return ZinitError.InvalidParams;
        }
    else
        .warn;

    const pdeath_signal = if (res.args.signal) |sig|
        parseSignal(sig) orelse {
            Logger.err("invalid signal name or number: '{s}'", .{sig});
            return ZinitError.InvalidSignal;
        }
    else
        null;

    const expected_exit = if (res.args.@"expect-exit") |value|
        parseExpectedExit(value) catch {
            Logger.err("invalid expected exit code: '{s}'", .{value});
            return ZinitError.InvalidExitCode;
        }
    else
        null;

    const tracing_child = parseTracingChild(environ.getPosix("ZINIT_TRACING_CHILD"), config.tracing_child);

    return try Args.init(
        allocator,
        environ,
        log_level,
        pdeath_signal,
        res.args.@"forward-mode" orelse .Child,
        res.args.rewrite,
        expected_exit,
        res.args.subreaper != 0,
        tracing_child,
        res.positionals[0],
    );
}

fn parseArgs(allocator: std.mem.Allocator, args: std.process.Args, environ: std.process.Environ) !?Args {
    var threaded: std.Io.Threaded = .init(allocator, .{
        .environ = environ,
        .argv0 = .init(args),
    });
    defer threaded.deinit();
    return parseArgsWithIo(threaded.io(), allocator, args, environ);
}

const SHUTDOWN_GRACE_PERIOD_NS: u64 = 5 * std.time.ns_per_s;

const SigConf = struct {
    old_set: std.posix.sigset_t,
    current_set: std.posix.sigset_t,
    ttin_action: std.posix.Sigaction,
    ttou_action: std.posix.Sigaction,
};

fn handleSignal(comptime sig_list: anytype) SigConf {
    var set = std.posix.sigfillset();
    inline for (sig_list) |sig| {
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

fn setupChildTerminal() void {
    const sid = std.os.linux.setsid();
    var err = std.os.linux.errno(sid);
    if (err != .SUCCESS and err != .PERM) {
        reportChildError("unable to create session: {s}", .{@tagName(err)});
    }

    const rc = std.os.linux.ioctl(std.posix.STDIN_FILENO, std.posix.T.IOCSCTTY, 1);
    err = std.os.linux.errno(rc);
    if (err != .SUCCESS and err != .NOTTY and err != .INVAL and err != .PERM) {
        reportChildError("unable to acquire controlling tty: {s}", .{@tagName(err)});
    }

    const child_pid = std.os.linux.getpid();
    std.posix.tcsetpgrp(std.posix.STDIN_FILENO, child_pid) catch |e| {
        if (e != std.posix.TermioSetPgrpError.NotATerminal and e != std.posix.TermioSetPgrpError.NotAPgrpMember) {
            reportChildError("tcsetpgrp failed: {s}", .{@errorName(e)});
        }
    };
}

fn run(args: *Args, sig_conf: *const SigConf) !usize {
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
    setupChildTerminal();

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

    const env_ptr: [*:null]const ?[*:0]const u8 = @ptrCast(args.envp.ptr);
    const args_ptr: [*:null]const ?[*:0]const u8 = @ptrCast(args.argv.ptr);
    const ret = std.os.linux.execve(args_ptr[0].?, args_ptr, env_ptr);
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
            else => return std.posix.unexpectedErrno(err),
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
    rewrite: ?RewriteMap,
    mode: forwardMode,
    sigfd: std.posix.fd_t,
    shutdown: ?ShutdownState = null,
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

fn getSignalDestination(mode: forwardMode, child_pid: usize) std.posix.pid_t {
    return if (mode == .ProcessGroup)
        -@as(std.posix.pid_t, @intCast(child_pid))
    else
        @intCast(child_pid);
}

fn forwardSignal(state: *ProcessState, signo: u32) void {
    const signal_to_send = mapSignal(state.rewrite, signo);
    Logger.debug("forwarding signal {d} as {d}", .{ signo, signal_to_send });

    const destination = getSignalDestination(state.mode, state.child);

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

fn tryClose(fd: std.os.linux.fd_t) void {
    if (fd < 0) {
        return;
    }

    while (true) {
        const close_rc = std.os.linux.close(fd);
        switch (std.os.linux.errno(close_rc)) {
            .SUCCESS => return,
            .INTR => continue,
            else => |err| Logger.err("unable to close fd {d}: {s}", .{ fd, @tagName(err) }),
        }
    }
}

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

    var args = parseArgs(allocator, init.args, init.environ) catch |err| {
        Logger.err("unable to parse arguments: {s}", .{@errorName(err)});
        return 1;
    } orelse return 0;
    defer args.deinit();
    Logger.setLevel(args.log_level);

    const unblocked_sigs = [_]std.posix.SIG{ .ABRT, .BUS, .FPE, .ILL, .SEGV, .SYS, .TRAP, .XCPU, .XFSZ, .TTIN, .TTOU };
    const sig_conf = handleSignal(unblocked_sigs);

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
        .rewrite = args.rewrite,
        .mode = args.mode,
        .sigfd = sigfd,
    };

    while (true) {
        const count = std.posix.poll(poll_fds[0..poll_fds_len], -1) catch |err| {
            Logger.err("poll failed: {s}", .{@errorName(err)});
            return 1;
        };

        if (count == 0) continue;

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
    try std.testing.expectEqual(@as(?u32, 15), parseSignal("15"));
    try std.testing.expectEqual(@as(?u32, 15), parseSignal("SIGTERM"));
    try std.testing.expectEqual(@as(?u32, 15), parseSignal("TERM"));
    try std.testing.expectEqual(@as(?u32, std.os.linux.sigrtmin()), parseSignal("SIGRTMIN"));
    try std.testing.expectEqual(@as(?u32, std.os.linux.sigrtmin() + 2), parseSignal("SIGRTMIN+2"));
    try std.testing.expectEqual(@as(?u32, std.os.linux.sigrtmax() - 1), parseSignal("RTMAX-1"));
    try std.testing.expectEqual(null, parseSignal("UNKNOWN"));
    try std.testing.expectEqual(null, parseSignal("999"));
    try std.testing.expectEqual(null, parseSignal("0"));
    try std.testing.expectEqual(null, parseSignal(""));
}

test "parseSignal edge cases" {
    try std.testing.expectEqual(null, parseSignal("SIG"));
    try std.testing.expectEqual(null, parseSignal("A"));
    const long_name = "SIG" ++ "A" ** 20;
    try std.testing.expectEqual(null, parseSignal(long_name));
}

test parseRewrite {
    const allocator = std.testing.allocator;
    var map = RewriteMap.empty;
    try map.ensureTotalCapacity(allocator, 1);
    defer map.deinit(allocator);

    try parseRewrite(&map, "TERM:INT");
    const new_sig = map.get(15);

    try std.testing.expectEqual(2, new_sig);
}

test "parseRewrite error cases" {
    const allocator = std.testing.allocator;
    var map = RewriteMap.empty;
    defer map.deinit(allocator);

    try map.ensureTotalCapacity(allocator, 3);

    try std.testing.expectError(ZinitError.InvalidRewrite, parseRewrite(&map, "TERM"));

    try std.testing.expectError(ZinitError.InvalidSignal, parseRewrite(&map, "TERM:BAD"));

    try std.testing.expectError(ZinitError.DuplicateSignal, parseRewrite(&map, "TERM:TERM"));

    try parseRewrite(&map, "TERM:INT");
    try std.testing.expectError(ZinitError.DuplicateSignal, parseRewrite(&map, "TERM:HUP"));

    map.clearRetainingCapacity();
    try std.testing.expectError(ZinitError.InvalidRewrite, parseRewrite(&map, "TERM:INT:EXTRA"));

    map.putAssumeCapacity(1, 2);
    map.putAssumeCapacity(2, 9);
    map.putAssumeCapacity(9, 1);
    try std.testing.expectError(ZinitError.CycleRewrite, parseRewrite(&map, "TERM:1"));
}

test hasCycle {
    const allocator = std.testing.allocator;
    var map = RewriteMap.empty;
    defer map.deinit(allocator);

    try map.ensureTotalCapacity(allocator, 3);

    map.putAssumeCapacity(15, 2);
    try std.testing.expect(!hasCycle(&map, 15));

    map.putAssumeCapacity(2, 9);
    try std.testing.expect(!hasCycle(&map, 15));

    map.putAssumeCapacity(9, 15);
    try std.testing.expect(hasCycle(&map, 15));
    try std.testing.expect(hasCycle(&map, 2));
    try std.testing.expect(hasCycle(&map, 9));

    map.clearRetainingCapacity();

    const rtmin = std.os.linux.sigrtmin();
    const rtmax = std.os.linux.sigrtmax();

    map.putAssumeCapacity(rtmin, @intCast(rtmin + 1));
    try std.testing.expect(!hasCycle(&map, rtmin));

    map.putAssumeCapacity(@intCast(rtmin + 1), @intCast(rtmin + 2));
    try std.testing.expect(!hasCycle(&map, rtmin));

    map.putAssumeCapacity(@intCast(rtmin + 2), rtmin);
    try std.testing.expect(hasCycle(&map, rtmin));

    if (rtmax > 60) {
        map.clearRetainingCapacity();
        map.putAssumeCapacity(@intCast(rtmax), @intCast(rtmax - 1));
        try std.testing.expect(!hasCycle(&map, rtmax));
    }
}

test mapSignal {
    const allocator = std.testing.allocator;
    var map = RewriteMap.empty;
    defer map.deinit(allocator);

    try map.ensureTotalCapacity(allocator, 1);

    map.putAssumeCapacity(15, 2);

    try std.testing.expectEqual(2, mapSignal(map, 15));
    try std.testing.expectEqual(9, mapSignal(map, 9));
    try std.testing.expectEqual(15, mapSignal(null, 15));
}

test buildRewriteMap {
    const allocator = std.testing.allocator;

    var map = try buildRewriteMap(allocator, &[_][]const u8{"TERM:INT"});
    try std.testing.expect(map != null);
    if (map) |*m| {
        defer m.deinit(allocator);
        try std.testing.expectEqual(@as(?u32, 2), m.get(15));
    }

    const empty_map = try buildRewriteMap(allocator, &[_][]const u8{});
    try std.testing.expect(empty_map == null);

    const invalid_result = buildRewriteMap(allocator, &[_][]const u8{"INVALID"});
    try std.testing.expectError(ZinitError.InvalidRewrite, invalid_result);
}

test Args {
    const allocator = std.testing.allocator;
    var env_map: std.process.Environ.Map = .init(allocator);
    defer env_map.deinit();
    try env_map.put("ZINIT_TEST_KEY", "1");

    const environ: std.process.Environ = .{ .block = try env_map.createPosixBlock(allocator, .{}) };
    defer environ.block.deinit(allocator);

    const p_args: []const []const u8 = &[_][]const u8{ "foo", "--bar=x", "-v", "-c" };

    var args = try Args.init(allocator, environ, .debug, 15, .Child, &[_][]const u8{"15:2"}, 143, true, true, p_args);
    defer args.deinit();

    try std.testing.expectEqual(LogLevel.debug, args.log_level);
    try std.testing.expectEqual(@as(?u32, 15), args.pdeath_signal);
    try std.testing.expectEqual(forwardMode.Child, args.mode);
    try std.testing.expectEqual(@as(?u8, 143), args.expected_exit);
    try std.testing.expect(args.subreaper);
    try std.testing.expect(args.tracing_child);
    try std.testing.expectEqualStrings("foo", std.mem.span(args.argv[0].?));
    try std.testing.expectEqualStrings("--bar=x", std.mem.span(args.argv[1].?));
    try std.testing.expectEqual(@as(?[*:0]const u8, null), args.argv[p_args.len]);

    var found_env = false;
    for (args.envp) |entry| {
        const raw = entry orelse continue;
        if (std.mem.eql(u8, std.mem.span(raw), "ZINIT_TEST_KEY=1")) {
            found_env = true;
            // run this loop till the end to make kcov happy
        }
    }

    try std.testing.expect(found_env);
}

test parseLogLevel {
    try std.testing.expectEqual(LogLevel.err, parseLogLevel("error").?);
    try std.testing.expectEqual(LogLevel.warn, parseLogLevel("WARNING").?);
    try std.testing.expectEqual(LogLevel.info, parseLogLevel("Info").?);
    try std.testing.expectEqual(LogLevel.debug, parseLogLevel("debug").?);
    try std.testing.expectEqual(null, parseLogLevel("trace"));
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
    var args = try Args.init(allocator, environ, .warn, null, .Child, &[_][]const u8{}, null, false, false, p_args);
    defer args.deinit();

    try std.testing.expect(args.rewrite == null);
    try std.testing.expect(args.envp[0] == null);
}

test "Args.init with invalid rewrite triggers error log" {
    const allocator = std.testing.allocator;
    var env_map: std.process.Environ.Map = .init(allocator);
    defer env_map.deinit();

    const environ: std.process.Environ = .{ .block = try env_map.createPosixBlock(allocator, .{}) };
    defer environ.block.deinit(allocator);

    const p_args: []const []const u8 = &[_][]const u8{"test"};
    const result = Args.init(allocator, environ, .warn, null, .Child, &[_][]const u8{"INVALID"}, null, false, false, p_args);
    try std.testing.expectError(ZinitError.InvalidRewrite, result);
}

test "Args.init with empty env" {
    const allocator = std.testing.allocator;
    var env_map: std.process.Environ.Map = .init(allocator);
    defer env_map.deinit();
    try env_map.put("TEST_KEY", "value");

    const environ: std.process.Environ = .{ .block = try env_map.createPosixBlock(allocator, .{}) };
    defer environ.block.deinit(allocator);

    const p_args: []const []const u8 = &[_][]const u8{"test"};
    var args = try Args.init(allocator, environ, .warn, null, .Child, &[_][]const u8{}, null, false, false, p_args);
    defer args.deinit();

    var found = false;
    for (args.envp) |entry| {
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
    try std.testing.expect(isValidU32(@as(u32, std.os.linux.NSIG) - 1));
    try std.testing.expect(!isValidU32(@as(u32, std.os.linux.NSIG)));
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
    try std.testing.expectEqual(@as(std.posix.pid_t, 100), getSignalDestination(.Child, 100));
    try std.testing.expectEqual(@as(std.posix.pid_t, -100), getSignalDestination(.ProcessGroup, 100));
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
