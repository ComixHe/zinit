// SPDX-FileCopyrightText: 2026 YuMing He <ComixHe1895@outlook.com>
//
// SPDX-License-Identifier: MIT

//! Minimal fault reporter for builds that do not carry `std.debug`'s crash
//! handler (`ReleaseSmall`, or `-Dstack-traces=false`).
//!
//! It writes one line naming the program counter and exits with 70. The address
//! is symbolized offline against the `.dbg` file built from the same link, so
//! the shipped binary stays small: no DWARF, no unwind tables, no symbol table.
//!
//! A static PIE has no dynamic linker and no libc, so `dl_iterate_phdr` and
//! `dladdr` are unavailable. The load bias comes from the kernel auxiliary
//! vector instead.

const std = @import("std");
const builtin = @import("builtin");
const fmt = @import("fmt.zig");

/// A stack overflow faults on the exhausted stack, so the handler needs its own.
/// It lives in `.bss` and costs no file size.
/// https://github.com/torvalds/linux/blob/9d66f26fefacebfeed15de31c1123451a17ff119/arch/arm/include/uapi/asm/signal.h#L70
const alt_stack_size = 8 * 1024;
var alt_stack: [alt_stack_size]u8 align(16) = undefined;

/// The exit status for an internal fatal failure: `EX_SOFTWARE`
const fatal_exit_code: u8 = 70;

/// What zinit was doing when the fault happened.
pub const Phase = enum { startup, spawn, supervise, shutdown };

var phase: Phase = .startup;

pub fn setPhase(value: Phase) void {
    phase = value;
}

var load_bias: usize = 0;
var elf_end: usize = 0;
var bias_known: bool = false;

/// Installs the handler for the terminating fault signals. The supervisor's
/// forwarded signals stay blocked and keep their default disposition.
pub fn install(comptime pie: bool) void {
    if (comptime pie) {
        if (detectLoadBias()) |range| {
            load_bias = range.base;
            elf_end = range.end;
            bias_known = true;
        }
    }

    var stack: std.os.linux.stack_t = .{
        .sp = @ptrCast(&alt_stack),
        .flags = 0,
        .size = alt_stack.len,
    };
    _ = std.os.linux.sigaltstack(&stack, null);

    const action: std.os.linux.Sigaction = .{
        .handler = .{ .sigaction = Handler(pie).handle },
        .mask = std.os.linux.sigemptyset(),
        .flags = std.os.linux.SA.SIGINFO | std.os.linux.SA.ONSTACK | std.os.linux.SA.RESTART,
    };

    for ([_]std.os.linux.SIG{ .SEGV, .BUS, .ILL, .FPE }) |sig| {
        _ = std.os.linux.sigaction(sig, &action, null);
    }
}

/// The auxv `AT_ENTRY` value is relocated at load time; `e_entry` is the
/// link-time value. Their difference is the load bias of an `ET_DYN` image.
/// An `ET_EXEC` image is loaded at its link-time addresses, so it has none.
///
/// The ELF header is found by scanning the page that contains `AT_PHDR` and
/// checking that `header + e_phoff` points back at the auxiliary vector's
/// program-header address. musl uses `AT_PHDR & -PAGESIZE` for the same job;
/// the scan also handles a first `PT_LOAD` whose virtual address is not zero.
const Image = struct {
    /// Runtime address minus link-time address for the main image.
    base: usize,
    /// One past the highest `PT_LOAD` byte; zero when program headers are not
    /// available, which disables the range check.
    end: usize,
};

fn detectLoadBias() ?Image {
    const phdr = std.os.linux.getauxval(std.elf.AT.PHDR);
    const entry = std.os.linux.getauxval(std.elf.AT.ENTRY);
    const page_size = std.os.linux.getauxval(std.elf.AT.PAGESZ);
    if (phdr == 0 or entry == 0 or page_size == 0) return null;
    if (!std.math.isPowerOfTwo(page_size)) return null;

    const page = phdr & ~(page_size - 1);
    var header = page;
    while (header + @sizeOf(std.elf.Ehdr) <= phdr) : (header += 8) {
        const ehdr: *const std.elf.Ehdr = @ptrFromInt(header);
        if (!std.mem.eql(u8, ehdr.e_ident[0..4], "\x7fELF")) continue;

        const phoff = std.math.cast(usize, ehdr.e_phoff) orelse return null;
        if (header + phoff != phdr) continue;

        if (ehdr.e_type != .DYN) return null;

        const entry_addr = std.math.cast(usize, ehdr.e_entry) orelse return null;
        if (entry < entry_addr) return null;
        const bias = entry - entry_addr;

        // A fault in the VDSO or another mapping must not be reported as a
        // main-image address. The range is the highest PT_LOAD end.
        var loaded_end: u64 = 0;
        const phnum = std.os.linux.getauxval(std.elf.AT.PHNUM);
        const phent = std.os.linux.getauxval(std.elf.AT.PHENT);
        if (phnum != 0 and phent >= @sizeOf(std.elf.Elf64.Phdr)) {
            for (0..phnum) |i| {
                const ph: *const std.elf.Elf64.Phdr = @ptrFromInt(phdr + i * phent);
                if (ph.type == .LOAD) loaded_end = @max(loaded_end, ph.vaddr + ph.memsz);
            }
        }

        const size = std.math.cast(usize, loaded_end) orelse 0;
        return .{ .base = bias, .end = bias +| size };
    }

    return null;
}

fn Handler(comptime pie: bool) type {
    return struct {
        /// Async-signal-safe: no allocation, no formatting machinery, no locks.
        fn handle(
            sig: std.os.linux.SIG,
            info: *const std.os.linux.siginfo_t,
            ctx: ?*anyopaque,
        ) callconv(.c) void {
            const pc = if (std.debug.cpu_context.fromPosixSignalContext(ctx)) |context|
                context.getPc()
            else
                0;

            // A positive code is a kernel fault code; otherwise the signal came
            // from kill/raise and the `sigfault` view is not valid.
            const addr: usize = if (info.code > 0)
                @intFromPtr(info.fields.sigfault.addr)
            else
                0;

            if (comptime pie) {
                if (bias_known and pc >= load_bias and (elf_end == 0 or pc < elf_end)) {
                    report(true, sig, pc, info.code, addr);
                    return;
                }
            }

            report(pie, sig, pc, info.code, addr);
        }
    };
}

fn appendCode(buf: []u8, at: usize, code: i32) usize {
    if (code < 0) {
        const next = fmt.appendBytes(buf, at, "-");
        return fmt.appendInt(buf, next, @abs(@as(i64, code)), .dec);
    }

    return fmt.appendInt(buf, at, @intCast(code), .dec);
}

fn report(comptime pie: bool, sig: std.os.linux.SIG, pc: usize, code: i32, addr: usize) noreturn {
    var buf: [192]u8 = undefined;
    var at: usize = 0;
    at = fmt.appendBytes(&buf, at, "zinit: fatal signal ");
    at = fmt.appendInt(&buf, at, @backingInt(sig), .dec);
    at = fmt.appendBytes(&buf, at, " phase=");
    at = fmt.appendBytes(&buf, at, @tagName(phase));
    at = fmt.appendBytes(&buf, at, " code=");
    at = appendCode(&buf, at, code);
    at = fmt.appendBytes(&buf, at, " addr=0x");
    at = fmt.appendInt(&buf, at, addr, .hex);

    if (pie) {
        at = fmt.appendBytes(&buf, at, " pc=0x");
        at = fmt.appendInt(&buf, at, pc, .hex);
        at = fmt.appendBytes(&buf, at, " load_bias=0x");
        at = fmt.appendInt(&buf, at, load_bias, .hex);
        at = fmt.appendBytes(&buf, at, " elf_pc=0x");
        at = fmt.appendInt(&buf, at, pc -| load_bias, .hex);
    } else {
        at = fmt.appendBytes(&buf, at, " at 0x");
        at = fmt.appendInt(&buf, at, pc, .hex);
    }

    buf[at] = '\n';
    at += 1;
    const iov = [_]std.posix.iovec_const{.{ .base = &buf, .len = at }};
    writeAndExit(&iov);
}

/// Writes an already-formatted fatal line to stderr and exits with 70. Shared
/// with the message-only panic handler in `app/main.zig`.
pub fn writeAndExit(iov: []const std.posix.iovec_const) noreturn {
    _ = std.os.linux.writev(std.os.linux.STDERR_FILENO, iov.ptr, iov.len);
    std.os.linux.exit(fatal_exit_code);
}
