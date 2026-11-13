// SPDX-FileCopyrightText: 2026 YuMing He <ComixHe1895@outlook.com>
//
// SPDX-License-Identifier: MIT

//! Strips an ELF64 executable to its allocatable sections.
//! A separate pass is needed because `-fstrip` changes code layout.

const std = @import("std");
const cli = @import("cli");

const usage = "usage: strip <input> <output>\n";

const Ehdr = std.elf.Elf64.Ehdr;
const Shdr = std.elf.Elf64.Shdr;

pub fn main(init: std.process.Init) !void {
    const arena = init.arena.allocator();
    const io = init.io;

    if (cli.hasHelp(init.minimal.args)) {
        try cli.printStdout(io, "{s}", .{usage});
        return;
    }

    var args = init.minimal.args.iterate();
    _ = args.skip();
    const input = args.next() orelse return cli.invalid(usage);
    const output = args.next() orelse return cli.invalid(usage);
    if (args.next() != null) return cli.invalid(usage);

    const cwd = std.Io.Dir.cwd();
    const original = try cwd.readFileAlloc(io, input, arena, .limited(1 << 30));
    const stripped = try strip(arena, original);

    var file = try cwd.createFile(io, output, .{ .truncate = true });
    defer file.close(io);
    try file.writeStreamingAll(io, stripped);
    try file.setPermissions(io, .fromMode(0o755));
}

pub fn strip(allocator: std.mem.Allocator, data: []const u8) ![]u8 {
    const ehdr = try elfHeader(data);
    const shoff: usize = @intCast(ehdr.shoff);
    const shentsize: usize = ehdr.shentsize;
    const shnum: usize = ehdr.shnum;
    if (shoff == 0 or shnum == 0) return error.NoSectionTable;
    if (@as(usize, ehdr.shstrndx) >= shnum) return error.NoSectionTable;
    if (shentsize < @sizeOf(Shdr)) return error.NoSectionTable;
    if (shoff + shnum * shentsize > data.len) return error.NoSectionTable;

    const sections = try allocator.alloc(Shdr, shnum);
    defer allocator.free(sections);
    for (sections, 0..) |*section, i| {
        section.* = sectionHeader(data, shoff + i * shentsize);
    }

    const names = sections[ehdr.shstrndx];
    if (names.offset + names.size > data.len) return error.NoSectionTable;
    const name_bytes = data[@intCast(names.offset)..][0..@intCast(names.size)];

    const keep = try allocator.alloc(usize, shnum);
    defer allocator.free(keep);
    var keep_count: usize = 0;
    var keep_end: u64 = @sizeOf(Ehdr);
    keep_end = @max(
        keep_end,
        ehdr.phoff + @as(u64, ehdr.phentsize) * ehdr.phnum,
    );

    for (sections, 0..) |section, i| {
        if (i == 0) {
            keep[keep_count] = 0;
            keep_count += 1;
            continue;
        }

        if (!section.flags.shf.ALLOC) continue;
        keep[keep_count] = i;
        keep_count += 1;
        if (section.type != .NOBITS) {
            keep_end = @max(keep_end, section.offset + section.size);
        }
    }

    if (keep_end > data.len) return error.BadSectionTable;

    var names_size: usize = 1;
    for (keep[0..keep_count]) |i| names_size += sectionName(name_bytes, sections[i].name).len + 1;
    const self_name_offset = names_size;
    names_size += ".shstrtab".len + 1;

    const new_names = try allocator.alloc(u8, names_size);
    defer allocator.free(new_names);
    @memset(new_names, 0);
    const name_offsets = try allocator.alloc(u32, keep_count);
    defer allocator.free(name_offsets);
    var at: usize = 1;
    for (keep[0..keep_count], 0..) |i, k| {
        const name = sectionName(name_bytes, sections[i].name);
        name_offsets[k] = @intCast(at);
        @memcpy(new_names[at..][0..name.len], name);
        at += name.len + 1;
    }
    @memcpy(new_names[self_name_offset..][0..".shstrtab".len], ".shstrtab");

    const names_offset = keep_end;
    const table_offset = std.mem.alignForward(u64, names_offset + names_size, 8);
    const new_count = keep_count + 1;
    const out = try allocator.alloc(u8, @intCast(table_offset + new_count * @sizeOf(Shdr)));
    @memset(out, 0);
    @memcpy(out[0..@intCast(keep_end)], data[0..@intCast(keep_end)]);
    @memcpy(out[@intCast(names_offset)..][0..names_size], new_names);

    for (keep[0..keep_count], 0..) |i, k| {
        var section = sections[i];
        section.name = name_offsets[k];
        const destination: usize = @intCast(table_offset + k * @sizeOf(Shdr));
        @memcpy(out[destination..][0..@sizeOf(Shdr)], std.mem.asBytes(&section));
    }

    const names_header: Shdr = .{
        .name = @intCast(self_name_offset),
        .type = .STRTAB,
        .flags = .{ .shf = .{} },
        .addr = 0,
        .offset = names_offset,
        .size = @intCast(names_size),
        .link = 0,
        .info = 0,
        .addralign = 1,
        .entsize = 0,
    };

    const names_header_at: usize = @intCast(table_offset + keep_count * @sizeOf(Shdr));
    @memcpy(out[names_header_at..][0..@sizeOf(Shdr)], std.mem.asBytes(&names_header));

    var new_ehdr = ehdr;
    new_ehdr.shoff = table_offset;
    new_ehdr.shentsize = @sizeOf(Shdr);
    new_ehdr.shnum = @intCast(new_count);
    new_ehdr.shstrndx = @intCast(keep_count);
    @memcpy(out[0..@sizeOf(Ehdr)], std.mem.asBytes(&new_ehdr));

    return out;
}

fn elfHeader(data: []const u8) !Ehdr {
    if (data.len < @sizeOf(Ehdr)) return error.NotElf64;
    const ehdr = std.mem.bytesToValue(Ehdr, data[0..@sizeOf(Ehdr)]);
    if (!std.mem.eql(u8, &ehdr.ident.magic, std.elf.MAGIC)) return error.NotElf64;
    if (ehdr.ident.class != .@"64") return error.NotElf64;
    if (ehdr.ident.data != .@"2LSB") return error.NotElf64;
    return ehdr;
}

fn sectionHeader(data: []const u8, at: usize) Shdr {
    return std.mem.bytesToValue(Shdr, data[at..][0..@sizeOf(Shdr)]);
}

fn sectionName(names: []const u8, offset: u32) []const u8 {
    if (offset >= names.len) return "";
    const rest = names[offset..];
    const end = std.mem.findScalar(u8, rest, 0) orelse rest.len;
    return rest[0..end];
}

fn put(buf: []u8, at: usize, value: anytype) void {
    const bytes = std.mem.asBytes(&value);
    @memcpy(buf[at..][0..bytes.len], bytes);
}

test "strip keeps allocated sections and rewrites the name table" {
    const allocator = std.testing.allocator;

    var input: [0x200]u8 = @splat(0);
    var ehdr: Ehdr = std.mem.zeroes(Ehdr);
    ehdr.ident.magic = .{ 0x7f, 'E', 'L', 'F' };
    ehdr.ident.class = .@"64";
    ehdr.ident.data = .@"2LSB";
    ehdr.shoff = 0x100;
    ehdr.shentsize = @sizeOf(Shdr);
    ehdr.shnum = 4;
    ehdr.shstrndx = 3;
    put(&input, 0, ehdr);

    const names = "\x00.text\x00.comment\x00.shstrtab\x00";
    @memcpy(input[0x40..][0..4], "CODE");
    @memcpy(input[0x44..][0..4], "NOTE");
    @memcpy(input[0x48..][0..names.len], names);

    var text: Shdr = std.mem.zeroes(Shdr);
    text.name = 1;
    text.type = .PROGBITS;
    text.flags.shf.ALLOC = true;
    text.offset = 0x40;
    text.size = 4;
    put(&input, 0x100 + @sizeOf(Shdr), text);

    var comment: Shdr = std.mem.zeroes(Shdr);
    comment.name = 7;
    comment.type = .PROGBITS;
    comment.offset = 0x44;
    comment.size = 4;
    put(&input, 0x100 + 2 * @sizeOf(Shdr), comment);

    var strings: Shdr = std.mem.zeroes(Shdr);
    strings.name = 16;
    strings.type = .STRTAB;
    strings.offset = 0x48;
    strings.size = names.len;
    put(&input, 0x100 + 3 * @sizeOf(Shdr), strings);

    const out = try strip(allocator, &input);
    defer allocator.free(out);

    const out_ehdr = std.mem.bytesToValue(Ehdr, out[0..@sizeOf(Ehdr)]);
    try std.testing.expectEqual(@as(u16, 3), out_ehdr.shnum);
    try std.testing.expectEqual(@as(u16, 2), out_ehdr.shstrndx);
    try std.testing.expectEqualSlices(u8, "CODE", out[0x40..0x44]);

    const table: usize = @intCast(out_ehdr.shoff);
    const kept = sectionHeader(out, table + @sizeOf(Shdr));
    try std.testing.expectEqual(@as(u64, 0x40), kept.offset);
    try std.testing.expectEqual(@as(u64, 4), kept.size);
    try std.testing.expect(std.mem.find(u8, out, "NOTE") == null);
}
