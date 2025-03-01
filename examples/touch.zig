const builtin = @import("builtin");
const std = @import("std");
const structopt = @import("structopt");

const debug = std.debug;
const heap = std.heap;

pub fn main() !void {
    var gpa = heap.GeneralPurposeAllocator(.{}){};
    defer {
        if (builtin.mode == .Debug) {
            _ = gpa.detectLeaks();
        } else {
            _ = gpa.deinit();
        }
    }

    var arena = heap.ArenaAllocator.init(gpa.allocator());
    defer arena.deinit();

    const Time = enum { access, modify };
    const opts = structopt.parse(
        struct {
            access_time: structopt.Flag(bool, .{
                .long_names = &.{},
                .help = "change only the access time",
            }) = .{ .default = false },
            @"no-create": structopt.Flag(bool, .{
                .short_names = &.{'c'},
                .help = "do not create any files",
            }) = .{ .default = false },
            date: structopt.Flag(?[]const u8, .{
                .placeholder = "STRING",
                .help = "parse STRING and use it instead of current time",
            }) = .{ .default = @as(?[]const u8, null) },
            _ignored: structopt.Flag(bool, .{
                .long_names = &.{},
                .short_names = &.{'f'},
                .help = "(ignored)",
            }) = .{ .default = false },
            @"no-dereference": structopt.Flag(bool, .{
                .short_names = &.{'h'},
                .help = "affect each symbolic link instead of any referenced file (useful only on systems that can change the timestamps of a symlink)",
            }) = .{ .default = false },
            modification_time: structopt.Flag(bool, .{
                .long_names = &.{},
                .help = "change only the modification time",
            }) = .{ .default = false },
            reference: structopt.Flag(?[]const u8, .{
                .placeholder = "FILE",
                .help = "use this file's times instead of current time",
            }) = .{ .default = @as(?[]const u8, null) },
            time_string: structopt.Flag(?[]const u8, .{
                .long_names = &.{},
                .help = "use specified time instead of current time, with a date-time format that differs from -d's",
            }) = .{ .default = @as(?[]const u8, null) },
            time: structopt.Flag(?Time, .{
                .short_names = &.{},
                .placeholder = "WORD",
                .help = "specify which time to change",
            }) = .{ .default = @as(?Time, null) },
            version: structopt.Flag(bool, .{
                .short_names = &.{},
                .help = "output version information and exit",
            }) = .{ .default = false },
            file: structopt.Positional([]const []const u8, .{}),
        },
        .{
            .binary_name = "touch",
            .description =
            \\Update the access and modification times of each FILE to the current time.
            \\
            \\A FILE argument that does not exist is created empty, unless -c or -h
            \\is supplied.
            \\
            \\A FILE argument string of - is handled specially and causes touch to
            \\change the times of the file associated with standard output."
            ,
        },
        arena.allocator(),
    );
    debug.print("{}\n", .{opts});
}
