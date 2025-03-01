const builtin = @import("builtin");
const std = @import("std");
const structopt = @import("structopt");

const debug = std.debug;
const fmt = std.fmt;
const heap = std.heap;
const mem = std.mem;

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

    const Flag = structopt.Flag;
    const opts = structopt.parse(
        struct {
            mode: Flag(?usize, .{
                .placeholder = "MODE",
                .help = "set file mode (as in chmod), not a=rwx - umask",
                .handler = .{ .value = struct {
                    fn f(arg: [:0]const u8, _: mem.Allocator) ?usize {
                        return fmt.parseInt(usize, arg, 8) catch |err| {
                            structopt.bail("failed to parse value \"{s}\" as mode: {}\n", .{ arg, err });
                        };
                    }
                }.f },
            }) = .{ .default = @as(?usize, null) },
            parents: Flag(bool, .{
                .help = "no error if existing, make parent directories as needed, with their file modes unaffected by any -m option.",
            }) = .{ .default = false },
            verbose: Flag(bool, .{
                .help = "print a message for each created directory",
            }) = .{ .default = false },
            context: Flag(bool, .{
                .short_names = &.{'Z'},
                .help = "set SELinux security context of each created directory to the default type",
            }) = .{ .default = false },
            version: Flag(bool, .{
                .short_names = &.{},
                .help = "output version information and exit",
            }) = .{ .default = false },
            directory: structopt.Positional([]const []const u8, .{}),
        },
        .{
            .binary_name = "mkdir",
            .description = "Create the DIRECTORY(ies), if they do not already exist.",
        },
        arena.allocator(),
    );
    debug.print("{}\n", .{opts});
}
