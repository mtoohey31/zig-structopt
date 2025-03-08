const builtin = @import("builtin");
const std = @import("std");
const ascii = std.ascii;
const fmt = std.fmt;
const io = std.io;
const mem = std.mem;
const process = std.process;
const StructField = std.builtin.Type.StructField;
const testing = std.testing;

var bail_error_message: ?[]const u8 = null;

pub fn bail(comptime format: []const u8, args: anytype) noreturn {
    if (builtin.is_test) {
        bail_error_message = fmt.allocPrint(testing.allocator, format, args) catch {
            @panic("out of memory while bailing in test");
        };
        @panic("test bail");
    } else {
        io.getStdErr().writer().print(format, args) catch {
            @panic("stderr write failed");
        };
        process.exit(2);
    }
}

pub fn ValueHandler(comptime T: type) type {
    return fn ([:0]const u8, arena: mem.Allocator) T;
}

pub fn Handler(comptime T: type) type {
    return union(enum) {
        occurrence: fn (arena: mem.Allocator) T,
        value: ValueHandler(T),
    };
}

const HandlerFor = struct {
    @"for": type,
    _handler: *const anyopaque,

    fn new(comptime @"for": type, handler_: *const Handler(@"for")) HandlerFor {
        return .{ .@"for" = @"for", ._handler = @ptrCast(handler_) };
    }

    fn handler(comptime self: HandlerFor) Handler(self.@"for") {
        return @as(*const Handler(self.@"for"), @ptrCast(self._handler)).*;
    }
};

const builtin_handlers: []const HandlerFor = &.{
    HandlerFor.new(bool, &.{ .occurrence = struct {
        fn f(_: mem.Allocator) bool {
            return true;
        }
    }.f }),
    HandlerFor.new([:0]const u8, &.{ .value = struct {
        fn f(arg: [:0]const u8, _: mem.Allocator) [:0]const u8 {
            return arg;
        }
    }.f }),
    HandlerFor.new([]const u8, &.{ .value = struct {
        fn f(arg: [:0]const u8, _: mem.Allocator) []const u8 {
            return arg;
        }
    }.f }),
    HandlerFor.new(f64, &.{ .value = struct {
        fn f(arg: [:0]const u8, _: mem.Allocator) f64 {
            return fmt.parseFloat(f64, arg) catch |err| {
                bail("failed to parse value \"{s}\" as f64: {}\n", .{ arg, err });
            };
        }
    }.f }),
    HandlerFor.new(f32, &.{ .value = struct {
        fn f(arg: [:0]const u8, _: mem.Allocator) f32 {
            return fmt.parseFloat(f32, arg) catch |err| {
                bail("failed to parse value \"{s}\" as f32: {}\n", .{ arg, err });
            };
        }
    }.f }),
};

pub fn FlagOptions(comptime T: type) type {
    return struct {
        long_names: ?[]const []const u8 = null,
        short_names: ?[]const u8 = null,
        placeholder: ?[]const u8 = null,
        help: ?[]const u8 = null,
        handler: ?Handler(T) = null,
    };
}

pub fn Flag(comptime T: type, comptime options: FlagOptions(T)) type {
    return struct {
        default: ?T,
        comptime unpacked: type = T,
        comptime structopt_flag_options: FlagOptions(T) = options,
    };
}

pub fn PositionalOptions(comptime T: type) type {
    return struct {
        handler: ?ValueHandler(T) = null,
    };
}

pub fn Positional(comptime T: type, comptime options: PositionalOptions(T)) type {
    return struct {
        default: ?T,
        comptime unpacked: type = T,
        comptime structopt_positional_options: PositionalOptions(T) = options,
    };
}

fn Options(comptime T: type) type {
    return union(enum) {
        flag: FlagOptions(T),
        positional: PositionalOptions(T),
    };
}

fn resolveBuiltinHandler(comptime T: type) Handler(T) {
    for (builtin_handlers) |builtin_handler| {
        if (builtin_handler.@"for" == T) {
            return builtin_handler.handler();
        }
    }

    switch (@typeInfo(T)) {
        .Int => return .{ .value = struct {
            fn f(arg: [:0]const u8, _: mem.Allocator) T {
                return fmt.parseInt(T, arg, 0) catch |err| {
                    bail("failed to parse value \"{s}\" as " ++ @typeName(T) ++ ": {}\n", .{ arg, err });
                };
            }
        }.f },
        .Pointer => |pointer| {
            if (T == *pointer.child or T == *const pointer.child) {
                switch (resolveBuiltinHandler(pointer.child)) {
                    .occurrence => |occurrence_handler| {
                        return .{ .occurrence = struct {
                            fn f(arena: mem.Allocator) T {
                                const res = arena.create(pointer.child) catch {
                                    bail("out of memory while handling pointer argument", .{});
                                };
                                res.* = occurrence_handler(arena);
                                return res;
                            }
                        }.f };
                    },
                    .value => |value_handler| {
                        return .{ .value = struct {
                            fn f(arg: [:0]const u8, arena: mem.Allocator) T {
                                const res = arena.create(pointer.child) catch {
                                    bail("out of memory while handling pointer argument", .{});
                                };
                                res.* = value_handler(arg, arena);
                                return res;
                            }
                        }.f };
                    },
                }
            }
        },
        .Optional => |optional| {
            switch (resolveBuiltinHandler(optional.child)) {
                .occurrence => |occurrence_handler| {
                    return .{ .occurrence = struct {
                        fn f(arena: mem.Allocator) ?optional.child {
                            return occurrence_handler(arena);
                        }
                    }.f };
                },
                .value => |value_handler| {
                    return .{ .value = struct {
                        fn f(arg: [:0]const u8, arena: mem.Allocator) ?optional.child {
                            return value_handler(arg, arena);
                        }
                    }.f };
                },
            }
        },
        .Enum => |@"enum"| {
            return .{ .value = struct {
                fn f(arg: [:0]const u8, _: mem.Allocator) T {
                    inline for (@"enum".fields) |field| {
                        if (mem.eql(u8, arg, field.name)) {
                            return @enumFromInt(field.value);
                        }
                    } else {
                        const expected_names = comptime blk: {
                            var expected_names: []const u8 = "";
                            for (0.., @"enum".fields) |i, field| {
                                if (i != 0) {
                                    expected_names = expected_names ++ ", ";
                                }
                                expected_names = expected_names ++ "\"" ++ field.name ++ "\"";
                            }
                            break :blk expected_names;
                        };
                        bail("unknown enum field \"{s}\"; expected one of " ++ expected_names ++ "\n", .{arg});
                    }
                }
            }.f };
        },
        else => {},
    }

    @compileError("unsupported option type " ++ @typeName(T));
}

fn resolvePositionalHandler(comptime T: type) ValueHandler(T) {
    switch (resolveBuiltinHandler(T)) {
        .occurrence => @compileError("failed to resolve value handler for positional with type " ++
            @typeName(T) ++ ", found only occurrence handler"),
        .value => |value_handler| return value_handler,
    }
}

fn Option(comptime T: fn (type) type) type {
    return struct {
        field: StructField,
        _options: *const anyopaque,

        fn new(comptime field: StructField, options_: T(field.type)) Option(T) {
            return .{ .field = field, ._options = @ptrCast(&options_) };
        }

        fn options(comptime self: Option(T)) T(self.field.type) {
            return @as(
                *const T(self.field.type),
                @ptrCast(@alignCast(self._options)),
            ).*;
        }

        fn resolveFlagHandler(comptime self: Option(FlagOptions)) Handler(self.field.type) {
            if (self.options().handler) |explicit_handler| {
                return explicit_handler;
            }

            return resolveBuiltinHandler(self.field.type);
        }

        const PositionalKind = struct {
            slice: bool,
            default: bool,
        };

        const Range = struct {
            min: comptime_int,
            max: ?comptime_int,

            fn variable(range: Range) bool {
                if (range.max) |max| {
                    return range.min != max;
                }

                return true;
            }
        };

        fn positionalKind(comptime self: Option(PositionalOptions)) PositionalKind {
            var slice = false;
            switch (@typeInfo(self.field.type)) {
                .Pointer => |pointer| {
                    if (self.field.type != []const u8 and
                        (self.field.type == []pointer.child or
                        self.field.type == []const pointer.child))
                    {
                        slice = true;
                    }
                },
                else => {},
            }

            return .{ .slice = slice, .default = self.field.default_value != null };
        }

        fn positionalRange(comptime self: Option(PositionalOptions)) Range {
            const kind = self.positionalKind();
            if (kind.slice) {
                return .{ .min = if (kind.default) 0 else 1, .max = null };
            }

            return .{ .min = if (kind.default) 0 else 1, .max = 1 };
        }
    };
}

fn looksPacked(comptime field: StructField) ?enum { flag, positional } {
    switch (@typeInfo(field.type)) {
        .Struct => |@"struct"| {
            const fields = @"struct".fields;
            if (fields.len == 3 and @"struct".decls.len == 0 and
                mem.eql(u8, fields[0].name, "default") and
                mem.eql(u8, fields[1].name, "unpacked") and fields[1].type == type and
                !fields[0].is_comptime and fields[1].is_comptime and fields[2].is_comptime)
            {
                const unpacked = @as(*const type, @ptrCast(fields[1].default_value.?)).*;
                if (fields[0].type == ?unpacked) {
                    if (mem.eql(u8, fields[2].name, "structopt_flag_options") and
                        fields[2].type == FlagOptions(unpacked))
                    {
                        return .flag;
                    }

                    if (mem.eql(u8, fields[2].name, "structopt_positional_options") and
                        fields[2].type == PositionalOptions(unpacked))
                    {
                        return .positional;
                    }
                }
            }
        },
        else => {},
    }

    return null;
}

fn unpack(comptime field: StructField) StructField {
    const packed_kind = looksPacked(field) orelse {
        return field;
    };
    const inner_fields = @typeInfo(field.type).Struct.fields;
    var new_field = field;
    new_field.type = @as(*const type, @ptrCast(inner_fields[1].default_value.?)).*;
    new_field.default_value = null;
    if (field.default_value) |default_option| {
        switch (packed_kind) {
            .flag => {
                const options = @as(
                    *const FlagOptions(new_field.type),
                    @ptrCast(@alignCast(inner_fields[2].default_value.?)),
                ).*;
                const default_flag = @as(
                    *const Flag(new_field.type, options),
                    @ptrCast(@alignCast(default_option)),
                ).*;
                if (default_flag.default) |default| {
                    new_field.default_value = @ptrCast(&default);
                }
            },
            .positional => {
                const options = @as(
                    *const PositionalOptions(new_field.type),
                    @ptrCast(@alignCast(inner_fields[2].default_value.?)),
                ).*;
                const default_positional = @as(
                    *const Positional(new_field.type, options),
                    @ptrCast(@alignCast(default_option)),
                ).*;
                if (default_positional.default) |default| {
                    new_field.default_value = @ptrCast(&default);
                }
            },
        }
    }
    return new_field;
}

fn unpackOptions(comptime field: StructField, comptime unpacked: StructField) Options(unpacked.type) {
    const packed_kind = looksPacked(field) orelse {
        return .{ .flag = .{
            .long_names = &.{field.name},
            .short_names = if (field.name.len > 0) &.{field.name[0]} else &.{},
        } };
    };
    switch (packed_kind) {
        .flag => {
            var options = @as(
                *const FlagOptions(unpacked.type),
                @ptrCast(@alignCast(@typeInfo(field.type).Struct.fields[2].default_value.?)),
            ).*;
            if (options.long_names == null) {
                options.long_names = &.{field.name};
            }
            if (options.short_names == null and field.name.len > 0) {
                options.short_names = &.{field.name[0]};
            }
            return .{ .flag = options };
        },
        .positional => {
            return .{ .positional = @as(
                *const PositionalOptions(unpacked.type),
                @ptrCast(@alignCast(@typeInfo(field.type).Struct.fields[2].default_value.?)),
            ).* };
        },
    }
}

pub fn Impl(comptime Spec: type) type {
    switch (@typeInfo(Spec)) {
        .Struct => |@"struct"| {
            var new_fields: []const StructField = &.{};
            for (@"struct".fields) |field| {
                new_fields = new_fields ++ &[_]StructField{unpack(field)};
            }
            var new_struct = @"struct";
            new_struct.fields = new_fields;
            return @Type(.{ .Struct = new_struct });
        },
        else => @compileError("options spec must be struct"),
    }
}

pub const ParseOptions = struct {
    binary_name: ?[]const u8 = null,
    description: ?[]const u8 = null,
    allow_repeats: bool = false,
};

pub fn parseIt(
    comptime Spec: type,
    comptime ArgIterator: type,
    comptime options: ParseOptions,
    arena: mem.Allocator,
    it: *ArgIterator,
) Impl(Spec) {
    const flags, const positionals, const min_positionals, const max_positionals, const variable_i_positional, const help_format = comptime blk: {
        var flags: []const Option(FlagOptions) = &.{};
        var positionals: []const Option(PositionalOptions) = &.{};

        const fields: []const StructField = switch (@typeInfo(Spec)) {
            .Struct => |@"struct"| @"struct".fields,
            else => @compileError("options spec must be struct"),
        };
        for (fields) |field| {
            const unpacked = unpack(field);
            switch (unpackOptions(field, unpacked)) {
                .flag => |flag_options| flags = flags ++ &[_]Option(FlagOptions){
                    Option(FlagOptions).new(unpacked, flag_options),
                },
                .positional => |positional_options| positionals = positionals ++ &[_]Option(PositionalOptions){
                    Option(PositionalOptions).new(unpacked, positional_options),
                },
            }
        }

        var long_names: []const []const u8 = &.{};
        var short_names: []const u8 = &.{};
        for (flags) |flag| {
            const flag_options = flag.options();
            if (flag_options.long_names) |new_long_names| {
                long_names = long_names ++ new_long_names;
            }
            if (flag_options.short_names) |new_short_names| {
                short_names = short_names ++ new_short_names;
            }
        }
        for (0.., long_names) |i, long_name| {
            if (long_name.len == 0) {
                @compileError("long names cannot be empty");
            }
            for (long_names[i + 1 ..]) |other_long_name| {
                if (mem.eql(u8, long_name, other_long_name)) {
                    @compileError("long name \"" ++ long_name ++ "\" was used more than once");
                }
            }
        }
        for (0.., short_names) |i, short_name| {
            for (short_names[i + 1 ..]) |other_short_name| {
                if (short_name == other_short_name) {
                    @compileError("short name '" ++ &[_]u8{short_name} ++ "' was used more than once");
                }
            }
        }

        var min_positionals = 0;
        var max_positionals: ?comptime_int = 0;
        var variable_i_positional: ?usize = null;
        for (0.., positionals) |i, positional| {
            const range = positional.positionalRange();
            if (positional.field.default_value != null and range.min != 0) {
                @compileError(positional.field.name);
            }
            min_positionals += range.min;
            if (max_positionals) |prev_max_positionals| {
                if (range.max) |max| {
                    max_positionals = prev_max_positionals + max;
                } else {
                    max_positionals = null;
                }
            }

            if (range.variable()) {
                if (variable_i_positional) |j| {
                    @compileError("encountered a second variable value positional \"" ++
                        positional.field.name ++ "\" after the first \"" ++ positionals[j].field.name ++ "\"");
                }

                variable_i_positional = i;
            }
        }

        var help_format: []const u8 = "Usage: {s} [FLAGS...]";

        for (positionals) |positional| {
            var upper_name: [positional.field.name.len]u8 = undefined;
            _ = ascii.upperString(&upper_name, positional.field.name);

            const range = positional.positionalRange();
            if (range.variable()) {
                help_format = help_format ++ " ";
                if (range.min == 0) {
                    help_format = help_format ++ "[";
                }
                help_format = help_format ++ upper_name;
                if (range.max) |max| {
                    if (max > 1) {
                        help_format = help_format ++ "...";
                    }
                } else {
                    help_format = help_format ++ "...";
                }
                if (range.min == 0) {
                    help_format = help_format ++ "]";
                }
            } else {
                help_format = help_format ++ " " ++ upper_name;
            }
        }

        if (options.description) |description| {
            help_format = help_format ++ "\n" ++ description;
        }

        help_format = help_format ++ "\nFlags:\n";

        var name_strings: []const []const u8 = &.{};
        var help_strings: []const ?[]const u8 = &.{};
        for (flags) |flag| {
            const flag_options = flag.options();
            var name_string: []const u8 = "";
            var name_seen = false;

            if (flag_options.short_names) |names| {
                for (names) |name| {
                    if (name_seen) {
                        name_string = name_string ++ ", ";
                    }
                    name_seen = true;
                    name_string = name_string ++ "-" ++ &[_]u8{name};
                }
            }

            if (flag_options.long_names) |names| {
                for (names) |name| {
                    if (name_seen) {
                        name_string = name_string ++ ", ";
                    }
                    name_seen = true;
                    name_string = name_string ++ "--" ++ name;
                    switch (flag.resolveFlagHandler()) {
                        .value => name_string = name_string ++ "=" ++
                            if (flag_options.placeholder) |placeholder| placeholder else "VALUE",
                        .occurrence => {},
                    }
                }
            }

            name_strings = name_strings ++ &[_][]const u8{name_string};
            help_strings = help_strings ++ &[_]?[]const u8{flag_options.help};
        }
        name_strings = name_strings ++ &[_][]const u8{"-h, --help"};
        help_strings = help_strings ++ &[_]?[]const u8{"display this help and exit"};

        var max_name_string_len = 0;
        for (name_strings) |name_string| {
            max_name_string_len = @max(max_name_string_len, name_string.len);
        }

        for (name_strings, help_strings) |name_string, help_string| {
            help_format = help_format ++ "  " ++ name_string;
            if (help_string) |help| {
                for (0..max_name_string_len + 2 - name_string.len) |_| {
                    help_format = help_format ++ " ";
                }
                help_format = help_format ++ help;
            }
            help_format = help_format ++ "\n";
        }

        break :blk .{
            flags,
            positionals,
            min_positionals,
            max_positionals,
            variable_i_positional,
            help_format,
        };
    };

    const binary_name = blk: {
        const dynamic = it.next() orelse {
            bail("failed to determine binary name, no arguments were present\n", .{});
        };
        if (options.binary_name) |static| {
            break :blk static;
        }
        break :blk dynamic;
    };
    var accepting_flags = true;
    var seen = mem.zeroes([flags.len]bool);
    var res: Impl(Spec) = undefined;
    var positional_values = std.ArrayList([:0]const u8).initCapacity(arena, min_positionals + 8) catch {
        bail("out of memory while initializing positionals arraylist\n", .{});
    };
    defer positional_values.deinit();

    while (it.next()) |arg| {
        if (accepting_flags and mem.startsWith(u8, arg, "--")) {
            if (arg.len == 2) {
                accepting_flags = false;
                continue;
            }

            const arg_name, const arg_value = blk: {
                if (mem.indexOf(u8, arg[2..], "=")) |i| {
                    break :blk .{ arg[2 .. i + 2], arg[i + 3 ..] };
                } else {
                    break :blk .{ arg[2..], null };
                }
            };

            // PERF: Use comptime-generated trie to identify flag.
            outer: inline for (0.., flags) |flag_i, flag| {
                if (flag.options().long_names) |long_names| {
                    inline for (long_names) |long_name| {
                        if (mem.eql(u8, arg_name, long_name)) {
                            if (!options.allow_repeats and seen[flag_i]) {
                                bail("flag \"--" ++ long_name ++ "\" specified multiple times\n", .{});
                            }

                            switch (flag.resolveFlagHandler()) {
                                .occurrence => |h| {
                                    if (arg_value != null) {
                                        bail("unexpected value for flag \"--" ++ long_name ++ "\"\n", .{});
                                    }

                                    @field(res, flag.field.name) = h(arena);
                                },
                                .value => |h| {
                                    const value = arg_value orelse blk: {
                                        if (it.next()) |value| {
                                            break :blk value;
                                        }

                                        bail("expected value for flag \"--" ++ long_name ++ "\"\n", .{});
                                    };
                                    @field(res, flag.field.name) = h(value, arena);
                                },
                            }

                            seen[flag_i] = true;
                            break :outer;
                        }
                    }
                }
            } else if (mem.eql(u8, arg_name, "help")) {
                io.getStdOut().writer().print(help_format, .{binary_name}) catch {
                    @panic("stdout write failed");
                };
                process.exit(0);
            } else {
                bail("unknown flag \"--{s}\"\n", .{arg_name});
            }
        } else if (accepting_flags and mem.startsWith(u8, arg, "-") and arg.len >= 2) {
            outer: for (1.., arg[1..]) |arg_i, name| {
                // PERF: Use some sort of switch to identify flag instead of ifs.
                intermediate: inline for (0.., flags) |flag_i, flag| {
                    if (flag.options().short_names) |short_names| {
                        inline for (short_names) |short_name| {
                            if (name == short_name) {
                                if (!options.allow_repeats and seen[flag_i]) {
                                    bail("flag \"-" ++ &[_]u8{short_name} ++ "\" specified multiple times\n", .{});
                                }

                                switch (flag.resolveFlagHandler()) {
                                    .occurrence => |h| @field(res, flag.field.name) = h(arena),
                                    .value => |h| {
                                        if (arg_i != arg.len - 1) {
                                            @field(res, flag.field.name) = h(arg[arg_i + 1 ..], arena);
                                            seen[flag_i] = true;
                                            break :outer;
                                        } else if (it.next()) |value| {
                                            @field(res, flag.field.name) = h(value, arena);
                                        } else {
                                            bail("expected value for flag \"-" ++ &[_]u8{short_name} ++ "\"\n", .{});
                                        }
                                    },
                                }

                                seen[flag_i] = true;
                                break :intermediate;
                            }
                        }
                    }
                } else if (name == 'h') {
                    io.getStdOut().writer().print(help_format, .{binary_name}) catch {
                        @panic("stdout write failed");
                    };
                    process.exit(0);
                } else {
                    bail("unknown flag \"-{c}\"\n", .{name});
                }
            }
        } else {
            positional_values.append(arg) catch {
                bail("out of memory while recording positional\n", .{});
            };
        }
    }

    inline for (0.., flags) |i, flag| {
        if (!seen[i]) {
            if (flag.field.default_value) |default_value| {
                @field(res, flag.field.name) = @as(
                    *const flag.field.type,
                    @ptrCast(@alignCast(default_value)),
                ).*;
            } else {
                const flag_name = comptime blk: {
                    const flag_options = flag.options();
                    if (flag_options.long_names) |long_names| {
                        if (long_names.len > 0) {
                            break :blk "--" ++ long_names[0];
                        }
                    }
                    if (flag_options.short_names) |short_names| {
                        if (short_names.len > 0) {
                            break :blk "-" ++ &[_]u8{short_names[0]};
                        }
                    }

                    @compileError("flag \"" ++ flag.field.name ++ "\" must have at least one name");
                };

                bail("required flag \"" ++ flag_name ++ "\" was not provided\n", .{});
            }
        }
    }

    if (positional_values.items.len < min_positionals) {
        inline for (0.., positionals) |i, positional| {
            const used_positionals = comptime blk: {
                var used_positionals = 0;
                for (0..i + 1) |j| {
                    used_positionals += positionals[j].positionalRange().min;
                }
                break :blk used_positionals;
            };
            if (positional_values.items.len < used_positionals) {
                bail("expected argument for positional \"" ++ positional.field.name ++ "\"\n", .{});
            }
        }
    }

    if (max_positionals) |max| {
        if (positional_values.items.len > max) {
            bail("unexpected positional \"{s}\"\n", .{positional_values.items[max]});
        }
    }

    if (variable_i_positional) |variable_i| {
        inline for (0.., positionals[0..variable_i]) |i, positional| {
            const handler = resolvePositionalHandler(positional.field.type);
            @field(res, positional.field.name) = handler(positional_values.items[i], arena);
        }

        const variable_positional = positionals[variable_i];
        const variable_assigned = positional_values.items.len + variable_positional.positionalRange().min - min_positionals;
        const kind = comptime variable_positional.positionalKind();
        if (kind.slice) {
            if (kind.default and variable_assigned == 0) {
                @field(res, variable_positional.field.name) = @as(
                    *const variable_positional.field.type,
                    @ptrCast(@alignCast(variable_positional.field.default_value.?)),
                ).*;
            } else {
                const child = @typeInfo(variable_positional.field.type).Pointer.child;
                const ptr: []child = arena.alloc(child, variable_assigned) catch {
                    bail("out of memory while handling slice positional\n", .{});
                };
                const handler = resolvePositionalHandler(child);
                for (0..variable_assigned) |i| {
                    ptr[i] = handler(positional_values.items[variable_i + i], arena);
                }
                @field(res, variable_positional.field.name) = ptr;
            }
        } else if (variable_assigned == 0) {
            @field(res, variable_positional.field.name) = @as(
                *const variable_positional.field.type,
                @ptrCast(@alignCast(variable_positional.field.default_value.?)),
            ).*;
        } else {
            const handler = resolvePositionalHandler(variable_positional.field.type);
            @field(res, variable_positional.field.name) = handler(positional_values.items[variable_i], arena);
        }

        inline for (variable_i + variable_assigned.., positionals[variable_i + 1 ..]) |i, positional| {
            const handler = resolvePositionalHandler(positional.field.type);
            @field(res, positional.field.name) = handler(positional_values.items[i], arena);
        }
    } else {
        inline for (0.., positionals) |i, positional| {
            const handler = resolvePositionalHandler(positional.field.type);
            @field(res, positional.field.name) = handler(positional_values.items[i], arena);
        }
    }

    return res;
}

pub fn parse(comptime Spec: type, comptime options: ParseOptions, arena: mem.Allocator) Impl(Spec) {
    var it = process.argsWithAllocator(arena) catch {
        bail("out of memory wile getting arguments");
    };
    defer it.deinit();

    return parseIt(Spec, process.ArgIterator, options, arena, &it);
}

const heap = std.heap;
const recover = @import("recover");

fn expectParseO(comptime Spec: type, comptime options: ParseOptions, cmd_line_utf8: []const u8, expected: Impl(Spec)) !void {
    comptime if (!builtin.is_test) @compileError("expectParse should only be used in tests");

    var arena = heap.ArenaAllocator.init(testing.allocator);
    defer arena.deinit();

    const AIG = process.ArgIteratorGeneral(.{});
    var it = try AIG.init(testing.allocator, cmd_line_utf8);
    defer it.deinit();

    try testing.expectEqualDeep(expected, parseIt(Spec, AIG, options, arena.allocator(), &it));
}

fn expectParse(comptime Spec: type, cmd_line_utf8: []const u8, expected: Impl(Spec)) !void {
    try expectParseO(Spec, .{}, cmd_line_utf8, expected);
}

fn expectParseError(comptime Spec: type, cmd_line_utf8: []const u8, expected_error: []const u8) !void {
    comptime if (!builtin.is_test) @compileError("expectParseError should only be used in tests");

    var arena = heap.ArenaAllocator.init(testing.allocator);
    defer arena.deinit();

    const AIG = process.ArgIteratorGeneral(.{});
    var it = try AIG.init(testing.allocator, cmd_line_utf8);
    defer it.deinit();

    _ = recover.call(struct {
        fn f(arena_: mem.Allocator, it_: *AIG) Impl(Spec) {
            return parseIt(Spec, AIG, .{}, arena_, it_);
        }
    }.f, .{ arena.allocator(), &it }) catch |err| {
        try testing.expect(error.Panic == err);
        if (bail_error_message) |actual_error| {
            defer testing.allocator.free(actual_error);
            try testing.expectEqualStrings(expected_error, actual_error);
            return;
        } else {
            return error.MissingBailErrorMessage;
        }
    };

    return error.ParseUnexpectedlySucceeded;
}

test {
    try expectParse(struct {}, "empty", .{});

    const Hello = struct { name: [:0]const u8 };
    try expectParse(Hello, "hello --name alice", .{ .name = "alice" });
    try expectParse(Hello, "hello --name=alice", .{ .name = "alice" });
    try expectParse(Hello, "hello -n bob", .{ .name = "bob" });
    try expectParse(Hello, "hello -njoe", .{ .name = "joe" });
    try expectParseO(Hello, .{ .allow_repeats = true }, "hello --name alice --name bob", .{ .name = "bob" });
    try expectParseO(Hello, .{ .allow_repeats = true }, "hello -n alice -n joe", .{ .name = "joe" });
    try expectParseError(Hello, "hello --name", "expected value for flag \"--name\"\n");
    try expectParseError(Hello, "hello -n", "expected value for flag \"-n\"\n");
    try expectParseError(Hello, "hello --name alice --name bob", "flag \"--name\" specified multiple times\n");
    try expectParseError(Hello, "hello -n alice -n bob", "flag \"-n\" specified multiple times\n");
    try expectParseError(Hello, "hello --foo", "unknown flag \"--foo\"\n");
    try expectParseError(Hello, "hello -f", "unknown flag \"-f\"\n");
    try expectParseError(Hello, "hello", "required flag \"--name\" was not provided\n");

    const Rm = struct { force: bool = false };
    try expectParse(Rm, "rm -f", .{ .force = true });
    try expectParse(Rm, "rm --force", .{ .force = true });
    try expectParse(Rm, "rm", .{ .force = false });
    try expectParseError(Rm, "rm --force=foo", "unexpected value for flag \"--force\"\n");

    const Rm_ = struct { force1: Flag(bool, .{}) = .{ .default = false } };
    try expectParse(Rm_, "rm", .{ .force1 = false });

    const expected_foo = try testing.allocator.create(i16);
    defer testing.allocator.destroy(expected_foo);
    expected_foo.* = -65;
    const expected_bar = try testing.allocator.create(*const f64);
    defer testing.allocator.destroy(expected_bar);
    expected_bar.* = &654.9165784;
    try expectParse(
        struct { foo: *i16, bar: *const **const f64, _baz: ?[]const u8, quux: ?u8 = null },
        "complex --foo -65 --bar 654.9165784 --_baz hello",
        .{ .foo = expected_foo, .bar = &expected_bar, ._baz = "hello" },
    );

    const Enum = struct { foo: enum { bar, baz } };
    try expectParse(Enum, "enum --foo bar", .{ .foo = .bar });
    try expectParse(Enum, "enum --foo baz", .{ .foo = .baz });
    try expectParseError(Enum, "enum --foo quux", "unknown enum field \"quux\"; expected one of \"bar\", \"baz\"\n");

    const Positional_ = struct { values: Positional([]const []const u8, .{}) };
    try expectParse(
        Positional_,
        "positional foo bar baz",
        .{ .values = &.{ "foo", "bar", "baz" } },
    );

    const Positional__ = struct {
        input: Positional([]const u8, .{}) = .{ .default = "/foo" },
    };
    try expectParse(Positional__, "positional", .{ .input = "/foo" });

    const Large = struct {
        hidden: ?bool = false,
        colour: []const u8,
        magnitude: ?f64 = 12.5,
        input: Positional([]const u8, .{}),
        output: Positional([]const []const u8, .{}) = .{ .default = &.{} },
        name: Positional([]const u8, .{}),
    };
    try expectParse(
        Large,
        "large --colour brown foo.zip foo",
        .{ .colour = "brown", .input = "foo.zip", .output = &.{}, .name = "foo" },
    );
    try expectParse(
        Large,
        "large --colour brown foo.zip --hidden 5315 purple cats --magnitude 981.515 foo",
        .{
            .hidden = true,
            .colour = "brown",
            .magnitude = 981.515,
            .input = "foo.zip",
            .output = &.{ "5315", "purple", "cats" },
            .name = "foo",
        },
    );

    // @compileError tests have to be manually uncommented and checked until the
    // following is addressed: https://github.com/ziglang/zig/issues/513

    // _ = try parse(struct { bar: Flag(bool, .{ .long_names = &.{""} }) }, testing.allocator); // long names cannot be empty

    // _ = try parse(struct { this0: Flag(bool, .{ .long_names = &.{"this"} }), this1: Flag(bool, .{ .long_names = &.{"this"} }) }, testing.allocator); // long name "this" was used more than once

    // _ = try parse(struct { this: bool, that: bool }, testing.allocator); // short name 't' was used more than once

    // _ = try parse(struct { foo: Flag(bool, .{ .long_names = &.{}, .short_names = &.{} }) }, testing.allocator); // flag "foo" must have at least one name

    // _ = try parse( // encountered a second variable value positional "bar" after the first "foo"
    //     struct {
    //         foo: Positional([][]const u8, .{}),
    //         bar: Positional(?f64, .{}),
    //     },
    //     testing.allocator,
    // );
}
