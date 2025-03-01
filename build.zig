pub fn build(b: *@import("std").Build) void {
    const target = b.standardTargetOptions(.{});

    const optimize = b.standardOptimizeOption(.{});

    const module = b.addModule("structopt", .{
        .root_source_file = b.path("src/root.zig"),
    });

    const lib_unit_tests = b.addTest(.{
        .root_source_file = b.path("src/root.zig"),
        .target = target,
        .optimize = optimize,
    });
    lib_unit_tests.test_runner = b.path("test/test_runner.zig");

    const recover = b.dependency("zig-recover", .{
        .target = target,
        .optimize = optimize,
    });
    lib_unit_tests.root_module.addImport("recover", recover.module("recover"));

    const run_lib_unit_tests = b.addRunArtifact(lib_unit_tests);

    const test_step = b.step("test", "Run unit tests");
    test_step.dependOn(&run_lib_unit_tests.step);

    const example_step = b.step("examples", "Build example programs");
    example_step.dependOn(b.getInstallStep());

    const mkdir_exe = b.addExecutable(.{
        .name = "mkdir",
        .root_source_file = b.path("examples/mkdir.zig"),
        .target = target,
        .optimize = optimize,
    });
    mkdir_exe.root_module.addImport("structopt", module);
    example_step.dependOn(&b.addInstallArtifact(mkdir_exe, .{}).step);

    const touch_exe = b.addExecutable(.{
        .name = "touch",
        .root_source_file = b.path("examples/touch.zig"),
        .target = target,
        .optimize = optimize,
    });
    touch_exe.root_module.addImport("structopt", module);
    example_step.dependOn(&b.addInstallArtifact(touch_exe, .{}).step);
}
