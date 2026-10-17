const std = @import("std");

/// What a project that depends on clearance builds: `clearance`, on std,
/// aegis, strand and cloak.
pub fn build(b: *std.Build) void {
    const target = b.standardTargetOptions(.{});
    const optimize = b.standardOptimizeOption(.{});
    _ = b.addModule("clearance", .{
        .root_source_file = b.path("src/clearance.zig"),
        .target = target,
        .optimize = optimize,
        .imports = &.{
            .{ .name = "aegis", .module = b.dependency("aegis", .{ .target = target, .optimize = optimize }).module("aegis") },
            .{ .name = "strand", .module = b.dependency("strand", .{ .target = target, .optimize = optimize }).module("strand") },
            .{ .name = "cloak", .module = b.dependency("cloak", .{ .target = target, .optimize = optimize }).module("cloak") },
        },
    });
}

/// clearance's development: its tests, its properties, the example and the
/// benchmarks, under preflight's gate. Run through bay.
pub fn dev(b: *std.Build, tools: type) void {
    const target = b.standardTargetOptions(.{});
    const optimize = b.standardOptimizeOption(.{});
    const test_filter = b.option([]const u8, "test-filter", "Select tests by name");
    const package = b.dependency("clearance", .{ .target = target, .optimize = optimize });
    const p = package.builder;
    const module = package.module("clearance");
    const aegis = p.dependency("aegis", .{ .target = target, .optimize = optimize });
    const strand = p.dependency("strand", .{ .target = target, .optimize = optimize });
    const cloak = p.dependency("cloak", .{ .target = target, .optimize = optimize });
    const filters: []const []const u8 = if (test_filter) |filter| &.{filter} else &.{};

    const test_step = b.step("test", "Run the tests, the example and each benchmark once");
    const check = b.step("check", "Compile the tests, the example and the benchmarks without running them");

    // The suite alone, in the mode asked for: what ThreadSanitizer runs.
    const tests = suite(b, "clearance-tests", target, optimize, filters);
    const unit = b.step("unit", "Run the test suite alone");
    unit.dependOn(&b.addRunArtifact(tests).step);
    test_step.dependOn(unit);
    check.dependOn(&tests.step);

    // The properties alone, every test of the binary a property: what the
    // fuzzer runs over every parser of untrusted input.
    const properties = suite(b, "clearance-properties", target, optimize, &.{"property_test."});
    const properties_step = b.step("properties", "Run the properties alone");
    properties_step.dependOn(&b.addRunArtifact(properties).step);
    check.dependOn(&properties.step);

    // examples/usage.zig is also README.md's Usage blocks (bay docs --
    // usage), so the code a reader copies is code the tests run.
    const example = b.addExecutable(.{
        .name = "usage",
        .root_module = b.createModule(.{
            .root_source_file = p.path("examples/usage.zig"),
            .target = target,
            .optimize = optimize,
            .imports = &.{.{ .name = "clearance", .module = module }},
        }),
    });
    const examples = b.step("examples", "Build and run the usage example");
    examples.dependOn(&b.addRunArtifact(example).step);
    test_step.dependOn(examples);
    check.dependOn(&example.step);
    b.getInstallStep().dependOn(check);

    tools.preflight.addCi(b, p, .{
        .tests = test_step,
        .portable_tests = true,
        // The release tier fuzzes the properties and runs the suite under
        // ThreadSanitizer.
        .hardened = .{ .fuzz_step = "properties", .tsan_step = "unit" },
        // `bay bench` times them in ReleaseFast, by hand; never timed in CI,
        // where `bay test` runs each row once.
        .bench = .{
            .programs = &.{.{ .name = "clearance-bench", .source = "bench/main.zig" }},
            .imports = benchImports,
            .target = target,
            .optimize = optimize,
        },
    });
    // A project that depends on clearance by path, with only the packages
    // clearance needs: the build a consumer gets.
    tools.preflight.addConsumerCheck(b, p, .{ .package = "clearance", .program = p.path("ci/consumer.zig"), .packages = &.{ aegis, strand, cloak }, .modules = &.{"clearance"} });
}

/// The tests run in the `clearance` module itself, which gets shakedown for
/// them, so a test binary holds one clearance.
fn suite(b: *std.Build, name: []const u8, target: std.Build.ResolvedTarget, optimize: std.lang.Optimize, filters: []const []const u8) *std.Build.Step.Compile {
    const module = b.dependency("clearance", .{ .target = target, .optimize = optimize }).module("clearance");
    if (module.import_table.get("shakedown") == null) {
        module.addImport("shakedown", b.dependency("shakedown", .{ .target = target, .optimize = optimize }).module("shakedown"));
    }
    return b.addTest(.{ .name = name, .filters = filters, .root_module = module });
}

/// clearance again, in the mode a benchmark builds in: an imported module
/// keeps its own mode, so a ReleaseFast benchmark over the Debug module would
/// time the Debug module. `b` is the development build; preflight adds
/// shakedown.
fn benchImports(b: *std.Build, target: std.Build.ResolvedTarget, optimize: std.lang.Optimize) []const std.Build.Module.Import {
    const clearance = b.dependency("clearance", .{ .target = target, .optimize = optimize }).module("clearance");
    return b.allocator.dupe(std.Build.Module.Import, &.{.{ .name = "clearance", .module = clearance }}) catch @panic("OOM");
}
