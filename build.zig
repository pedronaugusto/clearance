const std = @import("std");

/// What a project that depends on clearance builds: `clearance`, JWT and
/// JOSE, on std, aegis, strand and cloak alone; with `oauth` set,
/// `clearance.oauth`, OAuth 2.1 on uplink, which is fetched only then: a
/// project that verifies and signs tokens fetches no uplink.
pub fn build(b: *std.Build) void {
    const target = b.standardTargetOptions(.{});
    const optimize = b.standardOptimizeOption(.{});
    const with_oauth = b.option(bool, "oauth", "Build clearance.oauth, OAuth 2.1 on uplink, which fetches uplink") orelse false;
    const aegis = b.dependency("aegis", .{ .target = target, .optimize = optimize }).module("aegis");
    const strand = b.dependency("strand", .{ .target = target, .optimize = optimize }).module("strand");
    const cloak = b.dependency("cloak", .{ .target = target, .optimize = optimize }).module("cloak");
    const clearance = b.addModule("clearance", .{
        .root_source_file = b.path("src/clearance.zig"),
        .target = target,
        .optimize = optimize,
        .imports = &.{
            .{ .name = "aegis", .module = aegis },
            .{ .name = "strand", .module = strand },
            .{ .name = "cloak", .module = cloak },
        },
    });
    if (!with_oauth) return;
    // Declared before uplink is fetched: a consumer's first pass must find
    // the module it asks for, and only learns here what to fetch.
    const oauth = b.addModule("clearance.oauth", .{
        .root_source_file = b.path("src/oauth.zig"),
        .target = target,
        .optimize = optimize,
        .imports = &.{
            .{ .name = "aegis", .module = aegis },
            .{ .name = "strand", .module = strand },
            .{ .name = "cloak", .module = cloak },
            .{ .name = "clearance", .module = clearance },
        },
    });
    if (b.dependencyLazy("uplink", .{ .target = target, .optimize = optimize })) |uplink| {
        oauth.addImport("uplink.wire", uplink.module("uplink.wire"));
        oauth.addImport("uplink", uplink.module("uplink"));
    } else |_| {}
}

/// clearance's development: its tests, its properties, the example and the
/// benchmarks, under preflight's gate. Run through bay.
pub fn dev(b: *std.Build, tools: type) void {
    const target = b.standardTargetOptions(.{});
    const optimize = b.standardOptimizeOption(.{});
    const test_filter = b.option([]const u8, "test-filter", "Select tests by name");
    const package = b.dependency("clearance", .{ .target = target, .optimize = optimize, .oauth = true });
    const p = package.builder;
    const module = package.module("clearance");
    const aegis = p.dependency("aegis", .{ .target = target, .optimize = optimize });
    const strand = p.dependency("strand", .{ .target = target, .optimize = optimize });
    const cloak = p.dependency("cloak", .{ .target = target, .optimize = optimize });
    const filters: []const []const u8 = if (test_filter) |filter| &.{filter} else &.{};

    const test_step = b.step("test", "Run the tests, the example and each benchmark once");
    const check = b.step("check", "Compile the tests, the example and the benchmarks without running them");

    // The suite alone, in the mode asked for: what ThreadSanitizer runs.
    // clearance.oauth's tests are a binary of their own, rooted in that
    // module, after uplink is fetched.
    const tests = suite(b, "clearance-tests", "clearance", target, optimize, filters);
    const unit = b.step("unit", "Run the test suite alone");
    const tests_run = b.addRunArtifact(tests);
    unit.dependOn(&tests_run.step);
    test_step.dependOn(unit);
    check.dependOn(&tests.step);
    const properties = suite(b, "clearance-properties", "clearance", target, optimize, &.{"property_test."});
    const properties_step = b.step("properties", "Run the properties alone");
    properties_step.dependOn(&b.addRunArtifact(properties).step);
    check.dependOn(&properties.step);
    const uplink_package = p.dependencyLazy("uplink", .{ .target = target, .optimize = optimize }) catch return;
    const oauth_tests = suite(b, "clearance-oauth-tests", "clearance.oauth", target, optimize, filters);
    const oauth_run = b.addRunArtifact(oauth_tests);
    oauth_run.step.dependOn(&tests_run.step);
    unit.dependOn(&oauth_run.step);
    check.dependOn(&oauth_tests.step);

    // The properties alone, every test of the binary a property: what the
    // fuzzer runs over every parser of untrusted input.
    const oauth_properties = suite(b, "clearance-oauth-properties", "clearance.oauth", target, optimize, &.{"property_test."});
    properties_step.dependOn(&b.addRunArtifact(oauth_properties).step);
    check.dependOn(&oauth_properties.step);

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

    // An issuer discovered and its keys fetched, against live providers by
    // hand: `bay dev discover -- https://accounts.google.com`. CI compiles it.
    const discover = b.addExecutable(.{
        .name = "discover",
        .root_module = b.createModule(.{
            .root_source_file = p.path("examples/discover.zig"),
            .target = target,
            .optimize = optimize,
            .imports = &.{
                .{ .name = "clearance.oauth", .module = package.module("clearance.oauth") },
                .{ .name = "uplink", .module = uplink_package.module("uplink") },
            },
        }),
    });
    const discover_run = b.addRunArtifact(discover);
    discover_run.addPassthruArgs();
    b.step("discover", "Discover issuers and fetch their keys: -- <issuer>...").dependOn(&discover_run.step);
    check.dependOn(&discover.step);

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
    // A project that depends on clearance by path for JWT alone, with only
    // aegis, strand and cloak to fetch: what a JWT user gets, no uplink.
    tools.preflight.addConsumerCheck(b, p, .{ .package = "clearance", .program = p.path("ci/consumer.zig"), .packages = &.{ aegis, strand, cloak }, .modules = &.{"clearance"} });
}

/// The tests run in the module itself (`clearance` or `clearance.oauth`),
/// which gets shakedown for them, so a test binary holds one clearance.
fn suite(b: *std.Build, name: []const u8, root: []const u8, target: std.Build.ResolvedTarget, optimize: std.lang.Optimize, filters: []const []const u8) *std.Build.Step.Compile {
    const module = b.dependency("clearance", .{ .target = target, .optimize = optimize, .oauth = true }).module(root);
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
    const package = b.dependency("clearance", .{ .target = target, .optimize = optimize, .oauth = true });
    return b.allocator.dupe(std.Build.Module.Import, &.{
        .{ .name = "clearance", .module = package.module("clearance") },
        .{ .name = "clearance.oauth", .module = package.module("clearance.oauth") },
    }) catch @panic("OOM");
}
