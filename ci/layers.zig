//! Source layers, lowest first. Every production source has one place.
const gantry = @import("gantry");

pub const layers: []const gantry.rules.Layer = &.{
    .{ .name = "codecs", .patterns = &.{"src/base64url.zig"} },
    .{ .name = "algorithms", .patterns = &.{"src/Algorithm.zig"} },
    .{ .name = "keys", .patterns = &.{ "src/Key.zig", "src/jwk.zig" } },
    .{ .name = "JWS", .patterns = &.{"src/jws.zig"} },
    .{ .name = "JWT", .patterns = &.{"src/jwt.zig"} },
    .{ .name = "OAuth messages", .patterns = &.{ "src/oauth/*.zig", "src/oauth.zig" } },
    .{ .name = "public", .patterns = &.{"src/clearance.zig"} },
};

pub const entries: []const []const u8 = &.{};

pub const modules: []const gantry.NamedModule = &.{};

const package_references = [_]gantry.rules.ReferenceRule{
    .{ .name = "named dependencies", .unresolved_only = true, .except_targets = &.{
        "std",
        "builtin",
        "aegis",
        "strand",
        "cloak",
        "uplink.wire",
        "shakedown",
        "clearance",
        "preflight_bench_options",
    } },
    .{ .name = "source siblings", .suffix = ".zig", .relative = true, .except_targets = &.{"src/**"} },
};

pub const references: []const gantry.rules.ReferenceRule = &package_references;
pub const owned: []const gantry.rules.TokenRule = &.{};

pub const required = [_][]const u8{
    "src/clearance.zig",
    "src/jws.zig",
    "src/jwk.zig",
    "src/jwt.zig",
    "src/tests.zig",
};
