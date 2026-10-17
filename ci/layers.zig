//! Source layers, lowest first. Every production source has one place.
const gantry = @import("gantry");

pub const layers: []const gantry.rules.Layer = &.{
    .{ .name = "codecs", .patterns = &.{"src/base64url.zig"} },
    .{ .name = "algorithms", .patterns = &.{"src/Algorithm.zig"} },
    .{ .name = "keys", .patterns = &.{ "src/Key.zig", "src/jwk.zig" } },
    .{ .name = "JWS", .patterns = &.{"src/jws.zig"} },
    .{ .name = "JWT", .patterns = &.{"src/jwt.zig"} },
    .{ .name = "public", .patterns = &.{"src/clearance.zig"} },
    .{ .name = "OAuth messages", .patterns = &.{
        "src/oauth/url.zig",
        "src/oauth/errors.zig",
        "src/oauth/pkce.zig",
        "src/oauth/metadata.zig",
        "src/oauth/authorize.zig",
        "src/oauth/client_auth.zig",
        "src/oauth/token.zig",
        "src/oauth/registration.zig",
        "src/oauth/introspection.zig",
        "src/oauth/challenge.zig",
        "src/oauth/store.zig",
    } },
    .{ .name = "OAuth on HTTP", .patterns = &.{ "src/oauth/http/*.zig", "src/oauth/http.zig" } },
    .{ .name = "OAuth public", .patterns = &.{"src/oauth.zig"} },
};

pub const entries: []const []const u8 = &.{};

pub const modules: []const gantry.NamedModule = &.{
    .{ .name = "clearance", .path = "src/clearance.zig", .from = "src/oauth/**" },
    .{ .name = "clearance", .path = "src/clearance.zig", .from = "src/oauth.zig" },
};

const package_references = [_]gantry.rules.ReferenceRule{
    .{ .name = "named dependencies", .unresolved_only = true, .except_targets = &.{
        "std",
        "builtin",
        "aegis",
        "strand",
        "cloak",
        "uplink.wire",
        "uplink",
        "shakedown",
        "clearance",
        "preflight_bench_options",
    } },
    .{ .name = "source siblings", .suffix = ".zig", .relative = true, .except_targets = &.{"src/**"} },
    // JWT and JOSE fetch no uplink; the OAuth messages are sans I/O, on
    // `uplink.wire` alone: only the HTTP layer and the module's root reach
    // uplink's client.
    .{ .name = "JOSE without uplink", .from = "src/*.zig", .except_from = &.{"src/oauth.zig"}, .unresolved_only = true, .target = "uplink*" },
    .{ .name = "OAuth messages sans I/O", .from = "src/oauth/*.zig", .except_from = &.{"src/oauth/http.zig"}, .unresolved_only = true, .target = "uplink" },
};

pub const references: []const gantry.rules.ReferenceRule = &package_references;
pub const owned: []const gantry.rules.TokenRule = &.{};

pub const required = [_][]const u8{
    "src/clearance.zig",
    "src/jws.zig",
    "src/jwk.zig",
    "src/jwt.zig",
    "src/tests.zig",
    "src/oauth.zig",
};
