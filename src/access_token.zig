//! JWT access tokens as RFC 9068 profiles them, checked by the resource
//! server they are for (§4): typed `at+jwt`, signed with an algorithm the
//! resource server allows, from its authorization server (`iss` byte for
//! byte), for it (`aud` naming its resource identifier), unexpired, with
//! `sub`, `client_id`, `iat` and `jti` present; `scope` read for the
//! resource server's own scope check. A token bound to a key (`cnf`: DPoP,
//! mTLS) is refused: nothing here proves its binding.
const std = @import("std");
const aegis = @import("aegis");
const strand = @import("strand");
const jws = @import("jws.zig");
const jwt = @import("jwt.zig");
const Algorithm = @import("Algorithm.zig").Algorithm;
const Key = @import("Key.zig");

pub const Expected = struct {
    algorithms: []const Algorithm,
    /// The authorization server's issuer identifier.
    issuer: []const u8,
    /// This resource server's identifier (its RFC 8707 `resource`).
    audience: []const u8,
    leeway: jwt.Duration = .literal("0s"),
    max_bytes: aegis.units.Bytes(usize) = .literal("16KiB"),
    diagnostics: ?*jws.Diagnostics = null,
};

/// The claims RFC 9068 §2.2 adds that a resource server reads.
pub const Claims = struct {
    client_id: []const u8,
    /// Space-separated.
    scope: ?[]const u8 = null,
    auth_time: ?i64 = null,
    acr: ?[]const u8 = null,
};

const WireClaims = struct {
    client_id: ?[]const u8 = null,
    scope: ?[]const u8 = null,
    auth_time: ?strand.json.Raw = null,
    acr: ?[]const u8 = null,
    cnf: ?strand.json.Raw = null,
};

pub fn Verified(comptime Extra: type) type {
    return struct {
        header: jws.Header,
        registered: jwt.Registered,
        access: Claims,
        claims: Extra,
        key: *const Key,
    };
}

pub const VerifyError = jwt.VerifyError || error{
    /// The token is bound to a key (`cnf`), which a bearer check cannot prove.
    BoundToken,
};

/// Verifies an access token, reading the caller's claims into `Extra` (a
/// struct, or `void`). Strings borrow from `scratch` (at least
/// `jws.scratchLength(token.len)` bytes) and the keys.
pub fn verify(comptime Extra: type, token: []const u8, keys: []const Key, expected: Expected, now: std.Io.Timestamp, scratch: []u8) VerifyError!Verified(Extra) {
    var diagnostics: jws.Diagnostics = .{};
    defer if (expected.diagnostics) |d| {
        d.* = diagnostics;
    };
    const verified = try jwt.verify(Extra, token, keys, .{
        .algorithms = expected.algorithms,
        .issuer = expected.issuer,
        .audience = expected.audience,
        .typ = "at+jwt",
        .required = .{ .iss = true, .sub = true, .aud = true, .exp = true, .iat = true, .jti = true },
        .leeway = expected.leeway,
        .max_bytes = expected.max_bytes,
        .diagnostics = &diagnostics,
    }, now, scratch);
    var fixed: std.heap.FixedBufferAllocator = .init(verified.rest);
    const wire = strand.json.parseLeaky(WireClaims, fixed.allocator(), verified.payload, .{
        .ignore_unknown_fields = true,
        .limits = .{ .depth = 32 },
    }) catch {
        diagnostics.check = .claims;
        return error.InvalidClaims;
    };
    if (wire.cnf != null) {
        diagnostics.check = .claims;
        return error.BoundToken;
    }
    var access: Claims = .{
        .client_id = wire.client_id orelse {
            diagnostics.check = .required;
            return error.MissingClaim;
        },
        .scope = wire.scope,
        .acr = wire.acr,
    };
    if (wire.auth_time) |raw| access.auth_time = jwt.numericDate(raw.bytes) catch |err| {
        diagnostics.check = .claims;
        return err;
    };
    return .{ .header = verified.header, .registered = verified.registered, .access = access, .claims = verified.claims, .key = verified.key };
}

/// Whether the space-separated `scope` holds every one of `needed`.
pub fn hasScopes(scope: ?[]const u8, needed: []const []const u8) bool {
    for (needed) |n| {
        var it = std.mem.tokenizeScalar(u8, scope orelse return needed.len == 0, ' ');
        while (it.next()) |s| {
            if (std.mem.eql(u8, s, n)) break;
        } else return false;
    }
    return true;
}

const testing = std.testing;
const secret: [32]u8 = @splat(0x68);
const test_keys = [_]Key{Key.hmac(&secret)};
const test_now: std.Io.Timestamp = .{ .nanoseconds = 1_700_000_000 * std.time.ns_per_s };
const test_expected: Expected = .{ .algorithms = &.{.hs256}, .issuer = "https://as.example", .audience = "https://rs.example/mcp" };

fn check(claims: []const u8, typ: ?[]const u8) anyerror!void {
    var out: std.Io.Writer.Allocating = .init(testing.allocator);
    defer out.deinit();
    jws.sign(testing.allocator, testing.io, &out.writer, .{ .typ = typ }, claims, .{ .hmac = .{ .alg = .hs256, .secret = &secret } }) catch unreachable; // unreachable: signing with a fixed secret
    var scratch: [4096]u8 = undefined;
    const v = try verify(void, out.written(), &test_keys, test_expected, test_now, &scratch);
    try testing.expectEqualStrings("app", v.access.client_id);
    try testing.expect(hasScopes(v.access.scope, &.{"mcp"}));
}

const good = "{\"iss\":\"https://as.example\",\"aud\":\"https://rs.example/mcp\",\"sub\":\"u1\",\"client_id\":\"app\",\"scope\":\"mcp files:read\",\"exp\":1700000600,\"iat\":1699999990,\"jti\":\"j1\"}";

test "RFC 9068 4: an access token passes, typed, for this resource, its claims present" {
    try check(good, "at+jwt");
    try check(good, "application/at+jwt");
    try testing.expectError(error.WrongType, check(good, "JWT"));
    try testing.expectError(error.WrongType, check(good, null));
    try testing.expectError(error.WrongAudience, check("{\"iss\":\"https://as.example\",\"aud\":\"https://rs.example/other\",\"sub\":\"u1\",\"client_id\":\"app\",\"exp\":1700000600,\"iat\":1699999990,\"jti\":\"j1\"}", "at+jwt"));
    try testing.expectError(error.MissingClaim, check("{\"iss\":\"https://as.example\",\"aud\":\"https://rs.example/mcp\",\"sub\":\"u1\",\"exp\":1700000600,\"iat\":1699999990,\"jti\":\"j1\"}", "at+jwt"));
    try testing.expectError(error.MissingClaim, check("{\"iss\":\"https://as.example\",\"aud\":\"https://rs.example/mcp\",\"sub\":\"u1\",\"client_id\":\"app\",\"exp\":1700000600,\"iat\":1699999990}", "at+jwt"));
    try testing.expectError(error.BoundToken, check("{\"iss\":\"https://as.example\",\"aud\":\"https://rs.example/mcp\",\"sub\":\"u1\",\"client_id\":\"app\",\"exp\":1700000600,\"iat\":1699999990,\"jti\":\"j1\",\"cnf\":{\"jkt\":\"x\"}}", "at+jwt"));
}

test "scopes are checked word by word" {
    try testing.expect(hasScopes("mcp files:read", &.{ "files:read", "mcp" }));
    try testing.expect(!hasScopes("mcp files:read", &.{"files:write"}));
    try testing.expect(!hasScopes("mcp files:readx", &.{"files:read"}));
    try testing.expect(!hasScopes(null, &.{"mcp"}));
    try testing.expect(hasScopes(null, &.{}));
}
