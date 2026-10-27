//! JWT access tokens as RFC 9068 profiles them, checked by the resource
//! server they are for (§4): typed `at+jwt`, signed with an algorithm the
//! resource server allows, from its authorization server (`iss` byte for
//! byte), for it (`aud` naming its resource identifier), unexpired, with
//! `sub`, `client_id`, `iat` and `jti` present; `scope` read for the
//! resource server's own scope check. A token bound to a key (`cnf`, RFC
//! 7800) is accepted only when the caller has proved the binding: a DPoP
//! proof's key (RFC 9449 §6), or the TLS client certificate (RFC 8705 §3);
//! otherwise it is refused.
const std = @import("std");
const aegis = @import("aegis");
const strand = @import("strand");
const jws = @import("jws.zig");
const jwt = @import("jwt.zig");
const Algorithm = @import("Algorithm.zig").Algorithm;
const Key = @import("Key.zig");
const base64url = @import("base64url.zig");

/// What the request proved a token must be bound to.
/// What the request proved; neither set is a bearer request.
pub const Binding = struct {
    /// The RFC 7638 thumbprint of the key a DPoP proof verified with: the
    /// token's `cnf.jkt` must name it, and an unbound token presented with
    /// a proof is refused (RFC 9449 §7.1).
    dpop: ?[32]u8 = null,
    /// The SHA-256 of the TLS client certificate's DER: a token bound by
    /// `cnf`'s `x5t#S256` must name it (RFC 8705 §3). An unbound token over
    /// mutual TLS passes: the certificate may only authenticate the client.
    mtls: ?[32]u8 = null,
};

/// Holds a token's confirmation (its `jkt` and `x5t#S256`, decoded, or
/// `other` for a `cnf` naming neither) to what the request proved: each
/// binding the token has must be proved, and a DPoP proof needs a token
/// bound to its key.
pub fn holds(binding: Binding, jkt: ?[32]u8, x5t_s256: ?[32]u8, other: bool) error{ BoundToken, WrongBinding }!void {
    if (binding.dpop) |t| {
        const named = jkt orelse return error.WrongBinding;
        if (!std.mem.eql(u8, &named, &t)) return error.WrongBinding;
    } else if (jkt != null) return error.BoundToken;
    if (x5t_s256) |named| {
        const h = binding.mtls orelse return error.BoundToken;
        if (!std.mem.eql(u8, &named, &h)) return error.WrongBinding;
    }
    // A confirmation method clearance cannot check binds to something no
    // request here proves.
    if (other) return error.BoundToken;
}

pub const Expected = struct {
    algorithms: []const Algorithm,
    /// The authorization server's issuer identifier.
    issuer: []const u8,
    /// This resource server's identifier (its RFC 8707 `resource`).
    audience: []const u8,
    leeway: jwt.Duration = .literal("0s"),
    /// What the request proved: the token's `cnf` is held to it.
    binding: Binding = .{},
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

const Confirmation = struct {
    jkt: ?[]const u8 = null,
    @"x5t#S256": ?[]const u8 = null,
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
    /// The token is bound (`cnf`) and the request proved no binding: a
    /// bound token sent as a bearer token.
    BoundToken,
    /// The request proved a binding the token does not have: unbound, or
    /// bound to another key or certificate.
    WrongBinding,
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
    checkBinding(fixed.allocator(), wire.cnf, expected.binding) catch |err| {
        diagnostics.check = if (err == error.InvalidClaims) .claims else .binding;
        return err;
    };
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

/// Holds a token's `cnf` to what the request proved.
fn checkBinding(arena: std.mem.Allocator, cnf: ?strand.json.Raw, binding: Binding) error{ BoundToken, WrongBinding, InvalidClaims }!void {
    const raw = cnf orelse return holds(binding, null, null, false);
    const c = raw.parse(Confirmation, arena, .{ .ignore_unknown_fields = true }) catch return error.InvalidClaims;
    const jkt = hash(c.jkt);
    const x5t = hash(c.@"x5t#S256");
    // A member that is no SHA-256 binds the token to nothing a request can
    // prove, as a confirmation method clearance cannot check does.
    const unreadable = (c.jkt != null and jkt == null) or (c.@"x5t#S256" != null and x5t == null);
    return holds(binding, jkt, x5t, unreadable or (c.jkt == null and c.@"x5t#S256" == null));
}

/// A confirmation member's SHA-256, decoded: null when it is absent or is
/// not one.
fn hash(member: ?[]const u8) ?[32]u8 {
    const text = member orelse return null;
    var decoded: [32]u8 = undefined;
    const bytes = base64url.decode(&decoded, text) catch return null;
    if (bytes.len != 32) return null;
    return decoded;
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

fn checkBound(claims: []const u8, binding: Binding) anyerror!void {
    var out: std.Io.Writer.Allocating = .init(testing.allocator);
    defer out.deinit();
    jws.sign(testing.allocator, testing.io, &out.writer, .{ .typ = "at+jwt" }, claims, .{ .hmac = .{ .alg = .hs256, .secret = &secret } }) catch unreachable; // unreachable: signing with a fixed secret
    var scratch: [4096]u8 = undefined;
    var expected = test_expected;
    expected.binding = binding;
    _ = try verify(void, out.written(), &test_keys, expected, test_now, &scratch);
}

test "a bound token passes only with the binding the request proved" {
    const gpa = testing.allocator;
    // RFC 9449 §6.1's example thumbprint; a certificate's hash.
    const jkt = "0ZcOCORZNYy-DWpqq30jZyJGHTN0d2HglBV3uiguA4I";
    var thumbprint: [32]u8 = undefined;
    _ = try base64url.decode(&thumbprint, jkt);
    const certificate_hash: [32]u8 = @splat(0xab);
    var x5t: std.Io.Writer.Allocating = .init(gpa);
    defer x5t.deinit();
    try base64url.encode(&x5t.writer, &certificate_hash);
    const head = "{\"iss\":\"https://as.example\",\"aud\":\"https://rs.example/mcp\",\"sub\":\"u1\",\"client_id\":\"app\",\"exp\":1700000600,\"iat\":1699999990,\"jti\":\"j1\"";
    const dpop_bound = head ++ ",\"cnf\":{\"jkt\":\"" ++ jkt ++ "\"}}";
    const mtls_bound = try std.mem.concat(gpa, u8, &.{ head, ",\"cnf\":{\"x5t#S256\":\"", x5t.written(), "\"}}" });
    defer gpa.free(mtls_bound);
    try checkBound(dpop_bound, .{ .dpop = thumbprint });
    try checkBound(mtls_bound, .{ .mtls = certificate_hash });
    // A DPoP proof over mutual TLS, for either token.
    try checkBound(dpop_bound, .{ .dpop = thumbprint, .mtls = certificate_hash });
    // An unbound token over mutual TLS: the certificate authenticates the
    // client only (RFC 8705 §3 binds only what `cnf` names).
    try checkBound(head ++ "}", .{ .mtls = certificate_hash });
    // Sent as a bearer token, bound elsewhere, or not bound at all.
    try testing.expectError(error.BoundToken, checkBound(dpop_bound, .{}));
    try testing.expectError(error.BoundToken, checkBound(mtls_bound, .{}));
    try testing.expectError(error.WrongBinding, checkBound(dpop_bound, .{ .dpop = certificate_hash }));
    try testing.expectError(error.BoundToken, checkBound(dpop_bound, .{ .mtls = thumbprint }));
    try testing.expectError(error.WrongBinding, checkBound(mtls_bound, .{ .mtls = thumbprint }));
    try testing.expectError(error.WrongBinding, checkBound(mtls_bound, .{ .dpop = thumbprint }));
    // A DPoP proof with an unbound token (RFC 9449 §7.1), and a `cnf` of a
    // method clearance cannot check.
    try testing.expectError(error.WrongBinding, checkBound(head ++ "}", .{ .dpop = thumbprint }));
    try testing.expectError(error.BoundToken, checkBound(head ++ ",\"cnf\":{\"jwk\":{}}}", .{ .mtls = certificate_hash }));
    try testing.expectError(error.InvalidClaims, checkBound(head ++ ",\"cnf\":7}", .{ .dpop = thumbprint }));
}

test "scopes are checked word by word" {
    try testing.expect(hasScopes("mcp files:read", &.{ "files:read", "mcp" }));
    try testing.expect(!hasScopes("mcp files:read", &.{"files:write"}));
    try testing.expect(!hasScopes("mcp files:readx", &.{"files:read"}));
    try testing.expect(!hasScopes(null, &.{"mcp"}));
    try testing.expect(hasScopes(null, &.{}));
}
