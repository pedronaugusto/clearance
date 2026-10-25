//! OpenID Connect ID tokens checked as OpenID Connect Core §3.1.3.7 asks: the
//! signature with the caller's keys and algorithms; `iss` the issuer byte for
//! byte; `aud` the client, and any other audience one the client trusts, with
//! `azp` the client when present and required beside several audiences;
//! `exp`, `iat` and `sub` present; `nonce` the one the request sent; with
//! `max_age`, `auth_time` within it; `at_hash` the access token's when both
//! are given (§3.2.2.9). A token typed as anything but a JWT (an `at+jwt`
//! access token) is refused: one kind of token never passes for another
//! (RFC 8725 §3.11).
const std = @import("std");
const aegis = @import("aegis");
const strand = @import("strand");
const jws = @import("jws.zig");
const jwt = @import("jwt.zig");
const base64url = @import("base64url.zig");
const Algorithm = @import("Algorithm.zig").Algorithm;
const Key = @import("Key.zig");

pub const Duration = jwt.Duration;

/// What the client asked for and expects back.
pub const Expected = struct {
    /// The algorithms the client accepts: the provider's
    /// `id_token_signing_alg_values_supported` among clearance's, or the one
    /// the client registered. No default.
    algorithms: []const Algorithm,
    /// The issuer, as discovered.
    issuer: []const u8,
    /// The client's `client_id`: an audience the token must name.
    client_id: []const u8,
    /// Audiences beside the client's that the client trusts. Any other
    /// refuses the token.
    trusted_audiences: []const []const u8 = &.{},
    /// The `nonce` the authorization request sent: the token must carry it.
    nonce: ?[]const u8 = null,
    /// The `max_age` the request sent: `auth_time` must be within it.
    max_age: ?Duration = null,
    /// The access token issued beside the ID token: its `at_hash` checked
    /// when the token has one.
    access_token: ?[]const u8 = null,
    leeway: Duration = .literal("0s"),
    max_bytes: aegis.units.Bytes(usize) = .literal("16KiB"),
    /// Set when the client registered `id_token_encrypted_response_alg`:
    /// the token must be a nested JWT these keys decrypt (Core §10.2), and a
    /// signed token alone is refused.
    decryption: ?jwt.Decryption = null,
    diagnostics: ?*jws.Diagnostics = null,
};

/// The claims OpenID Connect adds that the checks read.
pub const Claims = struct {
    nonce: ?[]const u8 = null,
    azp: ?[]const u8 = null,
    auth_time: ?i64 = null,
    at_hash: ?[]const u8 = null,
    acr: ?[]const u8 = null,
};

const WireClaims = struct {
    nonce: ?[]const u8 = null,
    azp: ?[]const u8 = null,
    auth_time: ?strand.json.Raw = null,
    at_hash: ?[]const u8 = null,
    acr: ?[]const u8 = null,
};

pub fn Verified(comptime Extra: type) type {
    return struct {
        header: jws.Header,
        registered: jwt.Registered,
        /// The OpenID Connect claims the checks read.
        id: Claims,
        /// The claims as the caller's type (`email`, `name`...); `void` reads
        /// none.
        claims: Extra,
        key: *const Key,
    };
}

pub const VerifyError = jwt.VerifyError || error{
    /// `azp` is not the client, or several audiences and no `azp`.
    WrongParty,
    /// The `nonce` is absent or another than the request's.
    WrongNonce,
    /// `max_age` was asked and `auth_time` is absent or older.
    AuthenticationTooOld,
    /// `at_hash` is not the access token's.
    WrongAccessTokenHash,
};

/// Verifies an ID token, reading the caller's claims into `Extra` (a struct,
/// or `void`). Strings borrow from `scratch` (at least
/// `jws.scratchLength(token.len)` bytes, `jwe.scratchLength(token.len)` with
/// `decryption`) and the keys.
pub fn verify(comptime Extra: type, token: []const u8, keys: []const Key, expected: Expected, now: std.Io.Timestamp, scratch: []u8) VerifyError!Verified(Extra) {
    var diagnostics: jws.Diagnostics = .{};
    defer if (expected.diagnostics) |d| {
        d.* = diagnostics;
    };
    const verified = try jwt.verify(Extra, token, keys, .{
        .algorithms = expected.algorithms,
        .issuer = expected.issuer,
        .audience = expected.client_id,
        .required = .{ .iss = true, .sub = true, .aud = true, .exp = true, .iat = true },
        .leeway = expected.leeway,
        .max_bytes = expected.max_bytes,
        .decryption = expected.decryption,
        .diagnostics = &diagnostics,
    }, now, scratch);
    return check(Extra, verified, expected, now) catch |err| {
        diagnostics.check = switch (err) {
            error.WrongType => .type,
            error.WrongAudience => .audience,
            error.InvalidClaims => .claims,
            error.TooOld => .too_old,
            else => .claims,
        };
        return err;
    };
}

fn check(comptime Extra: type, verified: jwt.Verified(Extra), expected: Expected, now: std.Io.Timestamp) VerifyError!Verified(Extra) {
    if (verified.header.typ) |typ| if (!jwt.mediaTypeIs(typ, "JWT")) return error.WrongType;
    const seconds: i64 = @intCast(@divFloor(now.nanoseconds, std.time.ns_per_s));
    const leeway: i64 = expected.leeway.raw();
    // `iat` in the future is a token not yet made.
    if (verified.registered.iat.? > seconds +| leeway) return error.TooOld;

    var fixed: std.heap.FixedBufferAllocator = .init(verified.rest);
    const wire = strand.json.parseLeaky(WireClaims, fixed.allocator(), verified.payload, .{
        .ignore_unknown_fields = true,
        .limits = .{ .depth = 32 },
    }) catch return error.InvalidClaims;
    var id: Claims = .{ .nonce = wire.nonce, .azp = wire.azp, .at_hash = wire.at_hash, .acr = wire.acr };
    if (wire.auth_time) |raw| id.auth_time = try jwt.numericDate(raw.bytes);

    const audiences = verified.registered.aud.values;
    for (audiences) |a| {
        if (std.mem.eql(u8, a, expected.client_id)) continue;
        for (expected.trusted_audiences) |t| {
            if (std.mem.eql(u8, a, t)) break;
        } else return error.WrongAudience;
    }
    if (id.azp) |azp| {
        if (!std.mem.eql(u8, azp, expected.client_id)) return error.WrongParty;
    } else if (audiences.len > 1) return error.WrongParty;

    if (expected.nonce) |nonce| {
        const got = id.nonce orelse return error.WrongNonce;
        const same = aegis.secret.equalBytes(got, nonce) catch return error.WrongNonce;
        if (!same.declassify("a refused nonce ends the check")) return error.WrongNonce;
    }
    if (expected.max_age) |max_age| {
        const auth_time = id.auth_time orelse return error.AuthenticationTooOld;
        if (seconds -| auth_time > @as(i64, max_age.raw()) +| leeway) return error.AuthenticationTooOld;
    }
    if (expected.access_token) |access_token| if (id.at_hash) |at_hash| {
        var buffer: [43]u8 = undefined;
        const want = accessTokenHash(verified.header.alg, access_token, &buffer);
        const same = aegis.secret.equalBytes(at_hash, want) catch return error.WrongAccessTokenHash;
        if (!same.declassify("a refused hash ends the check")) return error.WrongAccessTokenHash;
    };
    return .{ .header = verified.header, .registered = verified.registered, .id = id, .claims = verified.claims, .key = verified.key };
}

/// The `at_hash` (or `c_hash`) of `value` under `alg`: the left half of its
/// hash by the algorithm's hash function (SHA-512 for EdDSA with Ed25519),
/// in base64url.
pub fn accessTokenHash(alg: Algorithm, value: []const u8, out: *[43]u8) []const u8 {
    var digest: [64]u8 = undefined;
    const half: usize = switch (alg.hash() orelse .sha512) {
        .sha256 => blk: {
            std.crypto.hash.sha2.Sha256.hash(value, digest[0..32], .{});
            break :blk 16;
        },
        .sha384 => blk: {
            std.crypto.hash.sha2.Sha384.hash(value, digest[0..48], .{});
            break :blk 24;
        },
        .sha512 => blk: {
            std.crypto.hash.sha2.Sha512.hash(value, digest[0..64], .{});
            break :blk 32;
        },
    };
    var w: std.Io.Writer = .fixed(out);
    // unreachable: at most 32 bytes encode to at most 43 characters
    base64url.encode(&w, digest[0..half]) catch unreachable;
    return w.buffered();
}

const testing = std.testing;
const secret: [32]u8 = @splat(0x24);
const test_keys = [_]Key{Key.hmac(&secret)};
const test_now: std.Io.Timestamp = .{ .nanoseconds = 1_700_000_000 * std.time.ns_per_s };
const test_expected: Expected = .{ .algorithms = &.{.hs256}, .issuer = "https://op.example", .client_id = "app", .nonce = "n-0S6_WzA2Mj" };

fn idToken(out: *std.Io.Writer.Allocating, claims: []const u8, typ: ?[]const u8) !void {
    out.clearRetainingCapacity();
    try jws.sign(testing.allocator, testing.io, &out.writer, .{ .typ = typ }, claims, .{ .hmac = .{ .alg = .hs256, .secret = &secret } });
}

fn expectRefused(err: anyerror, claims: []const u8, typ: ?[]const u8, e: Expected) !void {
    var out: std.Io.Writer.Allocating = .init(testing.allocator);
    defer out.deinit();
    try idToken(&out, claims, typ);
    var scratch: [4096]u8 = undefined;
    try testing.expectError(err, verify(void, out.written(), &test_keys, e, test_now, &scratch));
}

const good = "{\"iss\":\"https://op.example\",\"sub\":\"248289761001\",\"aud\":\"app\",\"nonce\":\"n-0S6_WzA2Mj\",\"exp\":1700000600,\"iat\":1699999990,\"auth_time\":1699999000,\"email\":\"j@example.com\"}";

test "an ID token passes each check of OpenID Connect Core 3.1.3.7, its claims read" {
    var out: std.Io.Writer.Allocating = .init(testing.allocator);
    defer out.deinit();
    try idToken(&out, good, null);
    var scratch: [4096]u8 = undefined;
    const v = try verify(struct { email: []const u8 }, out.written(), &test_keys, test_expected, test_now, &scratch);
    try testing.expectEqualStrings("248289761001", v.registered.sub.?);
    try testing.expectEqualStrings("j@example.com", v.claims.email);
    try testing.expectEqual(@as(?i64, 1699999000), v.id.auth_time);
    try idToken(&out, good, "JWT");
    _ = try verify(void, out.written(), &test_keys, test_expected, test_now, &scratch);
}

test "each check refuses: issuer, audience, party, nonce, times, type" {
    try expectRefused(error.WrongIssuer, "{\"iss\":\"https://op.example/\",\"sub\":\"s\",\"aud\":\"app\",\"nonce\":\"n-0S6_WzA2Mj\",\"exp\":1700000600,\"iat\":1699999990}", null, test_expected);
    try expectRefused(error.WrongAudience, "{\"iss\":\"https://op.example\",\"sub\":\"s\",\"aud\":\"other\",\"nonce\":\"n-0S6_WzA2Mj\",\"exp\":1700000600,\"iat\":1699999990}", null, test_expected);
    // Another audience beside the client's, untrusted.
    try expectRefused(error.WrongAudience, "{\"iss\":\"https://op.example\",\"sub\":\"s\",\"aud\":[\"app\",\"evil\"],\"azp\":\"app\",\"nonce\":\"n-0S6_WzA2Mj\",\"exp\":1700000600,\"iat\":1699999990}", null, test_expected);
    // Several trusted audiences, and no `azp` to say which party.
    var trusting = test_expected;
    trusting.trusted_audiences = &.{"api"};
    try expectRefused(error.WrongParty, "{\"iss\":\"https://op.example\",\"sub\":\"s\",\"aud\":[\"app\",\"api\"],\"nonce\":\"n-0S6_WzA2Mj\",\"exp\":1700000600,\"iat\":1699999990}", null, trusting);
    try expectRefused(error.WrongParty, "{\"iss\":\"https://op.example\",\"sub\":\"s\",\"aud\":\"app\",\"azp\":\"other\",\"nonce\":\"n-0S6_WzA2Mj\",\"exp\":1700000600,\"iat\":1699999990}", null, test_expected);
    try expectRefused(error.WrongNonce, "{\"iss\":\"https://op.example\",\"sub\":\"s\",\"aud\":\"app\",\"exp\":1700000600,\"iat\":1699999990}", null, test_expected);
    try expectRefused(error.WrongNonce, "{\"iss\":\"https://op.example\",\"sub\":\"s\",\"aud\":\"app\",\"nonce\":\"n-0S6_WzA2Mk\",\"exp\":1700000600,\"iat\":1699999990}", null, test_expected);
    try expectRefused(error.MissingClaim, "{\"iss\":\"https://op.example\",\"aud\":\"app\",\"nonce\":\"n-0S6_WzA2Mj\",\"exp\":1700000600,\"iat\":1699999990}", null, test_expected);
    try expectRefused(error.MissingClaim, "{\"iss\":\"https://op.example\",\"sub\":\"s\",\"aud\":\"app\",\"nonce\":\"n-0S6_WzA2Mj\",\"exp\":1700000600}", null, test_expected);
    try expectRefused(error.Expired, "{\"iss\":\"https://op.example\",\"sub\":\"s\",\"aud\":\"app\",\"nonce\":\"n-0S6_WzA2Mj\",\"exp\":1700000000,\"iat\":1699999990}", null, test_expected);
    try expectRefused(error.TooOld, "{\"iss\":\"https://op.example\",\"sub\":\"s\",\"aud\":\"app\",\"nonce\":\"n-0S6_WzA2Mj\",\"exp\":1700000600,\"iat\":1700000100}", null, test_expected);
    try expectRefused(error.InvalidClaims, "{\"iss\":\"https://op.example\",\"sub\":\"s\",\"aud\":\"app\",\"nonce\":\"n-0S6_WzA2Mj\",\"exp\":1700000600,\"iat\":1699999990,\"auth_time\":\"1\"}", null, test_expected);
    // An access token is not an ID token.
    try expectRefused(error.WrongType, good, "at+jwt", test_expected);
    var aged = test_expected;
    aged.max_age = .literal("600s");
    try expectRefused(error.AuthenticationTooOld, good, null, aged);
    try expectRefused(error.AuthenticationTooOld, "{\"iss\":\"https://op.example\",\"sub\":\"s\",\"aud\":\"app\",\"nonce\":\"n-0S6_WzA2Mj\",\"exp\":1700000600,\"iat\":1699999990}", null, aged);
}

test "at_hash: OpenID Connect Core A.3's value, checked when given" {
    // Core A.3's access token and its at_hash under RS256 (SHA-256).
    var buffer: [43]u8 = undefined;
    try testing.expectEqualStrings("77QmUPtjPfzWtF2AnpK9RQ", accessTokenHash(.rs256, "jHkWEdUXMU1BwAsC4vtUsZwnNvTIxEl0z9K3vx5KF0Y", &buffer));
    var with_hash = test_expected;
    with_hash.access_token = "jHkWEdUXMU1BwAsC4vtUsZwnNvTIxEl0z9K3vx5KF0Y";
    try expectRefused(error.WrongAccessTokenHash, "{\"iss\":\"https://op.example\",\"sub\":\"s\",\"aud\":\"app\",\"nonce\":\"n-0S6_WzA2Mj\",\"exp\":1700000600,\"iat\":1699999990,\"at_hash\":\"x\"}", null, with_hash);
    var out: std.Io.Writer.Allocating = .init(testing.allocator);
    defer out.deinit();
    try idToken(&out, "{\"iss\":\"https://op.example\",\"sub\":\"s\",\"aud\":\"app\",\"nonce\":\"n-0S6_WzA2Mj\",\"exp\":1700000600,\"iat\":1699999990,\"at_hash\":\"77QmUPtjPfzWtF2AnpK9RQ\"}", null);
    var scratch: [4096]u8 = undefined;
    _ = try verify(void, out.written(), &test_keys, with_hash, test_now, &scratch);
}

test "an encrypted ID token (Core §10.2) is decrypted, then verified; a signed one alone is refused" {
    const jwe = @import("jwe.zig");
    var signed: std.Io.Writer.Allocating = .init(testing.allocator);
    defer signed.deinit();
    try idToken(&signed, good, "JWT");
    const kek: [16]u8 = @splat(0x4b);
    var expected = test_expected;
    expected.decryption = .{
        .io = testing.io,
        .keys = &.{.{ .material = .{ .secret = &kek } }},
        .options = .{ .key_algorithms = &.{.a128kw}, .encryptions = &.{.a128cbc_hs256} },
    };
    var scratch: [16384]u8 = undefined;
    // `cty` `JWT`, as RFC 7519 §5.2 asks, or none, as many providers send.
    for ([_]?[]const u8{ "JWT", null }) |cty| {
        var nested: std.Io.Writer.Allocating = .init(testing.allocator);
        defer nested.deinit();
        try jwe.encrypt(testing.allocator, testing.io, &nested.writer, .{ .enc = .a128cbc_hs256, .cty = cty }, signed.written(), &.{.{ .alg = .a128kw, .key = .{ .key = Key.hmac(&kek) } }}, .compact, .{});
        const v = try verify(struct { email: []const u8 }, nested.written(), &test_keys, expected, test_now, &scratch);
        try testing.expectEqualStrings("j@example.com", v.claims.email);
    }
    // A signed token alone, when encryption was registered.
    try testing.expectError(error.NotEncrypted, verify(void, signed.written(), &test_keys, expected, test_now, &scratch));
    // Content of another type.
    var other: std.Io.Writer.Allocating = .init(testing.allocator);
    defer other.deinit();
    try jwe.encrypt(testing.allocator, testing.io, &other.writer, .{ .enc = .a128cbc_hs256, .cty = "json" }, signed.written(), &.{.{ .alg = .a128kw, .key = .{ .key = Key.hmac(&kek) } }}, .compact, .{});
    try testing.expectError(error.WrongType, verify(void, other.written(), &test_keys, expected, test_now, &scratch));
    // Encrypted content that is no signed JWT (a bare claims set) is refused
    // as a malformed JWS: anyone holding the client's public key can encrypt
    // to it, so the signature is what names the issuer.
    var bare: std.Io.Writer.Allocating = .init(testing.allocator);
    defer bare.deinit();
    try jwe.encrypt(testing.allocator, testing.io, &bare.writer, .{ .enc = .a128cbc_hs256 }, good, &.{.{ .alg = .a128kw, .key = .{ .key = Key.hmac(&kek) } }}, .compact, .{});
    try testing.expectError(error.Malformed, verify(void, bare.written(), &test_keys, expected, test_now, &scratch));
    // Under another key, or an algorithm off the allowlist.
    const wrong: [16]u8 = @splat(0x11);
    var wrong_key = expected;
    wrong_key.decryption.?.keys = &.{.{ .material = .{ .secret = &wrong } }};
    try testing.expectError(error.DecryptionFailed, verify(void, other.written(), &test_keys, wrong_key, test_now, &scratch));
    var narrow = expected;
    narrow.decryption.?.options.encryptions = &.{.a256gcm};
    try testing.expectError(error.AlgorithmNotAllowed, verify(void, other.written(), &test_keys, narrow, test_now, &scratch));
    // Without `decryption`, an encrypted token is no signed one.
    try testing.expectError(error.Malformed, verify(void, other.written(), &test_keys, test_expected, test_now, &scratch));
}
