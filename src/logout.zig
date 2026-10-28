//! Logout tokens (OpenID Connect Back-Channel Logout 1.0 §2.4): the JWT an
//! OpenID provider POSTs to a relying party to end a user's session there,
//! verified as §2.6 asks. It names the session (`sid`), the user (`sub`) or
//! both, carries the back-channel event, and never a `nonce`, so that no ID
//! token can pass for one; its `jti` is recorded so it is used once.
const std = @import("std");
const time = @import("time.zig");
const aegis = @import("aegis");
const strand = @import("strand");
const jws = @import("jws.zig");
const jwt = @import("jwt.zig");
const Algorithm = @import("Algorithm.zig").Algorithm;
const Key = @import("Key.zig");

/// The type a logout token is explicitly typed with (§2.4).
pub const media_type = "logout+jwt";

/// The member of `events` that makes a JWT a logout token (§2.4).
pub const event = "http://schemas.openid.net/event/backchannel-logout";

pub const Expected = struct {
    /// The provider's algorithms: at least one, no default.
    algorithms: []const Algorithm,
    /// The provider's issuer identifier: `iss` byte for byte.
    issuer: []const u8,
    /// This relying party: `aud` must contain it.
    client_id: []const u8,
    leeway: jwt.Duration = .literal("0s"),
    /// Where each token's `jti` is kept until its `exp`, so a token replayed
    /// is refused (§2.6, step 8). Null leaves replay to the caller.
    replay: ?*jwt.Replay = null,
    max_bytes: aegis.units.Bytes(usize) = .literal("16KiB"),
    diagnostics: ?*jws.Diagnostics = null,
};

/// What a verified logout token ends. Strings borrow the scratch buffer.
pub const Verified = struct {
    /// The user whose sessions end, when it names one.
    sub: ?[]const u8,
    /// The session that ends, when it names one.
    sid: ?[]const u8,
    jti: []const u8,
    exp: i64,
};

pub const VerifyError = jwt.VerifyError || error{
    /// No `events` with the back-channel event as an object, neither `sub`
    /// nor `sid`, or a `nonce`: not a logout token.
    NotLogoutToken,
    /// This token was received before.
    Replayed,
    /// The replay set has no room: refused rather than forgotten.
    ReplayFull,
};

const WireClaims = struct {
    sid: ?[]const u8 = null,
    events: ?strand.json.Raw = null,
    nonce: ?strand.json.Raw = null,
};

/// Verifies a logout token (§2.6): signed by one of `keys` with an allowed
/// algorithm, typed `logout+jwt` or untyped (or `JWT`, as tokens before the
/// type was registered were), from the provider for this client, with
/// `iat`, `exp` and `jti`, the back-channel event, a `sub` or `sid`, no
/// `nonce`, and not seen before. Strings borrow `scratch` (at least
/// `jws.scratchLength(token.len)` bytes).
pub fn verifyToken(io: std.Io, token: []const u8, keys: []const Key, expected: Expected, now: std.Io.Timestamp, scratch: []u8) VerifyError!Verified {
    var diagnostics: jws.Diagnostics = .{};
    defer if (expected.diagnostics) |d| {
        d.* = diagnostics;
    };
    const verified = try jwt.verify(void, token, keys, .{
        .algorithms = expected.algorithms,
        .issuer = expected.issuer,
        .audience = expected.client_id,
        .required = .{ .iat = true, .exp = true, .jti = true },
        .leeway = expected.leeway,
        .max_bytes = expected.max_bytes,
        .diagnostics = &diagnostics,
    }, now, scratch);
    if (verified.header.typ) |typ| if (!jwt.mediaTypeIs(typ, media_type) and !jwt.mediaTypeIs(typ, "JWT")) {
        diagnostics.check = .type;
        return error.WrongType;
    };
    var fixed: std.heap.FixedBufferAllocator = .init(verified.rest);
    const claims = strand.json.parseLeaky(WireClaims, fixed.allocator(), verified.payload, .{
        .ignore_unknown_fields = true,
        .limits = .{ .depth = 32 },
    }) catch {
        diagnostics.check = .claims;
        return error.InvalidClaims;
    };
    const is_logout = blk: {
        if (claims.nonce != null) break :blk false;
        if (verified.registered.sub == null and claims.sid == null) break :blk false;
        const events = claims.events orelse break :blk false;
        const Events = struct { @"http://schemas.openid.net/event/backchannel-logout": ?strand.json.Raw = null };
        const named = events.parse(Events, fixed.allocator(), .{ .ignore_unknown_fields = true }) catch break :blk false;
        const value = named.@"http://schemas.openid.net/event/backchannel-logout" orelse break :blk false;
        const trimmed = std.mem.trimStart(u8, value.bytes, " \t\r\n");
        break :blk trimmed.len > 0 and trimmed[0] == '{';
    };
    if (!is_logout) {
        diagnostics.check = .claims;
        return error.NotLogoutToken;
    }
    const jti = verified.registered.jti.?;
    const exp = verified.registered.exp.?;
    if (expected.replay) |replay| {
        const seconds: i64 = time.unixSeconds(now);
        const leeway: i64 = expected.leeway.raw();
        const fresh = replay.record(io, jwt.replayId(expected.issuer, jti), exp +| leeway +| 1, seconds) catch {
            diagnostics.check = .replay;
            return error.ReplayFull;
        };
        if (!fresh) {
            diagnostics.check = .replay;
            return error.Replayed;
        }
    }
    return .{ .sub = verified.registered.sub, .sid = claims.sid, .jti = jti, .exp = exp };
}

const testing = std.testing;
const secret: [32]u8 = @splat(0x4c);
const test_keys = [_]Key{Key.hmac(&secret)};
const test_now: std.Io.Timestamp = .{ .nanoseconds = 1_471_566_200 * std.time.ns_per_s };
const test_expected: Expected = .{ .algorithms = &.{.hs256}, .issuer = "https://server.example.com", .client_id = "s6BhdRkqt3" };

fn signed(gpa: std.mem.Allocator, typ: ?[]const u8, claims: []const u8) ![]u8 {
    var out: std.Io.Writer.Allocating = .init(gpa);
    errdefer out.deinit();
    try jws.sign(gpa, testing.io, &out.writer, .{ .typ = typ }, claims, .{ .hmac = .{ .alg = .hs256, .secret = &secret } });
    return out.toOwnedSlice();
}

/// §2.4's example claims, with `exp`.
const example = "{\"iss\":\"https://server.example.com\",\"sub\":\"248289761001\",\"aud\":\"s6BhdRkqt3\",\"iat\":1471566154,\"exp\":1471566274,\"jti\":\"bWJq\",\"sid\":\"08a5019c-17e1-4977-8f42-65a12843ea02\",\"events\":{\"http://schemas.openid.net/event/backchannel-logout\":{}}}";

test "§2.4's logout token is verified once: its user and session named" {
    const gpa = testing.allocator;
    const token = try signed(gpa, media_type, example);
    defer gpa.free(token);
    var replay: jwt.MemoryReplay = try .init(gpa, 8);
    defer replay.deinit();
    var expected = test_expected;
    expected.replay = &replay.replay;
    var scratch: [2048]u8 = undefined;
    const v = try verifyToken(testing.io, token, &test_keys, expected, test_now, &scratch);
    try testing.expectEqualStrings("248289761001", v.sub.?);
    try testing.expectEqualStrings("08a5019c-17e1-4977-8f42-65a12843ea02", v.sid.?);
    try testing.expectError(error.Replayed, verifyToken(testing.io, token, &test_keys, expected, test_now, &scratch));
    // Untyped, and typed `JWT` as older providers write it.
    for ([_]?[]const u8{ null, "JWT" }) |typ| {
        const other = try signed(gpa, typ, example);
        defer gpa.free(other);
        _ = try verifyToken(testing.io, other, &test_keys, test_expected, test_now, &scratch);
    }
}

test "a token that is not a logout token, or not for this client, is refused" {
    const gpa = testing.allocator;
    var scratch: [2048]u8 = undefined;
    const head = "{\"iss\":\"https://server.example.com\",\"aud\":\"s6BhdRkqt3\",\"iat\":1471566154,\"exp\":1471566274,\"jti\":\"j\"";
    const cases = [_]struct { claims: []const u8, typ: ?[]const u8, err: anyerror }{
        // An ID token: a nonce, no event.
        .{ .claims = head ++ ",\"sub\":\"u\",\"nonce\":\"n\",\"events\":{\"" ++ event ++ "\":{}}}", .typ = null, .err = error.NotLogoutToken },
        .{ .claims = head ++ ",\"sub\":\"u\"}", .typ = null, .err = error.NotLogoutToken },
        .{ .claims = head ++ ",\"sub\":\"u\",\"events\":{\"" ++ event ++ "\":true}}", .typ = null, .err = error.NotLogoutToken },
        .{ .claims = head ++ ",\"sub\":\"u\",\"events\":{\"http://schemas.openid.net/event/other\":{}}}", .typ = null, .err = error.NotLogoutToken },
        .{ .claims = head ++ ",\"events\":{\"" ++ event ++ "\":{}}}", .typ = null, .err = error.NotLogoutToken },
        .{ .claims = head ++ ",\"sub\":\"u\",\"events\":{\"" ++ event ++ "\":{}}}", .typ = "at+jwt", .err = error.WrongType },
        .{ .claims = "{\"iss\":\"https://server.example.com\",\"aud\":\"other\",\"iat\":1471566154,\"exp\":1471566274,\"jti\":\"j\",\"sid\":\"s\",\"events\":{\"" ++ event ++ "\":{}}}", .typ = null, .err = error.WrongAudience },
        .{ .claims = "{\"iss\":\"https://server.example.com\",\"aud\":\"s6BhdRkqt3\",\"iat\":1471566154,\"exp\":1471566274,\"sid\":\"s\",\"events\":{\"" ++ event ++ "\":{}}}", .typ = null, .err = error.MissingClaim },
        .{ .claims = "{\"iss\":\"https://server.example.com\",\"aud\":\"s6BhdRkqt3\",\"iat\":1471566154,\"jti\":\"j\",\"sid\":\"s\",\"events\":{\"" ++ event ++ "\":{}}}", .typ = null, .err = error.MissingClaim },
        .{ .claims = "{\"iss\":\"https://server.example.com\",\"aud\":\"s6BhdRkqt3\",\"iat\":1471566154,\"exp\":1471566000,\"jti\":\"j\",\"sid\":\"s\",\"events\":{\"" ++ event ++ "\":{}}}", .typ = null, .err = error.Expired },
    };
    for (cases) |case| {
        const token = try signed(gpa, case.typ, case.claims);
        defer gpa.free(token);
        try testing.expectError(case.err, verifyToken(testing.io, token, &test_keys, test_expected, test_now, &scratch));
    }
    // `sid` alone names a session.
    const sid_only = try signed(gpa, null, head ++ ",\"sid\":\"s\",\"events\":{\"" ++ event ++ "\":{}}}");
    defer gpa.free(sid_only);
    const v = try verifyToken(testing.io, sid_only, &test_keys, test_expected, test_now, &scratch);
    try testing.expectEqual(@as(?[]const u8, null), v.sub);
}
