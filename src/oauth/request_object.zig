//! JWT-Secured Authorization Requests (RFC 9101): the authorization
//! request's parameters as a JWT the client signs (a request object), and
//! encrypts to the server when the server asks (§6.1: signed, then
//! encrypted). Sent by value (`authorize.writeSignedUrl`) or pushed
//! (`par.requestObject`), as FAPI 2.0 asks.
const std = @import("std");
const strand = @import("strand");
const clearance = @import("clearance");
const authorize = @import("authorize.zig");
const pkce = @import("pkce.zig");

const jws = clearance.jws;
const jwe = clearance.jwe;
const jwt = clearance.jwt;

/// The `typ` of a request object (RFC 9101 §10.8).
pub const media_type = "oauth-authz-req+jwt";

pub const Options = struct {
    /// The client's key: the one its registered `request_object_signing_alg`
    /// names.
    signer: jws.Signer,
    /// The `kid` of that key in the client's published set.
    kid: ?[]const u8 = null,
    /// How long the object is good for; FAPI 2.0 asks for at most 60 s.
    lifetime: jwt.Duration = .literal("60s"),
    /// Set when the server takes encrypted request objects: the signed
    /// object becomes the content of a compact JWE to this recipient (the
    /// server's encryption key), `cty` `JWT`.
    encryption: ?Encryption = null,

    pub const Encryption = struct {
        recipient: jwe.Recipient,
        enc: jwe.ContentEncryption,
    };
};

pub const Error = error{
    /// The signer's key does not fit its algorithm, or the recipient's key
    /// does not fit its algorithm.
    InvalidKey,
    SigningFailed,
} || std.mem.Allocator.Error;

/// Writes the request object of `request` for the server `issuer`: every
/// authorization parameter as a claim (`resource` as an array when there
/// are several, RFC 8707 §2.1), with `iss` the client, `aud` the issuer,
/// `iat`, `nbf`, `exp` and a fresh `jti` (RFC 9101 §4, §10.2). `io` draws
/// the `jti` and the signature's and encryption's randomness.
pub fn write(gpa: std.mem.Allocator, io: std.Io, out: *std.Io.Writer, issuer: []const u8, request: authorize.Request, options: Options, now: std.Io.Timestamp) Error!void {
    var claims: std.Io.Writer.Allocating = .init(gpa);
    defer claims.deinit();
    writeClaims(&claims.writer, io, issuer, request, options.lifetime, now) catch return error.OutOfMemory;
    const header: jws.SignHeader = .{ .typ = media_type, .kid = options.kid };
    const encryption = options.encryption orelse return sign(gpa, io, out, header, claims.written(), options.signer);
    var signed: std.Io.Writer.Allocating = .init(gpa);
    defer signed.deinit();
    try sign(gpa, io, &signed.writer, header, claims.written(), options.signer);
    jwe.encrypt(gpa, io, out, .{ .enc = encryption.enc, .cty = "JWT" }, signed.written(), &.{encryption.recipient}, .compact, .{}) catch |err| return switch (err) {
        error.OutOfMemory, error.WriteFailed => error.OutOfMemory,
        error.InvalidKey, error.InvalidRecipients, error.UnsupportedAlgorithm => error.InvalidKey,
    };
}

fn sign(gpa: std.mem.Allocator, io: std.Io, out: *std.Io.Writer, header: jws.SignHeader, claims: []const u8, signer: jws.Signer) Error!void {
    jws.sign(gpa, io, out, header, claims, signer) catch |err| return switch (err) {
        error.OutOfMemory, error.WriteFailed => error.OutOfMemory,
        error.InvalidKey => error.InvalidKey,
        // No extra header member and an encoded payload: neither refusal can happen.
        error.SigningFailed, error.InvalidHeader, error.InvalidPayload => error.SigningFailed,
    };
}

fn writeClaims(w: *std.Io.Writer, io: std.Io, issuer: []const u8, request: authorize.Request, lifetime: jwt.Duration, now: std.Io.Timestamp) !void {
    const seconds: i64 = @intCast(@divFloor(now.nanoseconds, std.time.ns_per_s));
    var jti: [pkce.length]u8 = undefined;
    pkce.random(io, &jti);
    try w.writeAll("{\"iss\":");
    try string(w, request.client_id);
    try w.writeAll(",\"aud\":");
    try string(w, issuer);
    try w.print(",\"iat\":{d},\"nbf\":{d},\"exp\":{d},\"jti\":", .{ seconds, seconds, seconds + @as(i64, lifetime.raw()) });
    try string(w, &jti);
    var it: authorize.Params = .{ .request = request };
    while (it.next()) |pair| {
        if (std.mem.eql(u8, pair.name, "resource")) continue;
        try w.writeByte(',');
        try string(w, pair.name);
        try w.writeByte(':');
        try string(w, pair.value);
    }
    switch (request.resources.len) {
        0 => {},
        1 => {
            try w.writeAll(",\"resource\":");
            try string(w, request.resources[0]);
        },
        else => {
            try w.writeAll(",\"resource\":[");
            for (request.resources, 0..) |r, i| {
                if (i > 0) try w.writeByte(',');
                try string(w, r);
            }
            try w.writeByte(']');
        },
    }
    try w.writeByte('}');
}

fn string(w: *std.Io.Writer, value: []const u8) !void {
    try strand.json.write(w, value, .{});
}

const testing = std.testing;

const test_request: authorize.Request = .{
    .client_id = "s6BhdRkqt3",
    .redirect_uri = "https://client.example.org/cb",
    .state = "af0ifjsldkj",
    .code_challenge = "E9Melhoa2OwvFrEMTJguCHaoeK1t8URWbuGJSstw-cM",
    .scope = "openid email",
    .resources = &.{ "https://rs.example/a", "https://rs.example/b" },
    .nonce = "n-0S6_WzA2Mj",
    .extra = &.{.{ .name = "prompt", .value = "login \"now\"" }},
};

test "a request object carries every parameter as a claim, signed for the issuer" {
    const gpa = testing.allocator;
    const secret: [32]u8 = @splat(0x52);
    var out: std.Io.Writer.Allocating = .init(gpa);
    defer out.deinit();
    const now: std.Io.Timestamp = .{ .nanoseconds = 1_700_000_000 * std.time.ns_per_s };
    try write(gpa, testing.io, &out.writer, "https://server.example.com", test_request, .{ .signer = .{ .hmac = .{ .alg = .hs256, .secret = &secret } } }, now);
    const Claims = struct {
        client_id: []const u8,
        response_type: []const u8,
        redirect_uri: []const u8,
        state: []const u8,
        scope: []const u8,
        nonce: []const u8,
        code_challenge_method: []const u8,
        resource: []const []const u8,
        prompt: []const u8,
    };
    var scratch: [4096]u8 = undefined;
    const v = try jwt.verify(Claims, out.written(), &.{clearance.Key.hmac(&secret)}, .{
        .algorithms = &.{.hs256},
        .issuer = "s6BhdRkqt3",
        .audience = "https://server.example.com",
        .typ = media_type,
        .required = .{ .iss = true, .aud = true, .exp = true, .iat = true, .nbf = true, .jti = true },
    }, now, &scratch);
    try testing.expectEqualStrings("code", v.claims.response_type);
    try testing.expectEqualStrings("s6BhdRkqt3", v.claims.client_id);
    try testing.expectEqualStrings("S256", v.claims.code_challenge_method);
    try testing.expectEqual(@as(usize, 2), v.claims.resource.len);
    try testing.expectEqualStrings("login \"now\"", v.claims.prompt);
    try testing.expectEqual(@as(?i64, 1_700_000_060), v.registered.exp);
}

test "an encrypted request object is the signed one inside a JWE to the server" {
    const gpa = testing.allocator;
    const secret: [32]u8 = @splat(0x52);
    const kek: [16]u8 = @splat(0x4b);
    var out: std.Io.Writer.Allocating = .init(gpa);
    defer out.deinit();
    const now: std.Io.Timestamp = .{ .nanoseconds = 1_700_000_000 * std.time.ns_per_s };
    try write(gpa, testing.io, &out.writer, "https://server.example.com", test_request, .{
        .signer = .{ .hmac = .{ .alg = .hs256, .secret = &secret } },
        .encryption = .{ .recipient = .{ .alg = .a128kw, .key = .{ .key = clearance.Key.hmac(&kek) } }, .enc = .a128gcm },
    }, now);
    try testing.expectEqual(@as(usize, 4), std.mem.count(u8, out.written(), "."));
    var scratch: [jwe.scratchLength(4096)]u8 = undefined;
    const v = try jwt.verify(struct { state: []const u8 }, out.written(), &.{clearance.Key.hmac(&secret)}, .{
        .algorithms = &.{.hs256},
        .issuer = "s6BhdRkqt3",
        .audience = "https://server.example.com",
        .typ = media_type,
        .decryption = .{ .io = testing.io, .keys = &.{.{ .material = .{ .secret = &kek } }}, .options = .{ .key_algorithms = &.{.a128kw}, .encryptions = &.{.a128gcm} } },
    }, now, &scratch);
    try testing.expectEqualStrings("af0ifjsldkj", v.claims.state);
    // A recipient key that does not fit its algorithm.
    try testing.expectError(error.InvalidKey, write(gpa, testing.io, &out.writer, "https://server.example.com", test_request, .{
        .signer = .{ .hmac = .{ .alg = .hs256, .secret = &secret } },
        .encryption = .{ .recipient = .{ .alg = .a256kw, .key = .{ .key = clearance.Key.hmac(&kek) } }, .enc = .a128gcm },
    }, now));
}
