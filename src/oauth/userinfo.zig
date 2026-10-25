//! OpenID Connect's UserInfo (Core §5.3): the claims about the signed-in
//! user, asked for with the access token, as JSON or as a signed JWT. The
//! answer's `sub` must be the ID token's (§5.3.4): a response for another
//! user would otherwise pass, so the subject is a required argument.
const std = @import("std");
const aegis = @import("aegis");
const strand = @import("strand");
const clearance = @import("clearance");
const errors = @import("errors.zig");
const challenge = @import("challenge.zig");

const jwt = clearance.jwt;

/// OpenID Connect Core §5.1's standard claims, each optional but `sub`.
pub const Standard = struct {
    sub: []const u8,
    name: ?[]const u8 = null,
    given_name: ?[]const u8 = null,
    family_name: ?[]const u8 = null,
    middle_name: ?[]const u8 = null,
    nickname: ?[]const u8 = null,
    preferred_username: ?[]const u8 = null,
    profile: ?[]const u8 = null,
    picture: ?[]const u8 = null,
    website: ?[]const u8 = null,
    email: ?[]const u8 = null,
    email_verified: ?bool = null,
    gender: ?[]const u8 = null,
    birthdate: ?[]const u8 = null,
    zoneinfo: ?[]const u8 = null,
    locale: ?[]const u8 = null,
    phone_number: ?[]const u8 = null,
    phone_number_verified: ?bool = null,
    address: ?Address = null,
    updated_at: ?i64 = null,

    pub const Address = struct {
        formatted: ?[]const u8 = null,
        street_address: ?[]const u8 = null,
        locality: ?[]const u8 = null,
        region: ?[]const u8 = null,
        postal_code: ?[]const u8 = null,
        country: ?[]const u8 = null,
    };
};

/// What the answer must be.
pub const Expected = struct {
    /// The ID token's `sub`: the answer's must equal it, byte for byte.
    subject: []const u8,
    /// Set when the client registered a signed UserInfo response
    /// (`userinfo_signed_response_alg`): the answer must be a JWT these
    /// keys verify. Null takes JSON alone.
    signed: ?Signed = null,

    pub const Signed = struct {
        keys: []const clearance.Key,
        algorithms: []const clearance.Algorithm,
        /// The issuer: the JWT's `iss`, when it carries one (§5.3.2).
        issuer: []const u8,
        /// The client: the JWT's `aud` must contain it, when it carries one.
        client_id: []const u8,
        now: std.Io.Timestamp,
    };
};

pub fn Response(comptime Claims: type) type {
    return union(enum) {
        /// The claims, their strings in the arena.
        claims: Claims,
        /// The resource refused the token: its challenge's error (RFC 6750
        /// §3.1: `invalid_token`, `insufficient_scope`), or the error body.
        refused: errors.ErrorResponse,
    };
}

pub const ReadOptions = struct {
    max_bytes: aegis.units.Bytes(usize) = .literal("64KiB"),
};

pub const ReadError = error{
    TooLarge,
    /// A 200 that is not the claims: not a JSON object, a claim of the
    /// wrong type, no `sub`.
    InvalidResponse,
    /// The answer is about another user.
    WrongSubject,
    /// A signed answer was expected and JSON came, or a JWT came and no
    /// keys were given to verify it.
    WrongForm,
    /// A signed answer that does not verify, or names another issuer or
    /// audience.
    InvalidSignature,
    /// Neither the claims nor a refusal that says why.
    UnexpectedStatus,
} || std.mem.Allocator.Error;

/// Reads a UserInfo answer into `Claims` (a struct; `Standard` reads OpenID
/// Connect's own). `content_type` is the answer's media type, without
/// parameters; `challenges` its `WWW-Authenticate` lines. Strings live in
/// `arena`.
pub fn readResponse(comptime Claims: type, arena: std.mem.Allocator, status: u16, content_type: []const u8, challenges: []const []const u8, body: []const u8, expected: Expected, options: ReadOptions) ReadError!Response(Claims) {
    const limit: usize = options.max_bytes.raw();
    if (body.len > limit) return error.TooLarge;
    if (status != 200) {
        if (challenge.read(arena, challenges) catch null) |c| if (c.@"error") |code| if (code != .other) {
            return .{ .refused = .{ .code = code, .name = .init(@tagName(code)), .description = .init(c.error_description orelse "") } };
        };
        var scratch: [1024]u8 = undefined;
        if (body.len <= 4096) if (errors.readJson(body, &scratch)) |e| return .{ .refused = e };
        return error.UnexpectedStatus;
    }
    const is_jwt = std.ascii.eqlIgnoreCase(content_type, "application/jwt");
    if (is_jwt != (expected.signed != null)) return error.WrongForm;
    if (expected.signed) |signed| {
        const scratch = try arena.alloc(u8, clearance.jws.scratchLength(body.len));
        const token = std.mem.trim(u8, body, " \t\r\n");
        // An audience, when the token names one, must be the client (§5.3.2
        // has it SHOULD): asked for only then, since `jwt.verify` refuses an
        // `aud` it was not told of.
        const audience: ?[]const u8 = if (jwt.inspect(void, token, .{ .required = .{ .exp = false }, .max_bytes = options.max_bytes }, signed.now, scratch)) |_| null else |err| switch (err) {
            error.WrongAudience => signed.client_id,
            error.InvalidClaims => return error.InvalidResponse,
            else => return error.InvalidSignature,
        };
        return readSigned(Claims, token, expected, signed, audience, options, scratch);
    }
    const options_json: strand.json.ParseOptions = .{ .ignore_unknown_fields = true, .limits = .{ .depth = 16 } };
    const owned = try arena.dupe(u8, body);
    const Subject = struct { sub: []const u8 };
    const subject = strand.json.parseLeaky(Subject, arena, owned, options_json) catch |err| return switch (err) {
        error.OutOfMemory => error.OutOfMemory,
        else => error.InvalidResponse,
    };
    if (!std.mem.eql(u8, subject.sub, expected.subject)) return error.WrongSubject;
    const claims = strand.json.parseLeaky(Claims, arena, owned, options_json) catch |err| return switch (err) {
        error.OutOfMemory => error.OutOfMemory,
        else => error.InvalidResponse,
    };
    return .{ .claims = claims };
}

/// A signed answer: verified with the keys, for `audience` when it names
/// one, its `iss` the issuer when present, its `sub` the expected one.
fn readSigned(comptime Claims: type, token: []const u8, expected: Expected, signed: Expected.Signed, audience: ?[]const u8, options: ReadOptions, scratch: []u8) ReadError!Response(Claims) {
    const verified = jwt.verify(Claims, token, signed.keys, .{
        .algorithms = signed.algorithms,
        .audience = audience,
        .required = .{ .exp = false, .sub = true },
        .max_bytes = options.max_bytes,
    }, signed.now, scratch) catch |err| return switch (err) {
        error.InvalidClaims, error.MissingClaim => error.InvalidResponse,
        else => error.InvalidSignature,
    };
    if (verified.registered.iss) |iss| if (!std.mem.eql(u8, iss, signed.issuer)) return error.InvalidSignature;
    if (!std.mem.eql(u8, verified.registered.sub.?, expected.subject)) return error.WrongSubject;
    return .{ .claims = verified.claims };
}

const testing = std.testing;

test "OIDC Core §5.3.2's answer is read for its subject, and refused for another" {
    var arena: std.heap.ArenaAllocator = .init(testing.allocator);
    defer arena.deinit();
    const a = arena.allocator();
    const body =
        \\{"sub":"248289761001","name":"Jane Doe","given_name":"Jane","family_name":"Doe","preferred_username":"j.doe",
        \\"email":"janedoe@example.com","email_verified":true,"picture":"http://example.com/janedoe/me.jpg",
        \\"address":{"country":"US"},"updated_at":1311280970,"x-custom":[1,2]}
    ;
    const r = try readResponse(Standard, a, 200, "application/json", &.{}, body, .{ .subject = "248289761001" }, .{});
    try testing.expectEqualStrings("Jane Doe", r.claims.name.?);
    try testing.expect(r.claims.email_verified.?);
    try testing.expectEqualStrings("US", r.claims.address.?.country.?);
    try testing.expectError(error.WrongSubject, readResponse(Standard, a, 200, "application/json", &.{}, body, .{ .subject = "248289761002" }, .{}));
    try testing.expectError(error.InvalidResponse, readResponse(Standard, a, 200, "application/json", &.{}, "{\"name\":\"x\"}", .{ .subject = "s" }, .{}));
    try testing.expectError(error.InvalidResponse, readResponse(Standard, a, 200, "application/json", &.{}, "{\"sub\":\"s\",\"email_verified\":\"true\"}", .{ .subject = "s" }, .{}));
    try testing.expectError(error.InvalidResponse, readResponse(Standard, a, 200, "application/json", &.{}, "{\"sub\":\"s\",\"sub\":\"t\"}", .{ .subject = "s" }, .{}));
    try testing.expectError(error.WrongForm, readResponse(Standard, a, 200, "application/jwt", &.{}, "e.y.j", .{ .subject = "s" }, .{}));
}

test "a refusal is read from the challenge, else from the body" {
    var arena: std.heap.ArenaAllocator = .init(testing.allocator);
    defer arena.deinit();
    const a = arena.allocator();
    const r = try readResponse(Standard, a, 401, "", &.{"Bearer error=\"invalid_token\", error_description=\"The Access Token expired\""}, "", .{ .subject = "s" }, .{});
    try testing.expectEqual(errors.Code.invalid_token, r.refused.code);
    try testing.expectEqualStrings("The Access Token expired", r.refused.description.slice());
    const body = try readResponse(Standard, a, 403, "application/json", &.{}, "{\"error\":\"insufficient_scope\"}", .{ .subject = "s" }, .{});
    try testing.expectEqual(errors.Code.insufficient_scope, body.refused.code);
    try testing.expectError(error.UnexpectedStatus, readResponse(Standard, a, 500, "text/html", &.{}, "<html>", .{ .subject = "s" }, .{}));
}

test "a signed answer is verified, its issuer, audience and subject held" {
    var arena: std.heap.ArenaAllocator = .init(testing.allocator);
    defer arena.deinit();
    const a = arena.allocator();
    const secret: [32]u8 = @splat(0x55);
    const keys = [_]clearance.Key{clearance.Key.hmac(&secret)};
    const now: std.Io.Timestamp = .{ .nanoseconds = 1_800_000_000 * std.time.ns_per_s };
    const signed: Expected.Signed = .{ .keys = &keys, .algorithms = &.{.hs256}, .issuer = "https://as.example", .client_id = "app", .now = now };
    const claims = [_][]const u8{
        "{\"iss\":\"https://as.example\",\"aud\":\"app\",\"sub\":\"u1\",\"name\":\"Jane\"}",
        "{\"sub\":\"u1\",\"name\":\"Jane\"}",
        "{\"iss\":\"https://evil.example\",\"aud\":\"app\",\"sub\":\"u1\"}",
        "{\"iss\":\"https://as.example\",\"aud\":\"other\",\"sub\":\"u1\"}",
        "{\"iss\":\"https://as.example\",\"aud\":\"app\",\"sub\":\"u2\"}",
    };
    var tokens: [claims.len][]const u8 = undefined;
    for (claims, &tokens) |c, *t| {
        var out: std.Io.Writer.Allocating = .init(a);
        try clearance.jws.sign(a, testing.io, &out.writer, .{ .typ = "JWT" }, c, .{ .hmac = .{ .alg = .hs256, .secret = &secret } });
        t.* = out.written();
    }
    const expected: Expected = .{ .subject = "u1", .signed = signed };
    try testing.expectEqualStrings("Jane", (try readResponse(Standard, a, 200, "application/jwt", &.{}, tokens[0], expected, .{})).claims.name.?);
    try testing.expectEqualStrings("Jane", (try readResponse(Standard, a, 200, "application/jwt", &.{}, tokens[1], expected, .{})).claims.name.?);
    try testing.expectError(error.InvalidSignature, readResponse(Standard, a, 200, "application/jwt", &.{}, tokens[2], expected, .{}));
    try testing.expectError(error.InvalidSignature, readResponse(Standard, a, 200, "application/jwt", &.{}, tokens[3], expected, .{}));
    try testing.expectError(error.WrongSubject, readResponse(Standard, a, 200, "application/jwt", &.{}, tokens[4], expected, .{}));
    try testing.expectError(error.WrongForm, readResponse(Standard, a, 200, "application/json", &.{}, "{\"sub\":\"u1\"}", expected, .{}));
}
