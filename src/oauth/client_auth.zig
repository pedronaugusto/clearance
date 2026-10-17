//! How a client proves itself to the token and introspection endpoints
//! (RFC 6749 §2.3, OAuth 2.1 §2.4; RFC 7523 §2.2 and RFC 7521 §4.2 for
//! `private_key_jwt`), and the form request that carries it. A request holds
//! secrets (a client secret, a refresh token, a code verifier), so its body
//! and its `Authorization` value live in wiped memory.
const std = @import("std");
const aegis = @import("aegis");
const form = @import("uplink.wire").form;
const jws = @import("../jws.zig");
const jwt = @import("../jwt.zig");
const pkce = @import("pkce.zig");

/// The methods clearance speaks, by their registered names.
pub const Method = enum {
    none,
    client_secret_basic,
    client_secret_post,
    private_key_jwt,

    pub fn name(m: Method) []const u8 {
        return @tagName(m);
    }

    pub fn parse(text: []const u8) ?Method {
        return std.meta.stringToEnum(Method, text);
    }
};

/// What the client holds to authenticate with.
pub const Credentials = union(Method) {
    /// A public client: `client_id` alone.
    none,
    /// The secret, sent in `Authorization: Basic`.
    client_secret_basic: []const u8,
    /// The secret, sent in the body.
    client_secret_post: []const u8,
    /// A JWT the client signs, its audience the issuer.
    private_key_jwt: PrivateKeyJwt,
};

pub const PrivateKeyJwt = struct {
    signer: jws.Signer,
    /// The `kid` of the key in the client's published key set.
    kid: ?[]const u8 = null,
    /// How long an assertion is good for.
    lifetime: jwt.Duration = .literal("60s"),
};

pub const Client = struct {
    id: []const u8,
    credentials: Credentials = .none,
};

/// The method to use with a server that lists `supported` (its metadata's
/// `token_endpoint_auth_methods_supported`, which defaults to
/// `client_secret_basic` when absent, RFC 8414 §2) among the ones the client
/// can do, in the client's order of preference. Null when none fits.
pub fn choose(supported: ?[]const []const u8, available: []const Method) ?Method {
    const listed: []const []const u8 = supported orelse &.{"client_secret_basic"};
    for (available) |m| {
        for (listed) |s| if (std.mem.eql(u8, s, m.name())) return m;
    }
    return null;
}

/// A request to send as `application/x-www-form-urlencoded`, POSTed.
pub const FormRequest = struct {
    /// The form body.
    body: aegis.SecretBytes,
    /// The `Authorization` field's value, when the method puts the client's
    /// credentials there.
    authorization: ?aegis.SecretBytes = null,

    pub const content_type = form.content_type;

    pub fn deinit(r: *FormRequest) void {
        r.body.deinit();
        if (r.authorization) |*a| a.deinit();
        r.* = undefined;
    }
};

/// What a `private_key_jwt` assertion needs from the moment it is made.
pub const Context = struct {
    /// The authorization server's issuer identifier: the assertion's
    /// audience (RFC 7523 §3 as draft-ietf-oauth-rfc7523bis settles it).
    issuer: []const u8,
    now: std.Io.Timestamp,
};

pub const Error = error{
    /// The signer could not sign the assertion.
    SigningFailed,
    InvalidKey,
} || std.mem.Allocator.Error;

/// The form request of `pairs` from `client`: its credentials added as its
/// method says. `io` draws an assertion's `jti` and its signature's noise.
pub fn formRequest(gpa: std.mem.Allocator, io: std.Io, client: Client, pairs: []const form.Pair, context: Context) Error!FormRequest {
    var all: std.ArrayList(form.Pair) = .empty;
    defer all.deinit(gpa);
    try all.appendSlice(gpa, pairs);
    var assertion: std.Io.Writer.Allocating = .init(gpa);
    defer assertion.deinit();
    var authorization: ?aegis.SecretBytes = null;
    errdefer if (authorization) |*a| a.deinit();
    switch (client.credentials) {
        .none => try all.append(gpa, .{ .name = "client_id", .value = client.id }),
        .client_secret_post => |secret| try all.appendSlice(gpa, &.{
            .{ .name = "client_id", .value = client.id },
            .{ .name = "client_secret", .value = secret },
        }),
        .client_secret_basic => |secret| authorization = try basic(gpa, client.id, secret),
        .private_key_jwt => |p| {
            try signAssertion(gpa, io, &assertion.writer, client.id, p, context);
            try all.appendSlice(gpa, &.{
                .{ .name = "client_id", .value = client.id },
                .{ .name = "client_assertion_type", .value = "urn:ietf:params:oauth:client-assertion-type:jwt-bearer" },
                .{ .name = "client_assertion", .value = assertion.written() },
            });
        },
    }
    var body = try encodeSecret(gpa, all.items);
    errdefer body.deinit();
    return .{ .body = body, .authorization = authorization };
}

/// `pairs` form-encoded into wiped memory of exactly their length.
pub fn encodeSecret(gpa: std.mem.Allocator, pairs: []const form.Pair) std.mem.Allocator.Error!aegis.SecretBytes {
    const length: usize = @intCast(form.encodedLength(pairs));
    var body = aegis.SecretBytes.init(gpa, length) catch return error.OutOfMemory;
    errdefer body.deinit();
    // unreachable: the capacity was just allocated at this length
    body.resizeWithinCapacity(length) catch unreachable;
    var w: std.Io.Writer = .fixed(body.exposeMut());
    // unreachable: `encodedLength` is what `encode` writes
    form.encode(&w, pairs) catch unreachable;
    return body;
}

/// `Basic` with the id and secret each form-encoded first (RFC 6749 §2.3.1,
/// a step many clients skip, so a secret with a `:` breaks them).
fn basic(gpa: std.mem.Allocator, id: []const u8, secret: []const u8) std.mem.Allocator.Error!aegis.SecretBytes {
    const pairs = [_]form.Pair{.{ .name = id, .value = secret }};
    var joined = try encodeSecret(gpa, &pairs);
    defer joined.deinit();
    // `name=value` with the `=` made `:`.
    const raw = joined.exposeMut();
    raw[@intCast(form.encodedLength(&.{.{ .name = id, .value = "" }}) - 1)] = ':';
    const prefix = "Basic ";
    const length = prefix.len + std.base64.standard.Encoder.calcSize(raw.len);
    var out = aegis.SecretBytes.init(gpa, length) catch return error.OutOfMemory;
    // unreachable: the capacity was just allocated at this length
    out.resizeWithinCapacity(length) catch unreachable;
    const bytes = out.exposeMut();
    @memcpy(bytes[0..prefix.len], prefix);
    _ = std.base64.standard.Encoder.encode(bytes[prefix.len..], raw);
    return out;
}

fn signAssertion(gpa: std.mem.Allocator, io: std.Io, out: *std.Io.Writer, id: []const u8, p: PrivateKeyJwt, context: Context) Error!void {
    const now: i64 = @intCast(@divFloor(context.now.nanoseconds, std.time.ns_per_s));
    var jti: [pkce.length]u8 = undefined;
    pkce.random(io, &jti);
    const lifetime: i64 = p.lifetime.raw();
    jwt.sign(gpa, io, out, .{ .kid = p.kid }, .{
        .iss = id,
        .sub = id,
        .aud = context.issuer,
        .jti = @as([]const u8, &jti),
        .iat = now,
        .exp = now + lifetime,
    }, p.signer) catch |err| return switch (err) {
        error.OutOfMemory, error.WriteFailed => error.OutOfMemory,
        error.InvalidKey => error.InvalidKey,
        error.SigningFailed, error.InvalidClaims => error.SigningFailed,
    };
}

test "Basic form-encodes the id and secret before joining them" {
    var request = try formRequest(std.testing.allocator, std.testing.io, .{ .id = "s6BhdRkqt3", .credentials = .{ .client_secret_basic = "7Fjfp0ZBr1KtDRbnfVdmIw" } }, &.{.{ .name = "grant_type", .value = "client_credentials" }}, .{ .issuer = "https://as.example", .now = .{ .nanoseconds = 0 } });
    defer request.deinit();
    // RFC 6749 §4.4.2's example.
    try std.testing.expectEqualStrings("Basic czZCaGRSa3F0Mzo3RmpmcDBaQnIxS3REUmJuZlZkbUl3", request.authorization.?.expose());
    try std.testing.expectEqualStrings("grant_type=client_credentials", request.body.expose());
    var odd = try formRequest(std.testing.allocator, std.testing.io, .{ .id = "a:b", .credentials = .{ .client_secret_basic = "p w%" } }, &.{}, .{ .issuer = "https://as.example", .now = .{ .nanoseconds = 0 } });
    defer odd.deinit();
    var decoded: [64]u8 = undefined;
    const text = odd.authorization.?.expose()["Basic ".len..];
    const n = try std.base64.standard.Decoder.calcSizeForSlice(text);
    try std.base64.standard.Decoder.decode(decoded[0..n], text);
    try std.testing.expectEqualStrings("a%3Ab:p+w%25", decoded[0..n]);
}

test "post and none put the client in the body" {
    const ctx: Context = .{ .issuer = "https://as.example", .now = .{ .nanoseconds = 0 } };
    var post = try formRequest(std.testing.allocator, std.testing.io, .{ .id = "c", .credentials = .{ .client_secret_post = "s&t" } }, &.{.{ .name = "a", .value = "1" }}, ctx);
    defer post.deinit();
    try std.testing.expectEqualStrings("a=1&client_id=c&client_secret=s%26t", post.body.expose());
    try std.testing.expectEqual(@as(?aegis.SecretBytes, null), post.authorization);
    var none = try formRequest(std.testing.allocator, std.testing.io, .{ .id = "c" }, &.{}, ctx);
    defer none.deinit();
    try std.testing.expectEqualStrings("client_id=c", none.body.expose());
}

test "the method is chosen from what the server lists, basic when it lists nothing" {
    try std.testing.expectEqual(Method.client_secret_basic, choose(null, &.{ .client_secret_post, .client_secret_basic }).?);
    try std.testing.expectEqual(Method.client_secret_post, choose(&.{ "client_secret_post", "none" }, &.{ .client_secret_post, .none }).?);
    try std.testing.expectEqual(@as(?Method, null), choose(&.{"private_key_jwt"}, &.{.none}));
}
