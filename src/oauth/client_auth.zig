//! How a client proves itself to the token and introspection endpoints
//! (RFC 6749 §2.3, OAuth 2.1 §2.4; RFC 7523 §2.2 and RFC 7521 §4.2 for
//! `private_key_jwt` and `client_secret_jwt`), and the form request that
//! carries it. A request holds
//! secrets (a client secret, a refresh token, a code verifier), so its body
//! and its `Authorization` value live in wiped memory.
const std = @import("std");
const aegis = @import("aegis");
const form = @import("uplink.wire").form;
const clearance = @import("clearance");
const jws = clearance.jws;
const jwt = clearance.jwt;
const pkce = @import("pkce.zig");

/// The methods clearance speaks, by their registered names.
pub const Method = enum {
    none,
    client_secret_basic,
    client_secret_post,
    private_key_jwt,
    client_secret_jwt,
    /// RFC 8705 §2.1: the TLS client certificate, chained to a CA the
    /// server trusts, names the client.
    tls_client_auth,
    /// RFC 8705 §2.2: a self-signed TLS client certificate, matched against
    /// the client's registered keys.
    self_signed_tls_client_auth,

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
    /// A JWT the client signs with its private key (in memory, or kept by
    /// an external signer), its audience the issuer.
    private_key_jwt: PrivateKeyJwt,
    /// A JWT the client signs with HS256 under its secret, its audience the
    /// issuer: a server that asks for it rather than the secret itself.
    client_secret_jwt: []const u8,
    /// Mutual TLS (RFC 8705 §2): the certificate the HTTP client presents
    /// (uplink's `tls.ClientOptions.client_auth`) authenticates; the body
    /// carries `client_id` (§2). The certificate is the caller's to set on
    /// the connection, not clearance's to send.
    tls_client_auth,
    self_signed_tls_client_auth,
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
    /// The HTTP client presents a TLS certificate though the method is
    /// another: a public client asking for certificate-bound tokens (RFC
    /// 8705 §3, §4). The TLS methods imply it.
    mutual_tls: bool = false,

    /// Whether requests go over mutual TLS, and so to the server's
    /// `mtls_endpoint_aliases` (RFC 8705 §5).
    pub fn mutualTls(c: Client) bool {
        return c.mutual_tls or c.credentials == .tls_client_auth or c.credentials == .self_signed_tls_client_auth;
    }
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
/// A null `client` adds nothing: a request whose grant is its own
/// credential.
pub fn formRequest(gpa: std.mem.Allocator, io: std.Io, maybe_client: ?Client, pairs: []const form.Pair, context: Context) Error!FormRequest {
    var all: std.ArrayList(form.Pair) = .empty;
    defer all.deinit(gpa);
    try all.appendSlice(gpa, pairs);
    var assertion: std.Io.Writer.Allocating = .init(gpa);
    defer assertion.deinit();
    var authorization: ?aegis.SecretBytes = null;
    errdefer if (authorization) |*a| a.deinit();
    if (maybe_client) |client| switch (client.credentials) {
        .none, .tls_client_auth, .self_signed_tls_client_auth => try all.append(gpa, .{ .name = "client_id", .value = client.id }),
        .client_secret_post => |secret| try all.appendSlice(gpa, &.{
            .{ .name = "client_id", .value = client.id },
            .{ .name = "client_secret", .value = secret },
        }),
        .client_secret_basic => |secret| authorization = try basic(gpa, client.id, secret),
        inline .private_key_jwt, .client_secret_jwt => |p, method| {
            const key: PrivateKeyJwt = if (method == .private_key_jwt) p else .{ .signer = .{ .hmac = .{ .alg = .hs256, .secret = p } } };
            try signAssertion(gpa, io, &assertion.writer, client.id, key, context);
            try all.appendSlice(gpa, &.{
                .{ .name = "client_id", .value = client.id },
                .{ .name = "client_assertion_type", .value = "urn:ietf:params:oauth:client-assertion-type:jwt-bearer" },
                .{ .name = "client_assertion", .value = assertion.written() },
            });
        },
    };
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
        // No extra header member, and an encoded payload: neither refusal can happen.
        error.SigningFailed, error.InvalidClaims, error.InvalidHeader, error.InvalidPayload => error.SigningFailed,
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

test "private_key_jwt signs an assertion of the client, for the issuer, briefly" {
    const cloak = @import("cloak");
    const jwk = clearance.jwk;
    const gpa = std.testing.allocator;
    // RFC 8037 A.1's key, as PKCS#8.
    var der: [48]u8 = undefined;
    _ = try std.fmt.hexToBytes(der[0..16], "302e020100300506032b657004220420");
    _ = try std.base64.url_safe_no_pad.Decoder.decode(der[16..48], "nWGxne_9WmC6hEr0kuwsxERJxWl7MmkZcDusAxyuf2A");
    const key = try cloak.PrivateKey.parse(gpa, &der, .{});
    defer key.deinit();
    const now: std.Io.Timestamp = .{ .nanoseconds = 1_800_000_000 * std.time.ns_per_s };
    var request = try formRequest(gpa, std.testing.io, .{ .id = "mcp-client", .credentials = .{ .private_key_jwt = .{ .signer = .{ .private = .{ .alg = .eddsa, .key = key } }, .kid = "k1" } } }, &.{.{ .name = "grant_type", .value = "client_credentials" }}, .{ .issuer = "https://as.example", .now = now });
    defer request.deinit();
    const body = request.body.expose();
    try std.testing.expect(std.mem.startsWith(u8, body, "grant_type=client_credentials&client_id=mcp-client&client_assertion_type=urn%3Aietf%3Aparams%3Aoauth%3Aclient-assertion-type%3Ajwt-bearer&client_assertion="));
    const assertion = body[std.mem.find(u8, body, "client_assertion=").? + "client_assertion=".len ..];
    var set = try jwk.KeySet.parse(gpa, "{\"kty\":\"OKP\",\"crv\":\"Ed25519\",\"kid\":\"k1\",\"x\":\"11qYAYKxCrfVS_7TyWQHOg7hcvPapiMlrwIaaPcHURo\"}", .{});
    defer set.deinit();
    var scratch: [2048]u8 = undefined;
    const verified = try jwt.verify(void, assertion, set.keys, .{
        .algorithms = &.{.eddsa},
        .issuer = "mcp-client",
        .subject = "mcp-client",
        .audience = "https://as.example",
        .required = .{ .jti = true, .iat = true },
    }, now, &scratch);
    try std.testing.expectEqual(@as(?i64, 1_800_000_060), verified.registered.exp);
    try std.testing.expectEqual(@as(usize, pkce.length), verified.registered.jti.?.len);
}

test "client_secret_jwt signs the assertion with HS256 under the secret" {
    const gpa = std.testing.allocator;
    const secret = "a secret of at least thirty-two bytes!";
    const now: std.Io.Timestamp = .{ .nanoseconds = 1_800_000_000 * std.time.ns_per_s };
    var request = try formRequest(gpa, std.testing.io, .{ .id = "c", .credentials = .{ .client_secret_jwt = secret } }, &.{}, .{ .issuer = "https://as.example", .now = now });
    defer request.deinit();
    const body = request.body.expose();
    try std.testing.expectEqual(@as(?aegis.SecretBytes, null), request.authorization);
    const assertion = body[std.mem.find(u8, body, "client_assertion=").? + "client_assertion=".len ..];
    var scratch: [2048]u8 = undefined;
    const verified = try jwt.verify(void, assertion, &.{clearance.Key.hmac(secret)}, .{
        .algorithms = &.{.hs256},
        .issuer = "c",
        .subject = "c",
        .audience = "https://as.example",
        .required = .{ .jti = true, .iat = true },
    }, now, &scratch);
    try std.testing.expectEqual(clearance.Algorithm.hs256, verified.header.alg);
    // A secret shorter than the hash is no HS256 key (RFC 7518 §3.2).
    try std.testing.expectError(error.InvalidKey, formRequest(gpa, std.testing.io, .{ .id = "c", .credentials = .{ .client_secret_jwt = "short" } }, &.{}, .{ .issuer = "https://as.example", .now = now }));
}

test "the mutual TLS methods put client_id in the body, and choose the server's mTLS aliases" {
    const ctx: Context = .{ .issuer = "https://as.example", .now = .{ .nanoseconds = 0 } };
    for ([_]Credentials{ .tls_client_auth, .self_signed_tls_client_auth }) |credentials| {
        const client: Client = .{ .id = "c", .credentials = credentials };
        var r = try formRequest(std.testing.allocator, std.testing.io, client, &.{.{ .name = "a", .value = "1" }}, ctx);
        defer r.deinit();
        try std.testing.expectEqualStrings("a=1&client_id=c", r.body.expose());
        try std.testing.expect(r.authorization == null);
        try std.testing.expect(client.mutualTls());
    }
    try std.testing.expect(!(Client{ .id = "c" }).mutualTls());
    try std.testing.expect((Client{ .id = "c", .mutual_tls = true }).mutualTls());
    try std.testing.expectEqual(Method.tls_client_auth, choose(&.{ "private_key_jwt", "tls_client_auth" }, &.{ .self_signed_tls_client_auth, .tls_client_auth }).?);
}
