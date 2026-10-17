//! The Identity Assertion JWT Authorization Grant (ID-JAG,
//! draft-ietf-oauth-identity-assertion-authz-grant-04), a client's side, as
//! MCP's enterprise-managed authorization uses it: the user's token from the
//! enterprise's identity provider (an ID token, a SAML assertion, a refresh
//! token) exchanged there (RFC 8693) for an ID-JAG naming the MCP server's
//! authorization server, the client and the MCP server; the ID-JAG then
//! redeemed at that authorization server as a JWT-bearer grant (RFC 7523)
//! for an access token.
//!
//! What a client can check, it checks: that the identity provider issued an
//! ID-JAG for exactly what was asked (its issuer, the authorization server
//! as its sole audience, the client, the resource, no more scope than asked,
//! unexpired), and that the access token the authorization server gives for
//! it is a Bearer token for that resource with no more scope than the ID-JAG
//! carries. The ID-JAG's signature is the authorization server's to verify:
//! it came straight from the identity provider over TLS, and its keys are
//! the identity provider's arrangement with that server, not the client's.
const std = @import("std");
const aegis = @import("aegis");
const strand = @import("strand");
const clearance = @import("clearance");
const url = @import("url.zig");
const errors = @import("errors.zig");
const exchange = @import("exchange.zig");
const token = @import("token.zig");
const challenge = @import("challenge.zig");
const Scratch = @import("scratch.zig").Scratch;

/// The ID-JAG's media type, its header's `typ` (§3.1).
pub const typ = "oauth-id-jag+jwt";

/// What an ID-JAG is asked for.
pub const Request = struct {
    /// The identity provider's issuer identifier: the ID-JAG's `iss`.
    idp_issuer: []const u8,
    /// The user's token at the identity provider.
    subject_token: []const u8,
    /// Its type: `exchange.token_type.id_token`, `.saml2` or
    /// `.refresh_token`, as the identity provider takes them.
    subject_token_type: []const u8 = exchange.token_type.id_token,
    /// The MCP server's authorization server's issuer identifier: the
    /// exchange's `audience` and the ID-JAG's sole `aud`.
    audience: []const u8,
    /// The client's identifier at that authorization server: the ID-JAG's
    /// `client_id`.
    client_id: []const u8,
    /// The MCP server: the exchange's `resource` (RFC 8707) and the
    /// ID-JAG's.
    resource: []const u8,
    /// Space-separated, each scope once; none asked when null.
    scope: ?[]const u8 = null,
};

pub const RequestError = error{
    /// An issuer or the resource is not an HTTPS URL (or HTTP to loopback),
    /// the two issuers are one, a client ID or the subject token is empty,
    /// or the scope is not distinct scope tokens.
    InvalidRequest,
};

/// The token exchange that asks for an ID-JAG, checked first: sent with
/// `options` naming `request.resource`.
pub fn exchangeGrant(request: Request) RequestError!token.Grant {
    _ = url.issuer(request.idp_issuer) catch return error.InvalidRequest;
    _ = url.issuer(request.audience) catch return error.InvalidRequest;
    _ = url.endpoint(request.resource) catch return error.InvalidRequest;
    // The identity provider vouches to another server, never to itself.
    if (std.mem.eql(u8, request.idp_issuer, request.audience)) return error.InvalidRequest;
    if (blank(request.client_id) or blank(request.subject_token)) return error.InvalidRequest;
    if (request.scope) |s| if (!wellFormed(s)) return error.InvalidRequest;
    return .{ .token_exchange = .{
        .subject_token = request.subject_token,
        .subject_token_type = request.subject_token_type,
        .requested_token_type = exchange.token_type.id_jag,
        .audience = request.audience,
        .scope = request.scope,
    } };
}

/// An ID-JAG, checked against what was asked, owned. The assertion is a
/// credential: it lives in memory `deinit` wipes.
pub const Grant = struct {
    assertion: []const u8,
    /// The scope it carries, space-separated; null when it names none (the
    /// authorization server's policy decides).
    scope: ?[]const u8 = null,
    /// Its `exp`, in seconds since the epoch: redeem it before then.
    expires_at: i64,
    /// Private: holds the strings above.
    storage: aegis.SecretBytes,

    pub fn deinit(g: *Grant) void {
        g.storage.deinit();
        g.* = undefined;
    }

    /// Whether it has expired at `now`: a redemption would be refused.
    pub fn expired(g: *const Grant, at: std.Io.Timestamp) bool {
        return seconds(at) >= g.expires_at;
    }

    /// The JWT-bearer grant that redeems it. Only the assertion carries
    /// authority: naming the scope or resource again could undo what the
    /// identity provider narrowed (§4.4).
    pub fn redemption(g: *const Grant) token.Grant {
        return .{ .jwt_bearer = .{ .assertion = g.assertion } };
    }
};

/// The identity provider's answer.
pub const Response = union(enum) {
    granted: Grant,
    refused: errors.ErrorResponse,
};

pub const ReadOptions = struct {
    /// When the answer arrived: the ID-JAG's times are checked against it.
    now: std.Io.Timestamp,
    /// Clock skew forgiven on an `iat` in the future.
    leeway: clearance.jwt.Duration = .literal("60s"),
    max_bytes: aegis.units.Bytes(usize) = .literal("64KiB"),
};

pub const ReadError = exchange.ReadError || clearance.jwt.InspectError || error{
    /// The answer is not an ID-JAG: another `issued_token_type`, or a
    /// `token_type` other than `N_A`.
    NotIdJag,
    /// The ID-JAG names another client.
    WrongClient,
    /// It names another resource, several, or none.
    WrongResource,
    /// It carries more scope than was asked, or the answer's `scope` differs
    /// from its own, or a scope that is not distinct scope tokens.
    WrongScope,
    /// It carries `authorization_details` (RFC 9396), which nothing here
    /// asked for or can narrow.
    AuthorizationDetails,
};

/// The ID-JAG's own claims beyond the registered ones.
const Claims = struct {
    client_id: ?[]const u8 = null,
    resource: ?strand.json.Raw = null,
    scope: ?[]const u8 = null,
    authorization_details: ?strand.json.Raw = null,
};

/// Reads the identity provider's answer to `exchangeGrant(request)`: a 2xx
/// as an ID-JAG checked against `request`, any other status as the
/// provider's error.
pub fn readIssued(gpa: std.mem.Allocator, status: u16, body: []const u8, request: Request, options: ReadOptions) ReadError!Response {
    var issued = switch (try exchange.readResponse(gpa, status, body, .{ .now = options.now, .max_bytes = options.max_bytes })) {
        .refused => |e| return .{ .refused = e },
        .issued => |i| i,
    };
    defer issued.deinit();
    if (!std.mem.eql(u8, issued.issued_token_type, exchange.token_type.id_jag)) return error.NotIdJag;
    if (!std.ascii.eqlIgnoreCase(issued.token_type, "N_A")) return error.NotIdJag;

    const scratch = gpa.alloc(u8, clearance.jws.scratchLength(issued.token.len)) catch return error.OutOfMemory;
    defer {
        std.crypto.secureZero(u8, scratch);
        gpa.free(scratch);
    }
    const read = try clearance.jwt.inspect(Claims, issued.token, .{
        .issuer = request.idp_issuer,
        .audience = request.audience,
        .typ = typ,
        .required = .{ .iss = true, .sub = true, .aud = true, .exp = true, .iat = true, .jti = true },
        .max_bytes = options.max_bytes,
    }, options.now, scratch);
    const registered = read.registered;
    // Its sole audience: an assertion several servers would take is one any
    // of them could spend at another.
    if (registered.aud.values.len != 1) return error.WrongAudience;
    if (blank(registered.sub.?) or blank(registered.jti.?)) return error.MissingClaim;
    const leeway: i64 = options.leeway.raw();
    if (registered.iat.? > seconds(options.now) +| leeway) return error.TooOld;
    const claims = read.claims;
    var rest: std.heap.FixedBufferAllocator = .init(read.rest);
    if (!std.mem.eql(u8, claims.client_id orelse return error.MissingClaim, request.client_id)) return error.WrongClient;
    if (!soleResource(rest.allocator(), claims.resource orelse return error.WrongResource, request.resource)) return error.WrongResource;
    if (claims.authorization_details) |details| if (!emptyList(details)) return error.AuthorizationDetails;

    // What it carries: never more than asked, and what the answer says it
    // carries when it says.
    const carried = claims.scope orelse issued.scope;
    if (carried) |s| {
        if (!wellFormed(s)) return error.WrongScope;
        if (request.scope) |wanted| if (!subset(s, wanted)) return error.WrongScope;
    }
    if (claims.scope != null and issued.scope != null) {
        if (!wellFormed(issued.scope.?) or !sameSet(claims.scope.?, issued.scope.?)) return error.WrongScope;
    }

    const total = issued.token.len + if (carried) |s| s.len else 0;
    var storage = aegis.SecretBytes.init(gpa, total) catch return error.OutOfMemory;
    // unreachable: the capacity was just allocated at this length
    storage.resizeWithinCapacity(total) catch unreachable;
    const bytes = storage.exposeMut();
    @memcpy(bytes[0..issued.token.len], issued.token);
    var grant: Grant = .{ .assertion = bytes[0..issued.token.len], .expires_at = registered.exp.?, .storage = storage };
    if (carried) |s| {
        @memcpy(bytes[issued.token.len..], s);
        grant.scope = bytes[issued.token.len..];
    }
    return .{ .granted = grant };
}

pub const RedemptionError = token.ReadError || error{
    /// The access token names another resource, or several.
    WrongResource,
    /// It carries more scope than the ID-JAG, or a scope that is not
    /// distinct scope tokens.
    WrongScope,
    AuthorizationDetails,
};

const RedemptionWire = struct {
    resource: ?strand.json.Raw = null,
    authorization_details: ?strand.json.Raw = null,
};

/// Reads the authorization server's answer to `grant.redemption()`: a 2xx as
/// a Bearer token for `resource` (when the answer names one) with no more
/// scope than `grant` carries (the ID-JAG's when the answer names none), any
/// other status as the server's error. A refresh token is not kept: the
/// grant lasts as long as the identity provider vouches for the user, and a
/// new access token comes from a new ID-JAG (§4.4.3).
pub fn readRedemption(gpa: std.mem.Allocator, status: u16, body: []const u8, grant: *const Grant, resource: []const u8, options: token.ReadOptions) RedemptionError!token.Response {
    var response = try token.readResponse(gpa, status, body, .{
        .now = options.now,
        .requested_scope = grant.scope,
        .max_bytes = options.max_bytes,
    });
    const set = switch (response) {
        .refused => return response,
        .tokens => |*s| s,
    };
    errdefer set.deinit();
    {
        // The members a token set does not keep, read from the same body.
        var scratch: Scratch = undefined;
        try scratch.init(gpa, body.len);
        defer scratch.deinit();
        const wire = strand.json.parseLeaky(RedemptionWire, scratch.allocator(), body, .{
            .ignore_unknown_fields = true,
            .limits = .{ .depth = 16 },
        }) catch return error.InvalidResponse;
        if (wire.resource) |r| if (!soleResource(scratch.allocator(), r, resource)) return error.WrongResource;
        if (wire.authorization_details) |details| if (!emptyList(details)) return error.AuthorizationDetails;
    }
    if (set.scope) |s| if (!wellFormed(s)) return error.WrongScope;
    if (grant.scope) |carried| if (set.scope) |s| if (!subset(s, carried)) return error.WrongScope;
    if (set.refresh_token == null) return response;
    var kept = set.borrow();
    kept.refresh_token = null;
    const without = try token.TokenSet.init(gpa, kept);
    set.deinit();
    return .{ .tokens = without };
}

fn seconds(at: std.Io.Timestamp) i64 {
    return @intCast(@divFloor(at.nanoseconds, std.time.ns_per_s));
}

fn blank(text: []const u8) bool {
    return std.mem.trim(u8, text, " \t\r\n").len == 0;
}

/// Whether `raw` is `resource` alone: the string, or an array of it alone.
fn soleResource(arena: std.mem.Allocator, raw: strand.json.Raw, resource: []const u8) bool {
    if (raw.parse([]const u8, arena, .{})) |one| return std.mem.eql(u8, one, resource) else |_| {}
    const many = raw.parse([]const []const u8, arena, .{}) catch return false;
    return many.len == 1 and std.mem.eql(u8, many[0], resource);
}

/// Whether `raw` is an empty JSON array (or `null`): details present but
/// asking nothing.
fn emptyList(raw: strand.json.Raw) bool {
    const text = std.mem.trim(u8, raw.bytes, " \t\r\n");
    if (std.mem.eql(u8, text, "null")) return true;
    if (text.len < 2 or text[0] != '[' or text[text.len - 1] != ']') return false;
    return std.mem.trim(u8, text[1 .. text.len - 1], " \t\r\n").len == 0;
}

/// Whether `scope` is scope tokens (RFC 6749 §3.3) separated by single
/// spaces, each once.
fn wellFormed(scope: []const u8) bool {
    if (scope.len == 0) return false;
    var start: usize = 0;
    while (start <= scope.len) {
        const end = std.mem.findScalarPos(u8, scope, start, ' ') orelse scope.len;
        const s = scope[start..end];
        if (s.len == 0) return false;
        for (s) |c| if (c < 0x21 or c == 0x22 or c == 0x5c or c > 0x7e) return false;
        if (end < scope.len and challenge.contains(scope[end + 1 ..], s)) return false;
        start = end + 1;
    }
    return true;
}

/// Whether every scope of `inner` is one of `outer`'s.
fn subset(inner: []const u8, outer: []const u8) bool {
    var it = std.mem.tokenizeScalar(u8, inner, ' ');
    while (it.next()) |s| {
        var o = std.mem.tokenizeScalar(u8, outer, ' ');
        while (o.next()) |t| {
            if (std.mem.eql(u8, s, t)) break;
        } else return false;
    }
    return true;
}

fn sameSet(a: []const u8, b: []const u8) bool {
    return subset(a, b) and subset(b, a);
}

const testing = std.testing;
const cloak = @import("cloak");

const now_s: i64 = 1_800_000_000;
const now: std.Io.Timestamp = .{ .nanoseconds = now_s * std.time.ns_per_s };
const asked: Request = .{
    .idp_issuer = "https://idp.example",
    .subject_token = "eyJ.id.token",
    .audience = "https://as.example",
    .client_id = "mcp-client",
    .resource = "https://mcp.example/mcp",
    .scope = "files:read files:write",
};

/// An ID-JAG over `claims`, signed with RFC 8037's key, under `header_typ`.
fn jag(out: *std.Io.Writer, header_typ: []const u8, claims: anytype) !void {
    var der: [48]u8 = undefined;
    _ = try std.fmt.hexToBytes(der[0..16], "302e020100300506032b657004220420");
    _ = try std.base64.url_safe_no_pad.Decoder.decode(der[16..48], "nWGxne_9WmC6hEr0kuwsxERJxWl7MmkZcDusAxyuf2A");
    const key = try cloak.PrivateKey.parse(testing.allocator, &der, .{});
    defer key.deinit();
    try clearance.jwt.sign(testing.allocator, testing.io, out, .{ .typ = header_typ }, claims, .{ .private = .{ .alg = .eddsa, .key = key } });
}

/// The claims of a good ID-JAG for `asked`, each test changing one.
const JagClaims = struct {
    iss: []const u8 = "https://idp.example",
    sub: []const u8 = "u1",
    aud: []const u8 = "https://as.example",
    client_id: []const u8 = "mcp-client",
    jti: ?[]const u8 = "j1",
    iat: i64 = now_s,
    exp: i64 = now_s + 300,
    resource: []const u8 = "https://mcp.example/mcp",
    scope: ?[]const u8 = "files:read",
};
const good: JagClaims = .{};

/// The identity provider's answer carrying `assertion`, with `extra`
/// members.
fn answer(out: *std.Io.Writer.Allocating, assertion: []const u8, extra: []const u8) ![]const u8 {
    out.clearRetainingCapacity();
    try out.writer.print("{{\"access_token\":\"{s}\",\"issued_token_type\":\"urn:ietf:params:oauth:token-type:id-jag\",\"token_type\":\"N_A\"{s}}}", .{ assertion, extra });
    return out.written();
}

fn readWith(claims: anytype, header_typ: []const u8, extra: []const u8, request: Request) ReadError!Response {
    var t: std.Io.Writer.Allocating = .init(testing.allocator);
    defer t.deinit();
    jag(&t.writer, header_typ, claims) catch return error.OutOfMemory;
    var body: std.Io.Writer.Allocating = .init(testing.allocator);
    defer body.deinit();
    const text = answer(&body, t.written(), extra) catch return error.OutOfMemory;
    return readIssued(testing.allocator, 200, text, request, .{ .now = now });
}

test "the exchange asks for an ID-JAG for the server's authorization server and the resource" {
    const grant = try exchangeGrant(asked);
    try testing.expectEqualStrings(exchange.token_type.id_jag, grant.token_exchange.requested_token_type.?);
    try testing.expectEqualStrings("https://as.example", grant.token_exchange.audience.?);
    var same = asked;
    same.audience = asked.idp_issuer;
    try testing.expectError(error.InvalidRequest, exchangeGrant(same));
    var plain = asked;
    plain.idp_issuer = "http://idp.example";
    try testing.expectError(error.InvalidRequest, exchangeGrant(plain));
    var twice = asked;
    twice.scope = "a a";
    try testing.expectError(error.InvalidRequest, exchangeGrant(twice));
    var spaced = asked;
    spaced.scope = "a  b";
    try testing.expectError(error.InvalidRequest, exchangeGrant(spaced));
    var nobody = asked;
    nobody.client_id = " ";
    try testing.expectError(error.InvalidRequest, exchangeGrant(nobody));
}

test "an ID-JAG for what was asked is read; its scope narrowed, its expiry kept" {
    var response = try readWith(good, typ, ",\"scope\":\"files:read\",\"expires_in\":300", asked);
    defer response.granted.deinit();
    const grant = &response.granted;
    try testing.expectEqualStrings("files:read", grant.scope.?);
    try testing.expectEqual(now_s + 300, grant.expires_at);
    try testing.expect(!grant.expired(now));
    try testing.expect(grant.expired(.{ .nanoseconds = (now_s + 300) * std.time.ns_per_s }));
    try testing.expectEqualStrings(grant.assertion, grant.redemption().jwt_bearer.assertion);
    try testing.expectEqual(@as(?[]const u8, null), grant.redemption().jwt_bearer.scope);
}

test "an ID-JAG for anything else is refused" {
    var c = good;
    try testing.expectError(error.WrongType, readWith(c, "JWT", "", asked));
    c.iss = "https://other-idp.example";
    try testing.expectError(error.WrongIssuer, readWith(c, typ, "", asked));
    c = good;
    c.aud = "https://other-as.example";
    try testing.expectError(error.WrongAudience, readWith(c, typ, "", asked));
    c = good;
    c.client_id = "someone-else";
    try testing.expectError(error.WrongClient, readWith(c, typ, "", asked));
    c = good;
    c.resource = "https://other.example/mcp";
    try testing.expectError(error.WrongResource, readWith(c, typ, "", asked));
    c = good;
    c.scope = "files:read admin";
    try testing.expectError(error.WrongScope, readWith(c, typ, "", asked));
    c = good;
    c.exp = now_s;
    try testing.expectError(error.Expired, readWith(c, typ, "", asked));
    c = good;
    c.iat = now_s + 120;
    try testing.expectError(error.TooOld, readWith(c, typ, "", asked));
    // The answer says another scope than the token carries.
    try testing.expectError(error.WrongScope, readWith(good, typ, ",\"scope\":\"files:write\"", asked));

    const two_audiences = .{ .iss = good.iss, .sub = good.sub, .aud = [_][]const u8{ "https://as.example", "https://other-as.example" }, .client_id = good.client_id, .jti = good.jti, .iat = good.iat, .exp = good.exp, .resource = good.resource };
    try testing.expectError(error.WrongAudience, readWith(two_audiences, typ, "", asked));
    const two_resources = .{ .iss = good.iss, .sub = good.sub, .aud = good.aud, .client_id = good.client_id, .jti = good.jti, .iat = good.iat, .exp = good.exp, .resource = [_][]const u8{ "https://mcp.example/mcp", "https://x.example" } };
    try testing.expectError(error.WrongResource, readWith(two_resources, typ, "", asked));
    const one_in_array = .{ .iss = good.iss, .sub = good.sub, .aud = [_][]const u8{"https://as.example"}, .client_id = good.client_id, .jti = good.jti, .iat = good.iat, .exp = good.exp, .resource = [_][]const u8{"https://mcp.example/mcp"} };
    var ok = try readWith(one_in_array, typ, "", asked);
    ok.granted.deinit();
    c = good;
    c.jti = null;
    try testing.expectError(error.MissingClaim, readWith(c, typ, "", asked));
    c = good;
    c.sub = " ";
    try testing.expectError(error.MissingClaim, readWith(c, typ, "", asked));
    const details = .{ .iss = good.iss, .sub = good.sub, .aud = good.aud, .client_id = good.client_id, .jti = good.jti, .iat = good.iat, .exp = good.exp, .resource = good.resource, .authorization_details = [_]struct { type: []const u8 }{.{ .type = "x" }} };
    try testing.expectError(error.AuthorizationDetails, readWith(details, typ, "", asked));

    var body: std.Io.Writer.Allocating = .init(testing.allocator);
    defer body.deinit();
    try body.writer.writeAll("{\"access_token\":\"a.b.c\",\"issued_token_type\":\"urn:ietf:params:oauth:token-type:access_token\",\"token_type\":\"Bearer\"}");
    try testing.expectError(error.NotIdJag, readIssued(testing.allocator, 200, body.written(), asked, .{ .now = now }));
    const refused = try readIssued(testing.allocator, 400, "{\"error\":\"invalid_grant\"}", asked, .{ .now = now });
    try testing.expectEqual(errors.Code.invalid_grant, refused.refused.code);
}

test "the redemption's access token: for the resource, no more scope than the ID-JAG, no refresh token kept" {
    var granted = (try readWith(good, typ, "", asked)).granted;
    defer granted.deinit();
    const options: token.ReadOptions = .{ .now = now };
    var narrowed = try readRedemption(testing.allocator, 200, "{\"access_token\":\"at\",\"token_type\":\"Bearer\",\"expires_in\":60,\"refresh_token\":\"rt\",\"resource\":\"https://mcp.example/mcp\"}", &granted, asked.resource, options);
    defer narrowed.tokens.deinit();
    try testing.expectEqualStrings("at", narrowed.tokens.access_token);
    // The ID-JAG's scope when the answer names none.
    try testing.expectEqualStrings("files:read", narrowed.tokens.scope.?);
    try testing.expectEqual(@as(?[]const u8, null), narrowed.tokens.refresh_token);
    try testing.expectError(error.WrongScope, readRedemption(testing.allocator, 200, "{\"access_token\":\"at\",\"token_type\":\"Bearer\",\"scope\":\"files:read admin\"}", &granted, asked.resource, options));
    try testing.expectError(error.WrongResource, readRedemption(testing.allocator, 200, "{\"access_token\":\"at\",\"token_type\":\"Bearer\",\"resource\":[\"https://mcp.example/mcp\",\"x\"]}", &granted, asked.resource, options));
    try testing.expectError(error.AuthorizationDetails, readRedemption(testing.allocator, 200, "{\"access_token\":\"at\",\"token_type\":\"Bearer\",\"authorization_details\":[{}]}", &granted, asked.resource, options));
    try testing.expectError(error.UnsupportedTokenType, readRedemption(testing.allocator, 200, "{\"access_token\":\"at\",\"token_type\":\"DPoP\"}", &granted, asked.resource, options));
    const refused = try readRedemption(testing.allocator, 400, "{\"error\":\"invalid_grant\"}", &granted, asked.resource, options);
    try testing.expectEqual(errors.Code.invalid_grant, refused.refused.code);
}

test "scope tokens: single spaces, the allowed characters, each once" {
    try testing.expect(wellFormed("a b:c d/e"));
    try testing.expect(!wellFormed(""));
    try testing.expect(!wellFormed("a  b"));
    try testing.expect(!wellFormed(" a"));
    try testing.expect(!wellFormed("a "));
    try testing.expect(!wellFormed("a b a"));
    try testing.expect(!wellFormed("a\"b"));
    try testing.expect(!wellFormed("a\\b"));
    try testing.expect(subset("a", "b a"));
    try testing.expect(!subset("a c", "b a"));
    try testing.expect(sameSet("a b", "b a"));
}
