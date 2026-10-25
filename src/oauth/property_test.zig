//! Properties of every OAuth parser of untrusted input, held to a model. Run
//! seeded in every test run, and by the fuzzer under `bay properties --fuzz`.
const std = @import("std");
const shake = @import("shakedown");
const oauth = @import("../oauth.zig");
const form = @import("uplink.wire").form;
const aegis = @import("aegis");
const clearance = @import("clearance");

const as_documents = [_][]const u8{
    "{\"issuer\":\"https://as.example\",\"token_endpoint\":\"https://as.example/token\",\"code_challenge_methods_supported\":[\"S256\"],\"authorization_response_iss_parameter_supported\":true}",
    "{\"issuer\":\"https://as.example\",\"scopes_supported\":[\"a\",\"b\"],\"jwks_uri\":\"https://as.example/jwks\"}",
};

/// Any bytes as authorization server metadata: refused, or read with the
/// issuer asked for and every endpoint HTTPS.
fn anyAuthorizationServer(_: void, c: *shake.Case) !void {
    var buffer: [512]u8 = undefined;
    const input = shake.gen.mutated(c.source, &buffer, &as_documents);
    var m = oauth.metadata.readAuthorizationServer(c.gpa, input, "https://as.example", .{}) catch return;
    defer m.deinit();
    if (!std.mem.eql(u8, m.value.issuer, "https://as.example")) return error.WrongIssuer;
    if (m.value.token_endpoint) |e| _ = try oauth.url.endpoint(e);
    if (m.value.jwks_uri) |e| _ = try oauth.url.endpoint(e);
}

test "any bytes are read as authorization server metadata for the issuer asked, or refused" {
    try shake.check(std.testing.allocator, {}, anyAuthorizationServer, .{ .cases = 1000 });
}

/// Any bytes as protected resource metadata: refused, or read for the
/// resource asked.
fn anyProtectedResource(_: void, c: *shake.Case) !void {
    var buffer: [512]u8 = undefined;
    const input = shake.gen.mutated(c.source, &buffer, &.{ "{\"resource\":\"https://rs.example/mcp\",\"authorization_servers\":[\"https://as.example\"]}", "{\"resource\":\"https://rs.example\"}" });
    var m = oauth.metadata.readProtectedResource(c.gpa, input, "https://rs.example/mcp", .ancestor, .{}) catch return;
    defer m.deinit();
    if (!oauth.url.resourceMatches(m.value.resource, "https://rs.example/mcp", .ancestor)) return error.WrongResource;
    for (m.value.authorization_servers orelse &.{}) |s| _ = try oauth.url.issuer(s);
}

test "any bytes are read as protected resource metadata for the resource asked, or refused" {
    try shake.check(std.testing.allocator, {}, anyProtectedResource, .{ .cases = 1000 });
}

/// Any bytes as a token response, under any status: tokens with a non-empty
/// access token, the server's error, or refused; nothing left owned.
fn anyTokenResponse(_: void, c: *shake.Case) !void {
    var buffer: [512]u8 = undefined;
    const input = shake.gen.mutated(c.source, &buffer, &.{
        "{\"access_token\":\"a\\u0062\",\"token_type\":\"Bearer\",\"expires_in\":3600,\"refresh_token\":\"r\",\"scope\":\"s\"}",
        "{\"error\":\"invalid_grant\",\"error_description\":\"used\"}",
    });
    const status: u16 = if (shake.gen.boolean(c.source)) 200 else 400;
    var response = oauth.token.readResponse(c.gpa, status, input, .{ .now = .{ .nanoseconds = 0 }, .previous_refresh_token = "old" }) catch return;
    switch (response) {
        .tokens => |*set| {
            defer set.deinit();
            if (set.access_token.len == 0) return error.EmptyToken;
            if (set.refresh_token == null) return error.RefreshTokenLost;
        },
        .refused => |e| if (e.name.len == 0) return error.EmptyError,
    }
}

test "any bytes are read as a token response, the server's error, or refused" {
    try shake.check(std.testing.allocator, {}, anyTokenResponse, .{ .cases = 1000 });
}

/// Any bytes as a device authorization answer, under any status: codes a
/// person can be shown (printable, at a URI OAuth may send them to) with an
/// interval of at least a second, the server's error, or refused.
fn anyDeviceAuthorization(_: void, c: *shake.Case) !void {
    var buffer: [512]u8 = undefined;
    const input = shake.gen.mutated(c.source, &buffer, &.{
        "{\"device_code\":\"GmRhmhcxhwAzkoEqiMEg\",\"user_code\":\"WDJB-MJHT\",\"verification_uri\":\"https://example.com/device\",\"verification_uri_complete\":\"https://example.com/device?user_code=WDJB-MJHT\",\"expires_in\":1800,\"interval\":5}",
        "{\"device_code\":\"d\",\"user_code\":\"GQVQ-JKEC\",\"verification_url\":\"https://www.google.com/device\",\"expires_in\":1800}",
        "{\"error\":\"invalid_client\"}",
    });
    const status: u16 = if (shake.gen.boolean(c.source)) 200 else 400;
    var response = oauth.device.readAuthorization(c.gpa, status, input, .{ .now = .{ .nanoseconds = 0 } }) catch return;
    switch (response) {
        .authorization => |*a| {
            defer a.deinit();
            if (a.device_code.len == 0 or a.user_code.len == 0 or a.user_code.len > oauth.device.max_user_code) return error.BadCode;
            for (a.user_code) |byte| if (byte < 0x20 or byte == 0x7f) return error.ControlByte;
            _ = try oauth.url.endpoint(a.verification_uri);
            if (a.verification_uri_complete) |u| _ = try oauth.url.endpoint(u);
            if (a.interval < 1 or a.expires_at < 0) return error.BadTimes;
        },
        .refused => |e| if (e.name.len == 0) return error.EmptyError,
    }
}

test "any bytes are read as a device authorization, the server's error, or refused" {
    try shake.check(std.testing.allocator, {}, anyDeviceAuthorization, .{ .cases = 1000 });
}

/// Any bytes as a revocation answer under any status: a 2xx is always the
/// token revoked, anything else the server's error or refused.
fn anyRevocation(_: void, c: *shake.Case) !void {
    var buffer: [512]u8 = undefined;
    const input = shake.gen.mutated(c.source, &buffer, &.{ "", "{\"error\":\"unsupported_token_type\",\"error_description\":\"no\"}" });
    const statuses = [_]u16{ 200, 204, 400, 401, 503 };
    const status = shake.gen.oneOf(c.source, u16, &statuses);
    const response = oauth.revocation.readResponse(status, input, .{}) catch {
        if (status < 300) return error.SuccessRefused;
        return;
    };
    switch (response) {
        .revoked => if (status >= 300) return error.ErrorTakenForSuccess,
        .refused => |e| if (status < 300 or e.name.len == 0) return error.WrongRefusal,
    }
}

test "any answer to a revocation is revoked on a 2xx, else the server's error or refused" {
    try shake.check(std.testing.allocator, {}, anyRevocation, .{ .cases = 1000 });
}

/// Any bytes as a push's answer under any status: a `request_uri` that can
/// go back into a URL (printable, bounded) with a future expiry, the
/// server's error, or refused.
fn anyPushed(_: void, c: *shake.Case) !void {
    var buffer: [512]u8 = undefined;
    const input = shake.gen.mutated(c.source, &buffer, &.{ "{\"request_uri\":\"urn:ietf:params:oauth:request_uri:6esc_11ACC5bwc014ltc14eY22c\",\"expires_in\":60}", "{\"error\":\"invalid_request\"}" });
    const status: u16 = if (shake.gen.boolean(c.source)) 201 else 400;
    const response = oauth.par.readResponse(status, input, .{ .now = .{ .nanoseconds = 0 } }) catch return;
    switch (response) {
        .pushed => |p| {
            const uri = p.request_uri.slice();
            if (uri.len == 0 or p.request_uri.cut or p.expires_at <= 0) return error.BadPush;
            for (uri) |ch| if (ch < 0x21 or ch > 0x7e) return error.Unprintable;
        },
        .refused => |e| if (e.name.len == 0) return error.EmptyError,
    }
}

test "any bytes are read as a push's request_uri, the server's error, or refused" {
    try shake.check(std.testing.allocator, {}, anyPushed, .{ .cases = 1000 });
}

/// Any bytes as a UserInfo answer under any status: claims of the subject
/// expected and no other, the resource's refusal, or refused.
fn anyUserInfo(_: void, c: *shake.Case) !void {
    var buffer: [512]u8 = undefined;
    const input = shake.gen.mutated(c.source, &buffer, &.{ "{\"sub\":\"248289761001\",\"name\":\"Jane Doe\",\"email_verified\":true,\"address\":{\"country\":\"US\"},\"updated_at\":1311280970}", "{\"error\":\"insufficient_scope\"}" });
    var arena: std.heap.ArenaAllocator = .init(c.gpa);
    defer arena.deinit();
    const status: u16 = if (shake.gen.boolean(c.source)) 200 else 403;
    const challenges: []const []const u8 = if (shake.gen.boolean(c.source)) &.{"Bearer error=\"invalid_token\""} else &.{};
    const response = oauth.userinfo.readResponse(oauth.userinfo.Standard, arena.allocator(), status, "application/json", challenges, input, .{ .subject = "248289761001" }, .{}) catch return;
    switch (response) {
        .claims => |claims| {
            if (status != 200) return error.ClaimsFromAnError;
            if (!std.mem.eql(u8, claims.sub, "248289761001")) return error.AnotherUser;
        },
        .refused => |e| if (status == 200 or e.name.len == 0) return error.WrongRefusal,
    }
}

test "any bytes are read as the expected user's claims, the resource's refusal, or refused" {
    try shake.check(std.testing.allocator, {}, anyUserInfo, .{ .cases = 1000 });
}

/// Any bytes as a registration response.
fn anyRegistration(_: void, c: *shake.Case) !void {
    var buffer: [512]u8 = undefined;
    const input = shake.gen.mutated(c.source, &buffer, &.{
        "{\"client_id\":\"c\",\"client_secret\":\"s\",\"client_secret_expires_at\":0,\"grant_types\":[\"authorization_code\"]}",
        "{\"error\":\"invalid_redirect_uri\"}",
    });
    var response = oauth.registration.readResponse(c.gpa, if (shake.gen.boolean(c.source)) 201 else 400, input, .{}) catch return;
    switch (response) {
        .registered => |*r| {
            defer r.deinit();
            if (r.client_id.len == 0) return error.EmptyClientId;
        },
        .refused => {},
    }
}

test "any bytes are read as a registration, the server's error, or refused" {
    try shake.check(std.testing.allocator, {}, anyRegistration, .{ .cases = 1000 });
}

/// Any bytes as an introspection response.
fn anyIntrospection(_: void, c: *shake.Case) !void {
    var buffer: [512]u8 = undefined;
    const input = shake.gen.mutated(c.source, &buffer, &.{
        "{\"active\":true,\"scope\":\"a b\",\"aud\":[\"x\",\"y\"],\"exp\":1,\"cnf\":{\"jkt\":\"t\"}}",
        "{\"active\":false}",
    });
    var arena: std.heap.ArenaAllocator = .init(c.gpa);
    defer arena.deinit();
    const response = oauth.introspection.readResponse(arena.allocator(), 200, input, .{}) catch return;
    const i = response.introspected;
    if (!i.active and (i.scope != null or i.aud.len != 0)) return error.InactiveWithClaims;
}

test "any bytes are read as an introspection, or refused" {
    try shake.check(std.testing.allocator, {}, anyIntrospection, .{ .cases = 1000 });
}

/// Any bytes as a callback query: a code only under the expected state and
/// issuer.
fn anyCallback(_: void, c: *shake.Case) !void {
    var buffer: [256]u8 = undefined;
    const input = shake.gen.mutated(c.source, &buffer, &.{
        "code=abc&state=s1&iss=https%3A%2F%2Fas.example",
        "error=access_denied&error_description=no&state=s1",
    });
    var scratch: [256]u8 = undefined;
    const expected: oauth.authorize.Expected = .{ .state = "s1", .issuer = "https://as.example", .issuer_required = shake.gen.boolean(c.source) };
    const callback = oauth.authorize.readCallback(input, expected, &scratch) catch return;
    // Decoded again by hand: one `state`, the request's; `iss`, when there or
    // required, the issuer.
    var copy: [256]u8 = undefined;
    const text = copy[0..input.len];
    @memcpy(text, input);
    var states: usize = 0;
    var issuers: usize = 0;
    var pieces = std.mem.splitScalar(u8, text, '&');
    while (pieces.next()) |piece_const| {
        if (piece_const.len == 0) continue;
        const at = @intFromPtr(piece_const.ptr) - @intFromPtr(text.ptr); // safe: the split gives slices of `text`
        const piece = text[at..][0..piece_const.len];
        const eq = std.mem.findScalar(u8, piece, '=') orelse piece.len;
        const name = form.decode(piece[0..eq]);
        const value = if (eq == piece.len) "" else form.decode(piece[eq + 1 ..]);
        if (std.mem.eql(u8, name, "state")) {
            if (!std.mem.eql(u8, value, "s1")) return error.WrongState;
            states += 1;
        }
        if (std.mem.eql(u8, name, "iss")) {
            if (!std.mem.eql(u8, value, "https://as.example")) return error.WrongIssuer;
            issuers += 1;
        }
    }
    if (states != 1) return error.AcceptedWithoutState;
    if (expected.issuer_required and issuers != 1) return error.AcceptedWithoutIssuer;
    switch (callback) {
        .code => |code| if (code.len == 0) return error.EmptyCode,
        .refused => {},
    }
}

test "any query is a callback only under the request's state and issuer" {
    try shake.check(std.testing.allocator, {}, anyCallback, .{ .cases = 2000 });
}

/// Any bytes as `WWW-Authenticate`: a Bearer challenge, none, or refused; a
/// challenge written from what was read reads back the same.
fn anyChallenge(_: void, c: *shake.Case) !void {
    var buffer: [256]u8 = undefined;
    const input = shake.gen.mutated(c.source, &buffer, &.{
        "Bearer error=\"insufficient_scope\", scope=\"a b\", resource_metadata=\"https://rs.example/m\"",
        "Basic realm=\"x\", Bearer realm=\"y\"",
    });
    var arena: std.heap.ArenaAllocator = .init(c.gpa);
    defer arena.deinit();
    const read = (oauth.challenge.read(arena.allocator(), &.{input}) catch return) orelse return;
    var out: [512]u8 = undefined;
    var w: std.Io.Writer = .fixed(&out);
    var rewritten = read;
    if (rewritten.@"error" == .other) rewritten.@"error" = null;
    oauth.challenge.write(&w, rewritten) catch return;
    const again = (try oauth.challenge.read(arena.allocator(), &.{w.buffered()})) orelse return error.ChallengeLost;
    inline for (.{ "realm", "scope", "resource_metadata", "error_description" }) |name| {
        const a: ?[]const u8 = @field(rewritten, name);
        const b: ?[]const u8 = @field(again, name);
        if ((a == null) != (b == null)) return error.ParameterLost;
        if (a) |x| if (!std.mem.eql(u8, x, b.?)) return error.ParameterChanged;
    }
}

test "any bytes are read as a Bearer challenge that writes back the same, or refused" {
    try shake.check(std.testing.allocator, {}, anyChallenge, .{ .cases = 2000 });
}

/// Any bytes as an `Authorization` value: a token only when the value is
/// `Bearer` or `DPoP`, spaces, and a b64token, which is then a slice of the
/// value.
fn anyAuthorization(_: void, c: *shake.Case) !void {
    var buffer: [128]u8 = undefined;
    const input = shake.gen.mutated(c.source, &buffer, &.{ "Bearer mF_9.B5f-4.1JqM", "bearer  abc==", "Basic dXNlcjpwdw==", "DPoP Kz~8mXK1EalYznwH-LC-1fBAo.4Ljp~zsPE_NeO.gxU" });
    switch (oauth.bearer.credentials(input)) {
        .none, .malformed => {},
        .token => |presented| {
            const t = presented.token;
            const prefix: []const u8 = if (presented.scheme == .bearer) "bearer " else "dpop ";
            if (!std.ascii.startsWithIgnoreCase(input, prefix)) return error.WrongScheme;
            if (!std.mem.endsWith(u8, input, t)) return error.NotTheValue;
            var seen_pad = false;
            for (t) |ch| {
                if (ch == '=') {
                    seen_pad = true;
                } else if (seen_pad or !(std.ascii.isAlphanumeric(ch) or std.mem.findScalar(u8, "-._~+/", ch) != null)) return error.NotB64Token;
            }
        },
    }
}

test "any Authorization value gives a token only as RFC 6750's b64token, Bearer or DPoP" {
    try shake.check(std.testing.allocator, {}, anyAuthorization, .{ .cases = 2000 });
}

/// Any bytes as a token exchange's answer: the issued token with its types,
/// the server's error, or refused; nothing left owned.
fn anyExchangeResponse(_: void, c: *shake.Case) !void {
    var buffer: [512]u8 = undefined;
    const input = shake.gen.mutated(c.source, &buffer, &.{
        "{\"access_token\":\"a.b\\u002ec\",\"issued_token_type\":\"urn:ietf:params:oauth:token-type:id-jag\",\"token_type\":\"N_A\",\"expires_in\":300,\"scope\":\"s\",\"refresh_token\":\"r\"}",
        "{\"error\":\"insufficient_user_authentication\",\"error_description\":\"again\"}",
    });
    const status: u16 = if (shake.gen.boolean(c.source)) 200 else 400;
    var response = oauth.exchange.readResponse(c.gpa, status, input, .{ .now = .{ .nanoseconds = 0 } }) catch return;
    switch (response) {
        .issued => |*i| {
            defer i.deinit();
            if (i.token.len == 0 or i.issued_token_type.len == 0 or i.token_type.len == 0) return error.EmptyMember;
        },
        .refused => |e| if (e.name.len == 0) return error.EmptyError,
    }
}

test "any bytes are read as a token exchange's answer, the server's error, or refused" {
    try shake.check(std.testing.allocator, {}, anyExchangeResponse, .{ .cases = 1000 });
}

const jag_request: oauth.id_jag.Request = .{
    .idp_issuer = "https://idp.example",
    .subject_token = "id",
    .audience = "https://as.example",
    .client_id = "mcp-client",
    .resource = "https://mcp.example/mcp",
    .scope = "a b",
};
const jag_now_s: i64 = 1_800_000_000;

/// Any answer from an identity provider, built around a good ID-JAG (signed
/// with HS256: the client does not verify it) and mutated: an ID-JAG only
/// for what was asked, never more scope, unexpired; or the provider's error,
/// or refused.
fn anyIdJagAnswer(_: void, c: *shake.Case) !void {
    const secret: [32]u8 = @splat(3);
    var assertion: std.Io.Writer.Allocating = .init(c.gpa);
    defer assertion.deinit();
    try clearance.jwt.sign(c.gpa, std.testing.io, &assertion.writer, .{ .typ = oauth.id_jag.typ }, .{
        .iss = jag_request.idp_issuer,
        .sub = "u",
        .aud = jag_request.audience,
        .client_id = jag_request.client_id,
        .jti = "j",
        .iat = jag_now_s,
        .exp = jag_now_s + 300,
        .resource = jag_request.resource,
        .scope = "a",
    }, .{ .hmac = .{ .alg = .hs256, .secret = &secret } });
    var seed: std.Io.Writer.Allocating = .init(c.gpa);
    defer seed.deinit();
    try seed.writer.print("{{\"access_token\":\"{s}\",\"issued_token_type\":\"urn:ietf:params:oauth:token-type:id-jag\",\"token_type\":\"N_A\",\"scope\":\"a\"}}", .{assertion.written()});
    var buffer: [1024]u8 = undefined;
    const input = shake.gen.mutated(c.source, &buffer, &.{ seed.written(), "{\"error\":\"invalid_grant\"}" });
    const status: u16 = if (shake.gen.boolean(c.source)) 200 else 400;
    const now: std.Io.Timestamp = .{ .nanoseconds = jag_now_s * std.time.ns_per_s };
    var response = oauth.id_jag.readIssued(c.gpa, status, input, jag_request, .{ .now = now }) catch return;
    switch (response) {
        .granted => |*g| {
            defer g.deinit();
            if (g.expired(now)) return error.ExpiredGranted;
            if (g.scope) |s| {
                var it = std.mem.tokenizeScalar(u8, s, ' ');
                while (it.next()) |one| if (!oauth.challenge.contains(jag_request.scope.?, one)) return error.ScopeWidened;
            }
            var scratch: [2048]u8 = undefined;
            const read = try clearance.jwt.inspect(struct { client_id: []const u8 }, g.assertion, .{ .issuer = jag_request.idp_issuer, .audience = jag_request.audience, .typ = oauth.id_jag.typ }, now, &scratch);
            if (!std.mem.eql(u8, read.claims.client_id, jag_request.client_id)) return error.OtherClient;
        },
        .refused => {},
    }
}

test "any identity provider's answer is an ID-JAG for what was asked, its error, or refused" {
    try shake.check(std.testing.allocator, {}, anyIdJagAnswer, .{ .cases = 1000 });
}

/// Any answer to a redemption: a Bearer token with no refresh token and no
/// more scope than the ID-JAG's, the server's error, or refused.
fn anyRedemption(_: void, c: *shake.Case) !void {
    var buffer: [512]u8 = undefined;
    const input = shake.gen.mutated(c.source, &buffer, &.{
        "{\"access_token\":\"at\",\"token_type\":\"Bearer\",\"expires_in\":60,\"scope\":\"a\",\"refresh_token\":\"r\",\"resource\":\"https://mcp.example/mcp\"}",
        "{\"access_token\":\"at\",\"token_type\":\"bearer\",\"resource\":[\"https://mcp.example/mcp\"],\"authorization_details\":[]}",
        "{\"error\":\"invalid_grant\"}",
    });
    var grant: oauth.id_jag.Grant = .{ .assertion = "", .scope = "a b", .expires_at = jag_now_s + 300, .storage = try aegis.SecretBytes.init(c.gpa, 0) };
    defer grant.deinit();
    const status: u16 = if (shake.gen.boolean(c.source)) 200 else 400;
    var response = oauth.id_jag.readRedemption(c.gpa, status, input, &grant, jag_request.resource, .{ .now = .{ .nanoseconds = 0 } }) catch return;
    switch (response) {
        .tokens => |*set| {
            defer set.deinit();
            if (set.refresh_token != null) return error.RefreshTokenKept;
            var it = std.mem.tokenizeScalar(u8, set.scope orelse "", ' ');
            while (it.next()) |one| if (!oauth.challenge.contains(grant.scope.?, one)) return error.ScopeWidened;
        },
        .refused => {},
    }
}

test "any answer to a redemption is a Bearer token within the ID-JAG's scope, the server's error, or refused" {
    try shake.check(std.testing.allocator, {}, anyRedemption, .{ .cases = 1000 });
}
