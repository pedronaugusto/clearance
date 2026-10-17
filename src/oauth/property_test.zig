//! Properties of every OAuth parser of untrusted input, held to a model. Run
//! seeded in every test run, and by the fuzzer under `bay properties --fuzz`.
const std = @import("std");
const shake = @import("shakedown");
const oauth = @import("../oauth.zig");
const form = @import("uplink.wire").form;

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
/// `Bearer`, spaces, and a b64token, which is then a slice of the value.
fn anyAuthorization(_: void, c: *shake.Case) !void {
    var buffer: [128]u8 = undefined;
    const input = shake.gen.mutated(c.source, &buffer, &.{ "Bearer mF_9.B5f-4.1JqM", "bearer  abc==", "Basic dXNlcjpwdw==" });
    switch (oauth.bearer.bearerToken(input)) {
        .none, .malformed => {},
        .token => |t| {
            if (!std.ascii.startsWithIgnoreCase(input, "bearer ")) return error.NotBearer;
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

test "any Authorization value gives a token only as RFC 6750's b64token" {
    try shake.check(std.testing.allocator, {}, anyAuthorization, .{ .cases = 2000 });
}
