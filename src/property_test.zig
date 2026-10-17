//! Properties of every parser of untrusted input, held to a model. Run seeded
//! in every test run, and by the fuzzer under `bay properties --fuzz`.
const std = @import("std");
const shake = @import("shakedown");
const jws = @import("jws.zig");
const jwt = @import("jwt.zig");
const jwk = @import("jwk.zig");
const Key = @import("Key.zig");
const Algorithm = @import("Algorithm.zig").Algorithm;

const all = std.enums.values(Algorithm);

const tokens = [_][]const u8{
    "eyJhbGciOiJFZERTQSJ9.RXhhbXBsZSBvZiBFZDI1NTE5IHNpZ25pbmc.hgyY0il_MGCjP0JzlnLWG1PPOt7-09PGcvMg3AIbQR6dWbhijcNR4ki4iylGjg5BhVsPt9g7sVvpAr_MuM0KAg",
    "eyJhbGciOiJIUzI1NiIsImtpZCI6ImtpZC1hZXMtc2lnbiJ9.Zm9v.TD37p4c_0jmreSrBSDmE0F3mYSPtkZ3WrSyI5wb_KTg",
    "eyJhbGciOiJub25lIn0.cGF5bG9hZA.",
    "eyJhbGciOiJIUzI1NiIsImNyaXQiOlsiZXhwIl0sImV4cCI6MX0.cA.",
};

const sets = [_][]const u8{
    "{\"keys\":[{\"kty\":\"OKP\",\"crv\":\"Ed25519\",\"x\":\"11qYAYKxCrfVS_7TyWQHOg7hcvPapiMlrwIaaPcHURo\",\"kid\":\"ed\"}]}",
    "{\"kty\":\"oct\",\"k\":\"AyM1SysPpbyDfgZld3umj1qzKObwVMkoqQ-EstJQLr_T-1qS0gZH75aKtMN3Yj0iPS4hcgUuTwjAzZr1Z9CAow\",\"alg\":\"HS256\"}",
    "{\"kty\":\"EC\",\"crv\":\"P-256\",\"x\":\"f83OJ3D2xF1Bg8vub9tLe1gHMzV76e8Tus9uPHvRVEU\",\"y\":\"x_FEzRu9m36HLN_tue659LNpXW6pCyStikYjKIWI5a0\"}",
};

/// Any bytes as a token: refused or verified, never more; a verified token's
/// payload is inside the scratch and its algorithm one the key fits.
fn anyToken(_: void, c: *shake.Case) !void {
    var buffer: [512]u8 = undefined;
    const input = shake.gen.mutated(c.source, &buffer, &tokens);
    var set = try jwk.KeySet.parse(c.gpa, sets[0], .{});
    defer set.deinit();
    const secret: [64]u8 = @splat(1);
    const keys = [_]Key{ set.keys[0], Key.hmac(&secret) };
    var scratch: [jws.scratchLength(512)]u8 = undefined;
    const verified = jws.verify(input, &keys, .{ .algorithms = all }, &scratch) catch return;
    if (!verified.key.fits(verified.header.alg)) return error.KeyDoesNotFit;
    const start = @intFromPtr(&scratch);
    const at = @intFromPtr(verified.payload.ptr);
    if (verified.payload.len > 0 and (at < start or at + verified.payload.len > start + scratch.len)) return error.PayloadOutsideScratch;
}

test "any bytes are verified only as a token their key fits, or refused" {
    try shake.check(std.testing.allocator, {}, anyToken, .{ .cases = 2000 });
}

/// Any bytes as a key set: refused or read, every key read one that fits some
/// algorithm, and none left owned after deinit (the test allocator checks).
fn anyKeySet(_: void, c: *shake.Case) !void {
    var buffer: [512]u8 = undefined;
    const input = shake.gen.mutated(c.source, &buffer, &sets);
    var set = jwk.KeySet.parse(c.gpa, input, .{ .secrets = true }) catch return;
    defer set.deinit();
    for (set.keys) |key| {
        var fits = false;
        for (all) |alg| fits = fits or key.fits(alg);
        if (!fits and key.use != .enc) return error.KeyFitsNothing;
        _ = jwk.thumbprint(key);
    }
}

test "any bytes are read as a key set of usable keys, or refused" {
    try shake.check(std.testing.allocator, {}, anyKeySet, .{ .cases = 2000 });
}

/// Any claims under a valid signature: accepted or refused by a named check,
/// never a crash.
fn anyClaims(_: void, c: *shake.Case) !void {
    var buffer: [256]u8 = undefined;
    const claims = shake.gen.mutated(c.source, &buffer, &.{ "{\"exp\":1800000000,\"aud\":[\"a\"],\"iss\":\"x\"}", "{\"nbf\":1.5,\"iat\":-3}" });
    const secret: [32]u8 = @splat(9);
    var out: std.Io.Writer.Allocating = .init(c.gpa);
    defer out.deinit();
    try jws.sign(c.gpa, std.testing.io, &out.writer, .{}, claims, .{ .hmac = .{ .alg = .hs256, .secret = &secret } });
    const scratch = try c.gpa.alloc(u8, jws.scratchLength(out.written().len));
    defer c.gpa.free(scratch);
    _ = jwt.verify(void, out.written(), &.{Key.hmac(&secret)}, .{ .algorithms = &.{.hs256}, .audience = "a" }, .{ .nanoseconds = 0 }, scratch) catch |err| switch (err) {
        error.InvalidClaims, error.MissingClaim, error.WrongAudience, error.Expired, error.NotYetValid => return,
        else => return err,
    };
}

test "any claims under a good signature are accepted or refused by a claim check" {
    try shake.check(std.testing.allocator, {}, anyClaims, .{ .cases = 1000 });
}

const oauth = @import("oauth.zig");
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
            if (r.client_secret != null and r.client_secret_expires_at == null) return error.SecretWithoutExpiry;
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
