//! The flows end to end over loopback: an authorization server on uplink's
//! server in this process, uplink's client asking it.
const std = @import("std");
const uplink = @import("uplink");
const clearance = @import("clearance");
const cloak = @import("cloak");
const oauth = @import("../../oauth.zig");

const testing = std.testing;
const Io = std.Io;
const form = uplink.wire.form;

/// RFC 8037 A.1's Ed25519 key, PKCS#8, and its public JWK.
const ed25519_der_prefix = "302e020100300506032b657004220420";
const ed25519_d = "nWGxne_9WmC6hEr0kuwsxERJxWl7MmkZcDusAxyuf2A";
const ed25519_x = "11qYAYKxCrfVS_7TyWQHOg7hcvPapiMlrwIaaPcHURo";

/// An authorization server and a protected resource's metadata, serving on
/// 127.0.0.1 from a task of its own. What it saw and how often it was asked
/// are kept for the tests to check.
const Provider = struct {
    gpa: std.mem.Allocator,
    mutex: Io.Mutex = .init,
    http: uplink.Server,
    listener: Io.net.Server,
    serving: Io.Future(uplink.Server.ServeError!void),
    port: u16,
    base_buffer: [64]u8 = undefined,
    base: []const u8 = "",

    // Guarded by `mutex`.
    challenge: [43]u8 = undefined,
    redirect_uri_buffer: [128]u8 = undefined,
    redirect_uri: []const u8 = "",
    resource_seen: bool = false,
    refresh_token: []const u8 = "rt1",
    rotate: bool = true,
    jwks_kid: []const u8 = "k1",
    jwks_cache_control: []const u8 = "max-age=600",
    jwks_delay_ms: u32 = 0,
    jwks_fetches: u32 = 0,
    introspections: u32 = 0,
    token_requests: u32 = 0,

    fn start(p: *Provider, io: Io) !void {
        p.* = .{ .gpa = testing.allocator, .http = undefined, .listener = undefined, .serving = undefined, .port = 0 };
        p.listener = try (try Io.net.IpAddress.parse("127.0.0.1", 0)).listen(io, .{ .reuse_address = true });
        p.port = p.listener.socket.address.getPort();
        p.base = try std.mem.print(&p.base_buffer, "http://127.0.0.1:{d}", .{p.port});
        p.http = .init(testing.allocator, .{}, .init(p, handle));
        p.serving = io.concurrent(uplink.Server.serve, .{ &p.http, io, &p.listener }) catch return error.SkipZigTest;
    }

    fn stop(p: *Provider, io: Io) void {
        p.http.shutdown(io);
        // glint-ignore: Z026 -- serve ends with the shutdown; its result is not what the test checks
        p.serving.await(io) catch {};
        p.http.deinit(io);
        p.listener.deinit(io);
    }

    fn url(p: *const Provider, buffer: []u8, path: []const u8) []const u8 {
        return std.mem.print(buffer, "{s}{s}", .{ p.base, path }) catch unreachable; // unreachable: callers pass room for a URL
    }

    fn handle(p: *Provider, io: Io, request: *uplink.server.Request, response: *uplink.server.Response) anyerror!void {
        var arena_state: std.heap.ArenaAllocator = .init(p.gpa);
        defer arena_state.deinit();
        const arena = arena_state.allocator();
        const path = request.path;
        try response.header("Content-Type", "application/json");
        if (std.mem.eql(u8, path, "/.well-known/oauth-authorization-server")) {
            return response.send(io, try p.metadata(arena, p.base));
        }
        // An issuer with a path, found only at OpenID's appended location.
        if (std.mem.eql(u8, path, "/tenant/.well-known/openid-configuration")) {
            return response.send(io, try p.metadata(arena, try std.mem.concat(arena, u8, &.{ p.base, "/tenant" })));
        }
        // A document at the right place naming another issuer.
        if (std.mem.eql(u8, path, "/.well-known/oauth-authorization-server/evil")) {
            return response.send(io, try p.metadata(arena, p.base));
        }
        if (std.mem.eql(u8, path, "/.well-known/oauth-protected-resource")) {
            return response.send(io, try arena.print("{{\"resource\":\"{s}\",\"authorization_servers\":[\"{s}\"]}}", .{ p.base, p.base }));
        }
        if (std.mem.eql(u8, path, "/authorize")) return p.authorize(io, arena, request, response);
        if (std.mem.eql(u8, path, "/token")) return p.token(io, arena, request, response);
        if (std.mem.eql(u8, path, "/register")) {
            if (!std.mem.eql(u8, request.headers.get("authorization") orelse "", "Bearer initial")) {
                response.status = .unauthorized;
                return response.send(io, "{\"error\":\"invalid_token\"}");
            }
            response.status = .created;
            return response.send(io, "{\"client_id\":\"dyn-1\",\"client_secret\":\"s3cret\",\"client_secret_expires_at\":0,\"token_endpoint_auth_method\":\"client_secret_basic\"}");
        }
        if (std.mem.eql(u8, path, "/jwks")) {
            p.mutex.lockUncancelable(io);
            p.jwks_fetches += 1;
            const delay = p.jwks_delay_ms;
            const kid = p.jwks_kid;
            const cache = p.jwks_cache_control;
            p.mutex.unlock(io);
            if (delay != 0) try io.sleep(.fromMilliseconds(delay), .awake);
            try response.header("Cache-Control", cache);
            return response.send(io, try arena.print("{{\"keys\":[{{\"kty\":\"OKP\",\"crv\":\"Ed25519\",\"kid\":\"{s}\",\"x\":\"{s}\"}}]}}", .{ kid, ed25519_x }));
        }
        if (std.mem.eql(u8, path, "/introspect")) {
            const body = try request.collect(arena, io, .limited(4096));
            p.mutex.lockUncancelable(io);
            p.introspections += 1;
            p.mutex.unlock(io);
            const now = @divFloor(Io.Clock.real.now(io).nanoseconds, std.time.ns_per_s);
            const active = std.mem.eql(u8, field(arena, body, "token") orelse "", "good");
            if (!active) return response.send(io, "{\"active\":false}");
            return response.send(io, try arena.print("{{\"active\":true,\"scope\":\"mcp\",\"aud\":\"{s}\",\"exp\":{d}}}", .{ p.base, now + 3600 }));
        }
        response.status = .not_found;
        return response.send(io, "{}");
    }

    fn metadata(p: *Provider, arena: std.mem.Allocator, issuer: []const u8) ![]const u8 {
        return arena.print(
            \\{{"issuer":"{s}","authorization_endpoint":"{s}/authorize","token_endpoint":"{s}/token","registration_endpoint":"{s}/register",
            \\"jwks_uri":"{s}/jwks","introspection_endpoint":"{s}/introspect","code_challenge_methods_supported":["S256"],
            \\"grant_types_supported":["authorization_code","refresh_token","client_credentials"],"authorization_response_iss_parameter_supported":true}}
        , .{ issuer, p.base, p.base, p.base, p.base, p.base });
    }

    /// What a browser would do: the request read, and the redirect back
    /// with a code, the state and `iss`.
    fn authorize(p: *Provider, io: Io, arena: std.mem.Allocator, request: *uplink.server.Request, response: *uplink.server.Response) !void {
        const query = request.query orelse "";
        const challenge = field(arena, query, "code_challenge") orelse return error.NoChallenge;
        const redirect = field(arena, query, "redirect_uri") orelse return error.NoRedirect;
        const state = field(arena, query, "state") orelse return error.NoState;
        if (!std.mem.eql(u8, field(arena, query, "code_challenge_method") orelse "", "S256")) return error.NotS256;
        p.mutex.lockUncancelable(io);
        @memcpy(&p.challenge, challenge[0..43]);
        p.redirect_uri = p.redirect_uri_buffer[0..redirect.len];
        @memcpy(p.redirect_uri_buffer[0..redirect.len], redirect);
        p.resource_seen = std.mem.eql(u8, field(arena, query, "resource") orelse "", "https://rs.example/mcp");
        p.mutex.unlock(io);
        var location: std.Io.Writer.Allocating = .init(arena);
        try location.writer.print("{s}?", .{redirect});
        try form.encode(&location.writer, &.{
            .{ .name = "code", .value = "c0de" },
            .{ .name = "state", .value = state },
            .{ .name = "iss", .value = p.base },
        });
        response.status = .found;
        try response.header("Location", location.written());
        return response.send(io, "");
    }

    fn token(p: *Provider, io: Io, arena: std.mem.Allocator, request: *uplink.server.Request, response: *uplink.server.Response) !void {
        const body = try request.collect(arena, io, .limited(8192));
        p.mutex.lockUncancelable(io);
        defer p.mutex.unlock(io);
        p.token_requests += 1;
        const grant = field(arena, body, "grant_type") orelse "";
        if (std.mem.eql(u8, grant, "authorization_code")) {
            const verifier = field(arena, body, "code_verifier") orelse "";
            const expected = oauth.pkce.challengeOf(verifier);
            const ok = std.mem.eql(u8, field(arena, body, "code") orelse "", "c0de") and
                std.mem.eql(u8, &expected, &p.challenge) and
                std.mem.eql(u8, field(arena, body, "redirect_uri") orelse "", p.redirect_uri) and
                std.mem.eql(u8, field(arena, body, "resource") orelse "", "https://rs.example/mcp") and
                std.mem.eql(u8, field(arena, body, "client_id") orelse "", "app");
            if (!ok) return refuse(io, response, "invalid_grant");
            return response.send(io, "{\"access_token\":\"at1\",\"token_type\":\"Bearer\",\"expires_in\":3600,\"refresh_token\":\"rt1\",\"scope\":\"mcp\"}");
        }
        if (std.mem.eql(u8, grant, "refresh_token")) {
            if (!std.mem.eql(u8, field(arena, body, "refresh_token") orelse "", p.refresh_token)) return refuse(io, response, "invalid_grant");
            if (!p.rotate) return response.send(io, "{\"access_token\":\"at-kept\",\"token_type\":\"bearer\",\"expires_in\":3600}");
            p.refresh_token = "rt2";
            return response.send(io, "{\"access_token\":\"at2\",\"token_type\":\"Bearer\",\"expires_in\":3600,\"refresh_token\":\"rt2\"}");
        }
        if (std.mem.eql(u8, grant, "client_credentials")) {
            // RFC 6749 §4.4.2's client, `s6BhdRkqt3:7Fjfp0ZBr1KtDRbnfVdmIw`.
            if (!std.mem.eql(u8, request.headers.get("authorization") orelse "", "Basic czZCaGRSa3F0Mzo3RmpmcDBaQnIxS3REUmJuZlZkbUl3")) {
                response.status = .unauthorized;
                return response.send(io, "{\"error\":\"invalid_client\"}");
            }
            return response.send(io, "{\"access_token\":\"cc\",\"token_type\":\"bearer\",\"expires_in\":60,\"scope\":\"read\"}");
        }
        return refuse(io, response, "unsupported_grant_type");
    }

    fn refuse(io: Io, response: *uplink.server.Response, code: []const u8) !void {
        response.status = .bad_request;
        var buffer: [96]u8 = undefined;
        return response.send(io, try std.mem.print(&buffer, "{{\"error\":\"{s}\"}}", .{code}));
    }
};

/// The decoded value of `name` in a form or query, or null.
fn field(arena: std.mem.Allocator, text: []const u8, name: []const u8) ?[]const u8 {
    var it: form.Iterator = .init(text);
    while (it.next()) |pair| {
        const n = form.decode(arena.dupe(u8, pair.name) catch return null);
        if (std.mem.eql(u8, n, name)) return form.decode(arena.dupe(u8, pair.value) catch return null);
    }
    return null;
}

test "discovery: the issuer's locations in order, a 4xx trying the next, a wrong issuer refused" {
    const gpa = testing.allocator;
    const io = testing.io;
    var p: Provider = undefined;
    try p.start(io);
    defer p.stop(io);
    var http: uplink.Client = .init(gpa, .{});
    defer http.deinit(io);

    var server = try oauth.discover(gpa, io, &http, p.base, .{});
    defer server.deinit();
    var buffer: [128]u8 = undefined;
    try testing.expectEqualStrings(p.url(&buffer, "/token"), server.value.token_endpoint.?);

    // Two 404s, then OpenID's appended location.
    const tenant = try std.mem.concat(gpa, u8, &.{ p.base, "/tenant" });
    defer gpa.free(tenant);
    var at_tenant = try oauth.discover(gpa, io, &http, tenant, .{});
    defer at_tenant.deinit();
    try testing.expectEqualStrings(tenant, at_tenant.value.issuer);

    const evil = try std.mem.concat(gpa, u8, &.{ p.base, "/evil" });
    defer gpa.free(evil);
    try testing.expectError(error.IssuerMismatch, oauth.discover(gpa, io, &http, evil, .{}));
    const none = try std.mem.concat(gpa, u8, &.{ p.base, "/none" });
    defer gpa.free(none);
    try testing.expectError(error.NotFound, oauth.discover(gpa, io, &http, none, .{}));
    try testing.expectError(error.InvalidUrl, oauth.discover(gpa, io, &http, "http://as.example", .{}));

    // The resource's metadata: the inserted location 404s, the root names
    // the origin, which speaks for `/mcp` as an ancestor (MCP's rule).
    const mcp = try std.mem.concat(gpa, u8, &.{ p.base, "/mcp" });
    defer gpa.free(mcp);
    var resource = try oauth.discoverResource(gpa, io, &http, mcp, null, .ancestor, .{});
    defer resource.deinit();
    try testing.expectEqualStrings(p.base, resource.value.authorization_servers.?[0]);
    try testing.expectError(error.ResourceMismatch, oauth.discoverResource(gpa, io, &http, mcp, null, .exact, .{}));
    const named = try std.mem.concat(gpa, u8, &.{ p.base, "/.well-known/oauth-protected-resource" });
    defer gpa.free(named);
    var from_challenge = try oauth.discoverResource(gpa, io, &http, mcp, named, .ancestor, .{});
    from_challenge.deinit();

    // A step-up: the 403's challenge read from its lines, the scope widened.
    var arena: std.heap.ArenaAllocator = .init(gpa);
    defer arena.deinit();
    const fields: uplink.Headers = .init(&.{
        .{ .name = "WWW-Authenticate", .value = "Basic realm=\"x\"" },
        .{ .name = "www-authenticate", .value = "Bearer error=\"insufficient_scope\", scope=\"files:write\", resource_metadata=\"https://rs.example/m\"" },
    });
    const bearer = (try oauth.bearerChallenge(arena.allocator(), &fields)).?;
    try testing.expectEqual(oauth.errors.Code.insufficient_scope, bearer.@"error".?);
    var scope: [64]u8 = undefined;
    var w: std.Io.Writer = .fixed(&scope);
    try oauth.challenge.writeStepUp(&w, "files:read", bearer.scope.?);
    try testing.expectEqualStrings("files:read files:write", w.buffered());
}

test "the code flow: PKCE, state, iss and the resource carried to the token endpoint; then a refresh" {
    const gpa = testing.allocator;
    const io = testing.io;
    var p: Provider = undefined;
    try p.start(io);
    defer p.stop(io);
    var http: uplink.Client = .init(gpa, .{});
    defer http.deinit(io);
    var server = try oauth.discover(gpa, io, &http, p.base, .{});
    defer server.deinit();

    var url_out: std.Io.Writer.Allocating = .init(gpa);
    defer url_out.deinit();
    var flow = try oauth.AuthorizationFlow.begin(io, &server.value, .{
        .client_id = "app",
        .redirect_uri = "http://127.0.0.1:9/cb",
        .scope = "mcp",
        .resources = &.{"https://rs.example/mcp"},
        .require_pkce_listed = true,
    }, &url_out.writer);
    defer flow.deinit();

    // The browser: the server answers the authorization URL with a redirect.
    var answer = try http.send(io, .{ .url = url_out.written(), .redirects = .none });
    const location = try gpa.dupe(u8, answer.headers.get("location").?);
    defer gpa.free(location);
    answer.deinit(io);
    {
        p.mutex.lockUncancelable(io);
        defer p.mutex.unlock(io);
        try testing.expect(p.resource_seen);
    }

    const response = try flow.finish(gpa, io, &http, &server.value, .{ .id = "app" }, location, .{});
    var set = response.tokens;
    defer set.deinit();
    try testing.expectEqualStrings("at1", set.access_token);
    try testing.expectEqualStrings("mcp", set.scope.?);

    // A redirect forged for another state is refused before any request.
    try testing.expectError(error.StateMismatch, flow.finish(gpa, io, &http, &server.value, .{ .id = "app" }, "http://127.0.0.1:9/cb?code=c0de&state=other", .{}));
    // One from another server is refused by `iss` (RFC 9207).
    var forged: [256]u8 = undefined;
    const mixed = try std.mem.print(&forged, "http://127.0.0.1:9/cb?code=c0de&state={s}&iss=https%3A%2F%2Fevil.example", .{flow.state});
    try testing.expectError(error.IssuerMismatch, flow.finish(gpa, io, &http, &server.value, .{ .id = "app" }, mixed, .{}));

    var refreshed = try oauth.refresh(gpa, io, &http, &server.value, .{ .id = "app" }, &set, .{ .resources = &.{"https://rs.example/mcp"} });
    defer refreshed.tokens.deinit();
    try testing.expectEqualStrings("at2", refreshed.tokens.access_token);
    try testing.expectEqualStrings("rt2", refreshed.tokens.refresh_token.?);
    // The granted scope is kept when the answer names none.
    try testing.expectEqualStrings("mcp", refreshed.tokens.scope.?);
}

test "client credentials with Basic, refused with the server's error when the secret is wrong" {
    const gpa = testing.allocator;
    const io = testing.io;
    var p: Provider = undefined;
    try p.start(io);
    defer p.stop(io);
    var http: uplink.Client = .init(gpa, .{});
    defer http.deinit(io);
    var server = try oauth.discover(gpa, io, &http, p.base, .{});
    defer server.deinit();
    var ok = try oauth.clientCredentials(gpa, io, &http, &server.value, .{ .id = "s6BhdRkqt3", .credentials = .{ .client_secret_basic = "7Fjfp0ZBr1KtDRbnfVdmIw" } }, "read", .{});
    defer ok.tokens.deinit();
    try testing.expectEqualStrings("cc", ok.tokens.access_token);
    const refused = try oauth.clientCredentials(gpa, io, &http, &server.value, .{ .id = "s6BhdRkqt3", .credentials = .{ .client_secret_basic = "wrong" } }, null, .{});
    try testing.expectEqual(oauth.errors.Code.invalid_client, refused.refused.code);
}

test "registration with an initial access token" {
    const gpa = testing.allocator;
    const io = testing.io;
    var p: Provider = undefined;
    try p.start(io);
    defer p.stop(io);
    var http: uplink.Client = .init(gpa, .{});
    defer http.deinit(io);
    var server = try oauth.discover(gpa, io, &http, p.base, .{});
    defer server.deinit();
    const meta: oauth.registration.ClientMetadata = .{ .client_name = "app", .redirect_uris = &.{"http://127.0.0.1:9/cb"} };
    var registered = try oauth.register(gpa, io, &http, &server.value, meta, .{ .initial_access_token = "initial" });
    defer registered.registered.deinit();
    try testing.expectEqualStrings("dyn-1", registered.registered.client_id);
    try testing.expectEqualStrings("s3cret", registered.registered.client_secret.?);
    const refused = try oauth.register(gpa, io, &http, &server.value, meta, .{});
    try testing.expectEqual(oauth.errors.Code.invalid_token, refused.refused.code);
}

test "a store's tokens are refreshed and saved when they expire, forgotten when the grant is spent" {
    const gpa = testing.allocator;
    const io = testing.io;
    var p: Provider = undefined;
    try p.start(io);
    defer p.stop(io);
    var http: uplink.Client = .init(gpa, .{});
    defer http.deinit(io);
    var server = try oauth.discover(gpa, io, &http, p.base, .{});
    defer server.deinit();
    var memory: oauth.store.Memory = .init(gpa);
    defer memory.deinit();
    const tokens = memory.store();
    const key = "https://rs.example/mcp";
    const client: oauth.Client = .{ .id = "app" };

    try testing.expectEqual(@as(?oauth.TokenSet, null), try oauth.fresh(gpa, io, &http, tokens, key, &server.value, client, .{}));
    const now_s = @divFloor(Io.Clock.real.now(io).nanoseconds, std.time.ns_per_s);
    {
        var set = try oauth.TokenSet.init(gpa, .{ .access_token = "live", .refresh_token = "rt1", .expires_at = @intCast(now_s + 3600) });
        defer set.deinit();
        try tokens.save(io, key, &set);
    }
    var live = (try oauth.fresh(gpa, io, &http, tokens, key, &server.value, client, .{})).?;
    try testing.expectEqualStrings("live", live.access_token);
    live.deinit();
    {
        var set = try oauth.TokenSet.init(gpa, .{ .access_token = "old", .refresh_token = "rt1", .expires_at = @intCast(now_s + 10), .scope = "mcp" });
        defer set.deinit();
        try tokens.save(io, key, &set);
    }
    var renewed = (try oauth.fresh(gpa, io, &http, tokens, key, &server.value, client, .{})).?;
    try testing.expectEqualStrings("at2", renewed.access_token);
    renewed.deinit();
    var saved = (try tokens.load(io, gpa, key)).?;
    try testing.expectEqualStrings("rt2", saved.refresh_token.?);
    try testing.expectEqualStrings("mcp", saved.scope.?);
    saved.deinit();
    {
        var set = try oauth.TokenSet.init(gpa, .{ .access_token = "old", .refresh_token = "spent", .expires_at = @intCast(now_s) });
        defer set.deinit();
        try tokens.save(io, key, &set);
    }
    try testing.expectEqual(@as(?oauth.TokenSet, null), try oauth.fresh(gpa, io, &http, tokens, key, &server.value, client, .{}));
    try testing.expectEqual(@as(?oauth.TokenSet, null), try tokens.load(io, gpa, key));
}

/// A JWT for the provider's audience, signed with RFC 8037's key under `kid`.
fn signToken(gpa: std.mem.Allocator, io: Io, out: *std.Io.Writer, kid: []const u8, audience: []const u8) !void {
    var der: [48]u8 = undefined;
    _ = try std.fmt.hexToBytes(der[0..16], ed25519_der_prefix);
    _ = try std.base64.url_safe_no_pad.Decoder.decode(der[16..48], ed25519_d);
    const key = try cloak.PrivateKey.parse(gpa, &der, .{});
    defer key.deinit();
    const now: i64 = @intCast(@divFloor(Io.Clock.real.now(io).nanoseconds, std.time.ns_per_s));
    try clearance.jwt.sign(gpa, io, out, .{ .kid = kid, .typ = "at+jwt" }, .{ .iss = "issuer", .aud = audience, .exp = now + 600 }, .{ .private = .{ .alg = .eddsa, .key = key } });
}

test "a remote key set is fetched once, kept as its answer says, and fetched again for a new kid" {
    const gpa = testing.allocator;
    const io = testing.io;
    var p: Provider = undefined;
    try p.start(io);
    defer p.stop(io);
    var http: uplink.Client = .init(gpa, .{});
    defer http.deinit(io);
    var buffer: [128]u8 = undefined;
    var keys = try oauth.RemoteKeySet.init(gpa, p.url(&buffer, "/jwks"), .{ .cooldown = .literal("0s") });
    defer keys.deinit();

    var token: std.Io.Writer.Allocating = .init(gpa);
    defer token.deinit();
    try signToken(gpa, io, &token.writer, "k1", "rs");
    var scratch: [2048]u8 = undefined;
    const validation: clearance.jwt.Validation = .{ .algorithms = &.{.eddsa}, .audience = "rs", .typ = "at+jwt" };
    for (0..3) |_| {
        var v = try keys.verify(void, io, &http, token.written(), validation, Io.Clock.real.now(io), &scratch);
        v.release();
    }
    // A lease held across a refetch keeps its keys.
    var held = try keys.lease(io, &http, .current);
    defer held.release();

    // The provider rotates: a token under `k2` refetches once and verifies.
    {
        p.mutex.lockUncancelable(io);
        defer p.mutex.unlock(io);
        try testing.expectEqual(@as(u32, 1), p.jwks_fetches);
        p.jwks_kid = "k2";
    }
    token.clearRetainingCapacity();
    try signToken(gpa, io, &token.writer, "k2", "rs");
    var rotated = try keys.verify(void, io, &http, token.written(), validation, Io.Clock.real.now(io), &scratch);
    rotated.release();
    try testing.expectEqualStrings("k1", held.keys[0].kid.?);
    p.mutex.lockUncancelable(io);
    defer p.mutex.unlock(io);
    try testing.expectEqual(@as(u32, 2), p.jwks_fetches);
}

test "unknown kids cost one fetch per cooldown, and waiters share one fetch" {
    const gpa = testing.allocator;
    const io = testing.io;
    var p: Provider = undefined;
    try p.start(io);
    defer p.stop(io);
    var http: uplink.Client = .init(gpa, .{});
    defer http.deinit(io);
    var buffer: [128]u8 = undefined;
    var keys = try oauth.RemoteKeySet.init(gpa, p.url(&buffer, "/jwks"), .{});
    defer keys.deinit();
    p.jwks_delay_ms = 100;

    const Asker = struct {
        fn run(k: *oauth.RemoteKeySet, i: Io, h: *uplink.Client, failed: *std.atomic.Value(u32)) void {
            var l = k.lease(i, h, .current) catch {
                _ = failed.fetchAdd(1, .monotonic);
                return;
            };
            l.release();
        }
    };
    var failed: std.atomic.Value(u32) = .init(0);
    var group: Io.Group = .init;
    for (0..8) |_| group.concurrent(io, Asker.run, .{ &keys, io, &http, &failed }) catch return error.SkipZigTest;
    try group.await(io);
    try testing.expectEqual(@as(u32, 0), failed.load(.monotonic));

    var token: std.Io.Writer.Allocating = .init(gpa);
    defer token.deinit();
    var scratch: [2048]u8 = undefined;
    const validation: clearance.jwt.Validation = .{ .algorithms = &.{.eddsa}, .audience = "rs" };
    for ([_][]const u8{ "x1", "x2", "x3" }) |kid| {
        token.clearRetainingCapacity();
        try signToken(gpa, io, &token.writer, kid, "rs");
        try testing.expectError(error.NoKey, keys.verify(void, io, &http, token.written(), validation, Io.Clock.real.now(io), &scratch));
    }
    p.mutex.lockUncancelable(io);
    defer p.mutex.unlock(io);
    // One fetch for the eight, none for the unknown kids within the cooldown.
    try testing.expectEqual(@as(u32, 1), p.jwks_fetches);
}

test "a failing key server: the set held is used through its grace, and none is refused" {
    const gpa = testing.allocator;
    const io = testing.io;
    var http: uplink.Client = .init(gpa, .{});
    defer http.deinit(io);
    // Nothing listens on port 9 of loopback.
    var keys = try oauth.RemoteKeySet.init(gpa, "http://127.0.0.1:9/jwks", .{});
    defer keys.deinit();
    try testing.expectError(error.ConnectionFailed, keys.lease(io, &http, .current));
    // Within the cooldown the error is kept, no fetch made.
    try testing.expectError(error.ConnectionFailed, keys.lease(io, &http, .current));
}

test "introspection answers are kept until the bound, by the token's hash" {
    const gpa = testing.allocator;
    const io = testing.io;
    var p: Provider = undefined;
    try p.start(io);
    defer p.stop(io);
    var http: uplink.Client = .init(gpa, .{});
    defer http.deinit(io);
    var buffer: [128]u8 = undefined;
    var introspector = try oauth.Introspector.init(gpa, p.url(&buffer, "/introspect"), p.base, .{ .id = "rs", .credentials = .{ .client_secret_post = "pw" } }, .{ .max_entries = 2 });
    defer introspector.deinit();
    var arena: std.heap.ArenaAllocator = .init(gpa);
    defer arena.deinit();
    for (0..3) |_| {
        const r = try introspector.introspect(io, &http, arena.allocator(), "good");
        try testing.expect(r.introspected.active);
        try testing.expectEqualStrings("mcp", r.introspected.scope.?);
        try testing.expect(r.introspected.hasAudience(p.base));
    }
    const bad = try introspector.introspect(io, &http, arena.allocator(), "bad");
    try testing.expect(!bad.introspected.active);
    _ = try introspector.introspect(io, &http, arena.allocator(), "bad");
    // A third token evicts one of two: the cache stays bounded.
    _ = try introspector.introspect(io, &http, arena.allocator(), "other");
    try testing.expectEqual(@as(u32, 2), introspector.entries.count());
    p.mutex.lockUncancelable(io);
    defer p.mutex.unlock(io);
    try testing.expectEqual(@as(u32, 3), p.introspections);
}
