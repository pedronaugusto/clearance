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
    /// The token endpoint's answers to a device's code, in turn; the last
    /// repeats.
    device_answers: []const []const u8 = &.{"{\"access_token\":\"dev-at\",\"token_type\":\"Bearer\",\"expires_in\":600}"},
    device_polls: u32 = 0,
    device_expires_in: u32 = 600,
    dpop_requests: u32 = 0,
    /// A pushed request's parameters, kept for its `request_uri`.
    pushed_buffer: [1024]u8 = undefined,
    pushed: []const u8 = "",
    pushes: u32 = 0,
    revoked_buffer: [32]u8 = undefined,
    revoked: []const u8 = "",

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
        // UserInfo writes its own media type: JSON or a JWT.
        if (std.mem.eql(u8, path, "/userinfo")) return p.userinfo(io, arena, request, response);
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
        if (std.mem.eql(u8, path, "/idp/token")) return p.identityProvider(io, arena, request, response);
        if (std.mem.eql(u8, path, "/device")) {
            const body = try request.collect(arena, io, .limited(4096));
            if (!std.mem.eql(u8, field(arena, body, "client_id") orelse "", "tv-app")) return refuse(io, response, "invalid_client");
            p.mutex.lockUncancelable(io);
            const expires_in = p.device_expires_in;
            p.mutex.unlock(io);
            return response.send(io, try arena.print("{{\"device_code\":\"dc-1\",\"user_code\":\"WDJB-MJHT\",\"verification_uri\":\"{s}/activate\",\"expires_in\":{d},\"interval\":1}}", .{ p.base, expires_in }));
        }
        if (std.mem.eql(u8, path, "/par")) {
            const body = try request.collect(arena, io, .limited(4096));
            if (!std.mem.eql(u8, field(arena, body, "client_id") orelse "", "app")) {
                response.status = .unauthorized;
                return response.send(io, "{\"error\":\"invalid_client\"}");
            }
            if (!std.mem.startsWith(u8, field(arena, body, "redirect_uri") orelse "", "http://127.0.0.1")) return refuse(io, response, "invalid_request");
            p.mutex.lockUncancelable(io);
            defer p.mutex.unlock(io);
            p.pushes += 1;
            @memcpy(p.pushed_buffer[0..body.len], body);
            p.pushed = p.pushed_buffer[0..body.len];
            response.status = .created;
            return response.send(io, "{\"request_uri\":\"urn:ietf:params:oauth:request_uri:p1\",\"expires_in\":60}");
        }
        if (std.mem.eql(u8, path, "/revoke")) {
            const body = try request.collect(arena, io, .limited(4096));
            if (!std.mem.eql(u8, field(arena, body, "client_id") orelse "", "app")) {
                response.status = .unauthorized;
                return response.send(io, "{\"error\":\"invalid_client\"}");
            }
            const presented = field(arena, body, "token") orelse return refuse(io, response, "invalid_request");
            if (std.mem.eql(u8, presented, "busy")) {
                response.status = .service_unavailable;
                return response.send(io, "");
            }
            if (std.mem.eql(u8, field(arena, body, "token_type_hint") orelse "", "access_token") and std.mem.eql(u8, presented, "jwt-at")) {
                return refuse(io, response, "unsupported_token_type");
            }
            p.mutex.lockUncancelable(io);
            defer p.mutex.unlock(io);
            const n = @min(presented.len, p.revoked_buffer.len);
            @memcpy(p.revoked_buffer[0..n], presented[0..n]);
            p.revoked = p.revoked_buffer[0..n];
            // An unknown token is answered as a revoked one (RFC 7009 §2.2).
            return response.send(io, "");
        }
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
            const presented = field(arena, body, "token") orelse "";
            if (std.mem.eql(u8, presented, "eyJ.structured.jwt")) {
                response.status = .bad_request;
                return response.send(io, "{\"error\":\"unsupported_token_type\",\"error_description\":\"Structured JWT Tokens cannot be introspected\"}");
            }
            const active = std.mem.eql(u8, presented, "good");
            if (!active) return response.send(io, "{\"active\":false}");
            return response.send(io, try arena.print("{{\"active\":true,\"scope\":\"mcp\",\"aud\":\"{s}\",\"exp\":{d}}}", .{ p.base, now + 3600 }));
        }
        response.status = .not_found;
        return response.send(io, "{}");
    }

    fn metadata(p: *Provider, arena: std.mem.Allocator, issuer: []const u8) ![]const u8 {
        return arena.print(
            \\{{"issuer":"{s}","authorization_endpoint":"{s}/authorize","token_endpoint":"{s}/token","registration_endpoint":"{s}/register",
            \\"jwks_uri":"{s}/jwks","introspection_endpoint":"{s}/introspect","device_authorization_endpoint":"{s}/device","revocation_endpoint":"{s}/revoke","pushed_authorization_request_endpoint":"{s}/par","userinfo_endpoint":"{s}/userinfo","code_challenge_methods_supported":["S256"],
            \\"grant_types_supported":["authorization_code","refresh_token","client_credentials"],"authorization_response_iss_parameter_supported":true}}
        , .{ issuer, p.base, p.base, p.base, p.base, p.base, p.base, p.base, p.base, p.base });
    }

    /// What a browser would do: the request read, and the redirect back
    /// with a code, the state and `iss`.
    fn authorize(p: *Provider, io: Io, arena: std.mem.Allocator, request: *uplink.server.Request, response: *uplink.server.Response) !void {
        var query = request.query orelse "";
        // A pushed request: its parameters, as they were pushed.
        if (field(arena, query, "request_uri")) |uri| {
            if (!std.mem.eql(u8, uri, "urn:ietf:params:oauth:request_uri:p1") or !std.mem.eql(u8, field(arena, query, "client_id") orelse "", "app")) return error.UnknownRequestUri;
            p.mutex.lockUncancelable(io);
            query = try arena.dupe(u8, p.pushed);
            p.mutex.unlock(io);
        }
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
        if (request.headers.get("dpop")) |proof| return p.dpopToken(io, arena, proof, grant, body, response);
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
        if (std.mem.eql(u8, grant, "urn:ietf:params:oauth:grant-type:jwt-bearer")) return p.jwtBearer(io, arena, request, body, response);
        if (std.mem.eql(u8, grant, "urn:ietf:params:oauth:grant-type:device_code")) {
            if (!std.mem.eql(u8, field(arena, body, "device_code") orelse "", "dc-1") or
                !std.mem.eql(u8, field(arena, body, "client_id") orelse "", "tv-app")) return refuse(io, response, "invalid_grant");
            const answer = p.device_answers[@min(p.device_polls, p.device_answers.len - 1)];
            p.device_polls += 1;
            if (std.mem.startsWith(u8, answer, "{\"error\"")) response.status = .bad_request;
            return response.send(io, answer);
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

    /// An enterprise's identity provider: an ID token of the user `u1`
    /// (here the text `id-token-u1`) exchanged for an ID-JAG to the audience
    /// asked, for the client `mcp-client`, the resource asked and the scope
    /// asked less `admin`. The subject `id-token-other-client` gets one
    /// naming another client.
    fn identityProvider(p: *Provider, io: Io, arena: std.mem.Allocator, request: *uplink.server.Request, response: *uplink.server.Response) !void {
        const body = try request.collect(arena, io, .limited(8192));
        p.mutex.lockUncancelable(io);
        p.token_requests += 1;
        p.mutex.unlock(io);
        const ok = std.mem.eql(u8, field(arena, body, "grant_type") orelse "", "urn:ietf:params:oauth:grant-type:token-exchange") and
            std.mem.eql(u8, field(arena, body, "requested_token_type") orelse "", "urn:ietf:params:oauth:token-type:id-jag") and
            std.mem.eql(u8, field(arena, body, "subject_token_type") orelse "", "urn:ietf:params:oauth:token-type:id_token") and
            std.mem.eql(u8, field(arena, body, "client_id") orelse "", "idp-app");
        if (!ok) return refuse(io, response, "invalid_request");
        const subject = field(arena, body, "subject_token") orelse "";
        const client_id = if (std.mem.eql(u8, subject, "id-token-u1")) "mcp-client" else if (std.mem.eql(u8, subject, "id-token-other-client")) "someone-else" else return refuse(io, response, "invalid_grant");
        var scope: std.Io.Writer.Allocating = .init(arena);
        var it = std.mem.tokenizeScalar(u8, field(arena, body, "scope") orelse "", ' ');
        while (it.next()) |s| if (!std.mem.eql(u8, s, "admin")) {
            if (scope.written().len != 0) try scope.writer.writeByte(' ');
            try scope.writer.writeAll(s);
        };
        const now: i64 = @intCast(@divFloor(Io.Clock.real.now(io).nanoseconds, std.time.ns_per_s));
        var jag: std.Io.Writer.Allocating = .init(arena);
        try signTyped(arena, io, &jag.writer, "k1", "oauth-id-jag+jwt", .{
            .iss = try std.mem.concat(arena, u8, &.{ p.base, "/idp" }),
            .sub = "u1",
            .aud = field(arena, body, "audience") orelse "",
            .client_id = client_id,
            .jti = "jag-1",
            .iat = now,
            .exp = now + 300,
            .resource = field(arena, body, "resource") orelse "",
            .scope = if (scope.written().len == 0) null else scope.written(),
        });
        return response.send(io, try arena.print("{{\"access_token\":\"{s}\",\"issued_token_type\":\"urn:ietf:params:oauth:token-type:id-jag\",\"token_type\":\"N_A\",\"expires_in\":300}}", .{jag.written()}));
    }

    /// A JWT as the grant: an ID-JAG from the identity provider, for this
    /// server and the client that authenticates (`mcp-client`, Basic with
    /// `pw`), or a workload's token for this server with no client. Each
    /// is verified with the provider's key.
    fn jwtBearer(p: *Provider, io: Io, arena: std.mem.Allocator, request: *uplink.server.Request, body: []const u8, response: *uplink.server.Response) !void {
        const assertion = field(arena, body, "assertion") orelse return refuse(io, response, "invalid_request");
        var keys = try clearance.jwk.KeySet.parse(arena, "{\"kty\":\"OKP\",\"crv\":\"Ed25519\",\"kid\":\"k1\",\"x\":\"" ++ ed25519_x ++ "\"}", .{});
        defer keys.deinit();
        const scratch = try arena.alloc(u8, clearance.jws.scratchLength(assertion.len));
        const now = Io.Clock.real.now(io);
        if (request.headers.get("authorization")) |authorization| {
            // mcp-client:pw
            if (!std.mem.eql(u8, authorization, "Basic bWNwLWNsaWVudDpwdw==")) {
                response.status = .unauthorized;
                return response.send(io, "{\"error\":\"invalid_client\"}");
            }
            const Jag = struct { client_id: []const u8, resource: []const u8, scope: ?[]const u8 = null };
            const verified = clearance.jwt.verify(Jag, assertion, keys.keys, .{
                .algorithms = &.{.eddsa},
                .issuer = try std.mem.concat(arena, u8, &.{ p.base, "/idp" }),
                .audience = p.base,
                .typ = "oauth-id-jag+jwt",
                .required = .{ .sub = true, .jti = true, .iat = true },
            }, now, scratch) catch return refuse(io, response, "invalid_grant");
            if (!std.mem.eql(u8, verified.claims.client_id, "mcp-client")) return refuse(io, response, "invalid_grant");
            // Asking for a scope or naming a resource again is not the
            // redemption's: the assertion carries both.
            if (field(arena, body, "scope") != null or field(arena, body, "resource") != null) return refuse(io, response, "invalid_request");
            return response.send(io, try arena.print("{{\"access_token\":\"ema-at\",\"token_type\":\"Bearer\",\"expires_in\":600,\"refresh_token\":\"not-wanted\",\"resource\":\"{s}\"}}", .{verified.claims.resource}));
        }
        _ = clearance.jwt.verify(void, assertion, keys.keys, .{ .algorithms = &.{.eddsa}, .audience = p.base }, now, scratch) catch return refuse(io, response, "invalid_grant");
        const scope = field(arena, body, "scope") orelse "";
        if (oauth.challenge.contains(scope, "wif.rejected")) return refuse(io, response, "invalid_scope");
        return response.send(io, "{\"access_token\":\"wif-at\",\"token_type\":\"Bearer\",\"expires_in\":600}");
    }

    /// A token request with a DPoP proof (RFC 9449 §5): the proof checked
    /// for this endpoint with the server's nonce (a proof without it is
    /// answered `use_dpop_nonce` and the nonce), then an RFC 9068 access
    /// token bound to the proof's key for the public client `dpop-app`.
    fn dpopToken(p: *Provider, io: Io, arena: std.mem.Allocator, proof: []const u8, grant: []const u8, body: []const u8, response: *uplink.server.Response) !void {
        p.dpop_requests += 1;
        const scratch = try arena.alloc(u8, clearance.jws.scratchLength(proof.len));
        const verified = try arena.create(clearance.dpop.Verified);
        const htu = try std.mem.concat(arena, u8, &.{ p.base, "/token" });
        const now = Io.Clock.real.now(io);
        clearance.dpop.verifyProof(io, proof, .{ .algorithms = &.{ .es256, .eddsa }, .htm = "POST", .htu = htu, .nonce = "as-nonce-1" }, now, scratch, verified) catch |err| {
            if (err != error.UseNonce) return refuse(io, response, "invalid_dpop_proof");
            try response.header("DPoP-Nonce", "as-nonce-1");
            return refuse(io, response, "use_dpop_nonce");
        };
        if (!std.mem.eql(u8, grant, "client_credentials") or !std.mem.eql(u8, field(arena, body, "client_id") orelse "", "dpop-app")) return refuse(io, response, "invalid_grant");
        var jkt: std.Io.Writer.Allocating = .init(arena);
        try clearance.base64url.encode(&jkt.writer, &verified.thumbprint);
        const seconds: i64 = @intCast(@divFloor(now.nanoseconds, std.time.ns_per_s));
        var at: std.Io.Writer.Allocating = .init(arena);
        try signTyped(arena, io, &at.writer, "k1", "at+jwt", .{
            .iss = "https://as.example",
            .aud = "https://rs.example/mcp",
            .sub = "dpop-app",
            .client_id = "dpop-app",
            .scope = "mcp",
            .exp = seconds + 600,
            .iat = seconds,
            .jti = "dpop-j1",
            .cnf = .{ .jkt = jkt.written() },
        });
        return response.send(io, try arena.print("{{\"access_token\":\"{s}\",\"token_type\":\"DPoP\",\"expires_in\":600}}", .{at.written()}));
    }

    /// UserInfo: `at1` is the user `u1`, as JSON; `signed-ui` gets a signed
    /// answer; a DPoP token `dpop-ui` needs a proof with the nonce
    /// `ui-nonce`; any other token is refused with a challenge.
    fn userinfo(p: *Provider, io: Io, arena: std.mem.Allocator, request: *uplink.server.Request, response: *uplink.server.Response) !void {
        const authorization = request.headers.get("authorization") orelse "";
        if (!std.mem.eql(u8, authorization, "Bearer signed-ui")) try response.header("Content-Type", "application/json");
        if (std.mem.eql(u8, authorization, "Bearer at1")) return response.send(io, "{\"sub\":\"u1\",\"name\":\"Jane Doe\",\"email_verified\":true}");
        if (std.mem.eql(u8, authorization, "Bearer signed-ui")) {
            try response.header("Content-Type", "application/jwt");
            var out: std.Io.Writer.Allocating = .init(arena);
            try signTyped(arena, io, &out.writer, "k1", "JWT", .{ .iss = p.base, .aud = "app", .sub = "u1", .name = "Jane Doe" });
            return response.send(io, out.written());
        }
        if (std.mem.eql(u8, authorization, "DPoP dpop-ui")) {
            const proof = request.headers.get("dpop") orelse "";
            const scratch = try arena.alloc(u8, clearance.jws.scratchLength(proof.len));
            const verified = try arena.create(clearance.dpop.Verified);
            const htu = try std.mem.concat(arena, u8, &.{ p.base, "/userinfo" });
            if (clearance.dpop.verifyProof(io, proof, .{ .algorithms = &.{.es256}, .htm = "GET", .htu = htu, .access_token = "dpop-ui", .nonce = "ui-nonce" }, Io.Clock.real.now(io), scratch, verified)) {
                return response.send(io, "{\"sub\":\"u1\",\"name\":\"Jane Doe\"}");
            } else |_| {
                response.status = .unauthorized;
                try response.header("DPoP-Nonce", "ui-nonce");
                try response.header("WWW-Authenticate", "DPoP error=\"use_dpop_nonce\", algs=\"ES256\"");
                return response.send(io, "");
            }
        }
        response.status = .unauthorized;
        try response.header("WWW-Authenticate", "Bearer error=\"invalid_token\", error_description=\"expired\"");
        return response.send(io, "");
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

test "a pushed authorization request: the parameters pushed, the browser sent with the request_uri, the code redeemed" {
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
    const begin: oauth.AuthorizationFlow.Begin = .{ .client_id = "app", .redirect_uri = "http://127.0.0.1:9/cb", .scope = "mcp", .resources = &.{"https://rs.example/mcp"} };
    var pushed = try oauth.AuthorizationFlow.push(gpa, io, &http, &server.value, .{ .id = "app" }, begin, &url_out.writer, .{});
    var flow = &pushed.flow;
    defer flow.deinit();
    var buffer: [128]u8 = undefined;
    const expected_url = try std.mem.concat(gpa, u8, &.{ p.url(&buffer, "/authorize"), "?client_id=app&request_uri=urn%3Aietf%3Aparams%3Aoauth%3Arequest_uri%3Ap1" });
    defer gpa.free(expected_url);
    try testing.expectEqualStrings(expected_url, url_out.written());
    // The secrets went to the server, not into the URL.
    try testing.expect(std.mem.find(u8, url_out.written(), "code_challenge") == null);

    var answer = try http.send(io, .{ .url = url_out.written(), .redirects = .none });
    const location = try gpa.dupe(u8, answer.headers.get("location").?);
    defer gpa.free(location);
    answer.deinit(io);
    const response = try flow.finish(gpa, io, &http, &server.value, .{ .id = "app" }, location, .{});
    var set = response.tokens;
    defer set.deinit();
    try testing.expectEqualStrings("at1", set.access_token);

    // A refused push is the server's answer; a server that requires pushes
    // is never sent a plain request.
    url_out.clearRetainingCapacity();
    const refused = try oauth.AuthorizationFlow.push(gpa, io, &http, &server.value, .{ .id = "app" }, .{ .client_id = "app", .redirect_uri = "https://elsewhere.example/cb" }, &url_out.writer, .{});
    try testing.expectEqual(oauth.errors.Code.invalid_request, refused.refused.code);
    var strict = server.value;
    strict.require_pushed_authorization_requests = true;
    try testing.expectError(error.PushRequired, oauth.AuthorizationFlow.begin(io, &strict, begin, &url_out.writer));
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

test "device authorization: the codes shown, polled through pending and slow_down, then the tokens" {
    const gpa = testing.allocator;
    const io = testing.io;
    var p: Provider = undefined;
    try p.start(io);
    defer p.stop(io);
    var http: uplink.Client = .init(gpa, .{});
    defer http.deinit(io);
    var server = try oauth.discover(gpa, io, &http, p.base, .{});
    defer server.deinit();
    const client: oauth.Client = .{ .id = "tv-app" };

    p.device_answers = &.{ "{\"error\":\"authorization_pending\"}", "{\"error\":\"slow_down\"}", "{\"access_token\":\"dev-at\",\"token_type\":\"Bearer\",\"expires_in\":600}" };
    var begun = try oauth.DeviceFlow.begin(gpa, io, &http, &server.value, client, .{ .scope = "mcp" }, .{});
    var flow = &begun.flow;
    defer flow.deinit();
    try testing.expectEqualStrings("WDJB-MJHT", flow.authorization.user_code);
    var buffer: [128]u8 = undefined;
    try testing.expectEqualStrings(p.url(&buffer, "/activate"), flow.authorization.verification_uri);
    try testing.expectEqual(@as(u32, 1), flow.authorization.interval);
    try testing.expectEqual(oauth.DeviceFlow.Poll.pending, try flow.poll(gpa, io, &http, &server.value, client, .{}));
    try testing.expectEqual(oauth.DeviceFlow.Poll.slow_down, try flow.poll(gpa, io, &http, &server.value, client, .{}));
    // Five seconds more, as RFC 8628 §3.5 asks.
    try testing.expectEqual(@as(u32, 6), flow.authorization.interval);
    var polled = try flow.poll(gpa, io, &http, &server.value, client, .{});
    defer polled.tokens.deinit();
    try testing.expectEqualStrings("dev-at", polled.tokens.access_token);
    try testing.expectEqualStrings("mcp", polled.tokens.scope.?);

    // `wait` sleeps the interval between requests: one pending, then tokens.
    p.device_polls = 0;
    p.device_answers = &.{ "{\"error\":\"authorization_pending\"}", "{\"access_token\":\"dev-at2\",\"token_type\":\"Bearer\"}" };
    var again = try oauth.DeviceFlow.begin(gpa, io, &http, &server.value, client, .{}, .{});
    defer again.flow.deinit();
    const started = Io.Clock.awake.now(io);
    var waited = try again.flow.wait(gpa, io, &http, &server.value, client, .{});
    defer waited.tokens.deinit();
    try testing.expectEqualStrings("dev-at2", waited.tokens.access_token);
    try testing.expect(started.durationTo(Io.Clock.awake.now(io)).toMilliseconds() >= 2000);
    try testing.expectEqual(@as(u32, 2), p.device_polls);
}

test "device authorization: a refusal ends the wait, and codes about to expire are not polled" {
    const gpa = testing.allocator;
    const io = testing.io;
    var p: Provider = undefined;
    try p.start(io);
    defer p.stop(io);
    var http: uplink.Client = .init(gpa, .{});
    defer http.deinit(io);
    var server = try oauth.discover(gpa, io, &http, p.base, .{});
    defer server.deinit();

    p.device_answers = &.{"{\"error\":\"access_denied\"}"};
    var denied = try oauth.DeviceFlow.begin(gpa, io, &http, &server.value, .{ .id = "tv-app" }, .{}, .{});
    defer denied.flow.deinit();
    const answer = try denied.flow.wait(gpa, io, &http, &server.value, .{ .id = "tv-app" }, .{});
    try testing.expectEqual(oauth.errors.Code.access_denied, answer.refused.code);

    p.device_polls = 0;
    p.device_expires_in = 1;
    var short = try oauth.DeviceFlow.begin(gpa, io, &http, &server.value, .{ .id = "tv-app" }, .{}, .{});
    defer short.flow.deinit();
    try testing.expectError(error.Expired, short.flow.wait(gpa, io, &http, &server.value, .{ .id = "tv-app" }, .{}));
    try testing.expectEqual(@as(u32, 0), p.device_polls);

    const refused = try oauth.DeviceFlow.begin(gpa, io, &http, &server.value, .{ .id = "someone" }, .{}, .{});
    try testing.expectEqual(oauth.errors.Code.invalid_client, refused.refused.code);
}

test "revocation: the refresh token revoked, then the store forgets it; a refusal and a 503 are the server's" {
    const gpa = testing.allocator;
    const io = testing.io;
    var p: Provider = undefined;
    try p.start(io);
    defer p.stop(io);
    var http: uplink.Client = .init(gpa, .{});
    defer http.deinit(io);
    var server = try oauth.discover(gpa, io, &http, p.base, .{});
    defer server.deinit();
    const app: oauth.Client = .{ .id = "app" };

    var memory: oauth.store.Memory = .init(gpa);
    defer memory.deinit();
    const tokens = memory.store();
    var set = try oauth.TokenSet.init(gpa, .{ .access_token = "at1", .refresh_token = "rt1" });
    defer set.deinit();
    try tokens.save(io, "srv", &set);
    // A sign-out: the grant ended at the server, then forgotten here.
    try testing.expectEqual(oauth.revocation.Response.revoked, try oauth.revoke(gpa, io, &http, &server.value, app, set.refresh_token.?, .refresh_token, .{}));
    tokens.forget(io, "srv");
    try testing.expectEqualStrings("rt1", p.revoked);
    try testing.expectEqual(@as(?oauth.TokenSet, null), try tokens.load(io, gpa, "srv"));

    const unsupported = try oauth.revoke(gpa, io, &http, &server.value, app, "jwt-at", .access_token, .{});
    try testing.expectEqual(oauth.errors.Code.unsupported_token_type, unsupported.refused.code);
    const stranger = try oauth.revoke(gpa, io, &http, &server.value, .{ .id = "stranger" }, "rt1", null, .{});
    try testing.expectEqual(oauth.errors.Code.invalid_client, stranger.refused.code);
    try testing.expectError(error.UnexpectedStatus, oauth.revoke(gpa, io, &http, &server.value, app, "busy", null, .{}));
}

/// RFC 7515 A.3's P-256 key, the client's DPoP key.
const es256_private_jwk = "{\"kty\":\"EC\",\"crv\":\"P-256\",\"x\":\"f83OJ3D2xF1Bg8vub9tLe1gHMzV76e8Tus9uPHvRVEU\",\"y\":\"x_FEzRu9m36HLN_tue659LNpXW6pCyStikYjKIWI5a0\",\"d\":\"jpsQnnGQmL-YBIffH1136cspYG6-0iY7X1fCE9-E9LI\"}";

test "DPoP: the server's nonce learned and sent again, a bound token, its proof checked by the resource; replay and a bearer downgrade refused" {
    const gpa = testing.allocator;
    const io = testing.io;
    var p: Provider = undefined;
    try p.start(io);
    defer p.stop(io);
    var http: uplink.Client = .init(gpa, .{});
    defer http.deinit(io);
    var server = try oauth.discover(gpa, io, &http, p.base, .{});
    defer server.deinit();
    var private = try clearance.jwk.PrivateKey.parse(gpa, es256_private_jwk, .{});
    defer private.deinit();
    var session: oauth.dpop.Session = .init(try .fromJwk(&private, null));

    // The first proof has no nonce: answered with one, sent again once.
    var response = try oauth.clientCredentials(gpa, io, &http, &server.value, .{ .id = "dpop-app" }, null, .{ .dpop = &session });
    defer response.tokens.deinit();
    const set = &response.tokens;
    try testing.expectEqual(oauth.token.TokenType.dpop, set.token_type);
    try testing.expectEqual(@as(u32, 2), p.dpop_requests);
    // The nonce is kept: the next request needs one try.
    var again = try oauth.clientCredentials(gpa, io, &http, &server.value, .{ .id = "dpop-app" }, null, .{ .dpop = &session });
    again.tokens.deinit();
    try testing.expectEqual(@as(u32, 3), p.dpop_requests);
    // A DPoP token refreshes only with its key.
    try testing.expectError(error.DpopRequired, oauth.refresh(gpa, io, &http, &server.value, .{ .id = "dpop-app" }, set, .{}));
    // Without a proof the server's DPoP answer would be refused, and a
    // bearer answer to a proof is a bearer token.
    try testing.expectError(error.UnsupportedTokenType, oauth.token.readResponse(gpa, 200, "{\"access_token\":\"a\",\"token_type\":\"DPoP\"}", .{ .now = Io.Clock.real.now(io) }));

    var buffer: [128]u8 = undefined;
    var keys = try oauth.RemoteKeySet.init(gpa, p.url(&buffer, "/jwks"), .{});
    defer keys.deinit();
    var replay: clearance.jwt.MemoryReplay = try .init(gpa, 64);
    defer replay.deinit();
    var arena_state: std.heap.ArenaAllocator = .init(gpa);
    defer arena_state.deinit();
    const arena = arena_state.allocator();
    var verifier: oauth.bearer.Verifier = .{
        .source = .{ .keys = .{ .set = &keys, .algorithms = &.{.eddsa} } },
        .issuer = "https://as.example",
        .resource = "https://rs.example/mcp",
        .dpop = .{ .algorithms = &.{ .es256, .eddsa }, .replay = replay.replay() },
    };
    const target = "https://rs.example/mcp";
    var h = try session.headers(gpa, io, "GET", target, set);
    defer h.deinit();
    const allowed = try verifier.check(io, &http, arena, .{ .authorization = h.authorization.expose(), .dpop = &.{h.dpop}, .method = "GET", .url = target }, &.{"mcp"});
    try testing.expectEqualSlices(u8, &session.thumbprint(), &allowed.allowed.jkt.?);

    // The same proof again, a proof for another request, none, or the
    // bound token sent as a bearer token: each refused.
    const replayed = (try verifier.check(io, &http, arena, .{ .authorization = h.authorization.expose(), .dpop = &.{h.dpop}, .method = "GET", .url = target }, &.{})).refused;
    try testing.expectEqual(oauth.errors.Code.invalid_dpop_proof, replayed.dpop.?.@"error".?);
    var other = try session.headers(gpa, io, "POST", target, set);
    defer other.deinit();
    const wrong = (try verifier.check(io, &http, arena, .{ .authorization = other.authorization.expose(), .dpop = &.{other.dpop}, .method = "GET", .url = target }, &.{})).refused;
    try testing.expectEqual(std.http.Status.unauthorized, wrong.status);
    const missing = (try verifier.check(io, &http, arena, .{ .authorization = h.authorization.expose(), .method = "GET", .url = target }, &.{})).refused;
    try testing.expectEqual(oauth.errors.Code.invalid_dpop_proof, missing.dpop.?.@"error".?);
    const bearer_value = try std.mem.concat(arena, u8, &.{ "Bearer ", set.access_token });
    const downgraded = (try verifier.check(io, &http, arena, .{ .authorization = bearer_value, .method = "GET", .url = target }, &.{})).refused;
    try testing.expectEqual(oauth.errors.Code.invalid_token, downgraded.challenge.@"error".?);
    var out: [256]u8 = undefined;
    var w: std.Io.Writer = .fixed(&out);
    try downgraded.write(&w);
    try testing.expectEqualStrings("Bearer error=\"invalid_token\", error_description=\"binding\", DPoP algs=\"ES256 EdDSA\"", w.buffered());

    // The resource asks for its nonce: refused with it, accepted once the
    // session sends it.
    verifier.dpop.?.nonce = "rs-nonce-7";
    var first = try session.headers(gpa, io, "GET", target, set);
    defer first.deinit();
    const asked = (try verifier.check(io, &http, arena, .{ .authorization = first.authorization.expose(), .dpop = &.{first.dpop}, .method = "GET", .url = target }, &.{})).refused;
    try testing.expectEqual(oauth.errors.Code.use_dpop_nonce, asked.dpop.?.@"error".?);
    session.remember(io, target, asked.dpop_nonce.?);
    var second = try session.headers(gpa, io, "GET", target, set);
    defer second.deinit();
    _ = (try verifier.check(io, &http, arena, .{ .authorization = second.authorization.expose(), .dpop = &.{second.dpop}, .method = "GET", .url = target }, &.{})).allowed;
}

test "UserInfo: JSON for the ID token's subject, a signed answer, a DPoP token sent again with the nonce; a refusal read from the challenge" {
    const gpa = testing.allocator;
    const io = testing.io;
    var p: Provider = undefined;
    try p.start(io);
    defer p.stop(io);
    var http: uplink.Client = .init(gpa, .{});
    defer http.deinit(io);
    var server = try oauth.discover(gpa, io, &http, p.base, .{});
    defer server.deinit();
    var arena_state: std.heap.ArenaAllocator = .init(gpa);
    defer arena_state.deinit();
    const arena = arena_state.allocator();
    const Standard = oauth.userinfo.Standard;

    var set = try oauth.TokenSet.init(gpa, .{ .access_token = "at1" });
    defer set.deinit();
    const jane = try oauth.fetchUserInfo(Standard, arena, io, &http, &server.value, &set, "u1", .{});
    try testing.expectEqualStrings("Jane Doe", jane.claims.name.?);
    try testing.expectError(error.WrongSubject, oauth.fetchUserInfo(Standard, arena, io, &http, &server.value, &set, "u2", .{}));

    var keys = try clearance.jwk.KeySet.parse(gpa, "{\"kty\":\"OKP\",\"crv\":\"Ed25519\",\"kid\":\"k1\",\"x\":\"" ++ ed25519_x ++ "\"}", .{});
    defer keys.deinit();
    var signed_set = try oauth.TokenSet.init(gpa, .{ .access_token = "signed-ui" });
    defer signed_set.deinit();
    const signed = try oauth.fetchUserInfo(Standard, arena, io, &http, &server.value, &signed_set, "u1", .{ .signed = .{ .keys = keys.keys, .algorithms = &.{.eddsa}, .client_id = "app" } });
    try testing.expectEqualStrings("Jane Doe", signed.claims.name.?);
    try testing.expectError(error.InvalidSignature, oauth.fetchUserInfo(Standard, arena, io, &http, &server.value, &signed_set, "u1", .{ .signed = .{ .keys = keys.keys, .algorithms = &.{.eddsa}, .client_id = "another" } }));

    var private = try clearance.jwk.PrivateKey.parse(gpa, es256_private_jwk, .{});
    defer private.deinit();
    var session: oauth.dpop.Session = .init(try .fromJwk(&private, null));
    var bound = try oauth.TokenSet.init(gpa, .{ .access_token = "dpop-ui", .token_type = .dpop });
    defer bound.deinit();
    try testing.expectError(error.DpopRequired, oauth.fetchUserInfo(Standard, arena, io, &http, &server.value, &bound, "u1", .{}));
    const proved = try oauth.fetchUserInfo(Standard, arena, io, &http, &server.value, &bound, "u1", .{ .dpop = &session });
    try testing.expectEqualStrings("Jane Doe", proved.claims.name.?);

    var stale = try oauth.TokenSet.init(gpa, .{ .access_token = "old" });
    defer stale.deinit();
    const refused = try oauth.fetchUserInfo(Standard, arena, io, &http, &server.value, &stale, "u1", .{});
    try testing.expectEqual(oauth.errors.Code.invalid_token, refused.refused.code);
    try testing.expectEqualStrings("expired", refused.refused.description.slice());
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

/// A JWT for `audience`, signed with RFC 8037's key under `kid`.
fn signToken(gpa: std.mem.Allocator, io: Io, out: *std.Io.Writer, kid: []const u8, audience: []const u8) !void {
    const now: i64 = @intCast(@divFloor(Io.Clock.real.now(io).nanoseconds, std.time.ns_per_s));
    try signClaims(gpa, io, out, kid, .{ .iss = "issuer", .aud = audience, .exp = now + 600 });
}

fn signClaims(gpa: std.mem.Allocator, io: Io, out: *std.Io.Writer, kid: []const u8, claims: anytype) !void {
    return signTyped(gpa, io, out, kid, "at+jwt", claims);
}

fn signTyped(gpa: std.mem.Allocator, io: Io, out: *std.Io.Writer, kid: []const u8, typ: []const u8, claims: anytype) !void {
    var der: [48]u8 = undefined;
    _ = try std.fmt.hexToBytes(der[0..16], ed25519_der_prefix);
    _ = try std.base64.url_safe_no_pad.Decoder.decode(der[16..48], ed25519_d);
    const key = try cloak.PrivateKey.parse(gpa, &der, .{});
    defer key.deinit();
    try clearance.jwt.sign(gpa, io, out, .{ .kid = kid, .typ = typ }, claims, .{ .private = .{ .alg = .eddsa, .key = key } });
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

test "a resource server's bearer check: JWT access tokens with the key set, or introspection; 401 and 403 answers" {
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
    var arena_state: std.heap.ArenaAllocator = .init(gpa);
    defer arena_state.deinit();
    const arena = arena_state.allocator();
    const verifier: oauth.bearer.Verifier = .{
        .source = .{ .keys = .{ .set = &keys, .algorithms = &.{.eddsa} } },
        .issuer = "https://as.example",
        .resource = "https://rs.example/mcp",
        .resource_metadata = "https://rs.example/.well-known/oauth-protected-resource/mcp",
    };
    const now: i64 = @intCast(@divFloor(Io.Clock.real.now(io).nanoseconds, std.time.ns_per_s));
    var token: std.Io.Writer.Allocating = .init(gpa);
    defer token.deinit();
    try token.writer.writeAll("Bearer ");
    try signClaims(gpa, io, &token.writer, "k1", .{ .iss = "https://as.example", .aud = "https://rs.example/mcp", .sub = "u1", .client_id = "app", .scope = "mcp files:read", .exp = now + 600, .iat = now, .jti = "j1" });

    const allowed = try verifier.check(io, &http, arena, .{ .authorization = token.written() }, &.{"files:read"});
    try testing.expectEqualStrings("u1", allowed.allowed.subject.?);
    try testing.expectEqualStrings("app", allowed.allowed.client_id.?);

    const forbidden = (try verifier.check(io, &http, arena, .{ .authorization = token.written() }, &.{ "files:read", "files:write" })).refused;
    try testing.expectEqual(std.http.Status.forbidden, forbidden.status);
    var out: [256]u8 = undefined;
    var w: std.Io.Writer = .fixed(&out);
    try forbidden.write(&w);
    try testing.expectEqualStrings("Bearer error=\"insufficient_scope\", scope=\"files:read files:write\", resource_metadata=\"https://rs.example/.well-known/oauth-protected-resource/mcp\"", w.buffered());

    const anonymous = (try verifier.check(io, &http, arena, .{ .authorization = null }, &.{})).refused;
    try testing.expectEqual(std.http.Status.unauthorized, anonymous.status);
    try testing.expectEqual(@as(?oauth.errors.Code, null), anonymous.challenge.@"error");
    try testing.expectEqualStrings(verifier.resource_metadata.?, anonymous.challenge.resource_metadata.?);
    const malformed = (try verifier.check(io, &http, arena, .{ .authorization = "Bearer a b" }, &.{})).refused;
    try testing.expectEqual(std.http.Status.bad_request, malformed.status);

    // A token for another resource is refused here, as is a forged one.
    token.clearRetainingCapacity();
    try token.writer.writeAll("Bearer ");
    try signClaims(gpa, io, &token.writer, "k1", .{ .iss = "https://as.example", .aud = "https://other.example", .sub = "u1", .client_id = "app", .exp = now + 600, .iat = now, .jti = "j2" });
    const elsewhere = (try verifier.check(io, &http, arena, .{ .authorization = token.written() }, &.{})).refused;
    try testing.expectEqual(oauth.errors.Code.invalid_token, elsewhere.challenge.@"error".?);
    try testing.expectEqualStrings("audience", elsewhere.challenge.error_description.?);
    const forged = (try verifier.check(io, &http, arena, .{ .authorization = "Bearer eyJhbGciOiJFZERTQSJ9.e30.AAAA" }, &.{})).refused;
    try testing.expectEqual(std.http.Status.unauthorized, forged.status);

    // Introspection: the provider answers for the token `good`, naming its
    // own base as the audience.
    var introspector = try oauth.Introspector.init(gpa, p.url(&buffer, "/introspect"), p.base, .{ .id = "rs", .credentials = .{ .client_secret_basic = "pw" } }, .{});
    defer introspector.deinit();
    const asking: oauth.bearer.Verifier = .{ .source = .{ .introspection = &introspector }, .issuer = p.base, .resource = p.base };
    const active = try asking.check(io, &http, arena, .{ .authorization = "Bearer good" }, &.{"mcp"});
    try testing.expectEqualStrings("mcp", active.allowed.scope.?);
    const inactive = (try asking.check(io, &http, arena, .{ .authorization = "Bearer bad" }, &.{})).refused;
    try testing.expectEqualStrings("inactive", inactive.challenge.error_description.?);
    // A token the server will not introspect is the client's to fix: a 401,
    // not the 503 of a server that failed.
    const unsupported = (try asking.check(io, &http, arena, .{ .authorization = "Bearer eyJ.structured.jwt" }, &.{})).refused;
    try testing.expectEqual(std.http.Status.unauthorized, unsupported.status);
    try testing.expectEqualStrings("unsupported_token_type", unsupported.challenge.error_description.?);
}

test "an ID token from the code flow: the flow's nonce and the access token's hash expected" {
    const io = testing.io;
    var w: std.Io.Writer.Allocating = .init(testing.allocator);
    defer w.deinit();
    const server: oauth.metadata.AuthorizationServer = .{ .issuer = "https://op.example", .authorization_endpoint = "https://op.example/authorize" };
    var flow = try oauth.AuthorizationFlow.begin(io, &server, .{ .client_id = "app", .redirect_uri = "http://127.0.0.1/cb", .nonce = true }, &w.writer);
    defer flow.deinit();
    try testing.expect(std.mem.find(u8, w.written(), "&nonce=") != null);

    const now: i64 = @intCast(@divFloor(Io.Clock.real.now(io).nanoseconds, std.time.ns_per_s));
    var hash: [43]u8 = undefined;
    const at_hash = clearance.id_token.accessTokenHash(.eddsa, "at", &hash);
    var id: std.Io.Writer.Allocating = .init(testing.allocator);
    defer id.deinit();
    var der: [48]u8 = undefined;
    _ = try std.fmt.hexToBytes(der[0..16], ed25519_der_prefix);
    _ = try std.base64.url_safe_no_pad.Decoder.decode(der[16..48], ed25519_d);
    const key = try cloak.PrivateKey.parse(testing.allocator, &der, .{});
    defer key.deinit();
    try clearance.jwt.sign(testing.allocator, io, &id.writer, .{ .kid = "k1" }, .{ .iss = "https://op.example", .sub = "u1", .aud = "app", .nonce = @as([]const u8, &flow.nonce.?), .at_hash = at_hash, .exp = now + 600, .iat = now }, .{ .private = .{ .alg = .eddsa, .key = key } });
    var set = try oauth.TokenSet.init(testing.allocator, .{ .access_token = "at", .id_token = id.written() });
    defer set.deinit();
    var keys = try clearance.jwk.KeySet.parse(testing.allocator, "{\"kty\":\"OKP\",\"crv\":\"Ed25519\",\"kid\":\"k1\",\"x\":\"" ++ ed25519_x ++ "\"}", .{});
    defer keys.deinit();
    var scratch: [2048]u8 = undefined;
    const verified = try flow.verifyIdToken(void, &set, &server, "app", keys.keys, &.{.eddsa}, Io.Clock.real.now(io), &scratch);
    try testing.expectEqualStrings("u1", verified.registered.sub.?);
    // Another access token beside it fails its hash.
    var other = try oauth.TokenSet.init(testing.allocator, .{ .access_token = "other", .id_token = id.written() });
    defer other.deinit();
    try testing.expectError(error.WrongAccessTokenHash, flow.verifyIdToken(void, &other, &server, "app", keys.keys, &.{.eddsa}, Io.Clock.real.now(io), &scratch));
}

test "enterprise-managed authorization: the user's ID token exchanged for an ID-JAG, redeemed for an access token" {
    const gpa = testing.allocator;
    const io = testing.io;
    var p: Provider = undefined;
    try p.start(io);
    defer p.stop(io);
    var http: uplink.Client = .init(gpa, .{});
    defer http.deinit(io);
    var as = try oauth.discover(gpa, io, &http, p.base, .{});
    defer as.deinit();
    var buffer: [128]u8 = undefined;
    var idp_issuer: [128]u8 = undefined;
    const idp: oauth.metadata.AuthorizationServer = .{ .issuer = p.url(&idp_issuer, "/idp"), .token_endpoint = p.url(&buffer, "/idp/token") };
    const request: oauth.id_jag.Request = .{
        .idp_issuer = idp.issuer,
        .subject_token = "id-token-u1",
        .audience = as.value.issuer,
        .client_id = "mcp-client",
        .resource = "https://rs.example/mcp",
        .scope = "files:read admin",
    };
    var issued = try oauth.requestIdJag(gpa, io, &http, &idp, .{ .id = "idp-app" }, request, .{});
    var grant = &issued.granted;
    defer grant.deinit();
    // The provider narrowed the scope: what the ID-JAG carries is what the
    // access token is held to.
    try testing.expectEqualStrings("files:read", grant.scope.?);

    const client: oauth.Client = .{ .id = "mcp-client", .credentials = .{ .client_secret_basic = "pw" } };
    var redeemed = try oauth.redeemIdJag(gpa, io, &http, &as.value, client, grant, request.resource, .{});
    var set = &redeemed.tokens;
    defer set.deinit();
    try testing.expectEqualStrings("ema-at", set.access_token);
    try testing.expectEqualStrings("files:read", set.scope.?);
    // The server gave a refresh token anyway; it is not kept.
    try testing.expectEqual(@as(?[]const u8, null), set.refresh_token);

    // The wrong secret: the server's answer, as a value.
    const refused = try oauth.redeemIdJag(gpa, io, &http, &as.value, .{ .id = "mcp-client", .credentials = .{ .client_secret_basic = "wrong" } }, grant, request.resource, .{});
    try testing.expectEqual(oauth.errors.Code.invalid_client, refused.refused.code);
    // An expired ID-JAG is not sent.
    const before = blk: {
        p.mutex.lockUncancelable(io);
        defer p.mutex.unlock(io);
        break :blk p.token_requests;
    };
    grant.expires_at = 0;
    try testing.expectError(error.GrantExpired, oauth.redeemIdJag(gpa, io, &http, &as.value, client, grant, request.resource, .{}));
    p.mutex.lockUncancelable(io);
    defer p.mutex.unlock(io);
    try testing.expectEqual(before, p.token_requests);
}

test "an identity provider's refusal is its answer; an ID-JAG for another client is refused" {
    const gpa = testing.allocator;
    const io = testing.io;
    var p: Provider = undefined;
    try p.start(io);
    defer p.stop(io);
    var http: uplink.Client = .init(gpa, .{});
    defer http.deinit(io);
    var buffer: [128]u8 = undefined;
    var idp_issuer: [128]u8 = undefined;
    const idp: oauth.metadata.AuthorizationServer = .{ .issuer = p.url(&idp_issuer, "/idp"), .token_endpoint = p.url(&buffer, "/idp/token") };
    var request: oauth.id_jag.Request = .{
        .idp_issuer = idp.issuer,
        .subject_token = "stale",
        .audience = p.base,
        .client_id = "mcp-client",
        .resource = "https://rs.example/mcp",
    };
    const refused = try oauth.requestIdJag(gpa, io, &http, &idp, .{ .id = "idp-app" }, request, .{});
    try testing.expectEqual(oauth.errors.Code.invalid_grant, refused.refused.code);
    request.subject_token = "id-token-other-client";
    try testing.expectError(error.WrongClient, oauth.requestIdJag(gpa, io, &http, &idp, .{ .id = "idp-app" }, request, .{}));
    // Metadata of one provider and a request naming another.
    request.idp_issuer = "https://elsewhere.example";
    try testing.expectError(error.InvalidRequest, oauth.requestIdJag(gpa, io, &http, &idp, .{ .id = "idp-app" }, request, .{}));
}

test "a workload's JWT as the grant, with no client; a refusal is the server's answer, not retried" {
    const gpa = testing.allocator;
    const io = testing.io;
    var p: Provider = undefined;
    try p.start(io);
    defer p.stop(io);
    var http: uplink.Client = .init(gpa, .{});
    defer http.deinit(io);
    var as = try oauth.discover(gpa, io, &http, p.base, .{});
    defer as.deinit();
    const now: i64 = @intCast(@divFloor(Io.Clock.real.now(io).nanoseconds, std.time.ns_per_s));
    var workload: std.Io.Writer.Allocating = .init(gpa);
    defer workload.deinit();
    try signTyped(gpa, io, &workload.writer, "k1", "JWT", .{ .iss = "https://platform.example", .sub = "system:serviceaccount:ns:agent", .aud = p.base, .exp = now + 300 });
    var ok = try oauth.jwtBearer(gpa, io, &http, &as.value, null, workload.written(), null, .{});
    defer ok.tokens.deinit();
    try testing.expectEqualStrings("wif-at", ok.tokens.access_token);
    const before = blk: {
        p.mutex.lockUncancelable(io);
        defer p.mutex.unlock(io);
        break :blk p.token_requests;
    };
    const rejected = try oauth.jwtBearer(gpa, io, &http, &as.value, null, workload.written(), "wif.rejected", .{});
    try testing.expectEqual(oauth.errors.Code.invalid_scope, rejected.refused.code);
    p.mutex.lockUncancelable(io);
    defer p.mutex.unlock(io);
    try testing.expectEqual(before + 1, p.token_requests);
}
