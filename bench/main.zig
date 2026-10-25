//! clearance's benchmarks: JWT and JWS verification and signing per
//! algorithm, key sets read, DPoP proofs signed and verified; and OAuth's
//! messages: a token response read
//! into a `TokenSet`, a device authorization read (RFC 8628), a revocation request written and answered (RFC 7009), a pushed request
//! written and answered (RFC 9126), a UserInfo answer read, an authorization server's metadata read, an
//! authorization URL written with its PKCE verifier and state drawn. `bay bench` runs them in ReleaseFast and
//! writes one JSON line per row to stdout; `bay test` runs each row once with
//! `--smoke`. Timings are taken by hand, never in CI.
const std = @import("std");
const clearance = @import("clearance");
const oauth = @import("clearance.oauth");
const shakedown = @import("shakedown");
const provenance = @import("preflight_bench_options");

const WorkloadError = clearance.jwt.VerifyError || clearance.dpop.VerifyError || clearance.jwk.PrivateError || clearance.jwt.SignError || clearance.jwk.ParseError ||
    oauth.token.ReadError || oauth.device.ReadError || oauth.revocation.ReadError || oauth.par.ReadError || oauth.userinfo.ReadError || oauth.client_auth.Error || oauth.metadata.ReadError || oauth.authorize.WriteError || error{Refused};
const Row = shakedown.bench.Row(Bench, WorkloadError);

const secret: [32]u8 = @splat(0x2a);
const ed_jwks = "{\"keys\":[{\"kty\":\"OKP\",\"crv\":\"Ed25519\",\"kid\":\"ed\",\"x\":\"11qYAYKxCrfVS_7TyWQHOg7hcvPapiMlrwIaaPcHURo\"}]}";
const ed_token = "eyJhbGciOiJFZERTQSJ9.RXhhbXBsZSBvZiBFZDI1NTE5IHNpZ25pbmc.hgyY0il_MGCjP0JzlnLWG1PPOt7-09PGcvMg3AIbQR6dWbhijcNR4ki4iylGjg5BhVsPt9g7sVvpAr_MuM0KAg";

const Claims = struct { scope: []const u8 };

/// RFC 7515 A.3's P-256 key: a client's DPoP key.
const es256_private_jwk = "{\"kty\":\"EC\",\"crv\":\"P-256\",\"x\":\"f83OJ3D2xF1Bg8vub9tLe1gHMzV76e8Tus9uPHvRVEU\",\"y\":\"x_FEzRu9m36HLN_tue659LNpXW6pCyStikYjKIWI5a0\",\"d\":\"jpsQnnGQmL-YBIffH1136cspYG6-0iY7X1fCE9-E9LI\"}";
const dpop_htu = "https://server.example.com/token";
const dpop_now: std.Io.Timestamp = .{ .nanoseconds = 1_800_000_000 * std.time.ns_per_s };

/// A token response as a provider writes one: a JWT access token, a refresh
/// token and the granted scope.
const token_response = "{\"access_token\":\"eyJhbGciOiJSUzI1NiIsInR5cCI6ImF0K2p3dCIsImtpZCI6InJzYSJ9." ++ repeat('x', 400) ++ "." ++ repeat('y', 342) ++
    "\",\"token_type\":\"Bearer\",\"expires_in\":3600,\"refresh_token\":\"" ++ repeat('r', 64) ++ "\",\"scope\":\"openid profile email offline_access\"}";

fn repeat(comptime c: u8, comptime n: usize) *const [n]u8 {
    const bytes: [n]u8 = @splat(c);
    return &bytes;
}

/// RFC 8628 §3.2's example answer.
const device_authorization =
    \\{"device_code":"GmRhmhcxhwAzkoEqiMEg_DnyEysNkuNhszIySk9eS","user_code":"WDJB-MJHT",
    \\"verification_uri":"https://example.com/device","verification_uri_complete":"https://example.com/device?user_code=WDJB-MJHT",
    \\"expires_in":1800,"interval":5}
;

/// OpenID Connect Core §5.3.2's example answer.
const userinfo_answer =
    \\{"sub":"248289761001","name":"Jane Doe","given_name":"Jane","family_name":"Doe","preferred_username":"j.doe",
    \\"email":"janedoe@example.com","picture":"http://example.com/janedoe/me.jpg"}
;

/// RFC 8414 §3.2's example metadata.
const metadata =
    \\{"issuer":"https://server.example.com","authorization_endpoint":"https://server.example.com/authorize",
    \\"token_endpoint":"https://server.example.com/token","token_endpoint_auth_methods_supported":["client_secret_basic","private_key_jwt"],
    \\"token_endpoint_auth_signing_alg_values_supported":["RS256","ES256"],"userinfo_endpoint":"https://server.example.com/userinfo",
    \\"jwks_uri":"https://server.example.com/jwks.json","registration_endpoint":"https://server.example.com/register",
    \\"scopes_supported":["openid","profile","email","address","phone","offline_access"],"response_types_supported":["code","code token"],
    \\"service_documentation":"http://server.example.com/service_documentation.html","ui_locales_supported":["en-US","en-GB","en-CA","fr-FR","fr-CA"]}
;

const Bench = struct {
    gpa: std.mem.Allocator,
    io: std.Io = undefined,
    token: std.Io.Writer.Allocating = undefined,
    set: clearance.jwk.KeySet = undefined,
    scratch: [4096]u8 = undefined,
    sink: usize = 0,
    private: clearance.jwk.PrivateKey = undefined,
    proof: std.Io.Writer.Allocating = undefined,
    verified: clearance.dpop.Verified = undefined,

    fn setupDpop(b: *Bench) WorkloadError!void {
        b.private = try clearance.jwk.PrivateKey.parse(b.gpa, es256_private_jwk, .{});
        b.proof = .init(b.gpa);
        const key = clearance.dpop.Key.fromJwk(&b.private, null) catch return error.InvalidKey;
        try clearance.dpop.writeProof(b.gpa, b.io, &b.proof.writer, &key, .{ .htm = "POST", .htu = dpop_htu }, dpop_now);
    }

    fn teardownDpop(b: *Bench) WorkloadError!void {
        b.proof.deinit();
        b.private.deinit();
    }

    /// A DPoP proof for a token request, ES256.
    fn signProof(b: *Bench, units: u64) WorkloadError!void {
        const key = clearance.dpop.Key.fromJwk(&b.private, null) catch return error.InvalidKey;
        var out: std.Io.Writer.Allocating = .init(b.gpa);
        defer out.deinit();
        for (0..units) |_| {
            out.clearRetainingCapacity();
            try clearance.dpop.writeProof(b.gpa, b.io, &out.writer, &key, .{ .htm = "POST", .htu = dpop_htu }, dpop_now);
            b.sink +%= out.written().len;
        }
    }

    /// The same proof verified as a token endpoint does, its key read from
    /// its header.
    fn verifyProof(b: *Bench, units: u64) WorkloadError!void {
        for (0..units) |_| {
            try clearance.dpop.verifyProof(b.io, b.proof.written(), .{ .algorithms = &.{.es256}, .htm = "POST", .htu = dpop_htu }, dpop_now, &b.scratch, &b.verified);
            b.sink +%= b.verified.jti.len;
        }
    }

    fn setup(b: *Bench) WorkloadError!void {
        b.token = .init(b.gpa);
        try clearance.jwt.sign(b.gpa, b.io, &b.token.writer, .{}, .{ .exp = @as(i64, 4_000_000_000), .sub = "user-1", .scope = "read write" }, .{ .hmac = .{ .alg = .hs256, .secret = &secret } });
        b.set = try clearance.jwk.KeySet.parse(b.gpa, ed_jwks, .{});
    }

    fn teardown(b: *Bench) WorkloadError!void {
        b.set.deinit();
        b.token.deinit();
    }

    fn verifyHs256(b: *Bench, units: u64) WorkloadError!void {
        const keys = [_]clearance.Key{clearance.Key.hmac(&secret)};
        for (0..units) |_| {
            const verified = try clearance.jwt.verify(Claims, b.token.written(), &keys, .{ .algorithms = &.{.hs256} }, .{ .nanoseconds = 0 }, &b.scratch);
            b.sink +%= verified.claims.scope.len;
        }
    }

    fn verifyEdDsa(b: *Bench, units: u64) WorkloadError!void {
        for (0..units) |_| {
            const verified = try clearance.jws.verify(ed_token, b.set.keys, .{ .algorithms = &.{.eddsa} }, &b.scratch);
            b.sink +%= verified.payload.len;
        }
    }

    fn signHs256(b: *Bench, units: u64) WorkloadError!void {
        var out: [512]u8 = undefined;
        for (0..units) |_| {
            var w: std.Io.Writer = .fixed(&out);
            try clearance.jwt.sign(b.gpa, b.io, &w, .{}, .{ .exp = @as(i64, 4_000_000_000), .sub = "user-1" }, .{ .hmac = .{ .alg = .hs256, .secret = &secret } });
            b.sink +%= w.end;
        }
    }

    fn readTokenResponse(b: *Bench, units: u64) WorkloadError!void {
        for (0..units) |_| {
            const response = try oauth.token.readResponse(b.gpa, 200, token_response, .{ .now = .{ .nanoseconds = 0 } });
            var set = switch (response) {
                .tokens => |t| t,
                .refused => return error.Refused,
            };
            b.sink +%= set.access_token.len;
            set.deinit();
        }
    }

    fn readDeviceAuthorization(b: *Bench, units: u64) WorkloadError!void {
        for (0..units) |_| {
            const response = try oauth.device.readAuthorization(b.gpa, 200, device_authorization, .{ .now = .{ .nanoseconds = 0 } });
            var a = switch (response) {
                .authorization => |a| a,
                .refused => return error.Refused,
            };
            b.sink +%= a.user_code.len;
            a.deinit();
        }
    }

    /// RFC 7009 §2.1's request, with Basic, and its answer read.
    fn revokeRequest(b: *Bench, units: u64) WorkloadError!void {
        const client: oauth.Client = .{ .id = "s6BhdRkqt3", .credentials = .{ .client_secret_basic = "7Fjfp0ZBr1KtDRbnfVdmIw" } };
        for (0..units) |_| {
            var request = try oauth.revocation.request(b.gpa, b.io, client, "45ghiukldjahdnhzdauz/", .refresh_token, .{ .issuer = "https://server.example.com", .now = .{ .nanoseconds = 0 } });
            b.sink +%= request.body.len();
            request.deinit();
            const answer = try oauth.revocation.readResponse(200, "", .{});
            if (answer != .revoked) return error.Refused;
        }
    }

    /// RFC 9126 §2.1's pushed request built with Basic, and §2.2's answer
    /// read.
    fn pushRequest(b: *Bench, units: u64) WorkloadError!void {
        const client: oauth.Client = .{ .id = "s6BhdRkqt3", .credentials = .{ .client_secret_basic = "7Fjfp0ZBr1KtDRbnfVdmIw" } };
        const ask: oauth.authorize.Request = .{ .client_id = "s6BhdRkqt3", .redirect_uri = "https://client.example.org/cb", .state = "af0ifjsldkj", .code_challenge = "K2-ltc83acc4h0c9w6ESC_rEMTJ3bww-uCHaoeK1t8U", .scope = "openid" };
        for (0..units) |_| {
            var request = try oauth.par.request(b.gpa, b.io, client, ask, .{ .issuer = "https://server.example.com", .now = .{ .nanoseconds = 0 } });
            b.sink +%= request.body.len();
            request.deinit();
            const answer = try oauth.par.readResponse(201, "{\"request_uri\":\"urn:ietf:params:oauth:request_uri:6esc_11ACC5bwc014ltc14eY22c\",\"expires_in\":60}", .{ .now = .{ .nanoseconds = 0 } });
            b.sink +%= answer.pushed.request_uri.len;
        }
    }

    /// OpenID Connect Core §5.3.2's answer read as the standard claims, its
    /// subject held to the ID token's.
    fn readUserInfo(b: *Bench, units: u64) WorkloadError!void {
        var arena: std.heap.ArenaAllocator = .init(b.gpa);
        defer arena.deinit();
        for (0..units) |_| {
            _ = arena.reset(.retain_capacity);
            const r = try oauth.userinfo.readResponse(oauth.userinfo.Standard, arena.allocator(), 200, "application/json", &.{}, userinfo_answer, .{ .subject = "248289761001" }, .{});
            b.sink +%= r.claims.sub.len;
        }
    }

    fn readMetadata(b: *Bench, units: u64) WorkloadError!void {
        for (0..units) |_| {
            var parsed = try oauth.metadata.readAuthorizationServer(b.gpa, metadata, "https://server.example.com", .{});
            b.sink +%= parsed.value.issuer.len;
            parsed.deinit();
        }
    }

    fn writeAuthorizationUrl(b: *Bench, units: u64) WorkloadError!void {
        var out: [1024]u8 = undefined;
        for (0..units) |_| {
            var pkce: oauth.pkce.Pkce = .generate(b.io);
            defer pkce.deinit();
            var state: [oauth.pkce.length]u8 = undefined;
            oauth.pkce.random(b.io, &state);
            var w: std.Io.Writer = .fixed(&out);
            try oauth.authorize.writeUrl(&w, "https://as.example/authorize", .{
                .client_id = "app",
                .redirect_uri = "http://127.0.0.1:9/cb",
                .state = &state,
                .code_challenge = &pkce.challenge,
                .scope = "mcp",
                .resources = &.{"https://rs.example/mcp"},
            });
            b.sink +%= w.end;
        }
    }

    fn parseSet(b: *Bench, units: u64) WorkloadError!void {
        for (0..units) |_| {
            var set = try clearance.jwk.KeySet.parse(b.gpa, ed_jwks, .{});
            b.sink +%= set.keys.len;
            set.deinit();
        }
    }
};

const rows = [_]Row{
    .{ .name = "jwt/verify-hs256", .unit = "token", .run = Bench.verifyHs256, .fixture = .{ .lifetime = .row, .setup = Bench.setup, .teardown = Bench.teardown } },
    .{ .name = "jws/verify-eddsa", .unit = "token", .run = Bench.verifyEdDsa, .fixture = .{ .lifetime = .row, .setup = Bench.setup, .teardown = Bench.teardown } },
    .{ .name = "jwt/sign-hs256", .unit = "token", .run = Bench.signHs256, .fixture = .{ .lifetime = .row, .setup = Bench.setup, .teardown = Bench.teardown } },
    .{ .name = "jwk/parse-ed25519-set", .unit = "set", .run = Bench.parseSet },
    .{ .name = "dpop/sign-proof-es256", .unit = "proof", .run = Bench.signProof, .fixture = .{ .lifetime = .row, .setup = Bench.setupDpop, .teardown = Bench.teardownDpop } },
    .{ .name = "dpop/verify-proof-es256", .unit = "proof", .run = Bench.verifyProof, .fixture = .{ .lifetime = .row, .setup = Bench.setupDpop, .teardown = Bench.teardownDpop } },
    .{ .name = "oauth/read-token-response", .unit = "response", .run = Bench.readTokenResponse },
    .{ .name = "oauth/read-device-authorization", .unit = "response", .run = Bench.readDeviceAuthorization },
    .{ .name = "oauth/revocation-request", .unit = "request", .run = Bench.revokeRequest },
    .{ .name = "oauth/par-request", .unit = "request", .run = Bench.pushRequest },
    .{ .name = "oauth/read-userinfo", .unit = "response", .run = Bench.readUserInfo },
    .{ .name = "oauth/read-metadata-rfc8414", .unit = "document", .run = Bench.readMetadata },
    .{ .name = "oauth/write-authorization-url", .unit = "url", .run = Bench.writeAuthorizationUrl },
};

pub fn main(init: std.process.Init) !void {
    const args = try init.minimal.args.toSlice(init.arena.allocator());
    const options = try shakedown.bench.Options.fromArguments(args[1..]);
    var buffer: [4096]u8 = undefined;
    var stdout = std.Io.File.stdout().writerStreaming(init.io, &buffer);
    var b: Bench = .{ .gpa = init.gpa, .io = init.io };
    try shakedown.bench.run(WorkloadError, init.gpa, init.io, &stdout.interface, &b, &rows, .{ .commit = provenance.commit, .cpu = provenance.cpu, .os = provenance.os }, options);
    try stdout.interface.flush();
    std.mem.doNotOptimizeAway(b.sink);
}
