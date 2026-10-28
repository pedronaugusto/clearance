//! clearance's benchmarks: JWT and JWS verification and signing per
//! algorithm (ES512 on RFC 7520's P-521 key and ML-DSA-65 on RFC 9964's key among them), key sets read, flattened JWS JSON verified and signed, DPoP proofs signed and verified, a logout token
//! verified, JWE decrypted and encrypted (AES key wrap, RSA-OAEP-256, `dir`) and a nested ID token verified; and OAuth's
//! messages: a token response read
//! into a `TokenSet`, a device authorization read (RFC 8628), a revocation request written and answered (RFC 7009), a pushed request
//! written and answered (RFC 9126), a request object signed (RFC 9101), a UserInfo answer read, an authorization server's metadata read, an
//! authorization URL written with its PKCE verifier and state drawn. `bay bench` runs them in ReleaseFast and
//! writes one JSON line per row to stdout; `bay test` runs each row once with
//! `--smoke`. Timings are taken by hand, never in CI.
const std = @import("std");
const clearance = @import("clearance");
const oauth = @import("clearance.oauth");
const shakedown = @import("shakedown");
const provenance = @import("preflight_bench_options");

const WorkloadError = clearance.jwt.VerifyError || clearance.jwe.DecryptError || clearance.jwe.EncryptError || clearance.id_token.VerifyError || clearance.dpop.VerifyError || clearance.logout.VerifyError || clearance.jwk.PrivateError || clearance.jwt.SignError || clearance.jwk.ParseError ||
    oauth.token.ReadError || oauth.device.ReadError || oauth.revocation.ReadError || oauth.par.ReadError || oauth.userinfo.ReadError || oauth.client_auth.Error || oauth.metadata.ReadError || oauth.authorize.WriteError || oauth.request_object.Error || error{Refused};
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

/// The payload of the JSON rows: the claims the JWT rows sign.
const flattened_payload = "{\"exp\":4000000000,\"sub\":\"user-1\",\"scope\":\"read write\"}";

/// Back-Channel Logout 1.0 §2.4's example claims, with `exp`.
const logout_claims = "{\"iss\":\"https://server.example.com\",\"sub\":\"248289761001\",\"aud\":\"s6BhdRkqt3\",\"iat\":1471566154,\"exp\":1471566274,\"jti\":\"bWJq\",\"sid\":\"08a5019c-17e1-4977-8f42-65a12843ea02\",\"events\":{\"http://schemas.openid.net/event/backchannel-logout\":{}}}";
const logout_now: std.Io.Timestamp = .{ .nanoseconds = 1_471_566_200 * std.time.ns_per_s };

/// JWE's content: the bench's claims, as a token's.
const jwe_content = flattened_payload;
const kek: [16]u8 = @splat(0x4b);

/// An ID token's claims, as OpenID Connect Core §3.1.3.7 checks them.
const id_token_claims = "{\"iss\":\"https://op.example\",\"sub\":\"248289761001\",\"aud\":\"app\",\"nonce\":\"n-0S6_WzA2Mj\",\"exp\":1700000600,\"iat\":1699999990}";
const id_token_now: std.Io.Timestamp = .{ .nanoseconds = 1_700_000_000 * std.time.ns_per_s };

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
    logout_token: std.Io.Writer.Allocating = undefined,
    json_scratch: []u8 = &.{},
    jwe_token: std.Io.Writer.Allocating = undefined,
    jwe_scratch: []u8 = &.{},
    jwe_key: clearance.jwe.DecryptionKey = undefined,
    jwe_recipient: clearance.jwe.Recipient = undefined,

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

    /// RFC 7520 §4.3's P-521 key, and a token it signed.
    fn setupEs512(b: *Bench) WorkloadError!void {
        b.private = try clearance.jwk.PrivateKey.parse(b.gpa, @embedFile("data/es512.jwk.json"), .{});
        b.token = .init(b.gpa);
        const signer = clearance.jws.Signer.fromJwk(&b.private, .es512) catch return error.InvalidKey;
        try clearance.jwt.sign(b.gpa, b.io, &b.token.writer, .{}, .{ .exp = @as(i64, 4_000_000_000), .sub = "user-1", .scope = "read write" }, signer);
    }

    fn teardownEs512(b: *Bench) WorkloadError!void {
        b.token.deinit();
        b.private.deinit();
    }

    fn signEs512(b: *Bench, units: u64) WorkloadError!void {
        const signer = clearance.jws.Signer.fromJwk(&b.private, .es512) catch return error.InvalidKey;
        var out: [1024]u8 = undefined;
        for (0..units) |_| {
            var w: std.Io.Writer = .fixed(&out);
            try clearance.jwt.sign(b.gpa, b.io, &w, .{}, .{ .exp = @as(i64, 4_000_000_000), .sub = "user-1" }, signer);
            b.sink +%= w.end;
        }
    }

    fn verifyEs512(b: *Bench, units: u64) WorkloadError!void {
        for (0..units) |_| {
            const verified = try clearance.jwt.verify(Claims, b.token.written(), &.{b.private.public}, .{ .algorithms = &.{.es512} }, .{ .nanoseconds = 0 }, &b.scratch);
            b.sink +%= verified.claims.scope.len;
        }
    }

    /// RFC 9964 A.1's ML-DSA-65 key, and a token it signed.
    fn setupMlDsa65(b: *Bench) WorkloadError!void {
        b.private = try clearance.jwk.PrivateKey.parse(b.gpa, @embedFile("data/ml_dsa_65.jwk.json"), .{});
        b.token = .init(b.gpa);
        const signer = clearance.jws.Signer.fromJwk(&b.private, null) catch return error.InvalidKey;
        try clearance.jwt.sign(b.gpa, b.io, &b.token.writer, .{}, .{ .exp = @as(i64, 4_000_000_000), .sub = "user-1", .scope = "read write" }, signer);
        b.json_scratch = try b.gpa.alloc(u8, clearance.jws.scratchLength(b.token.written().len));
    }

    fn teardownMlDsa65(b: *Bench) WorkloadError!void {
        b.gpa.free(b.json_scratch);
        b.token.deinit();
        b.private.deinit();
    }

    fn signMlDsa65(b: *Bench, units: u64) WorkloadError!void {
        const signer = clearance.jws.Signer.fromJwk(&b.private, null) catch return error.InvalidKey;
        var out: [8192]u8 = undefined;
        for (0..units) |_| {
            var w: std.Io.Writer = .fixed(&out);
            try clearance.jwt.sign(b.gpa, b.io, &w, .{}, .{ .exp = @as(i64, 4_000_000_000), .sub = "user-1" }, signer);
            b.sink +%= w.end;
        }
    }

    fn verifyMlDsa65(b: *Bench, units: u64) WorkloadError!void {
        for (0..units) |_| {
            const verified = try clearance.jwt.verify(Claims, b.token.written(), &.{b.private.public}, .{ .algorithms = &.{.ml_dsa_65} }, .{ .nanoseconds = 0 }, b.json_scratch);
            b.sink +%= verified.claims.scope.len;
        }
    }

    /// The client's ES256 key (the DPoP one), which signs request objects.
    fn setupSigner(b: *Bench) WorkloadError!void {
        b.private = try clearance.jwk.PrivateKey.parse(b.gpa, es256_private_jwk, .{});
    }

    fn teardownSigner(b: *Bench) WorkloadError!void {
        b.private.deinit();
    }

    /// An authorization request signed as a request object, as FAPI 2.0
    /// pushes it.
    fn writeRequestObject(b: *Bench, units: u64) WorkloadError!void {
        const signer = clearance.jws.Signer.fromJwk(&b.private, .es256) catch return error.InvalidKey;
        var out: std.Io.Writer.Allocating = .init(b.gpa);
        defer out.deinit();
        for (0..units) |_| {
            out.clearRetainingCapacity();
            try oauth.request_object.write(b.gpa, b.io, &out.writer, "https://server.example.com", .{
                .client_id = "s6BhdRkqt3",
                .redirect_uri = "https://client.example.org/cb",
                .state = "af0ifjsldkj",
                .code_challenge = "K2-ltc83acc4h0c9w6ESC_rEMTJ3bww-uCHaoeK1t8U",
                .scope = "openid",
                .resources = &.{"https://rs.example/mcp"},
            }, .{ .signer = signer, .kid = "client-1" }, dpop_now);
            b.sink +%= out.written().len;
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

    /// Back-Channel Logout §2.4's token verified (HS256: the logout checks,
    /// not a public-key operation), with a replay set it is new to each time.
    fn verifyLogoutToken(b: *Bench, units: u64) WorkloadError!void {
        var replay: clearance.jwt.MemoryReplay = try .init(b.gpa, 1);
        defer replay.deinit();
        const keys = [_]clearance.Key{clearance.Key.hmac(&secret)};
        for (0..units) |_| {
            var held = replay.entries.acquireUncancelable(b.io);
            held.value().clearRetainingCapacity();
            held.deinit(b.io);
            const v = try clearance.logout.verifyToken(b.io, b.logout_token.written(), &keys, .{ .algorithms = &.{.hs256}, .issuer = "https://server.example.com", .client_id = "s6BhdRkqt3", .replay = &replay.replay }, logout_now, &b.scratch);
            b.sink +%= v.jti.len;
        }
    }

    /// A flattened JWS (RFC 7515 §7.2.2) of the bench's claims, HS256.
    fn setupFlattened(b: *Bench) WorkloadError!void {
        b.token = .init(b.gpa);
        try clearance.jws.signJson(b.gpa, b.io, &b.token.writer, .flattened, flattened_payload, &.{.{ .signer = .{ .hmac = .{ .alg = .hs256, .secret = &secret } }, .header = .{ .kid = "hs" } }}, .{});
        b.json_scratch = try b.gpa.alloc(u8, clearance.jws.scratchLengthJson(b.token.written().len, 0));
    }

    fn teardownFlattened(b: *Bench) WorkloadError!void {
        b.gpa.free(b.json_scratch);
        b.token.deinit();
    }

    fn verifyFlattened(b: *Bench, units: u64) WorkloadError!void {
        const keys = [_]clearance.Key{.{ .material = .{ .hmac = &secret }, .kid = "hs" }};
        for (0..units) |_| {
            const v = try clearance.jws.verifyJson(b.token.written(), &keys, .{ .algorithms = &.{.hs256} }, b.json_scratch);
            b.sink +%= v.payload.len;
        }
    }

    fn signFlattened(b: *Bench, units: u64) WorkloadError!void {
        var out: std.Io.Writer.Allocating = .init(b.gpa);
        defer out.deinit();
        for (0..units) |_| {
            out.clearRetainingCapacity();
            try clearance.jws.signJson(b.gpa, b.io, &out.writer, .flattened, flattened_payload, &.{.{ .signer = .{ .hmac = .{ .alg = .hs256, .secret = &secret } }, .header = .{ .kid = "hs" } }}, .{});
            b.sink +%= out.written().len;
        }
    }

    /// A compact JWE of `jwe_content` to the recipient, and the key that
    /// decrypts it.
    fn sealJwe(b: *Bench, enc: clearance.jwe.ContentEncryption) WorkloadError!void {
        b.jwe_token = .init(b.gpa);
        try clearance.jwe.encrypt(b.gpa, b.io, &b.jwe_token.writer, .{ .enc = enc }, jwe_content, &.{b.jwe_recipient}, .compact, .{});
        b.jwe_scratch = try b.gpa.alloc(u8, clearance.jwe.scratchLength(b.jwe_token.written().len));
    }

    fn setupKeyWrap(b: *Bench) WorkloadError!void {
        b.jwe_key = .{ .material = .{ .secret = &kek } };
        b.jwe_recipient = .{ .alg = .a128kw, .key = .{ .key = clearance.Key.hmac(&kek) } };
        try b.sealJwe(.a128cbc_hs256);
    }

    fn setupDirect(b: *Bench) WorkloadError!void {
        b.jwe_key = .{ .material = .{ .secret = &secret } };
        b.jwe_recipient = .{ .alg = .dir, .key = .{ .key = clearance.Key.hmac(&secret) } };
        try b.sealJwe(.a256gcm);
    }

    fn setupRsaOaep(b: *Bench) WorkloadError!void {
        b.private = try clearance.jwk.PrivateKey.parse(b.gpa, @embedFile("data/rsa_oaep_256.jwk.json"), .{ .purpose = .encryption });
        b.jwe_key = clearance.jwe.DecryptionKey.fromJwk(&b.private) catch return error.InvalidKey;
        b.jwe_recipient = .{ .alg = .rsa_oaep_256, .key = .{ .key = b.private.public } };
        try b.sealJwe(.a256gcm);
    }

    /// ECDH-ES+A128KW to the P-256 key: each encryption draws an ephemeral
    /// key, each decryption agrees with the token's.
    fn setupEcdhEs(b: *Bench) WorkloadError!void {
        b.private = try clearance.jwk.PrivateKey.parse(b.gpa, es256_private_jwk, .{ .purpose = .encryption });
        b.jwe_key = clearance.jwe.DecryptionKey.fromJwk(&b.private) catch return error.InvalidKey;
        b.jwe_recipient = .{ .alg = .ecdh_es_a128kw, .key = .{ .key = b.private.public } };
        try b.sealJwe(.a256gcm);
    }

    fn teardownJwe(b: *Bench) WorkloadError!void {
        b.gpa.free(b.jwe_scratch);
        b.jwe_token.deinit();
    }

    /// A row that parsed a private key (RSA-OAEP's, ECDH-ES's).
    fn teardownPrivate(b: *Bench) WorkloadError!void {
        try b.teardownJwe();
        b.private.deinit();
    }

    fn decryptJwe(b: *Bench, units: u64) WorkloadError!void {
        const options: clearance.jwe.Options = .{ .key_algorithms = &.{ .a128kw, .dir, .rsa_oaep_256, .ecdh_es_a128kw }, .encryptions = &.{ .a128cbc_hs256, .a256gcm } };
        for (0..units) |_| {
            const d = try clearance.jwe.decrypt(b.io, b.jwe_token.written(), &.{b.jwe_key}, options, b.jwe_scratch);
            b.sink +%= d.plaintext.len;
        }
    }

    fn encryptJwe(b: *Bench, units: u64) WorkloadError!void {
        var out: std.Io.Writer.Allocating = .init(b.gpa);
        defer out.deinit();
        const enc: clearance.jwe.ContentEncryption = if (b.jwe_recipient.alg == .a128kw) .a128cbc_hs256 else .a256gcm;
        for (0..units) |_| {
            out.clearRetainingCapacity();
            try clearance.jwe.encrypt(b.gpa, b.io, &out.writer, .{ .enc = enc }, jwe_content, &.{b.jwe_recipient}, .compact, .{});
            b.sink +%= out.written().len;
        }
    }

    /// An ID token signed HS256, then encrypted A128KW and A128GCM (OpenID
    /// Connect Core §10.2): decrypted, then verified with its checks.
    fn setupNested(b: *Bench) WorkloadError!void {
        var signed: std.Io.Writer.Allocating = .init(b.gpa);
        defer signed.deinit();
        try clearance.jws.sign(b.gpa, b.io, &signed.writer, .{ .typ = "JWT" }, id_token_claims, .{ .hmac = .{ .alg = .hs256, .secret = &secret } });
        b.jwe_token = .init(b.gpa);
        try clearance.jwe.encrypt(b.gpa, b.io, &b.jwe_token.writer, .{ .enc = .a128gcm, .cty = "JWT" }, signed.written(), &.{.{ .alg = .a128kw, .key = .{ .key = clearance.Key.hmac(&kek) } }}, .compact, .{});
        b.jwe_scratch = try b.gpa.alloc(u8, clearance.jwe.scratchLength(b.jwe_token.written().len));
    }

    fn verifyNested(b: *Bench, units: u64) WorkloadError!void {
        const keys = [_]clearance.Key{clearance.Key.hmac(&secret)};
        const expected: clearance.id_token.Expected = .{
            .algorithms = &.{.hs256},
            .issuer = "https://op.example",
            .client_id = "app",
            .nonce = "n-0S6_WzA2Mj",
            .decryption = .{ .io = b.io, .keys = &.{.{ .material = .{ .secret = &kek } }}, .options = .{ .key_algorithms = &.{.a128kw}, .encryptions = &.{.a128gcm} } },
        };
        for (0..units) |_| {
            const v = try clearance.id_token.verify(void, b.jwe_token.written(), &keys, expected, id_token_now, b.jwe_scratch);
            b.sink +%= v.registered.sub.?.len;
        }
    }

    fn setupLogout(b: *Bench) WorkloadError!void {
        b.logout_token = .init(b.gpa);
        try clearance.jws.sign(b.gpa, b.io, &b.logout_token.writer, .{ .typ = clearance.logout.media_type }, logout_claims, .{ .hmac = .{ .alg = .hs256, .secret = &secret } });
    }

    fn teardownLogout(b: *Bench) WorkloadError!void {
        b.logout_token.deinit();
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
    .{ .name = "jwt/sign-es512", .unit = "token", .run = Bench.signEs512, .fixture = .{ .lifetime = .row, .setup = Bench.setupEs512, .teardown = Bench.teardownEs512 } },
    .{ .name = "jwt/verify-es512", .unit = "token", .run = Bench.verifyEs512, .fixture = .{ .lifetime = .row, .setup = Bench.setupEs512, .teardown = Bench.teardownEs512 } },
    .{ .name = "jwt/sign-ml-dsa-65", .unit = "token", .run = Bench.signMlDsa65, .fixture = .{ .lifetime = .row, .setup = Bench.setupMlDsa65, .teardown = Bench.teardownMlDsa65 } },
    .{ .name = "jwt/verify-ml-dsa-65", .unit = "token", .run = Bench.verifyMlDsa65, .fixture = .{ .lifetime = .row, .setup = Bench.setupMlDsa65, .teardown = Bench.teardownMlDsa65 } },
    .{ .name = "oauth/request-object-es256", .unit = "object", .run = Bench.writeRequestObject, .fixture = .{ .lifetime = .row, .setup = Bench.setupSigner, .teardown = Bench.teardownSigner } },
    .{ .name = "jwk/parse-ed25519-set", .unit = "set", .run = Bench.parseSet },
    .{ .name = "dpop/sign-proof-es256", .unit = "proof", .run = Bench.signProof, .fixture = .{ .lifetime = .row, .setup = Bench.setupDpop, .teardown = Bench.teardownDpop } },
    .{ .name = "dpop/verify-proof-es256", .unit = "proof", .run = Bench.verifyProof, .fixture = .{ .lifetime = .row, .setup = Bench.setupDpop, .teardown = Bench.teardownDpop } },
    .{ .name = "jws/verify-flattened-hs256", .unit = "document", .run = Bench.verifyFlattened, .fixture = .{ .lifetime = .row, .setup = Bench.setupFlattened, .teardown = Bench.teardownFlattened } },
    .{ .name = "jws/sign-flattened-hs256", .unit = "document", .run = Bench.signFlattened },
    .{ .name = "jwe/decrypt-a128kw-a128cbc-hs256", .unit = "token", .run = Bench.decryptJwe, .fixture = .{ .lifetime = .row, .setup = Bench.setupKeyWrap, .teardown = Bench.teardownJwe } },
    .{ .name = "jwe/encrypt-a128kw-a128cbc-hs256", .unit = "token", .run = Bench.encryptJwe, .fixture = .{ .lifetime = .row, .setup = Bench.setupKeyWrap, .teardown = Bench.teardownJwe } },
    .{ .name = "jwe/decrypt-dir-a256gcm", .unit = "token", .run = Bench.decryptJwe, .fixture = .{ .lifetime = .row, .setup = Bench.setupDirect, .teardown = Bench.teardownJwe } },
    .{ .name = "jwe/decrypt-rsa-oaep-256-2048-a256gcm", .unit = "token", .run = Bench.decryptJwe, .fixture = .{ .lifetime = .row, .setup = Bench.setupRsaOaep, .teardown = Bench.teardownPrivate } },
    .{ .name = "jwe/encrypt-rsa-oaep-256-2048-a256gcm", .unit = "token", .run = Bench.encryptJwe, .fixture = .{ .lifetime = .row, .setup = Bench.setupRsaOaep, .teardown = Bench.teardownPrivate } },
    .{ .name = "jwe/decrypt-ecdh-es-a128kw-p256-a256gcm", .unit = "token", .run = Bench.decryptJwe, .fixture = .{ .lifetime = .row, .setup = Bench.setupEcdhEs, .teardown = Bench.teardownPrivate } },
    .{ .name = "jwe/encrypt-ecdh-es-a128kw-p256-a256gcm", .unit = "token", .run = Bench.encryptJwe, .fixture = .{ .lifetime = .row, .setup = Bench.setupEcdhEs, .teardown = Bench.teardownPrivate } },
    .{ .name = "id_token/verify-nested-a128kw-hs256", .unit = "token", .run = Bench.verifyNested, .fixture = .{ .lifetime = .row, .setup = Bench.setupNested, .teardown = Bench.teardownJwe } },
    .{ .name = "logout/verify-token-hs256", .unit = "token", .run = Bench.verifyLogoutToken, .fixture = .{ .lifetime = .row, .setup = Bench.setupLogout, .teardown = Bench.teardownLogout } },
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
