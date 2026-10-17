//! clearance's benchmarks: JWT and JWS verification and signing per
//! algorithm, key sets read; and OAuth's messages: a token response read
//! into a `TokenSet`, an authorization server's metadata read, an
//! authorization URL written with its PKCE verifier and state drawn. `bay bench` runs them in ReleaseFast and
//! writes one JSON line per row to stdout; `bay test` runs each row once with
//! `--smoke`. Timings are taken by hand, never in CI.
const std = @import("std");
const clearance = @import("clearance");
const oauth = @import("clearance.oauth");
const shakedown = @import("shakedown");
const provenance = @import("preflight_bench_options");

const WorkloadError = clearance.jwt.VerifyError || clearance.jwt.SignError || clearance.jwk.ParseError ||
    oauth.token.ReadError || oauth.metadata.ReadError || oauth.authorize.WriteError || error{Refused};
const Row = shakedown.bench.Row(Bench, WorkloadError);

const secret: [32]u8 = @splat(0x2a);
const ed_jwks = "{\"keys\":[{\"kty\":\"OKP\",\"crv\":\"Ed25519\",\"kid\":\"ed\",\"x\":\"11qYAYKxCrfVS_7TyWQHOg7hcvPapiMlrwIaaPcHURo\"}]}";
const ed_token = "eyJhbGciOiJFZERTQSJ9.RXhhbXBsZSBvZiBFZDI1NTE5IHNpZ25pbmc.hgyY0il_MGCjP0JzlnLWG1PPOt7-09PGcvMg3AIbQR6dWbhijcNR4ki4iylGjg5BhVsPt9g7sVvpAr_MuM0KAg";

const Claims = struct { scope: []const u8 };

/// A token response as a provider writes one: a JWT access token, a refresh
/// token and the granted scope.
const token_response = "{\"access_token\":\"eyJhbGciOiJSUzI1NiIsInR5cCI6ImF0K2p3dCIsImtpZCI6InJzYSJ9." ++ repeat('x', 400) ++ "." ++ repeat('y', 342) ++
    "\",\"token_type\":\"Bearer\",\"expires_in\":3600,\"refresh_token\":\"" ++ repeat('r', 64) ++ "\",\"scope\":\"openid profile email offline_access\"}";

fn repeat(comptime c: u8, comptime n: usize) *const [n]u8 {
    const bytes: [n]u8 = @splat(c);
    return &bytes;
}

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
    .{ .name = "oauth/read-token-response", .unit = "response", .run = Bench.readTokenResponse },
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
