//! README.md's Usage blocks, built and run by the tests.
const std = @import("std");
const clearance = @import("clearance");

pub fn main(init: std.process.Init) !void {
    const io = init.io;
    const gpa = init.gpa;

    // --- README:verify ---
    const jwk = clearance.jwk;
    const jwt = clearance.jwt;

    // A key set as a provider publishes it (here one Ed25519 key, RFC 8037's).
    var keys = try jwk.KeySet.parse(gpa,
        \\{"keys":[{"kty":"OKP","crv":"Ed25519","kid":"2026-10",
        \\  "x":"11qYAYKxCrfVS_7TyWQHOg7hcvPapiMlrwIaaPcHURo"}]}
    , .{});
    defer keys.deinit();

    // The claims the application reads, beside the registered ones.
    const Claims = struct { scope: []const u8 = "" };

    const validation: jwt.Validation = .{
        // Which algorithms a token may use is the verifier's choice: no default.
        .algorithms = &.{.eddsa},
        .issuer = "https://as.example",
        .audience = "https://api.example",
        .typ = "at+jwt",
        .leeway = .literal("30s"),
    };
    // Verifying allocates nothing: the decoded token lives in a scratch buffer.
    var scratch: [4096]u8 = undefined;
    const now = std.Io.Clock.real.now(io);
    // --- README:verify ---

    // --- README:sign ---
    const secret: [32]u8 = @splat(0x2a);
    var token: std.Io.Writer.Allocating = .init(gpa);
    defer token.deinit();
    try jwt.sign(gpa, io, &token.writer, .{ .kid = "hmac-1" }, .{
        .iss = "https://as.example",
        .aud = "https://api.example",
        .exp = now.toSeconds() + 300,
        .scope = "read",
    }, .{ .hmac = .{ .alg = .hs256, .secret = &secret } });
    // --- README:sign ---

    var hmac_key = clearance.Key.hmac(&secret);
    hmac_key.kid = "hmac-1";
    const verified = try jwt.verify(Claims, token.written(), &.{hmac_key}, .{
        .algorithms = &.{.hs256},
        .issuer = "https://as.example",
        .audience = "https://api.example",
    }, now, &scratch);
    std.debug.assert(std.mem.eql(u8, verified.claims.scope, "read"));
    // The Ed25519 set refuses an HMAC token: the algorithm is not allowed.
    if (jwt.verify(Claims, token.written(), keys.keys, validation, now, &scratch)) |_| unreachable else |err| std.debug.assert(err == error.AlgorithmNotAllowed);
}
