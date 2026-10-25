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

const private_keys = [_][]const u8{
    "{\"kty\":\"OKP\",\"crv\":\"Ed25519\",\"d\":\"nWGxne_9WmC6hEr0kuwsxERJxWl7MmkZcDusAxyuf2A\",\"x\":\"11qYAYKxCrfVS_7TyWQHOg7hcvPapiMlrwIaaPcHURo\"}",
    "{\"kty\":\"EC\",\"crv\":\"P-256\",\"alg\":\"ES256\",\"x\":\"04N0xi21hshyvBp7I167sbE_bXqyqkAPfefdklMO7wY\",\"y\":\"UI8exy-C06a7DUnjIdENkxeFtHM4-l_41LqEw9nVgmw\",\"d\":\"yy49oPcINGK2ps0LmtxpB6UTEOiITghHBif6wDqmJ3c\"}",
};

/// Any bytes as a private JWK: refused, or a key whose signature its own
/// public half verifies, and nothing left owned after deinit.
fn anyPrivateKey(_: void, c: *shake.Case) !void {
    var buffer: [512]u8 = undefined;
    const input = shake.gen.mutated(c.source, &buffer, &private_keys);
    var private = jwk.PrivateKey.parse(c.gpa, input, .{}) catch return;
    defer private.deinit();
    const signer = jws.Signer.fromJwk(&private, null) catch return;
    var token: std.Io.Writer.Allocating = .init(c.gpa);
    defer token.deinit();
    try jws.sign(c.gpa, std.testing.io, &token.writer, .{}, "payload", signer);
    var scratch: [jws.scratchLength(512)]u8 = undefined;
    _ = try jws.verify(token.written(), &.{private.public}, .{ .algorithms = &.{signer.algorithm()} }, &scratch);
}

test "any bytes are read as a private key its public half verifies, or refused" {
    try shake.check(std.testing.allocator, {}, anyPrivateKey, .{ .cases = 2000 });
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

/// Any bytes through `inspect`: refused, or read as a signed token whose
/// payload is inside the scratch; and every token `verify` takes, `inspect`
/// reads the same.
fn anyInspected(_: void, c: *shake.Case) !void {
    var buffer: [512]u8 = undefined;
    const input = shake.gen.mutated(c.source, &buffer, &tokens);
    var scratch: [jws.scratchLength(512)]u8 = undefined;
    var verify_scratch: [jws.scratchLength(512)]u8 = undefined;
    var set = try jwk.KeySet.parse(c.gpa, sets[0], .{});
    defer set.deinit();
    const secret: [64]u8 = @splat(1);
    const keys = [_]Key{ set.keys[0], Key.hmac(&secret) };
    const verified: ?jws.Verified = jws.verify(input, &keys, .{ .algorithms = all }, &verify_scratch) catch null;
    const read = jws.inspect(input, .literal("16KiB"), &scratch) catch {
        if (verified != null) return error.VerifiedButNotRead;
        return;
    };
    if (read.alg.len == 0 or std.ascii.eqlIgnoreCase(read.alg, "none")) return error.UnsignedRead;
    const start = @intFromPtr(&scratch);
    const at = @intFromPtr(read.payload.ptr);
    if (read.payload.len > 0 and (at < start or at + read.payload.len > start + scratch.len)) return error.PayloadOutsideScratch;
    if (verified) |v| if (!std.mem.eql(u8, v.payload, read.payload)) return error.PayloadsDiffer;
    _ = jwt.inspect(void, input, .{ .required = .{ .exp = false } }, .{ .nanoseconds = 0 }, &scratch) catch return;
}

test "any bytes are read by inspect as a signed token, or refused; what verifies is read the same" {
    try shake.check(std.testing.allocator, {}, anyInspected, .{ .cases = 2000 });
}

const dpop = @import("dpop.zig");

/// A proof the fuzzer mutates, and the verifier's expectations of it.
const ProofCase = struct { proof: []const u8, now: std.Io.Timestamp };

/// Any bytes as a DPoP proof: refused, or verified for exactly the request
/// expected, signed by the key in its own header, whose thumbprint is the
/// binding returned.
fn anyProof(case: ProofCase, c: *shake.Case) !void {
    var buffer: [1024]u8 = undefined;
    const input = shake.gen.mutated(c.source, &buffer, &.{case.proof});
    var scratch: [jws.scratchLength(1024)]u8 = undefined;
    var verified: dpop.Verified = undefined;
    dpop.verifyProof(std.testing.io, input, .{ .algorithms = &.{ .es256, .eddsa }, .htm = "POST", .htu = "https://as.example/token" }, case.now, &scratch, &verified) catch return;
    if (verified.key.material == .hmac) return error.SecretKey;
    if (!std.mem.eql(u8, &verified.thumbprint, &jwk.thumbprint(verified.key))) return error.WrongThumbprint;
    // What verified must verify again with the key it named.
    _ = try jws.verifyWith(input, &verified.key, .{ .algorithms = &.{ .es256, .eddsa } }, &scratch);
}

test "any bytes are a DPoP proof of the request expected, by the key it carries, or refused" {
    const gpa = std.testing.allocator;
    var private = try jwk.PrivateKey.parse(gpa, "{\"kty\":\"OKP\",\"crv\":\"Ed25519\",\"d\":\"nWGxne_9WmC6hEr0kuwsxERJxWl7MmkZcDusAxyuf2A\",\"x\":\"11qYAYKxCrfVS_7TyWQHOg7hcvPapiMlrwIaaPcHURo\"}", .{});
    defer private.deinit();
    const key = try dpop.Key.fromJwk(&private, null);
    const now: std.Io.Timestamp = .{ .nanoseconds = 1_800_000_000 * std.time.ns_per_s };
    var out: std.Io.Writer.Allocating = .init(gpa);
    defer out.deinit();
    try dpop.writeProof(gpa, std.testing.io, &out.writer, &key, .{ .htm = "POST", .htu = "https://as.example/token" }, now);
    try shake.check(gpa, ProofCase{ .proof = out.written(), .now = now }, anyProof, .{ .cases = 1000 });
}
