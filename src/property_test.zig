//! Properties of every parser of untrusted input, held to a model. Run seeded
//! in every test run, and by the fuzzer under `bay properties --fuzz`.
const std = @import("std");
const shake = @import("shakedown");
const jws = @import("jws.zig");
const jwt = @import("jwt.zig");
const jwk = @import("jwk.zig");
const jwe = @import("jwe.zig");
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

const logout = @import("logout.zig");

/// Any bytes as a logout token: refused, or verified as one, from the
/// provider for the client, naming a user or a session.
fn anyLogoutToken(token: []const u8, c: *shake.Case) !void {
    var buffer: [1024]u8 = undefined;
    const input = shake.gen.mutated(c.source, &buffer, &.{token});
    const secret: [32]u8 = @splat(0x4c);
    var scratch: [jws.scratchLength(1024)]u8 = undefined;
    const v = logout.verifyToken(std.testing.io, input, &.{Key.hmac(&secret)}, .{ .algorithms = &.{.hs256}, .issuer = "https://server.example.com", .client_id = "s6BhdRkqt3" }, .{ .nanoseconds = 1_471_566_200 * std.time.ns_per_s }, &scratch) catch return;
    if (v.sub == null and v.sid == null) return error.NamesNobody;
}

test "any bytes are a logout token for this client, naming a user or a session, or refused" {
    const gpa = std.testing.allocator;
    const secret: [32]u8 = @splat(0x4c);
    var out: std.Io.Writer.Allocating = .init(gpa);
    defer out.deinit();
    try jws.sign(gpa, std.testing.io, &out.writer, .{ .typ = logout.media_type }, "{\"iss\":\"https://server.example.com\",\"sub\":\"248289761001\",\"aud\":\"s6BhdRkqt3\",\"iat\":1471566154,\"exp\":1471566274,\"jti\":\"bWJq\",\"sid\":\"08a5019c\",\"events\":{\"http://schemas.openid.net/event/backchannel-logout\":{}}}", .{ .hmac = .{ .alg = .hs256, .secret = &secret } });
    try shake.check(gpa, @as([]const u8, out.written()), anyLogoutToken, .{ .cases = 1000 });
}

/// Seeds for the JSON serializations: a flattened and a general document.
const JsonCase = struct { flattened: []const u8, general: []const u8, secret: []const u8 };

/// Any bytes as a JWS JSON document: refused, or verified by a signature of
/// the document's whose algorithm the key fits, the payload inside the
/// scratch or the document.
fn anyJsonDocument(case: JsonCase, c: *shake.Case) !void {
    var buffer: [1024]u8 = undefined;
    const input = shake.gen.mutated(c.source, &buffer, &.{ case.flattened, case.general });
    var scratch: [jws.scratchLengthJson(1024, 0)]u8 = undefined;
    const keys = [_]Key{Key.hmac(case.secret)};
    const verified = jws.verifyJson(input, &keys, .{ .algorithms = all, .unencoded = shake.gen.boolean(c.source) }, &scratch) catch return;
    if (!verified.key.fits(verified.header.alg)) return error.KeyDoesNotFit;
    if (verified.index >= 16) return error.IndexOutOfRange;
}

test "any bytes are a JWS JSON document verified by one of its signatures, or refused" {
    const gpa = std.testing.allocator;
    const secret: [32]u8 = @splat(0x33);
    var flattened: std.Io.Writer.Allocating = .init(gpa);
    defer flattened.deinit();
    try jws.signJson(gpa, std.testing.io, &flattened.writer, .flattened, "payload", &.{.{ .signer = .{ .hmac = .{ .alg = .hs256, .secret = &secret } }, .header = .{ .kid = "k" } }}, .{});
    var general: std.Io.Writer.Allocating = .init(gpa);
    defer general.deinit();
    try jws.signJson(gpa, std.testing.io, &general.writer, .general, "$.02", &.{
        .{ .signer = .{ .hmac = .{ .alg = .hs512, .secret = &(@as([64]u8, @splat(1))) } }, .header = .{ .b64 = false } },
        .{ .signer = .{ .hmac = .{ .alg = .hs256, .secret = &secret } }, .header = .{ .b64 = false }, .unprotected = "{\"kid\":\"k\"}" },
    }, .{});
    try shake.check(gpa, JsonCase{ .flattened = flattened.written(), .general = general.written(), .secret = &secret }, anyJsonDocument, .{ .cases = 2000 });
}

/// Seeds for JWE: a compact token (A128KW), a flattened document (`dir`) and
/// a general one of two recipients (A256GCMKW, PBES2), all of `content`.
const JweCase = struct { seeds: [3][]const u8, kek: []const u8, cek: []const u8, wrap: []const u8 };
const jwe_content = "the one content";

/// Any bytes as a JWE: refused, or decrypted to the one content the seeds
/// carry (no mutation forges another), under allowlisted algorithms by a
/// key that fits them, the plaintext inside the scratch.
fn anyEncrypted(case: JweCase, c: *shake.Case) !void {
    var buffer: [2048]u8 = undefined;
    const input = shake.gen.mutated(c.source, &buffer, &case.seeds);
    var scratch: [jwe.scratchLength(2048)]u8 = undefined;
    const keys = [_]jwe.DecryptionKey{
        .{ .material = .{ .secret = case.kek }, .kid = "kw" },
        .{ .material = .{ .secret = case.cek }, .kid = "dir" },
        .{ .material = .{ .secret = case.wrap }, .kid = "gcm" },
        .{ .material = .{ .password = "pass phrase" }, .kid = "pw" },
    };
    const options: jwe.Options = .{
        .key_algorithms = &.{ .a128kw, .dir, .a256gcmkw, .pbes2_hs256_a128kw },
        .encryptions = &.{ .a128cbc_hs256, .a256gcm },
        .max_pbes2_count = 64,
    };
    const d = jwe.decrypt(std.testing.io, input, &keys, options, &scratch) catch return;
    if (!std.mem.eql(u8, jwe_content, d.plaintext)) return error.Forged;
    const start = @intFromPtr(&scratch);
    const at = @intFromPtr(d.plaintext.ptr);
    if (at < start or at + d.plaintext.len > start + scratch.len) return error.PlaintextOutsideScratch;
    if (d.index >= options.max_recipients) return error.IndexOutOfRange;
    for (keys) |k| {
        if (k.fits(d.header.alg, d.header.enc)) break;
    } else return error.KeyDoesNotFit;
}

test "any bytes are a JWE decrypted to the content its sender sealed, or refused" {
    const gpa = std.testing.allocator;
    const io = std.testing.io;
    const kek: [16]u8 = @splat(0x4b);
    const cek: [32]u8 = @splat(0x43);
    const wrap: [32]u8 = @splat(0x57);
    var compact: std.Io.Writer.Allocating = .init(gpa);
    defer compact.deinit();
    var kw = Key.hmac(&kek);
    kw.kid = "kw";
    try jwe.encrypt(gpa, io, &compact.writer, .{ .enc = .a128cbc_hs256 }, jwe_content, &.{.{ .alg = .a128kw, .key = .{ .key = kw } }}, .compact, .{});
    var flattened: std.Io.Writer.Allocating = .init(gpa);
    defer flattened.deinit();
    var direct = Key.hmac(&cek);
    direct.kid = "dir";
    try jwe.encrypt(gpa, io, &flattened.writer, .{ .enc = .a256gcm }, jwe_content, &.{.{ .alg = .dir, .key = .{ .key = direct } }}, .flattened, .{ .aad = "aad" });
    var general: std.Io.Writer.Allocating = .init(gpa);
    defer general.deinit();
    var gcm = Key.hmac(&wrap);
    gcm.kid = "gcm";
    try jwe.encrypt(gpa, io, &general.writer, .{ .enc = .a128cbc_hs256 }, jwe_content, &.{
        .{ .alg = .a256gcmkw, .key = .{ .key = gcm } },
        .{ .alg = .pbes2_hs256_a128kw, .key = .{ .password = .{ .password = "pass phrase", .count = 64, .salt_length = 8 } }, .kid = "pw" },
    }, .general, .{});
    const case: JweCase = .{ .seeds = .{ compact.written(), flattened.written(), general.written() }, .kek = &kek, .cek = &cek, .wrap = &wrap };
    try shake.check(gpa, case, anyEncrypted, .{ .cases = 1000 });
}

/// Any bytes as a nested ID token's JWE: refused, or verified as the signed
/// token sealed inside, never a plain signed token in its stead.
fn anyNested(case: NestedCase, c: *shake.Case) !void {
    var buffer: [2048]u8 = undefined;
    const input = shake.gen.mutated(c.source, &buffer, &.{ case.nested, case.signed });
    var scratch: [jwe.scratchLength(2048)]u8 = undefined;
    const keys = [_]Key{Key.hmac(case.secret)};
    const verified = jwt.verify(struct { name: []const u8 }, input, &keys, .{
        .algorithms = &.{.hs256},
        .required = .{ .exp = false },
        .decryption = .{ .io = std.testing.io, .keys = &.{.{ .material = .{ .secret = case.kek } }}, .options = .{ .key_algorithms = &.{.a128kw}, .encryptions = &.{.a128gcm} } },
    }, .{ .nanoseconds = 0 }, &scratch) catch return;
    if (!std.mem.eql(u8, "sealed", verified.claims.name)) return error.Forged;
    if (std.mem.count(u8, input, ".") != 4) return error.NotNested;
}

const NestedCase = struct { nested: []const u8, signed: []const u8, secret: []const u8, kek: []const u8 };

test "any bytes are a nested JWT whose signed content verifies, or refused" {
    const gpa = std.testing.allocator;
    const secret: [32]u8 = @splat(0x24);
    const kek: [16]u8 = @splat(0x4b);
    var signed: std.Io.Writer.Allocating = .init(gpa);
    defer signed.deinit();
    try jws.sign(gpa, std.testing.io, &signed.writer, .{ .typ = "JWT" }, "{\"name\":\"sealed\"}", .{ .hmac = .{ .alg = .hs256, .secret = &secret } });
    var nested: std.Io.Writer.Allocating = .init(gpa);
    defer nested.deinit();
    try jwe.encrypt(gpa, std.testing.io, &nested.writer, .{ .enc = .a128gcm, .cty = "JWT" }, signed.written(), &.{.{ .alg = .a128kw, .key = .{ .key = Key.hmac(&kek) } }}, .compact, .{});
    try shake.check(gpa, NestedCase{ .nested = nested.written(), .signed = signed.written(), .secret = &secret, .kek = &kek }, anyNested, .{ .cases = 1000 });
}
