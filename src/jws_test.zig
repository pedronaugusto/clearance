const std = @import("std");
const cloak = @import("cloak");
const jws = @import("jws.zig");
const jwk = @import("jwk.zig");
const Key = @import("Key.zig");
const Algorithm = @import("Algorithm.zig").Algorithm;

const gpa = std.testing.allocator;
const all = std.enums.values(Algorithm);

/// The cookbook's key for a vector, public members only.
fn cookbookKey(comptime file: []const u8) !jwk.KeySet {
    const Doc = struct { input: struct { key: std.json.Value } };
    const doc = try std.json.parseFromSlice(Doc, gpa, @embedFile("testing/vectors/rfc7520/" ++ file), .{ .ignore_unknown_fields = true });
    defer doc.deinit();
    var key = doc.value.input.key.object;
    inline for (.{ "d", "p", "q", "dp", "dq", "qi" }) |private| _ = key.swapRemove(private);
    const text = try std.json.Stringify.valueAlloc(gpa, std.json.Value{ .object = key }, .{});
    defer gpa.free(text);
    return jwk.KeySet.parse(gpa, text, .{ .secrets = true });
}

fn cookbookCompact(comptime file: []const u8, out: []u8) ![]const u8 {
    const Doc = struct { output: struct { compact: []const u8 } };
    const doc = try std.json.parseFromSlice(Doc, gpa, @embedFile("testing/vectors/rfc7520/" ++ file), .{ .ignore_unknown_fields = true });
    defer doc.deinit();
    @memcpy(out[0..doc.value.output.compact.len], doc.value.output.compact);
    return out[0..doc.value.output.compact.len];
}

const cookbook_payload = "It\xe2\x80\x99s a dangerous business, Frodo, going out your door. You step onto the road, and if you don't keep your feet, there\xe2\x80\x99s no knowing where you might be swept off to.";

test "RFC 7520 4.1 to 4.4: the cookbook's RS256, PS384, ES512 and HS256 signatures verify" {
    var buffer: [4096]u8 = undefined;
    var scratch: [8192]u8 = undefined;
    inline for (.{ .{ "4_1.rsa_v15_signature.json", Algorithm.rs256 }, .{ "4_2.rsa-pss_signature.json", Algorithm.ps384 }, .{ "4_3.ecdsa_signature.json", Algorithm.es512 }, .{ "4_4.hmac-sha2_integrity_protection.json", Algorithm.hs256 } }) |row| {
        var set = try cookbookKey(row[0]);
        defer set.deinit();
        try std.testing.expectEqual(@as(usize, 1), set.keys.len);
        const token = try cookbookCompact(row[0], &buffer);
        const verified = try jws.verify(token, set.keys, .{ .algorithms = &.{row[1]} }, &scratch);
        try std.testing.expectEqualStrings(cookbook_payload, verified.payload);
        try std.testing.expectEqual(row[1], verified.header.alg);
        // Not allowed by the caller: refused before any key is touched.
        const other: Algorithm = if (row[1] == .hs256) .rs256 else .hs256;
        try std.testing.expectError(error.AlgorithmNotAllowed, jws.verify(token, set.keys, .{ .algorithms = &.{other} }, &scratch));
    }
}

test "RFC 7520 4.3: ES512 is P-521's, refused under a P-256 or P-384 key and a signature of another length" {
    var buffer: [4096]u8 = undefined;
    var scratch: [8192]u8 = undefined;
    const token = try cookbookCompact("4_3.ecdsa_signature.json", &buffer);
    var set = try cookbookKey("4_3.ecdsa_signature.json");
    defer set.deinit();
    try std.testing.expectEqual(Key.Curve.p521, set.keys[0].material.ec.curve);
    try std.testing.expect(set.keys[0].fits(.es512));
    try std.testing.expect(!set.keys[0].fits(.es384));
    // The signature three bytes short: r || s is 132 bytes for P-521.
    try std.testing.expectError(error.InvalidSignature, jws.verify(token[0 .. token.len - 4], set.keys, .{ .algorithms = &.{.es512} }, &scratch));
}

const ed_public = "{\"kty\":\"OKP\",\"crv\":\"Ed25519\",\"x\":\"11qYAYKxCrfVS_7TyWQHOg7hcvPapiMlrwIaaPcHURo\"}";
const ed_token = "eyJhbGciOiJFZERTQSJ9.RXhhbXBsZSBvZiBFZDI1NTE5IHNpZ25pbmc.hgyY0il_MGCjP0JzlnLWG1PPOt7-09PGcvMg3AIbQR6dWbhijcNR4ki4iylGjg5BhVsPt9g7sVvpAr_MuM0KAg";

/// RFC 8037 A.1's private key as PKCS#8, the form cloak reads.
fn edPrivate() !cloak.PrivateKey {
    var der: [48]u8 = undefined;
    _ = try std.fmt.hexToBytes(der[0..16], "302e020100300506032b657004220420");
    _ = try std.base64.url_safe_no_pad.Decoder.decode(der[16..48], "nWGxne_9WmC6hEr0kuwsxERJxWl7MmkZcDusAxyuf2A");
    return cloak.PrivateKey.parse(gpa, &der, .{});
}

test "RFC 8037 A.4 and A.5: Ed25519 signs the example to the RFC's bytes and verifies it" {
    var set = try jwk.KeySet.parse(gpa, ed_public, .{});
    defer set.deinit();
    var scratch: [2048]u8 = undefined;
    const verified = try jws.verify(ed_token, set.keys, .{ .algorithms = &.{.eddsa} }, &scratch);
    try std.testing.expectEqualStrings("Example of Ed25519 signing", verified.payload);
    // The same key under the fully specified name (RFC 9864) is another algorithm: the header says EdDSA.
    try std.testing.expectError(error.AlgorithmNotAllowed, jws.verify(ed_token, set.keys, .{ .algorithms = &.{.ed25519} }, &scratch));

    const key = try edPrivate();
    defer key.deinit();
    // The RFC's header has no `typ`: written the same, Ed25519 is deterministic.
    var out: std.Io.Writer.Allocating = .init(gpa);
    defer out.deinit();
    try jws.sign(gpa, std.testing.io, &out.writer, .{}, "Example of Ed25519 signing", .{ .private = .{ .alg = .eddsa, .key = key } });
    try std.testing.expectEqualStrings(ed_token, out.written());
}

/// The cookbook's key for a vector as the file has it, private members and all.
fn cookbookPrivate(comptime file: []const u8) !jwk.PrivateKey {
    const Doc = struct { input: struct { key: std.json.Value } };
    const doc = try std.json.parseFromSlice(Doc, gpa, @embedFile("testing/vectors/rfc7520/" ++ file), .{ .ignore_unknown_fields = true });
    defer doc.deinit();
    const text = try std.json.Stringify.valueAlloc(gpa, doc.value.input.key, .{});
    defer gpa.free(text);
    return jwk.PrivateKey.parse(gpa, text, .{});
}

test "RFC 7520 4.1: the cookbook's private RSA JWK signs the example to its bytes" {
    var private = try cookbookPrivate("4_1.rsa_v15_signature.json");
    defer private.deinit();
    try std.testing.expectEqualStrings("bilbo.baggins@hobbiton.example", private.public.kid.?);
    var buffer: [4096]u8 = undefined;
    const expected = try cookbookCompact("4_1.rsa_v15_signature.json", &buffer);
    // RSA PKCS#1 v1.5 is deterministic: the same header, the same token.
    var out: std.Io.Writer.Allocating = .init(gpa);
    defer out.deinit();
    try jws.sign(gpa, std.testing.io, &out.writer, .{ .kid = private.public.kid }, cookbook_payload, try jws.Signer.fromJwk(&private, .rs256));
    try std.testing.expectEqualStrings(expected, out.written());
    // An RSA key names no algorithm of its own, and the cookbook's JWK has no `alg`.
    try std.testing.expectError(error.InvalidKey, jws.Signer.fromJwk(&private, null));
    try std.testing.expectError(error.InvalidKey, jws.Signer.fromJwk(&private, .es256));
}

test "RFC 7520 4.2: the cookbook's private RSA JWK signs PS384, and the token verifies with its public half" {
    var private = try cookbookPrivate("4_2.rsa-pss_signature.json");
    defer private.deinit();
    var out: std.Io.Writer.Allocating = .init(gpa);
    defer out.deinit();
    try jws.sign(gpa, std.testing.io, &out.writer, .{}, cookbook_payload, try jws.Signer.fromJwk(&private, .ps384));
    var scratch: [8192]u8 = undefined;
    const verified = try jws.verify(out.written(), &.{private.public}, .{ .algorithms = &.{.ps384} }, &scratch);
    try std.testing.expectEqualStrings(cookbook_payload, verified.payload);
}

test "RFC 7520 4.3: the cookbook's private P-521 JWK signs ES512, and the token verifies with its public half" {
    var private = try cookbookPrivate("4_3.ecdsa_signature.json");
    defer private.deinit();
    var out: std.Io.Writer.Allocating = .init(gpa);
    defer out.deinit();
    // ES512 from the key's curve, the algorithm its JWK names none of.
    try jws.sign(gpa, std.testing.io, &out.writer, .{}, cookbook_payload, try jws.Signer.fromJwk(&private, null));
    var scratch: [8192]u8 = undefined;
    const verified = try jws.verify(out.written(), &.{private.public}, .{ .algorithms = &.{.es512} }, &scratch);
    try std.testing.expectEqual(Algorithm.es512, verified.header.alg);
    try std.testing.expectEqualStrings(cookbook_payload, verified.payload);
    // The public half written back reads as the same key.
    var written: std.Io.Writer.Allocating = .init(gpa);
    defer written.deinit();
    try jwk.writePublic(&written.writer, private.public);
    var again = try jwk.KeySet.parse(gpa, written.written(), .{});
    defer again.deinit();
    try std.testing.expectEqualSlices(u8, private.public.material.ec.point, again.keys[0].material.ec.point);
}

/// RFC 8037 A.1's private key.
const ed_private_jwk = "{\"kty\":\"OKP\",\"crv\":\"Ed25519\",\"d\":\"nWGxne_9WmC6hEr0kuwsxERJxWl7MmkZcDusAxyuf2A\",\"x\":\"11qYAYKxCrfVS_7TyWQHOg7hcvPapiMlrwIaaPcHURo\"}";

test "RFC 8037 A.1 and A.4: the private Ed25519 JWK signs the example to the RFC's bytes" {
    var private = try jwk.PrivateKey.parse(gpa, ed_private_jwk, .{});
    defer private.deinit();
    var out: std.Io.Writer.Allocating = .init(gpa);
    defer out.deinit();
    // The curve implies EdDSA.
    try jws.sign(gpa, std.testing.io, &out.writer, .{}, "Example of Ed25519 signing", try jws.Signer.fromJwk(&private, null));
    try std.testing.expectEqualStrings(ed_token, out.written());
    // The public half is RFC 8037 A.3's key: its thumbprint names this one.
    var thumbprint: [43]u8 = undefined;
    _ = std.base64.url_safe_no_pad.Encoder.encode(&thumbprint, &jwk.thumbprint(private.public));
    try std.testing.expectEqualStrings("kPrK_qmxVWaYVA9wwBF6Iuo3vVzz7TxHCTwXBygrS4k", &thumbprint);
}

/// Wycheproof's P-256 signing key (json_web_signature_test.json, `kid-ec-sign`).
const ec_private_jwk = "{\"kty\":\"EC\",\"crv\":\"P-256\",\"alg\":\"ES256\",\"kid\":\"kid-ec-sign\",\"x\":\"04N0xi21hshyvBp7I167sbE_bXqyqkAPfefdklMO7wY\",\"y\":\"UI8exy-C06a7DUnjIdENkxeFtHM4-l_41LqEw9nVgmw\",\"d\":\"yy49oPcINGK2ps0LmtxpB6UTEOiITghHBif6wDqmJ3c\"}";

test "Wycheproof's private P-256 JWK signs ES256, and the token verifies with its public half alone" {
    var private = try jwk.PrivateKey.parse(gpa, ec_private_jwk, .{});
    defer private.deinit();
    var out: std.Io.Writer.Allocating = .init(gpa);
    defer out.deinit();
    try jws.sign(gpa, std.testing.io, &out.writer, .{}, "payload", try jws.Signer.fromJwk(&private, null));
    var scratch: [2048]u8 = undefined;
    _ = try jws.verify(out.written(), &.{private.public}, .{ .algorithms = &.{.es256} }, &scratch);
    try std.testing.expectError(error.InvalidKey, jws.Signer.fromJwk(&private, .es384));
}

test "a private JWK is refused for what it is, each by its error" {
    const cases = [_]struct { jwk.PrivateError, []const u8 }{
        .{ error.NotPrivate, ed_public },
        .{ error.UnsupportedKey, "{\"kty\":\"oct\",\"k\":\"AyM1SysPpbyDfgZld3umj1qzKObwVMkoqQ-EstJQLr_T-1qS0gZH75aKtMN3Yj0iPS4hcgUuTwjAzZr1Z9CAow\"}" },
        .{ error.UnsupportedKey, "{\"kty\":\"OKP\",\"crv\":\"X25519\",\"d\":\"nWGxne_9WmC6hEr0kuwsxERJxWl7MmkZcDusAxyuf2A\",\"x\":\"11qYAYKxCrfVS_7TyWQHOg7hcvPapiMlrwIaaPcHURo\"}" },
        // The scalar is another key's: the public half derived from it is not this `x`.
        .{ error.InvalidKey, "{\"kty\":\"OKP\",\"crv\":\"Ed25519\",\"d\":\"oWGxne_9WmC6hEr0kuwsxERJxWl7MmkZcDusAxyuf2A\",\"x\":\"11qYAYKxCrfVS_7TyWQHOg7hcvPapiMlrwIaaPcHURo\"}" },
        .{ error.InvalidKey, "{\"kty\":\"EC\",\"crv\":\"P-256\",\"x\":\"04N0xi21hshyvBp7I167sbE_bXqyqkAPfefdklMO7wY\",\"y\":\"UI8exy-C06a7DUnjIdENkxeFtHM4-l_41LqEw9nVgmw\",\"d\":\"zy49oPcINGK2ps0LmtxpB6UTEOiITghHBif6wDqmJ3c\"}" },
        // A member with an escape is not read: no key needs one.
        .{ error.InvalidKey, "{\"kty\":\"OKP\",\"crv\":\"Ed25519\",\"d\":\"\\u006eWGxne_9WmC6hEr0kuwsxERJxWl7MmkZcDusAxyuf2A\",\"x\":\"11qYAYKxCrfVS_7TyWQHOg7hcvPapiMlrwIaaPcHURo\"}" },
        .{ error.InvalidKey, "{\"kty\":\"OKP\",\"crv\":\"Ed25519\",\"d\":7,\"x\":\"11qYAYKxCrfVS_7TyWQHOg7hcvPapiMlrwIaaPcHURo\"}" },
        .{ error.NotForSigning, "{\"kty\":\"OKP\",\"crv\":\"Ed25519\",\"key_ops\":[\"verify\"],\"d\":\"nWGxne_9WmC6hEr0kuwsxERJxWl7MmkZcDusAxyuf2A\",\"x\":\"11qYAYKxCrfVS_7TyWQHOg7hcvPapiMlrwIaaPcHURo\"}" },
        .{ error.NotForSigning, "{\"kty\":\"OKP\",\"crv\":\"Ed25519\",\"use\":\"enc\",\"d\":\"nWGxne_9WmC6hEr0kuwsxERJxWl7MmkZcDusAxyuf2A\",\"x\":\"11qYAYKxCrfVS_7TyWQHOg7hcvPapiMlrwIaaPcHURo\"}" },
        .{ error.InvalidAlgorithm, "{\"kty\":\"OKP\",\"crv\":\"Ed25519\",\"alg\":\"ES256\",\"d\":\"nWGxne_9WmC6hEr0kuwsxERJxWl7MmkZcDusAxyuf2A\",\"x\":\"11qYAYKxCrfVS_7TyWQHOg7hcvPapiMlrwIaaPcHURo\"}" },
        .{ error.InvalidDocument, "[]" },
    };
    for (cases) |case| try std.testing.expectError(case[0], jwk.PrivateKey.parse(gpa, case[1], .{}));
    try std.testing.expectError(error.TooLarge, jwk.PrivateKey.parse(gpa, ed_private_jwk, .{ .max_bytes = .literal("64B") }));
}

test "an RSA private JWK without its CRT members, or with more primes, is not one clearance signs with" {
    const Doc = struct { input: struct { key: std.json.Value } };
    inline for (.{ "p", "oth" }) |change| {
        const doc = try std.json.parseFromSlice(Doc, gpa, @embedFile("testing/vectors/rfc7520/4_1.rsa_v15_signature.json"), .{ .ignore_unknown_fields = true });
        defer doc.deinit();
        var key = doc.value.input.key.object;
        if (comptime std.mem.eql(u8, change, "p")) _ = key.swapRemove("p") else try key.put(doc.arena.allocator(), "oth", .{ .integer = 1 });
        const text = try std.json.Stringify.valueAlloc(gpa, std.json.Value{ .object = key }, .{});
        defer gpa.free(text);
        try std.testing.expectError(error.UnsupportedKey, jwk.PrivateKey.parse(gpa, text, .{}));
    }
}

test "every allocation a private JWK's reading makes is released when one fails" {
    try std.testing.checkAllAllocationFailures(gpa, struct {
        fn run(a: std.mem.Allocator) !void {
            var private = try jwk.PrivateKey.parse(a, ec_private_jwk, .{});
            private.deinit();
        }
    }.run, .{});
}

test "a signature made with each algorithm verifies with its key and no other" {
    const secret: [64]u8 = @splat(0x5c);
    var out: std.Io.Writer.Allocating = .init(gpa);
    defer out.deinit();
    var scratch: [4096]u8 = undefined;
    inline for (.{ Algorithm.hs256, Algorithm.hs384, Algorithm.hs512 }) |alg| {
        out.clearRetainingCapacity();
        try jws.sign(gpa, std.testing.io, &out.writer, .{ .kid = "k1" }, "payload", .{ .hmac = .{ .alg = alg, .secret = &secret } });
        var key = Key.hmac(&secret);
        key.kid = "k1";
        const verified = try jws.verify(out.written(), &.{key}, .{ .algorithms = &.{alg} }, &scratch);
        try std.testing.expectEqualStrings("payload", verified.payload);
        try std.testing.expectEqualStrings("k1", verified.header.kid.?);
        const other_secret: [64]u8 = @splat(0x5d);
        var other = Key.hmac(&other_secret);
        other.kid = "k1";
        try std.testing.expectError(error.InvalidSignature, jws.verify(out.written(), &.{other}, .{ .algorithms = &.{alg} }, &scratch));
        // A key with another kid is not the token's key.
        var stranger = Key.hmac(&secret);
        stranger.kid = "k2";
        try std.testing.expectError(error.NoKey, jws.verify(out.written(), &.{stranger}, .{ .algorithms = &.{alg} }, &scratch));
    }
    // An HMAC secret shorter than the hash is refused both ways (RFC 7518 3.2).
    try std.testing.expectError(error.InvalidKey, jws.sign(gpa, std.testing.io, &out.writer, .{}, "p", .{ .hmac = .{ .alg = .hs512, .secret = secret[0..32] } }));
}

test "the header's own key, a third dot, crit and none are refused" {
    var scratch: [4096]u8 = undefined;
    const secret: [32]u8 = @splat(7);
    const keys = [_]Key{Key.hmac(&secret)};
    // {"alg":"none"}.payload. : `none` is not an algorithm here.
    try std.testing.expectError(error.AlgorithmNotAllowed, jws.verify("eyJhbGciOiJub25lIn0.cGF5bG9hZA.", &keys, .{ .algorithms = all }, &scratch));
    try std.testing.expectError(error.Malformed, jws.verify("a.b.c.d", &keys, .{ .algorithms = all }, &scratch));
    try std.testing.expectError(error.Malformed, jws.verify("a.b", &keys, .{ .algorithms = all }, &scratch));
    const dots: [20000]u8 = @splat('.');
    try std.testing.expectError(error.TooLarge, jws.verify(&dots, &keys, .{ .algorithms = all }, &scratch));
    try std.testing.expectError(error.Malformed, jws.verify(dots[0..100], &keys, .{ .algorithms = all }, &scratch));
    // {"alg":"HS256","crit":["exp"],"exp":1}
    var out: std.Io.Writer.Allocating = .init(gpa);
    defer out.deinit();
    try out.writer.writeAll("eyJhbGciOiJIUzI1NiIsImNyaXQiOlsiZXhwIl0sImV4cCI6MX0.cA.");
    try std.testing.expectError(error.UnsupportedCritical, jws.verify(out.written(), &keys, .{ .algorithms = all }, &scratch));
}

test "a key set picks by kid; without a kid only a single fitting key verifies" {
    const a: [32]u8 = @splat(1);
    const b: [32]u8 = @splat(2);
    var ka = Key.hmac(&a);
    ka.kid = "a";
    var kb = Key.hmac(&b);
    kb.kid = "b";
    var out: std.Io.Writer.Allocating = .init(gpa);
    defer out.deinit();
    var scratch: [4096]u8 = undefined;
    try jws.sign(gpa, std.testing.io, &out.writer, .{}, "p", .{ .hmac = .{ .alg = .hs256, .secret = &b } });
    // Two fit and the token names none: nothing to choose by.
    try std.testing.expectError(error.NoKey, jws.verify(out.written(), &.{ ka, kb }, .{ .algorithms = &.{.hs256} }, &scratch));
    _ = try jws.verify(out.written(), &.{kb}, .{ .algorithms = &.{.hs256} }, &scratch);
    out.clearRetainingCapacity();
    try jws.sign(gpa, std.testing.io, &out.writer, .{ .kid = "b" }, "p", .{ .hmac = .{ .alg = .hs256, .secret = &b } });
    _ = try jws.verify(out.written(), &.{ ka, kb }, .{ .algorithms = &.{.hs256} }, &scratch);
}

test "verifying allocates nothing and needs only the scratch it asks for" {
    var set = try jwk.KeySet.parse(gpa, ed_public, .{});
    defer set.deinit();
    var scratch: [2048]u8 = undefined;
    const length = jws.scratchLength(ed_token.len);
    _ = try jws.verify(ed_token, set.keys, .{ .algorithms = &.{.eddsa} }, scratch[0..length]);
    try std.testing.expectError(error.ScratchTooSmall, jws.verify(ed_token, set.keys, .{ .algorithms = &.{.eddsa} }, scratch[0 .. length - 1]));
}

test "inspect reads a token it cannot verify, and refuses one that is not signed or not well formed" {
    var scratch: [4096]u8 = undefined;
    // RFC 7520 4.3's ES512 token, read without its key.
    var buffer: [4096]u8 = undefined;
    const es512 = try cookbookCompact("4_3.ecdsa_signature.json", &buffer);
    const read = try jws.inspect(es512, .literal("16KiB"), &scratch);
    try std.testing.expectEqualStrings("ES512", read.alg);
    try std.testing.expectEqualStrings(cookbook_payload, read.payload);
    const ed = try jws.inspect(ed_token, .literal("16KiB"), &scratch);
    try std.testing.expectEqualStrings("EdDSA", ed.alg);
    try std.testing.expectEqualStrings("Example of Ed25519 signing", ed.payload);

    // {"alg":"none"}, {"alg":"NONE"}, {"alg":""}, and a token with no signature.
    try std.testing.expectError(error.Unsigned, jws.inspect("eyJhbGciOiJub25lIn0.cGF5bG9hZA.c2ln", .literal("16KiB"), &scratch));
    try std.testing.expectError(error.Unsigned, jws.inspect("eyJhbGciOiJOT05FIn0.cGF5bG9hZA.c2ln", .literal("16KiB"), &scratch));
    try std.testing.expectError(error.Unsigned, jws.inspect("eyJhbGciOiIifQ.cGF5bG9hZA.c2ln", .literal("16KiB"), &scratch));
    try std.testing.expectError(error.Unsigned, jws.inspect("eyJhbGciOiJFZERTQSJ9.cGF5bG9hZA.", .literal("16KiB"), &scratch));
    try std.testing.expectError(error.Malformed, jws.inspect("eyJhbGciOiJFZERTQSJ9.cGF5bG9hZA", .literal("16KiB"), &scratch));
    try std.testing.expectError(error.Malformed, jws.inspect("eyJhbGciOiJFZERTQSJ9.cGF5bG9hZA.c2ln.x", .literal("16KiB"), &scratch));
    try std.testing.expectError(error.TooLarge, jws.inspect(ed_token, .literal("64B"), &scratch));
    // {"alg":"HS256","crit":["exp"],"exp":1}
    try std.testing.expectError(error.UnsupportedCritical, jws.inspect("eyJhbGciOiJIUzI1NiIsImNyaXQiOlsiZXhwIl0sImV4cCI6MX0.cA.c2ln", .literal("16KiB"), &scratch));
    try std.testing.expectError(error.ScratchTooSmall, jws.inspect(ed_token, .literal("16KiB"), scratch[0..16]));
}

test "an external signer signs what clearance built, and its token verifies" {
    const Kms = struct {
        key: cloak.PrivateKey,
        calls: u32 = 0,
        fn sign(context: ?*anyopaque, io: std.Io, alg: Algorithm, input: []const u8, out: *[jws.Signer.max_signature]u8) error{SigningFailed}![]const u8 {
            _ = io;
            const kms: *@This() = @ptrCast(@alignCast(context.?)); // safe: the test passes its own Kms
            kms.calls += 1;
            if (alg != .eddsa) return error.SigningFailed;
            return kms.key.sign(alg.signature(), input, &.{}, out) catch error.SigningFailed;
        }
    };
    var kms: Kms = .{ .key = try edPrivate() };
    defer kms.key.deinit();
    var out: std.Io.Writer.Allocating = .init(gpa);
    defer out.deinit();
    try jws.sign(gpa, std.testing.io, &out.writer, .{}, "Example of Ed25519 signing", .{ .external = .{ .alg = .eddsa, .context = &kms, .sign = Kms.sign } });
    // Ed25519 is deterministic: the RFC's own token.
    try std.testing.expectEqualStrings(ed_token, out.written());
    try std.testing.expectEqual(@as(u32, 1), kms.calls);
    try std.testing.expectError(error.SigningFailed, jws.sign(gpa, std.testing.io, &out.writer, .{}, "x", .{ .external = .{ .alg = .es256, .context = &kms, .sign = Kms.sign } }));
}

/// RFC 9964 A.1's example of `name`: the private JWK, the token, and the
/// bytes signed and the signature, as hex.
const MlDsaExample = struct { jwk: std.json.Value, jws: []const u8, raw_to_be_signed: []const u8, raw_signature: []const u8 };

fn mldsaExample(comptime name: []const u8) !std.json.Parsed(MlDsaExample) {
    return std.json.parseFromSlice(MlDsaExample, gpa, @embedFile("testing/vectors/rfc9964/a_1." ++ name ++ ".json"), .{ .ignore_unknown_fields = true });
}

fn jsonText(value: std.json.Value) ![]u8 {
    return std.json.Stringify.valueAlloc(gpa, value, .{});
}

test "RFC 9964 A.1: each ML-DSA example verifies with its public JWK, named by its thumbprint, and its private JWK signs tokens that verify" {
    var scratch: [16384]u8 = undefined;
    inline for (.{ .{ "ml_dsa_44", Algorithm.ml_dsa_44 }, .{ "ml_dsa_65", Algorithm.ml_dsa_65 }, .{ "ml_dsa_87", Algorithm.ml_dsa_87 } }) |row| {
        const example = try mldsaExample(row[0]);
        defer example.deinit();
        const private_text = try jsonText(example.value.jwk);
        defer gpa.free(private_text);
        var public_value = try example.value.jwk.object.clone(gpa);
        defer public_value.deinit(gpa);
        _ = public_value.swapRemove("priv");
        const public_text = try jsonText(.{ .object = public_value });
        defer gpa.free(public_text);

        var set = try jwk.KeySet.parse(gpa, public_text, .{});
        defer set.deinit();
        try std.testing.expectEqual(@as(usize, 1), set.keys.len);
        try std.testing.expectEqual(row[1].mldsa().?, set.keys[0].material.akp.level);
        // RFC 9964 §6: the examples' kid is the key's thumbprint over alg, kty and pub.
        var thumbprint: std.Io.Writer.Allocating = .init(gpa);
        defer thumbprint.deinit();
        try @import("base64url.zig").encode(&thumbprint.writer, &jwk.thumbprint(set.keys[0]));
        try std.testing.expectEqualStrings(set.keys[0].kid.?, thumbprint.written());

        const verified = try jws.verify(example.value.jws, set.keys, .{ .algorithms = &.{row[1]} }, &scratch);
        try std.testing.expectEqual(row[1], verified.header.alg);
        try std.testing.expectEqualStrings("It\xe2\x80\x99s a dangerous business, Frodo, going out your door.", verified.payload);
        // Another level is another algorithm: not allowed, and not this key's.
        const other: Algorithm = if (row[1] == .ml_dsa_44) .ml_dsa_65 else .ml_dsa_44;
        try std.testing.expectError(error.AlgorithmNotAllowed, jws.verify(example.value.jws, set.keys, .{ .algorithms = &.{other} }, &scratch));
        try std.testing.expect(!set.keys[0].fits(other));
        // One bit of the signature's last character changed.
        const tampered = try gpa.dupe(u8, example.value.jws);
        defer gpa.free(tampered);
        tampered[tampered.len - 1] = if (tampered[tampered.len - 1] == 'A') 'B' else 'A';
        try std.testing.expectError(error.InvalidSignature, jws.verify(tampered, set.keys, .{ .algorithms = &.{row[1]} }, &scratch));

        // The private JWK: its seed, its algorithm named by its own alg.
        var private = try jwk.PrivateKey.parse(gpa, private_text, .{});
        defer private.deinit();
        const signer = try jws.Signer.fromJwk(&private, null);
        try std.testing.expectEqual(row[1], signer.algorithm());
        try std.testing.expectError(error.InvalidKey, jws.Signer.fromJwk(&private, other));
        var out: std.Io.Writer.Allocating = .init(gpa);
        defer out.deinit();
        try jws.sign(gpa, std.testing.io, &out.writer, .{ .kid = private.public.kid }, "payload", signer);
        const mine = try jws.verify(out.written(), set.keys, .{ .algorithms = &.{row[1]} }, &scratch);
        try std.testing.expectEqualStrings("payload", mine.payload);
    }
}

test "RFC 9964 A.1: ML-DSA-44's example signature is the deterministic one over its signing input" {
    const example = try mldsaExample("ml_dsa_44");
    defer example.deinit();
    const text = try jsonText(example.value.jwk);
    defer gpa.free(text);
    var private = try jwk.PrivateKey.parse(gpa, text, .{});
    defer private.deinit();
    var input: [4096]u8 = undefined;
    const signing_input = try std.fmt.hexToBytes(&input, example.value.raw_to_be_signed);
    var expected: [cloak.PrivateKey.max_signature]u8 = undefined;
    const signature = try std.fmt.hexToBytes(&expected, example.value.raw_signature);
    const noise: [32]u8 = @splat(0);
    var out: [cloak.PrivateKey.max_signature]u8 = undefined;
    try std.testing.expectEqualSlices(u8, signature, try private.key.sign(.{ .mldsa = .mldsa44 }, signing_input, &noise, &out));
}
