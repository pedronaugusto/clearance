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

test "RFC 7520 4.1, 4.2 and 4.4: the cookbook's RS256, PS384 and HS256 signatures verify" {
    var buffer: [4096]u8 = undefined;
    var scratch: [8192]u8 = undefined;
    inline for (.{ .{ "4_1.rsa_v15_signature.json", Algorithm.rs256 }, .{ "4_2.rsa-pss_signature.json", Algorithm.ps384 }, .{ "4_4.hmac-sha2_integrity_protection.json", Algorithm.hs256 } }) |row| {
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

test "RFC 7520 4.3: ES512 is not an algorithm clearance has, so its signature is refused" {
    var buffer: [4096]u8 = undefined;
    var scratch: [8192]u8 = undefined;
    const token = try cookbookCompact("4_3.ecdsa_signature.json", &buffer);
    var diagnostics: jws.Diagnostics = .{};
    try std.testing.expectError(error.AlgorithmNotAllowed, jws.verify(token, &.{}, .{ .algorithms = all, .diagnostics = &diagnostics }, &scratch));
    try std.testing.expectEqual(jws.Check.algorithm_unknown, diagnostics.check);
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
    // RFC 7520 4.3's ES512 token: an algorithm clearance does not verify, read all the same.
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
