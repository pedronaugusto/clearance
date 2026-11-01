//! JWE against the JOSE cookbook (RFC 7520 §5, ietf-jose/cookbook at the
//! commit `testing/vectors/provenance.txt` names) and Wycheproof's
//! json_web_encryption file: every example decrypted in every serialization
//! it is written in, the reproducible ones encrypted byte for byte, and the
//! refusals the safe subset makes.
const std = @import("std");
const jwe = @import("jwe.zig");
const jwk = @import("jwk.zig");
const Key = @import("Key.zig");

const gpa = std.testing.allocator;
const io = std.testing.io;

const all_algorithms = std.enums.values(jwe.KeyManagement);
const all_encryptions = std.enums.values(jwe.ContentEncryption);
const options: jwe.Options = .{ .key_algorithms = all_algorithms, .encryptions = all_encryptions };

/// A recipient's decryption key and what owns its bytes.
const Held = struct {
    key: jwe.DecryptionKey,
    private: ?jwk.PrivateKey = null,
    set: ?jwk.KeySet = null,

    fn deinit(held: *Held) void {
        if (held.private) |*p| p.deinit();
        if (held.set) |*s| s.deinit();
    }
};

/// A JWK (as JSON) read for decryption: a private RSA, EC or X25519 key, or
/// an `oct` secret.
fn hold(document: []const u8) !Held {
    if (std.mem.find(u8, document, "\"oct\"") != null) {
        var set = try jwk.KeySet.parse(gpa, document, .{ .purpose = .encryption, .secrets = true });
        errdefer set.deinit();
        if (set.keys.len != 1) return error.KeySkipped;
        return .{ .key = try .fromSecret(set.keys[0]), .set = set };
    }
    var private = try jwk.PrivateKey.parse(gpa, document, .{ .purpose = .encryption });
    errdefer private.deinit();
    return .{ .key = try .fromJwk(&private), .private = private };
}

fn stringify(arena: std.mem.Allocator, value: std.json.Value) ![]u8 {
    return std.json.Stringify.valueAlloc(arena, value, .{});
}

const Vector = struct {
    arena: std.heap.ArenaAllocator,
    root: std.json.Value,

    fn load(comptime name: []const u8) !Vector {
        var arena: std.heap.ArenaAllocator = .init(gpa);
        errdefer arena.deinit();
        const root = try std.json.parseFromSliceLeaky(std.json.Value, arena.allocator(), @embedFile("testing/vectors/rfc7520/" ++ name), .{});
        return .{ .arena = arena, .root = root };
    }

    fn deinit(v: *Vector) void {
        v.arena.deinit();
    }

    fn get(v: *const Vector, path: []const []const u8) ?std.json.Value {
        var at = v.root;
        for (path) |p| at = (if (at == .object) at.object.get(p) else null) orelse return null;
        return at;
    }

    fn text(v: *const Vector, path: []const []const u8) []const u8 {
        return v.get(path).?.string;
    }

    /// The example's outputs, each serialization as a token.
    fn tokens(v: *Vector) ![]const []const u8 {
        var list: std.ArrayList([]const u8) = .empty;
        const arena = v.arena.allocator();
        if (v.get(&.{ "output", "compact" })) |c| try list.append(arena, c.string);
        for ([_][]const u8{ "json", "json_flat" }) |form| if (v.get(&.{ "output", form })) |j| try list.append(arena, try stringify(arena, j));
        return list.items;
    }
};

fn decrypted(token: []const u8, keys: []const jwe.DecryptionKey) ![]u8 {
    const scratch = try gpa.alloc(u8, jwe.scratchLength(token.len));
    errdefer gpa.free(scratch);
    const d = try jwe.decrypt(io, token, keys, options, scratch);
    // The plaintext lives in the scratch buffer: move it to the front.
    @memmove(scratch[0..d.plaintext.len], d.plaintext);
    return gpa.realloc(scratch, d.plaintext.len);
}

/// Every serialization of the example at `name` decrypts with its key to
/// its plaintext.
fn decryptsEverywhere(comptime name: []const u8) !void {
    var v = try Vector.load(name);
    defer v.deinit();
    var held = try hold(try stringify(v.arena.allocator(), v.get(&.{ "input", "key" }).?));
    defer held.deinit();
    const tokens = try v.tokens();
    try std.testing.expect(tokens.len > 0);
    for (tokens) |token| {
        const plain = try decrypted(token, &.{held.key});
        defer gpa.free(plain);
        try std.testing.expectEqualStrings(v.text(&.{ "input", "plaintext" }), plain);
    }
}

test "JWE: RFC 7520 §5.2, 5.4, 5.5, 5.10-5.12: RSA-OAEP, ECDH-ES on P-384 and P-256, AAD and unprotected headers decrypt in every serialization" {
    try decryptsEverywhere("5_2.key_encryption_using_rsa-oaep_with_aes-gcm.json");
    try decryptsEverywhere("5_4.key_agreement_with_key_wrapping_using_ecdh-es_and_aes-keywrap_with_aes-gcm.json");
    try decryptsEverywhere("5_5.key_agreement_using_ecdh-es_with_aes-cbc-hmac-sha2.json");
    try decryptsEverywhere("5_10.including_additional_authentication_data.json");
    try decryptsEverywhere("5_11.protecting_specific_header_fields.json");
    try decryptsEverywhere("5_12.protecting_content_only.json");
}

/// The bytes a script feeds `encrypt`: each generated value, base64url.
fn script(arena: std.mem.Allocator, parts: []const []const u8) ![]const u8 {
    var out: std.ArrayList(u8) = .empty;
    for (parts) |part| {
        const length = try std.base64.url_safe_no_pad.Decoder.calcSizeForSlice(part);
        const at = out.items.len;
        try out.resize(arena, at + length);
        try std.base64.url_safe_no_pad.Decoder.decode(out.items[at..], part);
    }
    return out.items;
}

/// An example decrypts in every form, and `encrypt` with its generated
/// values writes its compact form byte for byte.
fn reproduces(comptime name: []const u8, generated: []const []const u8, recipient: jwe.Recipient, header: jwe.EncryptHeader) !void {
    try decryptsEverywhere(name);
    var v = try Vector.load(name);
    defer v.deinit();
    const arena = v.arena.allocator();
    var parts: std.ArrayList([]const u8) = .empty;
    for (generated) |path| {
        var it = std.mem.splitScalar(u8, path, '.');
        var p: std.ArrayList([]const u8) = .empty;
        while (it.next()) |segment| try p.append(arena, segment);
        try parts.append(arena, v.text(p.items));
    }
    var drawn = try script(arena, parts.items);
    var out: std.Io.Writer.Allocating = .init(gpa);
    defer out.deinit();
    try jwe.encryptScripted(gpa, &drawn, &out.writer, header, v.text(&.{ "input", "plaintext" }), &.{recipient}, .compact, .{});
    try std.testing.expectEqual(@as(usize, 0), drawn.len);
    try std.testing.expectEqualStrings(v.text(&.{ "output", "compact" }), out.written());
}

/// An `oct` key read for encryption from an example, for `encrypt`.
fn secretKey(set: *jwk.KeySet, comptime name: []const u8) !Key {
    var v = try Vector.load(name);
    defer v.deinit();
    set.* = try jwk.KeySet.parse(gpa, try stringify(v.arena.allocator(), v.get(&.{ "input", "key" }).?), .{ .purpose = .encryption, .secrets = true });
    return set.keys[0];
}

test "JWE: RFC 7520 §5.6-5.8: dir, A256GCMKW and A128KW decrypt, and encrypt byte for byte from the generated values" {
    var set: jwk.KeySet = undefined;
    {
        const key = try secretKey(&set, "5_6.direct_encryption_using_aes-gcm.json");
        defer set.deinit();
        try reproduces("5_6.direct_encryption_using_aes-gcm.json", &.{"generated.iv"}, .{ .alg = .dir, .key = .{ .key = key } }, .{ .enc = .a128gcm });
    }
    {
        const key = try secretKey(&set, "5_7.key_wrap_using_aes-gcm_keywrap_with_aes-cbc-hmac-sha2.json");
        defer set.deinit();
        try reproduces("5_7.key_wrap_using_aes-gcm_keywrap_with_aes-cbc-hmac-sha2.json", &.{ "generated.cek", "encrypting_key.iv", "generated.iv" }, .{ .alg = .a256gcmkw, .key = .{ .key = key } }, .{ .enc = .a128cbc_hs256 });
    }
    {
        const key = try secretKey(&set, "5_8.key_wrap_using_aes-keywrap_with_aes-gcm.json");
        defer set.deinit();
        try reproduces("5_8.key_wrap_using_aes-keywrap_with_aes-gcm.json", &.{ "generated.cek", "generated.iv" }, .{ .alg = .a128kw, .key = .{ .key = key } }, .{ .enc = .a128gcm });
    }
}

test "JWE: RFC 7520 §5.3: PBES2-HS512+A256KW decrypts with the password, and encrypts byte for byte" {
    const name = "5_3.key_wrap_using_pbes2-aes-keywrap_with-aes-cbc-hmac-sha2.json";
    var v = try Vector.load(name);
    defer v.deinit();
    const password = v.text(&.{ "input", "pwd" });
    const key: jwe.DecryptionKey = .{ .material = .{ .password = password } };
    for (try v.tokens()) |token| {
        const plain = try decrypted(token, &.{key});
        defer gpa.free(plain);
        try std.testing.expectEqualStrings(v.text(&.{ "input", "plaintext" }), plain);
    }
    const arena = v.arena.allocator();
    var drawn = try script(arena, &.{ v.text(&.{ "generated", "cek" }), v.text(&.{ "encrypting_key", "salt" }), v.text(&.{ "generated", "iv" }) });
    var out: std.Io.Writer.Allocating = .init(gpa);
    defer out.deinit();
    try jwe.encryptScripted(gpa, &drawn, &out.writer, .{ .enc = .a128cbc_hs256, .cty = "jwk-set+json" }, v.text(&.{ "input", "plaintext" }), &.{.{ .alg = .pbes2_hs512_a256kw, .key = .{ .password = .{ .password = password, .count = 8192 } } }}, .compact, .{});
    try std.testing.expectEqualStrings(v.text(&.{ "output", "compact" }), out.written());
    // A count past the reader's bound is refused before any derivation.
    var bounded = options;
    bounded.max_pbes2_count = 8191;
    const token = v.text(&.{ "output", "compact" });
    const scratch = try gpa.alloc(u8, jwe.scratchLength(token.len));
    defer gpa.free(scratch);
    var diagnostics: jwe.Diagnostics = .{};
    bounded.diagnostics = &diagnostics;
    try std.testing.expectError(error.InvalidHeader, jwe.decrypt(io, token, &.{key}, bounded, scratch));
    try std.testing.expectEqual(jwe.Check.pbes2, diagnostics.check);
}

test "JWE: RFC 7520 §5.13: each held key decrypts its recipient of three; the RSA1_5 recipient is never one" {
    var v = try Vector.load("5_13.encrypting_to_multiple_recipients.json");
    defer v.deinit();
    const arena = v.arena.allocator();
    const keys = v.get(&.{ "input", "key" }).?.array.items;
    const token = try stringify(arena, v.get(&.{ "output", "json" }).?);
    // The RSA key's recipient uses RSA1_5: no algorithm spells it, so the
    // key alone decrypts nothing.
    var rsa = try hold(try stringify(arena, keys[0]));
    defer rsa.deinit();
    const scratch = try gpa.alloc(u8, jwe.scratchLength(token.len));
    defer gpa.free(scratch);
    try std.testing.expectError(error.NoKey, jwe.decrypt(io, token, &.{rsa.key}, options, scratch));
    for (keys[1..], 1..) |key_value, index| {
        var held = try hold(try stringify(arena, key_value));
        defer held.deinit();
        const d = try jwe.decrypt(io, token, &.{held.key}, options, scratch);
        try std.testing.expectEqual(index, d.index);
        try std.testing.expectEqualStrings(v.text(&.{ "input", "plaintext" }), d.plaintext);
        try std.testing.expectEqualStrings("text/plain", d.header.cty.?);
    }
}

test "JWE: RFC 7520 §5.1 (RSA1_5) and §5.9 (compressed) are refused" {
    var v1 = try Vector.load("5_1.key_encryption_using_rsa_v15_and_aes-hmac-sha2.json");
    defer v1.deinit();
    // The key names no `alg`, so it is read as an RSA key; RSA1_5 is still no
    // algorithm the recipient decrypts under, with the key held.
    var held1 = try hold(try stringify(v1.arena.allocator(), v1.get(&.{ "input", "key" }).?));
    defer held1.deinit();
    for (try v1.tokens()) |token| {
        const scratch = try gpa.alloc(u8, jwe.scratchLength(token.len));
        defer gpa.free(scratch);
        try std.testing.expectError(error.AlgorithmNotAllowed, jwe.decrypt(io, token, &.{held1.key}, options, scratch));
    }
    // The same key naming RSA1_5 as its `alg` is not read as a decryption key.
    var named = v1.get(&.{ "input", "key" }).?;
    try named.object.put(v1.arena.allocator(), "alg", .{ .string = "RSA1_5" });
    try std.testing.expectError(error.InvalidAlgorithm, jwk.PrivateKey.parse(gpa, try stringify(v1.arena.allocator(), named), .{ .purpose = .encryption }));
    var v9 = try Vector.load("5_9.compressed_content.json");
    defer v9.deinit();
    var held = try hold(try stringify(v9.arena.allocator(), v9.get(&.{ "input", "key" }).?));
    defer held.deinit();
    for (try v9.tokens()) |token| {
        const scratch = try gpa.alloc(u8, jwe.scratchLength(token.len));
        defer gpa.free(scratch);
        try std.testing.expectError(error.Compressed, jwe.decrypt(io, token, &.{held.key}, options, scratch));
    }
}

test "JWE: allowlists, keys and tampering: what a recipient refuses" {
    var set: jwk.KeySet = undefined;
    const key = try secretKey(&set, "5_8.key_wrap_using_aes-keywrap_with_aes-gcm.json");
    defer set.deinit();
    const held = try jwe.DecryptionKey.fromSecret(key);
    var v = try Vector.load("5_8.key_wrap_using_aes-keywrap_with_aes-gcm.json");
    defer v.deinit();
    const token = v.text(&.{ "output", "compact" });
    const scratch = try gpa.alloc(u8, jwe.scratchLength(token.len) + 64);
    defer gpa.free(scratch);
    // Not on the allowlists.
    try std.testing.expectError(error.AlgorithmNotAllowed, jwe.decrypt(io, token, &.{held}, .{ .key_algorithms = &.{.a256kw}, .encryptions = all_encryptions }, scratch));
    try std.testing.expectError(error.AlgorithmNotAllowed, jwe.decrypt(io, token, &.{held}, .{ .key_algorithms = all_algorithms, .encryptions = &.{.a256gcm} }, scratch));
    // Another kid, or no key.
    var renamed = held;
    renamed.kid = "other";
    try std.testing.expectError(error.NoKey, jwe.decrypt(io, token, &.{renamed}, options, scratch));
    try std.testing.expectError(error.NoKey, jwe.decrypt(io, token, &.{}, options, scratch));
    // The right kid on the wrong secret: the unwrap fails, a random key goes
    // on, and the content refuses as any forgery.
    const wrong_secret: [16]u8 = @splat(0x11);
    var wrong = held;
    wrong.material = .{ .secret = &wrong_secret };
    var diagnostics: jwe.Diagnostics = .{};
    var traced = options;
    traced.diagnostics = &diagnostics;
    try std.testing.expectError(error.DecryptionFailed, jwe.decrypt(io, token, &.{wrong}, traced, scratch));
    try std.testing.expectEqual(jwe.Check.decryption, diagnostics.check);
    // Every byte of every part changed, one at a time, fails.
    const copy = try gpa.dupe(u8, token);
    defer gpa.free(copy);
    for (0..copy.len) |i| {
        if (copy[i] == '.') continue;
        const was = copy[i];
        copy[i] = if (was == 'A') 'B' else 'A';
        defer copy[i] = was;
        if (jwe.decrypt(io, copy, &.{held}, options, scratch)) |_| {
            // A changed last character can leave the same bytes (base64url's
            // spare bits); anything else that decrypts is a failure.
            const same = std.mem.eql(u8, v.text(&.{ "input", "plaintext" }), (try jwe.decrypt(io, copy, &.{held}, options, scratch)).plaintext);
            if (!same) return error.TestUnexpectedResult;
        } else |_| {}
    }
    try std.testing.expectError(error.Malformed, jwe.decrypt(io, "a.b.c.d", &.{held}, options, scratch));
    try std.testing.expectError(error.ScratchTooSmall, jwe.decrypt(io, token, &.{held}, options, scratch[0..10]));
}

const WycheproofCase = struct {
    tcId: u32,
    comment: []const u8,
    pt: []const u8 = "",
    jwe: []const u8,
    result: []const u8,
    enc: []const u8 = "",
    flags: []const []const u8 = &.{},

    fn flagged(t: WycheproofCase, flag: []const u8) bool {
        for (t.flags) |f| if (std.mem.eql(u8, f, flag)) return true;
        return false;
    }
};
const WycheproofGroup = struct { private: std.json.Value, tests: []const WycheproofCase };
const WycheproofFile = struct { numberOfTests: u32, testGroups: []const WycheproofGroup };

test "JWE: Wycheproof json_web_encryption: valid tokens decrypt, invalid ones are refused; RSA1_5 and A192 keys are not offered" {
    var arena_state: std.heap.ArenaAllocator = .init(gpa);
    defer arena_state.deinit();
    const arena = arena_state.allocator();
    const file = try std.json.parseFromSliceLeaky(WycheproofFile, arena, @embedFile("testing/vectors/wycheproof/json_web_encryption_test.json"), .{ .ignore_unknown_fields = true });
    var ran: usize = 0;
    var not_offered: usize = 0;
    for (file.testGroups) |g| {
        var held = hold(try stringify(arena, g.private)) catch |err| switch (err) {
            // RSA1_5 and the A192 algorithms: no key is read for them.
            error.InvalidAlgorithm, error.KeySkipped => {
                for (g.tests) |t| {
                    const scratch = try arena.alloc(u8, jwe.scratchLength(t.jwe.len));
                    if (jwe.decrypt(io, t.jwe, &.{}, options, scratch)) |_| return error.TestUnexpectedResult else |_| {}
                }
                not_offered += g.tests.len;
                continue;
            },
            else => return err,
        };
        defer held.deinit();
        for (g.tests) |t| {
            ran += 1;
            const scratch = try arena.alloc(u8, jwe.scratchLength(t.jwe.len));
            const made = jwe.decrypt(io, t.jwe, &.{held.key}, options, scratch);
            // A192GCM and A192CBC-HS384 under a key clearance holds: refused
            // as no algorithm it has.
            if (std.mem.startsWith(u8, t.enc, "A192")) {
                try std.testing.expectError(error.AlgorithmNotAllowed, made);
                ran -= 1;
                not_offered += 1;
                continue;
            }
            // Compressed content (RFC 7520 §5.9, its Figure 170): refused by
            // design, as `zip` always is.
            if (t.flagged("CompressedPlaintext")) {
                try std.testing.expectError(error.Compressed, made);
                ran -= 1;
                not_offered += 1;
                continue;
            }
            // Wycheproof's harness reads the compact serialization alone, so
            // a sound JSON document is "invalid" there (its note says so);
            // clearance reads both, and decrypts it.
            if (t.flagged("JsonSerialization")) {
                _ = made catch |err| {
                    std.debug.print("json_web_encryption tcId {d} ({s}): {t}\n", .{ t.tcId, t.comment, err });
                    return err;
                };
                continue;
            }
            if (std.mem.eql(u8, t.result, "valid")) {
                const d = made catch |err| {
                    std.debug.print("json_web_encryption tcId {d} ({s}): {t}\n", .{ t.tcId, t.comment, err });
                    return err;
                };
                const pt = try arena.alloc(u8, t.pt.len / 2);
                _ = try std.fmt.hexToBytes(pt, t.pt);
                try std.testing.expectEqualSlices(u8, pt, d.plaintext);
            } else if (made) |_| {
                std.debug.print("json_web_encryption tcId {d} ({s}) decrypted\n", .{ t.tcId, t.comment });
                return error.TestUnexpectedResult;
            } else |_| {}
        }
    }
    try std.testing.expectEqual(@as(usize, file.numberOfTests), ran + not_offered);
    try std.testing.expect(ran > 60);
}

test "JWE: encrypt to each kind of recipient, and to three at once, decrypts back" {
    var v = try Vector.load("5_13.encrypting_to_multiple_recipients.json");
    defer v.deinit();
    const arena = v.arena.allocator();
    // An RSA recipient: the 5.2 key's public half.
    var v2 = try Vector.load("5_2.key_encryption_using_rsa-oaep_with_aes-gcm.json");
    defer v2.deinit();
    var rsa = try hold(try stringify(v2.arena.allocator(), v2.get(&.{ "input", "key" }).?));
    defer rsa.deinit();
    const gcm_key = v.get(&.{ "input", "key" }).?.array.items[2];
    var gcm = try hold(try stringify(arena, gcm_key));
    defer gcm.deinit();
    const message = "a message for three";
    const recipients = [_]jwe.Recipient{
        .{ .alg = .rsa_oaep, .key = .{ .key = rsa.private.?.public } },
        .{ .alg = .a256gcmkw, .key = .{ .key = gcm.set.?.keys[0] } },
        .{ .alg = .pbes2_hs256_a128kw, .key = .{ .password = .{ .password = "correct horse" } } },
    };
    for ([_]jwe.ContentEncryption{ .a128gcm, .a256cbc_hs512 }) |enc| {
        var out: std.Io.Writer.Allocating = .init(gpa);
        defer out.deinit();
        try jwe.encrypt(gpa, io, &out.writer, .{ .enc = enc, .typ = "JWT" }, message, &recipients, .general, .{ .aad = "seen by all" });
        const token = out.written();
        const scratch = try gpa.alloc(u8, jwe.scratchLength(token.len));
        defer gpa.free(scratch);
        const keys = [_]jwe.DecryptionKey{ rsa.key, gcm.key, .{ .material = .{ .password = "correct horse" } } };
        for (keys, 0..) |key, index| {
            const d = try jwe.decrypt(io, token, &.{key}, options, scratch);
            try std.testing.expectEqual(index, d.index);
            try std.testing.expectEqualStrings(message, d.plaintext);
            try std.testing.expectEqualStrings("JWT", d.header.typ.?);
        }
        // Compact and flattened carry one recipient.
        for ([_]jwe.Serialization{ .compact, .flattened }) |form| {
            var single: std.Io.Writer.Allocating = .init(gpa);
            defer single.deinit();
            try jwe.encrypt(gpa, io, &single.writer, .{ .enc = enc }, message, recipients[0..1], form, .{});
            const s = try gpa.alloc(u8, jwe.scratchLength(single.written().len));
            defer gpa.free(s);
            try std.testing.expectEqualStrings(message, (try jwe.decrypt(io, single.written(), &.{rsa.key}, options, s)).plaintext);
        }
    }
    var out: std.Io.Writer.Allocating = .init(gpa);
    defer out.deinit();
    try std.testing.expectError(error.InvalidRecipients, jwe.encrypt(gpa, io, &out.writer, .{ .enc = .a128gcm }, message, &recipients, .compact, .{}));
    try std.testing.expectError(error.InvalidRecipients, jwe.encrypt(gpa, io, &out.writer, .{ .enc = .a128gcm }, message, &.{}, .general, .{}));
    try std.testing.expectError(error.InvalidRecipients, jwe.encrypt(gpa, io, &out.writer, .{ .enc = .a128gcm }, message, recipients[0..1], .compact, .{ .aad = "x" }));
    try std.testing.expectError(error.InvalidKey, jwe.encrypt(gpa, io, &out.writer, .{ .enc = .a128gcm }, message, &.{.{ .alg = .a128kw, .key = .{ .key = gcm.set.?.keys[0] } }}, .compact, .{}));
    try std.testing.expectError(error.InvalidKey, jwe.encrypt(gpa, io, &out.writer, .{ .enc = .a128gcm }, message, &.{.{ .alg = .rsa_oaep, .key = .{ .password = .{ .password = "p" } } }}, .compact, .{}));
}

/// RFC 7748 §6.1's second key pair (Bob's), as an X25519 JWK.
const x25519_jwk = "{\"kty\":\"OKP\",\"crv\":\"X25519\",\"d\":\"XasIfmJKikt54X-Lg4AO5m87sSkmGLb9HC-LJ_-I4Os\",\"x\":\"3p7bfXt9wbTTW2HC7OQ1Nz-DQ8hbeGdNrfx-FG-IK08\"}";

/// The token's protected header, decoded, into `arena`.
fn protectedHeader(arena: std.mem.Allocator, token: []const u8) !std.json.Value {
    const part = token[0 .. std.mem.findScalar(u8, token, '.') orelse return error.TestUnexpectedResult];
    const json = try arena.alloc(u8, try std.base64.url_safe_no_pad.Decoder.calcSizeForSlice(part));
    try std.base64.url_safe_no_pad.Decoder.decode(json, part);
    return std.json.parseFromSliceLeaky(std.json.Value, arena, json, .{});
}

test "JWE: ECDH-ES encryption on P-256, P-384 and X25519, direct and with key wrap, decrypts back under a fresh ephemeral key each time" {
    var p384_vector = try Vector.load("5_4.key_agreement_with_key_wrapping_using_ecdh-es_and_aes-keywrap_with_aes-gcm.json");
    defer p384_vector.deinit();
    var p256_vector = try Vector.load("5_5.key_agreement_using_ecdh-es_with_aes-cbc-hmac-sha2.json");
    defer p256_vector.deinit();
    var held = [_]Held{
        try hold(try stringify(p384_vector.arena.allocator(), p384_vector.get(&.{ "input", "key" }).?)),
        try hold(try stringify(p256_vector.arena.allocator(), p256_vector.get(&.{ "input", "key" }).?)),
        try hold(x25519_jwk),
    };
    defer for (&held) |*h| h.deinit();
    const message = "agreed with a key made for this message";
    var arena_state: std.heap.ArenaAllocator = .init(gpa);
    defer arena_state.deinit();
    const arena = arena_state.allocator();
    for (&held) |*h| {
        for ([_]jwe.KeyManagement{ .ecdh_es, .ecdh_es_a128kw, .ecdh_es_a256kw }) |alg| {
            for ([_]jwe.ContentEncryption{ .a128gcm, .a256cbc_hs512 }) |enc| {
                var epks: [2]std.json.Value = undefined;
                for (&epks) |*epk| {
                    var out: std.Io.Writer.Allocating = .init(gpa);
                    defer out.deinit();
                    try jwe.encrypt(gpa, io, &out.writer, .{ .enc = enc }, message, &.{.{ .alg = alg, .key = .{ .key = h.private.?.public } }}, .compact, .{});
                    const token = out.written();
                    const plain = try decrypted(token, &.{h.key});
                    defer gpa.free(plain);
                    try std.testing.expectEqualStrings(message, plain);
                    // Direct agreement carries no encrypted key; key wrap does.
                    var parts = std.mem.splitScalar(u8, token, '.');
                    _ = parts.next();
                    try std.testing.expectEqual(alg == .ecdh_es, parts.next().?.len == 0);
                    epk.* = (try protectedHeader(arena, token)).object.get("epk").?;
                }
                const a = try stringify(arena, epks[0]);
                const b = try stringify(arena, epks[1]);
                try std.testing.expect(!std.mem.eql(u8, a, b));
            }
        }
    }
}

test "JWE: RFC 7520 §5.4 encrypted with its ephemeral key wraps its content key byte for byte, and its epk is the example's" {
    const name = "5_4.key_agreement_with_key_wrapping_using_ecdh-es_and_aes-keywrap_with_aes-gcm.json";
    var v = try Vector.load(name);
    defer v.deinit();
    const arena = v.arena.allocator();
    var recipient = try hold(try stringify(arena, v.get(&.{ "input", "key" }).?));
    defer recipient.deinit();
    // The content key, the ephemeral private key, then the content's IV.
    var drawn = try script(arena, &.{ v.text(&.{ "generated", "cek" }), v.text(&.{ "encrypting_key", "epk", "d" }), v.text(&.{ "generated", "iv" }) });
    var out: std.Io.Writer.Allocating = .init(gpa);
    defer out.deinit();
    try jwe.encryptScripted(gpa, &drawn, &out.writer, .{ .enc = .a128gcm }, v.text(&.{ "input", "plaintext" }), &.{.{ .alg = .ecdh_es_a128kw, .key = .{ .key = recipient.private.?.public } }}, .compact, .{});
    try std.testing.expectEqual(@as(usize, 0), drawn.len);
    const token = out.written();
    var parts = std.mem.splitScalar(u8, token, '.');
    _ = parts.next();
    try std.testing.expectEqualStrings(v.text(&.{ "encrypting_key", "encrypted_key" }), parts.next().?);
    const epk = (try protectedHeader(arena, token)).object.get("epk").?.object;
    for ([_][]const u8{ "kty", "crv", "x", "y" }) |member| try std.testing.expectEqualStrings(v.text(&.{ "encrypting_key", "epk", member }), epk.get(member).?.string);
    const plain = try decrypted(token, &.{recipient.key});
    defer gpa.free(plain);
    try std.testing.expectEqualStrings(v.text(&.{ "input", "plaintext" }), plain);
}
