const std = @import("std");
const jwk = @import("jwk.zig");
const base64url = @import("base64url.zig");

const gpa = std.testing.allocator;

const rfc7638_n = "0vx7agoebGcQSuuPiLJXZptN9nndrQmbXEps2aiAFbWhM78LhWx4cbbfAAtVT86zwu1RK7aPFFxuhDR1L6tSoc_BJECPebWKRXjBZCiFV4n3oknjhMstn64tZ_2W-5JsGY4Hc5n9yBXArwl93lqt7_RN5w6Cf0h4QyQ5v-65YGjQR0_FDW2QvzqY368QQMicAtaSqzs8KJZgnYb9c7d0zgdAZHzu6qMQvRL5hajrn1n91CbOpbISD08qNLyrdkt-bFTWhAI4vMQFh6WeZu0fM4lFd2NcRwr3XPksINHaQ-G_xBniIqbw0Ls1jF44-csFCur-kEgU8awapJzKnqDKgw";

fn thumbprintText(key: @import("Key.zig")) ![]u8 {
    var out: std.Io.Writer.Allocating = .init(gpa);
    errdefer out.deinit();
    try base64url.encode(&out.writer, &jwk.thumbprint(key));
    return out.toOwnedSlice();
}

test "RFC 7638 3.1 and RFC 8037 A.3: thumbprints of an RSA and an Ed25519 key" {
    var set = try jwk.KeySet.parse(gpa, "{\"kty\":\"RSA\",\"n\":\"" ++ rfc7638_n ++ "\",\"e\":\"AQAB\",\"alg\":\"RS256\",\"kid\":\"2011-04-29\"}", .{});
    defer set.deinit();
    try std.testing.expectEqual(@as(usize, 1), set.keys.len);
    const rsa = try thumbprintText(set.keys[0]);
    defer gpa.free(rsa);
    try std.testing.expectEqualStrings("NzbLsXh8uDCcd-6MNwXF4W_7noWXFZAfHkxZsRGC9Xs", rsa);
    var ed = try jwk.KeySet.parse(gpa, "{\"kty\":\"OKP\",\"crv\":\"Ed25519\",\"x\":\"11qYAYKxCrfVS_7TyWQHOg7hcvPapiMlrwIaaPcHURo\"}", .{});
    defer ed.deinit();
    const okp = try thumbprintText(ed.keys[0]);
    defer gpa.free(okp);
    try std.testing.expectEqualStrings("kPrK_qmxVWaYVA9wwBF6Iuo3vVzz7TxHCTwXBygrS4k", okp);
    var uri: std.Io.Writer.Allocating = .init(gpa);
    defer uri.deinit();
    try jwk.writeThumbprintUri(&uri.writer, ed.keys[0]);
    try std.testing.expectEqualStrings("urn:ietf:params:oauth:jwk-thumbprint:sha-256:kPrK_qmxVWaYVA9wwBF6Iuo3vVzz7TxHCTwXBygrS4k", uri.written());
}

test "RFC 7520 3.3: the cookbook's RSA public key is read with its kid and use" {
    var set = try jwk.KeySet.parse(gpa, @embedFile("testing/vectors/rfc7520/3_3.rsa_public_key.json"), .{});
    defer set.deinit();
    try std.testing.expectEqual(@as(usize, 1), set.keys.len);
    try std.testing.expectEqualStrings("bilbo.baggins@hobbiton.example", set.keys[0].kid.?);
    try std.testing.expectEqual(.sig, set.keys[0].use);
}

test "RFC 7520 3.1: a P-521 key is read, its 66-byte coordinates one SEC 1 point" {
    var set = try jwk.KeySet.parse(gpa, @embedFile("testing/vectors/rfc7520/3_1.ec_public_key.json"), .{});
    defer set.deinit();
    try std.testing.expectEqual(@as(usize, 1), set.keys.len);
    try std.testing.expectEqual(@as(u16, 0), set.skipped.get(.unsupported));
    const ec = set.keys[0].material.ec;
    try std.testing.expectEqual(.p521, ec.curve);
    try std.testing.expectEqual(@as(usize, 1 + 2 * 66), ec.point.len);
    try std.testing.expectEqual(@as(u8, 0x04), ec.point[0]);
}

test "a set keeps the keys it can use and counts the rest by reason" {
    const doc =
        \\{"keys":[
        \\ {"kty":"OKP","crv":"Ed25519","x":"11qYAYKxCrfVS_7TyWQHOg7hcvPapiMlrwIaaPcHURo","kid":"ed"},
        \\ {"kty":"OKP","crv":"X25519","x":"hSDwCYkwp1R0i33ctD73Wg2_Og0mOBr066SpjqqbTmo"},
        \\ {"kty":"oct","k":"AyM1SysPpbyDfgZld3umj1qzKObwVMkoqQ-EstJQLr_T-1qS0gZH75aKtMN3Yj0iPS4hcgUuTwjAzZr1Z9CAow"},
        \\ {"kty":"EC","crv":"P-256","x":"AAAA","y":"AAAA"},
        \\ {"kty":"OKP","crv":"Ed25519","x":"11qYAYKxCrfVS_7TyWQHOg7hcvPapiMlrwIaaPcHURo","use":"enc"},
        \\ {"kty":"OKP","crv":"Ed25519","x":"11qYAYKxCrfVS_7TyWQHOg7hcvPapiMlrwIaaPcHURo","d":"nWGxne_9WmC6hEr0kuwsxERJxWl7MmkZcDusAxyuf2A"},
        \\ {"kty":"OKP","crv":"Ed25519","x":"11qYAYKxCrfVS_7TyWQHOg7hcvPapiMlrwIaaPcHURo","alg":"HS256"}
        \\]}
    ;
    var set = try jwk.KeySet.parse(gpa, doc, .{});
    defer set.deinit();
    try std.testing.expectEqual(@as(usize, 1), set.keys.len);
    try std.testing.expectEqualStrings("ed", set.keys[0].kid.?);
    try std.testing.expectEqual(@as(u16, 1), set.skipped.get(.unsupported));
    try std.testing.expectEqual(@as(u16, 1), set.skipped.get(.secret));
    try std.testing.expectEqual(@as(u16, 1), set.skipped.get(.invalid));
    try std.testing.expectEqual(@as(u16, 1), set.skipped.get(.not_for_signatures));
    try std.testing.expectEqual(@as(u16, 1), set.skipped.get(.private));
    try std.testing.expectEqual(@as(u16, 1), set.skipped.get(.algorithm));
    try std.testing.expectError(error.InvalidDocument, jwk.KeySet.parse(gpa, "[1,2]", .{}));
    try std.testing.expectError(error.TooLarge, jwk.KeySet.parse(gpa, doc, .{ .max_bytes = .literal("100B") }));
}

test "a key set's reading fails for memory as memory, never by leaving keys out" {
    try std.testing.checkAllAllocationFailures(gpa, struct {
        fn run(a: std.mem.Allocator) !void {
            var set = try jwk.KeySet.parse(a, "{\"keys\":[{\"kty\":\"RSA\",\"n\":\"" ++ rfc7638_n ++ "\",\"e\":\"AQAB\"},{\"kty\":\"OKP\",\"crv\":\"Ed25519\",\"x\":\"11qYAYKxCrfVS_7TyWQHOg7hcvPapiMlrwIaaPcHURo\"}]}", .{});
            defer set.deinit();
            if (set.keys.len != 2) return error.KeysLeftOut;
        }
    }.run, .{});
}

test "RFC 9964: an AKP key is kept only with its ML-DSA alg and a public key of that level's length, for signatures" {
    // ML-DSA-44's public key is 1312 bytes: 1750 base64url characters.
    const pub44: [1750]u8 = @splat('A');
    const doc =
        \\{"keys":[
        \\ {"kty":"AKP","alg":"ML-DSA-44","kid":"kept","pub":"
    ++ pub44 ++
        \\"},
        \\ {"kty":"AKP","pub":"
    ++ pub44 ++
        \\"},
        \\ {"kty":"AKP","alg":"ML-DSA-65","pub":"
    ++ pub44 ++
        \\"},
        \\ {"kty":"AKP","alg":"SLH-DSA-SHA2-128s","pub":"
    ++ pub44 ++
        \\"},
        \\ {"kty":"AKP","alg":"ES256","pub":"
    ++ pub44 ++
        \\"},
        \\ {"kty":"AKP","alg":"ML-DSA-44","pub":"
    ++ pub44 ++
        \\","priv":"AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA"}
        \\]}
    ;
    var set = try jwk.KeySet.parse(gpa, doc, .{});
    defer set.deinit();
    try std.testing.expectEqual(@as(usize, 1), set.keys.len);
    try std.testing.expectEqualStrings("kept", set.keys[0].kid.?);
    try std.testing.expectEqual(@as(usize, 1312), set.keys[0].material.akp.public.len);
    try std.testing.expect(set.keys[0].fits(.ml_dsa_44));
    try std.testing.expect(!set.keys[0].fits(.ml_dsa_65));
    try std.testing.expect(!set.keys[0].fits(.eddsa));
    // No alg, and a 44's key under 65: invalid; another AKP algorithm: unsupported; a
    // signature algorithm of another kind: algorithm; the seed beside it: private.
    try std.testing.expectEqual(@as(u16, 2), set.skipped.get(.invalid));
    try std.testing.expectEqual(@as(u16, 1), set.skipped.get(.unsupported));
    try std.testing.expectEqual(@as(u16, 1), set.skipped.get(.algorithm));
    try std.testing.expectEqual(@as(u16, 1), set.skipped.get(.private));
    // Read for encryption, an ML-DSA key is not one.
    var encryption = try jwk.KeySet.parse(gpa, doc, .{ .purpose = .encryption });
    defer encryption.deinit();
    try std.testing.expectEqual(@as(usize, 0), encryption.keys.len);
    // A private AKP key needs its 32-byte seed; a seed whose key is not `pub` is refused.
    try std.testing.expectError(error.NotPrivate, jwk.PrivateKey.parse(gpa, "{\"kty\":\"AKP\",\"alg\":\"ML-DSA-44\",\"pub\":\"" ++ pub44 ++ "\"}", .{}));
    try std.testing.expectError(error.InvalidKey, jwk.PrivateKey.parse(gpa, "{\"kty\":\"AKP\",\"alg\":\"ML-DSA-44\",\"pub\":\"" ++ pub44 ++ "\",\"priv\":\"AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA\"}", .{}));
    try std.testing.expectError(error.InvalidKey, jwk.PrivateKey.parse(gpa, "{\"kty\":\"AKP\",\"alg\":\"ML-DSA-44\",\"pub\":\"" ++ pub44 ++ "\",\"priv\":\"AAAA\"}", .{}));
}
