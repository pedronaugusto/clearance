//! The JWS algorithms clearance signs and verifies (RFC 7518 §3, RFC 8037,
//! RFC 9864), and the JWE ones it encrypts and decrypts with (RFC 7518 §4
//! and §5, RFC 8037 §3.2). `none` is not one of them, nor JWE's `RSA1_5`:
//! no value of these types spells either.
const std = @import("std");
const cloak = @import("cloak");

pub const Algorithm = enum {
    hs256,
    hs384,
    hs512,
    rs256,
    rs384,
    rs512,
    ps256,
    ps384,
    ps512,
    es256,
    es384,
    /// ECDSA on P-521 with SHA-512 (RFC 7518 §3.4), on cloak's P-521.
    es512,
    /// Ed25519 under its polymorphic name (RFC 8037), with an OKP key whose
    /// curve is Ed25519.
    eddsa,
    /// Ed25519 under its fully specified name (RFC 9864).
    ed25519,

    /// The kind of key an algorithm takes.
    pub const Family = enum { hmac, rsa, ec, okp };

    /// The name a header carries.
    pub fn name(a: Algorithm) []const u8 {
        return switch (a) {
            .eddsa => "EdDSA",
            .ed25519 => "Ed25519",
            inline else => |tag| comptime upper(@tagName(tag)),
        };
    }

    /// The algorithm a header names, exactly as registered (case matters), or
    /// null for any other name, `none` included.
    pub fn parse(text: []const u8) ?Algorithm {
        inline for (comptime std.enums.values(Algorithm)) |a| {
            if (std.mem.eql(u8, text, a.name())) return a;
        }
        return null;
    }

    pub fn family(a: Algorithm) Family {
        return switch (a) {
            .hs256, .hs384, .hs512 => .hmac,
            .rs256, .rs384, .rs512, .ps256, .ps384, .ps512 => .rsa,
            .es256, .es384, .es512 => .ec,
            .eddsa, .ed25519 => .okp,
        };
    }

    /// The hash an algorithm signs with; Ed25519's is internal to it.
    pub fn hash(a: Algorithm) ?cloak.certificates.certificate.Algorithm.Hash {
        return switch (a) {
            .hs256, .rs256, .ps256, .es256 => .sha256,
            .hs384, .rs384, .ps384, .es384 => .sha384,
            .hs512, .rs512, .ps512, .es512 => .sha512,
            .eddsa, .ed25519 => null,
        };
    }

    /// The curve an EC algorithm requires of its key.
    pub fn curve(a: Algorithm) ?cloak.certificates.certificate.Algorithm.Curve {
        return switch (a) {
            .es256 => .p256,
            .es384 => .p384,
            .es512 => .p521,
            else => null,
        };
    }

    /// cloak's name for a public-key algorithm: PSS with MGF1 over the same
    /// hash and a salt as long as the hash (RFC 7518 §3.5); ECDSA as r || s.
    pub fn signature(a: Algorithm) cloak.certificates.certificate.Algorithm.Signature {
        return switch (a) {
            .rs256, .rs384, .rs512 => .{ .rsa = a.hash().? },
            .ps256, .ps384, .ps512 => .{ .pss = .{ .hash = a.hash().?, .mgf_hash = a.hash().?, .salt_length = hashLength(a.hash().?) } },
            .es256, .es384, .es512 => .{ .ecdsa_p1363 = a.hash().? },
            .eddsa, .ed25519 => .ed25519,
            .hs256, .hs384, .hs512 => unreachable, // MACs are not cloak's
        };
    }

    pub fn format(a: Algorithm, w: *std.Io.Writer) std.Io.Writer.Error!void {
        try w.writeAll(a.name());
    }
};

/// How a JWE's content key is determined (RFC 7518 §4). RSA1_5 is absent
/// by construction (its decryption is Bleichenbacher's oracle), and so are
/// the 192-bit AES variants: std has no AES-192, RFC 7518 makes them
/// optional and WebCrypto has none. PBES2-HS384+A192KW goes with them.
pub const KeyManagement = enum {
    rsa_oaep,
    rsa_oaep_256,
    rsa_oaep_384,
    rsa_oaep_512,
    a128kw,
    a256kw,
    dir,
    ecdh_es,
    ecdh_es_a128kw,
    ecdh_es_a256kw,
    a128gcmkw,
    a256gcmkw,
    pbes2_hs256_a128kw,
    pbes2_hs512_a256kw,

    /// What kind of key an algorithm takes.
    pub const Kind = enum { rsa, wrap, direct, agreement, gcm_wrap, password };

    pub fn name(a: KeyManagement) []const u8 {
        return switch (a) {
            .rsa_oaep => "RSA-OAEP",
            .rsa_oaep_256 => "RSA-OAEP-256",
            .rsa_oaep_384 => "RSA-OAEP-384",
            .rsa_oaep_512 => "RSA-OAEP-512",
            .a128kw => "A128KW",
            .a256kw => "A256KW",
            .dir => "dir",
            .ecdh_es => "ECDH-ES",
            .ecdh_es_a128kw => "ECDH-ES+A128KW",
            .ecdh_es_a256kw => "ECDH-ES+A256KW",
            .a128gcmkw => "A128GCMKW",
            .a256gcmkw => "A256GCMKW",
            .pbes2_hs256_a128kw => "PBES2-HS256+A128KW",
            .pbes2_hs512_a256kw => "PBES2-HS512+A256KW",
        };
    }

    /// The algorithm a header names, exactly as registered, or null.
    pub fn parse(text: []const u8) ?KeyManagement {
        inline for (comptime std.enums.values(KeyManagement)) |a| {
            if (std.mem.eql(u8, text, a.name())) return a;
        }
        return null;
    }

    pub fn kind(a: KeyManagement) Kind {
        return switch (a) {
            .rsa_oaep, .rsa_oaep_256, .rsa_oaep_384, .rsa_oaep_512 => .rsa,
            .a128kw, .a256kw => .wrap,
            .dir => .direct,
            .ecdh_es, .ecdh_es_a128kw, .ecdh_es_a256kw => .agreement,
            .a128gcmkw, .a256gcmkw => .gcm_wrap,
            .pbes2_hs256_a128kw, .pbes2_hs512_a256kw => .password,
        };
    }

    /// The AES key a wrapping algorithm wraps under, in bytes: a KW or
    /// GCMKW key's length, or the one ECDH-ES+KW and PBES2 derive. Null for
    /// RSA, `dir` and ECDH-ES alone.
    pub fn wrapLength(a: KeyManagement) ?usize {
        return switch (a) {
            .a128kw, .ecdh_es_a128kw, .a128gcmkw, .pbes2_hs256_a128kw => 16,
            .a256kw, .ecdh_es_a256kw, .a256gcmkw, .pbes2_hs512_a256kw => 32,
            .rsa_oaep, .rsa_oaep_256, .rsa_oaep_384, .rsa_oaep_512, .dir, .ecdh_es => null,
        };
    }

    /// cloak's OAEP scheme for an RSA algorithm: the label hash and MGF1 on
    /// the same hash, the empty label (RFC 7518 §4.3).
    pub fn oaep(a: KeyManagement) ?cloak.certificates.certificate.Algorithm.Encryption {
        const hash: @FieldType(cloak.certificates.certificate.Algorithm.Oaep, "hash") = switch (a) {
            .rsa_oaep => .sha1,
            .rsa_oaep_256 => .sha256,
            .rsa_oaep_384 => .sha384,
            .rsa_oaep_512 => .sha512,
            else => return null,
        };
        return .{ .oaep = .{ .hash = hash, .mgf_hash = hash } };
    }

    pub fn format(a: KeyManagement, w: *std.Io.Writer) std.Io.Writer.Error!void {
        try w.writeAll(a.name());
    }
};

/// How a JWE's content is encrypted (RFC 7518 §5): AES-GCM, or AES-CBC with
/// HMAC as one authenticated cipher, the tag checked before any block is
/// decrypted (cloak's composite). The 192-bit variants are absent, as above.
pub const ContentEncryption = enum {
    a128gcm,
    a256gcm,
    a128cbc_hs256,
    a256cbc_hs512,

    pub fn name(e: ContentEncryption) []const u8 {
        return switch (e) {
            .a128gcm => "A128GCM",
            .a256gcm => "A256GCM",
            .a128cbc_hs256 => "A128CBC-HS256",
            .a256cbc_hs512 => "A256CBC-HS512",
        };
    }

    pub fn parse(text: []const u8) ?ContentEncryption {
        inline for (comptime std.enums.values(ContentEncryption)) |e| {
            if (std.mem.eql(u8, text, e.name())) return e;
        }
        return null;
    }

    /// The content key's length in bytes: for CBC-HMAC, the MAC key's half
    /// and the AES key's together.
    pub fn keyLength(e: ContentEncryption) usize {
        return switch (e) {
            .a128gcm => 16,
            .a256gcm, .a128cbc_hs256 => 32,
            .a256cbc_hs512 => 64,
        };
    }

    pub fn ivLength(e: ContentEncryption) usize {
        return switch (e) {
            .a128gcm, .a256gcm => 12,
            .a128cbc_hs256, .a256cbc_hs512 => 16,
        };
    }

    pub fn tagLength(e: ContentEncryption) usize {
        return switch (e) {
            .a128gcm, .a256gcm, .a128cbc_hs256 => 16,
            .a256cbc_hs512 => 32,
        };
    }

    pub fn format(e: ContentEncryption, w: *std.Io.Writer) std.Io.Writer.Error!void {
        try w.writeAll(e.name());
    }
};

pub fn hashLength(h: cloak.certificates.certificate.Algorithm.Hash) usize {
    return switch (h) {
        .sha256 => 32,
        .sha384 => 48,
        .sha512 => 64,
    };
}

fn upper(comptime text: []const u8) []const u8 {
    comptime {
        var out: [text.len]u8 = undefined;
        for (text, 0..) |c, i| out[i] = std.ascii.toUpper(c);
        const final = out;
        return &final;
    }
}

test "names are the registered ones and parse back exactly" {
    try std.testing.expectEqualStrings("HS256", Algorithm.hs256.name());
    try std.testing.expectEqualStrings("EdDSA", Algorithm.eddsa.name());
    inline for (comptime std.enums.values(Algorithm)) |a| {
        try std.testing.expectEqual(a, Algorithm.parse(a.name()).?);
    }
    try std.testing.expectEqual(@as(?Algorithm, null), Algorithm.parse("none"));
    try std.testing.expectEqual(@as(?Algorithm, null), Algorithm.parse("hs256"));
    try std.testing.expectEqual(@as(?Algorithm, null), Algorithm.parse("ES512"));
}

test "JWE names are the registered ones and parse back; RSA1_5 and the A192 variants spell nothing" {
    inline for (comptime std.enums.values(KeyManagement)) |a| try std.testing.expectEqual(a, KeyManagement.parse(a.name()).?);
    inline for (comptime std.enums.values(ContentEncryption)) |e| try std.testing.expectEqual(e, ContentEncryption.parse(e.name()).?);
    for ([_][]const u8{ "RSA1_5", "A192KW", "A192GCMKW", "ECDH-ES+A192KW", "PBES2-HS384+A192KW", "rsa-oaep" }) |name| {
        try std.testing.expectEqual(@as(?KeyManagement, null), KeyManagement.parse(name));
    }
    for ([_][]const u8{ "A192GCM", "A192CBC-HS384", "a128gcm" }) |name| try std.testing.expectEqual(@as(?ContentEncryption, null), ContentEncryption.parse(name));
    try std.testing.expectEqual(@as(usize, 64), ContentEncryption.a256cbc_hs512.keyLength());
}
