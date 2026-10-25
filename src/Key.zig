//! A key one JWS algorithm family can use, or a JWE key it can encrypt to,
//! with the JWK members that limit it. Its bytes are borrowed: a
//! `jwk.KeySet` or the caller owns them.
const std = @import("std");
const cloak = @import("cloak");
const Algorithm = @import("Algorithm.zig").Algorithm;
const KeyManagement = @import("Algorithm.zig").KeyManagement;
const ContentEncryption = @import("Algorithm.zig").ContentEncryption;

const Key = @This();

pub const Curve = cloak.certificates.certificate.Algorithm.Curve;

/// An OKP key's curve (RFC 8037): Ed25519 signs, X25519 agrees.
pub const OkpCurve = enum { ed25519, x25519 };

pub const Material = union(Algorithm.Family) {
    /// A symmetric secret (`oct`): an HMAC key, or under `use: enc` an AES
    /// key or a JWE content key (`dir`). Only secret bytes make one: no
    /// public key's encoding can become a secret.
    hmac: []const u8,
    /// The modulus and public exponent, big-endian, without leading zeros.
    rsa: struct { n: []const u8, e: []const u8 },
    /// The public point, SEC1 uncompressed (0x04, x, y).
    ec: struct { curve: Curve, point: []const u8 },
    /// An Ed25519 public key, or an X25519 one (read for encryption only).
    okp: struct { curve: OkpCurve = .ed25519, x: []const u8 },
};

/// What a JWK's `use` says the key is for.
pub const Use = enum { any, sig, enc };

material: Material,
/// The JWK's `kid`.
kid: ?[]const u8 = null,
/// The JWK's `alg`: the only algorithm the key may be used with when set.
alg: ?Algorithm = null,
/// The JWK's `alg` when it names a JWE key-management algorithm: the only
/// one the key is used with.
management: ?KeyManagement = null,
/// The JWK's `alg` when it names a content encryption (a `dir` key, as RFC
/// 7520 §5.6's): the key is that content key and nothing else.
content: ?ContentEncryption = null,
use: Use = .any,
/// Whether the JWK's `key_ops`, when it has one, allow verifying.
verify: bool = true,
/// Whether the JWK's `key_ops`, when it has one, allow signing.
sign: bool = true,
/// Whether the JWK's `key_ops`, when it has one, allow encrypting to the key
/// (`encrypt`, `wrapKey`, `deriveKey`, `deriveBits`).
encrypt: bool = true,
/// Whether they allow decrypting with it (`decrypt`, `unwrapKey`,
/// `deriveKey`, `deriveBits`).
decrypt: bool = true,

/// An HMAC key over `secret`, which the caller keeps alive and secret.
pub fn hmac(secret: []const u8) Key {
    return .{ .material = .{ .hmac = secret } };
}

/// Whether the key may verify a signature made with `alg`: its family fits,
/// its own `alg` (if any) is `alg`, it is not for encryption, and an EC key's
/// curve is the one the algorithm names.
pub fn fits(key: Key, alg: Algorithm) bool {
    if (key.use == .enc) return false;
    if (key.alg) |own| if (own != alg) return false;
    if (key.management != null or key.content != null) return false;
    if (std.meta.activeTag(key.material) != alg.family()) return false;
    return switch (key.material) {
        .ec => |ec| ec.curve == alg.curve().?,
        .okp => |okp| okp.curve == .ed25519,
        else => true,
    };
}

/// Whether a JWE may use the key under `alg` with content `enc`: it is not
/// for signatures, its own `alg` (if any) is `alg` (or, for a `dir` key,
/// `enc`), and its kind is the one `alg` takes, a secret of the length it
/// takes. PBES2 takes a password, never a JWK.
pub fn fitsEncryption(key: Key, alg: KeyManagement, enc: ContentEncryption) bool {
    if (key.use == .sig or key.alg != null) return false;
    if (key.management) |own| if (own != alg) return false;
    if (key.content) |own| if (alg != .dir or own != enc) return false;
    return switch (alg.kind()) {
        .rsa => key.material == .rsa,
        .agreement => switch (key.material) {
            .ec => true,
            .okp => |okp| okp.curve == .x25519,
            else => false,
        },
        .wrap, .gcm_wrap => key.material == .hmac and key.material.hmac.len == alg.wrapLength().?,
        .direct => key.material == .hmac and key.material.hmac.len == enc.keyLength(),
        .password => false,
    };
}

/// cloak's view of a public key.
pub fn public(key: Key) ?cloak.certificates.certificate.Algorithm.PublicKey {
    return switch (key.material) {
        .hmac => null,
        .rsa => |rsa| .{ .rsa = .{ .modulus = rsa.n, .exponent = rsa.e } },
        .ec => |ec| .{ .ec = .{ .curve = ec.curve, .bytes = ec.point } },
        .okp => |okp| switch (okp.curve) {
            .ed25519 => .{ .ed25519 = okp.x },
            .x25519 => .{ .x25519 = okp.x },
        },
    };
}

test "a key fits only its own family, curve and alg" {
    const secret: [32]u8 = @splat(1);
    const h = hmac(&secret);
    try std.testing.expect(h.fits(.hs256));
    try std.testing.expect(!h.fits(.rs256));
    var pinned = h;
    pinned.alg = .hs384;
    try std.testing.expect(!pinned.fits(.hs256));
    const point: [65]u8 = @splat(4);
    const ec: Key = .{ .material = .{ .ec = .{ .curve = .p256, .point = &point } } };
    try std.testing.expect(ec.fits(.es256));
    try std.testing.expect(!ec.fits(.es384));
    try std.testing.expect(!ec.fits(.hs256));
    var encrypting = ec;
    encrypting.use = .enc;
    try std.testing.expect(!encrypting.fits(.es256));
}

test "an encryption key fits the JWE algorithms its kind and its alg allow" {
    const point: [65]u8 = @splat(4);
    var ec: Key = .{ .material = .{ .ec = .{ .curve = .p256, .point = &point } }, .use = .enc };
    try std.testing.expect(ec.fitsEncryption(.ecdh_es, .a128gcm));
    try std.testing.expect(!ec.fitsEncryption(.rsa_oaep, .a128gcm));
    try std.testing.expect(!ec.fits(.es256));
    ec.management = .ecdh_es_a128kw;
    try std.testing.expect(!ec.fitsEncryption(.ecdh_es, .a128gcm));
    try std.testing.expect(ec.fitsEncryption(.ecdh_es_a128kw, .a256gcm));
    const x: [32]u8 = @splat(9);
    const x25519: Key = .{ .material = .{ .okp = .{ .curve = .x25519, .x = &x } } };
    try std.testing.expect(x25519.fitsEncryption(.ecdh_es, .a256gcm));
    try std.testing.expect(!x25519.fits(.eddsa));
    const secret: [16]u8 = @splat(1);
    var direct: Key = .{ .material = .{ .hmac = &secret }, .content = .a128gcm };
    try std.testing.expect(direct.fitsEncryption(.dir, .a128gcm));
    try std.testing.expect(!direct.fitsEncryption(.dir, .a256gcm));
    try std.testing.expect(!direct.fitsEncryption(.a128kw, .a128gcm));
    try std.testing.expect(!direct.fits(.hs256));
    direct.content = null;
    try std.testing.expect(direct.fitsEncryption(.a128kw, .a256gcm));
    try std.testing.expect(!direct.fitsEncryption(.a256kw, .a256gcm));
    try std.testing.expect(!direct.fitsEncryption(.pbes2_hs256_a128kw, .a256gcm));
    direct.use = .sig;
    try std.testing.expect(!direct.fitsEncryption(.a128kw, .a256gcm));
}
