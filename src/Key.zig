//! A key one JWS algorithm family can use, with the JWK members that limit
//! it. Its bytes are borrowed: a `jwk.KeySet` or the caller owns them.
const std = @import("std");
const cloak = @import("cloak");
const Algorithm = @import("Algorithm.zig").Algorithm;

const Key = @This();

pub const Curve = cloak.certificates.certificate.Algorithm.Curve;

pub const Material = union(Algorithm.Family) {
    /// The shared secret of an HMAC key. Only secret bytes make one: no
    /// public key's encoding can become an HMAC key.
    hmac: []const u8,
    /// The modulus and public exponent, big-endian, without leading zeros.
    rsa: struct { n: []const u8, e: []const u8 },
    /// The public point, SEC1 uncompressed (0x04, x, y).
    ec: struct { curve: Curve, point: []const u8 },
    /// An Ed25519 public key.
    okp: struct { x: []const u8 },
};

/// What a JWK's `use` says the key is for.
pub const Use = enum { any, sig, enc };

material: Material,
/// The JWK's `kid`.
kid: ?[]const u8 = null,
/// The JWK's `alg`: the only algorithm the key may be used with when set.
alg: ?Algorithm = null,
use: Use = .any,
/// Whether the JWK's `key_ops`, when it has one, allow verifying.
verify: bool = true,
/// Whether the JWK's `key_ops`, when it has one, allow signing.
sign: bool = true,

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
    if (std.meta.activeTag(key.material) != alg.family()) return false;
    return switch (key.material) {
        .ec => |ec| ec.curve == alg.curve().?,
        else => true,
    };
}

/// cloak's view of a public key.
pub fn public(key: Key) ?cloak.certificates.certificate.Algorithm.PublicKey {
    return switch (key.material) {
        .hmac => null,
        .rsa => |rsa| .{ .rsa = .{ .modulus = rsa.n, .exponent = rsa.e } },
        .ec => |ec| .{ .ec = .{ .curve = ec.curve, .bytes = ec.point } },
        .okp => |okp| .{ .ed25519 = okp.x },
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
