//! The JWS algorithms clearance signs and verifies (RFC 7518 §3, RFC 8037,
//! RFC 9864). `none` is not one of them: no value of this type spells it.
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
            .es256, .es384 => .ec,
            .eddsa, .ed25519 => .okp,
        };
    }

    /// The hash an algorithm signs with; Ed25519's is internal to it.
    pub fn hash(a: Algorithm) ?cloak.certificates.certificate.Algorithm.Hash {
        return switch (a) {
            .hs256, .rs256, .ps256, .es256 => .sha256,
            .hs384, .rs384, .ps384, .es384 => .sha384,
            .hs512, .rs512, .ps512 => .sha512,
            .eddsa, .ed25519 => null,
        };
    }

    /// The curve an EC algorithm requires of its key.
    pub fn curve(a: Algorithm) ?cloak.certificates.certificate.Algorithm.Curve {
        return switch (a) {
            .es256 => .p256,
            .es384 => .p384,
            else => null,
        };
    }

    /// cloak's name for a public-key algorithm: PSS with MGF1 over the same
    /// hash and a salt as long as the hash (RFC 7518 §3.5); ECDSA as r || s.
    pub fn signature(a: Algorithm) cloak.certificates.certificate.Algorithm.Signature {
        return switch (a) {
            .rs256, .rs384, .rs512 => .{ .rsa = a.hash().? },
            .ps256, .ps384, .ps512 => .{ .pss = .{ .hash = a.hash().?, .mgf_hash = a.hash().?, .salt_length = hashLength(a.hash().?) } },
            .es256, .es384 => .{ .ecdsa_p1363 = a.hash().? },
            .eddsa, .ed25519 => .ed25519,
            .hs256, .hs384, .hs512 => unreachable, // MACs are not cloak's
        };
    }

    pub fn format(a: Algorithm, w: *std.Io.Writer) std.Io.Writer.Error!void {
        try w.writeAll(a.name());
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
