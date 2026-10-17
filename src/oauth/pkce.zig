//! PKCE with S256 alone (RFC 7636; OAuth 2.1 §4.1.1: `plain` is never sent),
//! and the random values an authorization request carries: `state` and
//! `nonce`.
const std = @import("std");
const aegis = @import("aegis");
const base64url = @import("../base64url.zig");

/// What `code_challenge_method` says.
pub const method = "S256";

/// The length of a verifier, a challenge, a `state` or a `nonce` made here:
/// 32 random bytes in base64url.
pub const length = 43;

/// A verifier and its challenge. The verifier is a secret until the token
/// request spends it.
pub const Pkce = struct {
    verifier: aegis.Secret([length]u8),
    challenge: [length]u8,

    /// A fresh verifier of 32 bytes from `io`'s randomness.
    pub fn generate(io: std.Io) Pkce {
        var verifier: [length]u8 = undefined;
        defer std.crypto.secureZero(u8, &verifier);
        random(io, &verifier);
        return .{ .verifier = .init(verifier), .challenge = challengeOf(&verifier) };
    }

    pub fn deinit(p: *Pkce) void {
        p.verifier.deinit();
    }
};

/// The S256 challenge of `verifier`: base64url of its SHA-256.
pub fn challengeOf(verifier: []const u8) [length]u8 {
    var digest: [32]u8 = undefined;
    std.crypto.hash.sha2.Sha256.hash(verifier, &digest, .{});
    var out: [length]u8 = undefined;
    var w: std.Io.Writer = .fixed(&out);
    // unreachable: 32 bytes encode to exactly `length` characters
    base64url.encode(&w, &digest) catch unreachable;
    return out;
}

/// 32 random bytes as base64url, into `out`: a `state`, a `nonce`, a `jti`.
pub fn random(io: std.Io, out: *[length]u8) void {
    var bytes: [32]u8 = undefined;
    defer std.crypto.secureZero(u8, &bytes);
    io.random(&bytes);
    var w: std.Io.Writer = .fixed(out);
    // unreachable: 32 bytes encode to exactly `length` characters
    base64url.encode(&w, &bytes) catch unreachable;
}

/// Whether two values a peer echoes (a `state`, a `nonce`) are the same, in
/// time that does not depend on where they differ.
pub fn same(a: []const u8, b: []const u8) bool {
    const choice = aegis.secret.equalBytes(a, b) catch return false;
    return choice.declassify("a matched or refused echo ends the check");
}

test "RFC 7636 Appendix B: the verifier's S256 challenge" {
    const challenge = challengeOf("dBjftJeZ4CVP-mB92K27uhbUJU1p1r_wW1gFWFOEjXk");
    try std.testing.expectEqualStrings("E9Melhoa2OwvFrEMTJguCHaoeK1t8URWbuGJSstw-cM", &challenge);
}

test "a generated verifier is 43 unreserved characters and its challenge follows" {
    var p = Pkce.generate(std.testing.io);
    defer p.deinit();
    for (p.verifier.expose()) |c| try std.testing.expect(std.ascii.isAlphanumeric(c) or c == '-' or c == '_');
    try std.testing.expectEqualSlices(u8, &challengeOf(p.verifier.expose()), &p.challenge);
    var q = Pkce.generate(std.testing.io);
    defer q.deinit();
    try std.testing.expect(!same(p.verifier.expose(), q.verifier.expose()));
    try std.testing.expect(same("abc", "abc"));
    try std.testing.expect(!same("abc", "abcd"));
}
