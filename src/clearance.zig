//! JWT and JOSE for Zig: JWS signed and verified, JWK and key sets, JWT
//! claims checked by type. OAuth 2.1 is the module `clearance.oauth`.
const builtin = @import("builtin");

/// Base64url without padding, strict, as JOSE writes binary members.
pub const base64url = @import("base64url.zig");
/// The JWS algorithms clearance signs and verifies; `none` is not one.
pub const Algorithm = @import("Algorithm.zig").Algorithm;
/// A key one algorithm family can use.
pub const Key = @import("Key.zig");
/// JSON Web Keys and key sets, and thumbprints.
pub const jwk = @import("jwk.zig");
/// JWS in the compact serialization: split, verified, signed.
pub const jws = @import("jws.zig");
/// JSON Web Tokens: claims checked by type, then by value.
pub const jwt = @import("jwt.zig");
/// OpenID Connect ID tokens, checked as OpenID Connect Core 3.1.3.7 asks.
pub const id_token = @import("id_token.zig");
/// JWT access tokens (RFC 9068), checked by the resource server they are for.
pub const access_token = @import("access_token.zig");
/// DPoP proofs (RFC 9449): written by a client, verified by a server.
pub const dpop = @import("dpop.zig");

test {
    if (builtin.is_test) _ = @import("tests.zig");
}
