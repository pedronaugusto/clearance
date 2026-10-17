//! OAuth 2.1 messages, sans I/O: every request built and every response read
//! and checked, for a caller with an HTTP stack of its own or for
//! `clearance.http`, which performs them on uplink.
//!
//! Each reader is bounded by a size, refuses a member of the wrong type or a
//! member twice, and keeps an OAuth error response as a value
//! (`errors.ErrorResponse`). Secrets a request or a response carries (client
//! secrets, codes' verifiers, tokens) live in memory that is wiped.

/// URLs: endpoints held to HTTPS, issuers, metadata locations, resources.
pub const url = @import("oauth/url.zig");
/// OAuth error responses as values.
pub const errors = @import("oauth/errors.zig");
/// Authorization server (RFC 8414, OpenID Connect Discovery) and protected
/// resource (RFC 9728) metadata.
pub const metadata = @import("oauth/metadata.zig");
/// PKCE with S256, and `state` and `nonce` values.
pub const pkce = @import("oauth/pkce.zig");
/// The authorization request and its callback (RFC 8707 resources, the
/// RFC 9207 `iss` check).
pub const authorize = @import("oauth/authorize.zig");
/// Client authentication: none, `client_secret_basic`, `client_secret_post`,
/// `private_key_jwt`; and the form requests that carry it.
pub const client_auth = @import("oauth/client_auth.zig");
/// The token endpoint: grants asked, `TokenSet`s read.
pub const token = @import("oauth/token.zig");
/// Dynamic client registration (RFC 7591) and client ID metadata documents.
pub const registration = @import("oauth/registration.zig");
/// Token introspection (RFC 7662).
pub const introspection = @import("oauth/introspection.zig");
/// Bearer challenges (RFC 6750 §3, RFC 9728 §5.1) read and written; step-up.
pub const challenge = @import("oauth/challenge.zig");

pub const ErrorResponse = errors.ErrorResponse;
pub const TokenSet = token.TokenSet;
pub const Client = client_auth.Client;

test {
    _ = url;
    _ = errors;
    _ = metadata;
    _ = pkce;
    _ = authorize;
    _ = client_auth;
    _ = token;
    _ = registration;
    _ = introspection;
    _ = challenge;
}
