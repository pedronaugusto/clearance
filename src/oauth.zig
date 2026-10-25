//! OAuth 2.1 for Zig, on clearance's JOSE and uplink. Two layers: the
//! messages, sans I/O (on `uplink.wire` alone): every request built and every
//! response read and checked; and the flows performed on uplink's client:
//! discovery, the authorization code flow with PKCE, refresh, client
//! credentials, registration, remote key sets and introspection, kept.
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
/// Token exchange (RFC 8693): what it carries, its answer read.
pub const exchange = @import("oauth/exchange.zig");
/// The Identity Assertion JWT Authorization Grant: MCP's
/// enterprise-managed authorization, the client's side.
pub const id_jag = @import("oauth/id_jag.zig");
/// Device authorization (RFC 8628): a device's codes asked for and read.
pub const device = @import("oauth/device.zig");
/// Dynamic client registration (RFC 7591) and client ID metadata documents.
pub const registration = @import("oauth/registration.zig");
/// Token introspection (RFC 7662).
pub const introspection = @import("oauth/introspection.zig");
/// Bearer challenges (RFC 6750 §3, RFC 9728 §5.1) read and written; step-up.
pub const challenge = @import("oauth/challenge.zig");

/// Where a client keeps its tokens: the interface and a store in memory.
pub const store = @import("oauth/store.zig");

// The flows, on uplink's client. Each takes the client and `io` per call and
// keeps neither.

const http = @import("oauth/http.zig");
const http_discovery = http.discovery;
const http_flow = http.flow;

/// An authorization server's metadata, fetched from the locations its
/// issuer makes (RFC 8414, OpenID Connect Discovery, in MCP's order).
pub const discover = http_discovery.authorizationServer;
/// A protected resource's metadata (RFC 9728), from its challenge's
/// `resource_metadata` or its well-known locations.
pub const discoverResource = http_discovery.protectedResource;
/// The Bearer challenge of a resource's 401 or 403.
pub const bearerChallenge = http_discovery.bearerChallenge;
pub const DiscoverOptions = http_discovery.Options;
pub const DiscoverError = http_discovery.Error;
/// The authorization code flow with PKCE, begun and finished.
pub const AuthorizationFlow = http_flow.AuthorizationFlow;
/// Device authorization (RFC 8628): the codes asked for, then polled.
pub const DeviceFlow = http_flow.DeviceFlow;
/// A grant asked of the token endpoint.
pub const requestToken = http_flow.requestToken;
/// New tokens for a set's refresh token.
pub const refresh = http_flow.refresh;
/// Tokens for the client itself.
pub const clientCredentials = http_flow.clientCredentials;
/// Tokens for a JWT presented as the grant: a workload's identity token.
pub const jwtBearer = http_flow.jwtBearer;
/// An ID-JAG from an identity provider, for the user's token there.
pub const requestIdJag = http_flow.requestIdJag;
/// An access token for an ID-JAG, from the authorization server it names.
pub const redeemIdJag = http_flow.redeemIdJag;
/// Dynamic client registration (RFC 7591).
pub const register = http_flow.register;
/// The tokens a store keeps, refreshed first when they are about to expire.
pub const fresh = http_flow.fresh;
pub const TokenOptions = http_flow.TokenOptions;
pub const TokenError = http_flow.TokenError;
pub const RefreshError = http_flow.RefreshError;
pub const IdJagError = http_flow.IdJagError;
pub const RedeemError = http_flow.RedeemError;
pub const RegisterOptions = http_flow.RegisterOptions;
pub const RegisterError = http_flow.RegisterError;
pub const FreshOptions = http_flow.FreshOptions;
pub const FreshError = http_flow.FreshError;
/// A JWK set kept from a `jwks_uri`: cached, refetched on an unknown key at
/// most once per cooldown, one fetch for every waiter, leased.
pub const RemoteKeySet = http.RemoteKeySet;
/// Token introspection with its answers kept briefly.
pub const Introspector = http.Introspector;
/// A resource server's bearer check: a token from `Authorization`, checked
/// with a key set or by introspection, for this resource and its scopes;
/// the 400, 401 or 403 and its challenge when it fails.
pub const bearer = http.bearer;
/// The exchanges' options and errors.
pub const fetch = http.fetch;

pub const ErrorResponse = errors.ErrorResponse;
pub const TokenStore = store.TokenStore;
pub const TokenSet = token.TokenSet;
pub const Client = client_auth.Client;

const builtin = @import("builtin");

test {
    if (builtin.is_test) _ = @import("oauth/tests.zig");
}

test {
    _ = url;
    _ = errors;
    _ = metadata;
    _ = pkce;
    _ = authorize;
    _ = client_auth;
    _ = token;
    _ = exchange;
    _ = id_jag;
    _ = device;
    _ = registration;
    _ = introspection;
    _ = challenge;
    _ = store;
    _ = http;
}
