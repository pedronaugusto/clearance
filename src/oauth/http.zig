//! The flows on uplink's client: the layer above the messages that sends
//! them. Each takes the client and `io` per call and keeps neither.

/// The exchanges every flow is made of: their options and errors.
pub const fetch = @import("http/fetch.zig");
/// Metadata fetched and checked.
pub const discovery = @import("http/discovery.zig");
/// The authorization code flow, refresh, client credentials, registration,
/// and a store's tokens kept fresh.
pub const flow = @import("http/flow.zig");
/// A JWK set kept from a `jwks_uri`.
pub const RemoteKeySet = @import("http/RemoteKeySet.zig");
/// Token introspection with its answers kept briefly.
pub const Introspector = @import("http/Introspector.zig");
/// A resource server's bearer check and its answers.
pub const bearer = @import("http/bearer.zig");

test {
    _ = fetch;
    _ = discovery;
    _ = flow;
    _ = RemoteKeySet;
    _ = Introspector;
    _ = bearer;
}
