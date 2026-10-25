//! Metadata documents read and checked: an authorization server's (RFC 8414,
//! with OpenID Connect Discovery's members) and a protected resource's (RFC
//! 9728). Each is checked against what was asked before anything in it is
//! used: the issuer byte for byte (RFC 8414 §3.3), the resource as the
//! caller's rule says (RFC 9728 §3.3), every endpoint HTTPS.
const std = @import("std");
const aegis = @import("aegis");
const strand = @import("strand");
const url = @import("url.zig");
const pkce = @import("pkce.zig");

/// An authorization server's metadata: the members clearance uses. Lists
/// absent from the document are null, which is not the same as empty.
pub const AuthorizationServer = struct {
    issuer: []const u8,
    authorization_endpoint: ?[]const u8 = null,
    token_endpoint: ?[]const u8 = null,
    jwks_uri: ?[]const u8 = null,
    registration_endpoint: ?[]const u8 = null,
    introspection_endpoint: ?[]const u8 = null,
    /// RFC 8628 §4.
    device_authorization_endpoint: ?[]const u8 = null,
    /// RFC 7009 §2, in RFC 8414 §2.
    revocation_endpoint: ?[]const u8 = null,
    revocation_endpoint_auth_methods_supported: ?[]const []const u8 = null,
    scopes_supported: ?[]const []const u8 = null,
    response_types_supported: ?[]const []const u8 = null,
    grant_types_supported: ?[]const []const u8 = null,
    token_endpoint_auth_methods_supported: ?[]const []const u8 = null,
    token_endpoint_auth_signing_alg_values_supported: ?[]const []const u8 = null,
    introspection_endpoint_auth_methods_supported: ?[]const []const u8 = null,
    code_challenge_methods_supported: ?[]const []const u8 = null,
    /// RFC 9207: the authorization response carries `iss`.
    authorization_response_iss_parameter_supported: bool = false,
    /// draft-ietf-oauth-client-id-metadata-document: a client ID may be the
    /// URL of the client's metadata document.
    client_id_metadata_document_supported: bool = false,
    /// OpenID Connect Discovery.
    id_token_signing_alg_values_supported: ?[]const []const u8 = null,

    /// Whether S256 PKCE is listed. MCP's clients refuse a server that does
    /// not list it; OAuth 2.1 lets a server leave the list out.
    pub fn supportsPkce(m: *const AuthorizationServer) bool {
        return listed(m.code_challenge_methods_supported, pkce.method);
    }

    /// Whether `scope` is in `scopes_supported`.
    pub fn supportsScope(m: *const AuthorizationServer, scope: []const u8) bool {
        return listed(m.scopes_supported, scope);
    }

    /// Whether `grant` is in `grant_types_supported`, whose default is
    /// `authorization_code` and `implicit` (RFC 8414 §2).
    pub fn supportsGrant(m: *const AuthorizationServer, grant: []const u8) bool {
        if (m.grant_types_supported) |list| return listed(list, grant);
        return std.mem.eql(u8, grant, "authorization_code");
    }
};

/// Whether `value` is one of `list`'s.
pub fn listed(list: ?[]const []const u8, value: []const u8) bool {
    for (list orelse return false) |item| if (std.mem.eql(u8, item, value)) return true;
    return false;
}

/// A protected resource's metadata (RFC 9728 §2): the members clearance
/// uses and a resource server publishes.
pub const ProtectedResource = struct {
    resource: []const u8,
    authorization_servers: ?[]const []const u8 = null,
    jwks_uri: ?[]const u8 = null,
    scopes_supported: ?[]const []const u8 = null,
    bearer_methods_supported: ?[]const []const u8 = null,
    resource_signing_alg_values_supported: ?[]const []const u8 = null,
    resource_name: ?[]const u8 = null,
    resource_documentation: ?[]const u8 = null,
    resource_policy_uri: ?[]const u8 = null,
    resource_tos_uri: ?[]const u8 = null,

    /// Writes the document, for a resource server to serve at its
    /// well-known location.
    pub fn write(m: ProtectedResource, w: *std.Io.Writer) std.Io.Writer.Error!void {
        strand.json.write(w, m, .{ .nulls = .omit }) catch |err| return switch (err) {
            error.WriteFailed => error.WriteFailed,
            // unreachable: a fixed schema of strings and lists of strings always writes
            else => unreachable,
        };
    }
};

pub const Options = struct {
    max_bytes: aegis.units.Bytes(usize) = .literal("1MiB"),
};

pub const ReadError = error{
    TooLarge,
    /// Not a JSON object of the document's members, or a member twice.
    InvalidDocument,
    /// The document's `issuer` is not the one its location was made from
    /// (RFC 8414 §3.3).
    IssuerMismatch,
    /// The document's `resource` is not the one asked for (RFC 9728 §3.3).
    ResourceMismatch,
    /// An endpoint, a `jwks_uri` or an issuer the document names is not an
    /// HTTPS URL (or HTTP to loopback).
    InvalidEndpoint,
} || std.mem.Allocator.Error;

pub const Parsed = strand.json.Parsed;

/// Reads an authorization server's metadata, fetched from a location made
/// from `issuer` (`url.writeDiscovery`). Its `issuer` must equal `issuer`
/// byte for byte; an issuer that is a template (Microsoft's `{tenantid}`)
/// is resolved by the caller first, never compared loosely here.
pub fn readAuthorizationServer(gpa: std.mem.Allocator, body: []const u8, issuer: []const u8, options: Options) ReadError!Parsed(AuthorizationServer) {
    var parsed = try parse(AuthorizationServer, gpa, body, options);
    errdefer parsed.deinit();
    const m = &parsed.value;
    if (!std.mem.eql(u8, m.issuer, issuer)) return error.IssuerMismatch;
    _ = url.issuer(m.issuer) catch return error.InvalidEndpoint;
    inline for (.{ "authorization_endpoint", "token_endpoint", "jwks_uri", "registration_endpoint", "introspection_endpoint", "device_authorization_endpoint", "revocation_endpoint" }) |name| {
        if (@field(m, name)) |text| _ = url.endpoint(text) catch return error.InvalidEndpoint;
    }
    return parsed;
}

/// Reads a protected resource's metadata. Its `resource` must match `asked`,
/// the URL the client asked (or built the metadata location from), as `match`
/// says; each authorization server it names must be an issuer identifier.
pub fn readProtectedResource(gpa: std.mem.Allocator, body: []const u8, asked: []const u8, match: url.ResourceMatch, options: Options) ReadError!Parsed(ProtectedResource) {
    var parsed = try parse(ProtectedResource, gpa, body, options);
    errdefer parsed.deinit();
    const m = &parsed.value;
    if (!url.resourceMatches(m.resource, asked, match)) return error.ResourceMismatch;
    _ = url.endpoint(m.resource) catch return error.InvalidEndpoint;
    for (m.authorization_servers orelse &.{}) |server| _ = url.issuer(server) catch return error.InvalidEndpoint;
    if (m.jwks_uri) |text| _ = url.endpoint(text) catch return error.InvalidEndpoint;
    return parsed;
}

fn parse(comptime T: type, gpa: std.mem.Allocator, body: []const u8, options: Options) ReadError!Parsed(T) {
    const limit: usize = options.max_bytes.raw();
    if (body.len > limit) return error.TooLarge;
    return strand.json.parseOwned(T, gpa, body, .{
        .ignore_unknown_fields = true,
        .limits = .{ .depth = 32 },
    }) catch |err| switch (err) {
        error.OutOfMemory => error.OutOfMemory,
        else => error.InvalidDocument,
    };
}

const testing = std.testing;

test "RFC 8414 §3.2's example is read, its issuer checked byte for byte" {
    const body =
        \\{"issuer":"https://server.example.com","authorization_endpoint":"https://server.example.com/authorize",
        \\"token_endpoint":"https://server.example.com/token","token_endpoint_auth_methods_supported":["client_secret_basic","private_key_jwt"],
        \\"token_endpoint_auth_signing_alg_values_supported":["RS256","ES256"],"userinfo_endpoint":"https://server.example.com/userinfo",
        \\"jwks_uri":"https://server.example.com/jwks.json","registration_endpoint":"https://server.example.com/register",
        \\"scopes_supported":["openid","profile","email","address","phone","offline_access"],"response_types_supported":["code","code token"],
        \\"service_documentation":"http://server.example.com/service_documentation.html","ui_locales_supported":["en-US","en-GB","en-CA","fr-FR","fr-CA"],
        \\"code_challenge_methods_supported":["S256"],"authorization_response_iss_parameter_supported":true}
    ;
    var m = try readAuthorizationServer(testing.allocator, body, "https://server.example.com", .{});
    defer m.deinit();
    try testing.expectEqualStrings("https://server.example.com/token", m.value.token_endpoint.?);
    try testing.expect(m.value.supportsPkce());
    try testing.expect(m.value.supportsScope("offline_access"));
    try testing.expect(m.value.supportsGrant("authorization_code"));
    try testing.expect(!m.value.supportsGrant("client_credentials"));
    try testing.expect(m.value.authorization_response_iss_parameter_supported);
    try testing.expectError(error.IssuerMismatch, readAuthorizationServer(testing.allocator, body, "https://server.example.com/", .{}));
    try testing.expectError(error.IssuerMismatch, readAuthorizationServer(testing.allocator, body, "https://evil.example.com", .{}));
}

test "authorization server metadata with an insecure endpoint, a duplicate or a bad type is refused" {
    try testing.expectError(error.InvalidEndpoint, readAuthorizationServer(testing.allocator, "{\"issuer\":\"https://a.example\",\"token_endpoint\":\"http://a.example/token\"}", "https://a.example", .{}));
    try testing.expectError(error.InvalidEndpoint, readAuthorizationServer(testing.allocator, "{\"issuer\":\"http://a.example\"}", "http://a.example", .{}));
    try testing.expectError(error.InvalidDocument, readAuthorizationServer(testing.allocator, "{\"issuer\":\"https://a.example\",\"issuer\":\"https://b.example\"}", "https://a.example", .{}));
    try testing.expectError(error.InvalidDocument, readAuthorizationServer(testing.allocator, "{\"issuer\":\"https://a.example\",\"scopes_supported\":\"a b\"}", "https://a.example", .{}));
    try testing.expectError(error.TooLarge, readAuthorizationServer(testing.allocator, "{\"issuer\":\"https://a.example\"}", "https://a.example", .{ .max_bytes = .literal("8B") }));
    var local = try readAuthorizationServer(testing.allocator, "{\"issuer\":\"http://localhost:9\"}", "http://localhost:9", .{});
    defer local.deinit();
    try testing.expect(!local.value.supportsPkce());
}

test "protected resource metadata: the resource matched, the servers issuers, and written back" {
    const body = "{\"resource\":\"https://rs.example/mcp\",\"authorization_servers\":[\"https://as.example\"],\"scopes_supported\":[\"files:read\"],\"bearer_methods_supported\":[\"header\"]}";
    var m = try readProtectedResource(testing.allocator, body, "https://rs.example/mcp", .exact, .{});
    defer m.deinit();
    try testing.expectEqualStrings("https://as.example", m.value.authorization_servers.?[0]);
    try testing.expectError(error.ResourceMismatch, readProtectedResource(testing.allocator, body, "https://rs.example/other", .exact, .{}));
    var parent = try readProtectedResource(testing.allocator, "{\"resource\":\"https://rs.example\"}", "https://rs.example/mcp", .ancestor, .{});
    parent.deinit();
    try testing.expectError(error.ResourceMismatch, readProtectedResource(testing.allocator, "{\"resource\":\"https://evil.example/mcp\"}", "https://rs.example/mcp", .ancestor, .{}));
    try testing.expectError(error.InvalidEndpoint, readProtectedResource(testing.allocator, "{\"resource\":\"https://rs.example/mcp\",\"authorization_servers\":[\"https://as.example/?q\"]}", "https://rs.example/mcp", .exact, .{}));

    var out: std.Io.Writer.Allocating = .init(testing.allocator);
    defer out.deinit();
    try m.value.write(&out.writer);
    try testing.expectEqualStrings(body, out.written());
}
