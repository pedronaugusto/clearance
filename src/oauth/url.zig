//! The URLs OAuth names: endpoints held to HTTPS, issuers, the well-known
//! locations metadata is fetched from (RFC 8414 §3, OpenID Connect Discovery
//! §4, RFC 9728 §3), and which resource a protected resource's metadata may
//! speak for.
const std = @import("std");
const wire = @import("uplink.wire");

pub const Url = wire.url.Url;

pub const Error = error{
    /// Not an absolute `http` or `https` URL, or one with a user, a password
    /// or a fragment.
    InvalidUrl,
    /// `http` to a host other than this machine's loopback (OAuth 2.1 §1.5;
    /// RFC 8252 §8.3 allows it for loopback alone).
    NotHttps,
    /// An issuer with a query (RFC 8414 §2).
    InvalidIssuer,
};

/// Whether `host` is this machine: `localhost`, 127.0.0.0/8 or `::1`.
pub fn isLoopback(host: []const u8) bool {
    if (std.ascii.eqlIgnoreCase(host, "localhost")) return true;
    if (std.mem.eql(u8, host, "::1")) return true;
    const v4 = std.Io.net.Ip4Address.parse(host, 0) catch return false;
    return v4.bytes[0] == 127;
}

/// `text` as an endpoint OAuth may send to: HTTPS, or HTTP to loopback.
pub fn endpoint(text: []const u8) Error!Url {
    if (std.mem.findScalar(u8, text, '#') != null) return error.InvalidUrl;
    const u = wire.url.parse(text) catch return error.InvalidUrl;
    if (!u.secure and !isLoopback(u.host)) return error.NotHttps;
    return u;
}

/// `text` as an issuer identifier: an endpoint with no query (RFC 8414 §2).
pub fn issuer(text: []const u8) Error!Url {
    const u = try endpoint(text);
    if (std.mem.findScalar(u8, u.target, '?') != null) return error.InvalidIssuer;
    return u;
}

/// The scheme and authority of `text`, which parsed as `u`.
fn origin(text: []const u8, u: Url) []const u8 {
    const at = @intFromPtr(u.target.ptr) - @intFromPtr(text.ptr); // safe: `wire.url.parse` gives `target` as a slice of `text`
    return text[0..at];
}

/// The issuer's path without its query and trailing slash: what a well-known
/// name goes before or after.
fn issuerPath(u: Url) []const u8 {
    const query = std.mem.findScalar(u8, u.target, '?') orelse u.target.len;
    return std.mem.trimEnd(u8, u.target[0..query], "/");
}

/// Where an authorization server's metadata may be (RFC 8414 §3.1 and
/// OpenID Connect Discovery §4.1, with RFC 8414 §5's insertion for an
/// issuer with a path).
pub const Discovery = enum {
    /// `/.well-known/oauth-authorization-server` inserted before the path.
    oauth,
    /// `/.well-known/openid-configuration` inserted before the path.
    openid_inserted,
    /// `/.well-known/openid-configuration` after the path, OpenID Connect
    /// Discovery's own form.
    openid_appended,

    /// The locations to try for `issuer`, in MCP's order (2025-11-25,
    /// "Authorization Server Metadata Discovery"): an issuer without a path
    /// has two, and one with a path three.
    pub fn order(issuer_url: Url) []const Discovery {
        return if (issuerPath(issuer_url).len == 0) &.{ .oauth, .openid_inserted } else &.{ .oauth, .openid_inserted, .openid_appended };
    }
};

/// Writes the metadata URL of `issuer_text` at the location `where`.
pub fn writeDiscovery(w: *std.Io.Writer, issuer_text: []const u8, where: Discovery) (Error || std.Io.Writer.Error)!void {
    const u = try issuer(issuer_text);
    const path = issuerPath(u);
    try w.writeAll(origin(issuer_text, u));
    switch (where) {
        .oauth => try w.print("/.well-known/oauth-authorization-server{s}", .{path}),
        .openid_inserted => try w.print("/.well-known/openid-configuration{s}", .{path}),
        .openid_appended => try w.print("{s}/.well-known/openid-configuration", .{path}),
    }
}

/// Where a protected resource's metadata may be (RFC 9728 §3.1).
pub const ResourceDiscovery = enum {
    /// `/.well-known/oauth-protected-resource` inserted before the
    /// resource's path.
    inserted,
    /// `/.well-known/oauth-protected-resource` at the root, which MCP tries
    /// when the inserted one is not found.
    root,
};

/// Writes the metadata URL of the resource `resource_text` at `where`. The
/// query, which RFC 9728 §3.1 keeps after the path, is kept.
pub fn writeResourceDiscovery(w: *std.Io.Writer, resource_text: []const u8, where: ResourceDiscovery) (Error || std.Io.Writer.Error)!void {
    const u = try endpoint(resource_text);
    try w.writeAll(origin(resource_text, u));
    try w.writeAll("/.well-known/oauth-protected-resource");
    if (where == .inserted) {
        const query_at = std.mem.findScalar(u8, u.target, '?') orelse u.target.len;
        try w.writeAll(std.mem.trimEnd(u8, u.target[0..query_at], "/"));
        try w.writeAll(u.target[query_at..]);
    }
}

/// How the `resource` of protected resource metadata must relate to the URL
/// the client asked.
pub const ResourceMatch = enum {
    /// Equal, byte for byte (RFC 9728 §3.3).
    exact,
    /// The same origin, and a path that is the asked URL's or one of its
    /// ancestors at a segment boundary: MCP's rule, where a server at
    /// `https://host/mcp` may publish metadata for `https://host`.
    ancestor,
};

/// Whether metadata naming `resource` speaks for `asked` under `match`.
pub fn resourceMatches(resource: []const u8, asked: []const u8, match: ResourceMatch) bool {
    switch (match) {
        .exact => return std.mem.eql(u8, resource, asked),
        .ancestor => {
            if (std.mem.findScalar(u8, resource, '#') != null or std.mem.findScalar(u8, asked, '#') != null) return false;
            const r = wire.url.parse(resource) catch return false;
            const a = wire.url.parse(asked) catch return false;
            if (!wire.url.sameOrigin(r, a)) return false;
            // A query on the resource narrows it to that query alone.
            if (std.mem.findScalar(u8, r.target, '?') != null) return std.mem.eql(u8, r.target, a.target);
            const a_path = a.target[0 .. std.mem.findScalar(u8, a.target, '?') orelse a.target.len];
            const r_path = std.mem.trimEnd(u8, r.target, "/");
            if (!std.mem.startsWith(u8, a_path, r_path)) return false;
            return a_path.len == r_path.len or a_path[r_path.len] == '/';
        },
    }
}

/// Why a URL cannot be a client ID metadata document's.
pub const ClientIdError = error{
    /// Not HTTPS, no path, a dot segment, a fragment, a user or a password
    /// (draft-ietf-oauth-client-id-metadata-document §3).
    InvalidClientId,
};

/// Whether `text` may be a client ID that is the URL of its own metadata
/// document: HTTPS with a path, no dot segments, no fragment, no user or
/// password. A query, which the draft discourages, is refused too.
pub fn clientIdDocument(text: []const u8) ClientIdError!Url {
    if (std.mem.findScalar(u8, text, '#') != null) return error.InvalidClientId;
    const u = wire.url.parse(text) catch return error.InvalidClientId;
    if (!u.secure) return error.InvalidClientId;
    if (u.target.len < 2 or u.target[0] != '/') return error.InvalidClientId;
    if (std.mem.findScalar(u8, u.target, '?') != null) return error.InvalidClientId;
    var segments = std.mem.splitScalar(u8, u.target[1..], '/');
    while (segments.next()) |segment| {
        if (std.mem.eql(u8, segment, ".") or std.mem.eql(u8, segment, "..")) return error.InvalidClientId;
        if (std.ascii.eqlIgnoreCase(segment, "%2e") or std.ascii.eqlIgnoreCase(segment, "%2e%2e") or
            std.ascii.eqlIgnoreCase(segment, ".%2e") or std.ascii.eqlIgnoreCase(segment, "%2e.")) return error.InvalidClientId;
    }
    return u;
}

test "endpoints are HTTPS, or HTTP to loopback" {
    _ = try endpoint("https://as.example/token");
    _ = try endpoint("http://127.0.0.1:8080/cb");
    _ = try endpoint("http://localhost/cb");
    _ = try endpoint("http://[::1]:9/cb");
    try std.testing.expectError(error.NotHttps, endpoint("http://as.example/token"));
    try std.testing.expectError(error.NotHttps, endpoint("http://127.example/token"));
    try std.testing.expectError(error.InvalidUrl, endpoint("https://as.example/token#x"));
    try std.testing.expectError(error.InvalidUrl, endpoint("https://user:pw@as.example/"));
    try std.testing.expectError(error.InvalidUrl, endpoint("ftp://as.example/"));
    try std.testing.expectError(error.InvalidIssuer, issuer("https://as.example/?tenant=1"));
}

fn expectDiscovery(expected: []const u8, issuer_text: []const u8, where: Discovery) !void {
    var buffer: [256]u8 = undefined;
    var w: std.Io.Writer = .fixed(&buffer);
    try writeDiscovery(&w, issuer_text, where);
    try std.testing.expectEqualStrings(expected, w.buffered());
}

test "metadata locations insert the well-known name before an issuer's path, or append OpenID's" {
    try expectDiscovery("https://as.example/.well-known/oauth-authorization-server", "https://as.example", .oauth);
    try expectDiscovery("https://as.example/.well-known/oauth-authorization-server", "https://as.example/", .oauth);
    try expectDiscovery("https://as.example/.well-known/openid-configuration", "https://as.example", .openid_inserted);
    try expectDiscovery("https://as.example/.well-known/oauth-authorization-server/tenant/1", "https://as.example/tenant/1", .oauth);
    try expectDiscovery("https://as.example/.well-known/openid-configuration/tenant/1", "https://as.example/tenant/1", .openid_inserted);
    try expectDiscovery("https://as.example/tenant/1/.well-known/openid-configuration", "https://as.example/tenant/1/", .openid_appended);
    try expectDiscovery("http://localhost:9/.well-known/oauth-authorization-server", "http://localhost:9", .oauth);
    try std.testing.expectEqual(@as(usize, 2), Discovery.order(try issuer("https://a.example/")).len);
    try std.testing.expectEqual(@as(usize, 3), Discovery.order(try issuer("https://a.example/t")).len);
}

test "resource metadata locations, inserted and at the root" {
    var buffer: [256]u8 = undefined;
    var w: std.Io.Writer = .fixed(&buffer);
    try writeResourceDiscovery(&w, "https://rs.example/mcp?v=1", .inserted);
    try std.testing.expectEqualStrings("https://rs.example/.well-known/oauth-protected-resource/mcp?v=1", w.buffered());
    w = .fixed(&buffer);
    try writeResourceDiscovery(&w, "https://rs.example/mcp", .root);
    try std.testing.expectEqualStrings("https://rs.example/.well-known/oauth-protected-resource", w.buffered());
}

test "a resource matches exactly, or as an ancestor at a segment boundary" {
    try std.testing.expect(resourceMatches("https://rs.example/mcp", "https://rs.example/mcp", .exact));
    try std.testing.expect(!resourceMatches("https://rs.example", "https://rs.example/mcp", .exact));
    try std.testing.expect(resourceMatches("https://rs.example", "https://rs.example/mcp", .ancestor));
    try std.testing.expect(resourceMatches("https://rs.example/", "https://rs.example/mcp", .ancestor));
    try std.testing.expect(resourceMatches("https://RS.example/mcp", "https://rs.example/mcp/x", .ancestor));
    try std.testing.expect(!resourceMatches("https://rs.example/mc", "https://rs.example/mcp", .ancestor));
    try std.testing.expect(!resourceMatches("https://evil.example/mcp", "https://rs.example/mcp", .ancestor));
    try std.testing.expect(!resourceMatches("http://rs.example/mcp", "https://rs.example/mcp", .ancestor));
    try std.testing.expect(!resourceMatches("https://rs.example:444/mcp", "https://rs.example/mcp", .ancestor));
    try std.testing.expect(!resourceMatches("https://rs.example/mcp/x", "https://rs.example/mcp", .ancestor));
}

test "a client ID metadata document's URL" {
    _ = try clientIdDocument("https://app.example/oauth/client.json");
    _ = try clientIdDocument("https://app.example:8443/c");
    try std.testing.expectError(error.InvalidClientId, clientIdDocument("http://app.example/c"));
    try std.testing.expectError(error.InvalidClientId, clientIdDocument("https://app.example"));
    try std.testing.expectError(error.InvalidClientId, clientIdDocument("https://app.example/"));
    try std.testing.expectError(error.InvalidClientId, clientIdDocument("https://app.example/a/../c"));
    try std.testing.expectError(error.InvalidClientId, clientIdDocument("https://app.example/a/%2E/c"));
    try std.testing.expectError(error.InvalidClientId, clientIdDocument("https://app.example/c#f"));
    try std.testing.expectError(error.InvalidClientId, clientIdDocument("https://app.example/c?q=1"));
    try std.testing.expectError(error.InvalidClientId, clientIdDocument("https://u:p@app.example/c"));
}
