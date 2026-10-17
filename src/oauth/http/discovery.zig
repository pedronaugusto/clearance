//! Metadata fetched: an authorization server's (RFC 8414, OpenID Connect
//! Discovery) from the locations its issuer makes, in MCP's order, and a
//! protected resource's (RFC 9728) from the `resource_metadata` its
//! challenge names or from its well-known locations. What each document
//! says is checked against what was asked before it is returned.
const std = @import("std");
const uplink = @import("uplink");
const url = @import("../url.zig");
const metadata = @import("../metadata.zig");
const challenge = @import("../challenge.zig");
const fetch = @import("fetch.zig");

pub const Options = struct {
    fetch: fetch.Options = .{},
    max_bytes: fetch.Bytes = .literal("1MiB"),
};

pub const Error = fetch.Error || metadata.ReadError || error{
    /// The issuer or resource is not an HTTPS URL (or HTTP to loopback), or
    /// an issuer has a query.
    InvalidUrl,
    /// Every location answered with a 4xx: there is no document.
    NotFound,
    /// A location answered with neither a success nor a 4xx.
    UnexpectedStatus,
};

pub const Parsed = metadata.Parsed;

/// The metadata of the authorization server `issuer`: each location of
/// `url.Discovery.order` tried in turn, a 4xx trying the next. A document
/// whose `issuer` is not `issuer` byte for byte fails at once, never tries
/// on (RFC 8414 §3.3: mix-up).
pub fn authorizationServer(gpa: std.mem.Allocator, io: std.Io, http: *uplink.Client, issuer: []const u8, options: Options) Error!Parsed(metadata.AuthorizationServer) {
    const issuer_url = url.issuer(issuer) catch return error.InvalidUrl;
    for (url.Discovery.order(issuer_url)) |where| {
        var buffer: [2048]u8 = undefined;
        var w: std.Io.Writer = .fixed(&buffer);
        url.writeDiscovery(&w, issuer, where) catch return error.InvalidUrl;
        var answer = try fetch.get(gpa, io, http, w.buffered(), options.max_bytes, options.fetch);
        defer answer.deinit(gpa);
        if (answer.status >= 400 and answer.status < 500) continue;
        if (answer.status < 200 or answer.status > 299) return error.UnexpectedStatus;
        return metadata.readAuthorizationServer(gpa, answer.body, issuer, .{ .max_bytes = options.max_bytes });
    }
    return error.NotFound;
}

/// The metadata of the protected resource `resource`: from
/// `resource_metadata` when its challenge named one (RFC 9728 §5.1), else
/// from its well-known location with the path inserted, then at the root
/// (MCP's order), a 4xx trying the next. The document's `resource` must
/// match `resource` as `match` says.
pub fn protectedResource(
    gpa: std.mem.Allocator,
    io: std.Io,
    http: *uplink.Client,
    resource: []const u8,
    resource_metadata: ?[]const u8,
    match: url.ResourceMatch,
    options: Options,
) Error!Parsed(metadata.ProtectedResource) {
    const read_options: metadata.Options = .{ .max_bytes = options.max_bytes };
    if (resource_metadata) |location| {
        var answer = try fetch.get(gpa, io, http, location, options.max_bytes, options.fetch);
        defer answer.deinit(gpa);
        if (answer.status >= 400 and answer.status < 500) return error.NotFound;
        if (answer.status < 200 or answer.status > 299) return error.UnexpectedStatus;
        return metadata.readProtectedResource(gpa, answer.body, resource, match, read_options);
    }
    var tried: [2][2048]u8 = undefined;
    var tried_len: [2]usize = .{ 0, 0 };
    for ([_]url.ResourceDiscovery{ .inserted, .root }, 0..) |where, i| {
        var w: std.Io.Writer = .fixed(&tried[i]);
        url.writeResourceDiscovery(&w, resource, where) catch return error.InvalidUrl;
        tried_len[i] = w.end;
        // A resource at the root has one location, not two.
        if (i == 1 and std.mem.eql(u8, tried[0][0..tried_len[0]], w.buffered())) break;
        var answer = try fetch.get(gpa, io, http, w.buffered(), options.max_bytes, options.fetch);
        defer answer.deinit(gpa);
        if (answer.status >= 400 and answer.status < 500) continue;
        if (answer.status < 200 or answer.status > 299) return error.UnexpectedStatus;
        return metadata.readProtectedResource(gpa, answer.body, resource, match, read_options);
    }
    return error.NotFound;
}

/// The Bearer challenge of a resource's 401 or 403, from every
/// `WWW-Authenticate` line of `headers`: where its metadata is
/// (`resource_metadata`, RFC 9728 §5.1) and the scope it needs
/// (`insufficient_scope`: a step-up, `challenge.writeStepUp`). Null when no
/// challenge is Bearer. Strings live in `arena`.
pub fn bearerChallenge(arena: std.mem.Allocator, headers: *const uplink.Headers) challenge.ReadError!?challenge.Bearer {
    var values: std.ArrayList([]const u8) = .empty;
    var it = headers.iterator();
    while (it.next()) |f| {
        if (std.ascii.eqlIgnoreCase(f.name, "www-authenticate")) try values.append(arena, f.value);
    }
    return challenge.read(arena, values.items);
}
