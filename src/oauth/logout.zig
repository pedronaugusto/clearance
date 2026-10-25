//! OpenID Connect logout, the relying party's side: the RP-Initiated Logout
//! 1.0 request (the browser sent to the provider's `end_session_endpoint`),
//! the Back-Channel Logout 1.0 request read (its `logout_token`, verified by
//! `clearance.logout`), and the Front-Channel Logout 1.0 request's `iss`
//! and `sid` read and checked.
const std = @import("std");
const form = @import("uplink.wire").form;
const url = @import("url.zig");

/// RP-Initiated Logout 1.0 §2's parameters.
pub const Request = struct {
    /// The ID token the session was signed in with: the provider's way to
    /// know whose session, and that the request is this client's.
    id_token_hint: ?[]const u8 = null,
    logout_hint: ?[]const u8 = null,
    /// Sent when there is no ID token to send, or beside it.
    client_id: ?[]const u8 = null,
    /// Where the provider sends the browser after, as registered
    /// (`post_logout_redirect_uris`).
    post_logout_redirect_uri: ?[]const u8 = null,
    /// Returned with the redirect, for the client to check.
    state: ?[]const u8 = null,
    ui_locales: ?[]const u8 = null,
};

pub const WriteError = url.Error || std.Io.Writer.Error || error{
    /// A `post_logout_redirect_uri` without the ID token or the client that
    /// registered it (§2: the provider could not check it).
    UnknownClient,
};

/// Writes the logout URL: `end_session_endpoint` (its own query kept) with
/// the request's parameters.
pub fn writeUrl(w: *std.Io.Writer, end_session_endpoint: []const u8, request: Request) WriteError!void {
    if (request.post_logout_redirect_uri != null and request.id_token_hint == null and request.client_id == null) return error.UnknownClient;
    const u = try url.endpoint(end_session_endpoint);
    try w.writeAll(end_session_endpoint);
    var separator: u8 = if (std.mem.findScalar(u8, u.target, '?')) |at| (if (at + 1 == u.target.len or u.target[u.target.len - 1] == '&') 0 else '&') else '?';
    inline for (.{ "id_token_hint", "logout_hint", "client_id", "post_logout_redirect_uri", "state", "ui_locales" }) |name| {
        if (@field(request, name)) |value| {
            if (separator != 0) try w.writeByte(separator);
            separator = '&';
            try form.encode(w, &.{.{ .name = name, .value = value }});
        }
    }
}

pub const ReadError = error{
    /// No `logout_token`, or one named twice.
    Malformed,
    /// The body is longer than the scratch buffer.
    TooLarge,
};

/// The `logout_token` of a Back-Channel Logout request's form body (§2.5),
/// decoded into `scratch` (at least as long as the body); verify it with
/// `clearance.logout.verifyToken`. Answer 200 with `Cache-Control:
/// no-store` once the sessions are ended, 400 when it does not verify.
pub fn readBackChannel(body: []const u8, scratch: []u8) ReadError![]const u8 {
    if (body.len > scratch.len) return error.TooLarge;
    var found: ?[]const u8 = null;
    var it: form.Iterator = .init(body);
    var used: usize = 0;
    while (it.next()) |pair| {
        const name_buffer = scratch[used..][0..pair.name.len];
        @memcpy(name_buffer, pair.name);
        if (!std.mem.eql(u8, form.decode(name_buffer), "logout_token")) continue;
        if (found != null) return error.Malformed;
        const value = scratch[used..][0..pair.value.len];
        @memcpy(value, pair.value);
        const decoded = form.decode(value);
        used += decoded.len;
        found = decoded;
    }
    const token = found orelse return error.Malformed;
    if (token.len == 0) return error.Malformed;
    return token;
}

/// What a Front-Channel Logout request names (§2): the session that ends,
/// from the issuer that ends it.
pub const FrontChannel = struct {
    iss: ?[]const u8 = null,
    sid: ?[]const u8 = null,
};

pub const FrontChannelError = error{
    Malformed,
    TooLarge,
    /// `iss` is not the provider's issuer, byte for byte.
    WrongIssuer,
    /// One of `iss` and `sid` without the other, or neither when the client
    /// registered `frontchannel_logout_session_required`.
    MissingSession,
};

/// Reads a Front-Channel Logout request's query: `iss` and `sid` together
/// (both or neither, §2), `iss` held to `issuer`. `session_required` is the
/// client's `frontchannel_logout_session_required`. Strings are decoded into
/// `scratch`, at least as long as the query.
pub fn readFrontChannel(query: []const u8, issuer: []const u8, session_required: bool, scratch: []u8) FrontChannelError!FrontChannel {
    if (query.len > scratch.len) return error.TooLarge;
    var out: FrontChannel = .{};
    var it: form.Iterator = .init(query);
    var used: usize = 0;
    while (it.next()) |pair| {
        const name_buffer = scratch[used..][0..pair.name.len];
        @memcpy(name_buffer, pair.name);
        const name = form.decode(name_buffer);
        const slot: *?[]const u8 = if (std.mem.eql(u8, name, "iss")) &out.iss else if (std.mem.eql(u8, name, "sid")) &out.sid else continue;
        if (slot.* != null) return error.Malformed;
        const value = scratch[used..][0..pair.value.len];
        @memcpy(value, pair.value);
        const decoded = form.decode(value);
        used += decoded.len;
        slot.* = decoded;
    }
    if ((out.iss == null) != (out.sid == null)) return error.MissingSession;
    if (session_required and out.iss == null) return error.MissingSession;
    if (out.iss) |iss| if (!std.mem.eql(u8, iss, issuer)) return error.WrongIssuer;
    return out;
}

const testing = std.testing;

test "RP-Initiated Logout's URL carries the hint, the client and where to return" {
    var buffer: [512]u8 = undefined;
    var w: std.Io.Writer = .fixed(&buffer);
    try writeUrl(&w, "https://server.example.com/logout", .{ .id_token_hint = "eyJ.id.tok", .post_logout_redirect_uri = "https://client.example.org/bye", .state = "s 1" });
    try testing.expectEqualStrings("https://server.example.com/logout?id_token_hint=eyJ.id.tok&post_logout_redirect_uri=https%3A%2F%2Fclient.example.org%2Fbye&state=s+1", w.buffered());
    w = .fixed(&buffer);
    try writeUrl(&w, "https://server.example.com/logout?tenant=a", .{ .client_id = "app" });
    try testing.expectEqualStrings("https://server.example.com/logout?tenant=a&client_id=app", w.buffered());
    try testing.expectError(error.UnknownClient, writeUrl(&w, "https://server.example.com/logout", .{ .post_logout_redirect_uri = "https://client.example.org/bye" }));
    try testing.expectError(error.NotHttps, writeUrl(&w, "http://server.example.com/logout", .{}));
}

test "a back-channel request's logout_token is read once" {
    var scratch: [256]u8 = undefined;
    try testing.expectEqualStrings("eyJ.a.b", try readBackChannel("logout_token=eyJ.a.b", &scratch));
    try testing.expectEqualStrings("eyJ.a.b", try readBackChannel("x=1&logout%5Ftoken=eyJ%2Ea.b", &scratch));
    try testing.expectError(error.Malformed, readBackChannel("logout_token=a&logout_token=b", &scratch));
    try testing.expectError(error.Malformed, readBackChannel("token=a", &scratch));
    try testing.expectError(error.Malformed, readBackChannel("logout_token=", &scratch));
    try testing.expectError(error.TooLarge, readBackChannel("logout_token=abc", scratch[0..4]));
}

test "a front-channel request's iss and sid come together, iss the provider's" {
    var scratch: [256]u8 = undefined;
    const issuer = "https://server.example.com";
    const f = try readFrontChannel("iss=https%3A%2F%2Fserver.example.com&sid=08a5019c", issuer, true, &scratch);
    try testing.expectEqualStrings("08a5019c", f.sid.?);
    const bare = try readFrontChannel("", issuer, false, &scratch);
    try testing.expectEqual(@as(?[]const u8, null), bare.sid);
    try testing.expectError(error.MissingSession, readFrontChannel("", issuer, true, &scratch));
    try testing.expectError(error.MissingSession, readFrontChannel("sid=1", issuer, false, &scratch));
    try testing.expectError(error.WrongIssuer, readFrontChannel("iss=https%3A%2F%2Fevil.example&sid=1", issuer, false, &scratch));
    try testing.expectError(error.Malformed, readFrontChannel("iss=a&iss=b&sid=1", issuer, false, &scratch));
}
