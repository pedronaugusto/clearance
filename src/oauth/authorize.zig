//! The authorization request (RFC 6749 §4.1.1 as OAuth 2.1 §4.1.1 has it:
//! the code flow with PKCE) written as the URL a browser opens, and its
//! answer read from the redirect: `state` checked, the `iss` parameter
//! checked against the authorization server (RFC 9207), then the code or the
//! error.
const std = @import("std");
const wire = @import("uplink.wire");
const form = wire.form;
const url = @import("url.zig");
const pkce = @import("pkce.zig");
const errors = @import("errors.zig");

pub const Request = struct {
    client_id: []const u8,
    /// Exactly as registered: the token request repeats it.
    redirect_uri: []const u8,
    state: []const u8,
    /// `Pkce.challenge`; the method is always S256.
    code_challenge: []const u8,
    /// Space-separated; left out when null (MCP: when there is no scope to
    /// ask for, none is sent).
    scope: ?[]const u8 = null,
    /// RFC 8707's `resource`, once each: the resources the token is for.
    resources: []const []const u8 = &.{},
    /// OpenID Connect's `nonce`, when an ID token is asked for.
    nonce: ?[]const u8 = null,
    /// Any further parameters (`prompt`, `login_hint`...), written last.
    extra: []const form.Pair = &.{},
};

pub const WriteError = url.Error || std.Io.Writer.Error;

/// Writes the authorization URL: `endpoint` (an endpoint URL, whose query is
/// kept, RFC 6749 §3.1) with the request's parameters added.
pub fn writeUrl(w: *std.Io.Writer, endpoint: []const u8, request: Request) WriteError!void {
    const u = try url.endpoint(endpoint);
    try w.writeAll(endpoint);
    var separator: u8 = if (std.mem.findScalar(u8, u.target, '?')) |at| (if (at + 1 == u.target.len or u.target[u.target.len - 1] == '&') 0 else '&') else '?';
    const fixed = [_]form.Pair{
        .{ .name = "response_type", .value = "code" },
        .{ .name = "client_id", .value = request.client_id },
        .{ .name = "redirect_uri", .value = request.redirect_uri },
        .{ .name = "state", .value = request.state },
        .{ .name = "code_challenge", .value = request.code_challenge },
        .{ .name = "code_challenge_method", .value = pkce.method },
    };
    for (fixed) |pair| try param(w, &separator, pair);
    if (request.scope) |scope| try param(w, &separator, .{ .name = "scope", .value = scope });
    for (request.resources) |resource| try param(w, &separator, .{ .name = "resource", .value = resource });
    if (request.nonce) |nonce| try param(w, &separator, .{ .name = "nonce", .value = nonce });
    for (request.extra) |pair| try param(w, &separator, pair);
}

fn param(w: *std.Io.Writer, separator: *u8, pair: form.Pair) std.Io.Writer.Error!void {
    if (separator.* != 0) try w.writeByte(separator.*);
    separator.* = '&';
    try form.encode(w, &.{pair});
}

/// What the client sent and from whom it expects the answer.
pub const Expected = struct {
    /// The `state` the request carried.
    state: []const u8,
    /// The authorization server's issuer identifier, as its metadata gave it.
    issuer: []const u8,
    /// Whether the metadata advertised
    /// `authorization_response_iss_parameter_supported`: the answer must then
    /// carry `iss` (RFC 9207 §2.4).
    issuer_required: bool,
};

/// The authorization server's answer.
pub const Callback = union(enum) {
    /// The authorization code, decoded; it lives in the scratch buffer.
    code: []const u8,
    /// The server refused (RFC 6749 §4.1.2.1).
    refused: errors.ErrorResponse,
};

pub const CallbackError = error{
    /// A parameter named twice (RFC 6749 §3.1), or a code and an error both.
    Malformed,
    /// The query is longer than the scratch buffer.
    TooLarge,
    /// No `state`, or another than the request's: not an answer to this
    /// request (CSRF, RFC 9700 §4.7).
    StateMismatch,
    /// `iss` is not the expected issuer, byte for byte: the answer comes from
    /// another authorization server (mix-up, RFC 9207 §2.4).
    IssuerMismatch,
    /// The server advertised `iss` and the answer has none.
    MissingIssuer,
    /// Neither a code nor an error.
    MissingCode,
};

/// The query of a redirect URL: what follows `?`, up to a fragment.
pub fn queryOf(redirect: []const u8) []const u8 {
    const start = (std.mem.findScalar(u8, redirect, '?') orelse return "") + 1;
    const end = std.mem.findScalarPos(u8, redirect, start, '#') orelse redirect.len;
    return redirect[start..end];
}

/// Reads the redirect's query (`queryOf`): `state` first, then `iss`, then
/// the code or the error. `scratch` holds the decoded query; it is at least
/// as long as the query.
pub fn readCallback(query: []const u8, expected: Expected, scratch: []u8) CallbackError!Callback {
    if (query.len > scratch.len) return error.TooLarge;
    const text = scratch[0..query.len];
    @memcpy(text, query);
    const Name = enum { code, state, iss, @"error", error_description, error_uri };
    var values: std.EnumArray(Name, ?[]const u8) = .initFill(null);
    // Split by index, so each name and value is decoded in place in `text`:
    // pieces between `&`s, empty ones skipped, a piece without `=` a name
    // with an empty value (as `form.Iterator` reads them).
    var start: usize = 0;
    while (start < text.len) {
        const end = std.mem.findScalarPos(u8, text, start, '&') orelse text.len;
        defer start = end + 1;
        const piece = text[start..end];
        if (piece.len == 0) continue;
        const eq = std.mem.findScalar(u8, piece, '=') orelse piece.len;
        const which = std.meta.stringToEnum(Name, form.decode(piece[0..eq])) orelse continue;
        if (values.get(which) != null) return error.Malformed;
        values.set(which, if (eq == piece.len) "" else form.decode(piece[eq + 1 ..]));
    }
    const state = values.get(.state) orelse return error.StateMismatch;
    if (!pkce.same(state, expected.state)) return error.StateMismatch;
    if (values.get(.iss)) |iss| {
        // Compared as strings, never normalized (RFC 9207 §2.4).
        if (!std.mem.eql(u8, iss, expected.issuer)) return error.IssuerMismatch;
    } else if (expected.issuer_required) return error.MissingIssuer;
    if (values.get(.@"error")) |name| {
        if (values.get(.code) != null) return error.Malformed;
        return .{ .refused = errors.fromParts(name, values.get(.error_description), values.get(.error_uri)) orelse return error.Malformed };
    }
    const code = values.get(.code) orelse return error.MissingCode;
    if (code.len == 0) return error.MissingCode;
    return .{ .code = code };
}

test "the authorization URL carries PKCE, the resources and the endpoint's own query" {
    var buffer: [512]u8 = undefined;
    var w: std.Io.Writer = .fixed(&buffer);
    try writeUrl(&w, "https://as.example/authorize?tenant=a%20b", .{
        .client_id = "c 1",
        .redirect_uri = "http://127.0.0.1:9/cb",
        .state = "st",
        .code_challenge = "E9Melhoa2OwvFrEMTJguCHaoeK1t8URWbuGJSstw-cM",
        .scope = "read write",
        .resources = &.{"https://rs.example/mcp"},
    });
    try std.testing.expectEqualStrings("https://as.example/authorize?tenant=a%20b&response_type=code&client_id=c+1&redirect_uri=http%3A%2F%2F127.0.0.1%3A9%2Fcb&state=st&code_challenge=E9Melhoa2OwvFrEMTJguCHaoeK1t8URWbuGJSstw-cM&code_challenge_method=S256&scope=read+write&resource=https%3A%2F%2Frs.example%2Fmcp", w.buffered());
    w = .fixed(&buffer);
    try writeUrl(&w, "https://as.example/authorize", .{ .client_id = "c", .redirect_uri = "r", .state = "s", .code_challenge = "x" });
    try std.testing.expect(std.mem.startsWith(u8, w.buffered(), "https://as.example/authorize?response_type=code&"));
    try std.testing.expectError(error.NotHttps, writeUrl(&w, "http://as.example/authorize", .{ .client_id = "c", .redirect_uri = "r", .state = "s", .code_challenge = "x" }));
}

test "a callback is checked for state, then iss, then read" {
    var scratch: [256]u8 = undefined;
    const expected: Expected = .{ .state = "s1", .issuer = "https://as.example", .issuer_required = false };
    const got = try readCallback("code=abc%2Bd&state=s1", expected, &scratch);
    try std.testing.expectEqualStrings("abc+d", got.code);
    try std.testing.expectError(error.StateMismatch, readCallback("code=abc&state=s2", expected, &scratch));
    try std.testing.expectError(error.StateMismatch, readCallback("code=abc", expected, &scratch));
    try std.testing.expectError(error.Malformed, readCallback("code=a&code=b&state=s1", expected, &scratch));
    try std.testing.expectError(error.Malformed, readCallback("code=a&state=s1&state=s1", expected, &scratch));
    try std.testing.expectError(error.MissingCode, readCallback("state=s1", expected, &scratch));
    try std.testing.expectError(error.MissingCode, readCallback("code&state=s1", expected, &scratch));
    try std.testing.expectError(error.StateMismatch, readCallback("code=a&state", expected, &scratch));
    try std.testing.expectEqualStrings("a", (try readCallback("&&code=a&&st%61te=s1&", expected, &scratch)).code);
    const refused = try readCallback("error=access_denied&error_description=no+thanks&state=s1", expected, &scratch);
    try std.testing.expectEqual(errors.Code.access_denied, refused.refused.code);
    try std.testing.expectEqualStrings("no thanks", refused.refused.description.slice());
    try std.testing.expectError(error.TooLarge, readCallback("code=abc&state=s1", expected, scratch[0..4]));
    try std.testing.expectEqualStrings("code=1&state=2", queryOf("http://127.0.0.1/cb?code=1&state=2#frag"));
}

test "RFC 9207: iss compared as a string, required when advertised, checked when sent anyway" {
    var scratch: [256]u8 = undefined;
    const advertised: Expected = .{ .state = "s", .issuer = "https://as.example/", .issuer_required = true };
    _ = try readCallback("code=c&state=s&iss=https%3A%2F%2Fas.example%2F", advertised, &scratch);
    try std.testing.expectError(error.MissingIssuer, readCallback("code=c&state=s", advertised, &scratch));
    try std.testing.expectError(error.IssuerMismatch, readCallback("code=c&state=s&iss=https%3A%2F%2Fevil.example%2F", advertised, &scratch));
    // A normalized form is another string.
    try std.testing.expectError(error.IssuerMismatch, readCallback("code=c&state=s&iss=https%3A%2F%2FAS.example%2F", advertised, &scratch));
    try std.testing.expectError(error.IssuerMismatch, readCallback("code=c&state=s&iss=https%3A%2F%2Fas.example", advertised, &scratch));
    const silent: Expected = .{ .state = "s", .issuer = "https://as.example/", .issuer_required = false };
    _ = try readCallback("code=c&state=s", silent, &scratch);
    try std.testing.expectError(error.IssuerMismatch, readCallback("code=c&state=s&iss=https%3A%2F%2Fevil.example%2F", silent, &scratch));
    try std.testing.expectError(error.IssuerMismatch, readCallback("error=access_denied&state=s&iss=x", silent, &scratch));
}
