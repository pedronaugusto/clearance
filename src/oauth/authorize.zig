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
    /// RFC 9449 §10: the thumbprint of the DPoP key the code will be
    /// redeemed with, base64url.
    dpop_jkt: ?[]const u8 = null,
    /// Any further parameters (`prompt`, `login_hint`...), written last.
    extra: []const form.Pair = &.{},
};

pub const WriteError = url.Error || std.Io.Writer.Error;

/// Writes the authorization URL: `endpoint` (an endpoint URL, whose query is
/// kept, RFC 6749 §3.1) with the request's parameters added.
pub fn writeUrl(w: *std.Io.Writer, endpoint: []const u8, request: Request) WriteError!void {
    var separator = try writeEndpoint(w, endpoint);
    var it: Params = .{ .request = request };
    while (it.next()) |pair| try param(w, &separator, pair);
}

/// Writes `endpoint` and returns the separator its first added parameter
/// takes: its own query is kept (RFC 6749 §3.1).
fn writeEndpoint(w: *std.Io.Writer, endpoint: []const u8) WriteError!u8 {
    const u = try url.endpoint(endpoint);
    try w.writeAll(endpoint);
    return if (std.mem.findScalar(u8, u.target, '?')) |at| (if (at + 1 == u.target.len or u.target[u.target.len - 1] == '&') 0 else '&') else '?';
}

/// The authorization request's parameters in the order they are sent: one
/// list, read by the URL and by a pushed request (RFC 9126 §2.1) alike.
pub const Params = struct {
    request: Request,
    /// Whether `client_id` is among them: a pushed request leaves it to the
    /// client's authentication when that carries it.
    client_id: bool = true,
    at: usize = 0,

    pub fn next(it: *Params) ?form.Pair {
        const r = it.request;
        const fixed_count = 6;
        while (true) {
            const i = it.at;
            it.at += 1;
            if (i < fixed_count) {
                const pair: form.Pair = switch (i) {
                    0 => .{ .name = "response_type", .value = "code" },
                    1 => .{ .name = "client_id", .value = r.client_id },
                    2 => .{ .name = "redirect_uri", .value = r.redirect_uri },
                    3 => .{ .name = "state", .value = r.state },
                    4 => .{ .name = "code_challenge", .value = r.code_challenge },
                    else => .{ .name = "code_challenge_method", .value = pkce.method },
                };
                if (i == 1 and !it.client_id) continue;
                return pair;
            }
            var k = i - fixed_count;
            if (k == 0) {
                if (r.scope) |scope| return .{ .name = "scope", .value = scope };
                continue;
            }
            k -= 1;
            if (k < r.resources.len) return .{ .name = "resource", .value = r.resources[k] };
            k -= r.resources.len;
            if (k == 0) {
                if (r.nonce) |nonce| return .{ .name = "nonce", .value = nonce };
                continue;
            }
            if (k == 1) {
                if (r.dpop_jkt) |jkt| return .{ .name = "dpop_jkt", .value = jkt };
                continue;
            }
            k -= 2;
            if (k < r.extra.len) return r.extra[k];
            return null;
        }
    }
};

/// Writes the authorization URL of a pushed request (RFC 9126 §4): the
/// client and the `request_uri` the push was answered with.
pub fn writePushedUrl(w: *std.Io.Writer, endpoint: []const u8, client_id: []const u8, request_uri: []const u8) WriteError!void {
    var separator = try writeEndpoint(w, endpoint);
    try param(w, &separator, .{ .name = "client_id", .value = client_id });
    try param(w, &separator, .{ .name = "request_uri", .value = request_uri });
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

test "the parameters are one list: every member once, in order, client_id left out when asked" {
    const request: Request = .{ .client_id = "c", .redirect_uri = "r", .state = "s", .code_challenge = "x", .scope = "a", .resources = &.{ "r1", "r2" }, .nonce = "n", .dpop_jkt = "j", .extra = &.{.{ .name = "prompt", .value = "login" }} };
    var it: Params = .{ .request = request, .client_id = false };
    const names = [_][]const u8{ "response_type", "redirect_uri", "state", "code_challenge", "code_challenge_method", "scope", "resource", "resource", "nonce", "dpop_jkt", "prompt" };
    for (names) |n| try std.testing.expectEqualStrings(n, it.next().?.name);
    try std.testing.expectEqual(@as(?form.Pair, null), it.next());
    var bare: Params = .{ .request = .{ .client_id = "c", .redirect_uri = "r", .state = "s", .code_challenge = "x" } };
    var count: usize = 0;
    while (bare.next()) |_| count += 1;
    try std.testing.expectEqual(@as(usize, 6), count);
    var buffer: [256]u8 = undefined;
    var w: std.Io.Writer = .fixed(&buffer);
    try writePushedUrl(&w, "https://as.example/authorize", "s6BhdRkqt3", "urn:ietf:params:oauth:request_uri:6esc_11ACC5bwc014ltc14eY22c");
    try std.testing.expectEqualStrings("https://as.example/authorize?client_id=s6BhdRkqt3&request_uri=urn%3Aietf%3Aparams%3Aoauth%3Arequest_uri%3A6esc_11ACC5bwc014ltc14eY22c", w.buffered());
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
