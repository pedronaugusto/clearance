//! Pushed authorization requests (RFC 9126): the authorization request's
//! parameters sent to the server first, from the client, authenticated;
//! the browser is then sent with a `request_uri` that names them. The
//! parameters are `authorize.Params`, the list the URL itself is written
//! from, so a pushed request and a URL never differ.
const std = @import("std");
const time = @import("clearance").time;
const aegis = @import("aegis");
const strand = @import("strand");
const form = @import("uplink.wire").form;
const authorize = @import("authorize.zig");
const client_auth = @import("client_auth.zig");
const errors = @import("errors.zig");

/// The longest `request_uri` read: it goes back into a URL.
pub const max_request_uri = 1024;

/// The pushed request for `request`, authenticated as `client` says
/// (RFC 9126 §2.1). `client_id` is sent once: in the parameters, unless the
/// client's authentication puts it in the body itself.
pub fn request(gpa: std.mem.Allocator, io: std.Io, client: client_auth.Client, ask: authorize.Request, context: client_auth.Context) client_auth.Error!client_auth.FormRequest {
    var pairs: std.ArrayList(form.Pair) = .empty;
    defer pairs.deinit(gpa);
    const in_body = switch (client.credentials) {
        // `Basic` carries the id in the header only.
        .client_secret_basic => false,
        else => true,
    };
    var it: authorize.Params = .{ .request = ask, .client_id = !in_body };
    while (it.next()) |pair| try pairs.append(gpa, pair);
    return client_auth.formRequest(gpa, io, client, pairs.items, context);
}

/// The push of a request object (RFC 9126 §3, RFC 9101): `request` alone
/// beside the client's authentication, `client_id` as for `request`.
pub fn requestObject(gpa: std.mem.Allocator, io: std.Io, client: client_auth.Client, object: []const u8, context: client_auth.Context) client_auth.Error!client_auth.FormRequest {
    const pairs = [_]form.Pair{ .{ .name = "client_id", .value = client.id }, .{ .name = "request", .value = object } };
    return client_auth.formRequest(gpa, io, client, if (client.credentials == .client_secret_basic) &pairs else pairs[1..], context);
}

/// What the push was answered with (RFC 9126 §2.2): the URI the browser
/// takes to the authorization endpoint, and when it expires. Held inline.
pub const Pushed = struct {
    request_uri: errors.Text(max_request_uri),
    /// Seconds since the epoch.
    expires_at: i64,
};

pub const Response = union(enum) {
    pushed: Pushed,
    refused: errors.ErrorResponse,
};

pub const ReadOptions = struct {
    /// The moment the answer arrived: `expires_in` counts from it.
    now: std.Io.Timestamp,
    max_bytes: aegis.units.Bytes(usize) = .literal("64KiB"),
};

pub const ReadError = error{
    TooLarge,
    /// A 201 that is not a push's answer: not a JSON object, `request_uri`
    /// missing, empty, longer than `max_request_uri` or not printable ASCII,
    /// `expires_in` missing or not a positive integer, a member twice.
    InvalidResponse,
    /// Neither a 201 nor an OAuth error body.
    UnexpectedStatus,
};

const Wire = struct {
    request_uri: []const u8,
    expires_in: u63,
};

/// Reads the push's answer: a 201 as the `request_uri` (§2.2), any other
/// status as the server's error when the body is one (§2.3).
pub fn readResponse(status: u16, body: []const u8, options: ReadOptions) ReadError!Response {
    const limit: usize = options.max_bytes.raw();
    if (body.len > limit) return error.TooLarge;
    if (status != 201) {
        var scratch: [1024]u8 = undefined;
        if (body.len <= 4096) if (errors.readJson(body, &scratch)) |e| return .{ .refused = e };
        return error.UnexpectedStatus;
    }
    var scratch: [4096]u8 = undefined;
    var fixed: std.heap.FixedBufferAllocator = .init(&scratch);
    const wire = strand.json.parseLeaky(Wire, fixed.allocator(), body, .{
        .ignore_unknown_fields = true,
        .limits = .{ .depth = 8 },
    }) catch return error.InvalidResponse;
    const uri = wire.request_uri;
    if (uri.len == 0 or uri.len > max_request_uri or wire.expires_in == 0) return error.InvalidResponse;
    for (uri) |c| if (c < 0x21 or c > 0x7e) return error.InvalidResponse;
    const now: i64 = time.unixSeconds(options.now);
    return .{ .pushed = .{ .request_uri = .init(uri), .expires_at = now +| @as(i64, wire.expires_in) } };
}

const testing = std.testing;

test "RFC 9126 §2.1's request: the authorization parameters, client_id once" {
    const context: client_auth.Context = .{ .issuer = "https://as.example", .now = .{ .nanoseconds = 0 } };
    const ask: authorize.Request = .{ .client_id = "s6BhdRkqt3", .redirect_uri = "https://client.example.org/cb", .state = "af0ifjsldkj", .code_challenge = "K2-ltc83acc4h0c9w6ESC_rEMTJ3bww-uCHaoeK1t8U", .scope = "openid" };
    var basic = try request(testing.allocator, testing.io, .{ .id = "s6BhdRkqt3", .credentials = .{ .client_secret_basic = "7Fjfp0ZBr1KtDRbnfVdmIw" } }, ask, context);
    defer basic.deinit();
    try testing.expectEqualStrings("response_type=code&client_id=s6BhdRkqt3&redirect_uri=https%3A%2F%2Fclient.example.org%2Fcb&state=af0ifjsldkj&code_challenge=K2-ltc83acc4h0c9w6ESC_rEMTJ3bww-uCHaoeK1t8U&code_challenge_method=S256&scope=openid", basic.body.expose());
    try testing.expect(basic.authorization != null);
    var public = try request(testing.allocator, testing.io, .{ .id = "s6BhdRkqt3" }, ask, context);
    defer public.deinit();
    try testing.expectEqual(@as(usize, 1), std.mem.count(u8, public.body.expose(), "client_id="));
}

test "a 201 is read as the request_uri, anything else as the server's error or refused" {
    const now: ReadOptions = .{ .now = .{ .nanoseconds = 10 * std.time.ns_per_s } };
    const r = try readResponse(201, "{\"request_uri\":\"urn:ietf:params:oauth:request_uri:6esc_11ACC5bwc014ltc14eY22c\",\"expires_in\":60}", now);
    try testing.expectEqualStrings("urn:ietf:params:oauth:request_uri:6esc_11ACC5bwc014ltc14eY22c", r.pushed.request_uri.slice());
    try testing.expectEqual(@as(i64, 70), r.pushed.expires_at);
    const cases = [_][]const u8{
        "{\"expires_in\":60}",
        "{\"request_uri\":\"\",\"expires_in\":60}",
        "{\"request_uri\":\"urn:x\"}",
        "{\"request_uri\":\"urn:x\",\"expires_in\":0}",
        "{\"request_uri\":\"urn:x y\",\"expires_in\":60}",
        "{\"request_uri\":\"urn:x\",\"request_uri\":\"urn:y\",\"expires_in\":60}",
        "[]",
    };
    for (cases) |body| try testing.expectError(error.InvalidResponse, readResponse(201, body, now));
    try testing.expectError(error.UnexpectedStatus, readResponse(200, "{\"request_uri\":\"urn:x\",\"expires_in\":60}", now));
    const refused = try readResponse(400, "{\"error\":\"invalid_request\",\"error_description\":\"The redirect_uri is not valid for the given client\"}", now);
    try testing.expectEqual(errors.Code.invalid_request, refused.refused.code);
}

test "a pushed request object (RFC 9126 §3): request beside the client's authentication, client_id once" {
    const context: client_auth.Context = .{ .issuer = "https://as.example", .now = .{ .nanoseconds = 0 } };
    var basic = try requestObject(testing.allocator, testing.io, .{ .id = "s6BhdRkqt3", .credentials = .{ .client_secret_basic = "7Fjfp0ZBr1KtDRbnfVdmIw" } }, "e.y.j", context);
    defer basic.deinit();
    try testing.expectEqualStrings("client_id=s6BhdRkqt3&request=e.y.j", basic.body.expose());
    for ([_]client_auth.Credentials{ .none, .tls_client_auth, .self_signed_tls_client_auth }) |credentials| {
        var other = try requestObject(testing.allocator, testing.io, .{ .id = "s6BhdRkqt3", .credentials = credentials }, "e.y.j", context);
        defer other.deinit();
        try testing.expectEqualStrings("request=e.y.j&client_id=s6BhdRkqt3", other.body.expose());
        try testing.expect(other.authorization == null);
    }
}
