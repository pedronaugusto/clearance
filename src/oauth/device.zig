//! Device authorization (RFC 8628): a device without a browser asks for a
//! code, shows the person where to enter it, and polls the token endpoint
//! with the device code until they have. The request is a form request with
//! the client's authentication; the answer is read into an `Authorization`
//! or the server's error; the token request is `token.Grant.device_code`.
const std = @import("std");
const aegis = @import("aegis");
const strand = @import("strand");
const form = @import("uplink.wire").form;
const client_auth = @import("client_auth.zig");
const errors = @import("errors.zig");
const url = @import("url.zig");
const Scratch = @import("scratch.zig").Scratch;

/// The grant type the device code is redeemed with (RFC 8628 §3.4).
pub const grant_type = "urn:ietf:params:oauth:grant-type:device_code";

/// The longest `user_code` read: a person types it.
pub const max_user_code = 64;

/// The interval when the answer names none (RFC 8628 §3.2).
pub const default_interval = 5;

/// What the device asks for (RFC 8628 §3.1).
pub const Request = struct {
    /// Space-separated; the server's default when null.
    scope: ?[]const u8 = null,
    /// RFC 8707's `resource`, once each.
    resources: []const []const u8 = &.{},
    /// Any further parameters, written last.
    extra: []const form.Pair = &.{},
};

/// The device authorization request, authenticated as `client` says (a
/// public client sends its `client_id`, RFC 8628 §3.1).
pub fn request(gpa: std.mem.Allocator, io: std.Io, client: client_auth.Client, ask: Request, context: client_auth.Context) client_auth.Error!client_auth.FormRequest {
    var pairs: std.ArrayList(form.Pair) = .empty;
    defer pairs.deinit(gpa);
    if (ask.scope) |scope| try pairs.append(gpa, .{ .name = "scope", .value = scope });
    for (ask.resources) |resource| try pairs.append(gpa, .{ .name = "resource", .value = resource });
    try pairs.appendSlice(gpa, ask.extra);
    return client_auth.formRequest(gpa, io, client, pairs.items, context);
}

/// What the server answered (RFC 8628 §3.2), owned. The device code is a
/// secret until it is spent: every string lives in memory `deinit` wipes.
pub const Authorization = struct {
    /// What the token request carries.
    device_code: []const u8,
    /// What the person enters: printable, at most `max_user_code` bytes.
    user_code: []const u8,
    /// Where the person enters it: an HTTPS URL (or HTTP to loopback).
    verification_uri: []const u8,
    /// The same with the code in it, for a link or a QR code; checked as
    /// `verification_uri` is.
    verification_uri_complete: ?[]const u8 = null,
    /// When the codes expire, in seconds since the epoch.
    expires_at: i64,
    /// Seconds to wait between token requests: at least 1.
    interval: u32,
    /// Private: holds every string above.
    storage: aegis.SecretBytes,

    pub fn deinit(a: *Authorization) void {
        a.storage.deinit();
        a.* = undefined;
    }

    /// Whether the codes have expired at `now`: a new authorization is due.
    pub fn expired(a: *const Authorization, now: std.Io.Timestamp) bool {
        return @divFloor(now.nanoseconds, std.time.ns_per_s) >= a.expires_at;
    }
};

/// The device authorization endpoint's answer.
pub const Response = union(enum) {
    authorization: Authorization,
    refused: errors.ErrorResponse,
};

pub const ReadOptions = struct {
    /// The moment the answer arrived: `expires_in` counts from it.
    now: std.Io.Timestamp,
    max_bytes: aegis.units.Bytes(usize) = .literal("64KiB"),
};

pub const ReadError = error{
    TooLarge,
    /// A success that is not a device authorization: not a JSON object, a
    /// required member missing or of the wrong type, a member twice, a code
    /// with control bytes, a verification URI that is not HTTPS.
    InvalidResponse,
    /// Neither a success nor an OAuth error body.
    UnexpectedStatus,
} || std.mem.Allocator.Error;

const Wire = struct {
    device_code: []const u8,
    user_code: []const u8,
    verification_uri: ?[]const u8 = null,
    /// Google's name for `verification_uri`, from the draft RFC 8628 grew
    /// out of; read only when `verification_uri` is absent.
    verification_url: ?[]const u8 = null,
    verification_uri_complete: ?[]const u8 = null,
    expires_in: u63,
    interval: ?u32 = null,
};

/// Reads the device authorization endpoint's answer: a 2xx as an
/// `Authorization`, any other status as the server's error when the body is
/// one.
pub fn readAuthorization(gpa: std.mem.Allocator, status: u16, body: []const u8, options: ReadOptions) ReadError!Response {
    const limit: usize = options.max_bytes.raw();
    if (body.len > limit) return error.TooLarge;
    if (status < 200 or status > 299) {
        var scratch: [1024]u8 = undefined;
        if (body.len <= 4096) if (errors.readJson(body, &scratch)) |e| return .{ .refused = e };
        return error.UnexpectedStatus;
    }
    var scratch: Scratch = undefined;
    try scratch.init(gpa, body.len);
    defer scratch.deinit();
    const wire = strand.json.parseLeaky(Wire, scratch.allocator(), body, .{
        .ignore_unknown_fields = true,
        .limits = .{ .depth = 16 },
    }) catch return error.InvalidResponse;
    if (wire.device_code.len == 0) return error.InvalidResponse;
    if (!printable(wire.user_code)) return error.InvalidResponse;
    // Shown to a person: a link elsewhere than HTTPS is no place to send them.
    const verification_uri = wire.verification_uri orelse wire.verification_url orelse return error.InvalidResponse;
    _ = url.endpoint(verification_uri) catch return error.InvalidResponse;
    if (wire.verification_uri_complete) |complete| _ = url.endpoint(complete) catch return error.InvalidResponse;

    const strings = [_]?[]const u8{ wire.device_code, wire.user_code, verification_uri, wire.verification_uri_complete };
    var total: usize = 0;
    for (strings) |s| total += if (s) |v| v.len else 0;
    var storage = aegis.SecretBytes.init(gpa, total) catch return error.OutOfMemory;
    // unreachable: the capacity was just allocated at this length
    storage.resizeWithinCapacity(total) catch unreachable;
    var copied: [strings.len]?[]const u8 = undefined;
    const bytes = storage.exposeMut();
    var at: usize = 0;
    for (strings, &copied) |s, *out| {
        const v = s orelse {
            out.* = null;
            continue;
        };
        @memcpy(bytes[at..][0..v.len], v);
        out.* = bytes[at..][0..v.len];
        at += v.len;
    }
    const now: i64 = @intCast(@divFloor(options.now.nanoseconds, std.time.ns_per_s));
    return .{ .authorization = .{
        .device_code = copied[0].?,
        .user_code = copied[1].?,
        .verification_uri = copied[2].?,
        .verification_uri_complete = copied[3],
        .expires_at = now +| @as(i64, wire.expires_in),
        .interval = @max(1, wire.interval orelse default_interval),
        .storage = storage,
    } };
}

/// A code a person reads and types, printed to a screen or a terminal: not
/// empty, at most `max_user_code` bytes, UTF-8 without control characters
/// (a terminal escape in a hostile server's code would be written to the
/// user's terminal).
fn printable(code: []const u8) bool {
    if (code.len == 0 or code.len > max_user_code) return false;
    if (!std.unicode.utf8ValidateSlice(code)) return false;
    for (code) |c| if (c < 0x20 or c == 0x7f) return false;
    return true;
}

const testing = std.testing;

test "RFC 8628 §3.2's answer is read: expiry from now, the interval, the URIs checked" {
    var response = try readAuthorization(testing.allocator, 200,
        \\{"device_code":"GmRhmhcxhwAzkoEqiMEg_DnyEysNkuNhszIySk9eS","user_code":"WDJB-MJHT",
        \\"verification_uri":"https://example.com/device","verification_uri_complete":"https://example.com/device?user_code=WDJB-MJHT",
        \\"expires_in":1800,"interval":5}
    , .{ .now = .{ .nanoseconds = 100 * std.time.ns_per_s } });
    defer response.authorization.deinit();
    const a = &response.authorization;
    try testing.expectEqualStrings("GmRhmhcxhwAzkoEqiMEg_DnyEysNkuNhszIySk9eS", a.device_code);
    try testing.expectEqualStrings("WDJB-MJHT", a.user_code);
    try testing.expectEqualStrings("https://example.com/device", a.verification_uri);
    try testing.expectEqualStrings("https://example.com/device?user_code=WDJB-MJHT", a.verification_uri_complete.?);
    try testing.expectEqual(@as(i64, 1900), a.expires_at);
    try testing.expectEqual(@as(u32, 5), a.interval);
    try testing.expect(!a.expired(.{ .nanoseconds = 1899 * std.time.ns_per_s }));
    try testing.expect(a.expired(.{ .nanoseconds = 1900 * std.time.ns_per_s }));

    // Google's `verification_url`, no interval: five seconds.
    var google = try readAuthorization(testing.allocator, 200, "{\"device_code\":\"d\",\"user_code\":\"GQVQ-JKEC\",\"verification_url\":\"https://www.google.com/device\",\"expires_in\":1800}", .{ .now = .{ .nanoseconds = 0 } });
    defer google.authorization.deinit();
    try testing.expectEqualStrings("https://www.google.com/device", google.authorization.verification_uri);
    try testing.expectEqual(@as(u32, 5), google.authorization.interval);
    var zero = try readAuthorization(testing.allocator, 200, "{\"device_code\":\"d\",\"user_code\":\"u\",\"verification_uri\":\"https://a.example/d\",\"expires_in\":60,\"interval\":0}", .{ .now = .{ .nanoseconds = 0 } });
    defer zero.authorization.deinit();
    try testing.expectEqual(@as(u32, 1), zero.authorization.interval);
}

test "an answer that is not a device authorization is refused" {
    const now: ReadOptions = .{ .now = .{ .nanoseconds = 0 } };
    const cases = [_][]const u8{
        "{\"user_code\":\"u\",\"verification_uri\":\"https://a.example/d\",\"expires_in\":60}",
        "{\"device_code\":\"\",\"user_code\":\"u\",\"verification_uri\":\"https://a.example/d\",\"expires_in\":60}",
        "{\"device_code\":\"d\",\"user_code\":\"u\",\"expires_in\":60}",
        "{\"device_code\":\"d\",\"user_code\":\"u\",\"verification_uri\":\"https://a.example/d\"}",
        "{\"device_code\":\"d\",\"user_code\":\"u\",\"verification_uri\":\"https://a.example/d\",\"expires_in\":-1}",
        "{\"device_code\":\"d\",\"user_code\":\"u\",\"verification_uri\":\"https://a.example/d\",\"expires_in\":\"60\"}",
        "{\"device_code\":\"d\",\"device_code\":\"e\",\"user_code\":\"u\",\"verification_uri\":\"https://a.example/d\",\"expires_in\":60}",
        // Not a place to send a person.
        "{\"device_code\":\"d\",\"user_code\":\"u\",\"verification_uri\":\"http://a.example/d\",\"expires_in\":60}",
        "{\"device_code\":\"d\",\"user_code\":\"u\",\"verification_uri\":\"javascript:alert(1)\",\"expires_in\":60}",
        "{\"device_code\":\"d\",\"user_code\":\"u\",\"verification_uri\":\"https://a.example/d\",\"verification_uri_complete\":\"data:x\",\"expires_in\":60}",
        // A code that would write to the person's terminal.
        "{\"device_code\":\"d\",\"user_code\":\"\\u001b[2J\",\"verification_uri\":\"https://a.example/d\",\"expires_in\":60}",
        "{\"device_code\":\"d\",\"user_code\":\"\",\"verification_uri\":\"https://a.example/d\",\"expires_in\":60}",
        "[]",
    };
    for (cases) |body| try testing.expectError(error.InvalidResponse, readAuthorization(testing.allocator, 200, body, now));
    try testing.expectError(error.UnexpectedStatus, readAuthorization(testing.allocator, 502, "<html>", now));
    const refused = try readAuthorization(testing.allocator, 400, "{\"error\":\"invalid_client\"}", now);
    try testing.expectEqual(errors.Code.invalid_client, refused.refused.code);
    try testing.expectError(error.TooLarge, readAuthorization(testing.allocator, 200, "{}", .{ .now = now.now, .max_bytes = .literal("1B") }));
}

test "the request carries the scope, the resources and the client" {
    var r = try request(testing.allocator, testing.io, .{ .id = "tv-app" }, .{ .scope = "openid profile", .resources = &.{"https://rs.example/mcp"} }, .{ .issuer = "https://as.example", .now = .{ .nanoseconds = 0 } });
    defer r.deinit();
    try testing.expectEqualStrings("scope=openid+profile&resource=https%3A%2F%2Frs.example%2Fmcp&client_id=tv-app", r.body.expose());
}
