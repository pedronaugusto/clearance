//! The exchanges every flow is made of, on uplink's client: a GET of a JSON
//! document and a POST of a form or of JSON, each to an endpoint OAuth may
//! send to, never following a redirect (what was asked is what answers:
//! RFC 8414 §3, RFC 9728 §3), each answer read whole up to a bound. An
//! answer that may carry secrets (tokens, a client secret) is read into
//! wiped memory.
const std = @import("std");
const aegis = @import("aegis");
const uplink = @import("uplink");
const url = @import("../url.zig");
const client_auth = @import("../client_auth.zig");
const errors = @import("../errors.zig");

pub const Bytes = aegis.units.Bytes(usize);

pub const Error = error{
    /// The endpoint is not HTTPS (or HTTP to loopback), or not a URL.
    InvalidEndpoint,
    /// The answer is longer than the bound.
    TooLarge,
    /// The exchange failed: no connection, a timeout, TLS, a protocol error.
    /// What happened is in uplink's diagnostics when the caller asks.
    ConnectionFailed,
    TimedOut,
    TlsFailed,
    Canceled,
    OutOfMemory,
};

/// An answer read whole.
pub const Answer = struct {
    status: u16,
    body: []u8,
    /// How long a private cache may keep it (`uplink.wire.cache.freshFor`),
    /// null when the answer says nothing.
    fresh_for: ?u32,
    /// The media type of `Content-Type`, without its parameters (cut at 128
    /// bytes).
    content_type: errors.Text(128) = .{},
    /// Every `WWW-Authenticate` line, owned: a protected resource's 401 or
    /// 403 says why in them.
    challenges: []const []const u8 = &.{},
    /// The answer's `DPoP-Nonce` (RFC 9449 §9), when it has one that fits.
    dpop_nonce: ?errors.Text(256) = null,

    pub fn deinit(a: *Answer, gpa: std.mem.Allocator) void {
        gpa.free(a.body);
        for (a.challenges) |c| gpa.free(c);
        gpa.free(a.challenges);
        a.* = undefined;
    }
};

/// An answer whose body may hold secrets, in memory `deinit` wipes.
pub const SecretAnswer = struct {
    status: u16,
    body: aegis.SecretBytes,
    /// The answer's `DPoP-Nonce` (RFC 9449 §8), when it has one that fits.
    dpop_nonce: ?errors.Text(256) = null,
    /// What the secret bytes were allocated with, which frees them.
    gpa: std.mem.Allocator,

    pub fn deinit(a: *SecretAnswer) void {
        a.body.deinit(a.gpa);
        a.* = undefined;
    }
};

pub const Options = struct {
    /// Every exchange must be done by then, the body read included.
    timeout: std.Io.Timeout = .none,
    diagnostics: ?*uplink.Diagnostics = null,
};

/// GETs the JSON document at `target`.
pub fn get(gpa: std.mem.Allocator, io: std.Io, http: *uplink.Client, target: []const u8, limit: Bytes, options: Options) Error!Answer {
    return getWith(gpa, io, http, target, &.{.{ .name = "Accept", .value = "application/json" }}, limit, options);
}

/// GETs the protected resource at `target` (OpenID Connect's UserInfo)
/// presenting `authorization` (`Bearer <token>` or `DPoP <token>`), with
/// `dpop` as its `DPoP` field when given; JSON or a JWT accepted.
pub fn getProtected(gpa: std.mem.Allocator, io: std.Io, http: *uplink.Client, target: []const u8, authorization: []const u8, dpop: ?[]const u8, limit: Bytes, options: Options) Error!Answer {
    var headers: [3]uplink.Header = .{
        .{ .name = "Accept", .value = "application/json, application/jwt" },
        .{ .name = "Authorization", .value = authorization },
        undefined,
    };
    var count: usize = 2;
    if (dpop) |proof| {
        headers[2] = .{ .name = "DPoP", .value = proof };
        count = 3;
    }
    return getWith(gpa, io, http, target, headers[0..count], limit, options);
}

fn getWith(gpa: std.mem.Allocator, io: std.Io, http: *uplink.Client, target: []const u8, headers: []const uplink.Header, limit: Bytes, options: Options) Error!Answer {
    _ = url.endpoint(target) catch return error.InvalidEndpoint;
    var response = try send(http, io, .{
        .url = target,
        .headers = headers,
        .redirects = .none,
        .timeout = options.timeout,
        .diagnostics = options.diagnostics,
    });
    defer response.deinit(io);
    const body = response.collect(gpa, io, .limited(limit.raw())) catch |err| return switch (err) {
        error.StreamTooLong => error.TooLarge,
        error.OutOfMemory => error.OutOfMemory,
        error.TimedOut => error.TimedOut,
        error.Canceled => error.Canceled,
        error.TlsFailed, error.ClientCertificateRejected => error.TlsFailed,
        error.ConnectionFailed, error.HttpProtocolError, error.BadContentEncoding, error.BodyIncomplete => error.ConnectionFailed,
    };
    errdefer gpa.free(body);
    var answer: Answer = .{ .status = @backingInt(response.status), .body = body, .fresh_for = uplink.wire.cache.freshFor(&response.headers) };
    if (response.headers.get("content-type")) |t| answer.content_type = .init(std.mem.trim(u8, t[0 .. std.mem.findScalar(u8, t, ';') orelse t.len], " \t"));
    if (response.headers.get("dpop-nonce")) |n| if (n.len <= 256) {
        answer.dpop_nonce = .init(n);
    };
    var lines: std.ArrayList([]const u8) = .empty;
    errdefer {
        for (lines.items) |l| gpa.free(l);
        lines.deinit(gpa);
    }
    var it = response.headers.iterator();
    while (it.next()) |f| if (std.ascii.eqlIgnoreCase(f.name, "www-authenticate")) {
        const line = try gpa.dupe(u8, f.value);
        lines.append(gpa, line) catch {
            gpa.free(line);
            return error.OutOfMemory;
        };
    };
    answer.challenges = try lines.toOwnedSlice(gpa);
    return answer;
}

/// POSTs `request` (a form request with the client's credentials) to
/// `target`, with `dpop` as its `DPoP` field when given (RFC 9449 §5), the
/// answer read into wiped memory.
pub fn postForm(gpa: std.mem.Allocator, io: std.Io, http: *uplink.Client, target: []const u8, request: *const client_auth.FormRequest, dpop: ?[]const u8, limit: Bytes, options: Options) Error!SecretAnswer {
    var headers: [4]uplink.Header = .{
        .{ .name = "Content-Type", .value = client_auth.FormRequest.content_type },
        .{ .name = "Accept", .value = "application/json" },
        undefined,
        undefined,
    };
    var count: usize = 2;
    if (request.authorization) |*a| {
        headers[count] = .{ .name = "Authorization", .value = a.expose() };
        count += 1;
    }
    if (dpop) |proof| {
        headers[count] = .{ .name = "DPoP", .value = proof };
        count += 1;
    }
    return post(gpa, io, http, target, headers[0..count], request.body.expose(), limit, options);
}

/// POSTs the JSON `body` to `target`, with `bearer` as the `Authorization`
/// when given (an initial access token, RFC 7591 §3), the answer read into
/// wiped memory.
pub fn postJson(gpa: std.mem.Allocator, io: std.Io, http: *uplink.Client, target: []const u8, body: []const u8, bearer: ?[]const u8, limit: Bytes, options: Options) Error!SecretAnswer {
    var authorization: ?aegis.SecretBytes = null;
    defer if (authorization) |*a| a.deinit(gpa);
    var headers: [3]uplink.Header = .{
        .{ .name = "Content-Type", .value = "application/json" },
        .{ .name = "Accept", .value = "application/json" },
        undefined,
    };
    var count: usize = 2;
    if (bearer) |token| {
        const prefix = "Bearer ";
        authorization = aegis.SecretBytes.init(gpa, prefix.len + token.len) catch return error.OutOfMemory;
        // unreachable: the capacity was just allocated at this length
        authorization.?.resizeWithinCapacity(prefix.len + token.len) catch unreachable;
        const bytes = authorization.?.exposeMut();
        @memcpy(bytes[0..prefix.len], prefix);
        @memcpy(bytes[prefix.len..], token);
        headers[2] = .{ .name = "Authorization", .value = bytes };
        count = 3;
    }
    return post(gpa, io, http, target, headers[0..count], body, limit, options);
}

fn post(gpa: std.mem.Allocator, io: std.Io, http: *uplink.Client, target: []const u8, headers: []const uplink.Header, body: []const u8, limit: Bytes, options: Options) Error!SecretAnswer {
    _ = url.endpoint(target) catch return error.InvalidEndpoint;
    var response = try send(http, io, .{
        .method = .POST,
        .url = target,
        .headers = headers,
        .body = .{ .bytes = body },
        .redirects = .none,
        .timeout = options.timeout,
        .diagnostics = options.diagnostics,
    });
    defer response.deinit(io);
    var out = try readSecret(gpa, io, &response, limit.raw());
    errdefer out.deinit(gpa);
    var nonce: ?errors.Text(256) = null;
    if (response.headers.get("dpop-nonce")) |n| if (n.len <= 256) {
        nonce = .init(n);
    };
    return .{ .status = @backingInt(response.status), .body = out, .dpop_nonce = nonce, .gpa = gpa };
}

/// The body into wiped memory: grown by doubling, each old buffer wiped as
/// it is left.
fn readSecret(gpa: std.mem.Allocator, io: std.Io, response: *uplink.Response, limit: usize) Error!aegis.SecretBytes {
    var out = aegis.SecretBytes.init(gpa, @min(limit, 4096)) catch return error.OutOfMemory;
    errdefer out.deinit(gpa);
    const reader = response.reader(io);
    while (true) {
        if (out.len() == out.capacity()) {
            if (out.capacity() >= limit) {
                // Full at the bound: one byte more is too much.
                var probe: [1]u8 = undefined;
                const n = reader.readSliceShort(&probe) catch return readFailure(response);
                if (n == 0) return out;
                return error.TooLarge;
            }
            out.reserve(gpa, @min(limit, out.capacity() * 2)) catch return error.OutOfMemory;
        }
        const at = out.len();
        // unreachable: within the capacity just checked
        out.resizeWithinCapacity(out.capacity()) catch unreachable;
        const n = reader.readSliceShort(out.exposeMut()[at..]) catch return readFailure(response);
        // unreachable: shrinking within the capacity
        out.resizeWithinCapacity(at + n) catch unreachable;
        // A short read is the body's end.
        if (at + n < out.capacity()) return out;
    }
}

fn readFailure(response: *const uplink.Response) Error {
    return switch (response.failure()) {
        error.TimedOut => error.TimedOut,
        error.Canceled => error.Canceled,
        error.TlsFailed, error.ClientCertificateRejected => error.TlsFailed,
        error.ConnectionFailed, error.HttpProtocolError, error.BadContentEncoding, error.BodyIncomplete => error.ConnectionFailed,
    };
}

fn send(http: *uplink.Client, io: std.Io, request: uplink.Request) Error!uplink.Response {
    return http.send(io, request) catch |err| switch (err) {
        error.OutOfMemory => error.OutOfMemory,
        error.TimedOut => error.TimedOut,
        error.Canceled => error.Canceled,
        error.TlsFailed, error.ClientCertificateRejected, error.ClientCertificateSchemeUnsupported, error.CertificateBundleUnreadable => error.TlsFailed,
        error.InvalidUrl, error.UnsupportedScheme => error.InvalidEndpoint,
        else => error.ConnectionFailed,
    };
}
