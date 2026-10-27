//! Token exchange (RFC 8693): one token given to an authorization server for
//! another. The request is a grant like any other (`token.Grant`, written by
//! `token.request`); this is what it carries and how the answer is read.
const std = @import("std");
const aegis = @import("aegis");
const strand = @import("strand");
const errors = @import("errors.zig");
const Scratch = @import("scratch.zig").Scratch;

/// The grant type of a token exchange.
pub const grant_type = "urn:ietf:params:oauth:grant-type:token-exchange";

/// Token type identifiers (RFC 8693 §3), and the ID-JAG's
/// (draft-ietf-oauth-identity-assertion-authz-grant §3).
pub const token_type = struct {
    pub const access_token = "urn:ietf:params:oauth:token-type:access_token";
    pub const refresh_token = "urn:ietf:params:oauth:token-type:refresh_token";
    pub const id_token = "urn:ietf:params:oauth:token-type:id_token";
    pub const saml1 = "urn:ietf:params:oauth:token-type:saml1";
    pub const saml2 = "urn:ietf:params:oauth:token-type:saml2";
    pub const jwt = "urn:ietf:params:oauth:token-type:jwt";
    pub const id_jag = "urn:ietf:params:oauth:token-type:id-jag";
};

/// What a token exchange asks (RFC 8693 §2.1). RFC 8707's `resource` goes
/// in the request's options, as for every grant.
pub const Request = struct {
    /// The token given: who the new one is for.
    subject_token: []const u8,
    /// Its type: one of `token_type`'s, or another the server knows.
    subject_token_type: []const u8,
    /// The type wanted back; the server's choice when null.
    requested_token_type: ?[]const u8 = null,
    /// The logical name of the service the new token is for: an
    /// authorization server's issuer for an ID-JAG.
    audience: ?[]const u8 = null,
    /// Space-separated.
    scope: ?[]const u8 = null,
};

/// The token an exchange issued, owned. The token is a secret: it lives in
/// memory `deinit` wipes. A refresh token the answer carries is not kept:
/// nothing here refreshes an exchanged token (the ID-JAG profile asks that
/// none be issued), so it is wiped with the rest of what was read.
pub const Issued = struct {
    /// The answer's `access_token`: the issued token, an access token or
    /// not (RFC 8693 §2.2.1).
    token: []const u8,
    /// Its type identifier.
    issued_token_type: []const u8,
    /// How it is used: `Bearer`, or `N_A` for a token that is not an access
    /// token (an ID-JAG).
    token_type: []const u8,
    /// When it expires, in seconds since the epoch, from `expires_in`.
    expires_at: ?i64 = null,
    /// The scope it carries, space-separated, when the answer names one.
    scope: ?[]const u8 = null,
    /// Private: holds every string above.
    storage: aegis.SecretBytes,
    /// What the secret bytes were allocated with, which frees them.
    gpa: std.mem.Allocator,

    pub fn deinit(i: *Issued) void {
        i.storage.deinit(i.gpa);
        i.* = undefined;
    }
};

/// The server's answer.
pub const Response = union(enum) {
    issued: Issued,
    refused: errors.ErrorResponse,
};

pub const ReadOptions = struct {
    /// The moment the response arrived: `expires_in` counts from it.
    now: std.Io.Timestamp,
    max_bytes: aegis.units.Bytes(usize) = .literal("64KiB"),
};

pub const ReadError = error{
    TooLarge,
    /// A success that is not an exchange's answer: not a JSON object, an
    /// empty token, a required member missing, a member of the wrong type
    /// or twice.
    InvalidResponse,
    /// Neither a success nor an OAuth error body.
    UnexpectedStatus,
} || std.mem.Allocator.Error;

const Wire = struct {
    access_token: []const u8,
    issued_token_type: []const u8,
    token_type: []const u8,
    expires_in: ?u63 = null,
    scope: ?[]const u8 = null,
};

/// Reads a token exchange's answer: a 2xx as the issued token (RFC 8693
/// §2.2.1), any other status as the server's error (§2.2.2) when the body is
/// one.
pub fn readResponse(gpa: std.mem.Allocator, status: u16, body: []const u8, options: ReadOptions) ReadError!Response {
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
    if (wire.access_token.len == 0 or wire.issued_token_type.len == 0 or wire.token_type.len == 0) return error.InvalidResponse;
    const total = wire.access_token.len + wire.issued_token_type.len + wire.token_type.len + if (wire.scope) |s| s.len else 0;
    var storage = aegis.SecretBytes.init(gpa, total) catch return error.OutOfMemory;
    // unreachable: the capacity was just allocated at this length
    storage.resizeWithinCapacity(total) catch unreachable;
    const bytes = storage.exposeMut();
    var at: usize = 0;
    const strings = [_][]const u8{ wire.access_token, wire.issued_token_type, wire.token_type, wire.scope orelse "" };
    var copies: [strings.len][]const u8 = undefined;
    for (strings, &copies) |s, *copy| {
        @memcpy(bytes[at..][0..s.len], s);
        copy.* = bytes[at..][0..s.len];
        at += s.len;
    }
    const now: i64 = @intCast(@divFloor(options.now.nanoseconds, std.time.ns_per_s));
    return .{ .issued = .{
        .token = copies[0],
        .issued_token_type = copies[1],
        .token_type = copies[2],
        .expires_at = if (wire.expires_in) |seconds| now +| @as(i64, seconds) else null,
        .scope = if (wire.scope != null) copies[3] else null,
        .storage = storage,
        .gpa = gpa,
    } };
}

const testing = std.testing;

test "an exchange's answer is read: the token in wiped memory, its types, expiry and scope; a refresh token not kept" {
    var response = try readResponse(testing.allocator, 200,
        \\{"access_token":"eyJ.j\u0061g.sig","issued_token_type":"urn:ietf:params:oauth:token-type:id-jag","token_type":"N_A","expires_in":300,"scope":"a b","refresh_token":"never"}
    , .{ .now = .{ .nanoseconds = 7 * std.time.ns_per_s } });
    defer response.issued.deinit();
    const issued = &response.issued;
    try testing.expectEqualStrings("eyJ.jag.sig", issued.token);
    try testing.expectEqualStrings(token_type.id_jag, issued.issued_token_type);
    try testing.expectEqualStrings("N_A", issued.token_type);
    try testing.expectEqual(@as(?i64, 307), issued.expires_at);
    try testing.expectEqualStrings("a b", issued.scope.?);
    try testing.expect(std.mem.find(u8, issued.storage.expose(), "never") == null);
}

test "an answer that is not an exchange's is refused; an error is the server's" {
    const now: ReadOptions = .{ .now = .{ .nanoseconds = 0 } };
    try testing.expectError(error.InvalidResponse, readResponse(testing.allocator, 200, "{\"access_token\":\"a\",\"token_type\":\"N_A\"}", now));
    try testing.expectError(error.InvalidResponse, readResponse(testing.allocator, 200, "{\"access_token\":\"\",\"issued_token_type\":\"x\",\"token_type\":\"N_A\"}", now));
    try testing.expectError(error.InvalidResponse, readResponse(testing.allocator, 200, "{\"access_token\":\"a\",\"issued_token_type\":1,\"token_type\":\"N_A\"}", now));
    try testing.expectError(error.InvalidResponse, readResponse(testing.allocator, 200, "{\"access_token\":\"a\",\"access_token\":\"b\",\"issued_token_type\":\"x\",\"token_type\":\"N_A\"}", now));
    try testing.expectError(error.TooLarge, readResponse(testing.allocator, 200, "{}", .{ .now = now.now, .max_bytes = .literal("1B") }));
    try testing.expectError(error.UnexpectedStatus, readResponse(testing.allocator, 502, "<html>", now));
    const refused = try readResponse(testing.allocator, 400, "{\"error\":\"insufficient_user_authentication\",\"error_description\":\"sign in again\"}", now);
    try testing.expectEqual(errors.Code.insufficient_user_authentication, refused.refused.code);
}
