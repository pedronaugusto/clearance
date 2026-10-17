//! Token introspection (RFC 7662): a resource server asks the authorization
//! server what a token is. The request is a form request with the resource
//! server's own credentials; the answer is read and its claims checked by
//! type, as a JWT's are.
const std = @import("std");
const aegis = @import("aegis");
const strand = @import("strand");
const client_auth = @import("client_auth.zig");
const errors = @import("errors.zig");

/// The introspection request for `token` (RFC 7662 §2.1).
pub fn request(gpa: std.mem.Allocator, io: std.Io, client: client_auth.Client, token: []const u8, context: client_auth.Context) client_auth.Error!client_auth.FormRequest {
    return client_auth.formRequest(gpa, io, client, &.{
        .{ .name = "token", .value = token },
        .{ .name = "token_type_hint", .value = "access_token" },
    }, context);
}

/// What the authorization server says of a token (RFC 7662 §2.2). An
/// inactive token has nothing else worth reading.
pub const Introspection = struct {
    active: bool,
    scope: ?[]const u8 = null,
    client_id: ?[]const u8 = null,
    username: ?[]const u8 = null,
    token_type: ?[]const u8 = null,
    exp: ?i64 = null,
    iat: ?i64 = null,
    nbf: ?i64 = null,
    sub: ?[]const u8 = null,
    /// One audience or several, as a JWT's `aud`.
    aud: []const []const u8 = &.{},
    iss: ?[]const u8 = null,
    jti: ?[]const u8 = null,
    /// Whether the token is bound to a key (`cnf`, RFC 7800): a DPoP or mTLS
    /// token, whose binding clearance does not check.
    bound: bool = false,

    /// Whether `aud` contains `value`.
    pub fn hasAudience(i: *const Introspection, value: []const u8) bool {
        for (i.aud) |a| if (std.mem.eql(u8, a, value)) return true;
        return false;
    }
};

const Wire = struct {
    active: bool,
    scope: ?[]const u8 = null,
    client_id: ?[]const u8 = null,
    username: ?[]const u8 = null,
    token_type: ?[]const u8 = null,
    exp: ?i64 = null,
    iat: ?i64 = null,
    nbf: ?i64 = null,
    sub: ?[]const u8 = null,
    aud: ?strand.json.Raw = null,
    iss: ?[]const u8 = null,
    jti: ?[]const u8 = null,
    cnf: ?strand.json.Raw = null,
};

pub const Response = union(enum) {
    introspected: Introspection,
    refused: errors.ErrorResponse,
};

pub const ReadError = error{
    TooLarge,
    /// Not a JSON object with a boolean `active`; a member of the wrong type
    /// or twice.
    InvalidResponse,
    UnexpectedStatus,
} || std.mem.Allocator.Error;

pub const ReadOptions = struct {
    max_bytes: aegis.units.Bytes(usize) = .literal("64KiB"),
};

/// Reads the answer into `arena`, which owns the strings.
pub fn readResponse(arena: std.mem.Allocator, status: u16, body: []const u8, options: ReadOptions) ReadError!Response {
    const limit: usize = options.max_bytes.raw();
    if (body.len > limit) return error.TooLarge;
    if (status < 200 or status > 299) {
        var scratch: [1024]u8 = undefined;
        if (body.len <= 4096) if (errors.readJson(body, &scratch)) |e| return .{ .refused = e };
        return error.UnexpectedStatus;
    }
    const opts: strand.json.ParseOptions = .{ .ignore_unknown_fields = true, .limits = .{ .depth = 16 } };
    const owned = try arena.dupe(u8, body);
    const wire = strand.json.parseLeaky(Wire, arena, owned, opts) catch |err| return switch (err) {
        error.OutOfMemory => error.OutOfMemory,
        else => error.InvalidResponse,
    };
    if (!wire.active) return .{ .introspected = .{ .active = false } };
    var i: Introspection = .{ .active = true, .bound = wire.cnf != null };
    inline for (.{ "scope", "client_id", "username", "token_type", "exp", "iat", "nbf", "sub", "iss", "jti" }) |name| {
        @field(i, name) = @field(wire, name);
    }
    if (wire.aud) |raw| {
        if (raw.parse([]const u8, arena, opts)) |one| {
            i.aud = try arena.dupe([]const u8, &.{one});
        } else |_| {
            i.aud = raw.parse([]const []const u8, arena, opts) catch return error.InvalidResponse;
        }
    }
    return .{ .introspected = i };
}

const testing = std.testing;

test "RFC 7662 §2.2's answer is read, its audience one or several" {
    var arena: std.heap.ArenaAllocator = .init(testing.allocator);
    defer arena.deinit();
    const a = arena.allocator();
    const r = try readResponse(a, 200,
        \\{"active":true,"client_id":"l238j323ds-23ij4","username":"jdoe","scope":"read write dolphin","sub":"Z5O3upPC88QrAjx00dis",
        \\"aud":"https://protected.example.net/resource","iss":"https://server.example.com/","exp":1419356238,"iat":1419350238,"extension_field":"twenty-seven"}
    , .{});
    const i = r.introspected;
    try testing.expect(i.active);
    try testing.expectEqualStrings("read write dolphin", i.scope.?);
    try testing.expect(i.hasAudience("https://protected.example.net/resource"));
    try testing.expectEqual(@as(?i64, 1419356238), i.exp);
    try testing.expect(!i.bound);
    const several = try readResponse(a, 200, "{\"active\":true,\"aud\":[\"a\",\"b\"],\"cnf\":{\"jkt\":\"x\"}}", .{});
    try testing.expect(several.introspected.hasAudience("b"));
    try testing.expect(several.introspected.bound);
    const inactive = try readResponse(a, 200, "{\"active\":false,\"scope\":\"x\"}", .{});
    try testing.expect(!inactive.introspected.active);
    try testing.expectEqual(@as(?[]const u8, null), inactive.introspected.scope);
}

test "an answer of the wrong shape is refused" {
    var arena: std.heap.ArenaAllocator = .init(testing.allocator);
    defer arena.deinit();
    const a = arena.allocator();
    try testing.expectError(error.InvalidResponse, readResponse(a, 200, "{\"active\":\"true\"}", .{}));
    try testing.expectError(error.InvalidResponse, readResponse(a, 200, "{\"scope\":\"x\"}", .{}));
    try testing.expectError(error.InvalidResponse, readResponse(a, 200, "{\"active\":true,\"exp\":\"1\"}", .{}));
    try testing.expectError(error.InvalidResponse, readResponse(a, 200, "{\"active\":true,\"aud\":[1]}", .{}));
    try testing.expectError(error.InvalidResponse, readResponse(a, 200, "{\"active\":true,\"active\":false}", .{}));
    const refused = try readResponse(a, 401, "{\"error\":\"invalid_client\"}", .{});
    try testing.expectEqual(errors.Code.invalid_client, refused.refused.code);
}

test "the request carries the token and the resource server's credentials" {
    var r = try request(testing.allocator, testing.io, .{ .id = "rs", .credentials = .{ .client_secret_basic = "pw" } }, "mF_9.B5f-4.1JqM", .{ .issuer = "https://as.example", .now = .{ .nanoseconds = 0 } });
    defer r.deinit();
    try testing.expectEqualStrings("token=mF_9.B5f-4.1JqM&token_type_hint=access_token", r.body.expose());
    try testing.expect(r.authorization != null);
}
