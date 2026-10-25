//! The token endpoint (RFC 6749 §3.2, §4.1.3, §4.4, §6 as OAuth 2.1 §3.2 has
//! them): the grants clearance asks for written as form requests, and the
//! answer read into a `TokenSet` or the server's error.
const std = @import("std");
const aegis = @import("aegis");
const strand = @import("strand");
const form = @import("uplink.wire").form;
const client_auth = @import("client_auth.zig");
const errors = @import("errors.zig");
const exchange = @import("exchange.zig");
const device = @import("device.zig");
const Scratch = @import("scratch.zig").Scratch;

/// What the client asks a token for.
pub const Grant = union(enum) {
    /// The code from the authorization response (OAuth 2.1 §4.1.3).
    authorization_code: struct {
        code: []const u8,
        /// The `redirect_uri` the authorization request carried.
        redirect_uri: []const u8,
        /// `Pkce.verifier`.
        code_verifier: []const u8,
    },
    /// A new access token for a refresh token (OAuth 2.1 §4.3).
    refresh_token: struct {
        refresh_token: []const u8,
        /// Space-separated; at most what was granted. Null keeps the grant's.
        scope: ?[]const u8 = null,
    },
    /// The client on its own behalf (OAuth 2.1 §4.2).
    client_credentials: struct {
        scope: ?[]const u8 = null,
    },
    /// One token for another (RFC 8693 §2.1): an identity provider's for an
    /// ID-JAG, in MCP's enterprise-managed authorization.
    token_exchange: exchange.Request,
    /// A JWT as the grant (RFC 7523 §2.1): an ID-JAG redeemed at the
    /// authorization server it names, or a workload's identity token.
    jwt_bearer: struct {
        assertion: []const u8,
        /// Space-separated. Null: what the assertion carries, or the
        /// server's default.
        scope: ?[]const u8 = null,
    },
    /// A device's code, redeemed once the person has entered its user code
    /// (RFC 8628 §3.4).
    device_code: struct {
        device_code: []const u8,
    },

    /// The grant type it is sent as.
    pub fn typeName(g: Grant) []const u8 {
        return switch (g) {
            .authorization_code => "authorization_code",
            .refresh_token => "refresh_token",
            .client_credentials => "client_credentials",
            .token_exchange => exchange.grant_type,
            .jwt_bearer => jwt_bearer_grant_type,
            .device_code => device.grant_type,
        };
    }
};

/// The grant type of a JWT used as an authorization grant (RFC 7523 §2.1).
pub const jwt_bearer_grant_type = "urn:ietf:params:oauth:grant-type:jwt-bearer";

pub const RequestOptions = struct {
    /// RFC 8707's `resource`, once each.
    resources: []const []const u8 = &.{},
    /// Any further parameters, written last.
    extra: []const form.Pair = &.{},
};

/// The token request for `grant`, authenticated as `client` says; null
/// sends no client at all (a JWT-bearer grant whose assertion is the only
/// credential, RFC 7521 §4.1).
pub fn request(gpa: std.mem.Allocator, io: std.Io, client: ?client_auth.Client, grant: Grant, options: RequestOptions, context: client_auth.Context) client_auth.Error!client_auth.FormRequest {
    var pairs: std.ArrayList(form.Pair) = .empty;
    defer pairs.deinit(gpa);
    try pairs.append(gpa, .{ .name = "grant_type", .value = grant.typeName() });
    switch (grant) {
        .authorization_code => |g| try pairs.appendSlice(gpa, &.{
            .{ .name = "code", .value = g.code },
            .{ .name = "redirect_uri", .value = g.redirect_uri },
            .{ .name = "code_verifier", .value = g.code_verifier },
        }),
        .refresh_token => |g| {
            try pairs.append(gpa, .{ .name = "refresh_token", .value = g.refresh_token });
            if (g.scope) |scope| try pairs.append(gpa, .{ .name = "scope", .value = scope });
        },
        .client_credentials => |g| if (g.scope) |scope| try pairs.append(gpa, .{ .name = "scope", .value = scope }),
        .token_exchange => |g| {
            if (g.requested_token_type) |t| try pairs.append(gpa, .{ .name = "requested_token_type", .value = t });
            try pairs.appendSlice(gpa, &.{
                .{ .name = "subject_token", .value = g.subject_token },
                .{ .name = "subject_token_type", .value = g.subject_token_type },
            });
            if (g.audience) |a| try pairs.append(gpa, .{ .name = "audience", .value = a });
            if (g.scope) |scope| try pairs.append(gpa, .{ .name = "scope", .value = scope });
        },
        .jwt_bearer => |g| {
            try pairs.append(gpa, .{ .name = "assertion", .value = g.assertion });
            if (g.scope) |scope| try pairs.append(gpa, .{ .name = "scope", .value = scope });
        },
        .device_code => |g| try pairs.append(gpa, .{ .name = "device_code", .value = g.device_code }),
    }
    for (options.resources) |resource| try pairs.append(gpa, .{ .name = "resource", .value = resource });
    try pairs.appendSlice(gpa, options.extra);
    return client_auth.formRequest(gpa, io, client, pairs.items, context);
}

/// The token types clearance uses. A response naming another is refused: a
/// client must not use a token whose type it does not understand (RFC 6749
/// §7.1).
pub const TokenType = enum {
    bearer,

    pub fn name(_: TokenType) []const u8 {
        return "Bearer";
    }
};

/// The tokens a grant gave, owned. The tokens are secrets: they live in
/// memory `deinit` wipes.
pub const TokenSet = struct {
    access_token: []const u8,
    token_type: TokenType = .bearer,
    /// When the access token expires, in seconds since the epoch: the
    /// response's `expires_in` from the moment it was read.
    expires_at: ?i64 = null,
    refresh_token: ?[]const u8 = null,
    /// The granted scope, space-separated.
    scope: ?[]const u8 = null,
    /// An OpenID Connect ID token, not yet validated.
    id_token: ?[]const u8 = null,
    /// Private: holds every string above.
    storage: aegis.SecretBytes,

    /// The members, borrowed: what `init` copies.
    pub const Fields = struct {
        access_token: []const u8,
        token_type: TokenType = .bearer,
        expires_at: ?i64 = null,
        refresh_token: ?[]const u8 = null,
        scope: ?[]const u8 = null,
        id_token: ?[]const u8 = null,
    };

    /// A set holding copies of `fields`' strings.
    pub fn init(gpa: std.mem.Allocator, values: Fields) std.mem.Allocator.Error!TokenSet {
        const strings = .{ "access_token", "refresh_token", "scope", "id_token" };
        var total: usize = 0;
        inline for (strings) |s| {
            const value: ?[]const u8 = @field(values, s);
            if (value) |v| total += v.len;
        }
        var storage = aegis.SecretBytes.init(gpa, total) catch return error.OutOfMemory;
        // unreachable: the capacity was just allocated at this length
        storage.resizeWithinCapacity(total) catch unreachable;
        var set: TokenSet = .{ .access_token = undefined, .token_type = values.token_type, .expires_at = values.expires_at, .storage = storage };
        var at: usize = 0;
        const bytes = set.storage.exposeMut();
        inline for (strings) |s| {
            const value: ?[]const u8 = @field(values, s);
            if (value) |v| {
                @memcpy(bytes[at..][0..v.len], v);
                @field(set, s) = bytes[at..][0..v.len];
                at += v.len;
            } else if (comptime !std.mem.eql(u8, s, "access_token")) {
                @field(set, s) = null;
            }
        }
        return set;
    }

    pub fn deinit(set: *TokenSet) void {
        set.storage.deinit();
        set.* = undefined;
    }

    /// The members, borrowed from the set.
    pub fn borrow(set: *const TokenSet) Fields {
        return .{
            .access_token = set.access_token,
            .token_type = set.token_type,
            .expires_at = set.expires_at,
            .refresh_token = set.refresh_token,
            .scope = set.scope,
            .id_token = set.id_token,
        };
    }

    /// Whether the access token expires before `margin` from `now` has
    /// passed: time to refresh. A token with no expiry never does.
    pub fn expiresWithin(set: *const TokenSet, now: std.Io.Timestamp, margin: aegis.units.Duration(.second, u32)) bool {
        const at = set.expires_at orelse return false;
        const seconds: i64 = @intCast(@divFloor(now.nanoseconds, std.time.ns_per_s));
        return seconds +| @as(i64, margin.raw()) >= at;
    }

    /// Writes the set as JSON, for a store that keeps it across runs. The
    /// output holds the tokens: the store keeps it as a secret.
    pub fn write(set: *const TokenSet, w: *std.Io.Writer) std.Io.Writer.Error!void {
        strand.json.write(w, Stored{
            .access_token = set.access_token,
            .token_type = set.token_type.name(),
            .expires_at = set.expires_at,
            .refresh_token = set.refresh_token,
            .scope = set.scope,
            .id_token = set.id_token,
        }, .{ .nulls = .omit }) catch |err| return switch (err) {
            error.WriteFailed => error.WriteFailed,
            // unreachable: a fixed schema of strings and an integer always writes
            else => unreachable,
        };
    }

    /// A set from what `write` wrote.
    pub fn read(gpa: std.mem.Allocator, json: []const u8) ReadError!TokenSet {
        var scratch: Scratch = undefined;
        try scratch.init(gpa, json.len);
        defer scratch.deinit();
        const stored = strand.json.parseLeaky(Stored, scratch.allocator(), json, .{ .limits = .{ .depth = 4 } }) catch return error.InvalidResponse;
        if (!std.ascii.eqlIgnoreCase(stored.token_type, "bearer")) return error.UnsupportedTokenType;
        return init(gpa, .{
            .access_token = stored.access_token,
            .expires_at = stored.expires_at,
            .refresh_token = stored.refresh_token,
            .scope = stored.scope,
            .id_token = stored.id_token,
        });
    }

    const Stored = struct {
        access_token: []const u8,
        token_type: []const u8,
        expires_at: ?i64 = null,
        refresh_token: ?[]const u8 = null,
        scope: ?[]const u8 = null,
        id_token: ?[]const u8 = null,
    };
};

/// The token endpoint's answer.
pub const Response = union(enum) {
    tokens: TokenSet,
    refused: errors.ErrorResponse,
};

pub const ReadOptions = struct {
    /// The moment the response arrived: `expires_in` counts from it.
    now: std.Io.Timestamp,
    /// The scope the request asked for: the granted scope when the response
    /// names none (RFC 6749 §5.1).
    requested_scope: ?[]const u8 = null,
    /// The refresh token a refresh spent: kept when the response brings no
    /// new one (RFC 6749 §6).
    previous_refresh_token: ?[]const u8 = null,
    max_bytes: aegis.units.Bytes(usize) = .literal("64KiB"),
};

pub const ReadError = error{
    TooLarge,
    /// A success that is not a token response: not a JSON object, no
    /// `access_token` or `token_type`, a member of the wrong type, a member
    /// twice.
    InvalidResponse,
    /// `token_type` is not `Bearer`.
    UnsupportedTokenType,
    /// Neither a success nor an OAuth error body.
    UnexpectedStatus,
} || std.mem.Allocator.Error;

const Wire = struct {
    access_token: []const u8,
    token_type: []const u8,
    expires_in: ?u63 = null,
    refresh_token: ?[]const u8 = null,
    scope: ?[]const u8 = null,
    id_token: ?[]const u8 = null,
};

/// Reads the token endpoint's answer: a 2xx as tokens (RFC 6749 §5.1), any
/// other status as the server's error (§5.2) when the body is one.
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
    if (wire.access_token.len == 0) return error.InvalidResponse;
    // Compared without case (RFC 6749 §5.1).
    if (!std.ascii.eqlIgnoreCase(wire.token_type, "bearer")) return error.UnsupportedTokenType;
    const now: i64 = @intCast(@divFloor(options.now.nanoseconds, std.time.ns_per_s));
    return .{ .tokens = try TokenSet.init(gpa, .{
        .access_token = wire.access_token,
        .expires_at = if (wire.expires_in) |seconds| now +| @as(i64, seconds) else null,
        .refresh_token = wire.refresh_token orelse options.previous_refresh_token,
        .scope = wire.scope orelse options.requested_scope,
        .id_token = wire.id_token,
    }) };
}

const testing = std.testing;
const ctx: client_auth.Context = .{ .issuer = "https://as.example", .now = .{ .nanoseconds = 0 } };

test "each grant's request" {
    var code = try request(testing.allocator, testing.io, .{ .id = "c" }, .{ .authorization_code = .{ .code = "x y", .redirect_uri = "http://127.0.0.1/cb", .code_verifier = "v" } }, .{ .resources = &.{"https://rs.example/mcp"} }, ctx);
    defer code.deinit();
    try testing.expectEqualStrings("grant_type=authorization_code&code=x+y&redirect_uri=http%3A%2F%2F127.0.0.1%2Fcb&code_verifier=v&resource=https%3A%2F%2Frs.example%2Fmcp&client_id=c", code.body.expose());
    var refresh = try request(testing.allocator, testing.io, .{ .id = "c" }, .{ .refresh_token = .{ .refresh_token = "r", .scope = "a" } }, .{}, ctx);
    defer refresh.deinit();
    try testing.expectEqualStrings("grant_type=refresh_token&refresh_token=r&scope=a&client_id=c", refresh.body.expose());
    var credentials = try request(testing.allocator, testing.io, .{ .id = "c", .credentials = .{ .client_secret_post = "s" } }, .{ .client_credentials = .{} }, .{}, ctx);
    defer credentials.deinit();
    try testing.expectEqualStrings("grant_type=client_credentials&client_id=c&client_secret=s", credentials.body.expose());
    var exchanged = try request(testing.allocator, testing.io, .{ .id = "idp-app" }, .{ .token_exchange = .{
        .subject_token = "eyJ.id.tok",
        .subject_token_type = exchange.token_type.id_token,
        .requested_token_type = exchange.token_type.id_jag,
        .audience = "https://as.example",
        .scope = "files:read",
    } }, .{ .resources = &.{"https://rs.example/mcp"} }, ctx);
    defer exchanged.deinit();
    try testing.expectEqualStrings("grant_type=urn%3Aietf%3Aparams%3Aoauth%3Agrant-type%3Atoken-exchange&requested_token_type=urn%3Aietf%3Aparams%3Aoauth%3Atoken-type%3Aid-jag&subject_token=eyJ.id.tok&subject_token_type=urn%3Aietf%3Aparams%3Aoauth%3Atoken-type%3Aid_token&audience=https%3A%2F%2Fas.example&scope=files%3Aread&resource=https%3A%2F%2Frs.example%2Fmcp&client_id=idp-app", exchanged.body.expose());
    var bearer = try request(testing.allocator, testing.io, null, .{ .jwt_bearer = .{ .assertion = "eyJ.w.s" } }, .{}, ctx);
    defer bearer.deinit();
    try testing.expectEqualStrings("grant_type=urn%3Aietf%3Aparams%3Aoauth%3Agrant-type%3Ajwt-bearer&assertion=eyJ.w.s", bearer.body.expose());
    try testing.expectEqual(@as(?aegis.SecretBytes, null), bearer.authorization);
}

test "a token response is read into a set: expiry from now, Bearer in any case, scope and refresh token carried" {
    var response = try readResponse(testing.allocator, 200, "{\"access_token\":\"2YotnFZFEjr1zCsicMWpAA\",\"token_type\":\"bearer\",\"expires_in\":3600,\"refresh_token\":\"tGzv3JOkF0XG5Qx2TlKWIA\",\"example_parameter\":\"x\"}", .{ .now = .{ .nanoseconds = 10 * std.time.ns_per_s }, .requested_scope = "a b" });
    defer response.tokens.deinit();
    const set = &response.tokens;
    try testing.expectEqualStrings("2YotnFZFEjr1zCsicMWpAA", set.access_token);
    try testing.expectEqual(@as(?i64, 3610), set.expires_at);
    try testing.expectEqualStrings("tGzv3JOkF0XG5Qx2TlKWIA", set.refresh_token.?);
    try testing.expectEqualStrings("a b", set.scope.?);
    try testing.expect(!set.expiresWithin(.{ .nanoseconds = 3000 * std.time.ns_per_s }, .literal("60s")));
    try testing.expect(set.expiresWithin(.{ .nanoseconds = 3560 * std.time.ns_per_s }, .literal("60s")));

    var refreshed = try readResponse(testing.allocator, 200, "{\"access_token\":\"n\\u0065w\",\"token_type\":\"Bearer\",\"scope\":\"a\"}", .{ .now = .{ .nanoseconds = 0 }, .requested_scope = "a b", .previous_refresh_token = "old" });
    defer refreshed.tokens.deinit();
    try testing.expectEqualStrings("new", refreshed.tokens.access_token);
    try testing.expectEqualStrings("old", refreshed.tokens.refresh_token.?);
    try testing.expectEqualStrings("a", refreshed.tokens.scope.?);
    try testing.expectEqual(@as(?i64, null), refreshed.tokens.expires_at);
}

test "a token response that is not one is refused" {
    const now: ReadOptions = .{ .now = .{ .nanoseconds = 0 } };
    try testing.expectError(error.UnsupportedTokenType, readResponse(testing.allocator, 200, "{\"access_token\":\"a\",\"token_type\":\"DPoP\"}", now));
    try testing.expectError(error.InvalidResponse, readResponse(testing.allocator, 200, "{\"access_token\":\"a\"}", now));
    try testing.expectError(error.InvalidResponse, readResponse(testing.allocator, 200, "{\"access_token\":\"\",\"token_type\":\"Bearer\"}", now));
    try testing.expectError(error.InvalidResponse, readResponse(testing.allocator, 200, "{\"access_token\":\"a\",\"token_type\":\"Bearer\",\"expires_in\":\"3600\"}", now));
    try testing.expectError(error.InvalidResponse, readResponse(testing.allocator, 200, "{\"access_token\":\"a\",\"token_type\":\"Bearer\",\"expires_in\":-1}", now));
    try testing.expectError(error.InvalidResponse, readResponse(testing.allocator, 200, "{\"access_token\":\"a\",\"access_token\":\"b\",\"token_type\":\"Bearer\"}", now));
    try testing.expectError(error.InvalidResponse, readResponse(testing.allocator, 200, "[]", now));
    try testing.expectError(error.UnexpectedStatus, readResponse(testing.allocator, 500, "<html>", now));
    const refused = try readResponse(testing.allocator, 400, "{\"error\":\"invalid_grant\"}", now);
    try testing.expectEqual(errors.Code.invalid_grant, refused.refused.code);
}

test "a set is written for a store and read back" {
    var set = try TokenSet.init(testing.allocator, .{ .access_token = "a\"b", .expires_at = 5, .scope = "s" });
    defer set.deinit();
    var out: std.Io.Writer.Allocating = .init(testing.allocator);
    defer out.deinit();
    try set.write(&out.writer);
    var back = try TokenSet.read(testing.allocator, out.written());
    defer back.deinit();
    try testing.expectEqualStrings("a\"b", back.access_token);
    try testing.expectEqual(@as(?i64, 5), back.expires_at);
    try testing.expectEqualStrings("s", back.scope.?);
    try testing.expectEqual(@as(?[]const u8, null), back.refresh_token);
}

test "a response is parsed on the stack when small and in wiped heap memory when not; escapes are read either way" {
    const now: std.Io.Timestamp = .{ .nanoseconds = 0 };
    var small = (try readResponse(testing.allocator, 200, "{\"access_token\":\"a\\u0062c\\/d\",\"token_type\":\"Bearer\"}", .{ .now = now })).tokens;
    defer small.deinit();
    try testing.expectEqualStrings("abc/d", small.access_token);

    // Past what the stack holds: the scratch comes from the allocator.
    var body: std.Io.Writer.Allocating = .init(testing.allocator);
    defer body.deinit();
    try body.writer.writeAll("{\"access_token\":\"x\\u0079");
    try body.writer.splatByteAll('z', 4096);
    try body.writer.writeAll("\",\"token_type\":\"bearer\"}");
    var large = (try readResponse(testing.allocator, 200, body.written(), .{ .now = now })).tokens;
    defer large.deinit();
    try testing.expectEqual(4098, large.access_token.len);
    try testing.expectEqualStrings("xyzz", large.access_token[0..4]);

    var failing: testing.FailingAllocator = .init(testing.allocator, .{ .fail_index = 0 });
    try testing.expectError(error.OutOfMemory, readResponse(failing.allocator(), 200, body.written(), .{ .now = now }));
}
