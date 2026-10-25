//! An OAuth error response (RFC 6749 §4.1.2.1, §5.2; RFC 6750 §3; RFC 7591
//! §3.2.2) as a value: what the server said, kept whole, never folded into a
//! Zig error name. It holds its text inline, so it needs no owner.
const std = @import("std");
const strand = @import("strand");

/// The registered codes, and `other` for any name the server coins.
pub const Code = enum {
    invalid_request,
    invalid_client,
    invalid_grant,
    unauthorized_client,
    unsupported_grant_type,
    invalid_scope,
    access_denied,
    unsupported_response_type,
    server_error,
    temporarily_unavailable,
    /// RFC 6750 §3.1: a resource server's answers.
    invalid_token,
    insufficient_scope,
    /// RFC 7591 §3.2.2: a registration's.
    invalid_redirect_uri,
    invalid_client_metadata,
    invalid_software_statement,
    unapproved_software_statement,
    /// RFC 8707 §2: a resource the server does not serve, or will not
    /// issue for.
    invalid_target,
    /// RFC 9470 §3: the user's authentication is not enough; a new sign-in
    /// is due. An identity provider answers a token exchange with it.
    insufficient_user_authentication,
    /// RFC 8628 §3.5: a device's token request before the person has
    /// finished (`authorization_pending`), too soon after the last
    /// (`slow_down`: wait five seconds more), or after the codes expired.
    authorization_pending,
    slow_down,
    expired_token,
    other,

    pub fn parse(name: []const u8) Code {
        inline for (comptime std.enums.values(Code)) |code| {
            if (code != .other and std.mem.eql(u8, name, @tagName(code))) return code;
        }
        return .other;
    }
};

/// Text of at most `capacity` bytes, kept inline. Longer text is cut: what a
/// peer writes here is for a log, and a log does not need a megabyte of it.
pub fn Text(comptime capacity: usize) type {
    return struct {
        bytes: [capacity]u8 = undefined,
        len: u16 = 0,
        /// Whether the text was longer than `capacity` and cut.
        cut: bool = false,

        const Self = @This();

        pub fn init(text: []const u8) Self {
            // `set` writes every field; a literal would zero the bytes first.
            var t: Self = undefined;
            t.set(text);
            return t;
        }

        pub fn set(t: *Self, text: []const u8) void {
            const n = @min(text.len, capacity);
            @memcpy(t.bytes[0..n], text[0..n]);
            t.len = @intCast(n);
            t.cut = text.len > capacity;
        }

        pub fn slice(t: *const Self) []const u8 {
            return t.bytes[0..t.len];
        }
    };
}

/// What the server answered instead of what was asked.
pub const ErrorResponse = struct {
    code: Code,
    /// The `error` value as written: the name of an `other` code.
    name: Text(64) = .{},
    description: Text(256) = .{},
    uri: Text(256) = .{},

    pub fn format(e: ErrorResponse, w: *std.Io.Writer) std.Io.Writer.Error!void {
        try w.writeAll(e.name.slice());
        if (e.description.len != 0) try w.print(": {s}", .{e.description.slice()});
    }
};

const Wire = struct {
    @"error": []const u8,
    error_description: ?[]const u8 = null,
    error_uri: ?[]const u8 = null,
};

/// The JSON error body of a token, registration or introspection endpoint
/// (RFC 6749 §5.2), or null when the body is not one: an `error` string is
/// what makes it one. `scratch` holds what unescaping takes; a body longer
/// than it is refused.
pub fn readJson(body: []const u8, scratch: []u8) ?ErrorResponse {
    var fixed: std.heap.FixedBufferAllocator = .init(scratch);
    const wire = strand.json.parseLeaky(Wire, fixed.allocator(), body, .{
        .ignore_unknown_fields = true,
        .limits = .{ .depth = 8 },
    }) catch return null;
    return fromParts(wire.@"error", wire.error_description, wire.error_uri);
}

/// An error response from its three parts, as read.
pub fn fromParts(name: []const u8, description: ?[]const u8, uri: ?[]const u8) ?ErrorResponse {
    if (name.len == 0) return null;
    return .{
        .code = Code.parse(name),
        .name = .init(name),
        .description = .init(description orelse ""),
        .uri = .init(uri orelse ""),
    };
}

test "an error body is read whole, its code named or kept as written" {
    var scratch: [512]u8 = undefined;
    const e = readJson("{\"error\":\"invalid_grant\",\"error_description\":\"code \\\"used\\\"\",\"x\":1}", &scratch).?;
    try std.testing.expectEqual(Code.invalid_grant, e.code);
    try std.testing.expectEqualStrings("code \"used\"", e.description.slice());
    const other = readJson("{\"error\":\"quota_exceeded\"}", &scratch).?;
    try std.testing.expectEqual(Code.other, other.code);
    try std.testing.expectEqualStrings("quota_exceeded", other.name.slice());
    try std.testing.expectEqual(@as(?ErrorResponse, null), readJson("{\"access_token\":\"x\"}", &scratch));
    try std.testing.expectEqual(@as(?ErrorResponse, null), readJson("{\"error\":\"\"}", &scratch));
    const long: [300]u8 = @splat('a');
    const cut = fromParts("x", &long, null).?;
    try std.testing.expect(cut.description.cut);
    try std.testing.expectEqual(@as(usize, 256), cut.description.slice().len);
}
