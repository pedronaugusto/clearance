//! Bearer challenges (RFC 6750 §3): a resource server's `WWW-Authenticate`
//! answer written, and read by a client, with RFC 9728's
//! `resource_metadata` (§5.1) and the scope a step-up asks for. The
//! challenge syntax itself is `uplink.wire.auth`'s.
const std = @import("std");
const wire = @import("uplink.wire");
const errors = @import("errors.zig");

/// A Bearer challenge's parameters.
pub const Bearer = struct {
    realm: ?[]const u8 = null,
    /// `invalid_request` (400), `invalid_token` (401) or
    /// `insufficient_scope` (403); null when the request had no token.
    @"error": ?errors.Code = null,
    error_description: ?[]const u8 = null,
    error_uri: ?[]const u8 = null,
    /// The scope the resource needs, space-separated.
    scope: ?[]const u8 = null,
    /// RFC 9728 §5.1: where the resource's metadata is.
    resource_metadata: ?[]const u8 = null,
};

pub const ReadError = error{
    /// A `WWW-Authenticate` value that is not a list of challenges.
    MalformedChallenge,
    OutOfMemory,
};

/// The first Bearer challenge in a response's `WWW-Authenticate` values, or
/// null when none is Bearer. Strings live in `arena`.
pub fn read(arena: std.mem.Allocator, values: []const []const u8) ReadError!?Bearer {
    for (values) |value| {
        const challenges = try wire.auth.parse(arena, value);
        for (challenges) |c| {
            if (c.scheme != .bearer) continue;
            var b: Bearer = .{
                .realm = c.param("realm"),
                .error_description = c.param("error_description"),
                .error_uri = c.param("error_uri"),
                .scope = c.param("scope"),
                .resource_metadata = c.param("resource_metadata"),
            };
            if (c.param("error")) |name| b.@"error" = errors.Code.parse(name);
            return b;
        }
    }
    return null;
}

pub const WriteError = std.Io.Writer.Error || error{
    /// A value with a `"`, a `\` or a byte outside printable ASCII, which RFC
    /// 6750 §3 does not allow in a parameter.
    InvalidValue,
    /// `error` is `other`: name a registered code.
    InvalidError,
};

/// Writes the `WWW-Authenticate` value of `challenge`: `Bearer` and its
/// parameters, quoted.
pub fn write(w: *std.Io.Writer, challenge: Bearer) WriteError!void {
    try w.writeAll("Bearer");
    var first = true;
    if (challenge.realm) |v| try param(w, &first, "realm", v);
    if (challenge.@"error") |code| {
        if (code == .other) return error.InvalidError;
        try param(w, &first, "error", @tagName(code));
    }
    if (challenge.error_description) |v| try param(w, &first, "error_description", v);
    if (challenge.error_uri) |v| try param(w, &first, "error_uri", v);
    if (challenge.scope) |v| try param(w, &first, "scope", v);
    if (challenge.resource_metadata) |v| try param(w, &first, "resource_metadata", v);
}

fn param(w: *std.Io.Writer, first: *bool, name: []const u8, value: []const u8) WriteError!void {
    for (value) |c| if (c < 0x20 or c > 0x7e or c == '"' or c == '\\') return error.InvalidValue;
    try w.writeAll(if (first.*) " " else ", ");
    first.* = false;
    try w.print("{s}=\"{s}\"", .{ name, value });
}

/// Writes the scope to ask for in a step-up: what was asked before, then
/// what the challenge needs that it lacks, each once, space-separated. The
/// grant then covers both, so a step-up never drops a scope already held.
pub fn writeStepUp(w: *std.Io.Writer, previous: ?[]const u8, needed: []const u8) std.Io.Writer.Error!void {
    var first = true;
    var it = std.mem.tokenizeScalar(u8, previous orelse "", ' ');
    while (it.next()) |s| {
        if (seenBefore(previous.?, it.index - s.len, s)) continue;
        try word(w, &first, s);
    }
    var more = std.mem.tokenizeScalar(u8, needed, ' ');
    while (more.next()) |s| {
        if (contains(previous orelse "", s) or seenBefore(needed, more.index - s.len, s)) continue;
        try word(w, &first, s);
    }
}

fn word(w: *std.Io.Writer, first: *bool, s: []const u8) std.Io.Writer.Error!void {
    if (!first.*) try w.writeByte(' ');
    first.* = false;
    try w.writeAll(s);
}

/// Whether `scope`, a space-separated list, contains `s`.
pub fn contains(scope: []const u8, s: []const u8) bool {
    var it = std.mem.tokenizeScalar(u8, scope, ' ');
    while (it.next()) |t| if (std.mem.eql(u8, t, s)) return true;
    return false;
}

fn seenBefore(list: []const u8, at: usize, s: []const u8) bool {
    return contains(list[0..at], s);
}

const testing = std.testing;

test "a Bearer challenge is read among others, its error and metadata kept" {
    var arena: std.heap.ArenaAllocator = .init(testing.allocator);
    defer arena.deinit();
    const b = (try read(arena.allocator(), &.{
        "Basic realm=\"x\"",
        "Bearer error=\"insufficient_scope\", scope=\"files:read files:write\", resource_metadata=\"https://rs.example/.well-known/oauth-protected-resource/mcp\"",
    })).?;
    try testing.expectEqual(errors.Code.insufficient_scope, b.@"error".?);
    try testing.expectEqualStrings("files:read files:write", b.scope.?);
    try testing.expectEqualStrings("https://rs.example/.well-known/oauth-protected-resource/mcp", b.resource_metadata.?);
    const bare = (try read(arena.allocator(), &.{"bearer"})).?;
    try testing.expectEqual(@as(?errors.Code, null), bare.@"error");
    try testing.expectEqual(@as(?Bearer, null), try read(arena.allocator(), &.{"Basic realm=\"x\""}));
    try testing.expectError(error.MalformedChallenge, read(arena.allocator(), &.{"Bearer error=\"x"}));
}

test "a challenge is written quoted, and refuses what it cannot quote" {
    var buffer: [256]u8 = undefined;
    var w: std.Io.Writer = .fixed(&buffer);
    try write(&w, .{ .resource_metadata = "https://rs.example/.well-known/oauth-protected-resource" });
    try testing.expectEqualStrings("Bearer resource_metadata=\"https://rs.example/.well-known/oauth-protected-resource\"", w.buffered());
    w = .fixed(&buffer);
    try write(&w, .{ .realm = "example", .@"error" = .insufficient_scope, .scope = "a b" });
    try testing.expectEqualStrings("Bearer realm=\"example\", error=\"insufficient_scope\", scope=\"a b\"", w.buffered());
    w = .fixed(&buffer);
    try write(&w, .{});
    try testing.expectEqualStrings("Bearer", w.buffered());
    try testing.expectError(error.InvalidValue, write(&w, .{ .error_description = "say \"hi\"" }));
    try testing.expectError(error.InvalidError, write(&w, .{ .@"error" = .other }));
    // What is written reads back.
    var arena: std.heap.ArenaAllocator = .init(testing.allocator);
    defer arena.deinit();
    w = .fixed(&buffer);
    try write(&w, .{ .@"error" = .invalid_token, .error_description = "expired", .resource_metadata = "https://rs.example/m" });
    const back = (try read(arena.allocator(), &.{w.buffered()})).?;
    try testing.expectEqual(errors.Code.invalid_token, back.@"error".?);
    try testing.expectEqualStrings("expired", back.error_description.?);
}

test "a step-up keeps what was asked and adds what is needed, each once" {
    var buffer: [128]u8 = undefined;
    var w: std.Io.Writer = .fixed(&buffer);
    try writeStepUp(&w, "a b", "b c c d");
    try testing.expectEqualStrings("a b c d", w.buffered());
    w = .fixed(&buffer);
    try writeStepUp(&w, null, "x  y x");
    try testing.expectEqualStrings("x y", w.buffered());
    w = .fixed(&buffer);
    try writeStepUp(&w, "a a", "");
    try testing.expectEqualStrings("a", w.buffered());
}
