//! Token revocation (RFC 7009): a client tells the authorization server it
//! is done with a token. Revoking the refresh token ends the grant, and the
//! server is to revoke its access tokens with it (§2.1), so a sign-out
//! revokes the refresh token and then forgets the store's entry. The request
//! is a form request with the client's authentication; a 200 is success,
//! whatever its body (§2.2).
const std = @import("std");
const aegis = @import("aegis");
const client_auth = @import("client_auth.zig");
const errors = @import("errors.zig");

/// What the client says the token is (§2.1): the server looks there first.
pub const Hint = enum {
    access_token,
    refresh_token,

    pub fn name(h: Hint) []const u8 {
        return @tagName(h);
    }
};

/// The revocation request for `token`, authenticated as `client` says.
pub fn request(gpa: std.mem.Allocator, io: std.Io, client: client_auth.Client, token: []const u8, hint: ?Hint, context: client_auth.Context) client_auth.Error!client_auth.FormRequest {
    if (hint) |h| return client_auth.formRequest(gpa, io, client, &.{
        .{ .name = "token", .value = token },
        .{ .name = "token_type_hint", .value = h.name() },
    }, context);
    return client_auth.formRequest(gpa, io, client, &.{.{ .name = "token", .value = token }}, context);
}

/// The revocation endpoint's answer.
pub const Response = union(enum) {
    /// The token is revoked, or was never valid: the same to the client
    /// (§2.2).
    revoked,
    /// The server refused: `unsupported_token_type`, `invalid_client`, or
    /// another error. A 503 with an error body is one too, the server's word
    /// to try later (§2.2.1); clearance does not retry.
    refused: errors.ErrorResponse,
};

pub const ReadOptions = struct {
    max_bytes: aegis.units.Bytes(usize) = .literal("64KiB"),
};

pub const ReadError = error{
    TooLarge,
    /// Neither a success nor an OAuth error body.
    UnexpectedStatus,
};

/// Reads the answer: any 2xx is the token revoked (§2.2: the body is
/// ignored), any other status the server's error when the body is one.
pub fn readResponse(status: u16, body: []const u8, options: ReadOptions) ReadError!Response {
    const limit: usize = options.max_bytes.raw();
    if (body.len > limit) return error.TooLarge;
    if (status >= 200 and status <= 299) return .revoked;
    var scratch: [1024]u8 = undefined;
    if (body.len <= 4096) if (errors.readJson(body, &scratch)) |e| return .{ .refused = e };
    return error.UnexpectedStatus;
}

const testing = std.testing;

test "RFC 7009 §2.1's request: the token, its hint, the client's credentials" {
    const context: client_auth.Context = .{ .issuer = "https://as.example", .now = .{ .nanoseconds = 0 } };
    var r = try request(testing.allocator, testing.io, .{ .id = "s6BhdRkqt3", .credentials = .{ .client_secret_basic = "7Fjfp0ZBr1KtDRbnfVdmIw" } }, "45ghiukldjahdnhzdauz/", .refresh_token, context);
    defer r.deinit();
    try testing.expectEqualStrings("token=45ghiukldjahdnhzdauz%2F&token_type_hint=refresh_token", r.body.expose());
    try testing.expectEqualStrings("Basic czZCaGRSa3F0Mzo3RmpmcDBaQnIxS3REUmJuZlZkbUl3", r.authorization.?.expose());
    var public = try request(testing.allocator, testing.io, .{ .id = "cli" }, "at", null, context);
    defer public.deinit();
    try testing.expectEqualStrings("token=at&client_id=cli", public.body.expose());
}

test "a 2xx is revoked whatever its body; another status is the server's error or unexpected" {
    try testing.expectEqual(Response.revoked, try readResponse(200, "", .{}));
    try testing.expectEqual(Response.revoked, try readResponse(200, "<html>ok</html>", .{}));
    try testing.expectEqual(Response.revoked, try readResponse(204, "", .{}));
    const refused = try readResponse(400, "{\"error\":\"unsupported_token_type\"}", .{});
    try testing.expectEqual(errors.Code.unsupported_token_type, refused.refused.code);
    const later = try readResponse(503, "{\"error\":\"temporarily_unavailable\"}", .{});
    try testing.expectEqual(errors.Code.temporarily_unavailable, later.refused.code);
    try testing.expectError(error.UnexpectedStatus, readResponse(503, "", .{}));
    try testing.expectError(error.UnexpectedStatus, readResponse(401, "{\"error\":7}", .{}));
    try testing.expectError(error.TooLarge, readResponse(200, "xx", .{ .max_bytes = .literal("1B") }));
}
