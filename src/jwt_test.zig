const std = @import("std");
const jwt = @import("jwt.zig");
const jws = @import("jws.zig");
const Key = @import("Key.zig");

const gpa = std.testing.allocator;
const secret: [32]u8 = @splat(0x42);
const keys = [_]Key{Key.hmac(&secret)};
const now: std.Io.Timestamp = .{ .nanoseconds = 1_700_000_000 * std.time.ns_per_s };

/// A token over `claims` (JSON text), signed with the test secret.
fn token(out: *std.Io.Writer.Allocating, claims: []const u8, typ: ?[]const u8) !void {
    out.clearRetainingCapacity();
    try jws.sign(gpa, std.testing.io, &out.writer, .{ .typ = typ }, claims, .{ .hmac = .{ .alg = .hs256, .secret = &secret } });
}

fn check(claims: []const u8, validation: jwt.Validation) jwt.VerifyError!void {
    var out: std.Io.Writer.Allocating = .init(gpa);
    defer out.deinit();
    token(&out, claims, "JWT") catch unreachable;
    var scratch: [4096]u8 = undefined;
    _ = try jwt.verify(void, out.written(), &keys, validation, now, &scratch);
}

const base: jwt.Validation = .{ .algorithms = &.{.hs256} };

test "the time claims, with leeway" {
    try check("{\"exp\":1700000001}", base);
    try std.testing.expectError(error.Expired, check("{\"exp\":1700000000}", base));
    try check("{\"exp\":1699999990}", .{ .algorithms = &.{.hs256}, .leeway = .literal("11s") });
    try std.testing.expectError(error.NotYetValid, check("{\"exp\":1800000000,\"nbf\":1700000001}", base));
    try check("{\"exp\":1800000000,\"nbf\":1700000001}", .{ .algorithms = &.{.hs256}, .leeway = .literal("1s") });
    try std.testing.expectError(error.MissingClaim, check("{}", base));
    try check("{}", .{ .algorithms = &.{.hs256}, .required = .{ .exp = false } });
    // A fraction of a second is allowed and dropped toward the past (RFC 7519 2).
    try check("{\"exp\":1700000000.5e0}", .{ .algorithms = &.{.hs256}, .leeway = .literal("1s") });
    try std.testing.expectError(error.TooOld, check("{\"exp\":1800000000,\"iat\":1699990000}", .{ .algorithms = &.{.hs256}, .max_age = .literal("1h") }));
    try check("{\"exp\":1800000000,\"iat\":1699999000}", .{ .algorithms = &.{.hs256}, .max_age = .literal("1h") });
}

test "a registered claim of the wrong type refuses the token, never reads as absent (jsonwebtoken CVE-2026-25537)" {
    const relaxed: jwt.Validation = .{ .algorithms = &.{.hs256}, .required = .{ .exp = false } };
    try std.testing.expectError(error.InvalidClaims, check("{\"nbf\":\"99999999999\"}", relaxed));
    try std.testing.expectError(error.InvalidClaims, check("{\"exp\":\"1800000000\"}", relaxed));
    try std.testing.expectError(error.InvalidClaims, check("{\"exp\":null}", relaxed));
    try std.testing.expectError(error.InvalidClaims, check("{\"exp\":true}", relaxed));
    try std.testing.expectError(error.InvalidClaims, check("{\"exp\":1e400}", relaxed));
    try std.testing.expectError(error.InvalidClaims, check("{\"iss\":7}", relaxed));
    try std.testing.expectError(error.InvalidClaims, check("{\"aud\":null}", relaxed));
    try std.testing.expectError(error.InvalidClaims, check("{\"aud\":[\"a\",1]}", relaxed));
    try std.testing.expectError(error.InvalidClaims, check("[1]", relaxed));
    // A claim given twice is refused, not read as either (strand's strict parse).
    try std.testing.expectError(error.InvalidClaims, check("{\"exp\":1800000000,\"exp\":1}", base));
}

test "issuer, subject and audience, one audience or several (jwt-go CVE-2020-26160)" {
    const v: jwt.Validation = .{ .algorithms = &.{.hs256}, .issuer = "https://as.example", .audience = "api", .subject = "u1" };
    try check("{\"exp\":1800000000,\"iss\":\"https://as.example\",\"aud\":\"api\",\"sub\":\"u1\"}", v);
    try check("{\"exp\":1800000000,\"iss\":\"https://as.example\",\"aud\":[\"other\",\"api\"],\"sub\":\"u1\"}", v);
    try std.testing.expectError(error.WrongAudience, check("{\"exp\":1800000000,\"iss\":\"https://as.example\",\"aud\":[\"other\"],\"sub\":\"u1\"}", v));
    try std.testing.expectError(error.WrongAudience, check("{\"exp\":1800000000,\"iss\":\"https://as.example\",\"aud\":[],\"sub\":\"u1\"}", v));
    try std.testing.expectError(error.WrongIssuer, check("{\"exp\":1800000000,\"iss\":\"https://as.example/\",\"aud\":\"api\",\"sub\":\"u1\"}", v));
    try std.testing.expectError(error.WrongSubject, check("{\"exp\":1800000000,\"iss\":\"https://as.example\",\"aud\":\"api\",\"sub\":\"u2\"}", v));
    try std.testing.expectError(error.MissingClaim, check("{\"exp\":1800000000,\"aud\":\"api\",\"sub\":\"u1\"}", v));
    // A token for some audience, checked by a verifier that asked about none.
    try std.testing.expectError(error.WrongAudience, check("{\"exp\":1800000000,\"aud\":\"api\"}", base));
}

test "explicit typing: at+jwt with or without application/, any case" {
    var out: std.Io.Writer.Allocating = .init(gpa);
    defer out.deinit();
    var scratch: [4096]u8 = undefined;
    const v: jwt.Validation = .{ .algorithms = &.{.hs256}, .typ = "at+jwt" };
    try token(&out, "{\"exp\":1800000000}", "application/AT+JWT");
    _ = try jwt.verify(void, out.written(), &keys, v, now, &scratch);
    try token(&out, "{\"exp\":1800000000}", "JWT");
    try std.testing.expectError(error.WrongType, jwt.verify(void, out.written(), &keys, v, now, &scratch));
    try token(&out, "{\"exp\":1800000000}", null);
    try std.testing.expectError(error.WrongType, jwt.verify(void, out.written(), &keys, v, now, &scratch));
}

test "custom claims read into the caller's type; a claims type that does not fit refuses" {
    const Claims = struct { scope: []const u8, admin: bool = false };
    var out: std.Io.Writer.Allocating = .init(gpa);
    defer out.deinit();
    try jwt.sign(gpa, std.testing.io, &out.writer, .{}, .{ .exp = @as(i64, 1800000000), .scope = "read write", .admin = true }, .{ .hmac = .{ .alg = .hs256, .secret = &secret } });
    var scratch: [4096]u8 = undefined;
    var diagnostics: jws.Diagnostics = .{};
    const verified = try jwt.verify(Claims, out.written(), &keys, .{ .algorithms = &.{.hs256}, .diagnostics = &diagnostics }, now, &scratch);
    try std.testing.expectEqualStrings("read write", verified.claims.scope);
    try std.testing.expect(verified.claims.admin);
    try std.testing.expectEqual(@as(i64, 1800000000), verified.registered.exp.?);
    try std.testing.expectEqualStrings("JWT", verified.header.typ.?);
    const Wrong = struct { scope: u32 };
    try std.testing.expectError(error.InvalidClaims, jwt.verify(Wrong, out.written(), &keys, .{ .algorithms = &.{.hs256}, .diagnostics = &diagnostics }, now, &scratch));
    try std.testing.expectEqual(jws.Check.claims, diagnostics.check);
}
