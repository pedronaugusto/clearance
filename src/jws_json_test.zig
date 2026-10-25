//! JWS in the JSON serializations (RFC 7515 §7.2) and unencoded payloads
//! (RFC 7797): the JOSE cookbook's (RFC 7520 §4.4 to §4.8) and RFC 7797
//! §4's examples, byte for byte where the signature is deterministic.
const std = @import("std");
const jws = @import("jws.zig");
const jwk = @import("jwk.zig");
const base64url = @import("base64url.zig");
const cloak = @import("cloak");

const gpa = std.testing.allocator;
const testing = std.testing;

const cookbook_payload = "It\xe2\x80\x99s a dangerous business, Frodo, going out your door. You step onto the road, and if you don't keep your feet, there\xe2\x80\x99s no knowing where you might be swept off to.";

/// A cookbook file's key (public members only) and its outputs as text.
const Vector = struct {
    set: jwk.KeySet,
    compact: ?[]u8,
    json: ?[]u8,
    json_flat: ?[]u8,

    fn load(comptime file: []const u8) !Vector {
        const Doc = struct { input: struct { key: std.json.Value }, output: struct { compact: ?[]const u8 = null, json: ?std.json.Value = null, json_flat: ?std.json.Value = null } };
        const doc = try std.json.parseFromSlice(Doc, gpa, @embedFile("testing/vectors/rfc7520/" ++ file), .{ .ignore_unknown_fields = true });
        defer doc.deinit();
        var key = doc.value.input.key.object;
        inline for (.{ "d", "p", "q", "dp", "dq", "qi" }) |private| _ = key.swapRemove(private);
        const text = try std.json.Stringify.valueAlloc(gpa, std.json.Value{ .object = key }, .{});
        defer gpa.free(text);
        var v: Vector = .{ .set = try jwk.KeySet.parse(gpa, text, .{ .secrets = true }), .compact = null, .json = null, .json_flat = null };
        errdefer v.deinit();
        if (doc.value.output.compact) |c| v.compact = try gpa.dupe(u8, c);
        if (doc.value.output.json) |j| v.json = try std.json.Stringify.valueAlloc(gpa, j, .{});
        if (doc.value.output.json_flat) |j| v.json_flat = try std.json.Stringify.valueAlloc(gpa, j, .{});
        return v;
    }

    fn deinit(v: *Vector) void {
        v.set.deinit();
        inline for (.{ "compact", "json", "json_flat" }) |name| if (@field(v, name)) |t| gpa.free(t);
    }
};

/// The cookbook's HMAC key (§3.5), as a signer.
fn hmacSigner(set: *const jwk.KeySet) jws.Signer {
    return .{ .hmac = .{ .alg = .hs256, .secret = set.keys[0].material.hmac } };
}

test "RFC 7520 4.4: HS256 in both JSON serializations verifies, and is written byte for byte" {
    var v = try Vector.load("4_4.hmac-sha2_integrity_protection.json");
    defer v.deinit();
    const scratch = try gpa.alloc(u8, jws.scratchLengthJson(v.json.?.len, 0));
    defer gpa.free(scratch);
    for ([_][]const u8{ v.json.?, v.json_flat.? }) |document| {
        const verified = try jws.verifyJson(document, v.set.keys, .{ .algorithms = &.{.hs256} }, scratch);
        try testing.expectEqualStrings(cookbook_payload, verified.payload);
        try testing.expectEqualStrings("018c0ae5-4d9b-471b-bfd6-eef314bc7037", verified.header.kid.?);
        try testing.expectEqual(@as(usize, 0), verified.index);
    }
    const header: jws.SignHeader = .{ .kid = "018c0ae5-4d9b-471b-bfd6-eef314bc7037" };
    var out: std.Io.Writer.Allocating = .init(gpa);
    defer out.deinit();
    try jws.signJson(gpa, testing.io, &out.writer, .flattened, cookbook_payload, &.{.{ .signer = hmacSigner(&v.set), .header = header }}, .{});
    try testing.expectEqualStrings(v.json_flat.?, out.written());
    out.clearRetainingCapacity();
    try jws.signJson(gpa, testing.io, &out.writer, .general, cookbook_payload, &.{.{ .signer = hmacSigner(&v.set), .header = header }}, .{});
    try testing.expectEqualStrings(v.json.?, out.written());
}

test "RFC 7520 4.5: a detached payload, compact and JSON, verifies with the payload given and is written byte for byte" {
    var v = try Vector.load("4_5.signature_with_detached_content.json");
    defer v.deinit();
    const scratch = try gpa.alloc(u8, jws.scratchLengthJson(v.json.?.len, cookbook_payload.len));
    defer gpa.free(scratch);
    const options: jws.Options = .{ .algorithms = &.{.hs256}, .detached_payload = cookbook_payload };
    try testing.expectEqualStrings(cookbook_payload, (try jws.verify(v.compact.?, v.set.keys, options, scratch)).payload);
    for ([_][]const u8{ v.json.?, v.json_flat.? }) |document| _ = try jws.verifyJson(document, v.set.keys, options, scratch);
    // Without the payload it is not a token; another payload is not this one's.
    try testing.expectError(error.InvalidSignature, jws.verify(v.compact.?, v.set.keys, .{ .algorithms = &.{.hs256} }, scratch));
    try testing.expectError(error.InvalidSignature, jws.verify(v.compact.?, v.set.keys, .{ .algorithms = &.{.hs256}, .detached_payload = "another" }, scratch));
    try testing.expectError(error.Malformed, jws.verifyJson(v.json_flat.?, v.set.keys, .{ .algorithms = &.{.hs256} }, scratch));
    var out: std.Io.Writer.Allocating = .init(gpa);
    defer out.deinit();
    const header: jws.SignHeader = .{ .kid = "018c0ae5-4d9b-471b-bfd6-eef314bc7037" };
    try jws.signCompact(gpa, testing.io, &out.writer, header, cookbook_payload, hmacSigner(&v.set), .{ .detached = true });
    try testing.expectEqualStrings(v.compact.?, out.written());
    out.clearRetainingCapacity();
    try jws.signJson(gpa, testing.io, &out.writer, .flattened, cookbook_payload, &.{.{ .signer = hmacSigner(&v.set), .header = header }}, .{ .detached = true });
    try testing.expectEqualStrings(v.json_flat.?, out.written());
}

test "RFC 7520 4.6: the kid in the unprotected header chooses the key; the protected header alone is trusted" {
    var v = try Vector.load("4_6.protecting_specific_header_fields.json");
    defer v.deinit();
    const scratch = try gpa.alloc(u8, jws.scratchLengthJson(v.json.?.len, 0));
    defer gpa.free(scratch);
    for ([_][]const u8{ v.json.?, v.json_flat.? }) |document| {
        const verified = try jws.verifyJson(document, v.set.keys, .{ .algorithms = &.{.hs256} }, scratch);
        try testing.expectEqualStrings(cookbook_payload, verified.payload);
        try testing.expectEqualStrings("{\"alg\":\"HS256\"}", verified.protected);
        try testing.expect(std.mem.find(u8, verified.unprotected.?, "018c0ae5-4d9b-471b-bfd6-eef314bc7037") != null);
    }
    var out: std.Io.Writer.Allocating = .init(gpa);
    defer out.deinit();
    try jws.signJson(gpa, testing.io, &out.writer, .flattened, cookbook_payload, &.{.{ .signer = hmacSigner(&v.set), .unprotected = "{\"kid\":\"018c0ae5-4d9b-471b-bfd6-eef314bc7037\"}" }}, .{});
    try testing.expectEqualStrings(v.json_flat.?, out.written());
}

test "RFC 7520 4.7: alg in the unprotected header alone is refused, by decision" {
    var v = try Vector.load("4_7.protecting_content_only.json");
    defer v.deinit();
    const scratch = try gpa.alloc(u8, jws.scratchLengthJson(v.json.?.len, 0));
    defer gpa.free(scratch);
    // The cookbook's own valid example: an unprotected `alg` could be
    // changed in flight, so clearance never verifies one (panva jose agrees).
    for ([_][]const u8{ v.json.?, v.json_flat.? }) |document| {
        try testing.expectError(error.InvalidHeader, jws.verifyJson(document, v.set.keys, .{ .algorithms = &.{.hs256} }, scratch));
    }
}

test "RFC 7520 4.8: three signatures, each verified by its own key, the one with an unprotected alg never" {
    const Doc = struct { input: struct { key: []const std.json.Value }, output: struct { json: std.json.Value } };
    const doc = try std.json.parseFromSlice(Doc, gpa, @embedFile("testing/vectors/rfc7520/4_8.multiple_signatures.json"), .{ .ignore_unknown_fields = true });
    defer doc.deinit();
    const document = try std.json.Stringify.valueAlloc(gpa, doc.value.output.json, .{});
    defer gpa.free(document);
    const scratch = try gpa.alloc(u8, jws.scratchLengthJson(document.len, 0));
    defer gpa.free(scratch);
    for (doc.value.input.key, 0..) |key_value, i| {
        var key = key_value.object;
        inline for (.{ "d", "p", "q", "dp", "dq", "qi" }) |private| _ = key.swapRemove(private);
        const text = try std.json.Stringify.valueAlloc(gpa, std.json.Value{ .object = key }, .{});
        defer gpa.free(text);
        var set = try jwk.KeySet.parse(gpa, text, .{ .secrets = true });
        defer set.deinit();
        const options: jws.Options = .{ .algorithms = &.{ .rs256, .hs256, .es256 } };
        switch (i) {
            0 => try testing.expectEqual(@as(usize, 0), (try jws.verifyJson(document, set.keys, options, scratch)).index),
            // The ES512 signature names its alg in the unprotected header.
            1 => try testing.expectError(error.InvalidHeader, jws.verifyJson(document, set.keys, options, scratch)),
            else => try testing.expectEqual(@as(usize, 2), (try jws.verifyJson(document, set.keys, options, scratch)).index),
        }
    }
}

/// RFC 7515 A.1's HMAC key, RFC 7797 §4's.
const a1_key = "{\"kty\":\"oct\",\"k\":\"AyM1SysPpbyDfgZld3umj1qzKObwVMkoqQ-EstJQLr_T-1qS0gZH75aKtMN3Yj0iPS4hcgUuTwjAzZr1Z9CAow\"}";

test "RFC 7797 4: the unencoded payload $.02, detached in the compact form, inline in JSON, byte for byte" {
    var set = try jwk.KeySet.parse(gpa, a1_key, .{ .secrets = true });
    defer set.deinit();
    const signer: jws.Signer = .{ .hmac = .{ .alg = .hs256, .secret = set.keys[0].material.hmac } };
    var scratch: [4096]u8 = undefined;
    // §4.1: the same payload encoded.
    const encoded = "eyJhbGciOiJIUzI1NiJ9.JC4wMg.5mvfOroL-g7HyqJoozehmsaqmvTYGEq5jTI1gVvoEoQ";
    try testing.expectEqualStrings("$.02", (try jws.verify(encoded, set.keys, .{ .algorithms = &.{.hs256} }, &scratch)).payload);
    // §4.2.
    const compact = "eyJhbGciOiJIUzI1NiIsImI2NCI6ZmFsc2UsImNyaXQiOlsiYjY0Il19..A5dxf2s96_n5FLueVuW1Z_vh161FwXZC4YLPff6dmDY";
    const flat = "{\"payload\":\"$.02\",\"protected\":\"eyJhbGciOiJIUzI1NiIsImI2NCI6ZmFsc2UsImNyaXQiOlsiYjY0Il19\",\"signature\":\"A5dxf2s96_n5FLueVuW1Z_vh161FwXZC4YLPff6dmDY\"}";
    const unencoded: jws.Options = .{ .algorithms = &.{.hs256}, .unencoded = true, .detached_payload = "$.02" };
    try testing.expectEqualStrings("$.02", (try jws.verify(compact, set.keys, unencoded, &scratch)).payload);
    const json_scratch = try gpa.alloc(u8, jws.scratchLengthJson(flat.len, 0));
    defer gpa.free(json_scratch);
    try testing.expectEqualStrings("$.02", (try jws.verifyJson(flat, set.keys, .{ .algorithms = &.{.hs256}, .unencoded = true }, json_scratch)).payload);
    // A caller not expecting RFC 7797 refuses it (§7).
    try testing.expectError(error.UnsupportedCritical, jws.verify(compact, set.keys, .{ .algorithms = &.{.hs256}, .detached_payload = "$.02" }, &scratch));
    try testing.expectError(error.UnsupportedCritical, jws.verifyJson(flat, set.keys, .{ .algorithms = &.{.hs256} }, json_scratch));

    var out: std.Io.Writer.Allocating = .init(gpa);
    defer out.deinit();
    try jws.signCompact(gpa, testing.io, &out.writer, .{ .b64 = false }, "$.02", signer, .{ .detached = true });
    try testing.expectEqualStrings(compact, out.written());
    out.clearRetainingCapacity();
    try jws.signJson(gpa, testing.io, &out.writer, .flattened, "$.02", &.{.{ .signer = signer, .header = .{ .b64 = false } }}, .{});
    try testing.expectEqualStrings(flat, out.written());
    // In the compact form the payload's dot would end it.
    try testing.expectError(error.InvalidPayload, jws.sign(gpa, testing.io, &out.writer, .{ .b64 = false }, "$.02", signer));
}

/// A flattened document of `protected` (JSON) and `header`, HS256-signed
/// over `payload` with RFC 7515 A.1's key.
fn signedDocument(protected: []const u8, unprotected: ?[]const u8, payload: []const u8, out: *std.Io.Writer.Allocating, secret: []const u8) !void {
    var input: std.Io.Writer.Allocating = .init(gpa);
    defer input.deinit();
    try base64url.encode(&input.writer, protected);
    const protected_length = input.written().len;
    try input.writer.writeByte('.');
    try base64url.encode(&input.writer, payload);
    var mac: [32]u8 = undefined;
    std.crypto.auth.hmac.sha2.HmacSha256.create(&mac, input.written(), secret);
    try out.writer.print("{{\"payload\":\"{s}\",\"protected\":\"{s}\",", .{ input.written()[protected_length + 1 ..], input.written()[0..protected_length] });
    if (unprotected) |u| try out.writer.print("\"header\":{s},", .{u});
    try out.writer.writeAll("\"signature\":\"");
    try base64url.encode(&out.writer, &mac);
    try out.writer.writeAll("\"}");
}

test "headers RFC 7515 and 7797 forbid are refused, whatever the signature" {
    var set = try jwk.KeySet.parse(gpa, a1_key, .{ .secrets = true });
    defer set.deinit();
    const secret = set.keys[0].material.hmac;
    const scratch = try gpa.alloc(u8, 16384);
    defer gpa.free(scratch);
    const cases = [_]struct { protected: []const u8, unprotected: ?[]const u8 = null, err: anyerror }{
        // b64 not listed in crit, crit empty, a name twice, a registered
        // name, one not understood.
        .{ .protected = "{\"alg\":\"HS256\",\"b64\":true}", .err = error.InvalidHeader },
        .{ .protected = "{\"alg\":\"HS256\",\"crit\":[]}", .err = error.InvalidHeader },
        .{ .protected = "{\"alg\":\"HS256\",\"b64\":true,\"crit\":[\"b64\",\"b64\"]}", .err = error.InvalidHeader },
        .{ .protected = "{\"alg\":\"HS256\",\"crit\":[\"alg\"]}", .err = error.InvalidHeader },
        .{ .protected = "{\"alg\":\"HS256\",\"exp\":1,\"crit\":[\"exp\"]}", .err = error.UnsupportedCritical },
        .{ .protected = "{\"alg\":\"HS256\",\"crit\":[\"b64\"]}", .err = error.InvalidHeader },
        // A name in both headers; crit, b64 or alg unprotected.
        .{ .protected = "{\"alg\":\"HS256\",\"kid\":\"a\"}", .unprotected = "{\"kid\":\"b\"}", .err = error.InvalidHeader },
        .{ .protected = "{\"alg\":\"HS256\"}", .unprotected = "{\"crit\":[\"b64\"],\"b64\":false}", .err = error.InvalidHeader },
        .{ .protected = "{\"alg\":\"HS256\"}", .unprotected = "{\"alg\":\"none\"}", .err = error.InvalidHeader },
        .{ .protected = "{\"alg\":\"HS256\"}", .unprotected = "7", .err = error.InvalidHeader },
    };
    for (cases) |case| {
        var out: std.Io.Writer.Allocating = .init(gpa);
        defer out.deinit();
        try signedDocument(case.protected, case.unprotected, "payload", &out, secret);
        try testing.expectError(case.err, jws.verifyJson(out.written(), set.keys, .{ .algorithms = &.{.hs256}, .unencoded = true }, scratch));
    }
    // The control: the same document verifies when nothing is wrong.
    var good: std.Io.Writer.Allocating = .init(gpa);
    defer good.deinit();
    try signedDocument("{\"alg\":\"HS256\"}", "{\"kid\":\"x\",\"x-note\":1}", "payload", &good, secret);
    // A key without the kid the unprotected header names is not chosen.
    try testing.expectError(error.NoKey, jws.verifyJson(good.written(), set.keys, .{ .algorithms = &.{.hs256} }, scratch));
    const shapes = [_][]const u8{
        "{\"payload\":\"cA\",\"signatures\":[],\"x\":1}",
        "{\"payload\":\"cA\",\"signatures\":[{\"protected\":\"eyJhbGciOiJIUzI1NiJ9\",\"signature\":\"AA\"}],\"signature\":\"AA\"}",
        "{\"payload\":\"cA\"}",
        "[]",
        "{\"payload\":\"cA\",\"protected\":\"eyJhbGciOiJIUzI1NiJ9\",\"signature\":\"AA\",\"payload\":\"cB\"}",
    };
    for (shapes) |text| try testing.expectError(error.Malformed, jws.verifyJson(text, set.keys, .{ .algorithms = &.{.hs256} }, scratch));
}

test "an ACME request: jwk, nonce and url protected, read back from the verified header" {
    var der: [48]u8 = undefined;
    _ = try std.fmt.hexToBytes(der[0..16], "302e020100300506032b657004220420");
    _ = try std.base64.url_safe_no_pad.Decoder.decode(der[16..48], "nWGxne_9WmC6hEr0kuwsxERJxWl7MmkZcDusAxyuf2A");
    const private = try cloak.PrivateKey.parse(gpa, &der, .{});
    defer private.deinit();
    var set = try jwk.KeySet.parse(gpa, "{\"kty\":\"OKP\",\"crv\":\"Ed25519\",\"x\":\"11qYAYKxCrfVS_7TyWQHOg7hcvPapiMlrwIaaPcHURo\"}", .{});
    defer set.deinit();
    var out: std.Io.Writer.Allocating = .init(gpa);
    defer out.deinit();
    try jws.signJson(gpa, testing.io, &out.writer, .flattened, "{\"termsOfServiceAgreed\":true}", &.{.{
        .signer = .{ .private = .{ .alg = .eddsa, .key = private } },
        .header = .{ .jwk = &set.keys[0], .extra = &.{ .{ .name = "nonce", .value = .{ .string = "6S8IqOGY7eL2lsGoTZYifg" } }, .{ .name = "url", .value = .{ .string = "https://example.com/acme/new-account" } } } },
    }}, .{});
    const scratch = try gpa.alloc(u8, jws.scratchLengthJson(out.written().len, 0));
    defer gpa.free(scratch);
    const verified = try jws.verifyJson(out.written(), set.keys, .{ .algorithms = &.{.eddsa} }, scratch);
    const Acme = struct { nonce: []const u8, url: []const u8 };
    var fixed: std.heap.FixedBufferAllocator = .init(verified.rest);
    const acme = try std.json.parseFromSliceLeaky(Acme, fixed.allocator(), verified.protected, .{ .ignore_unknown_fields = true });
    try testing.expectEqualStrings("https://example.com/acme/new-account", acme.url);
    try testing.expect(verified.header.jwk != null);
    // A member clearance writes itself, or one twice, is refused.
    try testing.expectError(error.InvalidHeader, jws.signJson(gpa, testing.io, &out.writer, .flattened, "x", &.{.{ .signer = .{ .private = .{ .alg = .eddsa, .key = private } }, .header = .{ .extra = &.{.{ .name = "alg", .value = .{ .string = "none" } }} } }}, .{}));
    try testing.expectError(error.InvalidHeader, jws.signJson(gpa, testing.io, &out.writer, .flattened, "x", &.{.{ .signer = .{ .private = .{ .alg = .eddsa, .key = private } }, .header = .{ .extra = &.{ .{ .name = "n", .value = .{ .raw = "1" } }, .{ .name = "n", .value = .{ .raw = "2" } } } } }}, .{}));
    try testing.expectError(error.InvalidHeader, jws.signJson(gpa, testing.io, &out.writer, .flattened, "x", &.{.{ .signer = .{ .private = .{ .alg = .eddsa, .key = private } }, .header = .{ .extra = &.{.{ .name = "n", .value = .{ .raw = "{" } }} } }}, .{}));
}
