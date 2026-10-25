//! DPoP proofs (RFC 9449 §4): a JWT a client signs for each request with a
//! key it holds, naming the request (`htm`, `htu`), so a token bound to that
//! key (`cnf.jkt`) is worth nothing to whoever steals it. Written by the
//! client, verified by the authorization server and the resource server.
//!
//! The proof carries its public key in its header (`jwk`). It is the one
//! place clearance uses a key a token names: only to check that proof's
//! signature, the binding then held to the key's thumbprint, never to trust
//! what the proof says beyond who holds that key.
const std = @import("std");
const aegis = @import("aegis");
const strand = @import("strand");
const base64url = @import("base64url.zig");
const Algorithm = @import("Algorithm.zig").Algorithm;
const PublicKey = @import("Key.zig");
const jwk = @import("jwk.zig");
const jws = @import("jws.zig");
const jwt = @import("jwt.zig");

/// The proof's `typ` (RFC 9449 §4.2).
pub const media_type = "dpop+jwt";

/// A client's DPoP key: what signs its proofs and the public half they
/// carry. The signer is in memory or outside the process.
pub const Key = struct {
    signer: jws.Signer,
    /// The public half: written into every proof, its thumbprint the
    /// binding.
    public: PublicKey,

    /// A private JWK as a DPoP key, signing with `alg` or the algorithm its
    /// `alg` names or its curve implies. Borrows `private`.
    pub fn fromJwk(private: *const jwk.PrivateKey, alg: ?Algorithm) error{InvalidKey}!Key {
        return .{ .signer = try .fromJwk(private, alg), .public = private.public };
    }

    /// The RFC 7638 thumbprint a bound token's `cnf.jkt` names.
    pub fn thumbprint(k: *const Key) [32]u8 {
        return jwk.thumbprint(k.public);
    }
};

/// What a proof says of its request.
pub const Proof = struct {
    /// The request's method, as sent (`POST`, `GET`).
    htm: []const u8,
    /// The request's URL; its query and fragment are left out of the proof
    /// (§4.2).
    htu: []const u8,
    /// The access token the request presents, whose hash the proof carries
    /// (`ath`, §4.2): every request to a resource server.
    access_token: ?[]const u8 = null,
    /// The nonce the server last gave (`DPoP-Nonce`, §8, §9).
    nonce: ?[]const u8 = null,
};

/// Writes a proof of `proof` signed by `key` at `now`, with a fresh `jti`
/// drawn from `io`.
pub fn writeProof(gpa: std.mem.Allocator, io: std.Io, out: *std.Io.Writer, key: *const Key, proof: Proof, now: std.Io.Timestamp) jwt.SignError!void {
    if (key.public.material == .hmac or key.signer.algorithm().family() == .hmac) return error.InvalidKey;
    var noise: [16]u8 = undefined;
    io.random(&noise);
    var jti: [base64url.encodedLength(16)]u8 = undefined;
    encodeInto(&jti, &noise);
    var ath: [base64url.encodedLength(32)]u8 = undefined;
    if (proof.access_token) |token| encodeInto(&ath, &tokenHash(token));
    try jwt.sign(gpa, io, out, .{ .typ = media_type, .jwk = &key.public }, .{
        .jti = @as([]const u8, &jti),
        .htm = proof.htm,
        .htu = withoutQuery(proof.htu),
        .iat = @as(i64, @intCast(@divFloor(now.nanoseconds, std.time.ns_per_s))),
        .ath = if (proof.access_token != null) @as([]const u8, &ath) else null,
        .nonce = proof.nonce,
    }, key.signer);
}

fn encodeInto(out: []u8, bytes: []const u8) void {
    var w: std.Io.Writer = .fixed(out);
    // unreachable: `out` is `encodedLength(bytes.len)` long
    base64url.encode(&w, bytes) catch unreachable;
}

/// The hash a proof carries of an access token (`ath`): SHA-256 of its
/// ASCII.
pub fn tokenHash(token: []const u8) [32]u8 {
    var out: [32]u8 = undefined;
    std.crypto.hash.sha2.Sha256.hash(token, &out, .{});
    return out;
}

/// What the server expects of a proof.
pub const Expected = struct {
    /// The asymmetric algorithms accepted: at least one, no default.
    algorithms: []const Algorithm,
    /// The method the proof came with.
    htm: []const u8,
    /// The URL the request was sent to.
    htu: []const u8,
    /// The access token the request presents: the proof's `ath` must be its
    /// hash. Null at a token endpoint, where a proof carries none.
    access_token: ?[]const u8 = null,
    /// The nonce the server requires, when it gives them.
    nonce: ?[]const u8 = null,
    /// How old a proof may be (§11.1), and the clock skew forgiven (at most
    /// five minutes).
    max_age: jwt.Duration = .literal("60s"),
    leeway: jwt.Duration = .literal("0s"),
    /// Where each proof's `jti` is kept for its life, so a replayed proof is
    /// refused (§11.1). Null leaves replay to the caller.
    replay: ?jwt.Replay = null,
    max_bytes: aegis.units.Bytes(usize) = .literal("8KiB"),
    min_rsa_bits: u16 = 2048,
    diagnostics: ?*jws.Diagnostics = null,
};

/// A proof verified: its key (its bytes in `storage`, so the value stays
/// where `verifyProof` wrote it) and the thumbprint a bound token must name.
pub const Verified = struct {
    key: PublicKey,
    thumbprint: [32]u8,
    jti: []const u8,
    iat: i64,
    /// Private: the key's bytes.
    storage: [key_storage]u8,
};

/// Room for a proof's key: an RSA key of 4096 bits and its JSON.
const key_storage = 4096;

pub const VerifyError = jws.VerifyError || error{
    /// The header has no `jwk`, or one that is no public key clearance
    /// verifies with (private members, a secret, an unknown kind).
    InvalidKey,
    /// The header's `typ` is not `dpop+jwt`.
    WrongType,
    /// The claims are not a JSON object of the members a proof has, of their
    /// types.
    InvalidClaims,
    MissingClaim,
    /// `htm` or `htu` is not this request's.
    WrongRequest,
    /// `iat` is older than `max_age`, or in the future.
    TooOld,
    /// `ath` is absent or not the presented token's hash.
    WrongAccessToken,
    /// The server requires a nonce and the proof has none or another: the
    /// answer is `use_dpop_nonce` with a fresh one (§8, §9).
    UseNonce,
    /// This proof was presented before (its `jti`, within its life).
    Replayed,
    /// The replay set has no room: refused rather than forgotten.
    ReplayFull,
};

const WireClaims = struct {
    jti: ?[]const u8 = null,
    htm: ?[]const u8 = null,
    htu: ?[]const u8 = null,
    iat: ?strand.json.Raw = null,
    ath: ?[]const u8 = null,
    nonce: ?[]const u8 = null,
};

/// Verifies a proof (RFC 9449 §4.3) of the request `expected` describes:
/// a JWS of an allowed asymmetric algorithm, typed `dpop+jwt`, signed by the
/// public key its header carries, naming this method and URL, recent, with
/// the presented token's hash and the server's nonce when they are asked
/// for, and not seen before. Strings borrow `scratch` (at least
/// `jws.scratchLength(proof.len)` bytes) and the result.
pub fn verifyProof(io: std.Io, proof: []const u8, expected: Expected, now: std.Io.Timestamp, scratch: []u8, out: *Verified) VerifyError!void {
    var diagnostics: jws.Diagnostics = .{};
    defer if (expected.diagnostics) |d| {
        d.* = diagnostics;
    };
    verifyChecked(io, proof, expected, now, scratch, out, &diagnostics) catch |err| {
        if (diagnostics.check == .none) diagnostics.check = switch (err) {
            error.InvalidKey => .key,
            error.WrongType => .type,
            error.InvalidClaims => .claims,
            error.MissingClaim => .required,
            error.WrongRequest => .request,
            error.TooOld => .too_old,
            error.WrongAccessToken => .binding,
            error.UseNonce => .nonce,
            error.Replayed, error.ReplayFull => .replay,
            else => .none,
        };
        return err;
    };
}

fn verifyChecked(io: std.Io, proof: []const u8, expected: Expected, now: std.Io.Timestamp, scratch: []u8, out: *Verified, diagnostics: *jws.Diagnostics) VerifyError!void {
    const leeway: i64 = expected.leeway.raw();
    std.debug.assert(leeway <= 300);
    std.debug.assert(expected.algorithms.len > 0);
    for (expected.algorithms) |a| std.debug.assert(a.family() != .hmac);

    // The key first, from the header read under JWS's rules; copied out of
    // the scratch the signature check decodes into again.
    const inspected = jws.inspect(proof, expected.max_bytes, scratch) catch |err| return switch (err) {
        error.Unsigned => error.AlgorithmNotAllowed,
        else => |e| e,
    };
    if (!jwt.mediaTypeIs(inspected.typ orelse return error.WrongType, media_type)) return error.WrongType;
    const raw_key = inspected.jwk orelse return error.InvalidKey;
    if (raw_key.len > key_storage / 4) return error.InvalidKey;
    @memcpy(out.storage[0..raw_key.len], raw_key);
    var fixed: std.heap.FixedBufferAllocator = .init(out.storage[raw_key.len..]);
    out.key = jwk.readPublic(fixed.allocator(), out.storage[0..raw_key.len], .signatures, expected.min_rsa_bits) catch |err| return switch (err) {
        error.OutOfMemory, error.UnsupportedKey, error.NotPublic, error.NotForSignatures, error.NotForEncryption, error.InvalidAlgorithm, error.InvalidKey => error.InvalidKey,
    };
    if (out.key.material == .hmac) return error.InvalidKey;

    const verified = try jws.verifyWith(proof, &out.key, .{
        .algorithms = expected.algorithms,
        .max_bytes = expected.max_bytes,
        .min_rsa_bits = expected.min_rsa_bits,
        .diagnostics = diagnostics,
    }, scratch);
    var claims_arena: std.heap.FixedBufferAllocator = .init(verified.rest);
    const claims = strand.json.parseLeaky(WireClaims, claims_arena.allocator(), verified.payload, .{
        .ignore_unknown_fields = true,
        .limits = .{ .depth = 16 },
    }) catch return error.InvalidClaims;
    const jti = claims.jti orelse return error.MissingClaim;
    const htm = claims.htm orelse return error.MissingClaim;
    const htu = claims.htu orelse return error.MissingClaim;
    const iat = jwt.numericDate((claims.iat orelse return error.MissingClaim).bytes) catch return error.InvalidClaims;
    if (jti.len == 0 or jti.len > 256) return error.InvalidClaims;

    if (!std.mem.eql(u8, htm, expected.htm)) return error.WrongRequest;
    if (!sameUri(htu, expected.htu)) return error.WrongRequest;
    const seconds: i64 = @intCast(@divFloor(now.nanoseconds, std.time.ns_per_s));
    const max_age: i64 = expected.max_age.raw();
    if (iat > seconds +| leeway or seconds -| iat > max_age +| leeway) return error.TooOld;
    if (expected.access_token) |token| {
        const ath = claims.ath orelse return error.WrongAccessToken;
        var hash: [32]u8 = undefined;
        const decoded = base64url.decode(&hash, ath) catch return error.WrongAccessToken;
        if (decoded.len != 32) return error.WrongAccessToken;
        const same = aegis.secret.equalBytes(&hash, &tokenHash(token)) catch return error.WrongAccessToken;
        if (!same.declassify("a wrong token hash refuses the proof")) return error.WrongAccessToken;
    }
    if (expected.nonce) |nonce| {
        const given = claims.nonce orelse return error.UseNonce;
        if (!std.mem.eql(u8, given, nonce)) return error.UseNonce;
    }
    out.thumbprint = jwk.thumbprint(out.key);
    if (expected.replay) |replay| {
        const fresh = replay.record(io, jwt.replayId(&out.thumbprint, jti), iat +| max_age +| leeway +| 1, seconds) catch return error.ReplayFull;
        if (!fresh) return error.Replayed;
    }
    out.jti = jti;
    out.iat = iat;
}

/// `uri` without its query and fragment.
fn withoutQuery(uri: []const u8) []const u8 {
    const end = std.mem.findAny(u8, uri, "?#") orelse uri.len;
    return uri[0..end];
}

/// Whether two URIs name the same `htu` (RFC 9449 §4.3, point 9): query and
/// fragment left out, then compared after RFC 3986 §6.2.2 and §6.2.3's
/// normalisation (scheme and host without case, percent-encodings in upper
/// case, the scheme's default port and an empty path made explicit).
pub fn sameUri(a: []const u8, b: []const u8) bool {
    var x: [2048]u8 = undefined;
    var y: [2048]u8 = undefined;
    const na = normalize(withoutQuery(a), &x) orelse return false;
    const nb = normalize(withoutQuery(b), &y) orelse return false;
    return std.mem.eql(u8, na, nb);
}

fn normalize(uri: []const u8, out: []u8) ?[]const u8 {
    if (uri.len > out.len) return null;
    const sep = std.mem.find(u8, uri, "://") orelse return null;
    const scheme = uri[0..sep];
    const https = std.ascii.eqlIgnoreCase(scheme, "https");
    if (!https and !std.ascii.eqlIgnoreCase(scheme, "http")) return null;
    const rest = uri[sep + 3 ..];
    const path_at = std.mem.findScalar(u8, rest, '/') orelse rest.len;
    var authority = rest[0..path_at];
    if (authority.len == 0 or std.mem.findScalar(u8, authority, '@') != null) return null;
    const default_port: []const u8 = if (https) ":443" else ":80";
    if (std.mem.endsWith(u8, authority, default_port)) authority = authority[0 .. authority.len - default_port.len];
    var w: std.Io.Writer = .fixed(out);
    w.writeAll(if (https) "https://" else "http://") catch return null;
    for (authority) |c| w.writeByte(std.ascii.toLower(c)) catch return null;
    const path = if (path_at == rest.len) "/" else rest[path_at..];
    var i: usize = 0;
    while (i < path.len) : (i += 1) {
        if (path[i] == '%' and i + 2 < path.len) {
            w.writeByte('%') catch return null;
            w.writeByte(std.ascii.toUpper(path[i + 1])) catch return null;
            w.writeByte(std.ascii.toUpper(path[i + 2])) catch return null;
            i += 2;
            continue;
        }
        w.writeByte(path[i]) catch return null;
    }
    return w.buffered();
}

const testing = std.testing;

/// RFC 8037 A.1's Ed25519 key.
const test_private_jwk = "{\"kty\":\"OKP\",\"crv\":\"Ed25519\",\"d\":\"nWGxne_9WmC6hEr0kuwsxERJxWl7MmkZcDusAxyuf2A\",\"x\":\"11qYAYKxCrfVS_7TyWQHOg7hcvPapiMlrwIaaPcHURo\"}";
const test_now: std.Io.Timestamp = .{ .nanoseconds = 1_800_000_000 * std.time.ns_per_s };

fn testProof(gpa: std.mem.Allocator, key: *const Key, proof: Proof, now: std.Io.Timestamp) ![]u8 {
    var out: std.Io.Writer.Allocating = .init(gpa);
    errdefer out.deinit();
    try writeProof(gpa, testing.io, &out.writer, key, proof, now);
    return out.toOwnedSlice();
}

test "a proof is written with its key in the header and verified for its request" {
    const gpa = testing.allocator;
    var private = try jwk.PrivateKey.parse(gpa, test_private_jwk, .{});
    defer private.deinit();
    const key = try Key.fromJwk(&private, null);
    const text = try testProof(gpa, &key, .{ .htm = "POST", .htu = "https://server.example.com/token?x=1#f" }, test_now);
    defer gpa.free(text);
    var scratch: [4096]u8 = undefined;
    var verified: Verified = undefined;
    const expected: Expected = .{ .algorithms = &.{.eddsa}, .htm = "POST", .htu = "https://server.example.com/token" };
    try verifyProof(testing.io, text, expected, test_now, &scratch, &verified);
    try testing.expectEqualSlices(u8, &key.thumbprint(), &verified.thumbprint);
    try testing.expectEqual(@as(usize, 22), verified.jti.len);
    // The header holds the public half alone.
    const header = try base64url.decodeAlloc(gpa, text[0..std.mem.findScalar(u8, text, '.').?]);
    defer gpa.free(header);
    try testing.expectEqualStrings("{\"alg\":\"EdDSA\",\"typ\":\"dpop+jwt\",\"jwk\":{\"crv\":\"Ed25519\",\"kty\":\"OKP\",\"x\":\"11qYAYKxCrfVS_7TyWQHOg7hcvPapiMlrwIaaPcHURo\"}}", header);

    // Another request, another URL, an old proof, an algorithm not allowed.
    try testing.expectError(error.WrongRequest, verifyProof(testing.io, text, .{ .algorithms = &.{.eddsa}, .htm = "GET", .htu = "https://server.example.com/token" }, test_now, &scratch, &verified));
    try testing.expectError(error.WrongRequest, verifyProof(testing.io, text, .{ .algorithms = &.{.eddsa}, .htm = "POST", .htu = "https://server.example.com/other" }, test_now, &scratch, &verified));
    try testing.expectError(error.TooOld, verifyProof(testing.io, text, expected, .{ .nanoseconds = test_now.nanoseconds + 61 * std.time.ns_per_s }, &scratch, &verified));
    try testing.expectError(error.TooOld, verifyProof(testing.io, text, expected, .{ .nanoseconds = test_now.nanoseconds - std.time.ns_per_s }, &scratch, &verified));
    try testing.expectError(error.AlgorithmNotAllowed, verifyProof(testing.io, text, .{ .algorithms = &.{.es256}, .htm = "POST", .htu = "https://server.example.com/token" }, test_now, &scratch, &verified));
}

test "the access token's hash and the server's nonce are held to; a replayed proof is refused" {
    const gpa = testing.allocator;
    var private = try jwk.PrivateKey.parse(gpa, test_private_jwk, .{});
    defer private.deinit();
    const key = try Key.fromJwk(&private, null);
    const text = try testProof(gpa, &key, .{ .htm = "GET", .htu = "https://rs.example/mcp", .access_token = "Kz~8mXK1EalYznwH-LC-1fBAo.4Ljp~zsPE_NeO.gxU", .nonce = "eyJ7S_zG.eyJH0-Z.HX4w-7v" }, test_now);
    defer gpa.free(text);
    var scratch: [4096]u8 = undefined;
    var verified: Verified = undefined;
    var replay: jwt.MemoryReplay = try .init(gpa, 16);
    defer replay.deinit();
    var expected: Expected = .{ .algorithms = &.{ .es256, .eddsa }, .htm = "GET", .htu = "HTTPS://RS.example:443/mcp", .access_token = "Kz~8mXK1EalYznwH-LC-1fBAo.4Ljp~zsPE_NeO.gxU", .nonce = "eyJ7S_zG.eyJH0-Z.HX4w-7v", .replay = replay.replay() };
    try verifyProof(testing.io, text, expected, test_now, &scratch, &verified);
    try testing.expectError(error.Replayed, verifyProof(testing.io, text, expected, test_now, &scratch, &verified));
    expected.replay = null;
    expected.access_token = "another";
    try testing.expectError(error.WrongAccessToken, verifyProof(testing.io, text, expected, test_now, &scratch, &verified));
    expected.access_token = "Kz~8mXK1EalYznwH-LC-1fBAo.4Ljp~zsPE_NeO.gxU";
    expected.nonce = "fresher";
    try testing.expectError(error.UseNonce, verifyProof(testing.io, text, expected, test_now, &scratch, &verified));
    var diagnostics: jws.Diagnostics = .{};
    expected.diagnostics = &diagnostics;
    try testing.expectError(error.UseNonce, verifyProof(testing.io, text, expected, test_now, &scratch, &verified));
    try testing.expectEqual(jws.Check.nonce, diagnostics.check);
}

test "a proof whose header key is missing, secret, private or not its signer is refused" {
    const gpa = testing.allocator;
    var private = try jwk.PrivateKey.parse(gpa, test_private_jwk, .{});
    defer private.deinit();
    var scratch: [4096]u8 = undefined;
    var verified: Verified = undefined;
    const expected: Expected = .{ .algorithms = &.{.eddsa}, .htm = "POST", .htu = "https://as.example/token" };
    const claims = .{ .jti = "j", .htm = "POST", .htu = "https://as.example/token", .iat = @as(i64, 1_800_000_000) };
    const signer: jws.Signer = .{ .private = .{ .alg = .eddsa, .key = private.key } };
    var out: std.Io.Writer.Allocating = .init(gpa);
    defer out.deinit();

    // No jwk.
    try jwt.sign(gpa, testing.io, &out.writer, .{ .typ = media_type }, claims, signer);
    try testing.expectError(error.InvalidKey, verifyProof(testing.io, out.written(), expected, test_now, &scratch, &verified));
    // Another key in the header than the one that signed.
    out.clearRetainingCapacity();
    const pair = try std.crypto.sign.Ed25519.KeyPair.generateDeterministic(@splat(7));
    const other_x = pair.public_key.toBytes();
    const other: PublicKey = .{ .material = .{ .okp = .{ .x = &other_x } } };
    try jwt.sign(gpa, testing.io, &out.writer, .{ .typ = media_type, .jwk = &other }, claims, signer);
    try testing.expectError(error.InvalidSignature, verifyProof(testing.io, out.written(), expected, test_now, &scratch, &verified));
    // Not typed as a proof.
    out.clearRetainingCapacity();
    try jwt.sign(gpa, testing.io, &out.writer, .{ .jwk = &private.public }, claims, signer);
    try testing.expectError(error.WrongType, verifyProof(testing.io, out.written(), expected, test_now, &scratch, &verified));
    // A secret key cannot be written into a header.
    const secret: [32]u8 = @splat(1);
    const hmac = PublicKey.hmac(&secret);
    out.clearRetainingCapacity();
    try testing.expectError(error.InvalidKey, jwt.sign(gpa, testing.io, &out.writer, .{ .typ = media_type, .jwk = &hmac }, claims, signer));
}

test "htu compares as RFC 9449 §4.3 asks" {
    try testing.expect(sameUri("https://server.example.com/token", "https://server.example.com/token"));
    try testing.expect(sameUri("https://Server.Example.COM:443/token", "https://server.example.com/token"));
    try testing.expect(sameUri("HTTP://a.example:80", "http://a.example/"));
    try testing.expect(sameUri("https://a.example/a%2fb?q=1#x", "https://a.example/a%2Fb"));
    try testing.expect(!sameUri("https://a.example/token", "https://a.example/token/"));
    try testing.expect(!sameUri("https://a.example/token", "http://a.example/token"));
    try testing.expect(!sameUri("https://a.example:8443/token", "https://a.example/token"));
    try testing.expect(!sameUri("https://u@a.example/token", "https://a.example/token"));
    try testing.expect(!sameUri("ftp://a.example/token", "ftp://a.example/token"));
}
