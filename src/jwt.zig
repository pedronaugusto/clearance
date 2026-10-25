//! JSON Web Tokens (RFC 7519) as JWS, checked as RFC 8725 asks: the
//! registered claims by type before value, the type header when the profile
//! has one, the time claims against a clock the caller gives.
const std = @import("std");
const aegis = @import("aegis");
const strand = @import("strand");
const jws = @import("jws.zig");
const jwe = @import("jwe.zig");
const Algorithm = @import("Algorithm.zig").Algorithm;
const Key = @import("Key.zig");

/// Time spans in a validation: whole seconds, as NumericDate counts.
pub const Duration = aegis.units.Duration(.second, u32);

/// The registered claims (RFC 7519 §4.1), as a token carries them.
pub const Registered = struct {
    iss: ?[]const u8 = null,
    sub: ?[]const u8 = null,
    /// One audience or several: a string or an array of strings.
    aud: Audience = .{},
    exp: ?i64 = null,
    nbf: ?i64 = null,
    iat: ?i64 = null,
    jti: ?[]const u8 = null,
};

/// `aud` as read: absent, one value, or several.
pub const Audience = struct {
    values: []const []const u8 = &.{},
    present: bool = false,

    pub fn contains(a: Audience, value: []const u8) bool {
        for (a.values) |v| if (std.mem.eql(u8, v, value)) return true;
        return false;
    }
};

/// The registered claims as JSON has them: each read as raw JSON first, so a
/// claim of the wrong type is refused rather than taken as absent.
/// An absent claim keeps the empty default; a present `null` is a claim of
/// the wrong type.
const absent: strand.json.Raw = .{ .bytes = "" };
const WireRegistered = struct {
    iss: strand.json.Raw = absent,
    sub: strand.json.Raw = absent,
    aud: strand.json.Raw = absent,
    exp: strand.json.Raw = absent,
    nbf: strand.json.Raw = absent,
    iat: strand.json.Raw = absent,
    jti: strand.json.Raw = absent,
};

/// Which registered claims a token must carry.
pub const Required = packed struct {
    iss: bool = false,
    sub: bool = false,
    aud: bool = false,
    exp: bool = true,
    nbf: bool = false,
    iat: bool = false,
    jti: bool = false,
};

/// What a token must be to be accepted. `algorithms` is the verifier's; the
/// rest are checked when set.
pub const Validation = struct {
    algorithms: []const Algorithm,
    /// `iss` must equal it, byte for byte.
    issuer: ?[]const u8 = null,
    /// `aud` must contain it. A token with an `aud` is refused when this is
    /// null: its audience was not asked about (RFC 7519 §4.1.3).
    audience: ?[]const u8 = null,
    /// `sub` must equal it.
    subject: ?[]const u8 = null,
    /// The header's `typ` must name this media type, compared without case
    /// and with or without `application/` (RFC 7515 §4.1.9): `at+jwt` for
    /// access tokens (RFC 9068). Null accepts any.
    typ: ?[]const u8 = null,
    required: Required = .{},
    /// Clock skew forgiven on `exp`, `nbf` and `iat`; at most five minutes.
    leeway: Duration = .literal("0s"),
    /// When set, `iat` is required and no older than this.
    max_age: ?Duration = null,
    /// Read the claims type with unknown members passed over (the default) or
    /// refused.
    ignore_unknown_claims: bool = true,
    max_bytes: aegis.units.Bytes(usize) = .literal("16KiB"),
    min_rsa_bits: u16 = 2048,
    /// Set when the token is to come encrypted (a client that registered an
    /// encryption algorithm, OpenID Connect Registration §2): it must be a
    /// nested JWT (RFC 7519 §5.2), a compact JWE these keys decrypt whose
    /// content is the signed token, `cty` `JWT` or none. A signed token
    /// alone is then refused (`NotEncrypted`). Null takes a signed token.
    decryption: ?Decryption = null,
    diagnostics: ?*jws.Diagnostics = null,
};

/// What a nested JWT is decrypted with: the recipient's keys and the JWE
/// allowlists, as `jwe.decrypt` takes them, and the `io` it draws from.
pub const Decryption = struct {
    io: std.Io,
    keys: []const jwe.DecryptionKey,
    options: jwe.Options,
};

pub fn Verified(comptime Claims: type) type {
    return struct {
        header: jws.Header,
        registered: Registered,
        /// The claims as the caller's type; `void` reads none.
        claims: Claims,
        key: *const Key,
        payload: []const u8,
        /// What of the scratch buffer is still free: room for a profile to
        /// read more of the payload.
        rest: []u8,
    };
}

pub const VerifyError = jws.VerifyError || error{
    /// The payload is not a JSON object, a registered claim has the wrong
    /// type, or the claims do not decode into the caller's type.
    InvalidClaims,
    /// The header's `typ` is not the one the validation names.
    WrongType,
    WrongIssuer,
    WrongAudience,
    WrongSubject,
    Expired,
    NotYetValid,
    /// `iat` is older than `max_age`, or in the future.
    TooOld,
    /// A claim the validation requires is absent.
    MissingClaim,
} || NestedError;

pub const NestedError = jwe.DecryptError || error{
    /// `decryption` was set and the token is signed, not encrypted.
    NotEncrypted,
};

/// Verifies a JWT and reads its claims into `Claims` (a struct, or `void`).
/// `now` is the time the checks are made at. Strings borrow from `scratch`,
/// which holds at least `jws.scratchLength(token.len)` bytes
/// (`jwe.scratchLength(token.len)` with `decryption`), and from the keys.
pub fn verify(comptime Claims: type, token: []const u8, keys: []const Key, validation: Validation, now: std.Io.Timestamp, scratch: []u8) VerifyError!Verified(Claims) {
    const leeway_seconds: u32 = validation.leeway.raw();
    std.debug.assert(leeway_seconds <= 300);
    var diagnostics: jws.Diagnostics = .{};
    defer if (validation.diagnostics) |d| {
        d.* = diagnostics;
    };
    var signed = token;
    var room = scratch;
    if (validation.decryption) |decryption| {
        const nested = try decryptNested(token, decryption, scratch, &diagnostics);
        if (nested.content_type == .other) {
            diagnostics.check = .type;
            return error.WrongType;
        }
        signed = nested.content;
        room = nested.rest;
    }
    const verified = try jws.verify(signed, keys, .{
        .algorithms = validation.algorithms,
        .max_bytes = validation.max_bytes,
        .min_rsa_bits = validation.min_rsa_bits,
        .diagnostics = &diagnostics,
    }, room);
    const read = readClaims(Claims, verified.header.typ, verified.payload, verified.rest, inspectionOf(validation), now) catch |err| {
        diagnostics.check = switch (err) {
            error.InvalidClaims => .claims,
            error.WrongType => .type,
            error.WrongIssuer => .issuer,
            error.WrongAudience => .audience,
            error.WrongSubject => .subject,
            error.Expired => .expired,
            error.NotYetValid => .not_yet_valid,
            error.TooOld => .too_old,
            error.MissingClaim => .required,
        };
        return err;
    };
    return .{ .header = verified.header, .registered = read.registered, .claims = read.claims, .key = verified.key, .payload = verified.payload, .rest = read.rest };
}

/// A compact JWE's content, decrypted.
pub const Nested = struct {
    alg: jwe.KeyManagement,
    enc: jwe.ContentEncryption,
    /// What the header's `cty` says the content is.
    content_type: ContentType,
    /// The content, at the front of the scratch buffer.
    content: []const u8,
    /// The scratch buffer after the content, wiped: room for the next step.
    rest: []u8,
};

/// Decrypts the compact JWE a nested JWT or an encrypted answer is (JWTs
/// are compact, RFC 7519 §1: a JSON document is `Malformed`); a compact JWS
/// is `NotEncrypted`. The content is moved to the front of `scratch`
/// (`jwe.scratchLength(token.len)` bytes) and the rest wiped; the caller
/// erases the content when done.
pub fn decryptNested(token: []const u8, decryption: Decryption, scratch: []u8, diagnostics: *jws.Diagnostics) NestedError!Nested {
    if (std.mem.count(u8, token, ".") == 2) {
        diagnostics.check = .shape;
        return error.NotEncrypted;
    }
    if (token.len > 0 and token[0] == '{') {
        diagnostics.check = .shape;
        return error.Malformed;
    }
    var options = decryption.options;
    options.diagnostics = diagnostics;
    const d = try jwe.decrypt(decryption.io, token, decryption.keys, options, scratch);
    // Read before the header's strings, which live past the content, are wiped.
    const content_type: ContentType = if (d.header.cty) |cty| (if (mediaTypeIs(cty, "JWT")) .jwt else .other) else .none;
    @memmove(scratch[0..d.plaintext.len], d.plaintext);
    std.crypto.secureZero(u8, scratch[d.plaintext.len..]);
    return .{ .alg = d.header.alg, .enc = d.header.enc, .content_type = content_type, .content = scratch[0..d.plaintext.len], .rest = scratch[d.plaintext.len..] };
}

/// A JWE header's `cty`: absent, `JWT` (a nested token), or another.
pub const ContentType = enum { none, jwt, other };

/// The checks of a token's type and claims: a `Validation` without the
/// signature's part, for `inspect`.
pub const Inspection = struct {
    issuer: ?[]const u8 = null,
    audience: ?[]const u8 = null,
    subject: ?[]const u8 = null,
    typ: ?[]const u8 = null,
    required: Required = .{},
    leeway: Duration = .literal("0s"),
    max_age: ?Duration = null,
    ignore_unknown_claims: bool = true,
    max_bytes: aegis.units.Bytes(usize) = .literal("16KiB"),
};

fn inspectionOf(v: Validation) Inspection {
    return .{
        .issuer = v.issuer,
        .audience = v.audience,
        .subject = v.subject,
        .typ = v.typ,
        .required = v.required,
        .leeway = v.leeway,
        .max_age = v.max_age,
        .ignore_unknown_claims = v.ignore_unknown_claims,
        .max_bytes = v.max_bytes,
    };
}

pub fn Inspected(comptime Claims: type) type {
    return struct {
        header: jws.Inspected,
        registered: Registered,
        claims: Claims,
        /// What of the scratch buffer is still free.
        rest: []u8,
    };
}

pub const InspectError = jws.InspectError || error{
    InvalidClaims,
    WrongType,
    WrongIssuer,
    WrongAudience,
    WrongSubject,
    Expired,
    NotYetValid,
    TooOld,
    MissingClaim,
};

/// Reads a JWT without verifying its signature (`jws.inspect`), its type and
/// claims checked as `verify` checks them. For a token on its way to the
/// party that verifies it, whose holder checks it is what it asked for;
/// never a reason to trust its content. Strings borrow from `scratch` (at
/// least `jws.scratchLength(token.len)` bytes).
pub fn inspect(comptime Claims: type, token: []const u8, inspection: Inspection, now: std.Io.Timestamp, scratch: []u8) InspectError!Inspected(Claims) {
    const leeway_seconds: u32 = inspection.leeway.raw();
    std.debug.assert(leeway_seconds <= 300);
    const header = try jws.inspect(token, inspection.max_bytes, scratch);
    const read = try readClaims(Claims, header.typ, header.payload, header.rest, inspection, now);
    return .{ .header = header, .registered = read.registered, .claims = read.claims, .rest = read.rest };
}

const ClaimsError = error{ InvalidClaims, WrongType, WrongIssuer, WrongAudience, WrongSubject, Expired, NotYetValid, TooOld, MissingClaim };

fn ReadClaims(comptime Claims: type) type {
    return struct { registered: Registered, claims: Claims, rest: []u8 };
}

fn readClaims(comptime Claims: type, typ: ?[]const u8, payload: []const u8, rest: []u8, inspection: Inspection, now: std.Io.Timestamp) ClaimsError!ReadClaims(Claims) {
    if (inspection.typ) |expected| {
        const named = typ orelse return error.WrongType;
        if (!mediaTypeIs(named, expected)) return error.WrongType;
    }
    var fixed: std.heap.FixedBufferAllocator = .init(rest);
    const arena = fixed.allocator();
    const options: strand.json.ParseOptions = .{ .ignore_unknown_fields = true, .limits = .{ .depth = 32 } };
    const wire = strand.json.parseLeaky(WireRegistered, arena, payload, options) catch return error.InvalidClaims;
    const registered = try readRegistered(arena, wire);
    try checkRegistered(registered, inspection, now);
    const claims: Claims = if (Claims == void) {} else strand.json.parseLeaky(Claims, arena, payload, .{
        .ignore_unknown_fields = inspection.ignore_unknown_claims,
        .limits = .{ .depth = 32 },
    }) catch return error.InvalidClaims;
    return .{ .registered = registered, .claims = claims, .rest = rest[fixed.end_index..] };
}

fn present(raw: strand.json.Raw) bool {
    return raw.bytes.len != 0;
}

fn readRegistered(arena: std.mem.Allocator, wire: WireRegistered) ClaimsError!Registered {
    const opts: strand.json.ParseOptions = .{};
    var r: Registered = .{};
    inline for (.{ "iss", "sub", "jti" }) |name| {
        if (present(@field(wire, name))) @field(r, name) = @field(wire, name).parse([]const u8, arena, opts) catch return error.InvalidClaims;
    }
    inline for (.{ "exp", "nbf", "iat" }) |name| {
        if (present(@field(wire, name))) @field(r, name) = try numericDate(@field(wire, name).bytes);
    }
    if (present(wire.aud)) {
        const raw = wire.aud;
        r.aud.present = true;
        if (raw.parse([]const u8, arena, opts)) |one| {
            const values = arena.alloc([]const u8, 1) catch return error.InvalidClaims;
            values[0] = one;
            r.aud.values = values;
        } else |_| {
            r.aud.values = raw.parse([]const []const u8, arena, opts) catch return error.InvalidClaims;
        }
    }
    return r;
}

/// A NumericDate (RFC 7519 §2): a JSON number of seconds, a fraction allowed
/// and dropped toward the past. Anything else, or a value no clock reaches,
/// refuses the token.
pub fn numericDate(bytes: []const u8) error{InvalidClaims}!i64 {
    const text = std.mem.trim(u8, bytes, " \t\r\n");
    if (text.len == 0 or text.len > 32) return error.InvalidClaims;
    if (text[0] != '-' and !std.ascii.isDigit(text[0])) return error.InvalidClaims;
    if (std.fmt.parseInt(i64, text, 10)) |seconds| {
        return seconds;
    } else |_| {}
    const value = std.fmt.parseFloat(f64, text) catch return error.InvalidClaims;
    if (!std.math.isFinite(value) or @abs(value) > 1e15) return error.InvalidClaims;
    return @intFromFloat(@floor(value));
}

fn checkRegistered(r: Registered, v: Inspection, now: std.Io.Timestamp) ClaimsError!void {
    const seconds: i64 = @intCast(@divFloor(now.nanoseconds, std.time.ns_per_s));
    const leeway: i64 = v.leeway.raw();
    const required = v.required;
    if ((required.iss and r.iss == null) or (required.sub and r.sub == null) or (required.aud and !r.aud.present) or
        (required.exp and r.exp == null) or (required.nbf and r.nbf == null) or (required.iat and r.iat == null) or
        (required.jti and r.jti == null) or (v.max_age != null and r.iat == null)) return error.MissingClaim;
    if (v.issuer) |issuer| {
        const iss = r.iss orelse return error.MissingClaim;
        if (!std.mem.eql(u8, iss, issuer)) return error.WrongIssuer;
    }
    if (v.subject) |subject| {
        const sub = r.sub orelse return error.MissingClaim;
        if (!std.mem.eql(u8, sub, subject)) return error.WrongSubject;
    }
    if (v.audience) |audience| {
        if (!r.aud.present) return error.MissingClaim;
        if (!r.aud.contains(audience)) return error.WrongAudience;
    } else if (r.aud.present) return error.WrongAudience;
    if (r.exp) |exp| if (seconds >= exp +| leeway) return error.Expired;
    if (r.nbf) |nbf| if (seconds +| leeway < nbf) return error.NotYetValid;
    if (v.max_age) |max_age| {
        const iat = r.iat.?;
        if (iat > seconds +| leeway) return error.TooOld;
        const max_seconds: i64 = max_age.raw();
        if (seconds -| iat > max_seconds +| leeway) return error.TooOld;
    }
}

/// Whether a `typ` value names `expected`: compared without case, the
/// `application/` prefix optional on either (RFC 7515 §4.1.9).
pub fn mediaTypeIs(typ: []const u8, expected: []const u8) bool {
    return std.ascii.eqlIgnoreCase(strip(typ), strip(expected));
}

fn strip(media: []const u8) []const u8 {
    const prefix = "application/";
    if (media.len > prefix.len and std.ascii.eqlIgnoreCase(media[0..prefix.len], prefix)) return media[prefix.len..];
    return media;
}

/// Where the identifiers of tokens meant to be used once (a DPoP proof's
/// `jti`, a logout token's) are kept while those tokens could still be
/// accepted, so a token replayed within its life is refused. The caller
/// names an identifier by a hash (`replayId`), never the token's text.
pub const Replay = struct {
    context: *anyopaque,
    vtable: *const VTable,

    pub const VTable = struct {
        record: *const fn (context: *anyopaque, io: std.Io, id: [32]u8, until: i64, now: i64) RecordError!bool,
    };

    pub const RecordError = error{
        /// Every place is held by an identifier still in its life: refusing
        /// is the only safe answer (forgetting one would let it be replayed).
        Full,
    };

    /// Records `id` as seen until `until` (seconds since the epoch): true
    /// the first time, false when it is already held and `now` is before
    /// its end.
    pub fn record(r: Replay, io: std.Io, id: [32]u8, until: i64, now: i64) RecordError!bool {
        return r.vtable.record(r.context, io, id, until, now);
    }
};

/// The identifier a replay set keeps for a token: SHA-256 over the scope it
/// is unique in (the key that signed it, its issuer) and its own id, so one
/// party's identifiers never collide with another's.
pub fn replayId(scope: []const u8, id: []const u8) [32]u8 {
    var h: std.crypto.hash.sha2.Sha256 = .init(.{});
    var length: [8]u8 = undefined;
    std.mem.writeInt(u64, &length, scope.len, .big);
    h.update(&length);
    h.update(scope);
    h.update(id);
    return h.finalResult();
}

/// A replay set in memory, of a fixed number of places taken when it is
/// made: recording never allocates. Safe to share between tasks.
pub const MemoryReplay = struct {
    gpa: std.mem.Allocator,
    mutex: std.Io.Mutex = .init,
    /// Guarded by `mutex`: each identifier and the second its life ends.
    entries: std.array_hash_map.Auto([32]u8, i64) = .empty,
    capacity: u32,

    pub fn init(gpa: std.mem.Allocator, capacity: u32) std.mem.Allocator.Error!MemoryReplay {
        var m: MemoryReplay = .{ .gpa = gpa, .capacity = capacity };
        try m.entries.ensureTotalCapacity(gpa, capacity);
        return m;
    }

    pub fn deinit(m: *MemoryReplay) void {
        m.entries.deinit(m.gpa);
        m.* = undefined;
    }

    pub fn replay(m: *MemoryReplay) Replay {
        return .{ .context = m, .vtable = &.{ .record = record } };
    }

    fn record(context: *anyopaque, io: std.Io, id: [32]u8, until: i64, now: i64) Replay.RecordError!bool {
        const m: *MemoryReplay = @ptrCast(@alignCast(context)); // safe: the vtable is only ever handed out with a *MemoryReplay
        m.mutex.lockUncancelable(io);
        defer m.mutex.unlock(io);
        if (m.entries.getPtr(id)) |end| {
            if (now < end.*) return false;
            end.* = until;
            return true;
        }
        if (m.entries.count() >= m.capacity) {
            var i: usize = 0;
            while (i < m.entries.count()) {
                if (m.entries.values()[i] <= now) m.entries.swapRemoveAt(i) else i += 1;
            }
            if (m.entries.count() >= m.capacity) return error.Full;
        }
        // Within the capacity taken at `init`: no allocation.
        m.entries.putAssumeCapacity(id, until);
        return true;
    }
};

pub const SignError = jws.SignError || error{InvalidClaims};

/// Writes `claims` (any value strand writes as a JSON object) as a JWT signed
/// by `signer`, with `typ` `JWT` unless the header says otherwise.
pub fn sign(gpa: std.mem.Allocator, io: std.Io, out: *std.Io.Writer, header: jws.SignHeader, claims: anytype, signer: jws.Signer) SignError!void {
    var payload: std.Io.Writer.Allocating = .init(gpa);
    defer payload.deinit();
    strand.json.write(&payload.writer, claims, .{ .nulls = .omit }) catch |err| return switch (err) {
        error.WriteFailed => error.OutOfMemory,
        else => error.InvalidClaims,
    };
    var with_type = header;
    if (with_type.typ == null) with_type.typ = "JWT";
    try jws.sign(gpa, io, out, with_type, payload.written(), signer);
}

test "a replay set refuses an identifier within its life, takes it again after, and refuses when full" {
    var m: MemoryReplay = try .init(std.testing.allocator, 2);
    defer m.deinit();
    const r = m.replay();
    const io = std.testing.io;
    const a = replayId("key-a", "j1");
    try std.testing.expect(!std.mem.eql(u8, &a, &replayId("key-b", "j1")));
    try std.testing.expect(!std.mem.eql(u8, &replayId("ab", "c"), &replayId("a", "bc")));
    try std.testing.expect(try r.record(io, a, 100, 10));
    try std.testing.expect(!try r.record(io, a, 100, 99));
    try std.testing.expect(try r.record(io, a, 200, 100));
    try std.testing.expect(try r.record(io, replayId("key-a", "j2"), 150, 100));
    try std.testing.expectError(error.Full, r.record(io, replayId("key-a", "j3"), 150, 120));
    // Past the second identifier's end its place is free.
    try std.testing.expect(try r.record(io, replayId("key-a", "j3"), 300, 150));
}

test {
    _ = @import("jwt_test.zig");
}
