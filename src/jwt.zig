//! JSON Web Tokens (RFC 7519) as JWS, checked as RFC 8725 asks: the
//! registered claims by type before value, the type header when the profile
//! has one, the time claims against a clock the caller gives.
const std = @import("std");
const aegis = @import("aegis");
const strand = @import("strand");
const jws = @import("jws.zig");
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
    diagnostics: ?*jws.Diagnostics = null,
};

pub fn Verified(comptime Claims: type) type {
    return struct {
        header: jws.Header,
        registered: Registered,
        /// The claims as the caller's type; `void` reads none.
        claims: Claims,
        key: *const Key,
        payload: []const u8,
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
};

/// Verifies a JWT and reads its claims into `Claims` (a struct, or `void`).
/// `now` is the time the checks are made at. Strings borrow from `scratch`,
/// which holds at least `jws.scratchLength(token.len)` bytes, and from the
/// keys.
pub fn verify(comptime Claims: type, token: []const u8, keys: []const Key, validation: Validation, now: std.Io.Timestamp, scratch: []u8) VerifyError!Verified(Claims) {
    const leeway_seconds: u32 = validation.leeway.raw();
    std.debug.assert(leeway_seconds <= 300);
    var diagnostics: jws.Diagnostics = .{};
    defer if (validation.diagnostics) |d| {
        d.* = diagnostics;
    };
    const verified = try jws.verify(token, keys, .{
        .algorithms = validation.algorithms,
        .max_bytes = validation.max_bytes,
        .min_rsa_bits = validation.min_rsa_bits,
        .diagnostics = &diagnostics,
    }, scratch);
    return readClaims(Claims, verified, validation, now) catch |err| {
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

            else => diagnostics.check,
        };
        return err;
    };
}

fn readClaims(comptime Claims: type, verified: jws.Verified, validation: Validation, now: std.Io.Timestamp) VerifyError!Verified(Claims) {
    if (validation.typ) |expected| {
        const typ = verified.header.typ orelse return error.WrongType;
        if (!mediaTypeIs(typ, expected)) return error.WrongType;
    }
    var fixed: std.heap.FixedBufferAllocator = .init(verified.rest);
    const arena = fixed.allocator();
    const options: strand.json.ParseOptions = .{ .ignore_unknown_fields = true, .limits = .{ .depth = 32 } };
    const wire = strand.json.parseLeaky(WireRegistered, arena, verified.payload, options) catch return error.InvalidClaims;
    const registered = try readRegistered(arena, wire);
    try checkRegistered(registered, validation, now);
    const claims: Claims = if (Claims == void) {} else strand.json.parseLeaky(Claims, arena, verified.payload, .{
        .ignore_unknown_fields = validation.ignore_unknown_claims,
        .limits = .{ .depth = 32 },
    }) catch return error.InvalidClaims;
    return .{ .header = verified.header, .registered = registered, .claims = claims, .key = verified.key, .payload = verified.payload };
}

fn present(raw: strand.json.Raw) bool {
    return raw.bytes.len != 0;
}

fn readRegistered(arena: std.mem.Allocator, wire: WireRegistered) VerifyError!Registered {
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
fn numericDate(bytes: []const u8) VerifyError!i64 {
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

fn checkRegistered(r: Registered, v: Validation, now: std.Io.Timestamp) VerifyError!void {
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

test {
    _ = @import("jwt_test.zig");
}
