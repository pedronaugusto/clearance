//! JWS in the compact serialization (RFC 7515 §7.1): split, read, verified
//! against keys the caller holds, and signed. Verifying allocates nothing: the
//! decoded parts and the header's values live in a scratch buffer the caller
//! gives (`scratchLength`).
const std = @import("std");
const aegis = @import("aegis");
const strand = @import("strand");
const cloak = @import("cloak");
const base64url = @import("base64url.zig");
const Algorithm = @import("Algorithm.zig").Algorithm;
const hashLength = @import("Algorithm.zig").hashLength;
const Key = @import("Key.zig");
const jwk = @import("jwk.zig");

const Writer = std.Io.Writer;
/// Sizes in options: `.literal("16KiB")`.
pub const Bytes = aegis.units.Bytes(usize);

/// The three parts of a compact JWS, as written.
pub const Parts = struct {
    header: []const u8,
    payload: []const u8,
    signature: []const u8,
    /// The header and payload with the dot between them: what is signed.
    signing_input: []const u8,
};

pub const SplitError = error{ Malformed, TooLarge };

/// Splits a compact JWS into its parts by finding its two dots, refusing a
/// third, before anything is decoded: the work is one pass and no allocation
/// whatever the input (the `strings.Split` denial of service of go-jose,
/// golang-jwt and x/oauth2 cannot happen here).
pub fn split(token: []const u8, max: Bytes) SplitError!Parts {
    const limit: usize = max.raw();
    if (token.len > limit) return error.TooLarge;
    var dots: [2]usize = undefined;
    var found: usize = 0;
    for (token, 0..) |c, i| {
        if (c != '.') continue;
        if (found == 2) return error.Malformed;
        dots[found] = i;
        found += 1;
    }
    if (found != 2) return error.Malformed;
    return .{
        .header = token[0..dots[0]],
        .payload = token[dots[0] + 1 .. dots[1]],
        .signature = token[dots[1] + 1 ..],
        .signing_input = token[0..dots[1]],
    };
}

/// A protected header as read. Strings borrow from the scratch buffer.
pub const Header = struct {
    alg: Algorithm,
    kid: ?[]const u8 = null,
    typ: ?[]const u8 = null,
    cty: ?[]const u8 = null,
};

/// The members of a header clearance reads; any other is passed over. `crit`
/// is read only to refuse it: clearance understands no extension that would
/// have to be listed there (RFC 7515 §4.1.11), `b64` (RFC 7797) included.
const WireHeader = struct {
    alg: []const u8,
    kid: ?[]const u8 = null,
    typ: ?[]const u8 = null,
    cty: ?[]const u8 = null,
    crit: strand.json.Raw = .{ .bytes = "" },
};

/// Which check refused a token, for logs; never send more than its name to a
/// peer.
pub const Check = enum {
    none,
    size,
    shape,
    encoding,
    header,
    algorithm_unknown,
    algorithm_not_allowed,
    critical,
    key,
    key_strength,
    signature,
    claims,
    type,
    issuer,
    audience,
    subject,
    expired,
    not_yet_valid,
    too_old,
    required,
    scratch,
};

pub const Diagnostics = struct { check: Check = .none };

pub const Options = struct {
    /// The algorithms the caller accepts: at least one. There is no default:
    /// which algorithms a token may use is the verifier's decision, never the
    /// token's (RFC 8725 §3.1).
    algorithms: []const Algorithm,
    /// The longest token read; the parts' sizes follow from it.
    max_bytes: Bytes = .literal("16KiB"),
    /// RSA keys shorter than this are refused (RFC 7518 §3.3 asks 2048).
    min_rsa_bits: u16 = 2048,
    diagnostics: ?*Diagnostics = null,
};

/// A verified JWS: its header, the payload's bytes, and the key that verified
/// it. Slices live in the scratch buffer and the key set.
pub const Verified = struct {
    header: Header,
    payload: []const u8,
    key: *const Key,
    /// What of the scratch buffer is still free.
    rest: []u8,
};

pub const VerifyError = error{
    /// Too long, not three parts, or a part that is not base64url.
    Malformed,
    TooLarge,
    /// The header is not a JSON object with a string `alg`.
    InvalidHeader,
    /// The header names an algorithm clearance does not have (`none` among
    /// them) or one the caller did not allow.
    AlgorithmNotAllowed,
    /// The header lists critical extensions.
    UnsupportedCritical,
    /// No key fits: none with the token's `kid`, or none of the algorithm's
    /// kind; or several without a `kid` to choose by.
    NoKey,
    /// The chosen key is shorter than the algorithm allows.
    WeakKey,
    InvalidSignature,
    /// The scratch buffer is shorter than `scratchLength(token)`.
    ScratchTooSmall,
};

/// How much scratch `verify` needs for a token this long: room for its
/// decoded parts and the header's values.
pub fn scratchLength(token_len: usize) usize {
    return token_len + 1024;
}

/// Verifies a compact JWS against `keys`: the header's `alg` must be one the
/// options allow; the key is the one whose `kid` is the header's, or, when the
/// header names none, the only key that fits; the header's `jwk`, `jku`, `x5u`
/// and `x5c` never choose or fetch a key (RFC 8725 §3.10).
pub fn verify(token: []const u8, keys: []const Key, options: Options, scratch: []u8) VerifyError!Verified {
    std.debug.assert(options.algorithms.len > 0);
    var diagnostics: Diagnostics = .{};
    defer if (options.diagnostics) |d| {
        d.* = diagnostics;
    };
    return verifyParts(token, keys, options, scratch, &diagnostics) catch |err| {
        diagnostics.check = checkOf(err, diagnostics.check);
        return err;
    };
}

fn checkOf(err: VerifyError, found: Check) Check {
    return switch (err) {
        error.Malformed => if (found == .none) .shape else found,
        error.TooLarge => .size,
        error.InvalidHeader => .header,
        error.AlgorithmNotAllowed => if (found == .none) .algorithm_not_allowed else found,
        error.UnsupportedCritical => .critical,
        error.NoKey => .key,
        error.WeakKey => .key_strength,
        error.InvalidSignature => .signature,
        error.ScratchTooSmall => .scratch,
    };
}

fn verifyParts(token: []const u8, keys: []const Key, options: Options, scratch: []u8, diagnostics: *Diagnostics) VerifyError!Verified {
    const read = try readParts(token, options.max_bytes, scratch, diagnostics);
    const alg = Algorithm.parse(read.wire.alg) orelse {
        diagnostics.check = .algorithm_unknown;
        return error.AlgorithmNotAllowed;
    };
    if (std.mem.findScalar(Algorithm, options.algorithms, alg) == null) return error.AlgorithmNotAllowed;
    const header: Header = .{ .alg = alg, .kid = read.wire.kid, .typ = read.wire.typ, .cty = read.wire.cty };

    const key = try select(keys, header);
    try check(key, alg, read.signing_input, read.signature, options);
    return .{ .header = header, .payload = read.payload, .key = key, .rest = read.rest };
}

/// A compact JWS split, its parts decoded and its header read, the
/// signature not yet looked at.
const Read = struct {
    wire: WireHeader,
    payload: []const u8,
    signature: []const u8,
    signing_input: []const u8,
    rest: []u8,
};

/// What reading a token's parts can refuse, before any key is chosen.
const ReadError = error{ Malformed, TooLarge, InvalidHeader, UnsupportedCritical, ScratchTooSmall };

fn readParts(token: []const u8, max_bytes: Bytes, scratch: []u8, diagnostics: *Diagnostics) ReadError!Read {
    const parts = try split(token, max_bytes);
    if (scratch.len < scratchLength(token.len)) return error.ScratchTooSmall;
    var rest = scratch;
    const header_bytes = try decodePart(&rest, parts.header, diagnostics);
    const payload = try decodePart(&rest, parts.payload, diagnostics);
    const signature = try decodePart(&rest, parts.signature, diagnostics);

    var fixed: std.heap.FixedBufferAllocator = .init(rest);
    const wire = strand.json.parseLeaky(WireHeader, fixed.allocator(), header_bytes, .{
        .ignore_unknown_fields = true,
        .limits = .{ .depth = 16 },
    }) catch return error.InvalidHeader;
    if (wire.crit.bytes.len != 0) return error.UnsupportedCritical;
    return .{ .wire = wire, .payload = payload, .signature = signature, .signing_input = parts.signing_input, .rest = rest[fixed.end_index..] };
}

/// A JWS read but not verified: its header and payload, for a holder that
/// passes the token on to the party that verifies it (an ID-JAG on its way
/// to the authorization server it is for) and checks only that it is what it
/// asked for. Never a reason to trust its content: `verify` is.
pub const Inspected = struct {
    /// The header's `alg` as written: any algorithm but `none`, which a
    /// signed token never names, clearance's own or not.
    alg: []const u8,
    kid: ?[]const u8 = null,
    typ: ?[]const u8 = null,
    cty: ?[]const u8 = null,
    payload: []const u8,
    /// What of the scratch buffer is still free.
    rest: []u8,
};

pub const InspectError = ReadError || error{
    /// The header's `alg` is `none` or empty, or the signature is empty: not
    /// a signed token.
    Unsigned,
};

/// Reads a compact JWS without verifying it, under the same bounds and the
/// same header rules as `verify`: three parts of strict base64url, a header
/// that is a JSON object with a string `alg` and no `crit`. A token without
/// a signature (`alg` `none`, an empty third part) is refused. Slices live in
/// `scratch` (at least `scratchLength(token.len)` bytes).
pub fn inspect(token: []const u8, max_bytes: Bytes, scratch: []u8) InspectError!Inspected {
    var diagnostics: Diagnostics = .{};
    const read = try readParts(token, max_bytes, scratch, &diagnostics);
    if (read.wire.alg.len == 0 or std.ascii.eqlIgnoreCase(read.wire.alg, "none") or read.signature.len == 0) return error.Unsigned;
    return .{ .alg = read.wire.alg, .kid = read.wire.kid, .typ = read.wire.typ, .cty = read.wire.cty, .payload = read.payload, .rest = read.rest };
}

fn decodePart(rest: *[]u8, text: []const u8, diagnostics: *Diagnostics) ReadError![]const u8 {
    const length = base64url.decodedLength(text) catch {
        diagnostics.check = .encoding;
        return error.Malformed;
    };
    if (rest.len < length) return error.ScratchTooSmall;
    const decoded = base64url.decode(rest.*, text) catch {
        diagnostics.check = .encoding;
        return error.Malformed;
    };
    rest.* = rest.*[length..];
    return decoded;
}

/// The key a header names among `keys`.
pub fn select(keys: []const Key, header: Header) error{NoKey}!*const Key {
    var chosen: ?*const Key = null;
    for (keys) |*key| {
        if (!key.verify or !key.fits(header.alg)) continue;
        if (header.kid) |kid| {
            const own = key.kid orelse continue;
            if (!std.mem.eql(u8, own, kid)) continue;
        }
        if (chosen != null) return error.NoKey; // two candidates: nothing to choose by
        chosen = key;
    }
    return chosen orelse error.NoKey;
}

fn check(key: *const Key, alg: Algorithm, signing_input: []const u8, signature: []const u8, options: Options) VerifyError!void {
    switch (key.material) {
        .hmac => |secret| {
            const length = hashLength(alg.hash().?);
            // RFC 7518 §3.2: a key at least as long as the hash.
            if (secret.len < length) return error.WeakKey;
            var mac: [64]u8 = undefined;
            hmac(alg, secret, signing_input, mac[0..length]);
            defer std.crypto.secureZero(u8, &mac);
            const same = aegis.secret.equalBytes(mac[0..length], signature) catch return error.InvalidSignature;
            if (!same.declassify("a refused MAC ends the verification")) return error.InvalidSignature;
        },
        .rsa => |rsa| {
            if (bits(rsa.n) < options.min_rsa_bits) return error.WeakKey;
            cloak.certificates.signature.verify(key.public().?, alg.signature(), signing_input, signature) catch return error.InvalidSignature;
        },
        .ec, .okp => cloak.certificates.signature.verify(key.public().?, alg.signature(), signing_input, signature) catch return error.InvalidSignature,
    }
}

fn bits(big_endian: []const u8) usize {
    for (big_endian, 0..) |byte, i| {
        if (byte != 0) return (big_endian.len - i) * 8 - @clz(byte);
    }
    return 0;
}

fn hmac(alg: Algorithm, secret: []const u8, message: []const u8, out: []u8) void {
    const H = std.crypto.auth.hmac.sha2;
    switch (alg) {
        .hs256 => H.HmacSha256.create(out[0..32], message, secret),
        .hs384 => H.HmacSha384.create(out[0..48], message, secret),
        .hs512 => H.HmacSha512.create(out[0..64], message, secret),
        else => unreachable,
    }
}

/// What signs: an HMAC secret, a cloak private key with the algorithm it
/// signs with, or a signer outside the process (a KMS, an HSM, an agent),
/// the key never in clearance's memory.
pub const Signer = union(enum) {
    hmac: struct { alg: Algorithm, secret: []const u8 },
    private: struct { alg: Algorithm, key: cloak.PrivateKey },
    external: External,

    /// A signer clearance asks for the signature over the signing input it
    /// built: the header and claims stay clearance's to write.
    pub const External = struct {
        alg: Algorithm,
        context: ?*anyopaque = null,
        /// Signs `input` with `alg`, writing the signature as JWS has it
        /// (ECDSA's `r || s`, RFC 7518 §3.4) into `out`; returns what it
        /// wrote.
        sign: *const fn (context: ?*anyopaque, io: std.Io, alg: Algorithm, input: []const u8, out: *[max_signature]u8) error{SigningFailed}![]const u8,
    };

    /// The longest signature an external signer writes.
    pub const max_signature = cloak.PrivateKey.max_signature;

    pub fn algorithm(s: Signer) Algorithm {
        return switch (s) {
            inline else => |v| v.alg,
        };
    }

    /// A private JWK signing with `alg`, or, when null, the algorithm its
    /// `alg` member names or its curve implies (ES256, ES384, EdDSA; an RSA
    /// key names none). The signer borrows `private.key`.
    pub fn fromJwk(private: *const jwk.PrivateKey, alg: ?Algorithm) error{InvalidKey}!Signer {
        const chosen = alg orelse private.public.alg orelse switch (private.public.material) {
            .ec => |ec| switch (ec.curve) {
                .p256 => Algorithm.es256,
                .p384 => Algorithm.es384,
            },
            .okp => Algorithm.eddsa,
            .rsa, .hmac => return error.InvalidKey,
        };
        if (!private.public.fits(chosen)) return error.InvalidKey;
        return .{ .private = .{ .alg = chosen, .key = private.key } };
    }
};

/// The header a signer writes: `alg` from the signer, then these.
pub const SignHeader = struct {
    kid: ?[]const u8 = null,
    typ: ?[]const u8 = null,
    cty: ?[]const u8 = null,
};

pub const SignError = error{
    /// The signer's algorithm does not fit its key, or the HMAC secret is
    /// shorter than the hash.
    InvalidKey,
    SigningFailed,
} || Writer.Error || std.mem.Allocator.Error;

/// Writes the compact JWS of `payload` under `signer`. `io` draws the noise an
/// ECDSA, PSS or ML-DSA signature takes (RSA PKCS#1 v1.5 and Ed25519 are
/// deterministic). `gpa` holds the signing input while it is signed.
pub fn sign(gpa: std.mem.Allocator, io: std.Io, out: *Writer, header: SignHeader, payload: []const u8, signer: Signer) SignError!void {
    const alg = signer.algorithm();
    var input: Writer.Allocating = .init(gpa);
    defer input.deinit();
    var header_json: Writer.Allocating = .init(gpa);
    defer header_json.deinit();
    strand.json.write(&header_json.writer, .{
        .alg = alg.name(),
        .typ = header.typ,
        .cty = header.cty,
        .kid = header.kid,
    }, .{ .nulls = .omit }) catch |err| return switch (err) {
        error.WriteFailed => error.WriteFailed,
        else => error.SigningFailed,
    };
    try base64url.encode(&input.writer, header_json.written());
    try input.writer.writeByte('.');
    try base64url.encode(&input.writer, payload);
    const signing_input = input.written();

    var signature_buffer: [cloak.PrivateKey.max_signature]u8 = undefined;
    const signature: []const u8 = switch (signer) {
        .hmac => |h| blk: {
            if (alg.family() != .hmac) return error.InvalidKey;
            const length = hashLength(alg.hash().?);
            if (h.secret.len < length) return error.InvalidKey;
            hmac(alg, h.secret, signing_input, signature_buffer[0..length]);
            break :blk signature_buffer[0..length];
        },
        .private => |p| blk: {
            if (alg.family() == .hmac) return error.InvalidKey;
            var noise: [cloak.PrivateKey.max_noise]u8 = undefined;
            defer std.crypto.secureZero(u8, &noise);
            const noise_length = p.key.noiseLength();
            io.random(noise[0..noise_length]);
            break :blk p.key.sign(alg.signature(), signing_input, noise[0..noise_length], &signature_buffer) catch |err| return switch (err) {
                error.UnsupportedAlgorithm => error.InvalidKey,
                error.InvalidNoise, error.SigningFailed => error.SigningFailed,
            };
        },
        .external => |e| blk: {
            const written = try e.sign(e.context, io, alg, signing_input, &signature_buffer);
            if (written.len == 0) return error.SigningFailed;
            break :blk written;
        },
    };
    defer std.crypto.secureZero(u8, &signature_buffer);
    try out.writeAll(signing_input);
    try out.writeByte('.');
    try base64url.encode(out, signature);
}

test {
    _ = @import("jws_test.zig");
}
