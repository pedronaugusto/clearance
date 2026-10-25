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
    /// The header's `jwk` member as written (raw JSON), for a profile whose
    /// token carries its own key: a DPoP proof (RFC 9449 §4.2). `verify`
    /// never uses it to choose a key.
    jwk: ?[]const u8 = null,
};

/// The members of a header clearance reads; any other is passed over.
/// `crit` lists the extensions a reader must understand (RFC 7515
/// §4.1.11): clearance understands `b64` (RFC 7797) alone, and only when
/// the caller allows unencoded payloads.
const WireHeader = struct {
    alg: []const u8,
    kid: ?[]const u8 = null,
    typ: ?[]const u8 = null,
    cty: ?[]const u8 = null,
    jwk: strand.json.Raw = .{ .bytes = "" },
    b64: ?bool = null,
    crit: ?[]const []const u8 = null,
};

/// The header parameters RFC 7515 §4.1 and RFC 7518 register: never listed
/// in `crit` (§4.1.11).
const registered = [_][]const u8{ "alg", "jku", "jwk", "kid", "x5u", "x5c", "x5t", "x5t#S256", "typ", "cty", "crit", "enc", "zip", "epk", "apu", "apv", "iv", "tag", "p2s", "p2c" };

/// Checks a protected header's `crit` and `b64` (RFC 7515 §4.1.11, RFC 7797
/// §3 and §6) and returns whether the payload is base64url-encoded.
fn checkCritical(wire: WireHeader, unencoded: bool) error{ InvalidHeader, UnsupportedCritical }!bool {
    var lists_b64 = false;
    if (wire.crit) |names| {
        if (names.len == 0) return error.InvalidHeader;
        for (names, 0..) |name, i| {
            for (names[0..i]) |earlier| if (std.mem.eql(u8, earlier, name)) return error.InvalidHeader;
            for (registered) |r| if (std.mem.eql(u8, r, name)) return error.InvalidHeader;
            if (!std.mem.eql(u8, name, "b64")) return error.UnsupportedCritical;
            if (!unencoded) return error.UnsupportedCritical;
            // A listed extension must be in the header.
            if (wire.b64 == null) return error.InvalidHeader;
            lists_b64 = true;
        }
    }
    // `b64` is understood only through `crit` (RFC 7797 §6).
    if (wire.b64 != null and !lists_b64) return error.InvalidHeader;
    return wire.b64 orelse true;
}

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
    /// A DPoP proof's `htm` or `htu` is not the request's.
    request,
    /// A proof's `ath`, or a token's `cnf`, is not what binds it.
    binding,
    /// A nonce the server asked for is missing or stale.
    nonce,
    /// A token meant for one use was seen before, or the replay set is full.
    replay,
    /// A JWE names `zip`: compressed content is refused.
    compression,
    /// A JWE's PBES2 count is past the caller's bound, or its salt short.
    pbes2,
    /// A JWE's content did not decrypt: its key, its tag or its padding.
    decryption,
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
    /// The payload, when the token was sent without it (RFC 7515 Appendix
    /// F): a compact token's middle part, or a JSON document's `payload`,
    /// is then empty. Its scratch is `scratchLengthDetached`.
    detached_payload: ?[]const u8 = null,
    /// Whether a payload may be unencoded (RFC 7797: `b64` false, listed in
    /// `crit`). Off by default: a token naming `b64` is refused unless the
    /// caller expects it, as RFC 7797 §7 asks.
    unencoded: bool = false,
    /// The most signatures a JSON document may hold (general serialization).
    max_signatures: u8 = 16,
    diagnostics: ?*Diagnostics = null,
};

/// A verified JWS: its header, the payload's bytes, and the key that verified
/// it. Slices live in the scratch buffer and the key set.
pub const Verified = struct {
    header: Header,
    payload: []const u8,
    key: *const Key,
    /// The protected header, decoded: its JSON, for a caller reading
    /// members clearance does not (ACME's `nonce` and `url`).
    protected: []const u8 = "",
    /// For a JSON document: which signature verified, and that signature's
    /// unprotected header (raw JSON, never trusted: only its `kid` chose the
    /// key). The protected header is the only one integrity-protected.
    index: usize = 0,
    unprotected: ?[]const u8 = null,
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

/// How much scratch `verify` needs for a token this long whose payload of
/// `payload_len` bytes was sent apart (`Options.detached_payload`): its
/// signing input is built there too.
pub fn scratchLengthDetached(token_len: usize, payload_len: usize) usize {
    return scratchLength(token_len) + token_len + 1 + base64url.encodedLength(payload_len);
}

/// How much scratch `verifyJson` needs for a document this long (and a
/// detached payload this long, or 0): the document read, then each
/// signature's parts and signing input.
pub fn scratchLengthJson(document_len: usize, payload_len: usize) usize {
    return 4 * document_len + 2 * base64url.encodedLength(payload_len) + 4096;
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
    const parts = try split(token, options.max_bytes);
    if (scratch.len < compactScratch(token.len, options)) return error.ScratchTooSmall;
    var rest = scratch;
    const read = try readSigned(.{ .protected = parts.header, .payload = parts.payload, .signature = parts.signature, .signing_input = parts.signing_input }, options, &rest, diagnostics);
    return verifyRead(read, null, keys, options, rest, diagnostics);
}

fn compactScratch(token_len: usize, options: Options) usize {
    return if (options.detached_payload) |d| scratchLengthDetached(token_len, d.len) else scratchLength(token_len);
}

/// A read signature verified with the key its headers choose among `keys`.
fn verifyRead(read: Read, unprotected_kid: ?[]const u8, keys: []const Key, options: Options, rest: []u8, diagnostics: *Diagnostics) VerifyError!Verified {
    const alg = try allowed(read.wire.alg, options, diagnostics);
    var header = headerOf(read.wire, alg);
    if (header.kid == null) header.kid = unprotected_kid;
    const key = try select(keys, header);
    try check(key, alg, read.signing_input, read.signature, options);
    return .{ .header = header, .payload = read.payload, .key = key, .protected = read.protected, .rest = rest };
}

/// The header's algorithm, when the options allow it.
fn allowed(name: []const u8, options: Options, diagnostics: *Diagnostics) error{AlgorithmNotAllowed}!Algorithm {
    const alg = Algorithm.parse(name) orelse {
        diagnostics.check = .algorithm_unknown;
        return error.AlgorithmNotAllowed;
    };
    if (std.mem.findScalar(Algorithm, options.algorithms, alg) == null) return error.AlgorithmNotAllowed;
    return alg;
}

fn headerOf(wire: WireHeader, alg: Algorithm) Header {
    return .{ .alg = alg, .kid = wire.kid, .typ = wire.typ, .cty = wire.cty, .jwk = if (wire.jwk.bytes.len == 0) null else wire.jwk.bytes };
}

/// Verifies a compact JWS against the one key the caller has already
/// chosen, its `kid` not consulted: for a token that names its own key (a
/// DPoP proof, whose `jwk` the profile has read and checked), or a caller
/// that holds a single key by other means. The key must fit the header's
/// algorithm, which the options must allow.
pub fn verifyWith(token: []const u8, key: *const Key, options: Options, scratch: []u8) VerifyError!Verified {
    std.debug.assert(options.algorithms.len > 0);
    var diagnostics: Diagnostics = .{};
    defer if (options.diagnostics) |d| {
        d.* = diagnostics;
    };
    return verifyOne(token, key, options, scratch, &diagnostics) catch |err| {
        diagnostics.check = checkOf(err, diagnostics.check);
        return err;
    };
}

fn verifyOne(token: []const u8, key: *const Key, options: Options, scratch: []u8, diagnostics: *Diagnostics) VerifyError!Verified {
    const parts = try split(token, options.max_bytes);
    if (scratch.len < compactScratch(token.len, options)) return error.ScratchTooSmall;
    var rest = scratch;
    const read = try readSigned(.{ .protected = parts.header, .payload = parts.payload, .signature = parts.signature, .signing_input = parts.signing_input }, options, &rest, diagnostics);
    const alg = try allowed(read.wire.alg, options, diagnostics);
    if (!key.verify or !key.fits(alg)) return error.NoKey;
    try check(key, alg, read.signing_input, read.signature, options);
    return .{ .header = headerOf(read.wire, alg), .payload = read.payload, .key = key, .protected = read.protected, .rest = rest };
}

/// One signature's parts as written, from either serialization: the
/// protected header and the signature in base64url, the payload as sent
/// (base64url, or the bytes themselves when unencoded; empty when
/// detached), and the signing input when it lies in the input already.
const Piece = struct {
    protected: []const u8,
    payload: []const u8,
    signature: []const u8,
    signing_input: ?[]const u8,
};

/// A signature read: its header, the payload's bytes, the signature, and
/// what it signs, the signature not yet looked at.
const Read = struct {
    wire: WireHeader,
    protected: []const u8,
    payload: []const u8,
    signature: []const u8,
    signing_input: []const u8,
};

/// What reading a token's parts can refuse, before any key is chosen.
const ReadError = error{ Malformed, TooLarge, InvalidHeader, UnsupportedCritical, ScratchTooSmall };

/// Reads `piece` into `rest`, which moves past what it took: the protected
/// header decoded and read (`crit` and `b64` checked), the payload decoded
/// or taken as it is, the signature decoded, and the signing input built
/// when it is not in the input as it lies (a detached payload, a JSON
/// document).
fn readSigned(piece: Piece, options: Options, rest: *[]u8, diagnostics: *Diagnostics) ReadError!Read {
    const header_bytes = try decodePart(rest, piece.protected, diagnostics);
    var fixed: std.heap.FixedBufferAllocator = .init(rest.*);
    const wire = strand.json.parseLeaky(WireHeader, fixed.allocator(), header_bytes, .{
        .ignore_unknown_fields = true,
        .limits = .{ .depth = 16 },
    }) catch return error.InvalidHeader;
    rest.* = rest.*[fixed.end_index..];
    const encoded = try checkCritical(wire, options.unencoded);
    var payload_text = piece.payload;
    if (options.detached_payload) |detached| {
        if (piece.payload.len != 0) return error.Malformed;
        payload_text = detached;
    }
    // An unencoded payload in the compact form must hold no dot (RFC 7797 §5.2).
    if (!encoded and piece.signing_input != null and options.detached_payload == null and std.mem.findScalar(u8, payload_text, '.') != null) return error.Malformed;
    const signing_input = if (piece.signing_input != null and options.detached_payload == null) piece.signing_input.? else blk: {
        // header '.' payload, the payload encoded first when it is to be.
        const payload_length = if (encoded and options.detached_payload != null) base64url.encodedLength(payload_text.len) else payload_text.len;
        const length = piece.protected.len + 1 + payload_length;
        if (rest.len < length) return error.ScratchTooSmall;
        const input = rest.*[0..length];
        var w: Writer = .fixed(input);
        // unreachable: `input` is the length of what is written
        writeSigningInput(&w, piece.protected, payload_text, encoded and options.detached_payload != null) catch unreachable;
        rest.* = rest.*[length..];
        break :blk input;
    };
    const payload = if (!encoded) payload_text else if (options.detached_payload) |d| d else try decodePart(rest, payload_text, diagnostics);
    const signature = try decodePart(rest, piece.signature, diagnostics);
    return .{ .wire = wire, .protected = header_bytes, .payload = payload, .signature = signature, .signing_input = signing_input };
}

fn writeSigningInput(w: *Writer, protected: []const u8, payload: []const u8, encode: bool) Writer.Error!void {
    try w.writeAll(protected);
    try w.writeByte('.');
    if (encode) try base64url.encode(w, payload) else try w.writeAll(payload);
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
    /// The header's `jwk` member, raw, as `Header.jwk`.
    jwk: ?[]const u8 = null,
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
    const parts = try split(token, max_bytes);
    if (scratch.len < scratchLength(token.len)) return error.ScratchTooSmall;
    var rest = scratch;
    const read = try readSigned(.{ .protected = parts.header, .payload = parts.payload, .signature = parts.signature, .signing_input = parts.signing_input }, .{ .algorithms = &.{}, .max_bytes = max_bytes }, &rest, &diagnostics);
    if (read.wire.alg.len == 0 or std.ascii.eqlIgnoreCase(read.wire.alg, "none") or read.signature.len == 0) return error.Unsigned;
    return .{ .alg = read.wire.alg, .kid = read.wire.kid, .typ = read.wire.typ, .cty = read.wire.cty, .jwk = if (read.wire.jwk.bytes.len == 0) null else read.wire.jwk.bytes, .payload = read.payload, .rest = rest };
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

/// A JWS in the JSON serialization (RFC 7515 §7.2): general (`signatures`,
/// one or more) or flattened (one, its members at the top), as the document
/// is written. Verifies when one signature verifies with a key the caller's
/// `keys` gives for its headers; `Verified.index` names which, and only its
/// protected header is returned as trusted. Every signature's `alg` must be
/// in its protected header (an unprotected one could be changed in flight),
/// its protected and unprotected names disjoint (§7.2.1), `crit` and `b64`
/// protected. Strings live in `scratch` (`scratchLengthJson` bytes).
pub fn verifyJson(document: []const u8, keys: []const Key, options: Options, scratch: []u8) VerifyError!Verified {
    std.debug.assert(options.algorithms.len > 0);
    var diagnostics: Diagnostics = .{};
    defer if (options.diagnostics) |d| {
        d.* = diagnostics;
    };
    return verifyJsonChecked(document, keys, options, scratch, &diagnostics) catch |err| {
        diagnostics.check = checkOf(err, diagnostics.check);
        return err;
    };
}

const WireSignature = struct {
    protected: ?[]const u8 = null,
    header: ?strand.json.Raw = null,
    signature: []const u8,
};

const WireDocument = struct {
    payload: ?[]const u8 = null,
    signatures: ?[]const WireSignature = null,
    protected: ?[]const u8 = null,
    header: ?strand.json.Raw = null,
    signature: ?[]const u8 = null,
};

fn verifyJsonChecked(document: []const u8, keys: []const Key, options: Options, scratch: []u8, diagnostics: *Diagnostics) VerifyError!Verified {
    const limit: usize = options.max_bytes.raw();
    if (document.len > limit) return error.TooLarge;
    if (scratch.len < scratchLengthJson(document.len, if (options.detached_payload) |d| d.len else 0)) return error.ScratchTooSmall;
    var fixed: std.heap.FixedBufferAllocator = .init(scratch);
    const wire = strand.json.parseLeaky(WireDocument, fixed.allocator(), document, .{
        .ignore_unknown_fields = true,
        .limits = .{ .depth = 16 },
    }) catch {
        diagnostics.check = .shape;
        return error.Malformed;
    };
    const flattened = wire.signature != null or wire.protected != null or wire.header != null;
    if (flattened == (wire.signatures != null)) return error.Malformed;
    var one: [1]WireSignature = undefined;
    if (flattened) one[0] = .{ .protected = wire.protected, .header = wire.header, .signature = wire.signature orelse return error.Malformed };
    const signatures: []const WireSignature = if (flattened) &one else wire.signatures.?;
    if (signatures.len == 0 or signatures.len > options.max_signatures) return error.Malformed;
    const payload = wire.payload orelse "";
    if ((wire.payload == null) != (options.detached_payload != null)) return error.Malformed;
    const tail = scratch[fixed.end_index..];

    // The first signature to verify wins; else the most telling refusal.
    var refusal: ?VerifyError = null;
    for (signatures, 0..) |sig, i| {
        var rest = tail;
        var local: Diagnostics = .{};
        const attempt = verifySignature(sig, payload, keys, options, &rest, &local);
        if (attempt) |verified| {
            var out = verified;
            out.index = i;
            out.unprotected = if (sig.header) |h| h.bytes else null;
            diagnostics.* = local;
            return out;
        } else |err| {
            if (refusal == null or rank(err) >= rank(refusal.?)) {
                refusal = err;
                diagnostics.* = local;
            }
        }
    }
    return refusal.?;
}

/// How much a refusal says: a signature that failed says most, then a key
/// too weak, then a header that breaks the rules, then no key for it, then
/// an algorithm not allowed.
fn rank(err: VerifyError) u8 {
    return switch (err) {
        error.InvalidSignature => 5,
        error.WeakKey => 4,
        error.InvalidHeader, error.UnsupportedCritical, error.Malformed => 3,
        error.NoKey => 2,
        error.AlgorithmNotAllowed => 1,
        else => 0,
    };
}

fn verifySignature(sig: WireSignature, payload: []const u8, keys: []const Key, options: Options, rest: *[]u8, diagnostics: *Diagnostics) VerifyError!Verified {
    const protected = sig.protected orelse return error.InvalidHeader;
    const read = try readSigned(.{ .protected = protected, .payload = payload, .signature = sig.signature, .signing_input = null }, options, rest, diagnostics);
    var unprotected_kid: ?[]const u8 = null;
    if (sig.header) |raw| unprotected_kid = try checkUnprotected(raw.bytes, read.protected);
    return verifyRead(read, unprotected_kid, keys, options, rest.*, diagnostics);
}

/// Checks an unprotected header against the protected one (RFC 7515
/// §7.2.1: no name in both; `alg`, `crit` and `b64` protected only) and
/// returns its `kid`.
fn checkUnprotected(unprotected: []const u8, protected: []const u8) error{InvalidHeader}!?[]const u8 {
    var members: strand.json.Members = undefined;
    members.init(unprotected, .{});
    var kid: ?[]const u8 = null;
    while (members.next() catch return error.InvalidHeader) |m| {
        var name_buffer: [64]u8 = undefined;
        const name = m.nameInto(&name_buffer) catch return error.InvalidHeader;
        for ([_][]const u8{ "alg", "crit", "b64" }) |protected_only| if (std.mem.eql(u8, name, protected_only)) return error.InvalidHeader;
        var theirs: strand.json.Members = undefined;
        theirs.init(protected, .{});
        while (theirs.next() catch return error.InvalidHeader) |t| if (t.is(name)) return error.InvalidHeader;
        if (std.mem.eql(u8, name, "kid")) {
            const value = m.value;
            if (value.len < 2 or value[0] != '"' or value[value.len - 1] != '"') return error.InvalidHeader;
            const text = value[1 .. value.len - 1];
            if (std.mem.findScalar(u8, text, '\\') != null) return error.InvalidHeader;
            kid = text;
        }
    }
    return kid;
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
    /// `alg` member names or its curve implies (ES256, ES384, ES512, EdDSA; an RSA
    /// key names none). The signer borrows `private.key`.
    pub fn fromJwk(private: *const jwk.PrivateKey, alg: ?Algorithm) error{InvalidKey}!Signer {
        const chosen = alg orelse private.public.alg orelse switch (private.public.material) {
            .ec => |ec| switch (ec.curve) {
                .p256 => Algorithm.es256,
                .p384 => Algorithm.es384,
                .p521 => Algorithm.es512,
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
    /// A public key written as the header's `jwk`: a token that carries the
    /// key it is signed with (a DPoP proof, RFC 9449 §4.2; an ACME account's
    /// first request). Only its public members are written.
    jwk: ?*const Key = null,
    /// False signs the payload as it is (RFC 7797): `b64` false, listed in
    /// `crit`. A compact token's unencoded payload holds no `.`.
    b64: bool = true,
    /// More protected members, after these: ACME's `nonce` and `url` (RFC
    /// 8555 §6.2). A name clearance writes itself, or one twice, is refused.
    extra: []const Member = &.{},
};

/// A protected header member a caller adds.
pub const Member = struct {
    name: []const u8,
    value: union(enum) {
        /// Written as a JSON string.
        string: []const u8,
        /// One JSON value, written as it is.
        raw: []const u8,
    },
};

pub const SignError = error{
    /// The signer's algorithm does not fit its key, or the HMAC secret is
    /// shorter than the hash.
    InvalidKey,
    SigningFailed,
    /// An extra member named as one clearance writes, or twice; a raw value
    /// that is not one JSON value.
    InvalidHeader,
    /// An unencoded payload with a `.` in the compact serialization (RFC 7797
    /// §5.2), or signers of a JSON document that disagree on `b64`.
    InvalidPayload,
} || Writer.Error || std.mem.Allocator.Error;

/// How a payload is written beside its signatures.
pub const SignOptions = struct {
    /// Leave the payload out (RFC 7515 Appendix F): the verifier has it.
    detached: bool = false,
};

/// Writes the compact JWS of `payload` under `signer`. `io` draws the noise an
/// ECDSA, PSS or ML-DSA signature takes (RSA PKCS#1 v1.5 and Ed25519 are
/// deterministic). `gpa` holds the signing input while it is signed.
pub fn sign(gpa: std.mem.Allocator, io: std.Io, out: *Writer, header: SignHeader, payload: []const u8, signer: Signer) SignError!void {
    return signCompact(gpa, io, out, header, payload, signer, .{});
}

/// `sign` with the payload detached when `options` says so: `header..sig`.
pub fn signCompact(gpa: std.mem.Allocator, io: std.Io, out: *Writer, header: SignHeader, payload: []const u8, signer: Signer, options: SignOptions) SignError!void {
    if (!header.b64 and !options.detached and std.mem.findScalar(u8, payload, '.') != null) return error.InvalidPayload;
    var input: Writer.Allocating = .init(gpa);
    defer input.deinit();
    try writeProtected(gpa, &input.writer, header, signer.algorithm());
    const protected_length = input.written().len;
    try input.writer.writeByte('.');
    if (header.b64) try base64url.encode(&input.writer, payload) else try input.writer.writeAll(payload);
    var signature_buffer: [cloak.PrivateKey.max_signature]u8 = undefined;
    defer std.crypto.secureZero(u8, &signature_buffer);
    const signature = try signInput(io, signer, input.written(), &signature_buffer);
    if (options.detached) {
        try out.writeAll(input.written()[0..protected_length]);
        try out.writeByte('.');
    } else try out.writeAll(input.written());
    try out.writeByte('.');
    try base64url.encode(out, signature);
}

/// One signature of a JSON document: its signer, its protected header, and
/// an unprotected header (one JSON object, raw) or none.
pub const JsonSigner = struct {
    signer: Signer,
    header: SignHeader = .{},
    unprotected: ?[]const u8 = null,
};

pub const Serialization = enum {
    /// One signature, its members at the top (RFC 7515 §7.2.2).
    flattened,
    /// `signatures`, one or more (§7.2.1).
    general,
};

/// Writes `payload` as a JWS in the JSON serialization under every one of
/// `signers` (one for `flattened`): the payload once, each signature with
/// its protected header (and its unprotected one when given, whose names
/// must not be the protected header's). Every signer must agree on `b64`.
pub fn signJson(gpa: std.mem.Allocator, io: std.Io, out: *Writer, form: Serialization, payload: []const u8, signers: []const JsonSigner, options: SignOptions) SignError!void {
    if (signers.len == 0 or (form == .flattened and signers.len != 1)) return error.InvalidHeader;
    const b64 = signers[0].header.b64;
    for (signers) |s| if (s.header.b64 != b64) return error.InvalidPayload;
    try out.writeByte('{');
    if (!options.detached) {
        try out.writeAll("\"payload\":");
        if (b64) {
            try out.writeByte('"');
            try base64url.encode(out, payload);
            try out.writeByte('"');
        } else strand.json.write(out, payload, .{}) catch |err| return switch (err) {
            error.WriteFailed => error.WriteFailed,
            else => error.InvalidPayload,
        };
        try out.writeByte(',');
    }
    if (form == .general) try out.writeAll("\"signatures\":[");
    var input: Writer.Allocating = .init(gpa);
    defer input.deinit();
    for (signers, 0..) |s, i| {
        input.clearRetainingCapacity();
        try writeProtected(gpa, &input.writer, s.header, s.signer.algorithm());
        const protected_length = input.written().len;
        if (s.unprotected) |u| _ = try checkUnprotectedForSigning(u, input.written());
        try input.writer.writeByte('.');
        if (b64) try base64url.encode(&input.writer, payload) else try input.writer.writeAll(payload);
        var signature_buffer: [cloak.PrivateKey.max_signature]u8 = undefined;
        defer std.crypto.secureZero(u8, &signature_buffer);
        const signature = try signInput(io, s.signer, input.written(), &signature_buffer);
        if (i != 0) try out.writeByte(',');
        if (form == .general) try out.writeByte('{');
        try out.print("\"protected\":\"{s}\",", .{input.written()[0..protected_length]});
        if (s.unprotected) |u| try out.print("\"header\":{s},", .{u});
        try out.writeAll("\"signature\":\"");
        try base64url.encode(out, signature);
        try out.writeByte('"');
        if (form == .general) try out.writeByte('}');
    }
    if (form == .general) try out.writeByte(']');
    try out.writeByte('}');
}

/// An unprotected header a signer adds, checked as a verifier will.
fn checkUnprotectedForSigning(unprotected: []const u8, protected_b64: []const u8) SignError!void {
    var decoded: [4096]u8 = undefined;
    if ((base64url.decodedLength(protected_b64) catch return error.InvalidHeader) > decoded.len) return error.InvalidHeader;
    const protected = base64url.decode(&decoded, protected_b64) catch return error.InvalidHeader;
    _ = checkUnprotected(unprotected, protected) catch return error.InvalidHeader;
}

/// The names clearance writes into a protected header itself.
const written_names = [_][]const u8{ "alg", "typ", "cty", "kid", "jwk", "b64", "crit" };

/// Writes the protected header of `header` for `alg`, base64url.
fn writeProtected(gpa: std.mem.Allocator, out: *Writer, header: SignHeader, alg: Algorithm) SignError!void {
    for (header.extra, 0..) |m, i| {
        for (written_names) |n| if (std.mem.eql(u8, n, m.name)) return error.InvalidHeader;
        for (header.extra[0..i]) |earlier| if (std.mem.eql(u8, earlier.name, m.name)) return error.InvalidHeader;
        if (m.value == .raw) {
            var probe: std.heap.FixedBufferAllocator = .init(&.{});
            _ = strand.json.parseLeaky(strand.json.Raw, probe.allocator(), m.value.raw, .{}) catch |err| if (err != error.OutOfMemory) return error.InvalidHeader;
        }
    }
    var header_json: Writer.Allocating = .init(gpa);
    defer header_json.deinit();
    var public_jwk: Writer.Allocating = .init(gpa);
    defer public_jwk.deinit();
    if (header.jwk) |key| jwk.writePublic(&public_jwk.writer, key.*) catch |err| return switch (err) {
        error.WriteFailed => error.WriteFailed,
        error.NotPublic => error.InvalidKey,
    };
    const crit: []const []const u8 = &.{"b64"};
    var object = strand.json.writeObjectOpen(&header_json.writer, .{
        .alg = alg.name(),
        .typ = header.typ,
        .cty = header.cty,
        .kid = header.kid,
        .jwk = if (header.jwk != null) strand.json.Raw{ .bytes = public_jwk.written() } else null,
        .b64 = if (header.b64) null else false,
        .crit = if (header.b64) null else crit,
    }, .{ .nulls = .omit }) catch |err| return switch (err) {
        error.WriteFailed => error.WriteFailed,
        else => error.SigningFailed,
    };
    for (header.extra) |m| {
        const w = &header_json.writer;
        try w.writeByte(',');
        strand.json.write(w, m.name, .{}) catch |err| return switch (err) {
            error.WriteFailed => error.WriteFailed,
            else => error.InvalidHeader,
        };
        try w.writeByte(':');
        switch (m.value) {
            .string => |text| strand.json.write(w, text, .{}) catch |err| return switch (err) {
                error.WriteFailed => error.WriteFailed,
                else => error.InvalidHeader,
            },
            .raw => |raw| try w.writeAll(raw),
        }
    }
    try object.close();
    try base64url.encode(out, header_json.written());
}

/// The signature of `input` by `signer`, in `buffer`.
fn signInput(io: std.Io, signer: Signer, input: []const u8, buffer: *[cloak.PrivateKey.max_signature]u8) SignError![]const u8 {
    const alg = signer.algorithm();
    return switch (signer) {
        .hmac => |h| blk: {
            if (alg.family() != .hmac) return error.InvalidKey;
            const length = hashLength(alg.hash().?);
            if (h.secret.len < length) return error.InvalidKey;
            hmac(alg, h.secret, input, buffer[0..length]);
            break :blk buffer[0..length];
        },
        .private => |p| blk: {
            if (alg.family() == .hmac) return error.InvalidKey;
            var noise: [cloak.PrivateKey.max_noise]u8 = undefined;
            defer std.crypto.secureZero(u8, &noise);
            const noise_length = p.key.noiseLength();
            io.random(noise[0..noise_length]);
            break :blk p.key.sign(alg.signature(), input, noise[0..noise_length], buffer) catch |err| return switch (err) {
                error.UnsupportedAlgorithm => error.InvalidKey,
                error.InvalidNoise, error.SigningFailed => error.SigningFailed,
            };
        },
        .external => |e| blk: {
            const written = try e.sign(e.context, io, alg, input, buffer);
            if (written.len == 0) return error.SigningFailed;
            break :blk written;
        },
    };
}

test {
    _ = @import("jws_test.zig");
    _ = @import("jws_json_test.zig");
}
