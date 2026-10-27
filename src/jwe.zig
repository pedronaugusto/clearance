//! JWE (RFC 7516) in its compact and JSON serializations, the safe subset of
//! RFC 7518's algorithms: decrypted with keys the caller holds, under
//! allowlists the caller gives, and encrypted to one recipient or many.
//!
//! What is refused by construction: RSA1_5 (no `KeyManagement` value spells
//! it), compressed content (`zip`, wherever it is named: decompression bombs
//! and the compression oracle), a PBES2 count past the caller's bound or a
//! salt under 8 bytes, an `epk` that is not a point of the recipient key's
//! curve (cloak's check; X25519's all-zero secret refused), and a key chosen
//! by the token (`jku`, `jwk`, `x5u`, `x5c` are never read). Every failure
//! to recover the content key goes on with a random one, so the content's
//! tag fails alike (RFC 7516 §11.5): one `DecryptionFailed`, the check's name
//! in `Diagnostics` only. Content keys and derived keys live in wiped memory;
//! the plaintext lives in the caller's scratch buffer.
const std = @import("std");
const strand = @import("strand");
const cloak = @import("cloak");
const base64url = @import("base64url.zig");
const algorithms = @import("Algorithm.zig");
const Key = @import("Key.zig");
const jwk = @import("jwk.zig");
const jws = @import("jws.zig");

pub const KeyManagement = algorithms.KeyManagement;
pub const ContentEncryption = algorithms.ContentEncryption;
pub const Bytes = jws.Bytes;
pub const Check = jws.Check;
pub const Diagnostics = jws.Diagnostics;

const Writer = std.Io.Writer;
const Aes128Gcm = cloak.cipher.AesGcm(128);
const Aes256Gcm = cloak.cipher.AesGcm(256);

/// The longest content key: A256CBC-HS512's.
const max_cek = 64;

/// A recipient's decryption key: what a JWE's key-management algorithm
/// needs to recover the content key, with the JWK members that bind it.
pub const DecryptionKey = struct {
    material: Material,
    kid: ?[]const u8 = null,
    /// The only algorithm the key is used with, when set (a JWK's `alg`).
    management: ?KeyManagement = null,
    /// For a `dir` key: the one content encryption it is the key of.
    content: ?ContentEncryption = null,

    pub const Material = union(enum) {
        /// An RSA key (RSA-OAEP*), or an EC or X25519 key (ECDH-ES*), held
        /// by cloak, of the kind named.
        private: struct { key: cloak.PrivateKey, kind: PrivateKind },
        /// An AES key (A*KW, A*GCMKW) or a content key (`dir`). Borrowed.
        secret: []const u8,
        /// A password (PBES2). Borrowed.
        password: []const u8,
    };

    pub const PrivateKind = enum { rsa, p256, p384, x25519 };

    /// A private JWK read for decrypting (`jwk.PrivateKey.parse` with
    /// `.purpose = .encryption`). Borrows `private`.
    pub fn fromJwk(private: *const jwk.PrivateKey) error{InvalidKey}!DecryptionKey {
        const public = private.public;
        if (public.use == .sig or !public.decrypt) return error.InvalidKey;
        const kind: PrivateKind = switch (public.material) {
            .rsa => .rsa,
            .ec => |ec| switch (ec.curve) {
                .p256 => .p256,
                .p384 => .p384,
                .p521 => return error.InvalidKey,
            },
            .okp => |okp| if (okp.curve == .x25519) .x25519 else return error.InvalidKey,
            .hmac => return error.InvalidKey,
        };
        return .{ .material = .{ .private = .{ .key = private.key, .kind = kind } }, .kid = public.kid, .management = public.management };
    }

    /// An `oct` key from a set read for encryption with `secrets`: an AES
    /// key or a content key. Borrows the set.
    pub fn fromSecret(key: Key) error{InvalidKey}!DecryptionKey {
        if (key.material != .hmac or key.use == .sig or !key.decrypt or key.alg != null) return error.InvalidKey;
        return .{ .material = .{ .secret = key.material.hmac }, .kid = key.kid, .management = key.management, .content = key.content };
    }

    /// Whether the key may recover a content key under `alg` for `enc`.
    pub fn fits(key: DecryptionKey, alg: KeyManagement, enc: ContentEncryption) bool {
        if (key.management) |own| if (own != alg) return false;
        if (key.content) |own| if (alg != .dir or own != enc) return false;
        return switch (alg.kind()) {
            .rsa => key.material == .private and key.material.private.kind == .rsa,
            .agreement => key.material == .private and key.material.private.kind != .rsa,
            .wrap, .gcm_wrap => key.material == .secret and key.material.secret.len == alg.wrapLength().?,
            .direct => key.material == .secret and key.material.secret.len == enc.keyLength(),
            .password => key.material == .password and key.material.password.len > 0,
        };
    }
};

pub const Options = struct {
    /// The key-management algorithms the caller accepts: at least one, no
    /// default (as JWS's, RFC 8725 §3.1).
    key_algorithms: []const KeyManagement,
    /// The content encryptions the caller accepts: at least one.
    encryptions: []const ContentEncryption,
    max_bytes: Bytes = .literal("64KiB"),
    /// The most PBES2 iterations a token may ask for (jose's default).
    max_pbes2_count: u32 = 10_000,
    /// The most recipients a JSON document may name.
    max_recipients: u8 = 16,
    diagnostics: ?*Diagnostics = null,
};

/// A decrypted JWE's joint header as read. Strings borrow the scratch
/// buffer.
pub const Header = struct {
    alg: KeyManagement,
    enc: ContentEncryption,
    kid: ?[]const u8 = null,
    typ: ?[]const u8 = null,
    /// `JWT` for a nested JWT (RFC 7519 §5.2): verify the plaintext next.
    cty: ?[]const u8 = null,
};

pub const Decrypted = struct {
    header: Header,
    /// The content, in the scratch buffer: the caller erases it when done.
    plaintext: []u8,
    /// Which recipient's key decrypted it (0 for the compact serialization).
    index: usize,
    /// The protected header's JSON, decoded.
    protected: []const u8,
};

pub const DecryptError = error{
    /// Not five parts, or a JSON document of the wrong shape, or a part
    /// that is not base64url.
    Malformed,
    TooLarge,
    /// Headers that break the rules: `alg` or `enc` missing, a name in two
    /// of them, `crit` unprotected or empty or naming a registered member,
    /// an `epk` of the wrong curve or off it, a PBES2 count past the bound
    /// or a salt too short, an IV or tag of the wrong length.
    InvalidHeader,
    /// `crit` names an extension: clearance understands none for JWE.
    UnsupportedCritical,
    /// The content is compressed (`zip`).
    Compressed,
    /// `alg` or `enc` is not one the caller accepts (or not one clearance
    /// has: RSA1_5, the A192 variants).
    AlgorithmNotAllowed,
    /// No held key fits a recipient, or two do and the header names none.
    NoKey,
    /// The content did not decrypt: every cryptographic failure.
    DecryptionFailed,
    ScratchTooSmall,
};

/// How long the scratch buffer of `decrypt` must be for a token of
/// `token_len` bytes: its parts decoded, the plaintext, the headers read.
pub fn scratchLength(token_len: usize) usize {
    return 3 * token_len + 8192;
}

/// The members of a JWE header clearance reads; any other is passed over.
const WireHeader = struct {
    alg: ?[]const u8 = null,
    enc: ?[]const u8 = null,
    zip: ?strand.json.Raw = null,
    kid: ?[]const u8 = null,
    typ: ?[]const u8 = null,
    cty: ?[]const u8 = null,
    epk: ?strand.json.Raw = null,
    apu: ?[]const u8 = null,
    apv: ?[]const u8 = null,
    iv: ?[]const u8 = null,
    tag: ?[]const u8 = null,
    p2s: ?[]const u8 = null,
    p2c: ?u32 = null,
    crit: ?[]const []const u8 = null,

    /// `a`'s members, then `b`'s where `a` has none: headers proven
    /// disjoint, so no member is chosen over another.
    fn merge(a: WireHeader, b: WireHeader) WireHeader {
        var out = a;
        inline for (comptime @typeInfo(WireHeader).@"struct".field_names) |name| {
            if (@field(out, name) == null) @field(out, name) = @field(b, name);
        }
        return out;
    }
};

const WireRecipient = struct {
    header: ?strand.json.Raw = null,
    encrypted_key: ?[]const u8 = null,
};

const WireDocument = struct {
    protected: ?[]const u8 = null,
    unprotected: ?strand.json.Raw = null,
    header: ?strand.json.Raw = null,
    encrypted_key: ?[]const u8 = null,
    recipients: ?[]const WireRecipient = null,
    aad: ?[]const u8 = null,
    iv: []const u8,
    ciphertext: []const u8,
    tag: []const u8,
};

/// The header parameters RFC 7516 §4.1 and RFC 7518 register: never named
/// in `crit`.
const registered = [_][]const u8{ "alg", "enc", "zip", "jku", "jwk", "kid", "x5u", "x5c", "x5t", "x5t#S256", "typ", "cty", "crit", "epk", "apu", "apv", "iv", "tag", "p2s", "p2c" };

/// One recipient as written: its own header and encrypted key.
const Written = struct { header: ?[]const u8, encrypted_key: []const u8 };

/// The parts of a JWE every recipient shares.
const Shared = struct {
    /// The protected header as written (base64url): the AAD's start.
    protected_b64: []const u8,
    protected: []const u8,
    protected_wire: WireHeader,
    unprotected: ?[]const u8,
    aad_b64: ?[]const u8,
    iv: []const u8,
    ciphertext: []const u8,
    tag: []const u8,
    /// Decoded once for every recipient, with the AAD and the plaintext's
    /// buffer.
    iv_bytes: []const u8 = "",
    tag_bytes: []const u8 = "",
    ciphertext_bytes: []const u8 = "",
    aad: []const u8 = "",
    plaintext: []u8 = &.{},
};

/// Decrypts a JWE, compact or JSON (by its first byte), with the one of
/// `keys` that fits a recipient: the first recipient whose key is held and
/// whose content decrypts wins. `io` draws an RSA blinding seed and the
/// random content key a failed recovery goes on with. Strings and the
/// plaintext live in `scratch` (`scratchLength(token.len)` bytes).
pub fn decrypt(io: std.Io, token: []const u8, keys: []const DecryptionKey, options: Options, scratch: []u8) DecryptError!Decrypted {
    std.debug.assert(options.key_algorithms.len > 0);
    std.debug.assert(options.encryptions.len > 0);
    var diagnostics: Diagnostics = .{};
    defer if (options.diagnostics) |d| {
        d.* = diagnostics;
    };
    return decryptChecked(io, token, keys, options, scratch, &diagnostics) catch |err| {
        if (diagnostics.check == .none) diagnostics.check = switch (err) {
            error.Malformed => .shape,
            error.TooLarge => .size,
            error.InvalidHeader => .header,
            error.UnsupportedCritical => .critical,
            error.Compressed => .compression,
            error.AlgorithmNotAllowed => .algorithm_not_allowed,
            error.NoKey => .key,
            error.DecryptionFailed => .decryption,
            error.ScratchTooSmall => .scratch,
        };
        return err;
    };
}

fn decryptChecked(io: std.Io, token: []const u8, keys: []const DecryptionKey, options: Options, scratch: []u8, diagnostics: *Diagnostics) DecryptError!Decrypted {
    const limit: usize = options.max_bytes.raw();
    if (token.len > limit) return error.TooLarge;
    if (scratch.len < scratchLength(token.len)) return error.ScratchTooSmall;
    var fixed: std.heap.FixedBufferAllocator = .init(scratch);
    const arena = fixed.allocator();
    var one: [1]Written = undefined;
    var shared: Shared = undefined;
    var recipients: []const Written = &one;
    if (token.len > 0 and token[0] == '{') {
        const wire = strand.json.parseLeaky(WireDocument, arena, token, .{ .ignore_unknown_fields = true, .limits = .{ .depth = 16 } }) catch |err| return switch (err) {
            error.OutOfMemory => error.ScratchTooSmall,
            else => error.Malformed,
        };
        const flattened = wire.header != null or wire.encrypted_key != null;
        if (flattened and wire.recipients != null) return error.Malformed;
        if (wire.recipients) |list| {
            if (list.len == 0 or list.len > options.max_recipients) return error.Malformed;
            const all = arena.alloc(Written, list.len) catch return error.ScratchTooSmall;
            for (list, all) |r, *out| out.* = .{ .header = if (r.header) |h| h.bytes else null, .encrypted_key = r.encrypted_key orelse "" };
            recipients = all;
        } else one[0] = .{ .header = if (wire.header) |h| h.bytes else null, .encrypted_key = wire.encrypted_key orelse "" };
        shared = .{
            .protected_b64 = wire.protected orelse "",
            .protected = "",
            .protected_wire = .{},
            .unprotected = if (wire.unprotected) |u| u.bytes else null,
            .aad_b64 = wire.aad,
            .iv = wire.iv,
            .ciphertext = wire.ciphertext,
            .tag = wire.tag,
        };
    } else {
        var dots: [4]usize = undefined;
        var found: usize = 0;
        for (token, 0..) |c, i| {
            if (c != '.') continue;
            if (found == 4) return error.Malformed;
            dots[found] = i;
            found += 1;
        }
        if (found != 4) return error.Malformed;
        one[0] = .{ .header = null, .encrypted_key = token[dots[0] + 1 .. dots[1]] };
        shared = .{
            .protected_b64 = token[0..dots[0]],
            .protected = "",
            .protected_wire = .{},
            .unprotected = null,
            .aad_b64 = null,
            .iv = token[dots[1] + 1 .. dots[2]],
            .ciphertext = token[dots[2] + 1 .. dots[3]],
            .tag = token[dots[3] + 1 ..],
        };
        // The compact serialization's header is all protected.
        if (shared.protected_b64.len == 0) return error.InvalidHeader;
    }
    if (shared.protected_b64.len > 0) {
        shared.protected = try decodeAlloc(arena, shared.protected_b64);
        shared.protected_wire = try readHeader(arena, shared.protected);
    }
    try checkCritical(shared.protected_wire);
    shared.iv_bytes = try decodeAlloc(arena, shared.iv);
    shared.tag_bytes = try decodeAlloc(arena, shared.tag);
    shared.ciphertext_bytes = try decodeAlloc(arena, shared.ciphertext);
    shared.plaintext = arena.alloc(u8, shared.ciphertext_bytes.len) catch return error.ScratchTooSmall;
    // AAD: the protected header as written, then `.` and the JSON `aad`.
    const aad_length = shared.protected_b64.len + if (shared.aad_b64) |a| 1 + a.len else 0;
    const aad = arena.alloc(u8, aad_length) catch return error.ScratchTooSmall;
    @memcpy(aad[0..shared.protected_b64.len], shared.protected_b64);
    if (shared.aad_b64) |a| {
        _ = base64url.decodedLength(a) catch return error.Malformed;
        aad[shared.protected_b64.len] = '.';
        @memcpy(aad[shared.protected_b64.len + 1 ..], a);
    }
    shared.aad = aad;
    var unprotected_wire: WireHeader = .{};
    if (shared.unprotected) |u| {
        unprotected_wire = try readHeader(arena, u);
        if (unprotected_wire.crit != null) return error.InvalidHeader;
        try checkDisjoint(u, shared.protected);
    }

    var refusal: ?DecryptError = null;
    var refused: Diagnostics = .{};
    for (recipients, 0..) |r, index| {
        var local: Diagnostics = .{};
        const attempt = decryptRecipient(io, arena, &shared, unprotected_wire, r, keys, options, &local);
        if (attempt) |out| {
            var decrypted = out;
            decrypted.index = index;
            diagnostics.* = local;
            return decrypted;
        } else |err| {
            if (refusal == null or rank(err) >= rank(refusal.?)) {
                refusal = err;
                refused = local;
            }
        }
    }
    diagnostics.* = refused;
    return refusal.?;
}

/// How much a refusal says: content that did not decrypt says most, then a
/// header that breaks the rules, then no key, then an algorithm not allowed.
fn rank(err: DecryptError) u8 {
    return switch (err) {
        error.DecryptionFailed => 5,
        error.InvalidHeader, error.UnsupportedCritical, error.Compressed, error.Malformed => 3,
        error.NoKey => 2,
        error.AlgorithmNotAllowed => 1,
        error.TooLarge, error.ScratchTooSmall => 6,
    };
}

fn decryptRecipient(io: std.Io, arena: std.mem.Allocator, shared: *const Shared, unprotected: WireHeader, r: Written, keys: []const DecryptionKey, options: Options, diagnostics: *Diagnostics) DecryptError!Decrypted {
    var own: WireHeader = .{};
    if (r.header) |h| {
        own = try readHeader(arena, h);
        if (own.crit != null) return error.InvalidHeader;
        try checkDisjoint(h, shared.protected);
        if (shared.unprotected) |u| try checkDisjoint(h, u);
    }
    const joint = shared.protected_wire.merge(unprotected).merge(own);
    if (joint.zip != null) {
        diagnostics.check = .compression;
        return error.Compressed;
    }
    const alg_name = joint.alg orelse return error.InvalidHeader;
    const enc_name = joint.enc orelse return error.InvalidHeader;
    const alg = KeyManagement.parse(alg_name) orelse {
        diagnostics.check = .algorithm_unknown;
        return error.AlgorithmNotAllowed;
    };
    const enc = ContentEncryption.parse(enc_name) orelse {
        diagnostics.check = .algorithm_unknown;
        return error.AlgorithmNotAllowed;
    };
    if (std.mem.findScalar(KeyManagement, options.key_algorithms, alg) == null or std.mem.findScalar(ContentEncryption, options.encryptions, enc) == null) {
        diagnostics.check = .algorithm_not_allowed;
        return error.AlgorithmNotAllowed;
    }
    const key = try select(keys, joint.kid, alg, enc);

    const encrypted_key = try decodeAlloc(arena, r.encrypted_key);
    if (shared.iv_bytes.len != enc.ivLength() or shared.tag_bytes.len != enc.tagLength()) return error.InvalidHeader;

    var cek_buffer: [max_cek]u8 = undefined;
    defer std.crypto.secureZero(u8, &cek_buffer);
    const cek = cek_buffer[0..enc.keyLength()];
    try recoverKey(io, arena, key, alg, enc, joint, encrypted_key, options, cek, diagnostics);

    const opened = openContent(enc, shared.plaintext, shared.ciphertext_bytes, shared.tag_bytes, shared.aad, shared.iv_bytes, cek) catch {
        diagnostics.check = .decryption;
        return error.DecryptionFailed;
    };
    return .{
        .header = .{ .alg = alg, .enc = enc, .kid = joint.kid, .typ = joint.typ, .cty = joint.cty },
        .plaintext = opened,
        .index = 0,
        .protected = shared.protected,
    };
}

fn readHeader(arena: std.mem.Allocator, json: []const u8) DecryptError!WireHeader {
    return strand.json.parseLeaky(WireHeader, arena, json, .{ .ignore_unknown_fields = true, .limits = .{ .depth = 16 } }) catch |err| switch (err) {
        error.OutOfMemory => error.ScratchTooSmall,
        else => error.InvalidHeader,
    };
}

fn decodeAlloc(arena: std.mem.Allocator, text: []const u8) DecryptError![]u8 {
    const length = base64url.decodedLength(text) catch return error.Malformed;
    const out = arena.alloc(u8, length) catch return error.ScratchTooSmall;
    return base64url.decode(out, text) catch error.Malformed;
}

/// `crit` (RFC 7516 §4.1.13): never empty, no name twice, no registered
/// name; any extension it names is one clearance does not understand.
fn checkCritical(wire: WireHeader) DecryptError!void {
    const names = wire.crit orelse return;
    if (names.len == 0) return error.InvalidHeader;
    for (names, 0..) |name, i| {
        for (names[0..i]) |earlier| if (std.mem.eql(u8, earlier, name)) return error.InvalidHeader;
        for (registered) |r| if (std.mem.eql(u8, r, name)) return error.InvalidHeader;
    }
    return error.UnsupportedCritical;
}

/// Two headers name no member in common (RFC 7516 §7.2.1).
fn checkDisjoint(a: []const u8, b: []const u8) DecryptError!void {
    if (b.len == 0) return;
    var members: strand.json.Members = undefined;
    members.init(a, .{});
    while (members.next() catch return error.InvalidHeader) |m| {
        var name_buffer: [64]u8 = undefined;
        const name = m.nameInto(&name_buffer) catch return error.InvalidHeader;
        var theirs: strand.json.Members = undefined;
        theirs.init(b, .{});
        while (theirs.next() catch return error.InvalidHeader) |t| if (t.is(name)) return error.InvalidHeader;
    }
}

/// The one held key that fits: by `kid` when the header names one; with no
/// `kid`, the only key that fits, else none (nothing to choose by).
fn select(keys: []const DecryptionKey, kid: ?[]const u8, alg: KeyManagement, enc: ContentEncryption) error{NoKey}!*const DecryptionKey {
    var chosen: ?*const DecryptionKey = null;
    for (keys) |*key| {
        if (!key.fits(alg, enc)) continue;
        if (kid) |wanted| {
            const own = key.kid orelse continue;
            if (!std.mem.eql(u8, own, wanted)) continue;
        }
        if (chosen != null) return error.NoKey;
        chosen = key;
    }
    return chosen orelse error.NoKey;
}

/// Recovers the content key into `cek` (its length the content's). A key
/// that does not unwrap, or unwraps to the wrong length, leaves `cek` random:
/// the content then fails as any forgery does (RFC 7516 §11.5). Header
/// errors, which say nothing of a key, return.
fn recoverKey(io: std.Io, arena: std.mem.Allocator, key: *const DecryptionKey, alg: KeyManagement, enc: ContentEncryption, joint: WireHeader, encrypted_key: []const u8, options: Options, cek: []u8, diagnostics: *Diagnostics) DecryptError!void {
    var recovered = false;
    switch (alg.kind()) {
        .direct => {
            if (encrypted_key.len != 0) return error.InvalidHeader;
            @memcpy(cek, key.material.secret);
            recovered = true;
        },
        .wrap => recovered = unwrapInto(key.material.secret, encrypted_key, cek),
        .gcm_wrap => {
            const iv = try decodeAlloc(arena, joint.iv orelse return error.InvalidHeader);
            const tag = try decodeAlloc(arena, joint.tag orelse return error.InvalidHeader);
            if (iv.len != 12 or tag.len != 16) return error.InvalidHeader;
            if (encrypted_key.len == cek.len) {
                const secret = key.material.secret;
                const opened = switch (secret.len) {
                    16 => Aes128Gcm.open(cek, encrypted_key, tag[0..16], "", iv[0..12], secret[0..16]),
                    else => Aes256Gcm.open(cek, encrypted_key, tag[0..16], "", iv[0..12], secret[0..32]),
                };
                recovered = if (opened) |_| true else |_| false;
            }
        },
        .rsa => {
            const private = key.material.private.key;
            var noise: [cloak.PrivateKey.max_noise]u8 = undefined;
            defer std.crypto.secureZero(u8, &noise);
            const noise_length = private.noiseLength();
            io.random(noise[0..noise_length]);
            var plain: [cloak.PrivateKey.max_plaintext]u8 = undefined;
            defer std.crypto.secureZero(u8, &plain);
            if (private.decrypt(alg.oaep().?, encrypted_key, noise[0..noise_length], &plain)) |content_key| {
                if (content_key.len == cek.len) {
                    @memcpy(cek, content_key);
                    recovered = true;
                }
            } else |_| {}
        },
        .agreement => recovered = try agreeInto(arena, key, alg, enc, joint, encrypted_key, cek),
        .password => {
            const salt_input = try decodeAlloc(arena, joint.p2s orelse return error.InvalidHeader);
            const count = joint.p2c orelse return error.InvalidHeader;
            if (salt_input.len < 8 or count == 0 or count > options.max_pbes2_count) {
                diagnostics.check = .pbes2;
                return error.InvalidHeader;
            }
            var kek: [32]u8 = undefined;
            defer std.crypto.secureZero(u8, &kek);
            const kek_length = alg.wrapLength().?;
            try pbes2Key(arena, alg, key.material.password, salt_input, count, kek[0..kek_length]);
            recovered = unwrapInto(kek[0..kek_length], encrypted_key, cek);
        },
    }
    if (!recovered) io.random(cek);
}

/// RFC 3394 unwrap into `cek`; false (and `cek` zeroed) when the wrapped key
/// is not `cek`'s length or does not hold.
fn unwrapInto(kek: []const u8, wrapped: []const u8, cek: []u8) bool {
    if (wrapped.len != cek.len + 8) return false;
    cloak.cipher.keyWrap.unwrap(kek, wrapped, cek) catch return false;
    return true;
}

/// ECDH-ES (RFC 7518 §4.6): the shared secret of the held key and the
/// header's `epk`, through the Concat KDF to the content key (`ECDH-ES`) or
/// to the key that unwraps it (`ECDH-ES+A*KW`).
fn agreeInto(arena: std.mem.Allocator, key: *const DecryptionKey, alg: KeyManagement, enc: ContentEncryption, joint: WireHeader, encrypted_key: []const u8, cek: []u8) DecryptError!bool {
    const epk_raw = joint.epk orelse return error.InvalidHeader;
    const epk = jwk.readPublic(arena, epk_raw.bytes, .encryption, 2048) catch |err| return switch (err) {
        error.OutOfMemory => error.ScratchTooSmall,
        else => error.InvalidHeader,
    };
    const held = key.material.private;
    const peer: []const u8 = switch (epk.material) {
        .ec => |ec| if ((held.kind == .p256 and ec.curve == .p256) or (held.kind == .p384 and ec.curve == .p384)) ec.point else return error.InvalidHeader,
        .okp => |okp| if (held.kind == .x25519 and okp.curve == .x25519) okp.x else return error.InvalidHeader,
        .rsa, .hmac => return error.InvalidHeader,
    };
    const apu = if (joint.apu) |text| try decodeAlloc(arena, text) else "";
    const apv = if (joint.apv) |text| try decodeAlloc(arena, text) else "";
    var z_buffer: [cloak.PrivateKey.max_shared]u8 = undefined;
    defer std.crypto.secureZero(u8, &z_buffer);
    // An epk of the right curve that the agreement refuses (X25519 of small
    // order) is the sender's fault, like a point off the curve.
    const z = held.key.agree(peer, &z_buffer) catch return error.InvalidHeader;
    if (alg == .ecdh_es) {
        if (encrypted_key.len != 0) return error.InvalidHeader;
        concatKdf(z, enc.name(), apu, apv, cek);
        return true;
    }
    var kek: [32]u8 = undefined;
    defer std.crypto.secureZero(u8, &kek);
    const kek_length = alg.wrapLength().?;
    concatKdf(z, alg.name(), apu, apv, kek[0..kek_length]);
    return unwrapInto(kek[0..kek_length], encrypted_key, cek);
}

/// The Concat KDF of NIST SP 800-56A §5.8.1 on SHA-256, as RFC 7518 §4.6.2
/// takes it: `out.len` bytes from `z` and the AlgorithmID, PartyUInfo,
/// PartyVInfo and SuppPubInfo (the key's length in bits).
pub fn concatKdf(z: []const u8, algorithm_id: []const u8, apu: []const u8, apv: []const u8, out: []u8) void {
    const Sha256 = std.crypto.hash.sha2.Sha256;
    var counter: u32 = 1;
    var at: usize = 0;
    while (at < out.len) : (counter += 1) {
        var h = Sha256.init(.{});
        defer std.crypto.secureZero(u8, std.mem.asBytes(&h));
        var word: [4]u8 = undefined;
        std.mem.writeInt(u32, &word, counter, .big);
        h.update(&word);
        h.update(z);
        for ([_][]const u8{ algorithm_id, apu, apv }) |field| {
            std.mem.writeInt(u32, &word, @intCast(field.len), .big); // safe: header fields are below the token's bound
            h.update(&word);
            h.update(field);
        }
        std.mem.writeInt(u32, &word, @intCast(out.len * 8), .big); // safe: at most 64 bytes
        h.update(&word);
        var block = h.finalResult();
        defer std.crypto.secureZero(u8, &block);
        const take = @min(block.len, out.len - at);
        @memcpy(out[at..][0..take], block[0..take]);
        at += take;
    }
}

/// PBES2's key (RFC 7518 §4.8.1.1): PBKDF2 with HMAC-SHA-256 or -512 over the
/// salt `alg || 0x00 || p2s`.
fn pbes2Key(arena: std.mem.Allocator, alg: KeyManagement, password: []const u8, p2s: []const u8, count: u32, out: []u8) DecryptError!void {
    const name = alg.name();
    const salt = arena.alloc(u8, name.len + 1 + p2s.len) catch return error.ScratchTooSmall;
    @memcpy(salt[0..name.len], name);
    salt[name.len] = 0;
    @memcpy(salt[name.len + 1 ..], p2s);
    const derived = switch (alg) {
        .pbes2_hs256_a128kw => std.crypto.pwhash.pbkdf2(out, password, salt, count, std.crypto.auth.hmac.sha2.HmacSha256),
        else => std.crypto.pwhash.pbkdf2(out, password, salt, count, std.crypto.auth.hmac.sha2.HmacSha512),
    };
    // unreachable: the count is at least one and the key at most 32 bytes
    derived catch unreachable;
}

/// Decrypts the content under `cek`, the tag checked first.
fn openContent(enc: ContentEncryption, plaintext: []u8, ciphertext: []const u8, tag: []const u8, aad: []const u8, iv: []const u8, cek: []const u8) cloak.cipher.Error![]u8 {
    switch (enc) {
        .a128gcm => {
            try Aes128Gcm.open(plaintext, ciphertext, tag[0..16], aad, iv[0..12], cek[0..16]);
            return plaintext;
        },
        .a256gcm => {
            try Aes256Gcm.open(plaintext, ciphertext, tag[0..16], aad, iv[0..12], cek[0..32]);
            return plaintext;
        },
        .a128cbc_hs256 => return cloak.cipher.CbcHmac(.a128cbc_hs256).open(plaintext, ciphertext, tag[0..16], aad, iv[0..16], cek[0..32]),
        .a256cbc_hs512 => return cloak.cipher.CbcHmac(.a256cbc_hs512).open(plaintext, ciphertext, tag[0..32], aad, iv[0..16], cek[0..64]),
    }
}

/// A password a PBES2 recipient's key is derived from, with the cost of the
/// derivation: the count is written in the header (`p2c`) and a reader
/// bounds it, so the default is the bound `decrypt` reads by default.
pub const Password = struct {
    password: []const u8,
    count: u32 = 10_000,
    /// The `p2s` salt's length in bytes: at least 8 (RFC 7518 §4.8.1.1).
    salt_length: u8 = 16,
};

/// One recipient of `encrypt`: the algorithm and what it encrypts to.
pub const Recipient = struct {
    alg: KeyManagement,
    key: union(enum) {
        /// A key read for encryption (`jwk.Purpose.encryption`): an RSA
        /// public key, an `oct` secret (A*KW, A*GCMKW, `dir`), or an EC or
        /// X25519 public key (ECDH-ES*).
        key: Key,
        password: Password,
    },
    /// The `kid` written for this recipient; the key's own when null.
    kid: ?[]const u8 = null,
};

/// The header `encrypt` writes: the content encryption, then these.
pub const EncryptHeader = struct {
    enc: ContentEncryption,
    typ: ?[]const u8 = null,
    /// `JWT` for a nested JWT: the plaintext is a signed JWT.
    cty: ?[]const u8 = null,
};

pub const Serialization = enum {
    /// Five dot-separated parts, one recipient, every header protected.
    compact,
    /// One recipient's members at the top of a JSON object (RFC 7516
    /// §7.2.2), every header protected.
    flattened,
    /// `recipients`, one or more (§7.2.1): the protected header holds the
    /// content's members, each recipient's header its own.
    general,
};

pub const EncryptOptions = struct {
    /// Additional authenticated data (the JSON `aad`, §5.1 step 14): JSON
    /// serializations only.
    aad: ?[]const u8 = null,
};

pub const EncryptError = error{
    /// A recipient's key does not fit its algorithm (`Key.fitsEncryption`),
    /// or does not allow encrypting to it.
    InvalidKey,
    /// No recipient; more than one for the compact or flattened form; or
    /// more than one where `dir` or `ECDH-ES` fixes the content key; or
    /// `aad` with the compact form.
    InvalidRecipients,
    /// The system's secure random source failed while drawing an ECDH-ES
    /// ephemeral key.
    EntropyUnavailable,
} || Writer.Error || std.mem.Allocator.Error;

/// What one recipient's key management wrote: its encrypted key, and the
/// header members it adds (base64url text).
const Wrapped = struct {
    encrypted_key: []u8 = &.{},
    iv: ?[]const u8 = null,
    tag: ?[]const u8 = null,
    p2s: ?[]const u8 = null,
    p2c: ?u32 = null,
    /// ECDH-ES's ephemeral public key, a JWK.
    epk: ?[]const u8 = null,
};

/// Encrypts `plaintext` under a fresh content key (or, for `dir`, the
/// recipient's) to every one of `recipients`, and writes the JWE in `form`.
/// `io` draws the content key, the IVs, salts and RSA-OAEP seeds, and an
/// ECDH-ES recipient's ephemeral key.
pub fn encrypt(gpa: std.mem.Allocator, io: std.Io, out: *Writer, header: EncryptHeader, plaintext: []const u8, recipients: []const Recipient, form: Serialization, options: EncryptOptions) EncryptError!void {
    return encryptDrawn(gpa, .{ .io = io }, out, header, plaintext, recipients, form, options);
}

/// Where `encrypt` draws its random bytes: `io`, or in tests a script read
/// in order (the content key, then each recipient's IV or salt, then the
/// content's IV), so a cookbook example comes out byte for byte.
const Draw = struct {
    io: ?std.Io = null,
    script: ?*[]const u8 = null,

    fn fill(d: Draw, out: []u8) void {
        if (d.script) |script| {
            @memcpy(out, script.*[0..out.len]);
            script.* = script.*[out.len..];
        } else d.io.?.random(out);
    }

    /// ECDH-ES's ephemeral key on `curve`: generated by cloak from `io`, or
    /// its private key read from the script.
    fn ephemeral(d: Draw, gpa: std.mem.Allocator, curve: Agreement) EncryptError!cloak.PrivateKey {
        if (d.script) |script| {
            const length: usize = switch (curve) {
                .p256, .x25519 => 32,
                .p384 => 48,
                .p521 => 66,
            };
            const private = script.*[0..length];
            script.* = script.*[length..];
            const components: cloak.PrivateKey.Components = switch (curve) {
                .p256 => .{ .ec = .{ .curve = .p256, .d = private } },
                .p384 => .{ .ec = .{ .curve = .p384, .d = private } },
                .p521 => .{ .ec = .{ .curve = .p521, .d = private } },
                .x25519 => .{ .x25519 = .{ .d = private } },
            };
            // unreachable: a test script holds a valid private key
            return cloak.PrivateKey.fromComponents(gpa, components) catch |err| switch (err) {
                error.OutOfMemory => error.OutOfMemory,
                else => unreachable,
            };
        }
        return cloak.PrivateKey.generate(gpa, d.io.?, switch (curve) {
            .p256 => .p256,
            .p384 => .p384,
            .p521 => .p521,
            .x25519 => .x25519,
        }) catch |err| switch (err) {
            error.OutOfMemory => error.OutOfMemory,
            error.EntropyUnavailable => error.EntropyUnavailable,
            // unreachable: only RSA's search can run out
            error.GenerationFailed => unreachable,
        };
    }
};

/// The curves an ECDH-ES recipient's key can be on.
const Agreement = enum { p256, p384, p521, x25519 };

/// Test seam: `encrypt` drawing from `script`.
pub fn encryptScripted(gpa: std.mem.Allocator, script: *[]const u8, out: *Writer, header: EncryptHeader, plaintext: []const u8, recipients: []const Recipient, form: Serialization, options: EncryptOptions) EncryptError!void {
    if (!@import("builtin").is_test) @compileError("scripted randomness is a test seam");
    return encryptDrawn(gpa, .{ .script = script }, out, header, plaintext, recipients, form, options);
}

fn encryptDrawn(gpa: std.mem.Allocator, draw: Draw, out: *Writer, header: EncryptHeader, plaintext: []const u8, recipients: []const Recipient, form: Serialization, options: EncryptOptions) EncryptError!void {
    if (recipients.len == 0 or (form != .general and recipients.len != 1)) return error.InvalidRecipients;
    if (form == .compact and options.aad != null) return error.InvalidRecipients;
    const enc = header.enc;
    for (recipients) |r| {
        if ((r.alg == .dir or r.alg == .ecdh_es) and recipients.len != 1) return error.InvalidRecipients;
        switch (r.key) {
            .key => |k| if (!k.encrypt or !k.fitsEncryption(r.alg, enc)) return error.InvalidKey,
            .password => |p| if (r.alg.kind() != .password or p.password.len == 0 or p.count == 0 or p.salt_length < 8) return error.InvalidKey,
        }
    }

    var arena_state: std.heap.ArenaAllocator = .init(gpa);
    defer arena_state.deinit();
    const arena = arena_state.allocator();
    var cek_buffer: [max_cek]u8 = undefined;
    defer std.crypto.secureZero(u8, &cek_buffer);
    const cek = cek_buffer[0..enc.keyLength()];
    // `dir`'s is the recipient's key and ECDH-ES's the agreement's (`wrapKey`).
    switch (recipients[0].alg) {
        .dir => @memcpy(cek, recipients[0].key.key.material.hmac),
        .ecdh_es => {},
        else => draw.fill(cek),
    }

    const wrapped = try arena.alloc(Wrapped, recipients.len);
    for (recipients, wrapped) |r, *w| w.* = try wrapKey(gpa, arena, draw, r, enc, cek);

    // The protected header: everything for one recipient, the content's
    // members for many.
    var protected_json: Writer.Allocating = .init(arena);
    if (form == .general) {
        try writeHeader(&protected_json.writer, .{ .enc = enc.name(), .typ = header.typ, .cty = header.cty });
    } else {
        const r = recipients[0];
        const w = wrapped[0];
        try writeHeader(&protected_json.writer, .{ .alg = r.alg.name(), .enc = enc.name(), .kid = kidOf(r), .epk = rawOf(w.epk), .typ = header.typ, .cty = header.cty, .iv = w.iv, .tag = w.tag, .p2s = w.p2s, .p2c = w.p2c });
    }
    var protected_b64: Writer.Allocating = .init(arena);
    try base64url.encode(&protected_b64.writer, protected_json.written());
    var aad_b64: Writer.Allocating = .init(arena);
    if (options.aad) |a| try base64url.encode(&aad_b64.writer, a);
    var aad: Writer.Allocating = .init(arena);
    try aad.writer.writeAll(protected_b64.written());
    if (options.aad != null) {
        try aad.writer.writeByte('.');
        try aad.writer.writeAll(aad_b64.written());
    }

    var iv: [16]u8 = undefined;
    draw.fill(iv[0..enc.ivLength()]);
    var tag: [32]u8 = undefined;
    const ciphertext = try arena.alloc(u8, switch (enc) {
        .a128gcm, .a256gcm => plaintext.len,
        .a128cbc_hs256 => cloak.cipher.CbcHmac(.a128cbc_hs256).ciphertextLength(plaintext.len),
        .a256cbc_hs512 => cloak.cipher.CbcHmac(.a256cbc_hs512).ciphertextLength(plaintext.len),
    });
    switch (enc) {
        .a128gcm => Aes128Gcm.seal(ciphertext, tag[0..16], plaintext, aad.written(), iv[0..12], cek[0..16]),
        .a256gcm => Aes256Gcm.seal(ciphertext, tag[0..16], plaintext, aad.written(), iv[0..12], cek[0..32]),
        .a128cbc_hs256 => cloak.cipher.CbcHmac(.a128cbc_hs256).seal(ciphertext, tag[0..16], plaintext, aad.written(), &iv, cek[0..32]),
        .a256cbc_hs512 => cloak.cipher.CbcHmac(.a256cbc_hs512).seal(ciphertext, tag[0..32], plaintext, aad.written(), &iv, cek[0..64]),
    }
    const iv_part = iv[0..enc.ivLength()];
    const tag_part = tag[0..enc.tagLength()];

    switch (form) {
        .compact => {
            try out.writeAll(protected_b64.written());
            try out.writeByte('.');
            try base64url.encode(out, wrapped[0].encrypted_key);
            for ([_][]const u8{ iv_part, ciphertext, tag_part }) |part| {
                try out.writeByte('.');
                try base64url.encode(out, part);
            }
        },
        .flattened, .general => {
            try out.writeAll("{\"protected\":\"");
            try out.writeAll(protected_b64.written());
            try out.writeByte('"');
            if (form == .flattened) {
                if (wrapped[0].encrypted_key.len > 0) try writeMember(out, "encrypted_key", wrapped[0].encrypted_key);
            } else {
                try out.writeAll(",\"recipients\":[");
                for (recipients, wrapped, 0..) |r, w, i| {
                    if (i > 0) try out.writeByte(',');
                    try out.writeAll("{\"header\":");
                    try writeHeader(out, .{ .alg = r.alg.name(), .kid = kidOf(r), .epk = rawOf(w.epk), .iv = w.iv, .tag = w.tag, .p2s = w.p2s, .p2c = w.p2c });
                    if (w.encrypted_key.len > 0) try writeMember(out, "encrypted_key", w.encrypted_key);
                    try out.writeByte('}');
                }
                try out.writeByte(']');
            }
            if (options.aad != null) {
                try out.writeAll(",\"aad\":\"");
                try out.writeAll(aad_b64.written());
                try out.writeByte('"');
            }
            try writeMember(out, "iv", iv_part);
            try writeMember(out, "ciphertext", ciphertext);
            try writeMember(out, "tag", tag_part);
            try out.writeByte('}');
        },
    }
}

fn rawOf(json: ?[]const u8) ?strand.json.Raw {
    return if (json) |bytes| .{ .bytes = bytes } else null;
}

fn kidOf(r: Recipient) ?[]const u8 {
    return r.kid orelse switch (r.key) {
        .key => |k| k.kid,
        .password => null,
    };
}

/// `,"name":"<base64url of bytes>"`.
fn writeMember(out: *Writer, comptime name: []const u8, bytes: []const u8) Writer.Error!void {
    try out.writeAll(",\"" ++ name ++ "\":\"");
    try base64url.encode(out, bytes);
    try out.writeByte('"');
}

/// The members `encrypt` writes into a header, absent ones left out, in
/// the order RFC 7520's examples write them (§5.3, §5.6-5.8 come out byte
/// for byte).
const HeaderOut = struct {
    alg: ?[]const u8 = null,
    kid: ?[]const u8 = null,
    epk: ?strand.json.Raw = null,
    tag: ?[]const u8 = null,
    iv: ?[]const u8 = null,
    p2s: ?[]const u8 = null,
    p2c: ?u32 = null,
    typ: ?[]const u8 = null,
    cty: ?[]const u8 = null,
    enc: ?[]const u8 = null,
};

fn writeHeader(w: *Writer, header: HeaderOut) Writer.Error!void {
    var object = strand.json.writeObjectOpen(w, header, .{ .nulls = .omit }) catch |err| return switch (err) {
        error.WriteFailed => error.WriteFailed,
        // unreachable: strings and an integer, each one JSON value
        else => unreachable,
    };
    try object.close();
}

/// One recipient's key management over `cek`; ECDH-ES (direct) derives it.
fn wrapKey(gpa: std.mem.Allocator, arena: std.mem.Allocator, draw: Draw, r: Recipient, enc: ContentEncryption, cek: []u8) EncryptError!Wrapped {
    var out: Wrapped = .{};
    switch (r.alg.kind()) {
        .direct => {},
        .wrap => {
            out.encrypted_key = try arena.alloc(u8, cek.len + 8);
            // unreachable: a KW secret is 16 or 32 bytes (fitsEncryption) and a content key 16 to 64
            cloak.cipher.keyWrap.wrap(r.key.key.material.hmac, cek, out.encrypted_key) catch unreachable;
        },
        .gcm_wrap => {
            const secret = r.key.key.material.hmac;
            var iv: [12]u8 = undefined;
            draw.fill(&iv);
            var tag: [16]u8 = undefined;
            out.encrypted_key = try arena.alloc(u8, cek.len);
            switch (secret.len) {
                16 => Aes128Gcm.seal(out.encrypted_key, &tag, cek, "", &iv, secret[0..16]),
                else => Aes256Gcm.seal(out.encrypted_key, &tag, cek, "", &iv, secret[0..32]),
            }
            out.iv = try encodeAlloc(arena, &iv);
            out.tag = try encodeAlloc(arena, &tag);
        },
        .rsa => {
            const public = r.key.key.public().?;
            var seed: [64]u8 = undefined;
            const scheme = r.alg.oaep().?;
            const seed_part = seed[0..cloak.certificates.encryption.seedLength(scheme)];
            draw.fill(seed_part);
            var sealed: [cloak.certificates.encryption.max_ciphertext]u8 = undefined;
            const made = cloak.certificates.encryption.encrypt(public, scheme, cek, seed_part, &sealed) catch return error.InvalidKey;
            out.encrypted_key = try arena.dupe(u8, made);
        },
        .password => {
            const p = r.key.password;
            var salt: [255]u8 = undefined;
            draw.fill(salt[0..p.salt_length]);
            var kek: [32]u8 = undefined;
            defer std.crypto.secureZero(u8, &kek);
            const kek_length = r.alg.wrapLength().?;
            pbes2Key(arena, r.alg, p.password, salt[0..p.salt_length], p.count, kek[0..kek_length]) catch |err| return switch (err) {
                error.ScratchTooSmall => error.OutOfMemory,
                // unreachable: pbes2Key fails only for room
                else => unreachable,
            };
            out.encrypted_key = try arena.alloc(u8, cek.len + 8);
            // unreachable: the KEK is 16 or 32 bytes and the content key 16 to 64
            cloak.cipher.keyWrap.wrap(kek[0..kek_length], cek, out.encrypted_key) catch unreachable;
            out.p2s = try encodeAlloc(arena, salt[0..p.salt_length]);
            out.p2c = p.count;
        },
        .agreement => try agreeTo(gpa, arena, draw, r, enc, cek, &out),
    }
    return out;
}

/// ECDH-ES to `r` (RFC 7518 §4.6): an ephemeral key on the recipient's
/// curve, its public half the header's `epk`, the shared secret through the
/// Concat KDF (no `apu` or `apv`) to the content key (`ECDH-ES`, written to
/// `cek`) or to the key that wraps it (`ECDH-ES+A*KW`).
fn agreeTo(gpa: std.mem.Allocator, arena: std.mem.Allocator, draw: Draw, r: Recipient, enc: ContentEncryption, cek: []u8, out: *Wrapped) EncryptError!void {
    const recipient = r.key.key;
    const curve: Agreement, const peer: []const u8 = switch (recipient.material) {
        .ec => |ec| .{ switch (ec.curve) {
            .p256 => .p256,
            .p384 => .p384,
            .p521 => .p521,
        }, ec.point },
        .okp => |okp| .{ .x25519, okp.x },
        // unreachable: fitsEncryption admits EC and X25519 keys alone
        .rsa, .hmac => unreachable,
    };
    var ephemeral = try draw.ephemeral(gpa, curve);
    defer ephemeral.deinit();
    var info: [cloak.PrivateKey.max_public_key_info]u8 = undefined;
    // unreachable: cloak reads back the key info it writes
    const public = cloak.certificates.certificate.parsePublicKey(ephemeral.publicKeyInfo(&info)) catch unreachable;
    const epk: Key = .{
        .material = switch (public) {
            .ec => |ec| .{ .ec = .{ .curve = ec.curve, .point = ec.bytes } },
            .x25519 => |x| .{ .okp = .{ .curve = .x25519, .x = x } },
            // unreachable: an agreement key's public half
            else => unreachable,
        },
    };
    var epk_json: Writer.Allocating = .init(arena);
    jwk.writePublic(&epk_json.writer, epk) catch |err| return switch (err) {
        error.WriteFailed => error.OutOfMemory,
        // unreachable: an EC or OKP key is public
        error.NotPublic => unreachable,
    };
    out.epk = epk_json.written();
    var z_buffer: [cloak.PrivateKey.max_shared]u8 = undefined;
    defer std.crypto.secureZero(u8, &z_buffer);
    // A recipient key the agreement refuses (an X25519 key of small order).
    const z = ephemeral.agree(peer, &z_buffer) catch return error.InvalidKey;
    if (r.alg == .ecdh_es) return concatKdf(z, enc.name(), "", "", cek);
    var kek: [32]u8 = undefined;
    defer std.crypto.secureZero(u8, &kek);
    const kek_length = r.alg.wrapLength().?;
    concatKdf(z, r.alg.name(), "", "", kek[0..kek_length]);
    out.encrypted_key = try arena.alloc(u8, cek.len + 8);
    // unreachable: the KEK is 16 or 32 bytes and the content key 16 to 64
    cloak.cipher.keyWrap.wrap(kek[0..kek_length], cek, out.encrypted_key) catch unreachable;
}

fn encodeAlloc(arena: std.mem.Allocator, bytes: []const u8) std.mem.Allocator.Error![]const u8 {
    var w: Writer.Allocating = .init(arena);
    base64url.encode(&w.writer, bytes) catch return error.OutOfMemory;
    return w.written();
}

test {
    _ = @import("jwe_test.zig");
}
