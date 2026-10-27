//! JSON Web Keys (RFC 7517, 7518 §6, RFC 8037): a key or a set read into
//! `Key`s, each checked as it is read, for signatures or for encryption, a
//! private key read for signing or decrypting, and thumbprints (RFC 7638,
//! RFC 9278).
const std = @import("std");
const aegis = @import("aegis");
const strand = @import("strand");
const cloak = @import("cloak");
const base64url = @import("base64url.zig");
const Algorithm = @import("Algorithm.zig").Algorithm;
const KeyManagement = @import("Algorithm.zig").KeyManagement;
const ContentEncryption = @import("Algorithm.zig").ContentEncryption;
const Key = @import("Key.zig");

/// Sizes in options: `.literal("16KiB")`.
pub const Bytes = aegis.units.Bytes(usize);

/// A JWK's members as JSON has them. Members clearance does not read are
/// passed over. The secret ones (`k` and the private members) stay raw: they
/// are read in place from the wiped copy of the document (`rawText`), never
/// copied by the parser.
const Wire = struct {
    kty: []const u8,
    kid: ?[]const u8 = null,
    alg: ?[]const u8 = null,
    use: ?[]const u8 = null,
    key_ops: ?[]const []const u8 = null,
    // RSA
    n: ?[]const u8 = null,
    e: ?[]const u8 = null,
    // EC and OKP
    crv: ?[]const u8 = null,
    x: ?[]const u8 = null,
    y: ?[]const u8 = null,
    // oct
    k: ?strand.json.Raw = null,
    // private members of RSA, EC and OKP keys
    d: ?strand.json.Raw = null,
    p: ?strand.json.Raw = null,
    q: ?strand.json.Raw = null,
    dp: ?strand.json.Raw = null,
    dq: ?strand.json.Raw = null,
    qi: ?strand.json.Raw = null,
    oth: ?strand.json.Raw = null,
};

/// What keys are read for. A key is read for one: a JWK's `use` and
/// `key_ops` name signatures or encryption (RFC 7517 §4.2-4.3), and a key
/// read for one is never used for the other.
pub const Purpose = enum {
    /// JWS: verifying or signing. RSA, EC, Ed25519 and HMAC keys.
    signatures,
    /// JWE: encrypting to the key or decrypting with it. RSA and EC keys,
    /// X25519 keys, and AES or content keys (`oct`).
    encryption,
};

/// Why a key was left out of a set.
pub const Skip = enum {
    /// `kty` or `crv` names a kind clearance does not use for the purpose
    /// (for signatures X25519, for encryption Ed25519; P-521, secp256k1,
    /// Ed448, AKP...).
    unsupported,
    /// Read for signatures: `use` is `enc`, or `key_ops` allows neither
    /// signing nor verifying.
    not_for_signatures,
    /// Read for encryption: `use` is `sig`, or `key_ops` allows neither
    /// encrypting nor decrypting.
    not_for_encryption,
    /// `alg` names an algorithm clearance does not have, or one the key's
    /// kind cannot use.
    algorithm,
    /// The members do not make a valid key: bad base64url, a point off the
    /// curve, a modulus out of range, members missing or of the wrong size.
    invalid,
    /// An `oct` key in a set read for public keys only.
    secret,
    /// A private key's members in a set read for public keys only.
    private,
    /// Another key in the set has the same `kid` and `kty`: a token naming it
    /// could mean either, so neither is kept.
    duplicate,
};

pub const Options = struct {
    purpose: Purpose = .signatures,
    /// Whether `oct` (HMAC) keys are taken. Off for a set fetched from a
    /// server: a published key set holds public keys.
    secrets: bool = false,
    /// The largest document read.
    max_bytes: Bytes = .literal("1MiB"),
    /// The most keys a set may hold.
    max_keys: u16 = 256,
    /// RSA moduli shorter than this are left out (and any shorter than 2048
    /// or longer than 4096 bits, which cloak refuses).
    min_rsa_bits: u16 = 2048,

    fn read(options: Options) Reading {
        return .{ .purpose = options.purpose, .secrets = options.secrets, .min_rsa_bits = options.min_rsa_bits };
    }
};

pub const ParseError = error{
    /// Not a JSON object, or a set whose `keys` is not an array of objects.
    InvalidDocument,
    TooLarge,
    /// More keys than `max_keys`.
    TooManyKeys,
    /// Secret (`oct`) keys beside public ones: a set holds one or the other,
    /// and a mixed one suggests secrets published by mistake.
    MixedKeySet,
} || std.mem.Allocator.Error;

/// Keys read from a JWK set (or one JWK), with their bytes. Keys that cannot
/// be used are left out and counted in `skipped`, so a set with one key of a
/// kind clearance does not verify with still serves the others.
pub const KeySet = struct {
    keys: []const Key,
    skipped: std.EnumArray(Skip, u16),
    /// Private: owns `keys` and their bytes but secrets.
    arena: std.heap.ArenaAllocator,
    /// Private: the `oct` keys' bytes, wiped by `deinit`.
    secrets: ?aegis.SecretBytes,
    /// Private: the copy of the document the keys' strings borrow, wiped by
    /// `deinit`: it holds every secret member the document had, the ones
    /// left out among them.
    document: aegis.SecretBytes,
    /// What the secret bytes were allocated with, which frees them.
    gpa: std.mem.Allocator,

    /// Reads `{"keys":[...]}`, or a single JWK as a set of one.
    pub fn parse(gpa: std.mem.Allocator, document: []const u8, options: Options) ParseError!KeySet {
        const limit: usize = options.max_bytes.raw();
        if (document.len > limit) return error.TooLarge;
        var set: KeySet = .{ .keys = &.{}, .skipped = .initFill(0), .arena = .init(gpa), .secrets = null, .document = try .init(gpa, document.len), .gpa = gpa };
        errdefer set.deinit();
        const arena = set.arena.allocator();
        // The keys outlive the caller's document: strings read from it borrow the copy.
        // unreachable: the copy is a fresh allocation of the document's length
        set.document.replace(document) catch unreachable;
        const json = set.document.expose();
        const parse_options: strand.json.ParseOptions = .{ .ignore_unknown_fields = true, .limits = .{ .depth = 16 } };
        const wires: []const Wire = blk: {
            const Set = struct { keys: []const strand.json.Raw };
            if (strand.json.parseLeaky(Set, arena, json, parse_options)) |doc| {
                if (doc.keys.len > options.max_keys) return error.TooManyKeys;
                const out = try arena.alloc(Wire, doc.keys.len);
                var kept: usize = 0;
                for (doc.keys) |raw| {
                    out[kept] = raw.parse(Wire, arena, parse_options) catch |err| switch (err) {
                        error.OutOfMemory => return error.OutOfMemory,
                        else => {
                            set.skipped.getPtr(.invalid).* += 1;
                            continue;
                        },
                    };
                    kept += 1;
                }
                break :blk out[0..kept];
            } else |err| if (err == error.OutOfMemory) return error.OutOfMemory;
            const one = strand.json.parseLeaky(Wire, arena, json, parse_options) catch |err| return switch (err) {
                error.OutOfMemory => error.OutOfMemory,
                else => error.InvalidDocument,
            };
            break :blk try arena.dupe(Wire, &.{one});
        };
        var has_secret = false;
        var has_public = false;
        for (wires) |w| {
            if (std.mem.eql(u8, w.kty, "oct")) has_secret = true else has_public = true;
        }
        if (options.secrets and has_secret and has_public) return error.MixedKeySet;
        var secret_length: usize = 0;
        for (wires) |w| if (w.k) |k| {
            secret_length += base64url.decodedLength(rawText(k) orelse continue) catch 0;
        };
        if (options.secrets and secret_length > 0) {
            set.secrets = try aegis.SecretBytes.init(gpa, secret_length);
            // unreachable: the length is the capacity just allocated
            set.secrets.?.resizeWithinCapacity(secret_length) catch unreachable;
        }
        var secrets: Secrets = .{ .storage = if (set.secrets) |*s| s.exposeMut() else &.{} };
        const keys = try arena.alloc(Key, wires.len);
        var count: usize = 0;
        for (wires, 0..) |w, i| {
            if (duplicated(wires, i)) {
                set.skipped.getPtr(.duplicate).* += 1;
                continue;
            }
            var why: Skip = undefined;
            keys[count] = read(arena, w, options.read(), &secrets, &why) catch |err| switch (err) {
                error.OutOfMemory => return error.OutOfMemory,
                error.Skipped => {
                    set.skipped.getPtr(why).* += 1;
                    continue;
                },
            };
            count += 1;
        }
        set.keys = keys[0..count];
        return set;
    }

    pub fn deinit(set: *KeySet) void {
        if (set.secrets) |*s| s.deinit(set.gpa);
        set.document.deinit(set.gpa);
        set.arena.deinit();
        set.* = undefined;
    }

    /// How many keys were left out, for every reason.
    pub fn skippedTotal(set: *const KeySet) usize {
        var total: usize = 0;
        for (set.skipped.values) |n| total += n;
        return total;
    }
};

/// How `PrivateKey.parse` reads.
pub const PrivateOptions = struct {
    /// Signing (JWS), or decrypting (JWE: RSA, EC and X25519 keys).
    purpose: Purpose = .signatures,
    /// The largest document read.
    max_bytes: Bytes = .literal("64KiB"),
    /// RSA moduli shorter than this are refused (and any shorter than
    /// 2048 or longer than 4096 bits, which cloak refuses).
    min_rsa_bits: u16 = 2048,
};

/// Why `PrivateKey.parse` refused a document.
pub const PrivateError = error{
    /// Not one JSON object with a `kty`.
    InvalidDocument,
    TooLarge,
    /// A `kty` or `crv` clearance does not sign with (X25519, P-521, a
    /// multi-prime RSA key, an RSA key without its CRT members), or `oct`:
    /// an HMAC secret is read by `KeySet.parse` with `secrets`.
    UnsupportedKey,
    /// A public key: no private member.
    NotPrivate,
    /// Read for signing: `use` is `enc`, or `key_ops` does not allow
    /// signing.
    NotForSigning,
    /// Read for decrypting: `use` is `sig`, or `key_ops` does not allow
    /// decrypting.
    NotForDecryption,
    /// `alg` names an algorithm clearance does not have, or one the key
    /// cannot sign with.
    InvalidAlgorithm,
    /// The members do not make a valid key: bad base64url, sizes, a
    /// scalar out of range, RSA numbers that disagree, a public half that
    /// is not the private key's.
    InvalidKey,
} || std.mem.Allocator.Error;

/// A private JWK read for signing (RFC 7518 §6.2.2, §6.3.2, RFC 8037 §2): an
/// EC key on P-256 or P-384, an Ed25519 key, or a two-prime RSA key with its
/// CRT members; `jws.Signer.fromJwk` signs with it. Or read for decrypting:
/// an RSA, EC or X25519 key (RFC 8037 §3.2), which `jwe.Key.fromJwk` holds.
pub const PrivateKey = struct {
    /// The key, as cloak holds it: wiped when its last owner releases it.
    key: cloak.PrivateKey,
    /// The public half, with the JWK's `kid`, `alg`, `use` and `key_ops`: what
    /// a verifier is given, and the key whose thumbprint names this one.
    public: Key,
    /// Private: owns `public`'s bytes.
    arena: std.heap.ArenaAllocator,

    /// Reads one private JWK. The document is read from a wiped copy and the
    /// private members decoded into wiped memory, both erased before this
    /// returns; nothing else holds them.
    pub fn parse(gpa: std.mem.Allocator, document: []const u8, options: PrivateOptions) PrivateError!PrivateKey {
        const limit: usize = options.max_bytes.raw();
        if (document.len > limit) return error.TooLarge;
        var text = try aegis.SecretBytes.init(gpa, document.len);
        defer text.deinit(gpa);
        // unreachable: a fresh allocation of the document's length
        text.replace(document) catch unreachable;
        var arena: std.heap.ArenaAllocator = .init(gpa);
        errdefer arena.deinit();
        const parse_options: strand.json.ParseOptions = .{ .ignore_unknown_fields = true, .limits = .{ .depth = 16 } };
        const w = strand.json.parseLeaky(Wire, arena.allocator(), text.expose(), parse_options) catch |err| return switch (err) {
            error.OutOfMemory => error.OutOfMemory,
            else => error.InvalidDocument,
        };
        if (std.mem.eql(u8, w.kty, "oct") or w.oth != null) return error.UnsupportedKey;
        if (w.d == null) return error.NotPrivate;

        // The public half, through the same checks a key set's keys get.
        var public_wire = w;
        public_wire.d = null;
        public_wire.p = null;
        public_wire.q = null;
        public_wire.dp = null;
        public_wire.dq = null;
        public_wire.qi = null;
        var why: Skip = undefined;
        var no_secrets: Secrets = .{ .storage = &.{} };
        var public = read(arena.allocator(), public_wire, .{ .purpose = options.purpose, .secrets = false, .min_rsa_bits = options.min_rsa_bits }, &no_secrets, &why) catch |err| switch (err) {
            error.OutOfMemory => return error.OutOfMemory,
            error.Skipped => return switch (why) {
                .unsupported => error.UnsupportedKey,
                .not_for_signatures => error.NotForSigning,
                .not_for_encryption => error.NotForDecryption,
                .algorithm => error.InvalidAlgorithm,
                // unreachable: no set, no secret, no private member
                .secret, .private, .duplicate => unreachable,
                .invalid => error.InvalidKey,
            },
        };
        switch (options.purpose) {
            .signatures => if (!public.sign) return error.NotForSigning,
            .encryption => if (!public.decrypt) return error.NotForDecryption,
        }
        // The kid borrowed the document, which is wiped on return.
        if (public.kid) |kid| public.kid = try arena.allocator().dupe(u8, kid);

        const d = rawText(w.d.?) orelse return error.InvalidKey;
        const rsa_members = [_]?strand.json.Raw{ w.p, w.q, w.dp, w.dq, w.qi };
        var length = base64url.decodedLength(d) catch return error.InvalidKey;
        if (public.material == .rsa) for (rsa_members) |member| {
            const member_text = rawText(member orelse return error.UnsupportedKey) orelse return error.InvalidKey;
            length += base64url.decodedLength(member_text) catch return error.InvalidKey;
        };
        var numbers = try aegis.SecretBytes.init(gpa, length);
        defer numbers.deinit(gpa);
        // unreachable: the length is the capacity just allocated
        numbers.resizeWithinCapacity(length) catch unreachable;
        const storage = numbers.exposeMut();
        var used: usize = 0;
        const private_scalar = decodeInto(storage, &used, d) orelse return error.InvalidKey;
        const components: cloak.PrivateKey.Components = switch (public.material) {
            .ec => |ec| .{
                .ec = .{
                    .curve = switch (ec.curve) {
                        .p256 => .p256,
                        .p384 => .p384,
                        // unreachable: `read` takes no `crv` but P-256 and P-384
                        .p521 => unreachable,
                    },
                    .d = private_scalar,
                    .public = ec.point,
                },
            },
            .okp => |okp| switch (okp.curve) {
                .ed25519 => .{ .ed25519 = .{ .seed = private_scalar, .public = okp.x } },
                .x25519 => .{ .x25519 = .{ .d = private_scalar, .public = okp.x } },
            },
            .rsa => |rsa| blk: {
                var members: [5][]const u8 = undefined;
                for (rsa_members, &members) |member, *out| out.* = decodeInto(storage, &used, rawText(member.?).?) orelse return error.InvalidKey;
                break :blk .{ .rsa = .{ .n = rsa.n, .e = rsa.e, .d = private_scalar, .p = members[0], .q = members[1], .dp = members[2], .dq = members[3], .qi = members[4] } };
            },
            // unreachable: `oct` is refused above
            .hmac => unreachable,
        };
        const key = cloak.PrivateKey.fromComponents(gpa, components) catch |err| return switch (err) {
            error.OutOfMemory => error.OutOfMemory,
            error.InvalidKey => error.InvalidKey,
            error.UnsupportedKey => error.UnsupportedKey,
        };
        return .{ .key = key, .public = public, .arena = arena };
    }

    pub fn deinit(private: *PrivateKey) void {
        private.key.deinit();
        private.arena.deinit();
        private.* = undefined;
    }
};

/// A member's base64url text, read in place: the JSON string's contents when
/// it has no escape (no key member needs one), else null.
fn rawText(raw: strand.json.Raw) ?[]const u8 {
    const bytes = raw.bytes;
    if (bytes.len < 2 or bytes[0] != '"' or bytes[bytes.len - 1] != '"') return null;
    const text = bytes[1 .. bytes.len - 1];
    if (std.mem.findScalar(u8, text, '\\') != null) return null;
    return text;
}

/// `text` decoded into `storage` at `used.*`, which moves past it.
fn decodeInto(storage: []u8, used: *usize, text: []const u8) ?[]const u8 {
    const decoded = base64url.decode(storage[used.*..], text) catch return null;
    used.* += decoded.len;
    return decoded;
}

/// Whether another entry has the same `kid` and `kty` as `wires[i]`.
fn duplicated(wires: []const Wire, i: usize) bool {
    const kid = wires[i].kid orelse return false;
    for (wires, 0..) |other, j| {
        if (j == i) continue;
        const other_kid = other.kid orelse continue;
        if (std.mem.eql(u8, kid, other_kid) and std.mem.eql(u8, wires[i].kty, other.kty)) return true;
    }
    return false;
}

const ReadError = error{Skipped} || std.mem.Allocator.Error;

/// What `read` takes from a set's or a private key's options.
const Reading = struct { purpose: Purpose, secrets: bool, min_rsa_bits: u16 };

/// Where `oct` keys' bytes are decoded: the set's wiped storage.
const Secrets = struct { storage: []u8, used: usize = 0 };

fn skip(reason: *Skip, why: Skip) error{Skipped} {
    reason.* = why;
    return error.Skipped;
}

/// `w` as a public key (or a secret one when `options.secrets`), or
/// `error.Skipped` with the reason in `why`.
fn read(arena: std.mem.Allocator, w: Wire, options: Reading, secrets: *Secrets, why: *Skip) ReadError!Key {
    var key: Key = .{ .material = undefined, .kid = w.kid };
    const signatures = options.purpose == .signatures;
    try readUse(w, signatures, &key, why);
    const private = w.d != null or w.p != null or w.q != null or w.dp != null or w.dq != null or w.qi != null or w.oth != null;
    if (std.mem.eql(u8, w.kty, "RSA")) {
        if (private) return skip(why, .private);
        const n = try decodeMember(arena, w.n) orelse return skip(why, .invalid);
        const e = try decodeMember(arena, w.e) orelse return skip(why, .invalid);
        // cloak's checks for every RSA public key: minimal integers (RFC 7518
        // §6.3.1.1), 2048 to 4096 bits, an odd exponent of 3 to 2^32-1, no
        // ROCA fingerprint (CVE-2017-15361).
        cloak.certificates.certificate.Algorithm.checkRsa(n, e) catch return skip(why, .invalid);
        if (bitLength(n) < options.min_rsa_bits) return skip(why, .invalid);
        key.material = .{ .rsa = .{ .n = n, .e = e } };
    } else if (std.mem.eql(u8, w.kty, "EC")) {
        if (private) return skip(why, .private);
        const crv = w.crv orelse return skip(why, .invalid);
        const curve: Key.Curve = if (std.mem.eql(u8, crv, "P-256")) .p256 else if (std.mem.eql(u8, crv, "P-384")) .p384 else return skip(why, .unsupported);
        const width: usize = if (curve == .p256) 32 else 48;
        const x = try decodeMember(arena, w.x) orelse return skip(why, .invalid);
        const y = try decodeMember(arena, w.y) orelse return skip(why, .invalid);
        // Exactly the field's width (RFC 7518 §6.2.1.2-3).
        if (x.len != width or y.len != width) return skip(why, .invalid);
        const point = try arena.alloc(u8, 1 + 2 * width);
        point[0] = 4;
        @memcpy(point[1..][0..width], x);
        @memcpy(point[1 + width ..], y);
        const valid = switch (curve) {
            .p256 => if (std.crypto.sign.ecdsa.EcdsaP256Sha256.PublicKey.fromSec1(point)) |_| true else |_| false,
            .p384 => if (std.crypto.sign.ecdsa.EcdsaP384Sha384.PublicKey.fromSec1(point)) |_| true else |_| false,
            // unreachable: the `crv` read above is P-256 or P-384
            .p521 => unreachable,
        };
        if (!valid) return skip(why, .invalid);
        key.material = .{ .ec = .{ .curve = curve, .point = point } };
    } else if (std.mem.eql(u8, w.kty, "OKP")) {
        if (private) return skip(why, .private);
        const crv = w.crv orelse return skip(why, .invalid);
        const curve: Key.OkpCurve = if (signatures and std.mem.eql(u8, crv, "Ed25519")) .ed25519 else if (!signatures and std.mem.eql(u8, crv, "X25519")) .x25519 else return skip(why, .unsupported);
        const x = try decodeMember(arena, w.x) orelse return skip(why, .invalid);
        if (x.len != 32) return skip(why, .invalid);
        // Every 32 bytes are an X25519 key (RFC 7748 §5); an agreement
        // refuses the ones of small order.
        if (curve == .ed25519) _ = std.crypto.sign.Ed25519.PublicKey.fromBytes(x[0..32].*) catch return skip(why, .invalid);
        key.material = .{ .okp = .{ .curve = curve, .x = x } };
    } else if (std.mem.eql(u8, w.kty, "oct")) {
        if (!options.secrets) return skip(why, .secret);
        const k = rawText(w.k orelse return skip(why, .invalid)) orelse return skip(why, .invalid);
        const length = base64url.decodedLength(k) catch return skip(why, .invalid);
        if (length == 0) return skip(why, .invalid);
        const storage = secrets.storage[secrets.used..][0..length];
        const secret = base64url.decode(storage, k) catch return skip(why, .invalid);
        secrets.used += length;
        if (secret.len == 0) return skip(why, .invalid);
        key.material = .{ .hmac = secret };
    } else return skip(why, .unsupported);
    if (w.alg) |name| {
        if (signatures) {
            const alg = Algorithm.parse(name) orelse return skip(why, .algorithm);
            if (alg.family() != std.meta.activeTag(key.material)) return skip(why, .algorithm);
            if (alg.curve()) |c| if (key.material.ec.curve != c) return skip(why, .algorithm);
            key.alg = alg;
        } else if (KeyManagement.parse(name)) |alg| {
            const fits = switch (alg.kind()) {
                .rsa => key.material == .rsa,
                .agreement => key.material == .ec or key.material == .okp,
                .wrap, .gcm_wrap => key.material == .hmac and key.material.hmac.len == alg.wrapLength().?,
                // `dir` with no content named: any content key's length.
                .direct => key.material == .hmac,
                .password => false,
            };
            if (!fits) return skip(why, .algorithm);
            key.management = alg;
        } else if (ContentEncryption.parse(name)) |enc| {
            // A content key itself (`dir`), of that content's length.
            if (key.material != .hmac or key.material.hmac.len != enc.keyLength()) return skip(why, .algorithm);
            key.content = enc;
        } else return skip(why, .algorithm);
    }
    return key;
}

/// `use` and `key_ops` into `key` for the purpose read: a key read for one
/// does nothing of the other's.
fn readUse(w: Wire, signatures: bool, key: *Key, why: *Skip) error{Skipped}!void {
    if (signatures) {
        key.encrypt = false;
        key.decrypt = false;
    } else {
        key.verify = false;
        key.sign = false;
    }
    if (w.use) |use| {
        if (std.mem.eql(u8, use, "sig")) {
            if (!signatures) return skip(why, .not_for_encryption);
            key.use = .sig;
        } else if (std.mem.eql(u8, use, "enc")) {
            if (signatures) return skip(why, .not_for_signatures);
            key.use = .enc;
        } else return skip(why, .invalid);
    }
    if (w.key_ops) |ops| {
        var verify = false;
        var sign = false;
        var encrypt = false;
        var decrypt = false;
        for (ops) |op| {
            if (std.mem.eql(u8, op, "verify")) verify = true;
            if (std.mem.eql(u8, op, "sign")) sign = true;
            if (std.mem.eql(u8, op, "encrypt") or std.mem.eql(u8, op, "wrapKey")) encrypt = true;
            if (std.mem.eql(u8, op, "decrypt") or std.mem.eql(u8, op, "unwrapKey")) decrypt = true;
            if (std.mem.eql(u8, op, "deriveKey") or std.mem.eql(u8, op, "deriveBits")) {
                encrypt = true;
                decrypt = true;
            }
        }
        if (signatures) {
            key.verify = verify;
            key.sign = sign;
            if (!verify and !sign) return skip(why, .not_for_signatures);
        } else {
            key.encrypt = encrypt;
            key.decrypt = decrypt;
            if (!encrypt and !decrypt) return skip(why, .not_for_encryption);
        }
    }
}

/// A member decoded, or null when it is missing or not base64url.
fn decodeMember(arena: std.mem.Allocator, member: ?[]const u8) std.mem.Allocator.Error!?[]const u8 {
    const text = member orelse return null;
    return base64url.decodeAlloc(arena, text) catch |err| switch (err) {
        error.OutOfMemory => error.OutOfMemory,
        else => null,
    };
}

fn bitLength(big_endian: []const u8) usize {
    for (big_endian, 0..) |byte, i| {
        if (byte != 0) return (big_endian.len - i) * 8 - @clz(byte);
    }
    return 0;
}

/// Writes a public key as a JWK: its required members (RFC 7638 §3.2), in
/// lexicographic order. A secret (`oct`) key is not public.
pub fn writePublic(w: *std.Io.Writer, key: Key) (std.Io.Writer.Error || error{NotPublic})!void {
    if (key.material == .hmac) return error.NotPublic;
    try writeRequired(w, key);
}

pub const PublicError = error{
    /// Not one JSON object with a `kty`, or members that make no valid key.
    InvalidKey,
    /// A `kty` or `crv` clearance does not verify with.
    UnsupportedKey,
    /// Private members, or an `oct` key: not a public key.
    NotPublic,
    /// Read for signatures: `use` is `enc`, or `key_ops` does not allow
    /// verifying.
    NotForSignatures,
    /// Read for encryption: `use` is `sig`, or `key_ops` does not allow
    /// encrypting to the key.
    NotForEncryption,
    /// `alg` names an algorithm clearance does not have, or one the key
    /// cannot use.
    InvalidAlgorithm,
} || std.mem.Allocator.Error;

/// Reads one public JWK (a DPoP proof's `jwk`, a document's own key) into a
/// key whose bytes live in `arena`, through the checks a key set's keys
/// get. A key with private members or a secret one is refused, never read
/// as public.
pub fn readPublic(arena: std.mem.Allocator, document: []const u8, purpose: Purpose, min_rsa_bits: u16) PublicError!Key {
    const parse_options: strand.json.ParseOptions = .{ .ignore_unknown_fields = true, .limits = .{ .depth = 8 } };
    const w = strand.json.parseLeaky(Wire, arena, document, parse_options) catch |err| return switch (err) {
        error.OutOfMemory => error.OutOfMemory,
        else => error.InvalidKey,
    };
    var why: Skip = undefined;
    var no_secrets: Secrets = .{ .storage = &.{} };
    const key = read(arena, w, .{ .purpose = purpose, .secrets = false, .min_rsa_bits = min_rsa_bits }, &no_secrets, &why) catch |err| switch (err) {
        error.OutOfMemory => return error.OutOfMemory,
        error.Skipped => return switch (why) {
            .unsupported => error.UnsupportedKey,
            .not_for_signatures => error.NotForSignatures,
            .not_for_encryption => error.NotForEncryption,
            .algorithm => error.InvalidAlgorithm,
            .secret, .private => error.NotPublic,
            // unreachable: one key, no set to share a kid with
            .duplicate => unreachable,
            .invalid => error.InvalidKey,
        },
    };
    switch (purpose) {
        .signatures => if (!key.verify) return error.NotForSignatures,
        .encryption => if (!key.encrypt) return error.NotForEncryption,
    }
    return key;
}

/// The JWK thumbprint of a key (RFC 7638): SHA-256 over its required members
/// in lexicographic order, without whitespace.
pub fn thumbprint(key: Key) [32]u8 {
    var hash: std.crypto.hash.sha2.Sha256 = .init(.{});
    var buffer: [256]u8 = undefined;
    var w: HashWriter = .{ .hash = &hash, .writer = .{ .buffer = &buffer, .vtable = &HashWriter.vtable } };
    // unreachable: the writer hashes what it is given and never fails
    writeRequired(&w.writer, key) catch unreachable;
    // unreachable: as above, a flush only hashes
    w.writer.flush() catch unreachable;
    return hash.finalResult();
}

/// The thumbprint as a URI (RFC 9278):
/// `urn:ietf:params:oauth:jwk-thumbprint:sha-256:` and its base64url.
pub fn writeThumbprintUri(w: *std.Io.Writer, key: Key) std.Io.Writer.Error!void {
    try w.writeAll("urn:ietf:params:oauth:jwk-thumbprint:sha-256:");
    try base64url.encode(w, &thumbprint(key));
}

fn writeRequired(w: *std.Io.Writer, key: Key) std.Io.Writer.Error!void {
    switch (key.material) {
        .rsa => |rsa| {
            try w.writeAll("{\"e\":\"");
            try base64url.encode(w, rsa.e);
            try w.writeAll("\",\"kty\":\"RSA\",\"n\":\"");
            try base64url.encode(w, rsa.n);
            try w.writeAll("\"}");
        },
        .ec => |ec| {
            const width = (ec.point.len - 1) / 2;
            try w.writeAll(if (ec.curve == .p256) "{\"crv\":\"P-256\",\"kty\":\"EC\",\"x\":\"" else "{\"crv\":\"P-384\",\"kty\":\"EC\",\"x\":\"");
            try base64url.encode(w, ec.point[1..][0..width]);
            try w.writeAll("\",\"y\":\"");
            try base64url.encode(w, ec.point[1 + width ..]);
            try w.writeAll("\"}");
        },
        .okp => |okp| {
            try w.writeAll(if (okp.curve == .ed25519) "{\"crv\":\"Ed25519\",\"kty\":\"OKP\",\"x\":\"" else "{\"crv\":\"X25519\",\"kty\":\"OKP\",\"x\":\"");
            try base64url.encode(w, okp.x);
            try w.writeAll("\"}");
        },
        .hmac => |secret| {
            try w.writeAll("{\"k\":\"");
            try base64url.encode(w, secret);
            try w.writeAll("\",\"kty\":\"oct\"}");
        },
    }
}

/// A writer that hashes what is written to it.
const HashWriter = struct {
    hash: *std.crypto.hash.sha2.Sha256,
    writer: std.Io.Writer,

    const vtable: std.Io.Writer.VTable = .{ .drain = drain };

    fn drain(w: *std.Io.Writer, data: []const []const u8, splat: usize) std.Io.Writer.Error!usize {
        const self: *HashWriter = @alignCast(@fieldParentPtr("writer", w)); // safe: every HashWriter.writer is its own field
        self.hash.update(w.buffered());
        w.end = 0;
        var written: usize = 0;
        for (data[0 .. data.len - 1]) |bytes| {
            self.hash.update(bytes);
            written += bytes.len;
        }
        const last = data[data.len - 1];
        for (0..splat) |_| self.hash.update(last);
        return written + last.len * splat;
    }
};

test {
    _ = @import("jwk_test.zig");
}
