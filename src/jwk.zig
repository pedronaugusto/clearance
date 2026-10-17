//! JSON Web Keys (RFC 7517, 7518 §6, RFC 8037): a key or a set read into
//! `Key`s, each checked as it is read, and thumbprints (RFC 7638, RFC 9278).
const std = @import("std");
const aegis = @import("aegis");
const strand = @import("strand");
const base64url = @import("base64url.zig");
const Algorithm = @import("Algorithm.zig").Algorithm;
const Key = @import("Key.zig");

/// Sizes in options: `.literal("16KiB")`.
pub const Bytes = aegis.units.Bytes(usize);

/// A JWK's members as JSON has them. Members clearance does not read are
/// passed over; the private ones are read only to refuse them.
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
    k: ?[]const u8 = null,
    // private members of RSA, EC and OKP keys
    d: ?strand.json.Raw = null,
    p: ?strand.json.Raw = null,
    q: ?strand.json.Raw = null,
    dp: ?strand.json.Raw = null,
    dq: ?strand.json.Raw = null,
    qi: ?strand.json.Raw = null,
    oth: ?strand.json.Raw = null,
};

/// Why a key was left out of a set.
pub const Skip = enum {
    /// `kty` or `crv` names a kind clearance does not verify with (X25519,
    /// P-521, secp256k1, Ed448, AKP...).
    unsupported,
    /// `use` is `enc`, or `key_ops` allows neither signing nor verifying.
    not_for_signatures,
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
    /// Whether `oct` (HMAC) keys are taken. Off for a set fetched from a
    /// server: a published key set holds public keys.
    secrets: bool = false,
    /// The largest document read.
    max_bytes: Bytes = .literal("1MiB"),
    /// The most keys a set may hold.
    max_keys: u16 = 256,
    /// RSA moduli shorter than this, or longer than 4096 bits, are left out.
    min_rsa_bits: u16 = 2048,
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

    /// Reads `{"keys":[...]}`, or a single JWK as a set of one.
    pub fn parse(gpa: std.mem.Allocator, document: []const u8, options: Options) ParseError!KeySet {
        const limit: usize = options.max_bytes.raw();
        if (document.len > limit) return error.TooLarge;
        var set: KeySet = .{ .keys = &.{}, .skipped = .initFill(0), .arena = .init(gpa), .secrets = null };
        errdefer set.deinit();
        const arena = set.arena.allocator();
        // The keys outlive the caller's document: strings read from it borrow the copy.
        const json = try arena.dupe(u8, document);
        const parse_options: strand.json.ParseOptions = .{ .ignore_unknown_fields = true, .limits = .{ .depth = 16 } };
        const wires: []const Wire = blk: {
            const Set = struct { keys: []const strand.json.Raw };
            if (strand.json.parseLeaky(Set, arena, json, parse_options)) |doc| {
                if (doc.keys.len > options.max_keys) return error.TooManyKeys;
                const out = try arena.alloc(Wire, doc.keys.len);
                var kept: usize = 0;
                for (doc.keys) |raw| {
                    out[kept] = raw.parse(Wire, arena, parse_options) catch {
                        set.skipped.getPtr(.invalid).* += 1;
                        continue;
                    };
                    kept += 1;
                }
                break :blk out[0..kept];
            } else |_| {}
            const one = strand.json.parseLeaky(Wire, arena, json, parse_options) catch return error.InvalidDocument;
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
            secret_length += base64url.decodedLength(k) catch 0;
        };
        if (options.secrets and secret_length > 0) {
            set.secrets = try aegis.SecretBytes.init(gpa, secret_length);
            // unreachable: the length is the capacity just allocated
            set.secrets.?.resizeWithinCapacity(secret_length) catch unreachable;
        }
        var secret_used: usize = 0;
        const keys = try arena.alloc(Key, wires.len);
        var count: usize = 0;
        for (wires, 0..) |w, i| {
            if (duplicated(wires, i)) {
                set.skipped.getPtr(.duplicate).* += 1;
                continue;
            }
            keys[count] = read(arena, w, options, &set, &secret_used) catch |err| switch (err) {
                error.OutOfMemory => return error.OutOfMemory,
                error.Skipped => continue,
            };
            count += 1;
        }
        set.keys = keys[0..count];
        return set;
    }

    pub fn deinit(set: *KeySet) void {
        if (set.secrets) |*s| s.deinit();
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

fn skip(set: *KeySet, why: Skip) error{Skipped} {
    set.skipped.getPtr(why).* += 1;
    return error.Skipped;
}

fn read(arena: std.mem.Allocator, w: Wire, options: Options, set: *KeySet, secret_used: *usize) ReadError!Key {
    var key: Key = .{ .material = undefined, .kid = w.kid };
    if (w.use) |use| {
        if (std.mem.eql(u8, use, "sig")) key.use = .sig else if (std.mem.eql(u8, use, "enc")) return skip(set, .not_for_signatures) else return skip(set, .invalid);
    }
    if (w.key_ops) |ops| {
        key.verify = false;
        key.sign = false;
        for (ops) |op| {
            if (std.mem.eql(u8, op, "verify")) key.verify = true;
            if (std.mem.eql(u8, op, "sign")) key.sign = true;
        }
        if (!key.verify and !key.sign) return skip(set, .not_for_signatures);
    }
    const private = w.d != null or w.p != null or w.q != null or w.dp != null or w.dq != null or w.qi != null or w.oth != null;
    if (std.mem.eql(u8, w.kty, "RSA")) {
        if (private) return skip(set, .private);
        const n = decodeMember(arena, w.n) orelse return skip(set, .invalid);
        const e = decodeMember(arena, w.e) orelse return skip(set, .invalid);
        // Minimal big-endian integers (RFC 7518 §6.3.1.1): no leading zero.
        if (n.len == 0 or n[0] == 0 or e.len == 0 or e[0] == 0 or e.len > 8) return skip(set, .invalid);
        const length = bitLength(n);
        if (length < options.min_rsa_bits or length > 4096) return skip(set, .invalid);
        // An even exponent or one of 1 makes no RSA key.
        if (e[e.len - 1] & 1 == 0 or (e.len == 1 and e[0] == 1)) return skip(set, .invalid);
        key.material = .{ .rsa = .{ .n = n, .e = e } };
    } else if (std.mem.eql(u8, w.kty, "EC")) {
        if (private) return skip(set, .private);
        const crv = w.crv orelse return skip(set, .invalid);
        const curve: Key.Curve = if (std.mem.eql(u8, crv, "P-256")) .p256 else if (std.mem.eql(u8, crv, "P-384")) .p384 else return skip(set, .unsupported);
        const width: usize = if (curve == .p256) 32 else 48;
        const x = decodeMember(arena, w.x) orelse return skip(set, .invalid);
        const y = decodeMember(arena, w.y) orelse return skip(set, .invalid);
        // Exactly the field's width (RFC 7518 §6.2.1.2-3).
        if (x.len != width or y.len != width) return skip(set, .invalid);
        const point = try arena.alloc(u8, 1 + 2 * width);
        point[0] = 4;
        @memcpy(point[1..][0..width], x);
        @memcpy(point[1 + width ..], y);
        const valid = switch (curve) {
            .p256 => if (std.crypto.sign.ecdsa.EcdsaP256Sha256.PublicKey.fromSec1(point)) |_| true else |_| false,
            .p384 => if (std.crypto.sign.ecdsa.EcdsaP384Sha384.PublicKey.fromSec1(point)) |_| true else |_| false,
        };
        if (!valid) return skip(set, .invalid);
        key.material = .{ .ec = .{ .curve = curve, .point = point } };
    } else if (std.mem.eql(u8, w.kty, "OKP")) {
        if (private) return skip(set, .private);
        const crv = w.crv orelse return skip(set, .invalid);
        if (!std.mem.eql(u8, crv, "Ed25519")) return skip(set, .unsupported);
        const x = decodeMember(arena, w.x) orelse return skip(set, .invalid);
        if (x.len != 32) return skip(set, .invalid);
        _ = std.crypto.sign.Ed25519.PublicKey.fromBytes(x[0..32].*) catch return skip(set, .invalid);
        key.material = .{ .okp = .{ .x = x } };
    } else if (std.mem.eql(u8, w.kty, "oct")) {
        if (!options.secrets) return skip(set, .secret);
        const k = w.k orelse return skip(set, .invalid);
        const length = base64url.decodedLength(k) catch return skip(set, .invalid);
        if (length == 0) return skip(set, .invalid);
        const storage = set.secrets.?.exposeMut()[secret_used.*..][0..length];
        const secret = base64url.decode(storage, k) catch return skip(set, .invalid);
        secret_used.* += length;
        if (secret.len == 0) return skip(set, .invalid);
        key.material = .{ .hmac = secret };
    } else return skip(set, .unsupported);
    if (w.alg) |name| {
        const alg = Algorithm.parse(name) orelse return skip(set, .algorithm);
        if (alg.family() != std.meta.activeTag(key.material)) return skip(set, .algorithm);
        if (alg.curve()) |c| if (key.material.ec.curve != c) return skip(set, .algorithm);
        key.alg = alg;
    }
    return key;
}

fn decodeMember(arena: std.mem.Allocator, member: ?[]const u8) ?[]const u8 {
    const text = member orelse return null;
    return base64url.decodeAlloc(arena, text) catch null;
}

fn bitLength(big_endian: []const u8) usize {
    for (big_endian, 0..) |byte, i| {
        if (byte != 0) return (big_endian.len - i) * 8 - @clz(byte);
    }
    return 0;
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
            try w.writeAll("{\"crv\":\"Ed25519\",\"kty\":\"OKP\",\"x\":\"");
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
