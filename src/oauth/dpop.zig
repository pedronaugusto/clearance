//! DPoP for a client (RFC 9449): a session holds the key every proof is
//! signed with and the nonce each server last gave, so a token request, a
//! refresh and every resource request carry a proof the server accepts.
//! The proofs themselves are `clearance.dpop`'s.
const std = @import("std");
const aegis = @import("aegis");
const clearance = @import("clearance");
const errors = @import("errors.zig");
const url = @import("url.zig");
const token = @import("token.zig");

const proofs = clearance.dpop;

/// Why a proof could not be written.
pub const ProofError = error{ OutOfMemory, SigningFailed, InvalidKey };

/// How many servers' nonces a session keeps; the oldest goes first.
pub const max_origins = 8;

/// One client's DPoP key and the nonces its servers gave. Its tokens are
/// bound to the key: keep the session (or its key) as long as them. Safe to
/// share between tasks.
pub const Session = struct {
    key: proofs.Key,
    mutex: std.Io.Mutex = .init,
    /// Guarded by `mutex`.
    slots: [max_origins]Slot = @splat(.{}),
    /// Guarded by `mutex`: the slot the next new origin takes.
    next: u8 = 0,

    const Slot = struct {
        origin: errors.Text(256) = .{},
        nonce: errors.Text(256) = .{},
        used: bool = false,
    };

    pub fn init(key: proofs.Key) Session {
        return .{ .key = key };
    }

    /// The thumbprint tokens bound to this session name (`cnf.jkt`), and
    /// the authorization request's `dpop_jkt` (RFC 9449 §10).
    pub fn thumbprint(s: *const Session) [32]u8 {
        return s.key.thumbprint();
    }

    /// Keeps `nonce` (a `DPoP-Nonce` answer) for the server `target` is on.
    /// A nonce that is longer than 256 bytes or not printable is not kept:
    /// it could not be sent back.
    pub fn remember(s: *Session, io: std.Io, target: []const u8, nonce: []const u8) void {
        const origin = url.originOf(target) catch return;
        if (nonce.len == 0 or nonce.len > 256 or origin.len > 256) return;
        for (nonce) |c| if (c < 0x21 or c > 0x7e) return;
        s.mutex.lockUncancelable(io);
        defer s.mutex.unlock(io);
        const slot = s.find(origin) orelse blk: {
            const taken = &s.slots[s.next];
            s.next = (s.next + 1) % max_origins;
            taken.* = .{ .origin = .init(origin), .used = true };
            break :blk taken;
        };
        slot.nonce.set(nonce);
    }

    fn find(s: *Session, origin: []const u8) ?*Slot {
        for (&s.slots) |*slot| if (slot.used and std.mem.eql(u8, slot.origin.slice(), origin)) return slot;
        return null;
    }

    /// Writes a proof for `method` to `target`, with `access_token`'s hash
    /// when the request presents one and the server's last nonce when it
    /// gave one.
    pub fn proof(s: *Session, gpa: std.mem.Allocator, io: std.Io, out: *std.Io.Writer, method: []const u8, target: []const u8, access_token: ?[]const u8) ProofError!void {
        var nonce: errors.Text(256) = .{};
        if (url.originOf(target)) |origin| {
            s.mutex.lockUncancelable(io);
            defer s.mutex.unlock(io);
            if (s.find(origin)) |slot| nonce = slot.nonce;
        } else |_| {}
        proofs.writeProof(gpa, io, out, &s.key, .{
            .htm = method,
            .htu = target,
            .access_token = access_token,
            .nonce = if (nonce.len == 0) null else nonce.slice(),
        }, std.Io.Clock.real.now(io)) catch |err| return switch (err) {
            error.OutOfMemory, error.WriteFailed => error.OutOfMemory,
            error.InvalidKey => error.InvalidKey,
            // A proof's claims are strings and a number, its header clearance's
            // own and its payload encoded: they always write.
            error.SigningFailed, error.InvalidClaims, error.InvalidHeader, error.InvalidPayload => error.SigningFailed,
        };
    }

    /// The two fields of a request to a resource server presenting `set`'s
    /// access token (RFC 9449 §7.1): `Authorization: DPoP <token>` and its
    /// proof. After a 401 whose DPoP challenge says `use_dpop_nonce`,
    /// `remember` its `DPoP-Nonce` and send the request again.
    pub fn headers(s: *Session, gpa: std.mem.Allocator, io: std.Io, method: []const u8, target: []const u8, set: *const token.TokenSet) (ProofError || error{NotBound})!Headers {
        if (set.token_type != .dpop) return error.NotBound;
        var out: std.Io.Writer.Allocating = .init(gpa);
        errdefer out.deinit();
        try s.proof(gpa, io, &out.writer, method, target, set.access_token);
        const prefix = "DPoP ";
        var authorization = aegis.SecretBytes.init(gpa, prefix.len + set.access_token.len) catch return error.OutOfMemory;
        // unreachable: the capacity was just allocated at this length
        authorization.resizeWithinCapacity(prefix.len + set.access_token.len) catch unreachable;
        @memcpy(authorization.exposeMut()[0..prefix.len], prefix);
        @memcpy(authorization.exposeMut()[prefix.len..], set.access_token);
        return .{ .authorization = authorization, .dpop = try out.toOwnedSlice(), .gpa = gpa };
    }
};

/// A resource request's `Authorization` and `DPoP` values.
pub const Headers = struct {
    /// `DPoP <token>`, in wiped memory.
    authorization: aegis.SecretBytes,
    /// The proof.
    dpop: []u8,
    gpa: std.mem.Allocator,

    pub fn deinit(h: *Headers) void {
        h.authorization.deinit(h.gpa);
        h.gpa.free(h.dpop);
        h.* = undefined;
    }
};

const testing = std.testing;

test "a session keeps each server's nonce and signs proofs the server verifies" {
    const gpa = testing.allocator;
    var private = try clearance.jwk.PrivateKey.parse(gpa, "{\"kty\":\"OKP\",\"crv\":\"Ed25519\",\"d\":\"nWGxne_9WmC6hEr0kuwsxERJxWl7MmkZcDusAxyuf2A\",\"x\":\"11qYAYKxCrfVS_7TyWQHOg7hcvPapiMlrwIaaPcHURo\"}", .{});
    defer private.deinit();
    var session: Session = .init(try .fromJwk(&private, null));
    const io = testing.io;
    session.remember(io, "https://as.example/token", "n-1");
    session.remember(io, "https://as.example/par", "n-2");
    session.remember(io, "https://rs.example/mcp", "n-rs");
    session.remember(io, "https://rs.example/mcp", "bad nonce");
    var set = try token.TokenSet.init(gpa, .{ .access_token = "at-1", .token_type = .dpop });
    defer set.deinit();
    var h = try session.headers(gpa, io, "GET", "https://rs.example/mcp?x", &set);
    defer h.deinit();
    try testing.expectEqualStrings("DPoP at-1", h.authorization.expose());
    var scratch: [4096]u8 = undefined;
    var verified: proofs.Verified = undefined;
    try proofs.verifyProof(io, h.dpop, .{ .algorithms = &.{.eddsa}, .htm = "GET", .htu = "https://rs.example/mcp", .access_token = "at-1", .nonce = "n-rs" }, std.Io.Clock.real.now(io), &scratch, &verified);
    try testing.expectEqualSlices(u8, &session.thumbprint(), &verified.thumbprint);
    var out: std.Io.Writer.Allocating = .init(gpa);
    defer out.deinit();
    try session.proof(gpa, io, &out.writer, "POST", "https://as.example/token", null);
    try proofs.verifyProof(io, out.written(), .{ .algorithms = &.{.eddsa}, .htm = "POST", .htu = "https://as.example/token", .nonce = "n-2" }, std.Io.Clock.real.now(io), &scratch, &verified);
    var bearer = try token.TokenSet.init(gpa, .{ .access_token = "at-2" });
    defer bearer.deinit();
    try testing.expectError(error.NotBound, session.headers(gpa, io, "GET", "https://rs.example/mcp", &bearer));
}
