//! A resource server's token check: the token read from `Authorization:
//! Bearer` (RFC 6750 §2.1; never from the query) or `Authorization: DPoP`
//! with its proof (RFC 9449 §7), checked as a JWT access token (RFC 9068)
//! with a remote key set or asked of the authorization server (RFC 7662),
//! held to this resource as its audience, to the scopes the request needs,
//! and to the key its DPoP proof holds when it is bound; and the answer when
//! it fails: 400, 401 or 403 with the `WWW-Authenticate` challenges that say
//! why (RFC 6750 §3, RFC 9449 §7.1) and where this resource's metadata is
//! (RFC 9728 §5.1).
const std = @import("std");
const uplink = @import("uplink");
const clearance = @import("clearance");
const challenge = @import("../challenge.zig");
const errors = @import("../errors.zig");
const RemoteKeySet = @import("RemoteKeySet.zig");
const Introspector = @import("Introspector.zig");

const access_token = clearance.access_token;
const jws = clearance.jws;
const dpop = clearance.dpop;
const Algorithm = clearance.Algorithm;

/// Where tokens are checked.
pub const Source = union(enum) {
    /// JWT access tokens, verified with the authorization server's keys.
    keys: struct { set: *RemoteKeySet, algorithms: []const Algorithm },
    /// Tokens of any form, asked of the authorization server.
    introspection: *Introspector,
};

/// Who the token speaks for. Strings live in the arena `check` was given.
pub const Principal = struct {
    subject: ?[]const u8 = null,
    client_id: ?[]const u8 = null,
    /// Space-separated.
    scope: ?[]const u8 = null,
    /// Seconds since the epoch.
    expires_at: ?i64 = null,
    /// The DPoP key the token is bound to, when it was presented with its
    /// proof.
    jkt: ?[32]u8 = null,
};

/// What of the request the check reads.
pub const Request = struct {
    /// The `Authorization` value; null when the request has none.
    authorization: ?[]const u8,
    /// Every `DPoP` field the request carries (RFC 9449 §4.3: one, for a
    /// DPoP token).
    dpop: []const []const u8 = &.{},
    /// The method and the absolute URL the request was received at: what a
    /// DPoP proof names.
    method: []const u8 = "GET",
    url: []const u8 = "",
};

/// How a resource that takes DPoP-bound tokens checks their proofs.
pub const Dpop = struct {
    /// The asymmetric algorithms accepted for proofs.
    algorithms: []const Algorithm,
    /// Where proofs' `jti`s are kept for their life (RFC 9449 §11.1).
    replay: ?clearance.jwt.Replay = null,
    max_age: clearance.jwt.Duration = .literal("60s"),
    /// The nonce proofs must carry, when the resource gives them (§9); the
    /// caller rotates it. A proof without it is answered `use_dpop_nonce`
    /// with it in `DPoP-Nonce`.
    nonce: ?[]const u8 = null,
};

/// A request refused: the status to answer with and its challenges.
pub const Refusal = struct {
    /// 400 (a malformed `Authorization`), 401 (no token, or one not valid
    /// here) or 403 (a valid token without the scopes needed).
    status: std.http.Status,
    challenge: challenge.Bearer,
    /// The `DPoP` challenge beside it, for a resource that takes DPoP
    /// tokens: the error is in the scheme the request used.
    dpop: ?challenge.Bearer = null,
    /// The `DPoP-Nonce` to answer with (RFC 9449 §9).
    dpop_nonce: ?[]const u8 = null,

    /// Writes the `WWW-Authenticate` value: the Bearer challenge, then the
    /// DPoP one.
    pub fn write(r: Refusal, w: *std.Io.Writer) challenge.WriteError!void {
        try challenge.write(w, r.challenge);
        if (r.dpop) |d| {
            try w.writeAll(", ");
            try challenge.write(w, d);
        }
    }
};

pub const Outcome = union(enum) {
    allowed: Principal,
    refused: Refusal,
};

pub const CheckError = error{
    /// The key server or the introspection endpoint could not answer, or
    /// refused this resource server's credentials, or the DPoP replay set
    /// is full: a 503, not the client's fault.
    Unavailable,
    Canceled,
    OutOfMemory,
};

pub const Verifier = struct {
    source: Source,
    /// The authorization server's issuer identifier.
    issuer: []const u8,
    /// This resource's identifier: the audience every token must name.
    resource: []const u8,
    /// Where this resource's metadata is, named in every challenge.
    resource_metadata: ?[]const u8 = null,
    realm: ?[]const u8 = null,
    leeway: clearance.jwt.Duration = .literal("0s"),
    max_token_bytes: jws.Bytes = .literal("16KiB"),
    /// Set to take DPoP-bound tokens (RFC 9449 §7); null takes bearer tokens
    /// alone, a bound one refused.
    dpop: ?Dpop = null,

    /// Checks `request` for a token valid here that grants every scope of
    /// `scopes`: a bearer token, or a DPoP token with its proof.
    pub fn check(v: *const Verifier, io: std.Io, http: *uplink.Client, arena: std.mem.Allocator, request: Request, scopes: []const []const u8) CheckError!Outcome {
        const presented = switch (credentials(request.authorization)) {
            .none => return v.refuse(arena, .unauthorized, .bearer, null, null, null),
            .malformed => return v.refuse(arena, .bad_request, .bearer, .invalid_request, "malformed Authorization", null),
            .token => |t| t,
        };
        const scheme = presented.scheme;
        // A resource without DPoP reads another scheme as no token.
        if (scheme == .dpop and v.dpop == null) return v.refuse(arena, .unauthorized, .bearer, null, null, null);
        const token = presented.token;
        const limit: usize = v.max_token_bytes.raw();
        if (token.len > limit) return v.refuse(arena, .unauthorized, scheme, .invalid_token, "size", null);
        const now = std.Io.Clock.real.now(io);

        var binding: access_token.Binding = .none;
        if (scheme == .dpop) {
            const d = v.dpop.?;
            if (request.dpop.len != 1) return v.refuse(arena, .unauthorized, .dpop, .invalid_dpop_proof, "one DPoP proof", null);
            const scratch = try arena.alloc(u8, jws.scratchLength(request.dpop[0].len));
            const proof = try arena.create(dpop.Verified);
            var diagnostics: jws.Diagnostics = .{};
            dpop.verifyProof(io, request.dpop[0], .{
                .algorithms = d.algorithms,
                .htm = request.method,
                .htu = request.url,
                .access_token = token,
                .nonce = d.nonce,
                .max_age = d.max_age,
                .leeway = v.leeway,
                .replay = d.replay,
                .diagnostics = &diagnostics,
            }, now, scratch, proof) catch |err| return switch (err) {
                error.ReplayFull => error.Unavailable,
                error.UseNonce => v.refuse(arena, .unauthorized, .dpop, .use_dpop_nonce, null, null),
                else => v.refuse(arena, .unauthorized, .dpop, .invalid_dpop_proof, @tagName(diagnostics.check), null),
            };
            binding = .{ .dpop = proof.thumbprint };
        }
        const principal = switch (v.source) {
            .keys => |k| try v.checkJwt(io, http, arena, k.set, k.algorithms, token, binding, scheme, now),
            .introspection => |i| try v.checkIntrospected(io, http, arena, i, token, binding, scheme, now),
        };
        const p = switch (principal) {
            .allowed => |p| p,
            .refused => return principal,
        };
        if (!access_token.hasScopes(p.scope, scopes)) {
            const needed = try std.mem.join(arena, " ", scopes);
            return v.refuse(arena, .forbidden, scheme, .insufficient_scope, null, needed);
        }
        return .{ .allowed = p };
    }

    fn checkJwt(v: *const Verifier, io: std.Io, http: *uplink.Client, arena: std.mem.Allocator, set: *RemoteKeySet, algorithms: []const Algorithm, token: []const u8, binding: access_token.Binding, scheme: Scheme, now: std.Io.Timestamp) CheckError!Outcome {
        const scratch = try arena.alloc(u8, jws.scratchLength(token.len));
        var want: RemoteKeySet.Want = .current;
        while (true) {
            var lease = set.lease(io, http, want) catch |err| return switch (err) {
                error.Canceled => error.Canceled,
                error.OutOfMemory => error.OutOfMemory,
                else => error.Unavailable,
            };
            defer lease.release();
            var diagnostics: jws.Diagnostics = .{};
            const expected: access_token.Expected = .{
                .algorithms = algorithms,
                .issuer = v.issuer,
                .audience = v.resource,
                .leeway = v.leeway,
                .binding = binding,
                .max_bytes = v.max_token_bytes,
                .diagnostics = &diagnostics,
            };
            const verified = access_token.verify(void, token, lease.keys, expected, now, scratch) catch |err| {
                // A key the set lacks: fetched again once, as its cooldown allows.
                if (err == error.NoKey and want == .current) {
                    want = .missing_key;
                    continue;
                }
                return v.refuse(arena, .unauthorized, scheme, .invalid_token, @tagName(diagnostics.check), null);
            };
            // The strings live in `scratch`, the arena's; none in the keys.
            return .{ .allowed = .{
                .subject = verified.registered.sub,
                .client_id = verified.access.client_id,
                .scope = verified.access.scope,
                .expires_at = verified.registered.exp,
                .jkt = if (binding == .dpop) binding.dpop else null,
            } };
        }
    }

    fn checkIntrospected(v: *const Verifier, io: std.Io, http: *uplink.Client, arena: std.mem.Allocator, introspector: *Introspector, token: []const u8, binding: access_token.Binding, scheme: Scheme, now: std.Io.Timestamp) CheckError!Outcome {
        const result = introspector.introspect(io, http, arena, token) catch |err| return switch (err) {
            error.Canceled => error.Canceled,
            error.OutOfMemory => error.OutOfMemory,
            else => error.Unavailable,
        };
        const i = switch (result) {
            .refused => |e| {
                // The server introspects no token of this kind (oidc-provider
                // says so of the JWT access tokens it issues, with RFC 7009's
                // code): the token is not shown valid here, the client's to fix.
                if (e.code == .unsupported_token_type)
                    return v.refuse(arena, .unauthorized, scheme, .invalid_token, "unsupported_token_type", null);
                // The server refused this resource server's own credentials,
                // or failed.
                return error.Unavailable;
            },
            .introspected => |i| i,
        };
        const seconds: i64 = @intCast(@divFloor(now.nanoseconds, std.time.ns_per_s));
        const leeway: i64 = v.leeway.raw();
        if (!i.active) return v.refuse(arena, .unauthorized, scheme, .invalid_token, "inactive", null);
        switch (binding) {
            .none => if (i.bound) return v.refuse(arena, .unauthorized, scheme, .invalid_token, "bound", null),
            .dpop => |t| {
                const jkt = i.jkt orelse return v.refuse(arena, .unauthorized, scheme, .invalid_token, "binding", null);
                if (!std.mem.eql(u8, &jkt, &t)) return v.refuse(arena, .unauthorized, scheme, .invalid_token, "binding", null);
            },
            .mtls => |h| {
                const x5t = i.x5t_s256 orelse return v.refuse(arena, .unauthorized, scheme, .invalid_token, "binding", null);
                if (!std.mem.eql(u8, &x5t, &h)) return v.refuse(arena, .unauthorized, scheme, .invalid_token, "binding", null);
            },
        }
        if (i.exp) |exp| if (seconds >= exp +| leeway) return v.refuse(arena, .unauthorized, scheme, .invalid_token, "expired", null);
        if (i.nbf) |nbf| if (seconds +| leeway < nbf) return v.refuse(arena, .unauthorized, scheme, .invalid_token, "not_yet_valid", null);
        if (i.iss) |iss| if (!std.mem.eql(u8, iss, v.issuer)) return v.refuse(arena, .unauthorized, scheme, .invalid_token, "issuer", null);
        // A token must name this resource: one for another would be replayed
        // here (RFC 8707, MCP's audience rule).
        if (!i.hasAudience(v.resource)) return v.refuse(arena, .unauthorized, scheme, .invalid_token, "audience", null);
        return .{ .allowed = .{ .subject = i.sub, .client_id = i.client_id, .scope = i.scope, .expires_at = i.exp, .jkt = if (binding == .dpop) binding.dpop else null } };
    }

    /// The refusal: its error in the challenge of the scheme the request
    /// used, a bare challenge of the other beside it when the resource takes
    /// DPoP, the nonce when the proof needs one.
    fn refuse(v: *const Verifier, arena: std.mem.Allocator, status: std.http.Status, scheme: Scheme, code: ?errors.Code, description: ?[]const u8, scope: ?[]const u8) CheckError!Outcome {
        const named: challenge.Bearer = .{
            .realm = v.realm,
            .@"error" = code,
            .error_description = description,
            .scope = scope,
            .resource_metadata = v.resource_metadata,
        };
        const bare: challenge.Bearer = .{ .realm = v.realm, .resource_metadata = v.resource_metadata };
        const d = v.dpop orelse return .{ .refused = .{ .status = status, .challenge = named } };
        var algs: std.Io.Writer.Allocating = .init(arena);
        for (d.algorithms, 0..) |a, i| {
            if (i != 0) algs.writer.writeByte(' ') catch return error.OutOfMemory;
            algs.writer.writeAll(a.name()) catch return error.OutOfMemory;
        }
        var bearer = if (scheme == .bearer) named else bare;
        var other = if (scheme == .dpop) named else bare;
        bearer.scheme = .bearer;
        other.scheme = .dpop;
        other.algs = algs.written();
        return .{ .refused = .{
            .status = status,
            .challenge = bearer,
            .dpop = other,
            .dpop_nonce = if (code == .use_dpop_nonce) d.nonce else null,
        } };
    }
};

/// The schemes a token is presented with.
pub const Scheme = challenge.Bearer.Scheme;

/// A token as `Authorization` presents it.
pub const Presented = struct { scheme: Scheme, token: []const u8 };

/// What an `Authorization` value holds for a token check.
pub const Credentials = union(enum) { none, malformed, token: Presented };

/// The token of an `Authorization: Bearer` or `Authorization: DPoP` value
/// (RFC 6750 §2.1, RFC 9449 §7.1): the scheme without case, one or more
/// spaces, a b64token. Another scheme is no token.
pub fn credentials(authorization: ?[]const u8) Credentials {
    const value = authorization orelse return .none;
    const space = std.mem.findScalar(u8, value, ' ') orelse value.len;
    const scheme: Scheme = if (std.ascii.eqlIgnoreCase(value[0..space], "bearer")) .bearer else if (std.ascii.eqlIgnoreCase(value[0..space], "dpop")) .dpop else return .none;
    return switch (bearerToken(value[space..])) {
        .none, .malformed => .malformed,
        .token => |t| .{ .token = .{ .scheme = scheme, .token = t } },
    };
}

/// What follows a scheme: a token, or nothing usable.
const Extracted = union(enum) { none, malformed, token: []const u8 };

/// A b64token after its scheme (RFC 6750 §2.1): one or more spaces, then
/// the token and nothing else.
fn bearerToken(rest: []const u8) Extracted {
    if (rest.len == 0 or rest[0] != ' ') return .malformed;
    const token = std.mem.trimStart(u8, rest, " ");
    if (token.len == 0) return .malformed;
    var i: usize = 0;
    while (i < token.len and (std.ascii.isAlphanumeric(token[i]) or std.mem.findScalar(u8, "-._~+/", token[i]) != null)) i += 1;
    if (i == 0) return .malformed;
    while (i < token.len and token[i] == '=') i += 1;
    if (i != token.len) return .malformed;
    return .{ .token = token };
}

test "the token is read from a Bearer or DPoP value alone" {
    try std.testing.expectEqualStrings("mF_9.B5f-4.1JqM", credentials("Bearer mF_9.B5f-4.1JqM").token.token);
    try std.testing.expectEqual(Scheme.bearer, credentials("Bearer mF_9.B5f-4.1JqM").token.scheme);
    try std.testing.expectEqualStrings("abc==", credentials("bearer   abc==").token.token);
    try std.testing.expectEqual(Scheme.dpop, credentials("DPoP Kz~8mXK1EalYznwH-LC-1fBAo.4Ljp~zsPE_NeO.gxU").token.scheme);
    try std.testing.expectEqual(Credentials.none, credentials(null));
    try std.testing.expectEqual(Credentials.none, credentials("Basic dXNlcjpwdw=="));
    try std.testing.expectEqual(Credentials.malformed, credentials("Bearer"));
    try std.testing.expectEqual(Credentials.malformed, credentials("DPoP"));
    try std.testing.expectEqual(Credentials.malformed, credentials("Bearer "));
    try std.testing.expectEqual(Credentials.malformed, credentials("Bearer a b"));
    try std.testing.expectEqual(Credentials.malformed, credentials("Bearer a=b"));
    try std.testing.expectEqual(Credentials.malformed, credentials("Bearer \"a\""));
}
