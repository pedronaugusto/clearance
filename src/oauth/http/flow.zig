//! The flows performed: the authorization code flow with PKCE (begun as a
//! URL for the browser, finished from the redirect), refresh, client
//! credentials, a JWT as the grant, the ID-JAG's exchange and redemption,
//! dynamic registration, and the tokens a store keeps, kept fresh. Each takes the authorization server's metadata as discovered, so
//! every endpoint was checked when it was read.
const std = @import("std");
const aegis = @import("aegis");
const uplink = @import("uplink");
const clearance = @import("clearance");
const form = @import("uplink.wire").form;
const metadata = @import("../metadata.zig");
const pkce = @import("../pkce.zig");
const authorize = @import("../authorize.zig");
const client_auth = @import("../client_auth.zig");
const token = @import("../token.zig");
const registration = @import("../registration.zig");
const id_jag = @import("../id_jag.zig");
const device = @import("../device.zig");
const store = @import("../store.zig");
const fetch = @import("fetch.zig");

const Server = metadata.AuthorizationServer;
const Client = client_auth.Client;
const TokenSet = token.TokenSet;

pub const TokenOptions = struct {
    /// RFC 8707's `resource`, once each: MCP names its server here.
    resources: []const []const u8 = &.{},
    /// Any further parameters, written last.
    extra: []const form.Pair = &.{},
    max_bytes: fetch.Bytes = .literal("64KiB"),
    fetch: fetch.Options = .{},
};

pub const TokenError = fetch.Error || client_auth.Error || token.ReadError || error{
    /// The metadata names no token endpoint.
    NoTokenEndpoint,
};

/// Asks the token endpoint of `server` for `grant`, authenticated as
/// `client` says. `read` carries what the answer is read with beyond the
/// clock: the scope asked, the refresh token spent.
pub fn requestToken(
    gpa: std.mem.Allocator,
    io: std.Io,
    http: *uplink.Client,
    server: *const Server,
    client: ?Client,
    grant: token.Grant,
    read: struct { requested_scope: ?[]const u8 = null, previous_refresh_token: ?[]const u8 = null },
    options: TokenOptions,
) TokenError!token.Response {
    var sent = try send(gpa, io, http, server, client, grant, options);
    defer sent.answer.deinit();
    return token.readResponse(gpa, sent.answer.status, sent.answer.body.expose(), .{
        .now = sent.at,
        .requested_scope = read.requested_scope,
        .previous_refresh_token = read.previous_refresh_token,
        .max_bytes = options.max_bytes,
    });
}

/// A grant sent to the token endpoint, its answer not yet read.
const Sent = struct {
    answer: fetch.SecretAnswer,
    /// When the request left: `expires_in` counts from it, so an expiry is
    /// never later than the server's.
    at: std.Io.Timestamp,
};

fn send(gpa: std.mem.Allocator, io: std.Io, http: *uplink.Client, server: *const Server, client: ?Client, grant: token.Grant, options: TokenOptions) (fetch.Error || client_auth.Error || error{NoTokenEndpoint})!Sent {
    const endpoint = server.token_endpoint orelse return error.NoTokenEndpoint;
    const now = std.Io.Clock.real.now(io);
    var request = try token.request(gpa, io, client, grant, .{ .resources = options.resources, .extra = options.extra }, .{ .issuer = server.issuer, .now = now });
    defer request.deinit();
    return .{ .answer = try fetch.postForm(gpa, io, http, endpoint, &request, options.max_bytes, options.fetch), .at = now };
}

/// Tokens for a JWT presented as the grant (RFC 7523 §2.1): a workload's
/// identity token, its platform's word for who it is (MCP's workload
/// identity federation). `client` is null when the assertion is the only
/// credential the server asks for. A refusal is the server's answer, never
/// retried here: the same assertion would be refused again.
pub fn jwtBearer(gpa: std.mem.Allocator, io: std.Io, http: *uplink.Client, server: *const Server, client: ?Client, assertion: []const u8, scope: ?[]const u8, options: TokenOptions) TokenError!token.Response {
    return requestToken(gpa, io, http, server, client, .{ .jwt_bearer = .{ .assertion = assertion, .scope = scope } }, .{ .requested_scope = scope }, options);
}

pub const IdJagError = fetch.Error || client_auth.Error || id_jag.RequestError || id_jag.ReadError || error{NoTokenEndpoint};

/// An ID-JAG from the identity provider `idp` (its metadata, discovered or
/// configured): the user's token there exchanged for an assertion to
/// `request.audience` (RFC 8693), checked against `request`. `client` is
/// the client as the identity provider knows it.
pub fn requestIdJag(gpa: std.mem.Allocator, io: std.Io, http: *uplink.Client, idp: *const Server, client: Client, request: id_jag.Request, options: TokenOptions) IdJagError!id_jag.Response {
    // The provider's metadata and the request name one identity provider.
    if (!std.mem.eql(u8, idp.issuer, request.idp_issuer)) return error.InvalidRequest;
    const grant = try id_jag.exchangeGrant(request);
    var exchange = options;
    exchange.resources = &.{request.resource};
    var sent = try send(gpa, io, http, idp, client, grant, exchange);
    defer sent.answer.deinit();
    return id_jag.readIssued(gpa, sent.answer.status, sent.answer.body.expose(), request, .{ .now = sent.at, .max_bytes = options.max_bytes });
}

pub const RedeemError = fetch.Error || client_auth.Error || id_jag.RedemptionError || error{
    NoTokenEndpoint,
    /// The ID-JAG expired before it was sent: a new one is due.
    GrantExpired,
};

/// An access token for `grant`, redeemed at `server` (the authorization
/// server the ID-JAG names, RFC 7523 §2.1) by `client` as that server knows
/// it, for `resource`. Sent once: a refusal is the server's answer.
pub fn redeemIdJag(gpa: std.mem.Allocator, io: std.Io, http: *uplink.Client, server: *const Server, client: Client, grant: *const id_jag.Grant, resource: []const u8, options: TokenOptions) RedeemError!token.Response {
    if (grant.expired(std.Io.Clock.real.now(io))) return error.GrantExpired;
    var redemption = options;
    // Only the assertion carries authority (`Grant.redemption`).
    redemption.resources = &.{};
    var sent = try send(gpa, io, http, server, client, grant.redemption(), redemption);
    defer sent.answer.deinit();
    return id_jag.readRedemption(gpa, sent.answer.status, sent.answer.body.expose(), grant, resource, .{ .now = sent.at, .max_bytes = options.max_bytes });
}

pub const RefreshError = TokenError || error{
    /// The set has no refresh token.
    NoRefreshToken,
};

/// New tokens for `set`'s refresh token, asking for the scope it was
/// granted (RFC 6749 §6: a refresh keeps the grant's scope). An answer
/// without a refresh token keeps `set`'s.
pub fn refresh(gpa: std.mem.Allocator, io: std.Io, http: *uplink.Client, server: *const Server, client: Client, set: *const TokenSet, options: TokenOptions) RefreshError!token.Response {
    const refresh_token = set.refresh_token orelse return error.NoRefreshToken;
    return requestToken(gpa, io, http, server, client, .{ .refresh_token = .{ .refresh_token = refresh_token } }, .{
        .requested_scope = set.scope,
        .previous_refresh_token = refresh_token,
    }, options);
}

/// Tokens for the client itself (OAuth 2.1 §4.2).
pub fn clientCredentials(gpa: std.mem.Allocator, io: std.Io, http: *uplink.Client, server: *const Server, client: Client, scope: ?[]const u8, options: TokenOptions) TokenError!token.Response {
    return requestToken(gpa, io, http, server, client, .{ .client_credentials = .{ .scope = scope } }, .{ .requested_scope = scope }, options);
}

/// The authorization code flow with PKCE (OAuth 2.1 §4.1), one sign-in:
/// `begin` writes the URL to open and keeps the request's secrets; `finish`
/// reads the redirect it led to and spends the code.
pub const AuthorizationFlow = struct {
    pkce: pkce.Pkce,
    state: [pkce.length]u8,
    /// OpenID Connect's, when an ID token was asked for.
    nonce: ?[pkce.length]u8,
    /// Borrowed from `Begin`: they must live until `finish`.
    redirect_uri: []const u8,
    scope: ?[]const u8,
    resources: []const []const u8,

    pub const Begin = struct {
        client_id: []const u8,
        /// Exactly as registered; a loopback one for a native app (RFC 8252).
        redirect_uri: []const u8,
        /// Space-separated; none asked when null.
        scope: ?[]const u8 = null,
        /// RFC 8707's `resource`, once each: repeated to the token endpoint.
        resources: []const []const u8 = &.{},
        /// Whether to send a `nonce`: an OpenID Connect sign-in.
        nonce: bool = false,
        /// Refuse a server whose metadata does not list S256 (MCP's rule;
        /// OAuth 2.1 lets a server leave the list out, and PKCE is sent
        /// either way).
        require_pkce_listed: bool = false,
        extra: []const form.Pair = &.{},
    };

    pub const BeginError = authorize.WriteError || error{
        /// The metadata names no authorization endpoint.
        NoAuthorizationEndpoint,
        /// `require_pkce_listed`, and the metadata does not list S256.
        PkceNotSupported,
    };

    /// Draws the state, the verifier and the nonce from `io`, and writes the
    /// URL to open into `w`.
    pub fn begin(io: std.Io, server: *const Server, request: Begin, w: *std.Io.Writer) BeginError!AuthorizationFlow {
        const endpoint = server.authorization_endpoint orelse return error.NoAuthorizationEndpoint;
        if (request.require_pkce_listed and !server.supportsPkce()) return error.PkceNotSupported;
        var flow: AuthorizationFlow = .{
            .pkce = .generate(io),
            .state = undefined,
            .nonce = null,
            .redirect_uri = request.redirect_uri,
            .scope = request.scope,
            .resources = request.resources,
        };
        errdefer flow.deinit();
        pkce.random(io, &flow.state);
        if (request.nonce) {
            var nonce: [pkce.length]u8 = undefined;
            pkce.random(io, &nonce);
            flow.nonce = nonce;
        }
        try authorize.writeUrl(w, endpoint, .{
            .client_id = request.client_id,
            .redirect_uri = request.redirect_uri,
            .state = &flow.state,
            .code_challenge = &flow.pkce.challenge,
            .scope = request.scope,
            .resources = request.resources,
            .nonce = if (flow.nonce) |*n| n else null,
            .extra = request.extra,
        });
        return flow;
    }

    /// Verifies the ID token `set` brought (`error.NoIdToken` when none):
    /// for the client `client_id` from `server`, with this flow's `nonce` and
    /// the set's access token for `at_hash`, signed by one of `keys` with one
    /// of `algorithms`. Strings borrow from `scratch` and the keys.
    pub fn verifyIdToken(
        flow: *const AuthorizationFlow,
        comptime Extra: type,
        set: *const TokenSet,
        server: *const Server,
        client_id: []const u8,
        keys: []const clearance.Key,
        algorithms: []const clearance.Algorithm,
        now: std.Io.Timestamp,
        scratch: []u8,
    ) (clearance.id_token.VerifyError || error{NoIdToken})!clearance.id_token.Verified(Extra) {
        const token_text = set.id_token orelse return error.NoIdToken;
        return clearance.id_token.verify(Extra, token_text, keys, .{
            .algorithms = algorithms,
            .issuer = server.issuer,
            .client_id = client_id,
            .nonce = if (flow.nonce) |*n| n else null,
            .access_token = set.access_token,
        }, now, scratch);
    }

    pub fn deinit(flow: *AuthorizationFlow) void {
        flow.pkce.deinit();
        flow.* = undefined;
    }

    pub const FinishError = TokenError || authorize.CallbackError;

    /// Reads `redirect` (the URL the browser was sent back to, or its
    /// query): `state` checked, then `iss` against `server` (RFC 9207,
    /// required when the metadata advertises it), then the code exchanged
    /// with the verifier. A refusal at either step is `.refused`.
    pub fn finish(flow: *const AuthorizationFlow, gpa: std.mem.Allocator, io: std.Io, http: *uplink.Client, server: *const Server, client: Client, redirect: []const u8, options: TokenOptions) FinishError!token.Response {
        const query = if (std.mem.findScalar(u8, redirect, '?') != null) authorize.queryOf(redirect) else redirect;
        // The code is a secret until spent: decoded into wiped memory.
        var scratch = aegis.SecretBytes.init(gpa, query.len) catch return error.OutOfMemory;
        defer scratch.deinit();
        // unreachable: the capacity was just allocated at this length
        scratch.resizeWithinCapacity(query.len) catch unreachable;
        const callback = try authorize.readCallback(query, .{
            .state = &flow.state,
            .issuer = server.issuer,
            .issuer_required = server.authorization_response_iss_parameter_supported,
        }, scratch.exposeMut());
        const code = switch (callback) {
            .refused => |e| return .{ .refused = e },
            .code => |c| c,
        };
        var exchange = options;
        if (exchange.resources.len == 0) exchange.resources = flow.resources;
        return requestToken(gpa, io, http, server, client, .{ .authorization_code = .{
            .code = code,
            .redirect_uri = flow.redirect_uri,
            .code_verifier = flow.pkce.verifier.expose(),
        } }, .{ .requested_scope = flow.scope }, exchange);
    }
};

/// Device authorization (RFC 8628): `begin` asks for the codes the person
/// is shown, `poll` makes one token request with the device code, and
/// `wait` polls at the server's interval until the person has finished.
pub const DeviceFlow = struct {
    authorization: device.Authorization,
    /// The scope asked: the granted one when the answer names none.
    /// Borrowed from `begin`'s request.
    scope: ?[]const u8,
    /// RFC 8707's resources, repeated to the token endpoint. Borrowed.
    resources: []const []const u8,

    pub const Begun = union(enum) {
        flow: DeviceFlow,
        refused: @import("../errors.zig").ErrorResponse,
    };

    pub const BeginError = fetch.Error || client_auth.Error || device.ReadError || error{
        /// The metadata names no device authorization endpoint.
        NoDeviceEndpoint,
    };

    /// Asks `server` for a device's codes, for `client` (a public client
    /// sends its id; a confidential one authenticates as at the token
    /// endpoint).
    pub fn begin(gpa: std.mem.Allocator, io: std.Io, http: *uplink.Client, server: *const Server, client: Client, request: device.Request, options: TokenOptions) BeginError!Begun {
        const endpoint = server.device_authorization_endpoint orelse return error.NoDeviceEndpoint;
        const now = std.Io.Clock.real.now(io);
        var form_request = try device.request(gpa, io, client, request, .{ .issuer = server.issuer, .now = now });
        defer form_request.deinit();
        var answer = try fetch.postForm(gpa, io, http, endpoint, &form_request, options.max_bytes, options.fetch);
        defer answer.deinit();
        return switch (try device.readAuthorization(gpa, answer.status, answer.body.expose(), .{ .now = now, .max_bytes = options.max_bytes })) {
            .authorization => |a| .{ .flow = .{ .authorization = a, .scope = request.scope, .resources = request.resources } },
            .refused => |e| .{ .refused = e },
        };
    }

    pub fn deinit(flow: *DeviceFlow) void {
        flow.authorization.deinit();
        flow.* = undefined;
    }

    pub const Poll = union(enum) {
        tokens: TokenSet,
        /// The person has not finished: ask again after the interval.
        pending,
        /// Asked too soon: the interval has grown by five seconds (RFC 8628
        /// §3.5), ask again after it.
        slow_down,
        /// Refused for good: `access_denied`, `expired_token`, or another
        /// error.
        refused: @import("../errors.zig").ErrorResponse,
    };

    /// One token request with the device code.
    pub fn poll(flow: *DeviceFlow, gpa: std.mem.Allocator, io: std.Io, http: *uplink.Client, server: *const Server, client: Client, options: TokenOptions) TokenError!Poll {
        var exchange = options;
        if (exchange.resources.len == 0) exchange.resources = flow.resources;
        const response = try requestToken(gpa, io, http, server, client, .{ .device_code = .{ .device_code = flow.authorization.device_code } }, .{ .requested_scope = flow.scope }, exchange);
        return switch (response) {
            .tokens => |t| .{ .tokens = t },
            .refused => |e| switch (e.code) {
                .authorization_pending => .pending,
                .slow_down => blk: {
                    flow.authorization.interval +|= 5;
                    break :blk .slow_down;
                },
                else => .{ .refused = e },
            },
        };
    }

    pub const WaitError = TokenError || error{
        /// The codes expired before the person finished: begin again.
        Expired,
        Canceled,
    };

    /// Polls at the interval until the person has finished: the tokens, or
    /// the server's refusal. Each wait is `io`'s sleep, so canceling the
    /// task ends it.
    pub fn wait(flow: *DeviceFlow, gpa: std.mem.Allocator, io: std.Io, http: *uplink.Client, server: *const Server, client: Client, options: TokenOptions) WaitError!token.Response {
        while (true) {
            const now = std.Io.Clock.real.now(io);
            const seconds: i64 = @intCast(@divFloor(now.nanoseconds, std.time.ns_per_s));
            // A request after the codes expired would only be refused.
            if (seconds +| @as(i64, flow.authorization.interval) >= flow.authorization.expires_at) return error.Expired;
            try io.sleep(.fromSeconds(flow.authorization.interval), .awake);
            switch (try flow.poll(gpa, io, http, server, client, options)) {
                .tokens => |t| return .{ .tokens = t },
                .refused => |e| return .{ .refused = e },
                .pending, .slow_down => {},
            }
        }
    }
};

pub const RegisterOptions = struct {
    /// RFC 7591 §3's initial access token, when the server asks for one.
    initial_access_token: ?[]const u8 = null,
    max_bytes: fetch.Bytes = .literal("64KiB"),
    fetch: fetch.Options = .{},
};

pub const RegisterError = fetch.Error || registration.WriteError || registration.ReadError || error{
    /// The metadata names no registration endpoint.
    NoRegistrationEndpoint,
};

/// Registers a client with `server` (RFC 7591).
pub fn register(gpa: std.mem.Allocator, io: std.Io, http: *uplink.Client, server: *const Server, client_metadata: registration.ClientMetadata, options: RegisterOptions) RegisterError!registration.Response {
    const endpoint = server.registration_endpoint orelse return error.NoRegistrationEndpoint;
    var body: std.Io.Writer.Allocating = .init(gpa);
    defer body.deinit();
    registration.writeRequest(&body.writer, client_metadata) catch |err| return switch (err) {
        error.WriteFailed => error.OutOfMemory,
        error.InvalidMetadata => error.InvalidMetadata,
    };
    var answer = try fetch.postJson(gpa, io, http, endpoint, body.written(), options.initial_access_token, options.max_bytes, options.fetch);
    defer answer.deinit();
    return registration.readResponse(gpa, answer.status, answer.body.expose(), .{ .max_bytes = options.max_bytes });
}

pub const FreshOptions = struct {
    /// Refresh when the access token expires within this.
    margin: aegis.units.Duration(.second, u32) = .literal("60s"),
    token: TokenOptions = .{},
};

pub const FreshError = RefreshError || store.LoadError || store.SaveError || error{
    /// The refresh was refused for a reason other than the grant's end
    /// (`invalid_grant`): the server's error, not this client's tokens.
    RefreshRefused,
};

/// The tokens `tokens` keeps under `key`, refreshed and saved first when the
/// access token expires within the margin. Null when none are kept, or the
/// kept ones are spent: expired with no refresh token, or a refresh the
/// server answered `invalid_grant` (they are forgotten then): a sign-in is
/// due.
pub fn fresh(gpa: std.mem.Allocator, io: std.Io, http: *uplink.Client, tokens: store.TokenStore, key: []const u8, server: *const Server, client: Client, options: FreshOptions) FreshError!?TokenSet {
    var set = (try tokens.load(io, gpa, key)) orelse return null;
    const now = std.Io.Clock.real.now(io);
    if (!set.expiresWithin(now, options.margin)) return set;
    if (set.refresh_token == null) {
        // Still usable for the margin's rest; spent once past its expiry.
        if (!set.expiresWithin(now, .literal("0s"))) return set;
        set.deinit();
        tokens.forget(io, key);
        return null;
    }
    const response = refresh(gpa, io, http, server, client, &set, options.token);
    set.deinit();
    switch (try response) {
        .refused => |e| {
            if (e.code != .invalid_grant) return error.RefreshRefused;
            tokens.forget(io, key);
            return null;
        },
        .tokens => |renewed| {
            var kept = renewed;
            errdefer kept.deinit();
            try tokens.save(io, key, &kept);
            return kept;
        },
    }
}
