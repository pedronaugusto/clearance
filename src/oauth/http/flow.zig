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
const revocation = @import("../revocation.zig");
const par = @import("../par.zig");
const store = @import("../store.zig");
const dpop = @import("../dpop.zig");
const errors = @import("../errors.zig");
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
    /// The client's DPoP session: every token request carries a proof of its
    /// key, and the tokens come back bound to it (RFC 9449 §5).
    dpop: ?*dpop.Session = null,
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
        .dpop = options.dpop != null,
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
    const Builder = struct {
        client: ?Client,
        grant: token.Grant,
        options: TokenOptions,
        issuer: []const u8,
        fn build(b: @This(), g: std.mem.Allocator, i: std.Io, now: std.Io.Timestamp) client_auth.Error!client_auth.FormRequest {
            return token.request(g, i, b.client, b.grant, .{ .resources = b.options.resources, .extra = b.options.extra }, .{ .issuer = b.issuer, .now = now });
        }
    };
    return postProved(gpa, io, http, endpoint, options, Builder{ .client = client, .grant = grant, .options = options, .issuer = server.issuer });
}

/// POSTs the form request `builder` makes to `endpoint`, with a DPoP proof
/// when `options.dpop` is set: a nonce the server answers with is kept,
/// and a request it refused for want of one is made again, once, with it
/// (RFC 9449 §8). Each attempt is built again: a client assertion's `jti`
/// is spent by the first.
fn postProved(gpa: std.mem.Allocator, io: std.Io, http: *uplink.Client, endpoint: []const u8, options: TokenOptions, builder: anytype) (fetch.Error || client_auth.Error)!Sent {
    var attempt: u8 = 0;
    while (true) : (attempt += 1) {
        const now = std.Io.Clock.real.now(io);
        var request = try builder.build(gpa, io, now);
        defer request.deinit();
        var proof: std.Io.Writer.Allocating = .init(gpa);
        defer proof.deinit();
        if (options.dpop) |session| try session.proof(gpa, io, &proof.writer, "POST", endpoint, null);
        var answer = try fetch.postForm(gpa, io, http, endpoint, &request, if (options.dpop != null) proof.written() else null, options.max_bytes, options.fetch);
        const session = options.dpop orelse return .{ .answer = answer, .at = now };
        if (answer.dpop_nonce) |*n| session.remember(io, endpoint, n.slice());
        if (attempt == 0 and answer.dpop_nonce != null and answer.status == 400 and isNonceError(answer.body.expose())) {
            answer.deinit();
            continue;
        }
        return .{ .answer = answer, .at = now };
    }
}

/// Whether an error body is `use_dpop_nonce`.
fn isNonceError(body: []const u8) bool {
    if (body.len > 4096) return false;
    var scratch: [1024]u8 = undefined;
    const e = errors.readJson(body, &scratch) orelse return false;
    return e.code == .use_dpop_nonce;
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
    /// The set's tokens are bound to a DPoP key and the options carry no
    /// session: the server would refuse the refresh (RFC 9449 §5).
    DpopRequired,
};

/// New tokens for `set`'s refresh token, asking for the scope it was
/// granted (RFC 6749 §6: a refresh keeps the grant's scope). An answer
/// without a refresh token keeps `set`'s.
pub fn refresh(gpa: std.mem.Allocator, io: std.Io, http: *uplink.Client, server: *const Server, client: Client, set: *const TokenSet, options: TokenOptions) RefreshError!token.Response {
    if (set.token_type == .dpop and options.dpop == null) return error.DpopRequired;
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
        /// The DPoP session the code will be redeemed with: the request
        /// carries its thumbprint (`dpop_jkt`, RFC 9449 §10), binding the
        /// code to its key. `finish` then needs the session in its options.
        dpop: ?*const dpop.Session = null,
        extra: []const form.Pair = &.{},
    };

    pub const BeginError = authorize.WriteError || error{
        /// The metadata names no authorization endpoint.
        NoAuthorizationEndpoint,
        /// `require_pkce_listed`, and the metadata does not list S256.
        PkceNotSupported,
        /// The server requires pushed requests (RFC 9126 §5): `push`.
        PushRequired,
    };

    /// Draws the state, the verifier and the nonce from `io`, and writes the
    /// URL to open into `w`.
    pub fn begin(io: std.Io, server: *const Server, request: Begin, w: *std.Io.Writer) BeginError!AuthorizationFlow {
        const endpoint = server.authorization_endpoint orelse return error.NoAuthorizationEndpoint;
        if (server.require_pushed_authorization_requests) return error.PushRequired;
        var flow = try start(io, server, request);
        errdefer flow.deinit();
        var jkt: [43]u8 = undefined;
        try authorize.writeUrl(w, endpoint, flow.parameters(request, &jkt));
        return flow;
    }

    pub const Pushed = union(enum) {
        flow: AuthorizationFlow,
        /// The server refused the pushed request (RFC 9126 §2.3).
        refused: errors.ErrorResponse,
    };

    pub const PushError = authorize.WriteError || fetch.Error || client_auth.Error || par.ReadError || error{
        NoAuthorizationEndpoint,
        PkceNotSupported,
        /// The metadata names no pushed authorization request endpoint.
        NoPushEndpoint,
    };

    /// Pushes the request to `server` (RFC 9126), authenticated as `client`
    /// (with a DPoP proof when `options.dpop` is set, which then binds the
    /// code as well), and writes the URL to open into `w`: the client and
    /// the `request_uri` the server answered with. `finish` reads the
    /// redirect as for `begin`.
    pub fn push(gpa: std.mem.Allocator, io: std.Io, http: *uplink.Client, server: *const Server, client: Client, request: Begin, w: *std.Io.Writer, options: TokenOptions) PushError!Pushed {
        const endpoint = server.authorization_endpoint orelse return error.NoAuthorizationEndpoint;
        const push_endpoint = server.pushed_authorization_request_endpoint orelse return error.NoPushEndpoint;
        var flow = start(io, server, request) catch |err| return switch (err) {
            error.PkceNotSupported => error.PkceNotSupported,
        };
        errdefer flow.deinit();
        var jkt: [43]u8 = undefined;
        const ask = flow.parameters(request, &jkt);
        const Builder = struct {
            client: Client,
            ask: authorize.Request,
            issuer: []const u8,
            fn build(b: @This(), g: std.mem.Allocator, i: std.Io, now: std.Io.Timestamp) client_auth.Error!client_auth.FormRequest {
                return par.request(g, i, b.client, b.ask, .{ .issuer = b.issuer, .now = now });
            }
        };
        var sent = try postProved(gpa, io, http, push_endpoint, options, Builder{ .client = client, .ask = ask, .issuer = server.issuer });
        defer sent.answer.deinit();
        switch (try par.readResponse(sent.answer.status, sent.answer.body.expose(), .{ .now = sent.at, .max_bytes = options.max_bytes })) {
            .refused => |e| {
                flow.deinit();
                return .{ .refused = e };
            },
            .pushed => |p| try authorize.writePushedUrl(w, endpoint, client.id, p.request_uri.slice()),
        }
        return .{ .flow = flow };
    }

    /// The flow's secrets drawn, before any request is written.
    fn start(io: std.Io, server: *const Server, request: Begin) error{PkceNotSupported}!AuthorizationFlow {
        if (request.require_pkce_listed and !server.supportsPkce()) return error.PkceNotSupported;
        var flow: AuthorizationFlow = .{
            .pkce = .generate(io),
            .state = undefined,
            .nonce = null,
            .redirect_uri = request.redirect_uri,
            .scope = request.scope,
            .resources = request.resources,
        };
        pkce.random(io, &flow.state);
        if (request.nonce) {
            var nonce: [pkce.length]u8 = undefined;
            pkce.random(io, &nonce);
            flow.nonce = nonce;
        }
        return flow;
    }

    /// The authorization request's parameters: borrowed from `flow`,
    /// `request` and `jkt`, which holds the DPoP thumbprint when there is one.
    fn parameters(flow: *const AuthorizationFlow, request: Begin, jkt: *[43]u8) authorize.Request {
        if (request.dpop) |session| {
            var jw: std.Io.Writer = .fixed(jkt);
            // unreachable: a SHA-256 is 43 base64url characters
            clearance.base64url.encode(&jw, &session.thumbprint()) catch unreachable;
        }
        return .{
            .client_id = request.client_id,
            .redirect_uri = request.redirect_uri,
            .state = &flow.state,
            .code_challenge = &flow.pkce.challenge,
            .scope = request.scope,
            .resources = request.resources,
            .nonce = if (flow.nonce) |*n| n else null,
            .dpop_jkt = if (request.dpop != null) jkt else null,
            .extra = request.extra,
        };
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
        var answer = try fetch.postForm(gpa, io, http, endpoint, &form_request, null, options.max_bytes, options.fetch);
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

pub const RevokeOptions = struct {
    max_bytes: fetch.Bytes = .literal("64KiB"),
    fetch: fetch.Options = .{},
};

pub const RevokeError = fetch.Error || client_auth.Error || revocation.ReadError || error{
    /// The metadata names no revocation endpoint.
    NoRevocationEndpoint,
};

/// Revokes `token` at `server` (RFC 7009), authenticated as `client`. For a
/// sign-out, revoke the refresh token (the server ends the grant and its
/// access tokens with it, §2.1), then forget the store's entry. Sent once:
/// a refusal, a 503 among them, is the server's answer.
pub fn revoke(gpa: std.mem.Allocator, io: std.Io, http: *uplink.Client, server: *const Server, client: Client, token_text: []const u8, hint: ?revocation.Hint, options: RevokeOptions) RevokeError!revocation.Response {
    const endpoint = server.revocation_endpoint orelse return error.NoRevocationEndpoint;
    var request = try revocation.request(gpa, io, client, token_text, hint, .{ .issuer = server.issuer, .now = std.Io.Clock.real.now(io) });
    defer request.deinit();
    var answer = try fetch.postForm(gpa, io, http, endpoint, &request, null, options.max_bytes, options.fetch);
    defer answer.deinit();
    return revocation.readResponse(answer.status, answer.body.expose(), .{ .max_bytes = options.max_bytes });
}

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
