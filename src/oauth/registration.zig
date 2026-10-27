//! A client's metadata, sent to register it (RFC 7591) or published at its
//! client ID's URL (draft-ietf-oauth-client-id-metadata-document), and the
//! registration endpoint's answer read.
const std = @import("std");
const aegis = @import("aegis");
const strand = @import("strand");
const errors = @import("errors.zig");
const url = @import("url.zig");

/// Client metadata (RFC 7591 §2): what a client says of itself. Null members
/// are left out of what is written.
pub const ClientMetadata = struct {
    redirect_uris: ?[]const []const u8 = null,
    token_endpoint_auth_method: ?[]const u8 = null,
    grant_types: ?[]const []const u8 = null,
    response_types: ?[]const []const u8 = null,
    client_name: ?[]const u8 = null,
    client_uri: ?[]const u8 = null,
    logo_uri: ?[]const u8 = null,
    scope: ?[]const u8 = null,
    contacts: ?[]const []const u8 = null,
    tos_uri: ?[]const u8 = null,
    policy_uri: ?[]const u8 = null,
    /// Where the client's public keys are, for `private_key_jwt`.
    jwks_uri: ?[]const u8 = null,
    /// The client's public keys, as a JWK set, in place of `jwks_uri`.
    jwks: ?strand.json.Raw = null,
    software_id: ?[]const u8 = null,
    software_version: ?[]const u8 = null,
    /// OpenID Connect Dynamic Client Registration §2: `native` for an
    /// application on the user's device, `web` for one a server runs; MCP
    /// asks every client to name it when it registers.
    application_type: ?ApplicationType = null,
    /// OpenID Connect RP-Initiated Logout 1.0 §3.1: where the provider may
    /// send the browser after a logout.
    post_logout_redirect_uris: ?[]const []const u8 = null,
    /// OpenID Connect Back-Channel Logout 1.0 §2.2: where logout tokens are
    /// POSTed, and whether they must carry `sid`.
    backchannel_logout_uri: ?[]const u8 = null,
    backchannel_logout_session_required: ?bool = null,
    /// OpenID Connect Front-Channel Logout 1.0 §2: the page the provider
    /// renders in an iframe, and whether it gets `iss` and `sid`.
    frontchannel_logout_uri: ?[]const u8 = null,
    frontchannel_logout_session_required: ?bool = null,
    /// RFC 8705 §2.1.2: what of the certificate names the client under
    /// `tls_client_auth`, one of these.
    tls_client_auth_subject_dn: ?[]const u8 = null,
    tls_client_auth_san_dns: ?[]const u8 = null,
    tls_client_auth_san_uri: ?[]const u8 = null,
    tls_client_auth_san_ip: ?[]const u8 = null,
    tls_client_auth_san_email: ?[]const u8 = null,
    /// RFC 8705 §3.4: the client asks for certificate-bound access tokens.
    tls_client_certificate_bound_access_tokens: ?bool = null,
    /// JAR (RFC 9101 §10.4) and OpenID Connect Registration: the request
    /// object's signing algorithm, the encryption of it, and whether every
    /// authorization request must carry one.
    request_object_signing_alg: ?[]const u8 = null,
    request_object_encryption_alg: ?[]const u8 = null,
    request_object_encryption_enc: ?[]const u8 = null,
    require_signed_request_object: ?bool = null,
    /// OpenID Connect Registration §2: encrypted ID tokens and UserInfo
    /// answers (`id_token.Expected.decryption`, `userinfo.Expected.encrypted`).
    id_token_encrypted_response_alg: ?[]const u8 = null,
    id_token_encrypted_response_enc: ?[]const u8 = null,
    userinfo_signed_response_alg: ?[]const u8 = null,
    userinfo_encrypted_response_alg: ?[]const u8 = null,
    userinfo_encrypted_response_enc: ?[]const u8 = null,
};

pub const ApplicationType = enum { native, web };

pub const WriteError = std.Io.Writer.Error || error{
    /// `jwks` is not one JSON value.
    InvalidMetadata,
};

/// Writes the registration request's body (RFC 7591 §3.1), JSON.
pub fn writeRequest(w: *std.Io.Writer, metadata: ClientMetadata) WriteError!void {
    strand.json.write(w, metadata, .{ .nulls = .omit }) catch |err| return switch (err) {
        error.WriteFailed => error.WriteFailed,
        else => error.InvalidMetadata,
    };
}

/// Writes a client ID metadata document: the metadata and `client_id`, the
/// document's own URL, which `url.clientIdDocument` checks.
pub fn writeDocument(w: *std.Io.Writer, client_id: []const u8, metadata: ClientMetadata) (WriteError || url.ClientIdError)!void {
    _ = try url.clientIdDocument(client_id);
    var open = strand.json.writeObjectOpen(w, metadata, .{ .nulls = .omit }) catch |err| return switch (err) {
        error.WriteFailed => error.WriteFailed,
        else => error.InvalidMetadata,
    };
    open.member("client_id", client_id) catch |err| return switch (err) {
        error.WriteFailed => error.WriteFailed,
        else => error.InvalidMetadata,
    };
    try open.close();
}

/// A registered client (RFC 7591 §3.2.1): its id and secret, owned. The
/// secret and the registration access token live in memory `deinit` wipes.
pub const Registration = struct {
    client_id: []const u8,
    client_secret: ?[]const u8 = null,
    /// Seconds since the epoch; null when the response leaves it out.
    client_id_issued_at: ?i64 = null,
    /// When the secret expires, seconds since the epoch; 0 for never; null
    /// when the response leaves it out. RFC 7591 §3.2.1 requires it with a
    /// secret, and servers leave it out (the MCP conformance suite's among
    /// them): a secret with no expiry stated is read as one that says nothing
    /// of when it ends, as the members a response omits are.
    client_secret_expires_at: ?i64 = null,
    registration_access_token: ?[]const u8 = null,
    registration_client_uri: ?[]const u8 = null,
    /// What the server registered, which may differ from what was asked.
    token_endpoint_auth_method: ?[]const u8 = null,
    redirect_uris: ?[]const []const u8 = null,
    grant_types: ?[]const []const u8 = null,
    scope: ?[]const u8 = null,
    /// Private: holds every string above.
    storage: aegis.SecretBytes,
    /// What the secret bytes were allocated with, which frees them.
    gpa: std.mem.Allocator,

    pub fn deinit(r: *Registration) void {
        r.storage.deinit(r.gpa);
        r.* = undefined;
    }
};

const Wire = struct {
    client_id: []const u8,
    client_secret: ?[]const u8 = null,
    client_id_issued_at: ?i64 = null,
    client_secret_expires_at: ?i64 = null,
    registration_access_token: ?[]const u8 = null,
    registration_client_uri: ?[]const u8 = null,
    token_endpoint_auth_method: ?[]const u8 = null,
    redirect_uris: ?[]const []const u8 = null,
    grant_types: ?[]const []const u8 = null,
    scope: ?[]const u8 = null,
};

pub const Response = union(enum) {
    registered: Registration,
    refused: errors.ErrorResponse,
};

pub const ReadError = error{
    TooLarge,
    /// A success that is not a registration: no `client_id`, a member of the
    /// wrong type or twice.
    InvalidResponse,
    /// Neither a success nor an OAuth error body.
    UnexpectedStatus,
} || std.mem.Allocator.Error;

pub const ReadOptions = struct {
    max_bytes: aegis.units.Bytes(usize) = .literal("64KiB"),
};

/// Reads the registration endpoint's answer: 201 (or any 2xx) as a
/// registration, another status as the server's error when the body is one.
pub fn readResponse(gpa: std.mem.Allocator, status: u16, body: []const u8, options: ReadOptions) ReadError!Response {
    const limit: usize = options.max_bytes.raw();
    if (body.len > limit) return error.TooLarge;
    if (status < 200 or status > 299) {
        var scratch: [1024]u8 = undefined;
        if (body.len <= 4096) if (errors.readJson(body, &scratch)) |e| return .{ .refused = e };
        return error.UnexpectedStatus;
    }
    // The body is copied into wiped memory and parsed there, so every string,
    // the secret among them, lives in it.
    const capacity = body.len * 3 + 4096;
    var storage = aegis.SecretBytes.init(gpa, capacity) catch return error.OutOfMemory;
    errdefer storage.deinit(gpa);
    // unreachable: the capacity was just allocated at this length
    storage.resizeWithinCapacity(capacity) catch unreachable;
    const bytes = storage.exposeMut();
    @memcpy(bytes[0..body.len], body);
    var fixed: std.heap.FixedBufferAllocator = .init(bytes[body.len..]);
    const wire = strand.json.parseLeaky(Wire, fixed.allocator(), bytes[0..body.len], .{
        .ignore_unknown_fields = true,
        .limits = .{ .depth = 16 },
    }) catch return error.InvalidResponse;
    if (wire.client_id.len == 0) return error.InvalidResponse;
    var r: Registration = .{ .client_id = wire.client_id, .storage = storage, .gpa = gpa };
    inline for (@typeInfo(Wire).@"struct".field_names) |name| {
        if (comptime !std.mem.eql(u8, name, "client_id")) @field(r, name) = @field(wire, name);
    }
    return .{ .registered = r };
}

const testing = std.testing;

test "RFC 7591 §3.1's request is written without its nulls" {
    var out: std.Io.Writer.Allocating = .init(testing.allocator);
    defer out.deinit();
    try writeRequest(&out.writer, .{
        .redirect_uris = &.{ "https://client.example.org/callback", "https://client.example.org/callback2" },
        .client_name = "My Example Client",
        .token_endpoint_auth_method = "client_secret_basic",
        .logo_uri = "https://client.example.org/logo.png",
        .jwks_uri = "https://client.example.org/my_public_keys.jwks",
    });
    try testing.expectEqualStrings("{\"redirect_uris\":[\"https://client.example.org/callback\",\"https://client.example.org/callback2\"],\"token_endpoint_auth_method\":\"client_secret_basic\",\"client_name\":\"My Example Client\",\"logo_uri\":\"https://client.example.org/logo.png\",\"jwks_uri\":\"https://client.example.org/my_public_keys.jwks\"}", out.written());
}

test "a client ID metadata document carries its own URL" {
    var out: std.Io.Writer.Allocating = .init(testing.allocator);
    defer out.deinit();
    try writeDocument(&out.writer, "https://app.example/client.json", .{ .client_name = "App", .redirect_uris = &.{"http://127.0.0.1/cb"}, .token_endpoint_auth_method = "none" });
    try testing.expectEqualStrings("{\"redirect_uris\":[\"http://127.0.0.1/cb\"],\"token_endpoint_auth_method\":\"none\",\"client_name\":\"App\",\"client_id\":\"https://app.example/client.json\"}", out.written());
    try testing.expectError(error.InvalidClientId, writeDocument(&out.writer, "http://app.example/client.json", .{}));
}

test "an application type is written by its name" {
    var out: std.Io.Writer.Allocating = .init(testing.allocator);
    defer out.deinit();
    try writeRequest(&out.writer, .{ .client_name = "cli", .application_type = .native });
    try testing.expectEqualStrings("{\"client_name\":\"cli\",\"application_type\":\"native\"}", out.written());
}

test "RFC 7591 §3.2.1's response is read, the secret owned" {
    const body =
        \\{"client_id":"s6BhdRkqt3","client_secret":"cf136dc3c1fc93f31185e5885805d","client_id_issued_at":2893256800,
        \\"client_secret_expires_at":2893276800,"redirect_uris":["https://client.example.org/callback","https://client.example.org/callback2"],
        \\"grant_types":["authorization_code","refresh_token"],"client_name":"My Example Client","token_endpoint_auth_method":"client_secret_basic",
        \\"logo_uri":"https://client.example.org/logo.png","jwks_uri":"https://client.example.org/my_public_keys.jwks","example_extension_parameter":"example_value"}
    ;
    var response = try readResponse(testing.allocator, 201, body, .{});
    defer response.registered.deinit();
    const r = &response.registered;
    try testing.expectEqualStrings("s6BhdRkqt3", r.client_id);
    try testing.expectEqualStrings("cf136dc3c1fc93f31185e5885805d", r.client_secret.?);
    try testing.expectEqual(@as(?i64, 2893276800), r.client_secret_expires_at);
    try testing.expectEqualStrings("client_secret_basic", r.token_endpoint_auth_method.?);
    try testing.expectEqual(@as(usize, 2), r.grant_types.?.len);

    // A secret whose expiry the server leaves out is read, its expiry null.
    var unstated = try readResponse(testing.allocator, 201, "{\"client_id\":\"a\",\"client_secret\":\"b\"}", .{});
    defer unstated.registered.deinit();
    try testing.expectEqualStrings("b", unstated.registered.client_secret.?);
    try testing.expectEqual(@as(?i64, null), unstated.registered.client_secret_expires_at);
    try testing.expectError(error.InvalidResponse, readResponse(testing.allocator, 201, "{\"client_secret\":\"b\"}", .{}));
    const refused = try readResponse(testing.allocator, 400, "{\"error\":\"invalid_redirect_uri\",\"error_description\":\"no\"}", .{});
    try testing.expectEqual(errors.Code.invalid_redirect_uri, refused.refused.code);
    try testing.expectError(error.UnexpectedStatus, readResponse(testing.allocator, 404, "", .{}));
}
