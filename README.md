# clearance

clearance is JWT and JOSE (JWS, JWK) and OAuth 2.1 for Zig. Two modules:

- `clearance`: JSON Web Keys and key sets, JWS in the compact serialization,
  signed and verified, JWTs whose claims are checked by type before value,
  and three profiles: OpenID Connect ID tokens, JWT access tokens (RFC 9068)
  and DPoP proofs (RFC 9449).
  On std, [cloak](https://github.com/pedronaugusto/cloak) (signatures),
  [strand](https://github.com/pedronaugusto/strand) (JSON) and
  [aegis](https://github.com/pedronaugusto/aegis) (checked types) alone.
- `clearance.oauth`: OAuth 2.1 clients on
  [uplink](https://github.com/pedronaugusto/uplink): discovery, the
  authorization code flow with PKCE, refresh, client credentials, device
  authorization (RFC 8628), token revocation (RFC 7009), DPoP-bound tokens
  (RFC 9449), MCP's
  enterprise-managed authorization (an identity provider's ID-JAG redeemed
  for an access token), a workload's JWT as the grant, registration, key sets
  kept from a `jwks_uri`, introspection, a token store;
  a resource server's bearer check with its 401 and 403 answers; and every
  message underneath, sans I/O, for any HTTP stack.

Work in progress toward the public cut.

## Install

Requires Zig 0.17.0. Fetch with `zig fetch --save
git+https://github.com/pedronaugusto/clearance`, then take the modules through
`b.dependency` and add them to your executable's imports. A project that
verifies and signs tokens takes `clearance` and fetches no uplink; one that
speaks OAuth asks for it, `b.dependency("clearance", .{ .oauth = true })`, and
takes `clearance.oauth` too (uplink is fetched then).

## Usage

A resource server checks an access token against the keys its authorization
server publishes:

<!-- BEGIN GENERATED zig build docs -- verify -->
```zig
const clearance = @import("clearance");

const jwk = clearance.jwk;
const jwt = clearance.jwt;

// A key set as a provider publishes it (here one Ed25519 key, RFC 8037's).
var keys = try jwk.KeySet.parse(gpa,
    \\{"keys":[{"kty":"OKP","crv":"Ed25519","kid":"2026-10",
    \\  "x":"11qYAYKxCrfVS_7TyWQHOg7hcvPapiMlrwIaaPcHURo"}]}
, .{});
defer keys.deinit();

// The claims the application reads, beside the registered ones.
const Claims = struct { scope: []const u8 = "" };

const validation: jwt.Validation = .{
    // Which algorithms a token may use is the verifier's choice: no default.
    .algorithms = &.{.eddsa},
    .issuer = "https://as.example",
    .audience = "https://api.example",
    .typ = "at+jwt",
    .leeway = .literal("30s"),
};
// Verifying allocates nothing: the decoded token lives in a scratch buffer.
var scratch: [4096]u8 = undefined;
const now = std.Io.Clock.real.now(io);
```
<!-- END GENERATED -->

`jwt.verify(Claims, token, keys.keys, validation, now, &scratch)` then returns
the header, the registered claims, the claims as `Claims` and the key that
verified the token, or the error naming the check that refused it.

Signing, here with an HMAC secret (a private JWK signs RS, PS, ES and EdDSA
tokens the same way, read by `jwk.PrivateKey.parse` and given as
`jws.Signer.fromJwk(&private, null)`, as does a cloak private key read from
PEM or DER):

<!-- BEGIN GENERATED zig build docs -- sign -->
```zig
const clearance = @import("clearance");

const secret: [32]u8 = @splat(0x2a);
var token: std.Io.Writer.Allocating = .init(gpa);
defer token.deinit();
try jwt.sign(gpa, io, &token.writer, .{ .kid = "hmac-1" }, .{
    .iss = "https://as.example",
    .aud = "https://api.example",
    .exp = now.toSeconds() + 300,
    .scope = "read",
}, .{ .hmac = .{ .alg = .hs256, .secret = &secret } });
```
<!-- END GENERATED -->

A client finds an authorization server and the keys it signs with (the
`discover` example runs this against live providers):

<!-- BEGIN GENERATED zig build docs -- oauth -->
```zig
const oauth = @import("clearance.oauth");

// The metadata from the issuer's well-known locations, its `issuer`
// checked byte for byte against the one asked.
var server = try oauth.discover(gpa, io, http, issuer, .{});
defer server.deinit();
// Its keys, kept for as long as their answer allows. A resource server
// shares one set between its tasks and calls
// `keys.verify(Claims, io, http, token, validation, now, &scratch)`.
var keys = try oauth.RemoteKeySet.init(gpa, server.value.jwks_uri orelse return error.NoJwksUri, .{});
defer keys.deinit();
var lease = try keys.lease(io, http, .current);
defer lease.release();
```
<!-- END GENERATED -->

`oauth.AuthorizationFlow.begin` then writes the URL to open, and `finish`
reads the redirect and exchanges the code; `oauth.fresh` keeps a store's
tokens refreshed. Without a sign-in: `oauth.requestIdJag` exchanges the
user's token at an enterprise's identity provider for an ID-JAG, and
`oauth.redeemIdJag` redeems it with the authorization server it names;
`oauth.jwtBearer` presents a workload's identity token as the grant.

## Design

- **No `none`, no algorithm confusion.** `Algorithm` has no value for `none`.
  A verifier names the algorithms it accepts; there is no default. A `Key` is
  typed by its family, an HMAC key is made only from secret bytes, and a key
  with an `alg` is used with that algorithm alone.
- **The verifier picks the key.** The header's `kid` chooses among the
  caller's keys; a token without one verifies only when exactly one key fits.
  The header's `jwk`, `jku`, `x5u` and `x5c` never choose or fetch a key.
- **Types before values.** A registered claim of the wrong JSON type (a string
  `exp`, a `null` audience) refuses the token; it is never read as absent. A
  member given twice refuses it. A token with an audience is refused by a
  verifier that did not name one.
- **Bounded, allocation-free verification.** A token is split by counting its
  dots once, refusing a third, before anything is decoded; its decoded parts
  and the header's values live in a scratch buffer the caller gives.
- **Key sets keep what they can use.** Keys of a kind clearance does not
  verify with (P-521, X25519, ...) and keys that do not check out are left out
  of a set and counted by reason, so a provider's set still serves.
- **Critical extensions are refused.** clearance understands no header that
  must be listed in `crit`.
- **What was asked is what answered.** Authorization server metadata must
  name the issuer it was fetched for, byte for byte; protected resource
  metadata the resource asked for; every endpoint is HTTPS (HTTP to loopback
  alone). A callback is read only under the request's `state`, and its `iss`
  (RFC 9207) is compared as a string, required when the server advertises it.
- **Remote key sets that a rotation or a flood cannot break.** A set is kept
  for its answer's `max-age` (clamped to 5 minutes..24 hours), fetched again
  for an unknown `kid` at most once a minute, by one task while the others
  wait, and kept through a failing key server for a grace. Keys are leased:
  a fetch never frees keys a verification holds.
- **An ID-JAG holds to what was asked.** The identity provider's assertion
  must name that provider, the authorization server as its sole audience,
  the client, the resource alone and no scope beyond what was asked, and be
  unexpired; the access token it buys must be Bearer, for that resource, with
  no more scope than the assertion. Its signature is the authorization
  server's to verify. A refresh token offered for it is not kept: a new
  access token comes from the identity provider's word again.
- **Keys may stay elsewhere.** A JWT can be signed by an external signer (a
  KMS, an HSM) that sees only the signing input clearance built, so client
  assertions keep their claims right whoever holds the key.
- **Secrets in wiped memory.** Token requests (client secrets, verifiers,
  refresh tokens) and token sets live in aegis secret memory; `state` and
  `nonce` compare in constant time.

## Scope

In this release: JWS compact serialization with HS256/384/512, RS256/384/512,
PS256/384/512, ES256, ES384 and EdDSA (Ed25519, under both its names); JWK
and JWK sets (RSA, EC P-256 and P-384, OKP Ed25519, oct), and private JWKs
read for signing (RSA with its CRT members, EC P-256 and P-384, Ed25519); thumbprints (RFC
7638) and their URIs (RFC 9278); JWT claims and explicit typing; ID tokens
(OpenID Connect Core 3.1.3.7, `at_hash`) and RFC 9068 access tokens. OAuth 2.1
flows on uplink: discovery (RFC 8414, OpenID Connect, RFC 9728), the
authorization code flow with PKCE, refresh, client credentials, RFC 7591
registration, remote key sets, cached introspection, a token store kept fresh,
the Bearer challenge read for a step-up, the resource server's bearer check
(a key set or introspection, the audience and scopes, RFC 6750 and RFC 9728
answers), the Identity Assertion JWT Authorization Grant
(draft-ietf-oauth-identity-assertion-authz-grant-04) as MCP's
enterprise-managed authorization uses it, and the JWT-bearer grant (RFC 7523)
for a workload's identity token. Their messages: RFC 8414 and OpenID Connect Discovery metadata, RFC 9728 protected
resource metadata, PKCE (S256), the authorization request with RFC 8707
resources and its callback with RFC 9207's `iss`, the authorization code,
refresh, client credentials, token exchange (RFC 8693) and JWT-bearer
grants, client authentication (none, `client_secret_basic`,
`client_secret_post`, `private_key_jwt` with the key in memory or an external
signer, `client_secret_jwt`), RFC 7591
registration, client ID metadata documents, RFC 7662 introspection, RFC 6750
challenges with `resource_metadata`.

Not built: JWE; ES512, ES256K and Ed448; the JWS JSON serialization; unencoded
payloads (RFC 7797); an authorization server; device authorization, token
revocation, DPoP, PAR and rich authorization requests (RFC 9396), until a
user needs one.

## Built with

cloak verifies and signs (ECDSA in the fixed-width form JOSE uses, RSA
PKCS#1 v1.5 and PSS, Ed25519), checks every RSA public key (the ROCA
fingerprint among the checks) and makes a private key from a JWK's numbers; strand reads and writes JSON under limits;
aegis wipes secrets and compares MACs in constant time; uplink's codecs
parse URLs, challenges and `Cache-Control` and encode forms, and its client
carries the flows;
[shakedown](https://github.com/pedronaugusto/shakedown) runs the tests and
properties; [preflight](https://github.com/pedronaugusto/preflight) gates it.

## Testing

`bay test` runs the suite: the examples of RFC 7520 (the JOSE cookbook), 7638
and 8037, Wycheproof's `json_web_signature`, `json_web_key` and
`json_web_crypto` files, and properties over every parser of untrusted input
(tokens, read verified or not, key sets, private keys, claims, metadata, token, exchange,
ID-JAG, registration and introspection responses, callbacks, challenges), which `bay properties --fuzz` runs under Zig's
fuzzer; and the flows end to end against an authorization server and an
identity provider on uplink's server in the same process.

## Licence

MIT.
