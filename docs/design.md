# clearance: design

OAuth 2.1 clients, resource servers and JOSE (JWS, JWE, JWK, JWT) for any Zig program, on
cloak (crypto), uplink (HTTP), strand (JSON) and aegis (secrets, durations, sizes,
contracts). Not an authorization server.

The bar: every flow and check the strongest rival offers in this scope (panva's
openid-client, oauth4webapi and jose for breadth; Nimbus for checks; Rust's `jsonwebtoken` and
`oauth2` for API shape), none of the footguns any of them shipped, the RFC vectors and
Wycheproof's JOSE files in the suite, and verification that allocates nothing.

## Modules

| Module | What | Builds on |
|---|---|---|
| `clearance` | JWS, JWE, JWK and JWKS, JWT and its profiles (ID tokens, RFC 9068 access tokens, DPoP proofs, logout tokens) | std, aegis, strand, cloak |
| `clearance.oauth` | OAuth 2.1: every request built and response read sans I/O (on `uplink.wire` alone), and the flows on `uplink.Client` | the above, uplink |

Both modules are always declared, and the build takes no option: a library takes every
dependency with its default options, so every project reaching clearance builds the same one.
uplink is a lazy dependency, fetched with clearance and compiled only in a program that
imports `clearance.oauth`; a JWT user never compiles uplink or what it brings (reactor, warp,
xenoglyph). `ci/layers.zig` keeps the JOSE layers from importing uplink, and the OAuth
messages from importing anything of it but `uplink.wire`, so a split into a messages-only
module stays additive the day a user with an HTTP stack of its own needs one.

## Layers, lowest first (`ci/layers.zig`)

| Layer | Files | What |
|---|---|---|
| codecs | `base64url.zig`, `time.zig` | Strict base64url without padding (non-canonical trailing bits refused); NumericDate |
| algorithms | `Algorithm.zig` | The JWS algorithms, ML-DSA (`AKP` keys, RFC 9964) among them; `none` unrepresentable |
| keys | `Key.zig`, `jwk.zig` | JWK and JWKS read, validated and selected, for signatures or for encryption; private keys; thumbprints (RFC 7638, 9278) |
| JWS | `jws.zig` | Compact and JSON serializations, RFC 7797, verify and sign (or an external signer), `inspect` |
| JWE | `jwe.zig` | Compact and JSON serializations, decrypt and encrypt, the safe subset |
| JWT | `jwt.zig` | Registered claims by type, custom claims through strand, `Validation`, `Replay`, `inspect` |
| JWT profiles | `id_token.zig`, `access_token.zig`, `dpop.zig`, `logout.zig` | OIDC Core §3.1.3.7, RFC 9068, RFC 9449 proofs, Back-Channel Logout tokens |
| public | `clearance.zig` | The module's names |
| OAuth messages | `oauth/*.zig` | URLs, errors, PKCE, metadata, authorization requests and callbacks, client authentication, token requests and responses, token exchange and ID-JAG, device, revocation, DPoP sessions, PAR, request objects, UserInfo, logout, registration, introspection, challenges, the token store |
| OAuth on HTTP | `oauth/http/*.zig`, `oauth/http.zig` | Fetching, discovery, the flows, `RemoteKeySet`, `Introspector`, the resource server's `bearer.Verifier` |
| OAuth public | `oauth.zig` | `clearance.oauth`'s names |

## Scope

In: authorization code with PKCE, refresh, client credentials; discovery (RFC 8414 and OpenID
Connect Discovery) and protected-resource metadata (RFC 9728); dynamic registration (RFC
7591) and client ID metadata documents; resource indicators (RFC 8707); the `iss` callback
check (RFC 9207); bearer checking on a resource server, by JWT through a key set or by
introspection (RFC 7662); ID-token validation; scope step-up from a 403 `insufficient_scope`;
a token store; device authorization (RFC 8628); revocation (RFC 7009); DPoP (RFC 9449); PAR
(RFC 9126); UserInfo; JAR (RFC 9101) and mTLS (RFC 8705); OpenID Connect RP-Initiated,
Back-Channel and Front-Channel Logout; token exchange (RFC 8693), the JWT-bearer grant (RFC
7523 §2.1) and MCP's enterprise-managed authorization (an ID-JAG); client authentication by
`client_secret_basic`, `client_secret_post`, `none`, `private_key_jwt`, `client_secret_jwt`
and the two TLS methods; JWS (compact, JSON, RFC 7797), JWE's safe subset, JWK, JWKS, JWT,
and ES512 on P-521.

Out, each named so a user sees a decision, not an omission:

| Out | Why |
|---|---|
| Implicit and password grants | Removed by OAuth 2.1. |
| An authorization server | A different kind of thing. |
| Ed448 | No curve in std or cloak; rare. |
| ES256K, JARM, CIBA, rich authorization requests (RFC 9396) | Banking and blockchain niches. |
| COSE and CWT | Another format family with its own libraries. |
| OIDC Session Management 1.0 | A script in a browser posting to an iframe, which no Zig program runs. |
| JWE `zip`, RSA1_5, PBES2 without a bound, every 192-bit AES variant | Refused by construction (JWE, below). |

## Decisions

**`none` and algorithm confusion.** `none` is no algorithm clearance has: no type spells it,
so no option, key or default accepts it. A key is typed by its family (`Key`'s `.hmac`, `.rsa`,
`.ec`, `.okp`, `.akp`); an HMAC key is built only from secret bytes, never from a public key's encoding.
A verify needs the caller's allowed algorithms (no default "all"); the header's `alg` must be
in that list, fit the key's family, and match the key's own `alg` when the JWK has one, so a
JWK's `alg` binds the key to that algorithm alone (as panva's jose does; Wycheproof labels four
tokens valid that clearance refuses for it). Answers authlib CVE-2024-37568 and CVE-2026-28802,
golang-jwt's opt-in `WithValidMethods`, RFC 8725 §3.1-3.2.

**Which key.** Chosen from the caller's key set by `kid`, then `kty`, `use` or `key_ops`, and
`alg`. The header's `jwk`, `jku`, `x5u` and `x5c` never select or fetch a key (the one use of a
header key is a DPoP proof's own, below). A token without `kid` is tried only when exactly one
key matches. A set mixing `oct` with public keys is refused, and two keys sharing `kid` and
`kty` are both left out. A key is read for signatures or for encryption (`jwk.Purpose`) and
never used for the other. Answers CVE-2018-0114's embedded-key forgery and .NET's
CVE-2024-21643 (`jku` trusted); RFC 8725 §3.10.

**Claims.** Registered claims are checked by type before value: a present `exp`, `nbf` or
`iat` that is not a NumericDate, or an `aud` that is neither a string nor an array of strings,
refuses the token, never reads as absent. `exp` is required unless the caller says otherwise;
`iss` and `aud` are checked when the options name them; leeway is an aegis duration, 0 by
default and at most 5 minutes. Duplicate member names refuse the token (strand's strict
parse). Explicit typing is checked where the profile has one (`at+jwt`; an ID token's `JWT` or
none). Answers jsonwebtoken CVE-2026-25537 and jwt-go CVE-2020-26160; RFC 8725 §3.11.

**Untrusted sizes.** A compact token is split by counting its dots once, refusing a third,
before anything is decoded or allocated. Every reader has a size bound (16 KiB a token, 8 KiB
a DPoP proof, 64 KiB a JWE, 1 MiB a key set) and a JSON depth bound in strand's bounded parser;
nothing recurses on input. Answers go-jose CVE-2025-27144, golang-jwt CVE-2025-30204, x/oauth2
CVE-2025-22868, authlib CVE-2025-61920 and Nimbus CVE-2025-53864.

**Allocation.** Verifying a compact JWS allocates nothing: segments decode into the caller's
buffer or a fixed one the limits size, and claims decode with strand into the caller's type,
strings borrowed from the decoded buffer. Every rival allocates per token.

**Secrets.** Client secrets, HMAC keys, private keys, refresh and access tokens are aegis
secrets (wiped, refused by `{f}`); MACs, `state` and `nonce` are compared in constant time.

**Crypto.** cloak's, for every public-key operation (RSA PKCS#1 and PSS, ECDSA on P-256, P-384
and P-521 in JOSE's fixed-width form, Ed25519, ML-DSA, RSA-OAEP, ECDH and X25519, AES-GCM, AES
key wrap, the CBC-HMAC composite, key generation); std's HMAC-SHA-2 and SHA-2 for HS*,
thumbprints, PKCE and `at_hash`. A gap goes into cloak, never into clearance.

**PKCE, state, nonce.** S256 only; `plain` is never sent. The verifier is 32 random bytes from
`io.random` (43 base64url characters); `state` and `nonce` the same.

**HTTP.** The flows take an `*uplink.Client` and `io` per call and store neither. Responses are
bounded (metadata and key sets 1 MiB, token and other responses 64 KiB). No redirect is
followed, for any request: a discovery document's issuer must match where it was fetched (RFC
8414 §3), and what was asked is what was answered. HTTPS is required for every endpoint but
loopback (OAuth 2.1 §1.5, RFC 8252 §8.3).

**Discovery.** RFC 8414's path inserts `/.well-known/oauth-authorization-server` between host
and path; OIDC's appends `/.well-known/openid-configuration`; for MCP both, in its order. The
document's `issuer` must equal the issuer asked for byte for byte; a template issuer
(Microsoft's `{tenantid}`) is a caller-supplied rule, never a relaxed compare. RFC 9728: the
resource's metadata from `WWW-Authenticate`'s `resource_metadata` or its well-known path, its
`resource` equal to the URL asked.

**Remote key sets.** A `RemoteKeySet` per `jwks_uri`, handed out by leases: kept for the
answer's lifetime clamped to 5 minutes..24 hours (1 hour when it gives none), fetched again at
most once per cooldown (60 s) whatever unknown `kid`s arrive, one fetch at a time for all its
waiters, and a set past its expiry still used for a grace (`stale_if_error`, 1 hour; zero
turns it off) while its key server fails. A rotation costs no refused token, and a flood of
bad `kid`s is no flood of fetches.

**Client authentication.** Chosen from what the server's metadata lists when the caller does
not choose. `client_secret_basic` form-encodes id and secret before Basic (RFC 6749 §2.3.1, a
step several libraries skip). `private_key_jwt` signs with a key in memory or behind
`jws.Signer.external` (a KMS or HSM signs the input clearance built, so the claims are right
whoever holds the key), `aud` the issuer identifier. The TLS methods take the client's
identity from the certificate on the caller's `uplink.Client` and use the server's
`mtls_endpoint_aliases`.

**Tokens.** A `TokenSet`: access token, type, absolute expiry from `expires_in` and the clock
at the request, refresh token, granted scope, ID token. `token_type` is read case-insensitively;
an ID token asked for is validated. A refresh keeps the old refresh token when the answer
omits one (RFC 6749 §6). Flows read and write a `TokenStore` (load, save, forget); an in-memory
one ships, a durable one is the caller's, and `fresh` refreshes a set within a margin of its
expiry. A 403 `insufficient_scope` names the scopes to ask again, the granted ones kept.

**Resource server.** `bearer.Verifier` reads `Authorization: Bearer` (never the query
parameter, the form body only when asked), checks a JWT access token through a key set or
asks introspection (cached until the earlier of `exp` and a bound), and writes the answer: 401
with `resource_metadata` (RFC 9728 §5.1), 403 `insufficient_scope` with the scope needed. A
token bound by `cnf` is checked against `access_token.Expected.binding` (`.dpop(thumbprint)`,
`.mtls(certificate hash)`); `.none` refuses a bound token, and a bound token presented as
Bearer is refused.

**Clock and errors.** Every time check takes a `std.Io.Timestamp` the caller gives, so tests and
replays are exact. Errors are named sets per function; an OAuth error response is a value
(`ErrorResponse`), never a lost error name; a verify failure says which check refused
(`Diagnostics`), and a peer gets no more than the check's name.

### Per feature

**Enterprise-managed authorization.** Token exchange of the user's token (an ID token, a SAML
assertion or a refresh token) at an identity provider for an ID-JAG, its redemption by the
JWT-bearer grant, and the workload grant carrying a workload's identity token
(`requestIdJag`, `redeemIdJag`, `jwtBearer`). The client checks what it can, read with
`jwt.inspect` (the JOSE checks without the signature, which is the authorization server's to
check): the ID-JAG names the identity provider, the authorization server as its sole audience,
the client, the resource alone, no scope beyond the request, `typ` `oauth-id-jag+jwt`,
unexpired, no `authorization_details`. The redemption sends the assertion alone (scope and
resource would undo the provider's narrowing) and holds the answer to Bearer, the resource and
the assertion's scope. A refresh token offered by either is not kept. No retries: a refusal is
the server's answer.

**Device authorization.** `DeviceFlow.begin`, `poll` (one token request) and `wait` (the loop
over `poll`, sleeping the interval, 5 s more on `slow_down`, until tokens, a refusal or
expiry): one path, so a caller with its own scheduler polls. Both verification URIs must be
HTTPS or loopback, and `user_code` printable and at most 64 bytes, since a person is shown them
and a hostile server's `javascript:` URI is a phishing link; no rival checks either. An
interval is never below 1 s nor taken past the expiry.

**Revocation.** A 200 is success whatever its body (RFC 7009 §2.2); a 503 is the server's
answer, never retried here. A logout revokes the refresh token, then forgets the store's entry.

**DPoP.** `dpop.writeProof` and `verifyProof` in `clearance` (a resource server needs no
uplink), `oauth.dpop.Session` for a client (its key, and the server nonces per origin). The
proof's embedded `jwk` is the one header key ever used, and only to verify that proof: the
token's `cnf.jkt` must be its thumbprint, so the key proves possession, never trust. That key
must be public and asymmetric, its `alg` allowed by the caller. `htu` is compared after RFC
9449 §4.3's normalization, `htm` exactly; `iat` within `max_age` (60 s) and the leeway; the
`jti` recorded in a `jwt.Replay` until `iat + max_age`, so a replayed proof is refused within
its life (as Nimbus checks); `ath` compared in constant time. Token, PAR and refresh requests
retry once on `use_dpop_nonce`.

**PAR.** `AuthorizationFlow.push` sends the authorization parameters from the one list
`authorize.writeUrl` writes, so the two cannot drift. `begin` refuses a server that requires
PAR (`error.PushRequired`); `request_uri` is bounded (1 KiB) and not interpreted; the answer
must be a 201 or an error body.

**UserInfo.** The subject is a required argument and `sub` must equal it byte for byte (OIDC
Core §5.3.4: a substituted response otherwise passes). An `application/jwt` answer is verified
as a JWT, decrypted first when encrypted; a 401's `WWW-Authenticate` is read into the error.

**JWS JSON and RFC 7797.** `jws.verifyJson` and `signJson`, flattened or general. `alg` must be
protected (an unprotected `alg` is the substitution hole); protected and unprotected names are
disjoint; `crit` only protected, non-empty, unique, no registered name, every name understood
(`b64` alone, and only when `unencoded` is allowed), and `b64` listed in `crit` when present. A
general document verifies when one signature verifies with a key the caller selected; the
result names which, and only its protected header is returned as trusted (go-jose's
CVE-2016-9123). At most 16 signatures by default. ACME's protected `nonce` and `url` are
written through `SignHeader.extra`.

**JWE, the safe subset.** Key management: RSA-OAEP (SHA-1, -256, -384, -512), A128KW,
A256KW, `dir`, ECDH-ES and ECDH-ES+A128KW or +A256KW (P-256, P-384, P-521, X25519), A128GCMKW,
A256GCMKW, PBES2-HS256+A128KW, PBES2-HS512+A256KW. Content: A128GCM, A256GCM, A128CBC-HS256,
A256CBC-HS512. No value spells the 192-bit AES variants (std has no AES-192 key schedule, RFC
7518 marks them optional, WebCrypto has none) or RSA1_5 (Bleichenbacher). Any `zip` member
refuses the token (decompression bombs, the compression oracle). A PBES2 `p2c` above the
caller's bound (10,000) or a `p2s` under 8 bytes is refused; an `epk` off the recipient key's
curve is refused, and X25519's all-zero secret. Both allowlists are required, with no default.
A failed key unwrap goes on with a random CEK so the content's tag fails alike (RFC 7516 §11.5:
no timing oracle), every cryptographic failure is one error (`DecryptionFailed`, the check's
name in `Diagnostics` only), the CBC composite checks its tag in constant time before
decrypting, and plaintext and CEK live in wiped memory. A nested JWT is decrypted, then
verified.

**JAR and mTLS.** A request object signs the authorization parameters as a JWT (`typ`
`oauth-authz-req+jwt`, `iss` the client, `aud` the issuer), sent by value or pushed by PAR,
encrypted to the server when it asks. A certificate-bound token's `cnf` is checked against the
request's client certificate.

**Logout.** RP-Initiated: `logout.writeUrl`. Back-Channel: `logout.verifyToken` requires `typ`
`logout+jwt` or none, `iss`, `aud`, `iat`, `exp`, `jti`, the back-channel event, `sub` or
`sid`, and no `nonce` (it would let an ID token pass as a logout token), the `jti` recorded in
`jwt.Replay`. Front-Channel: `iss` and `sid` read, `iss` checked.

## Evidence

- The RFCs' own examples: RFC 7515 Appendix A, 7520 (the JOSE cookbook, signatures and
  encryption), 7638, 7797, 8037, and 7636's PKCE example.
- Wycheproof's `json_web_signature`, `json_web_key`, `json_web_crypto` and
  `json_web_encryption` files; each case whose label clearance departs from is named, and the
  harness fails when one stops departing.
- Properties over every parser of untrusted input (tokens verified or not, key sets, private
  keys, claims, metadata, token, exchange, ID-JAG, registration and introspection responses,
  callbacks, challenges), run under Zig's fuzzer by `bay properties --fuzz`.
- The flows end to end against an authorization server and an identity provider on uplink's
  server in the test process; no network.
- By hand, never in CI: live discovery and key sets from Google, Microsoft (its `{tenantid}`
  issuer) and GitHub Actions' OIDC issuer, and the flows against panva's `oidc-provider`, a
  certified OP (trials, `zig build interop`).

## Measured

`bench/` measures clearance alone; rivals' rows on the same inputs are in trials
(`clearance/`). JOSE: JWT verify and sign per algorithm (HS256, RS256 2048, PS256, ES256,
ES512, EdDSA) with allocations, JWKS parse of Google's and Microsoft's sets, JWS JSON verify and
sign, JWE decrypt and encrypt per algorithm pair, DPoP proof and logout token verified with a
replay set. OAuth: a discovery document, a token response into a `TokenSet`, an authorization
request built, a whole code flow on loopback (begin, redirect, finish, refresh), device, PAR
and revocation round trips, UserInfo read, a request object signed, an mTLS-bound token
checked. RSA is cloak's public exponentiation, and its row is cloak's.

## Rivals, and what is taken

Rust `oauth2` and `openidconnect`, `jsonwebtoken`, josekit; Go `x/oauth2`, go-jose,
golang-jwt; Node openid-client, oauth4webapi and jose (the certified breadth leader); Python
authlib; Java Nimbus (JOSE and the OAuth SDK); .NET Microsoft.IdentityModel and Duende. Taken:
`oauth2`'s pluggable HTTP (here, the sans-I/O messages), panva's key-bound algorithms and remote
key sets with cooldown, .NET's last-known-good refresh, go-jose v4's mandatory algorithm list,
`jsonwebtoken`'s single `Validation` value. What none of them has, from Zig and the family:
verification without allocation, secrets wiped by type, a JWK's `alg` binding its key, and
every untrusted parser fuzzed.
