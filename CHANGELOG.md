# Changelog

All notable changes to this project are documented here. The format follows
[Keep a Changelog](https://keepachangelog.com/en/1.1.0/), and this project
adheres to [Semantic Versioning](https://semver.org/spec/v2.0.0.html).

## [Unreleased]

### Breaking

- `token.Grant` gains `device_code`, and `errors.Code` gains `authorization_pending`, `slow_down`, `expired_token` and `unsupported_token_type` (which was `other`, the bearer check's introspection refusal among them): a switch over either needs the new cases.

### Added

- Device authorization (RFC 8628): `oauth.device` writes the request and reads the answer into an `Authorization` (the device code in wiped memory; `verification_uri` and `verification_uri_complete` held to HTTPS or loopback, since a person is sent there; a `user_code` of at most 64 bytes with no control characters, since it is printed to a terminal; Google's `verification_url` read when `verification_uri` is absent; the interval 5 s when absent, never below 1 s); `token.Grant.device_code`; metadata's `device_authorization_endpoint`. `oauth.DeviceFlow`: `begin` asks for the codes, `poll` makes one token request (`pending`, `slow_down` with the interval grown by 5 s, the tokens, or the refusal), `wait` polls at the interval on `io`'s sleep until the person finishes, the server refuses, or the codes would expire first (`error.Expired`, nothing sent). A property over the answer; a bench row.
- Token revocation (RFC 7009): `oauth.revocation` writes the request (the token, its `token_type_hint`, the client's authentication) and reads the answer (any 2xx is the token revoked, whatever its body; another status is the server's error, a 503 among them, never retried); metadata's `revocation_endpoint` and its auth methods; `oauth.revoke` sends it. A sign-out revokes the refresh token, which ends the grant at the server, then forgets the store's entry. A property, a bench row.

## [0.4.0] - 2026-10-21

### Breaking

- Pins uplink 0.8.7, cloak 0.19.0 and aegis 0.1.14 (were 0.8.1, 0.14.0 and 0.1.11): a build with clearance moves to those lines, and `jws.Signer.private` takes cloak 0.19's `PrivateKey`.
- A JWK's RSA public key gets cloak's checks for every RSA public key: 2048 to 4096 bits, minimal integers, an odd exponent of 3 to 2^32-1 (an exponent of 5 to 8 bytes was read), and no ROCA fingerprint (CVE-2017-15361). Wycheproof's `json_web_key` tcId 7 and `json_web_crypto` tcId 46 now pass, where they were named divergences.
- An `oct` key whose `k` holds a JSON escape is left out as invalid: no base64url text needs one, and the unescaped copy would sit outside wiped memory.

### Added

- `jwk.PrivateKey.parse`: a private JWK read for signing (RFC 7518 §6.2.2 and §6.3.2, RFC 8037 §2): EC P-256 and P-384, Ed25519, and two-prime RSA keys with their CRT members, made by cloak's `PrivateKey.fromComponents` through the checks a parsed key gets (the public half derived and compared). The document is read from a wiped copy and the private members decoded into wiped memory, both erased before it returns; `public` is the public half with the JWK's `kid`, `alg`, `use` and `key_ops`. Each refusal has its error (`jwk.PrivateError`).
- `jws.Signer.fromJwk`: a private JWK as a signer, with an algorithm, or the one its `alg` names or its curve implies.
- A property over private JWKs: any bytes are refused, or read as a key whose signature its public half verifies.

### Fixed

- A key set read out of memory fails with `OutOfMemory`. A key whose members could not be allocated was left out as invalid, and a set whose keys could not be allocated was refused as `InvalidDocument`.
- `jwk.KeySet`'s copy of its document is wiped by `deinit`: it held the secret members the document had (an `oct` key's `k`, private members left out) in memory freed unwiped.

## [0.3.0] - 2026-10-17

### Breaking

- `oauth.client_auth.Method` and `Credentials` gain `client_secret_jwt`, `jws.Signer` gains `external`, `oauth.errors.Code` gains `invalid_target` and `insufficient_user_authentication`, `oauth.token.Grant` gains `token_exchange` and `jwt_bearer`: an exhaustive switch over any of them needs the new cases.

### Added

- MCP's enterprise-managed authorization, as the Identity Assertion JWT Authorization Grant (draft-ietf-oauth-identity-assertion-authz-grant-04) gives it: `oauth.requestIdJag` exchanges the user's token at an identity provider (an ID token, a SAML assertion or a refresh token) for an ID-JAG (RFC 8693), checked for exactly what was asked (the provider as issuer, the authorization server as its sole audience, the client, the resource alone, no scope beyond the request, unexpired, no `authorization_details`); `oauth.redeemIdJag` redeems it with that authorization server (RFC 7523), the assertion alone carrying scope and resource, and holds the access token to Bearer, the resource and the assertion's scope, keeping no refresh token. The messages in `oauth.id_jag`, sans I/O.
- `oauth.jwtBearer`: a JWT as the grant (RFC 7523 §2.1), with a client or with none, for a workload's identity token (MCP's workload identity federation).
- `oauth.exchange`: token exchange (RFC 8693), its request as `token.Grant.token_exchange` and its answer read (`readResponse`), the token type identifiers.
- `client_secret_jwt` client authentication (an HS256 assertion under the client's secret), and `jws.Signer.external`: a signer outside the process (a KMS, an HSM) that signs the input clearance built, for `private_key_jwt` or any JWT.
- `jws.inspect` and `jwt.inspect`: a token read and its type and claims checked under `verify`'s bounds and rules, its signature not verified, for a holder that passes it to the party that verifies it.
- Properties over `inspect`, the exchange's answer, the identity provider's answer and the redemption's.

### Changed

- `oauth.requestToken`, `oauth.token.request` and `oauth.client_auth.formRequest` take the client as optional: null sends no client, for a grant that is its own credential. Passing a client is unchanged.

## [0.2.3] - 2026-10-17

### Added

- `oauth.registration.ClientMetadata.application_type` (`native` or `web`, OpenID Connect Dynamic Client Registration §2), which MCP asks every client to name when it registers.

### Changed

- A registration that gives a secret without `client_secret_expires_at` is read, its expiry null, where it was refused: RFC 7591 requires the member, servers leave it out (the MCP conformance suite's authorization server among them), and its absence says nothing a client acts on.

## [0.2.2] - 2026-10-17

### Changed

- `oauth.bearer.Verifier` answers a token its authorization server will not introspect (`unsupported_token_type`, which oidc-provider gives for the JWT access tokens it issues) with 401 `invalid_token`, the client's to fix, instead of failing with `error.Unavailable` (a 503), which is kept for a server refusing the resource server's credentials or failing. Found running the flows against oidc-provider.
- `oauth.token.readResponse` and `TokenSet.read` no longer zero their 8 KiB stack scratch before each parse: it was set up from a struct literal, which fills the whole buffer first, and that fill was half the time of reading a 1 KiB response on Linux. The scratch is now set up in place (389 to 217 ns per response on the Lima VM, 325 to 224 ns on an M3, best of 7). `errors.Text.init` the same way.

## [0.2.1] - 2026-10-17

### Changed

- `oauth.token.readResponse` and `TokenSet.read` parse a response of up to 2 KiB on the stack, wiping only what the parser wrote (the strings it unescaped), instead of allocating and wiping a heap buffer of twice the body and 4 KiB: one allocation per response (the set's own) and about a fifth less time (433 to 352 ns for a 1 KiB response on an M3). Larger responses still parse in wiped heap memory.
- The benchmarks time OAuth's messages: a token response read, RFC 8414's example metadata read, an authorization URL written.

## [0.2.0] - 2026-10-17

### Breaking

- Two modules: `clearance` is JWT and JOSE alone, on std, aegis, strand and cloak; OAuth 2.1 is the module `clearance.oauth` (the messages that were `clearance.oauth`, and the flows), built when a project sets the build option `oauth`. uplink is a lazy dependency, fetched only then: a project that verifies and signs tokens fetches no uplink.

### Added

- `clearance.oauth`, the flows on uplink's client, each request to an endpoint held to HTTPS, no redirect followed, each answer bounded and read into wiped memory when it carries secrets: `discover` (RFC 8414 and OpenID Connect locations in MCP's order, a 4xx trying the next, an issuer mismatch failing at once); `discoverResource` (RFC 9728, from a challenge's `resource_metadata` or the inserted then the root location); `bearerChallenge` (a 401's or 403's Bearer challenge from its `WWW-Authenticate` lines, for a step-up); `AuthorizationFlow` (`begin` draws the state, the PKCE verifier and the nonce and writes the URL; `finish` reads the redirect, `state` then RFC 9207's `iss`, and exchanges the code with the RFC 8707 resources); `requestToken`, `refresh` (the granted scope and refresh token kept when the answer leaves them out), `clientCredentials`, `register` (RFC 7591, with an initial access token); `fresh` (a store's tokens refreshed and saved when they near expiry, forgotten when the grant is spent); `RemoteKeySet` (a `jwks_uri` kept for its `Cache-Control` lifetime clamped to 5 minutes..24 hours, fetched again for an unknown `kid` at most once per cooldown, one fetch for every waiter, the set held kept through a failing key server for a grace, keys leased so a fetch never frees keys in use; `verify`); `Introspector` (RFC 7662 answers kept until the earlier of `exp` and a bound, keyed by the token's SHA-256, the count bounded).
- `id_token`: OpenID Connect ID tokens checked as OpenID Connect Core 3.1.3.7 asks: `iss` byte for byte, the client among the audiences and any other one trusted, `azp` the client and required beside several audiences, `sub`, `exp` and `iat` present (`iat` not in the future), the request's `nonce` in constant time, `auth_time` within `max_age`, `at_hash` the access token's (SHA-512 for EdDSA); a token typed other than `JWT` refused. `accessTokenHash` (Core A.3's value in the tests).
- `access_token`: JWT access tokens as RFC 9068 profiles them: `at+jwt`, the issuer, this resource as the audience, `sub`, `client_id`, `iat` and `jti` present, `scope` read, a key-bound token (`cnf`) refused; `hasScopes`.
- `jwt.Verified.rest`: the scratch still free, for a profile reading more of the payload; `jwt.numericDate` public.
- `clearance.oauth.bearer.Verifier`: a resource server's check of `Authorization: Bearer` (RFC 6750 §2.1, a b64token, never the query) as a JWT access token through a `RemoteKeySet` (fetched again once for an unknown key) or by introspection (active, unbound, unexpired, the issuer, this resource among the audiences), then the scopes needed; a refusal carries its status (400, 401, 403) and the challenge to write (`error`, `scope` for a step-up, `resource_metadata`). `AuthorizationFlow.verifyIdToken`: the ID token a code flow brought, with the flow's nonce and the access token's hash.
- `oauth.store`: the `TokenStore` interface (load, save, forget by key) and a store in memory.
- End-to-end tests against an authorization server on uplink's server in the same process; the `discover` example, run by hand against Google, Microsoft and GitHub Actions.

### Changed

- Depends on uplink 0.8.1, lazily, with its client (for `wire.cache`).

## [0.1.1] - 2026-10-17

### Added

- `oauth`: OAuth 2.1's messages, sans I/O, on `uplink.wire`. `url`: endpoints held to HTTPS (HTTP to loopback alone), issuers, the metadata locations of RFC 8414, OpenID Connect Discovery and RFC 9728 in MCP's order, a resource matched exactly or as an ancestor, and client ID metadata document URLs checked. `metadata`: authorization server and protected resource metadata read, the issuer compared byte for byte and the resource as the caller's rule says, every endpoint checked; protected resource metadata written. `pkce`: S256 alone, verifiers and `state`/`nonce` values from `io`, compared in constant time. `authorize`: the authorization URL (RFC 8707 resources, the endpoint's own query kept) and the callback read: `state`, then RFC 9207's `iss` (compared as a string, required when advertised, checked when sent anyway), then the code or the error; a parameter twice refused. `client_auth`: none, `client_secret_basic` (id and secret form-encoded first), `client_secret_post` and `private_key_jwt` (its audience the issuer), chosen from the server's list; form requests in wiped memory. `token`: the code, refresh and client-credentials grants; responses read into a `TokenSet` whose tokens live in wiped memory, expiry from the moment read, the requested scope and the previous refresh token kept when the response leaves them out, a type other than Bearer refused; a set written and read for a store. `registration`: RFC 7591 requests and responses (a secret with no expiry refused), client ID metadata documents written. `introspection`: RFC 7662 requests and responses, the audience one or several, a key-bound token marked. `challenge`: Bearer challenges read (with `resource_metadata`) and written, and a step-up's scope. `errors`: an OAuth error response as a value with its text inline.
- Properties over every OAuth reader (metadata, token, registration and introspection responses, the callback, challenges), fuzzed in the release tier.

### Changed

- Depends on uplink 0.8.0 for `uplink.wire` alone (`.client = false`: uplink's client and what it fetches stay out).

## [0.1.0] - 2026-10-17

### Added

- `jws`: the compact serialization split by its two dots before anything is decoded (a third refused, a size limit first), the protected header read under limits, `crit` refused, and the signature verified against the caller's keys with HS256/384/512, RS256/384/512, PS256/384/512, ES256, ES384 and EdDSA (Ed25519, as `EdDSA` and as `Ed25519`). The caller names the allowed algorithms; there is no `none`. The key is chosen by `kid` among the caller's keys, never from the header's `jwk`, `jku`, `x5u` or `x5c`. Verification allocates nothing: the decoded parts live in a scratch buffer. `Diagnostics` names the check that refused. `sign` writes a compact JWS with an HMAC secret or a cloak private key.
- `jwk`: JWKs and JWK sets read into keys (RSA of 2048 to 4096 bits, EC P-256 and P-384 with the point checked on its curve, OKP Ed25519, and `oct` when asked), each checked as read; keys that cannot be used are left out and counted by reason, two keys with one `kid` both left out, private members refused, a set mixing secret and public keys refused. Thumbprints (RFC 7638) and their URIs (RFC 9278).
- `jwt`: claims read by type before value (a registered claim of the wrong JSON type refuses the token), `exp` required unless the validation says otherwise, `nbf`, `iat` and `max_age` with a bounded leeway, `iss`, `sub` and `aud` (a token with an audience refused by a verifier that names none), explicit typing (`at+jwt`, `dpop+jwt`), custom claims decoded into the caller's type; `sign`.
- Tests: RFC 7520, 7638 and 8037 examples; Wycheproof's `json_web_signature`, `json_web_key` and `json_web_crypto` files (465 of 475 cases as the files say, 10 diverging by decision, each named in the harness); properties over tokens, key sets and claims, fuzzed in the release tier.

[Unreleased]: https://github.com/pedronaugusto/clearance/compare/v0.4.0...HEAD
[0.4.0]: https://github.com/pedronaugusto/clearance/compare/v0.3.0...v0.4.0
[0.3.0]: https://github.com/pedronaugusto/clearance/compare/v0.2.3...v0.3.0
[0.2.3]: https://github.com/pedronaugusto/clearance/compare/v0.2.2...v0.2.3
[0.2.2]: https://github.com/pedronaugusto/clearance/compare/v0.2.1...v0.2.2
[0.2.1]: https://github.com/pedronaugusto/clearance/compare/v0.2.0...v0.2.1
[0.2.0]: https://github.com/pedronaugusto/clearance/compare/v0.1.1...v0.2.0
[0.1.1]: https://github.com/pedronaugusto/clearance/compare/v0.1.0...v0.1.1
[0.1.0]: https://github.com/pedronaugusto/clearance/releases/tag/v0.1.0
