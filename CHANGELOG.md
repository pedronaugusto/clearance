# Changelog

All notable changes to this project are documented here. The format follows
[Keep a Changelog](https://keepachangelog.com/en/1.1.0/), and this project
adheres to [Semantic Versioning](https://semver.org/spec/v2.0.0.html).

## [Unreleased]

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

[Unreleased]: https://github.com/pedronaugusto/clearance/compare/v0.2.0...HEAD
[0.2.0]: https://github.com/pedronaugusto/clearance/compare/v0.1.1...v0.2.0
[0.1.1]: https://github.com/pedronaugusto/clearance/compare/v0.1.0...v0.1.1
[0.1.0]: https://github.com/pedronaugusto/clearance/releases/tag/v0.1.0
