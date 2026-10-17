# Changelog

All notable changes to this project are documented here. The format follows
[Keep a Changelog](https://keepachangelog.com/en/1.1.0/), and this project
adheres to [Semantic Versioning](https://semver.org/spec/v2.0.0.html).

## [Unreleased]

## [0.1.0] - 2026-10-17

### Added

- `jws`: the compact serialization split by its two dots before anything is decoded (a third refused, a size limit first), the protected header read under limits, `crit` refused, and the signature verified against the caller's keys with HS256/384/512, RS256/384/512, PS256/384/512, ES256, ES384 and EdDSA (Ed25519, as `EdDSA` and as `Ed25519`). The caller names the allowed algorithms; there is no `none`. The key is chosen by `kid` among the caller's keys, never from the header's `jwk`, `jku`, `x5u` or `x5c`. Verification allocates nothing: the decoded parts live in a scratch buffer. `Diagnostics` names the check that refused. `sign` writes a compact JWS with an HMAC secret or a cloak private key.
- `jwk`: JWKs and JWK sets read into keys (RSA of 2048 to 4096 bits, EC P-256 and P-384 with the point checked on its curve, OKP Ed25519, and `oct` when asked), each checked as read; keys that cannot be used are left out and counted by reason, two keys with one `kid` both left out, private members refused, a set mixing secret and public keys refused. Thumbprints (RFC 7638) and their URIs (RFC 9278).
- `jwt`: claims read by type before value (a registered claim of the wrong JSON type refuses the token), `exp` required unless the validation says otherwise, `nbf`, `iat` and `max_age` with a bounded leeway, `iss`, `sub` and `aud` (a token with an audience refused by a verifier that names none), explicit typing (`at+jwt`, `dpop+jwt`), custom claims decoded into the caller's type; `sign`.
- Tests: RFC 7520, 7638 and 8037 examples; Wycheproof's `json_web_signature`, `json_web_key` and `json_web_crypto` files (465 of 475 cases as the files say, 10 diverging by decision, each named in the harness); properties over tokens, key sets and claims, fuzzed in the release tier.

[Unreleased]: https://github.com/pedronaugusto/clearance/compare/v0.1.0...HEAD
[0.1.0]: https://github.com/pedronaugusto/clearance/releases/tag/v0.1.0
