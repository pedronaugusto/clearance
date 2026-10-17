# clearance

clearance is OAuth 2.1 and JOSE (JWT, JWS, JWK) for Zig. This first release is
the JOSE layer: JSON Web Keys and key sets, JWS in the compact serialization,
signed and verified, and JWTs whose claims are checked by type before value.
The OAuth client flows, discovery, protected-resource metadata, dynamic client
registration, the resource server's bearer checks, ID tokens and DPoP follow on
the same layers.

Work in progress toward the public cut.

## Install

Requires Zig 0.17.0. Fetch with `zig fetch --save
git+https://github.com/pedronaugusto/clearance`, then take the `clearance`
module through `b.dependency` and add it to your executable's imports. It
depends on std, [cloak](https://github.com/pedronaugusto/cloak) (signatures),
[strand](https://github.com/pedronaugusto/strand) (JSON) and
[aegis](https://github.com/pedronaugusto/aegis) (checked types).

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

Signing, here with an HMAC secret (a cloak private key signs RS, PS, ES and
EdDSA tokens the same way):

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

## Scope

In this release: JWS compact serialization with HS256/384/512, RS256/384/512,
PS256/384/512, ES256, ES384 and EdDSA (Ed25519, under both its names); JWK
and JWK sets (RSA, EC P-256 and P-384, OKP Ed25519, oct); thumbprints (RFC
7638) and their URIs (RFC 9278); JWT claims and explicit typing.

Not built: JWE; ES512, ES256K and Ed448; the JWS JSON serialization; unencoded
payloads (RFC 7797).

## Built with

cloak verifies and signs (ECDSA in the fixed-width form JOSE uses, RSA
PKCS#1 v1.5 and PSS, Ed25519); strand reads and writes JSON under limits;
aegis wipes secrets and compares MACs in constant time;
[shakedown](https://github.com/pedronaugusto/shakedown) runs the tests and
properties; [preflight](https://github.com/pedronaugusto/preflight) gates it.

## Testing

`bay test` runs the suite: the examples of RFC 7520 (the JOSE cookbook), 7638
and 8037, Wycheproof's `json_web_signature`, `json_web_key` and
`json_web_crypto` files, and properties over every parser of untrusted input
(tokens, key sets, claims), which `bay properties --fuzz` runs under Zig's
fuzzer.

## Licence

MIT.
