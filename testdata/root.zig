//! clearance's test data: the JOSE cookbook (RFC 7520), RFC 9964's ML-DSA examples and
//! Wycheproof's JOSE files, with their provenance and licence under vectors/. It stays out of
//! src/ and of the package a project fetches (build.zig.zon's paths), and reaches the tests only
//! as the development build's module `testdata`.

/// The file at `path` under testdata/, embedded: `file("vectors/rfc7520/3_3.rsa_public_key.json")`.
pub fn file(comptime path: []const u8) @TypeOf(@embedFile(path)) {
    return @embedFile(path);
}
