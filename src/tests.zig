//! Every test of clearance, reached from here.
test {
    _ = @import("base64url.zig");
    _ = @import("Algorithm.zig");
    _ = @import("Key.zig");
    _ = @import("jwk.zig");
    _ = @import("jws.zig");
    _ = @import("jwt.zig");
    _ = @import("id_token.zig");
    _ = @import("access_token.zig");
    _ = @import("wycheproof_test.zig");
    _ = @import("property_test.zig");
}
