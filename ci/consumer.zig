//! A consumer imports the module and reaches every part with only its
//! runtime dependencies.
const std = @import("std");
const clearance = @import("clearance");

pub fn main() !void {
    var set = try clearance.jwk.KeySet.parse(std.heap.page_allocator, "{\"kty\":\"OKP\",\"crv\":\"Ed25519\",\"x\":\"11qYAYKxCrfVS_7TyWQHOg7hcvPapiMlrwIaaPcHURo\"}", .{});
    defer set.deinit();
    var scratch: [512]u8 = undefined;
    const verified = try clearance.jws.verify("eyJhbGciOiJFZERTQSJ9.RXhhbXBsZSBvZiBFZDI1NTE5IHNpZ25pbmc.hgyY0il_MGCjP0JzlnLWG1PPOt7-09PGcvMg3AIbQR6dWbhijcNR4ki4iylGjg5BhVsPt9g7sVvpAr_MuM0KAg", set.keys, .{ .algorithms = &.{.eddsa} }, &scratch);
    std.debug.assert(std.mem.eql(u8, verified.payload, "Example of Ed25519 signing"));
}
