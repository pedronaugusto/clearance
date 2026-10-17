//! An issuer discovered and its keys fetched, as a resource server or a
//! client starts: `bay dev discover -- https://accounts.google.com`. Run by
//! hand against live providers; built by the tests.
const std = @import("std");
const uplink = @import("uplink");
const oauth = @import("clearance.oauth");

pub fn main(init: std.process.Init) !void {
    const io = init.io;
    const gpa = init.gpa;
    const args = try init.minimal.args.toSlice(init.arena.allocator());
    var out_buffer: [1024]u8 = undefined;
    var out = std.Io.File.stdout().writer(io, &out_buffer);
    const w = &out.interface;
    defer w.flush() catch {}; // glint-ignore: Z026 -- a closed stdout leaves nothing to report to
    if (args.len < 2) return w.writeAll("usage: discover <issuer>...\n");
    var http: uplink.Client = .init(gpa, .{});
    defer http.deinit(io);
    for (args[1..]) |issuer| show(gpa, io, &http, issuer, w) catch |err| try w.print("{s}: {t}\n", .{ issuer, err });
}

fn show(gpa: std.mem.Allocator, io: std.Io, http: *uplink.Client, issuer: []const u8, w: *std.Io.Writer) !void {
    // --- README:oauth ---
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
    // --- README:oauth ---
    const m = &server.value;
    try w.print("{s}\n  token endpoint {s}\n  PKCE S256 {}\n  iss in callbacks {}\n", .{ m.issuer, m.token_endpoint orelse "-", m.supportsPkce(), m.authorization_response_iss_parameter_supported });
    try w.print("  keys {s}: {d} kept, {d} left out\n", .{ m.jwks_uri.?, lease.keys.len, lease.snapshot.set.skippedTotal() });
    for (lease.keys) |k| try w.print("    {s} {t}\n", .{ k.kid orelse "-", k.material });
}
