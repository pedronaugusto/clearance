//! clearance's benchmarks: JWT and JWS verification and signing per
//! algorithm, and key sets read. `bay bench` runs them in ReleaseFast and
//! writes one JSON line per row to stdout; `bay test` runs each row once with
//! `--smoke`. Timings are taken by hand, never in CI.
const std = @import("std");
const clearance = @import("clearance");
const shakedown = @import("shakedown");
const provenance = @import("preflight_bench_options");

const WorkloadError = clearance.jwt.VerifyError || clearance.jwt.SignError || clearance.jwk.ParseError;
const Row = shakedown.bench.Row(Bench, WorkloadError);

const secret: [32]u8 = @splat(0x2a);
const ed_jwks = "{\"keys\":[{\"kty\":\"OKP\",\"crv\":\"Ed25519\",\"kid\":\"ed\",\"x\":\"11qYAYKxCrfVS_7TyWQHOg7hcvPapiMlrwIaaPcHURo\"}]}";
const ed_token = "eyJhbGciOiJFZERTQSJ9.RXhhbXBsZSBvZiBFZDI1NTE5IHNpZ25pbmc.hgyY0il_MGCjP0JzlnLWG1PPOt7-09PGcvMg3AIbQR6dWbhijcNR4ki4iylGjg5BhVsPt9g7sVvpAr_MuM0KAg";

const Claims = struct { scope: []const u8 };

const Bench = struct {
    gpa: std.mem.Allocator,
    io: std.Io = undefined,
    token: std.Io.Writer.Allocating = undefined,
    set: clearance.jwk.KeySet = undefined,
    scratch: [4096]u8 = undefined,
    sink: usize = 0,

    fn setup(b: *Bench) WorkloadError!void {
        b.token = .init(b.gpa);
        try clearance.jwt.sign(b.gpa, b.io, &b.token.writer, .{}, .{ .exp = @as(i64, 4_000_000_000), .sub = "user-1", .scope = "read write" }, .{ .hmac = .{ .alg = .hs256, .secret = &secret } });
        b.set = try clearance.jwk.KeySet.parse(b.gpa, ed_jwks, .{});
    }

    fn teardown(b: *Bench) WorkloadError!void {
        b.set.deinit();
        b.token.deinit();
    }

    fn verifyHs256(b: *Bench, units: u64) WorkloadError!void {
        const keys = [_]clearance.Key{clearance.Key.hmac(&secret)};
        for (0..units) |_| {
            const verified = try clearance.jwt.verify(Claims, b.token.written(), &keys, .{ .algorithms = &.{.hs256} }, .{ .nanoseconds = 0 }, &b.scratch);
            b.sink +%= verified.claims.scope.len;
        }
    }

    fn verifyEdDsa(b: *Bench, units: u64) WorkloadError!void {
        for (0..units) |_| {
            const verified = try clearance.jws.verify(ed_token, b.set.keys, .{ .algorithms = &.{.eddsa} }, &b.scratch);
            b.sink +%= verified.payload.len;
        }
    }

    fn signHs256(b: *Bench, units: u64) WorkloadError!void {
        var out: [512]u8 = undefined;
        for (0..units) |_| {
            var w: std.Io.Writer = .fixed(&out);
            try clearance.jwt.sign(b.gpa, b.io, &w, .{}, .{ .exp = @as(i64, 4_000_000_000), .sub = "user-1" }, .{ .hmac = .{ .alg = .hs256, .secret = &secret } });
            b.sink +%= w.end;
        }
    }

    fn parseSet(b: *Bench, units: u64) WorkloadError!void {
        for (0..units) |_| {
            var set = try clearance.jwk.KeySet.parse(b.gpa, ed_jwks, .{});
            b.sink +%= set.keys.len;
            set.deinit();
        }
    }
};

const rows = [_]Row{
    .{ .name = "jwt/verify-hs256", .unit = "token", .run = Bench.verifyHs256, .fixture = .{ .lifetime = .row, .setup = Bench.setup, .teardown = Bench.teardown } },
    .{ .name = "jws/verify-eddsa", .unit = "token", .run = Bench.verifyEdDsa, .fixture = .{ .lifetime = .row, .setup = Bench.setup, .teardown = Bench.teardown } },
    .{ .name = "jwt/sign-hs256", .unit = "token", .run = Bench.signHs256, .fixture = .{ .lifetime = .row, .setup = Bench.setup, .teardown = Bench.teardown } },
    .{ .name = "jwk/parse-ed25519-set", .unit = "set", .run = Bench.parseSet },
};

pub fn main(init: std.process.Init) !void {
    const args = try init.minimal.args.toSlice(init.arena.allocator());
    const options = try shakedown.bench.Options.fromArguments(args[1..]);
    var buffer: [4096]u8 = undefined;
    var stdout = std.Io.File.stdout().writerStreaming(init.io, &buffer);
    var b: Bench = .{ .gpa = init.gpa, .io = init.io };
    try shakedown.bench.run(WorkloadError, init.gpa, init.io, &stdout.interface, &b, &rows, .{ .commit = provenance.commit, .cpu = provenance.cpu, .os = provenance.os }, options);
    try stdout.interface.flush();
    std.mem.doNotOptimizeAway(b.sink);
}
