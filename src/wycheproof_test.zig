//! Wycheproof's JOSE files (C2SP, testvectors_v1): every compact JWS in them
//! is verified against its group's key or key set, with every algorithm
//! clearance has allowed, and must be accepted exactly when the file says
//! `valid`.
const std = @import("std");
const jws = @import("jws.zig");
const jwk = @import("jwk.zig");
const Algorithm = @import("Algorithm.zig").Algorithm;
const Key = @import("Key.zig");

const all = std.enums.values(Algorithm);

const Outcome = struct { passed: usize = 0, total: usize = 0, mismatches: usize = 0, diverged: usize = 0 };

/// Cases clearance answers differently from the file, each with its reason.
/// Every one is checked to still diverge, so a fix shows here.
const Divergence = struct { file: []const u8, tc_id: i64, why: []const u8 };
const divergences = [_]Divergence{
    // The token is signed with PS384 under a key whose JWK says `alg: PS256` (RS256 for
    // 347 and 351): clearance uses a key that names its algorithm with that algorithm
    // alone (RFC 7517 4.4), as panva's jose does.
    .{ .file = "json_web_signature_test.json", .tc_id = 346, .why = "key alg differs from the token's" },
    .{ .file = "json_web_signature_test.json", .tc_id = 347, .why = "key alg differs from the token's" },
    .{ .file = "json_web_signature_test.json", .tc_id = 350, .why = "key alg differs from the token's" },
    .{ .file = "json_web_signature_test.json", .tc_id = 351, .why = "key alg differs from the token's" },
    // The same bytes as tcId 357, which the file calls valid: the labels of 367, 370,
    // 372 and 373 are crossed (372 and 373 hold a `?`, which is no base64url).
    .{ .file = "json_web_signature_test.json", .tc_id = 367, .why = "identical to valid tcId 357" },
    .{ .file = "json_web_signature_test.json", .tc_id = 370, .why = "identical to valid tcId 357" },
    .{ .file = "json_web_signature_test.json", .tc_id = 372, .why = "a ? in the header is not base64url" },
    .{ .file = "json_web_signature_test.json", .tc_id = 373, .why = "a ? in the payload is not base64url" },
};

fn diverges(file: []const u8, tc_id: i64) bool {
    for (divergences) |d| if (std.mem.eql(u8, d.file, file) and d.tc_id == tc_id) return true;
    return false;
}

fn campaign(comptime file: []const u8) !Outcome {
    const gpa = std.testing.allocator;
    var arena: std.heap.ArenaAllocator = .init(gpa);
    defer arena.deinit();
    const a = arena.allocator();
    const root = try std.json.parseFromSliceLeaky(std.json.Value, a, @embedFile("testing/vectors/wycheproof/" ++ file), .{});
    var outcome: Outcome = .{};
    for (root.object.get("testGroups").?.array.items) |group| {
        const key_json = group.object.get("public") orelse group.object.get("private").?;
        const text = try std.json.Stringify.valueAlloc(a, key_json, .{});
        var parsed = jwk.KeySet.parse(gpa, text, .{ .secrets = true });
        defer if (parsed) |*set| set.deinit() else |_| {};
        const keys: []const Key = if (parsed) |*set| set.keys else |_| &.{};
        for (group.object.get("tests").?.array.items) |vector| {
            const token = switch (vector.object.get("jws") orelse continue) {
                .string => |s| s,
                else => continue, // JWE and JSON serializations are not compact JWS
            };
            outcome.total += 1;
            const expected = std.mem.eql(u8, vector.object.get("result").?.string, "valid");
            const scratch = try a.alloc(u8, jws.scratchLength(token.len));
            const accepted = if (jws.verify(token, keys, .{ .algorithms = all, .max_bytes = .literal("1MiB") }, scratch)) |_| true else |_| false;
            const tc_id = vector.object.get("tcId").?.integer;
            if (diverges(file, tc_id)) {
                if (accepted == expected) {
                    std.debug.print("WYCHEPROOF {s} tcId={d} no longer diverges: remove it from the table\n", .{ file, tc_id });
                    outcome.mismatches += 1;
                } else outcome.diverged += 1;
            } else if (accepted == expected) {
                outcome.passed += 1;
            } else {
                outcome.mismatches += 1;
                std.debug.print("WYCHEPROOF {s} tcId={d} expected={s} accepted={} comment={s}\n", .{ file, vector.object.get("tcId").?.integer, vector.object.get("result").?.string, accepted, vector.object.get("comment").?.string });
            }
        }
    }
    return outcome;
}

test "Wycheproof json_web_signature_test: every compact JWS accepted exactly when valid" {
    const outcome = try campaign("json_web_signature_test.json");
    try std.testing.expectEqual(@as(usize, 393), outcome.passed);
    try std.testing.expectEqual(@as(usize, 0), outcome.mismatches);
}

test "Wycheproof json_web_key_test: key sets, duplicate and mixed keys" {
    const outcome = try campaign("json_web_key_test.json");
    try std.testing.expectEqual(@as(usize, 26), outcome.passed);
    try std.testing.expectEqual(@as(usize, 0), outcome.mismatches);
}

test "Wycheproof json_web_crypto_test: the compact JWS cases" {
    const outcome = try campaign("json_web_crypto_test.json");
    try std.testing.expectEqual(@as(usize, 48), outcome.passed);
    try std.testing.expectEqual(@as(usize, 0), outcome.mismatches);
}
