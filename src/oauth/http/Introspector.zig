//! Token introspection (RFC 7662) for a resource server, its answers kept:
//! an answer is reused until the earlier of the token's `exp` and a bound
//! (RFC 7662 §4: a cached answer is a revocation not yet seen, so the bound
//! is short), keyed by the token's SHA-256, never the token itself. The
//! cache holds at most a count of answers; when full, expired ones go first,
//! then the one closest to expiry.
const std = @import("std");
const aegis = @import("aegis");
const uplink = @import("uplink");
const client_auth = @import("../client_auth.zig");
const introspection = @import("../introspection.zig");
const errors = @import("../errors.zig");
const url = @import("../url.zig");
const fetch = @import("fetch.zig");

const Introspection = introspection.Introspection;
const Introspector = @This();

pub const Duration = aegis.units.Duration(.second, u32);

pub const Options = struct {
    /// The longest an answer is kept. Zero keeps none.
    max_lifetime: Duration = .literal("60s"),
    /// The most answers kept.
    max_entries: u32 = 1024,
    max_bytes: fetch.Bytes = .literal("64KiB"),
    fetch: fetch.Options = .{},
};

pub const Error = fetch.Error || client_auth.Error || introspection.ReadError || std.Io.Cancelable;

/// The authorization server's answer.
pub const Result = union(enum) {
    introspected: Introspection,
    /// The endpoint refused the request (the resource server's credentials,
    /// most often): not an answer about the token.
    refused: errors.ErrorResponse,
};

const Entry = struct {
    arena: *std.heap.ArenaAllocator,
    value: Introspection,
    /// Seconds since the epoch.
    until: i64,
};

gpa: std.mem.Allocator,
/// Owned.
endpoint: []const u8,
/// Owned: the audience of a `private_key_jwt` assertion.
issuer: []const u8,
/// The resource server's credentials, borrowed.
client: client_auth.Client,
options: Options,
mutex: std.Io.Mutex = .init,
/// Guarded by `mutex`.
entries: std.AutoHashMapUnmanaged([32]u8, Entry) = .empty,

/// An introspector asking `endpoint` (the metadata's
/// `introspection_endpoint`) of the server `issuer`, as `client`. `gpa`
/// must be safe to share between the tasks that use it.
pub fn init(gpa: std.mem.Allocator, endpoint: []const u8, issuer: []const u8, client: client_auth.Client, options: Options) error{ OutOfMemory, InvalidEndpoint }!Introspector {
    _ = url.endpoint(endpoint) catch return error.InvalidEndpoint;
    const e = try gpa.dupe(u8, endpoint);
    errdefer gpa.free(e);
    return .{ .gpa = gpa, .endpoint = e, .issuer = try gpa.dupe(u8, issuer), .client = client, .options = options };
}

pub fn deinit(i: *Introspector) void {
    var it = i.entries.valueIterator();
    while (it.next()) |e| drop(i.gpa, e);
    i.entries.deinit(i.gpa);
    i.gpa.free(i.endpoint);
    i.gpa.free(i.issuer);
    i.* = undefined;
}

fn drop(gpa: std.mem.Allocator, e: *Entry) void {
    e.arena.deinit();
    gpa.destroy(e.arena);
}

/// What the server says of `token`, from the cache while it holds an
/// answer. Strings live in `arena`.
pub fn introspect(i: *Introspector, io: std.Io, http: *uplink.Client, arena: std.mem.Allocator, token: []const u8) Error!Result {
    var key: [32]u8 = undefined;
    std.crypto.hash.sha2.Sha256.hash(token, &key, .{});
    const now = std.Io.Clock.real.now(io);
    const now_s: i64 = @intCast(@divFloor(now.nanoseconds, std.time.ns_per_s));
    {
        try i.mutex.lock(io);
        defer i.mutex.unlock(io);
        if (i.entries.get(key)) |e| if (now_s < e.until) return .{ .introspected = try clone(arena, e.value) };
    }

    var request = try introspection.request(i.gpa, io, i.client, token, .{ .issuer = i.issuer, .now = now });
    defer request.deinit();
    var answer = try fetch.postForm(i.gpa, io, http, i.endpoint, &request, i.options.max_bytes, i.options.fetch);
    defer answer.deinit();

    const entry_arena = try i.gpa.create(std.heap.ArenaAllocator);
    entry_arena.* = .init(i.gpa);
    var entry: Entry = .{ .arena = entry_arena, .value = undefined, .until = undefined };
    var kept = false;
    defer if (!kept) drop(i.gpa, &entry);
    const read = try introspection.readResponse(entry_arena.allocator(), answer.status, answer.body.expose(), .{ .max_bytes = i.options.max_bytes });
    const value = switch (read) {
        .refused => |e| return .{ .refused = e },
        .introspected => |v| v,
    };
    const out = try clone(arena, value);
    const bound = now_s + @as(i64, i.options.max_lifetime.raw());
    entry.value = value;
    entry.until = if (value.active) @min(bound, value.exp orelse bound) else bound;
    if (entry.until <= now_s or i.options.max_entries == 0) return .{ .introspected = out };

    try i.mutex.lock(io);
    defer i.mutex.unlock(io);
    if (i.entries.count() >= i.options.max_entries) i.evict(now_s);
    const slot = try i.entries.getOrPut(i.gpa, key);
    if (slot.found_existing) drop(i.gpa, slot.value_ptr);
    slot.value_ptr.* = entry;
    kept = true;
    return .{ .introspected = out };
}

/// Makes room for one: every expired answer dropped, else the one closest
/// to its expiry.
fn evict(i: *Introspector, now: i64) void {
    var soonest: ?[32]u8 = null;
    var soonest_until: i64 = std.math.maxInt(i64);
    var expired: std.ArrayList([32]u8) = .empty;
    defer expired.deinit(i.gpa);
    var it = i.entries.iterator();
    while (it.next()) |e| {
        if (e.value_ptr.until <= now) {
            // Without room to list more, those listed are dropped, or the soonest.
            expired.append(i.gpa, e.key_ptr.*) catch break;
        } else if (e.value_ptr.until < soonest_until) {
            soonest_until = e.value_ptr.until;
            soonest = e.key_ptr.*;
        }
    }
    for (expired.items) |k| if (i.entries.fetchRemove(k)) |kv| {
        var e = kv.value;
        drop(i.gpa, &e);
    };
    if (expired.items.len != 0) return;
    if (soonest) |k| if (i.entries.fetchRemove(k)) |kv| {
        var e = kv.value;
        drop(i.gpa, &e);
    };
}

fn clone(arena: std.mem.Allocator, v: Introspection) std.mem.Allocator.Error!Introspection {
    var out = v;
    inline for (.{ "scope", "client_id", "username", "token_type", "sub", "iss", "jti" }) |name| {
        if (@field(v, name)) |s| @field(out, name) = try arena.dupe(u8, s);
    }
    const aud = try arena.alloc([]const u8, v.aud.len);
    for (v.aud, aud) |a, *o| o.* = try arena.dupe(u8, a);
    out.aud = aud;
    return out;
}
