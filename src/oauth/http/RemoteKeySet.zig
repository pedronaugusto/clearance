//! A JWK set kept from a `jwks_uri`: fetched when first asked for, kept for
//! as long as its answer's caching allows (clamped to a range), fetched again
//! when a token names a key it lacks, at most once per cooldown, and by one
//! task at a time while every other asking waits for that fetch. A failed
//! fetch keeps the old set for a grace past its expiry, so a key server's
//! outage costs no tokens while the grace lasts, and a flood of unknown
//! `kid`s costs one fetch per cooldown.
//!
//! The keys are handed out as a `Lease` on the set as it was: a fetch
//! replaces the set, and the old one is freed when its last lease is
//! released, never under a verification that holds it.
const std = @import("std");
const aegis = @import("aegis");
const uplink = @import("uplink");
const clearance = @import("clearance");
const fetch = @import("fetch.zig");

const jwk = clearance.jwk;
const jwt = clearance.jwt;
const Key = clearance.Key;
const RemoteKeySet = @This();

pub const Duration = aegis.units.Duration(.second, u32);

pub const Options = struct {
    /// How the set is read: `secrets` is always off, a published set holds
    /// public keys.
    keys: jwk.Options = .{},
    /// The lifetime when the answer says none.
    lifetime: Duration = .literal("1h"),
    /// What the answer's lifetime is clamped to: a set is kept at least
    /// `min_lifetime` (a `no-store` key server is not asked per token) and at
    /// most `max_lifetime` (a rotation is seen within it).
    min_lifetime: Duration = .literal("5m"),
    max_lifetime: Duration = .literal("24h"),
    /// The least time between two fetches: what an unknown `kid`, or a
    /// failing key server, costs at most.
    cooldown: Duration = .literal("60s"),
    /// How long past its expiry a set is still used while fetches fail
    /// (.NET's last known good). Zero refuses every token once the set has
    /// expired and its key server does not answer.
    stale_if_error: Duration = .literal("1h"),
    fetch: fetch.Options = .{},
};

pub const FetchError = fetch.Error || jwk.ParseError || error{
    /// The key server answered with a status other than a success.
    UnexpectedStatus,
};

pub const LeaseError = FetchError || error{
    /// No set is held and the last fetch failed less than a cooldown ago.
    Unavailable,
};

/// A set as it was fetched, shared by its leases.
const Snapshot = struct {
    gpa: std.mem.Allocator,
    set: jwk.KeySet,
    /// One for the key set holding it as its current one, one per lease.
    refs: std.atomic.Value(u32),
    /// Seconds since the epoch: when it is to be fetched again.
    fresh_until: i64,
    /// Seconds since the epoch: when it is used no more, fetched or not.
    usable_until: i64,

    fn unref(s: *Snapshot) void {
        if (s.refs.fetchSub(1, .acq_rel) != 1) return;
        const gpa = s.gpa;
        s.set.deinit();
        gpa.destroy(s);
    }
};

/// The keys of a set, held until `release`.
pub const Lease = struct {
    keys: []const Key,
    snapshot: *Snapshot,

    pub fn release(l: *Lease) void {
        l.snapshot.unref();
        l.* = undefined;
    }
};

gpa: std.mem.Allocator,
/// Owned.
uri: []const u8,
options: Options,
mutex: std.Io.Mutex = .init,
/// Broadcast when a fetch ends.
fetched: std.Io.Condition = .init,
/// Guarded by `mutex`: the set held, one ref of it ours.
current: ?*Snapshot = null,
/// Guarded by `mutex`: a task is fetching.
fetching: bool = false,
/// Guarded by `mutex`: seconds since the epoch when the last fetch began.
last_attempt: ?i64 = null,
/// Guarded by `mutex`: why the last fetch failed, null after a success.
last_error: ?FetchError = null,

/// A key set for `uri`, an HTTPS URL (or HTTP to loopback), fetched when
/// first asked for. `gpa` must be safe to share between the tasks that
/// lease from it.
pub fn init(gpa: std.mem.Allocator, uri: []const u8, options: Options) error{ OutOfMemory, InvalidEndpoint }!RemoteKeySet {
    _ = @import("../url.zig").endpoint(uri) catch return error.InvalidEndpoint;
    var o = options;
    o.keys.secrets = false;
    return .{ .gpa = gpa, .uri = try gpa.dupe(u8, uri), .options = o };
}

/// Drops the set held. Leases still out keep theirs until released.
pub fn deinit(r: *RemoteKeySet) void {
    if (r.current) |c| c.unref();
    r.gpa.free(r.uri);
    r.* = undefined;
}

/// Which set a lease wants.
pub const Want = enum {
    /// The set held while it is fresh; fetched when none is or it expired.
    current,
    /// A token named a key the held set lacks: fetched again unless the last
    /// fetch was less than a cooldown ago.
    missing_key,
};

/// The keys to verify with now, as `want` says.
pub fn lease(r: *RemoteKeySet, io: std.Io, http: *uplink.Client, want: Want) (LeaseError || std.Io.Cancelable)!Lease {
    try r.mutex.lock(io);
    defer r.mutex.unlock(io);
    var waited = false;
    while (true) {
        const now = seconds(io);
        const held = r.current;
        const stale = if (held) |c| now >= c.fresh_until else true;
        if (!stale and (want == .current or waited)) return take(held.?);
        if (waited) return r.usableOr(now, held);
        if (r.fetching) {
            try r.fetched.wait(io, &r.mutex);
            waited = true;
            continue;
        }
        const cooling = if (r.last_attempt) |at| now - at < @as(i64, r.options.cooldown.raw()) else false;
        if (cooling) return r.usableOr(now, held);
        r.fetching = true;
        const previous_attempt = r.last_attempt;
        r.last_attempt = now;
        r.mutex.unlock(io);
        const result = r.fetchSet(io, http, now);
        r.mutex.lockUncancelable(io);
        r.fetching = false;
        r.fetched.broadcast(io);
        if (result) |snapshot| {
            if (r.current) |old| old.unref();
            r.current = snapshot;
            r.last_error = null;
        } else |err| switch (err) {
            // A canceled fetch says nothing of the key server.
            error.Canceled => {
                r.last_attempt = previous_attempt;
                return error.Canceled;
            },
            else => |e| r.last_error = e,
        }
        waited = true;
    }
}

/// The set held while still usable, else why there is none.
fn usableOr(r: *RemoteKeySet, now: i64, held: ?*Snapshot) LeaseError!Lease {
    if (held) |c| if (now < c.usable_until) return take(c);
    return r.last_error orelse error.Unavailable;
}

fn take(s: *Snapshot) Lease {
    _ = s.refs.fetchAdd(1, .monotonic);
    return .{ .keys = s.set.keys, .snapshot = s };
}

fn fetchSet(r: *RemoteKeySet, io: std.Io, http: *uplink.Client, now: i64) FetchError!*Snapshot {
    var answer = try fetch.get(r.gpa, io, http, r.uri, r.options.keys.max_bytes, r.options.fetch);
    defer answer.deinit(r.gpa);
    if (answer.status < 200 or answer.status > 299) return error.UnexpectedStatus;
    var set = try jwk.KeySet.parse(r.gpa, answer.body, r.options.keys);
    errdefer set.deinit();
    const lifetime: i64 = std.math.clamp(
        @as(i64, answer.fresh_for orelse r.options.lifetime.raw()),
        @as(i64, r.options.min_lifetime.raw()),
        @as(i64, r.options.max_lifetime.raw()),
    );
    const s = try r.gpa.create(Snapshot);
    s.* = .{
        .gpa = r.gpa,
        .set = set,
        .refs = .init(1),
        .fresh_until = now + lifetime,
        .usable_until = now + lifetime + @as(i64, r.options.stale_if_error.raw()),
    };
    return s;
}

fn seconds(io: std.Io) i64 {
    return @intCast(@divFloor(std.Io.Clock.real.now(io).nanoseconds, std.time.ns_per_s));
}

/// A JWT verified with the keys of a lease the caller releases once done
/// with `verified`, whose key and strings may live in the set.
pub fn Verification(comptime Claims: type) type {
    return struct {
        verified: jwt.Verified(Claims),
        lease: Lease,

        pub fn release(v: *@This()) void {
            v.lease.release();
        }
    };
}

pub const VerifyError = jwt.VerifyError || LeaseError || std.Io.Cancelable;

/// Verifies `token` with the set: the set held first, and when no key of
/// it fits, the set fetched again (as the cooldown allows) and tried once
/// more. `now` is the time the claims are checked at.
pub fn verify(r: *RemoteKeySet, comptime Claims: type, io: std.Io, http: *uplink.Client, token: []const u8, validation: jwt.Validation, now: std.Io.Timestamp, scratch: []u8) VerifyError!Verification(Claims) {
    var l = try r.lease(io, http, .current);
    if (jwt.verify(Claims, token, l.keys, validation, now, scratch)) |verified| {
        return .{ .verified = verified, .lease = l };
    } else |err| {
        l.release();
        if (err != error.NoKey) return err;
    }
    var again = try r.lease(io, http, .missing_key);
    errdefer again.release();
    return .{ .verified = try jwt.verify(Claims, token, again.keys, validation, now, scratch), .lease = again };
}
