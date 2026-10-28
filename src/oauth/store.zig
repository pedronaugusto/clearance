//! Where a client keeps its tokens between requests and across runs: the
//! `TokenStore` interface the flows read and write, by a key the caller
//! chooses (a resource's URL, an issuer and client), and a store in memory.
//! A durable store (a file, a keychain) is the caller's: it writes a set
//! with `TokenSet.write` and reads it back with `TokenSet.read`, and keeps
//! what it wrote as the secret it is.
const std = @import("std");
const aegis = @import("aegis");
const token = @import("token.zig");

const TokenSet = token.TokenSet;

pub const LoadError = error{
    /// The store could not be read.
    Unavailable,
    Canceled,
    OutOfMemory,
};

pub const SaveError = error{
    /// The store could not be written.
    Unavailable,
    Canceled,
    OutOfMemory,
};

/// A store embeds one and finds itself from it by `@fieldParentPtr`
/// (`Memory.store`).
pub const TokenStore = struct {
    loadFn: *const fn (s: *TokenStore, io: std.Io, gpa: std.mem.Allocator, key: []const u8) LoadError!?TokenSet,
    saveFn: *const fn (s: *TokenStore, io: std.Io, key: []const u8, set: *const TokenSet) SaveError!void,
    forgetFn: *const fn (s: *TokenStore, io: std.Io, key: []const u8) void,

    /// The set kept under `key`, a copy the caller owns, or null.
    pub fn load(s: *TokenStore, io: std.Io, gpa: std.mem.Allocator, key: []const u8) LoadError!?TokenSet {
        return s.loadFn(s, io, gpa, key);
    }

    /// Keeps a copy of `set` under `key`, replacing what was there.
    pub fn save(s: *TokenStore, io: std.Io, key: []const u8, set: *const TokenSet) SaveError!void {
        return s.saveFn(s, io, key, set);
    }

    /// Drops what is kept under `key`: a sign-out, or a refresh token the
    /// server refused.
    pub fn forget(s: *TokenStore, io: std.Io, key: []const u8) void {
        s.forgetFn(s, io, key);
    }
};

/// Tokens kept in this process's memory, wiped when dropped. Safe to share
/// between tasks; `gpa` must be too.
pub const Memory = struct {
    gpa: std.mem.Allocator,
    /// Keys are owned.
    sets: aegis.BlockingGuarded(Sets) = .init(.empty),
    /// The memory as the flows take it.
    store: TokenStore = .{ .loadFn = load, .saveFn = save, .forgetFn = forget },

    const Sets = std.StringHashMapUnmanaged(TokenSet);

    pub fn init(gpa: std.mem.Allocator) Memory {
        return .{ .gpa = gpa };
    }

    pub fn deinit(m: *Memory) void {
        const sets = m.sets.teardown();
        var it = sets.iterator();
        while (it.next()) |entry| {
            entry.value_ptr.deinit();
            m.gpa.free(entry.key_ptr.*);
        }
        sets.deinit(m.gpa);
        m.* = undefined;
    }

    fn load(s: *TokenStore, io: std.Io, gpa: std.mem.Allocator, key: []const u8) LoadError!?TokenSet {
        const m: *Memory = @fieldParentPtr("store", s);
        var held = try m.sets.acquire(io);
        defer held.deinit(io);
        const set = held.value().getPtr(key) orelse return null;
        return try TokenSet.init(gpa, set.borrow());
    }

    fn save(s: *TokenStore, io: std.Io, key: []const u8, set: *const TokenSet) SaveError!void {
        const m: *Memory = @fieldParentPtr("store", s);
        var copy = try TokenSet.init(m.gpa, set.borrow());
        errdefer copy.deinit();
        var held = try m.sets.acquire(io);
        defer held.deinit(io);
        const sets = held.value();
        const entry = try sets.getOrPut(m.gpa, key);
        if (entry.found_existing) {
            entry.value_ptr.deinit();
        } else {
            entry.key_ptr.* = m.gpa.dupe(u8, key) catch |err| {
                sets.removeByPtr(entry.key_ptr);
                return err;
            };
        }
        entry.value_ptr.* = copy;
    }

    fn forget(s: *TokenStore, io: std.Io, key: []const u8) void {
        const m: *Memory = @fieldParentPtr("store", s);
        var held = m.sets.acquireUncancelable(io);
        defer held.deinit(io);
        const entry = held.value().fetchRemove(key) orelse return;
        var set = entry.value;
        set.deinit();
        m.gpa.free(entry.key);
    }
};

test "a memory store keeps copies by key, replaces them, and forgets them" {
    const gpa = std.testing.allocator;
    const io = std.testing.io;
    var memory: Memory = .init(gpa);
    defer memory.deinit();
    const s = &memory.store;
    try std.testing.expectEqual(@as(?TokenSet, null), try s.load(io, gpa, "https://rs.example/mcp"));
    {
        var set = try TokenSet.init(gpa, .{ .access_token = "a1", .refresh_token = "r1", .expires_at = 10 });
        defer set.deinit();
        try s.save(io, "https://rs.example/mcp", &set);
    }
    var loaded = (try s.load(io, gpa, "https://rs.example/mcp")).?;
    try std.testing.expectEqualStrings("r1", loaded.refresh_token.?);
    loaded.deinit();
    {
        var set = try TokenSet.init(gpa, .{ .access_token = "a2" });
        defer set.deinit();
        try s.save(io, "https://rs.example/mcp", &set);
    }
    var replaced = (try s.load(io, gpa, "https://rs.example/mcp")).?;
    try std.testing.expectEqualStrings("a2", replaced.access_token);
    try std.testing.expectEqual(@as(?[]const u8, null), replaced.refresh_token);
    replaced.deinit();
    s.forget(io, "https://rs.example/mcp");
    s.forget(io, "never kept");
    try std.testing.expectEqual(@as(?TokenSet, null), try s.load(io, gpa, "https://rs.example/mcp"));
}
