//! Where a client keeps its tokens between requests and across runs: the
//! `TokenStore` interface the flows read and write, by a key the caller
//! chooses (a resource's URL, an issuer and client), and a store in memory.
//! A durable store (a file, a keychain) is the caller's: it writes a set
//! with `TokenSet.write` and reads it back with `TokenSet.read`, and keeps
//! what it wrote as the secret it is.
const std = @import("std");
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

pub const TokenStore = struct {
    ptr: *anyopaque,
    vtable: *const VTable,

    pub const VTable = struct {
        /// The set kept under `key`, a copy the caller owns, or null.
        load: *const fn (ptr: *anyopaque, io: std.Io, gpa: std.mem.Allocator, key: []const u8) LoadError!?TokenSet,
        /// Keeps a copy of `set` under `key`, replacing what was there.
        save: *const fn (ptr: *anyopaque, io: std.Io, key: []const u8, set: *const TokenSet) SaveError!void,
        /// Drops what is kept under `key`: a sign-out, or a refresh token the
        /// server refused.
        forget: *const fn (ptr: *anyopaque, io: std.Io, key: []const u8) void,
    };

    pub fn load(s: TokenStore, io: std.Io, gpa: std.mem.Allocator, key: []const u8) LoadError!?TokenSet {
        return s.vtable.load(s.ptr, io, gpa, key);
    }

    pub fn save(s: TokenStore, io: std.Io, key: []const u8, set: *const TokenSet) SaveError!void {
        return s.vtable.save(s.ptr, io, key, set);
    }

    pub fn forget(s: TokenStore, io: std.Io, key: []const u8) void {
        s.vtable.forget(s.ptr, io, key);
    }
};

/// Tokens kept in this process's memory, wiped when dropped. Safe to share
/// between tasks; `gpa` must be too.
pub const Memory = struct {
    gpa: std.mem.Allocator,
    mutex: std.Io.Mutex = .init,
    /// Guarded by `mutex`. Keys are owned.
    sets: std.StringHashMapUnmanaged(TokenSet) = .empty,

    pub fn init(gpa: std.mem.Allocator) Memory {
        return .{ .gpa = gpa };
    }

    pub fn deinit(m: *Memory) void {
        var it = m.sets.iterator();
        while (it.next()) |entry| {
            entry.value_ptr.deinit();
            m.gpa.free(entry.key_ptr.*);
        }
        m.sets.deinit(m.gpa);
        m.* = undefined;
    }

    pub fn store(m: *Memory) TokenStore {
        return .{ .ptr = m, .vtable = &vtable };
    }

    const vtable: TokenStore.VTable = .{ .load = load, .save = save, .forget = forget };

    fn load(ptr: *anyopaque, io: std.Io, gpa: std.mem.Allocator, key: []const u8) LoadError!?TokenSet {
        const m: *Memory = @ptrCast(@alignCast(ptr)); // safe: the vtable is `store`'s, made over a `Memory`
        try m.mutex.lock(io);
        defer m.mutex.unlock(io);
        const set = m.sets.getPtr(key) orelse return null;
        return try TokenSet.init(gpa, set.borrow());
    }

    fn save(ptr: *anyopaque, io: std.Io, key: []const u8, set: *const TokenSet) SaveError!void {
        const m: *Memory = @ptrCast(@alignCast(ptr)); // safe: the vtable is `store`'s, made over a `Memory`
        var copy = try TokenSet.init(m.gpa, set.borrow());
        errdefer copy.deinit();
        try m.mutex.lock(io);
        defer m.mutex.unlock(io);
        const entry = try m.sets.getOrPut(m.gpa, key);
        if (entry.found_existing) {
            entry.value_ptr.deinit();
        } else {
            entry.key_ptr.* = m.gpa.dupe(u8, key) catch |err| {
                m.sets.removeByPtr(entry.key_ptr);
                return err;
            };
        }
        entry.value_ptr.* = copy;
    }

    fn forget(ptr: *anyopaque, io: std.Io, key: []const u8) void {
        const m: *Memory = @ptrCast(@alignCast(ptr)); // safe: the vtable is `store`'s, made over a `Memory`
        m.mutex.lockUncancelable(io);
        defer m.mutex.unlock(io);
        const entry = m.sets.fetchRemove(key) orelse return;
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
    const s = memory.store();
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
