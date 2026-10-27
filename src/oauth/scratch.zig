//! Where a response that may hold secrets is parsed: on the stack when it is
//! small, in wiped heap memory when it is not; what the parser wrote is wiped
//! either way. The token and exchange readers share it.
const std = @import("std");
const aegis = @import("aegis");

/// What reading `length` bytes of JSON that may hold secrets can take: its
/// unescaped strings and the parser's own bookkeeping.
pub fn scratchLength(length: usize) usize {
    return length * 2 + 4096;
}

/// Where a response is parsed: on the stack when it is small (a token
/// response usually is), on the heap in wiped memory when it is not. Only
/// what the parser wrote is wiped from the stack: strings it unescaped, so a
/// response without escapes costs no allocation and no wipe.
pub const Scratch = struct {
    stack: [scratchLength(2048)]u8,
    heap: ?aegis.SecretBytes,
    /// What `heap` was allocated with.
    gpa: std.mem.Allocator,
    fixed: std.heap.FixedBufferAllocator,
    /// The furthest the parser has written: a shrink or a free moves the
    /// fixed allocator's end back, never this.
    high: usize,

    /// Sets up `s` in place, its stack left as it is: a struct literal
    /// would fill the whole buffer with zeros first, more work than the
    /// parse itself.
    pub fn init(s: *Scratch, gpa: std.mem.Allocator, length: usize) std.mem.Allocator.Error!void {
        s.heap = null;
        s.gpa = gpa;
        s.high = 0;
        const capacity = scratchLength(length);
        if (capacity <= s.stack.len) {
            s.fixed = .init(s.stack[0..capacity]);
            return;
        }
        s.heap = aegis.SecretBytes.init(gpa, capacity) catch return error.OutOfMemory;
        // unreachable: the capacity was just allocated at this length
        s.heap.?.resizeWithinCapacity(capacity) catch unreachable;
        s.fixed = .init(s.heap.?.exposeMut());
    }

    pub fn deinit(s: *Scratch) void {
        if (s.heap) |*h| return h.deinit(s.gpa);
        std.crypto.secureZero(u8, s.stack[0..s.high]);
    }

    pub fn allocator(s: *Scratch) std.mem.Allocator {
        return .{ .ptr = s, .vtable = &.{ .alloc = alloc, .resize = resize, .remap = remap, .free = free } };
    }

    fn mark(s: *Scratch) void {
        s.high = @max(s.high, s.fixed.end_index);
    }

    fn alloc(opaque_self: *anyopaque, len: usize, alignment: std.mem.Alignment, ret: usize) ?[*]u8 {
        const s: *Scratch = @ptrCast(@alignCast(opaque_self)); // safe: the vtable is only ever handed out with a *Scratch
        defer s.mark();
        return s.fixed.allocator().rawAlloc(len, alignment, ret);
    }

    fn resize(opaque_self: *anyopaque, memory: []u8, alignment: std.mem.Alignment, new_len: usize, ret: usize) bool {
        const s: *Scratch = @ptrCast(@alignCast(opaque_self)); // safe: the vtable is only ever handed out with a *Scratch
        defer s.mark();
        return s.fixed.allocator().rawResize(memory, alignment, new_len, ret);
    }

    fn remap(opaque_self: *anyopaque, memory: []u8, alignment: std.mem.Alignment, new_len: usize, ret: usize) ?[*]u8 {
        const s: *Scratch = @ptrCast(@alignCast(opaque_self)); // safe: the vtable is only ever handed out with a *Scratch
        defer s.mark();
        return s.fixed.allocator().rawRemap(memory, alignment, new_len, ret);
    }

    fn free(opaque_self: *anyopaque, memory: []u8, alignment: std.mem.Alignment, ret: usize) void {
        const s: *Scratch = @ptrCast(@alignCast(opaque_self)); // safe: the vtable is only ever handed out with a *Scratch
        s.fixed.allocator().rawFree(memory, alignment, ret);
    }
};
