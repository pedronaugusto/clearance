//! JOSE's time: a NumericDate (RFC 7519 section 2), whole seconds since the Unix epoch, read from a
//! timestamp of the real clock.
const std = @import("std");
const aegis = @import("aegis");

/// A NumericDate as aegis holds it: an instant of the real clock in whole seconds.
pub const NumericDate = aegis.units.Instant(.real, .second, i64);

/// The second `at` falls in, since the Unix epoch. A timestamp past what i64 seconds hold saturates
/// at that bound: later, or earlier, than every date a token carries.
pub fn unixSeconds(at: std.Io.Timestamp) i64 {
    const date = NumericDate.fromTimestamp(at, .down) catch return if (at.nanoseconds < 0) std.math.minInt(i64) else std.math.maxInt(i64);
    return date.raw();
}

test "a timestamp's NumericDate is its second, rounded down" {
    try std.testing.expectEqual(@as(i64, 1_700_000_000), unixSeconds(.fromNanoseconds(1_700_000_000_999_999_999)));
    try std.testing.expectEqual(@as(i64, -1), unixSeconds(.fromNanoseconds(-1)));
    try std.testing.expectEqual(std.math.maxInt(i64), unixSeconds(.fromNanoseconds(std.math.maxInt(i96))));
}
