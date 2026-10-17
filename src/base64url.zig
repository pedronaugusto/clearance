//! Base64url without padding (RFC 7515 §2, RFC 4648 §5), as JOSE writes every
//! binary member. Decoding is strict: a padding character, a character outside
//! the alphabet, a length no encoding has, or a last character whose unused
//! bits are not zero is refused, so one value has exactly one encoding.
const std = @import("std");

const codecs = std.base64.url_safe_no_pad;

pub const DecodeError = error{Invalid};

/// The length `text` decodes to, or `Invalid` when no encoding is that long.
pub fn decodedLength(text: []const u8) DecodeError!usize {
    if (text.len % 4 == 1) return error.Invalid;
    return codecs.Decoder.calcSizeForSlice(text) catch error.Invalid;
}

/// Decodes `text` into the start of `out`, which holds at least
/// `decodedLength(text)` bytes, and returns what was written.
pub fn decode(out: []u8, text: []const u8) DecodeError![]u8 {
    const length = try decodedLength(text);
    if (out.len < length) unreachable; // the caller sized `out` from decodedLength
    codecs.Decoder.decode(out[0..length], text) catch return error.Invalid;
    // The last character's unused bits must be zero: std's decoder drops them.
    const rest = text.len % 4;
    if (rest != 0) {
        const last = codecs.Decoder.char_to_index[text[text.len - 1]];
        const unused: u3 = if (rest == 2) 4 else 2;
        if (last & ((@as(u8, 1) << unused) - 1) != 0) return error.Invalid;
    }
    return out[0..length];
}

/// Decodes `text` into a new allocation of exactly its length.
pub fn decodeAlloc(gpa: std.mem.Allocator, text: []const u8) (DecodeError || std.mem.Allocator.Error)![]u8 {
    const out = try gpa.alloc(u8, try decodedLength(text));
    errdefer gpa.free(out);
    return decode(out, text);
}

/// The length of the encoding of `length` bytes.
pub fn encodedLength(length: usize) usize {
    return codecs.Encoder.calcSize(length);
}

/// Writes the encoding of `bytes`.
pub fn encode(w: *std.Io.Writer, bytes: []const u8) std.Io.Writer.Error!void {
    var chunk: [3 * 64]u8 = undefined;
    var encoded: [4 * 64]u8 = undefined;
    var rest = bytes;
    while (rest.len > 0) {
        const n = @min(rest.len, chunk.len);
        @memcpy(chunk[0..n], rest[0..n]);
        try w.writeAll(codecs.Encoder.encode(&encoded, chunk[0..n]));
        rest = rest[n..];
    }
}

test "decoding is strict: padding, foreign characters, impossible lengths and set unused bits are refused" {
    var out: [16]u8 = undefined;
    try std.testing.expectEqualStrings("hi", try decode(&out, "aGk"));
    try std.testing.expectError(error.Invalid, decode(&out, "aGk="));
    try std.testing.expectError(error.Invalid, decode(&out, "aGl"));
    try std.testing.expectError(error.Invalid, decode(&out, "a+k"));
    try std.testing.expectError(error.Invalid, decode(&out, "aGkaa"));
    try std.testing.expectError(error.Invalid, decode(&out, "aGk."));
    try std.testing.expectEqualStrings("", try decode(&out, ""));
}
