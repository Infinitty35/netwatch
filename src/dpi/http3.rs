//! HTTP/3 body extraction + decompression for decrypted QUIC 1-RTT
//! payloads.
//!
//! Once `dpi::quic::decrypt_1rtt_packet` hands back a decrypted 1-RTT
//! packet's *frame* bytes, this module turns them into something a human
//! can read:
//!
//! 1. Walk the QUIC frames (RFC 9000 §19) and pull out STREAM-frame data.
//! 2. For a STREAM that starts at offset 0 (so we have the head of the
//!    request/response stream), parse the HTTP/3 framing layer
//!    (RFC 9114 §7.1) and concatenate DATA-frame payloads.
//! 3. Sniff / trial-decompress the body. gzip and zlib are detected by
//!    magic bytes. brotli has none, so it is tried only when the HEADERS
//!    frame says `content-encoding: br` in a form readable without QPACK
//!    decoder state (a static-table entry or a literal value; see
//!    [`fields_declare_brotli`]). Output is capped at [`MAX_H3_BODY_BYTES`].
//!
//! ## Scope
//! [`H3StreamReassembler`] (Phase 3b) accumulates STREAM-frame bytes per
//! (stream, direction), by offset, across packets and decodes the contiguous
//! prefix from byte 0 — a gzip/brotli stream must be fed from the start, so a
//! body is only recovered once its head and a contiguous run are present. A
//! response that fits one packet is just the single-chunk case of the same
//! path. zstd and identity (uncompressed) bodies are out of scope.

use std::io::Read;

/// A STREAM frame located inside a decrypted 1-RTT packet payload.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct StreamChunk {
    pub stream_id: u64,
    pub offset: u64,
    pub fin: bool,
    pub data: Vec<u8>,
}

/// Content coding detected for an HTTP/3 body.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum BodyEncoding {
    Gzip,
    Deflate,
    Brotli,
}

impl BodyEncoding {
    pub fn label(self) -> &'static str {
        match self {
            BodyEncoding::Gzip => "gzip",
            BodyEncoding::Deflate => "deflate",
            BodyEncoding::Brotli => "br",
        }
    }
}

/// A decompressed HTTP/3 body ready to show in the UI.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct DecodedBody {
    pub encoding: BodyEncoding,
    /// Stream the body came from (HTTP/3 request/response stream id).
    pub stream_id: u64,
    pub bytes: Vec<u8>,
    /// The body decompressed to more than [`MAX_H3_BODY_BYTES`], or than
    /// its flow had room for, and `bytes` holds only the first of them.
    pub truncated: bool,
}

impl DecodedBody {
    /// Its size for a label: "N bytes", or "first N bytes" when truncated.
    pub fn size_label(&self) -> String {
        if self.truncated {
            format!("first {} bytes", self.bytes.len())
        } else {
            format!("{} bytes", self.bytes.len())
        }
    }
}

/// Read a QUIC variable-length integer (RFC 9000 §16). Returns the value
/// and the number of bytes consumed. Self-contained so this module doesn't
/// depend on `quic`'s private helper.
fn read_varint(buf: &[u8]) -> Option<(u64, usize)> {
    let first = *buf.first()?;
    let len = 1usize << (first >> 6);
    if buf.len() < len {
        return None;
    }
    let mut val = (first & 0x3f) as u64;
    for &b in &buf[1..len] {
        val = (val << 8) | b as u64;
    }
    Some((val, len))
}

/// Skip `n` variable-length integers starting at `pos`, returning the new
/// position or `None` if the buffer runs out.
fn skip_varints(buf: &[u8], mut pos: usize, n: usize) -> Option<usize> {
    for _ in 0..n {
        let (_, used) = read_varint(buf.get(pos..)?)?;
        pos += used;
    }
    Some(pos)
}

/// Walk the QUIC frames in a decrypted 1-RTT packet payload and collect any
/// STREAM-frame chunks (RFC 9000 §19.8). Best-effort: on a frame type we
/// can't size, we stop and return what we have rather than risk
/// misaligned reads. The frame types handled are the ones that realistically
/// precede a STREAM frame in a server→client 1-RTT packet.
pub fn extract_stream_chunks(frames: &[u8]) -> Vec<StreamChunk> {
    let mut chunks = Vec::new();
    let mut pos = 0;
    while pos < frames.len() {
        let Some((frame_type, used)) = read_varint(&frames[pos..]) else {
            break;
        };
        pos += used;
        match frame_type {
            // PADDING / PING — single-byte, nothing follows the type.
            0x00 | 0x01 => continue,
            // ACK (0x02) / ACK+ECN (0x03). Layout: Largest Acked, ACK Delay,
            // Range Count, First Range, then Range Count × (Gap, Length),
            // then 3 ECN counts when the type is 0x03.
            0x02 | 0x03 => {
                // Read Range Count (3rd varint) to know how many ranges follow.
                let Some((range_count, _)) = read_varint(
                    frames
                        .get(skip_varints(frames, pos, 2).unwrap_or(frames.len())..)
                        .unwrap_or(&[]),
                ) else {
                    break;
                };
                // largest, delay, range_count, first_range = 4 varints.
                let Some(mut p) = skip_varints(frames, pos, 4) else {
                    break;
                };
                let mut ok = true;
                for _ in 0..range_count {
                    match skip_varints(frames, p, 2) {
                        Some(np) => p = np,
                        None => {
                            ok = false;
                            break;
                        }
                    }
                }
                if !ok {
                    break;
                }
                if frame_type == 0x03 {
                    let Some(np) = skip_varints(frames, p, 3) else {
                        break;
                    };
                    p = np;
                }
                pos = p;
            }
            // RESET_STREAM: stream_id, app_error, final_size.
            0x04 => match skip_varints(frames, pos, 3) {
                Some(np) => pos = np,
                None => break,
            },
            // STOP_SENDING: stream_id, app_error.
            0x05 => match skip_varints(frames, pos, 2) {
                Some(np) => pos = np,
                None => break,
            },
            // CRYPTO: offset, length, data — skip past the data.
            0x06 => {
                let Some((_offset, o)) = read_varint(&frames[pos..]) else {
                    break;
                };
                let Some((length, l)) = read_varint(&frames[pos + o..]) else {
                    break;
                };
                pos = pos + o + l + length as usize;
            }
            // NEW_TOKEN: length, token.
            0x07 => {
                let Some((length, l)) = read_varint(&frames[pos..]) else {
                    break;
                };
                pos = pos + l + length as usize;
            }
            // STREAM frames: 0x08..=0x0f. Low 3 bits are OFF/LEN/FIN.
            0x08..=0x0f => {
                let off_bit = frame_type & 0x04 != 0;
                let len_bit = frame_type & 0x02 != 0;
                let fin = frame_type & 0x01 != 0;
                let Some((stream_id, idu)) = read_varint(&frames[pos..]) else {
                    break;
                };
                pos += idu;
                let offset = if off_bit {
                    let Some((o, ou)) = read_varint(&frames[pos..]) else {
                        break;
                    };
                    pos += ou;
                    o
                } else {
                    0
                };
                let data_len = if len_bit {
                    let Some((l, lu)) = read_varint(&frames[pos..]) else {
                        break;
                    };
                    pos += lu;
                    l as usize
                } else {
                    // No LEN bit → data runs to the end of the packet.
                    frames.len() - pos
                };
                let end = pos.saturating_add(data_len);
                if end > frames.len() {
                    break;
                }
                chunks.push(StreamChunk {
                    stream_id,
                    offset,
                    fin,
                    data: frames[pos..end].to_vec(),
                });
                pos = end;
            }
            // MAX_DATA / MAX_STREAMS(2) — single varint argument.
            0x10 | 0x12 | 0x13 => match skip_varints(frames, pos, 1) {
                Some(np) => pos = np,
                None => break,
            },
            // MAX_STREAM_DATA — two varints.
            0x11 => match skip_varints(frames, pos, 2) {
                Some(np) => pos = np,
                None => break,
            },
            // HANDSHAKE_DONE — no payload.
            0x1e => continue,
            // Anything else (NEW_CONNECTION_ID, path frames, …) has a shape
            // we don't track here; stop rather than misread.
            _ => break,
        }
    }
    chunks
}

/// HTTP/3 frame types we care about (RFC 9114 §7.2).
const H3_FRAME_DATA: u64 = 0x00;
const H3_FRAME_HEADERS: u64 = 0x01;

/// The DATA-frame payload of one HTTP/3 stream, and whether its HEADERS
/// declared `content-encoding: br`.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct H3Payload {
    pub body: Vec<u8>,
    pub brotli: bool,
}

/// Parse the HTTP/3 framing layer of a request/response stream that starts
/// at offset 0 and concatenate the DATA-frame payloads. Returns `None` if
/// the bytes don't parse as H3 framing or carry no DATA. A trailing frame
/// truncated by the packet boundary is tolerated (we keep what parsed).
pub fn h3_data_payload(stream: &[u8]) -> Option<H3Payload> {
    let mut out = Vec::new();
    let mut pos = 0;
    let mut saw_known_frame = false;
    let mut brotli = false;
    while pos < stream.len() {
        let (ftype, tu) = read_varint(&stream[pos..])?;
        let Some((flen, lu)) = read_varint(stream.get(pos + tu..)?) else {
            // Length varint truncated at packet edge — stop with what we have.
            break;
        };
        let body_start = pos + tu + lu;
        let body_end = body_start.saturating_add(flen as usize);
        match ftype {
            H3_FRAME_DATA => {
                saw_known_frame = true;
                let end = body_end.min(stream.len());
                if body_start <= end {
                    out.extend_from_slice(&stream[body_start..end]);
                }
                if body_end > stream.len() {
                    break; // truncated final DATA frame
                }
                pos = body_end;
            }
            H3_FRAME_HEADERS => {
                saw_known_frame = true;
                if body_end > stream.len() {
                    break;
                }
                // QPACK-compressed; read only for the content coding.
                brotli |= fields_declare_brotli(&stream[body_start..body_end]);
                pos = body_end;
            }
            // Unknown/extension/GREASE frame — skip by its length.
            _ => {
                if body_end > stream.len() {
                    break;
                }
                pos = body_end;
            }
        }
    }
    if saw_known_frame && !out.is_empty() {
        Some(H3Payload { body: out, brotli })
    } else {
        None
    }
}

/// QPACK static-table indexes (RFC 9204 Appendix A) of the two
/// `content-encoding` entries: 42 is `content-encoding: br`, 43 is
/// `content-encoding: gzip`.
const QPACK_CONTENT_ENCODING_BR: u64 = 42;
const QPACK_CONTENT_ENCODING_GZIP: u64 = 43;

/// Whether a HEADERS frame's QPACK field section (RFC 9204 §4.5) says
/// `content-encoding: br`. Reads only what needs no decoder state: the
/// static-table entry, or a literal `br` value under a static or literal
/// `content-encoding` name. A dynamic-table reference, or a name we would
/// need Huffman-decoding to read, reads as "not br".
fn fields_declare_brotli(fields: &[u8]) -> bool {
    fn walk(fields: &[u8]) -> Option<bool> {
        // Section prefix: Required Insert Count, then sign + Delta Base.
        let (_, a) = read_prefixed_int(fields, 8)?;
        let (_, b) = read_prefixed_int(fields.get(a..)?, 7)?;
        let mut pos = a + b;
        while let Some(&first) = fields.get(pos) {
            let line = &fields[pos..];
            if first & 0x80 != 0 {
                // Indexed field line: 1 T index(6).
                let (index, n) = read_prefixed_int(line, 6)?;
                if first & 0x40 != 0 && index == QPACK_CONTENT_ENCODING_BR {
                    return Some(true);
                }
                pos += n;
            } else if first & 0x40 != 0 {
                // Literal with name reference: 01 N T index(4), value.
                let (index, n) = read_prefixed_int(line, 4)?;
                let (value, huffman, m) = read_string(line.get(n..)?, 7)?;
                let static_name = first & 0x10 != 0
                    && matches!(
                        index,
                        QPACK_CONTENT_ENCODING_BR | QPACK_CONTENT_ENCODING_GZIP
                    );
                if static_name && value_is_br(value, huffman) {
                    return Some(true);
                }
                pos += n + m;
            } else if first & 0x20 != 0 {
                // Literal with literal name: 001 N H length(3), name, value.
                let (name, name_huffman, n) = read_string(line, 3)?;
                let (value, huffman, m) = read_string(line.get(n..)?, 7)?;
                if !name_huffman
                    && name.eq_ignore_ascii_case(b"content-encoding")
                    && value_is_br(value, huffman)
                {
                    return Some(true);
                }
                pos += n + m;
            } else if first & 0x10 != 0 {
                // Indexed with post-base index: 0001 index(4). Dynamic.
                pos += read_prefixed_int(line, 4)?.1;
            } else {
                // Literal with post-base name reference: 0000 N index(3), value.
                let (_, n) = read_prefixed_int(line, 3)?;
                pos += n + read_string(line.get(n..)?, 7)?.2;
            }
        }
        Some(false)
    }
    walk(fields).unwrap_or(false)
}

/// Read an HPACK/QPACK prefixed integer (RFC 7541 §5.1) held in the low
/// `bits` bits of the first byte. Returns the value and bytes consumed.
fn read_prefixed_int(buf: &[u8], bits: u32) -> Option<(u64, usize)> {
    let max = (1u64 << bits) - 1;
    let value = u64::from(*buf.first()?) & max;
    if value < max {
        return Some((value, 1));
    }
    let mut value = value;
    for (i, &byte) in buf.iter().enumerate().skip(1) {
        let shift = 7 * (i as u32 - 1);
        if shift > 56 {
            return None;
        }
        value = value.checked_add(u64::from(byte & 0x7f) << shift)?;
        if byte & 0x80 == 0 {
            return Some((value, i + 1));
        }
    }
    None
}

/// Read a string literal (RFC 9204 §4.1.2): a Huffman flag just above a
/// `bits`-bit length prefix, then that many bytes. Returns the bytes, the
/// flag and the bytes consumed.
fn read_string(buf: &[u8], bits: u32) -> Option<(&[u8], bool, usize)> {
    let huffman = buf.first()? & (1 << bits) != 0;
    let (len, n) = read_prefixed_int(buf, bits)?;
    let end = n.checked_add(usize::try_from(len).ok()?)?;
    Some((buf.get(n..end)?, huffman, end))
}

/// `br` as sent: plain, or Huffman-coded (RFC 7541 Appendix B: `b` is
/// 100011, `r` is 101100, padded with ones to 0x8e 0xcf).
fn value_is_br(value: &[u8], huffman: bool) -> bool {
    if huffman {
        value == [0x8e, 0xcf]
    } else {
        value.eq_ignore_ascii_case(b"br")
    }
}

/// Most bytes one body decompresses to. A small compressed body can expand
/// a thousandfold, so without a cap one response could take gigabytes.
pub const MAX_H3_BODY_BYTES: u64 = 4 * 1024 * 1024;

/// Sniff / trial-decompress an HTTP body. gzip and zlib are detected by
/// magic bytes. brotli has none, so it's tried only when `brotli_declared`
/// (the response's HEADERS said `content-encoding: br`): trial-decoding
/// arbitrary bytes as brotli gives false positives. Returns the coding, the
/// decompressed bytes (at most `limit`, itself at most
/// [`MAX_H3_BODY_BYTES`]) and whether the body was cut short there, or
/// `None` if nothing produced sane output.
pub fn decompress_body(
    body: &[u8],
    brotli_declared: bool,
    limit: u64,
) -> Option<(BodyEncoding, Vec<u8>, bool)> {
    if body.len() < 2 {
        return None;
    }
    // gzip: 1f 8b.
    if body[0] == 0x1f && body[1] == 0x8b {
        if let Some((out, truncated)) = inflate(flate2::read::GzDecoder::new(body), limit) {
            return Some((BodyEncoding::Gzip, out, truncated));
        }
    }
    // zlib/deflate: 0x78 with a valid FCHECK (common variants 0x01/0x9c/0xda).
    if body[0] == 0x78 {
        if let Some((out, truncated)) = inflate(flate2::read::ZlibDecoder::new(body), limit) {
            return Some((BodyEncoding::Deflate, out, truncated));
        }
    }
    // brotli — only accept if it yields non-empty output.
    if brotli_declared {
        if let Some((out, truncated)) = inflate(brotli::Decompressor::new(body, 4096), limit) {
            if !out.is_empty() {
                return Some((BodyEncoding::Brotli, out, truncated));
            }
        }
    }
    None
}

/// Read a decoder to the end or to `limit`, whichever comes first. The flag
/// is true when the decoder had more to give.
fn inflate(mut decoder: impl Read, limit: u64) -> Option<(Vec<u8>, bool)> {
    let mut out = Vec::new();
    decoder.by_ref().take(limit).read_to_end(&mut out).ok()?;
    let truncated = out.len() as u64 == limit && !matches!(decoder.read(&mut [0u8; 1]), Ok(0));
    Some((out, truncated))
}

/// Per-stream byte cap and concurrent-stream cap, to bound memory on a busy
/// QUIC flow. A 2 MiB body is already far beyond what any single 1-RTT packet
/// carries; past it we keep the decodable prefix and drop the overflow.
const MAX_H3_STREAM_BYTES: usize = 2 * 1024 * 1024;
const MAX_H3_STREAMS: usize = 64;

/// Most bytes one flow's reassembler holds, buffers and decoded bodies
/// together. The caps above alone allow 64 × (2 MiB + 4 MiB), 384 MiB: more
/// than the stream tracker's whole budget, which never evicts the flow it is
/// charging. Past this, new data is dropped, and a body decodes only as far
/// as the room left.
pub const MAX_H3_FLOW_BYTES: usize = 64 * 1024 * 1024;

/// Cross-packet HTTP/3 stream reassembly (Phase 3b).
///
/// Feed each decrypted 1-RTT packet's frame bytes to [`ingest`] with the packet
/// direction; it routes STREAM-frame data into a per-(stream, direction) buffer
/// at the frame's offset. A QUIC *bidirectional* stream carries two independent
/// byte streams — request (c→s) and response (s→c) — each with its own offset
/// space starting at 0, so direction is part of the key; otherwise the request
/// and response would overwrite each other. Only client-initiated bidirectional
/// streams (`stream_id % 4 == 0`, the HTTP/3 request/response streams) are
/// tracked; control/QPACK/push streams are ignored.
///
/// Decoding is lazy: [`ingest`] only buffers (a memcpy + range bookkeeping) so it
/// stays off the capture hot path; [`decoded_bodies`] decompresses the
/// **contiguous prefix from offset 0** (feeding a gzip/brotli decoder across a
/// not-yet-received gap would corrupt it) and caches the result, re-running only
/// when more contiguous bytes have arrived.
#[derive(Debug, Clone, Default)]
pub struct H3StreamReassembler {
    /// Keyed by (HTTP/3 stream id, client_to_server) — see the type doc for why
    /// direction is part of the key.
    streams: std::collections::BTreeMap<(u64, bool), H3Stream>,
}

#[derive(Debug, Clone, Default)]
struct H3Stream {
    /// Offset-indexed byte buffer (zero-filled across not-yet-received gaps).
    data: Vec<u8>,
    /// Merged received byte ranges, sorted by start, so we know how far the
    /// contiguous prefix from offset 0 reaches.
    received: Vec<(u64, u64)>,
    fin: bool,
    /// Contiguous-prefix length last decoded, so we only re-run the
    /// decompressor when more contiguous bytes have arrived.
    decoded_len: usize,
    decoded: Option<DecodedBody>,
}

impl H3Stream {
    /// Length of the contiguous prefix starting at offset 0.
    fn contiguous_len(&self) -> usize {
        match self.received.first() {
            Some(&(0, end)) => end as usize,
            _ => 0,
        }
    }

    /// Record `[start, end)` as received, merging into the sorted range set.
    fn mark_received(&mut self, start: u64, end: u64) {
        if end <= start {
            return;
        }
        self.received.push((start, end));
        self.received.sort_unstable_by_key(|r| r.0);
        let mut merged: Vec<(u64, u64)> = Vec::with_capacity(self.received.len());
        for &(s, e) in &self.received {
            match merged.last_mut() {
                Some(last) if s <= last.1 => last.1 = last.1.max(e),
                _ => merged.push((s, e)),
            }
        }
        self.received = merged;
    }
}

impl H3StreamReassembler {
    pub fn new() -> Self {
        Self::default()
    }

    /// Buffer one decrypted 1-RTT packet's frame bytes for the given direction.
    /// Cheap — memcpy + range bookkeeping only, no decompression (that happens
    /// lazily in [`decoded_bodies`]) — so it's safe on the capture hot path.
    pub fn ingest(&mut self, client_to_server: bool, frames: &[u8]) {
        let mut held = self.held_bytes();
        for chunk in extract_stream_chunks(frames) {
            // HTTP/3 request/response data rides client-initiated bidirectional
            // streams (id % 4 == 0); skip control/QPACK/push streams.
            if chunk.stream_id % 4 != 0 {
                continue;
            }
            let key = (chunk.stream_id, client_to_server);
            if !self.streams.contains_key(&key) && self.streams.len() >= MAX_H3_STREAMS {
                continue;
            }
            let start = chunk.offset;
            let end = start.saturating_add(chunk.data.len() as u64);
            // Drop chunks that would push the buffer past the per-stream cap;
            // the decodable prefix below the cap is still useful.
            if end as usize > MAX_H3_STREAM_BYTES {
                continue;
            }
            // Likewise past the flow's cap.
            let grown =
                (end as usize).saturating_sub(self.streams.get(&key).map_or(0, |st| st.data.len()));
            if held + grown > MAX_H3_FLOW_BYTES {
                continue;
            }
            held += grown;
            let st = self.streams.entry(key).or_default();
            if end as usize > st.data.len() {
                st.data.resize(end as usize, 0);
            }
            st.data[start as usize..end as usize].copy_from_slice(&chunk.data);
            st.mark_received(start, end);
            if chunk.fin {
                st.fin = true;
            }
        }
    }

    /// Bytes buffered and decoded across all streams, for the stream
    /// tracker's memory budget.
    pub fn held_bytes(&self) -> usize {
        self.streams
            .values()
            .map(|st| st.data.len() + st.decoded.as_ref().map_or(0, |d| d.bytes.len()))
            .sum()
    }

    /// Bodies recovered so far — one per (stream, direction) whose contiguous
    /// prefix decodes. Decodes lazily and caches per stream, re-running the
    /// decompressor only when the contiguous prefix has grown, so calling this
    /// every render frame is cheap once a body is decoded.
    pub fn decoded_bodies(&mut self) -> Vec<DecodedBody> {
        let mut held = self.held_bytes();
        let mut out = Vec::new();
        for (&(stream_id, _dir), st) in self.streams.iter_mut() {
            let clen = st.contiguous_len();
            let prev_len = st.decoded.as_ref().map(|d| d.bytes.len());
            // A body decodes only into the room the flow's cap leaves,
            // counting what its previous decode frees.
            let others = held.saturating_sub(prev_len.unwrap_or(0));
            let room = MAX_H3_FLOW_BYTES.saturating_sub(others);
            if clen > st.decoded_len && room > 0 {
                st.decoded_len = clen;
                let limit = MAX_H3_BODY_BYTES.min(room as u64);
                st.decoded = h3_data_payload(&st.data[..clen])
                    .and_then(|p| decompress_body(&p.body, p.brotli, limit))
                    .map(|(encoding, bytes, truncated)| DecodedBody {
                        encoding,
                        stream_id,
                        bytes,
                        truncated,
                    });
                held = others + st.decoded.as_ref().map_or(0, |d| d.bytes.len());
                if let Some(body) = &st.decoded {
                    if Some(body.bytes.len()) != prev_len {
                        // `prefix_bytes` is the contiguous *compressed* prefix; a
                        // value past one packet's worth (~1200 B) means this body
                        // was reassembled across multiple 1-RTT packets.
                        tracing::debug!(
                            target: "netwatch::dpi::http3",
                            stream_id,
                            prefix_bytes = clen,
                            body_bytes = body.bytes.len(),
                            encoding = body.encoding.label(),
                            "reassembled HTTP/3 body"
                        );
                    }
                }
            }
            if let Some(body) = &st.decoded {
                out.push(body.clone());
            }
        }
        out
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::io::Write;

    fn gzip(data: &[u8]) -> Vec<u8> {
        let mut e = flate2::write::GzEncoder::new(Vec::new(), flate2::Compression::default());
        e.write_all(data).unwrap();
        e.finish().unwrap()
    }

    fn zlib(data: &[u8]) -> Vec<u8> {
        let mut e = flate2::write::ZlibEncoder::new(Vec::new(), flate2::Compression::default());
        e.write_all(data).unwrap();
        e.finish().unwrap()
    }

    fn brotli(data: &[u8]) -> Vec<u8> {
        let mut out = Vec::new();
        {
            let mut w = brotli::CompressorWriter::new(&mut out, 4096, 5, 22);
            w.write_all(data).unwrap();
        }
        out
    }

    /// Encode a value as a QUIC varint (minimal width) for test fixtures.
    fn varint(v: u64) -> Vec<u8> {
        if v < 64 {
            vec![v as u8]
        } else if v < 16384 {
            let b = (v as u16) | 0x4000;
            b.to_be_bytes().to_vec()
        } else if v < 1_073_741_824 {
            let b = (v as u32) | 0x8000_0000;
            b.to_be_bytes().to_vec()
        } else {
            let b = v | 0xc000_0000_0000_0000;
            b.to_be_bytes().to_vec()
        }
    }

    /// Build an HTTP/3 DATA frame carrying `body`.
    fn h3_data_frame(body: &[u8]) -> Vec<u8> {
        let mut f = varint(H3_FRAME_DATA);
        f.extend(varint(body.len() as u64));
        f.extend_from_slice(body);
        f
    }

    /// Build a QUIC STREAM frame (OFF + LEN bits set) for `stream_id`.
    fn stream_frame(stream_id: u64, offset: u64, data: &[u8]) -> Vec<u8> {
        // Type 0x0c = STREAM | OFF | LEN (0x08 | 0x04 | 0x02 = 0x0e). Use
        // 0x0e so both offset and length are explicit.
        let mut f = vec![0x0e];
        f.extend(varint(stream_id));
        f.extend(varint(offset));
        f.extend(varint(data.len() as u64));
        f.extend_from_slice(data);
        f
    }

    #[test]
    fn decompress_sniffs_gzip_zlib_brotli() {
        let payload = b"hello world, this is a compressible body ".repeat(8);
        for (mk, want) in [
            (gzip(&payload), BodyEncoding::Gzip),
            (zlib(&payload), BodyEncoding::Deflate),
            (brotli(&payload), BodyEncoding::Brotli),
        ] {
            let (enc, out, truncated) =
                decompress_body(&mk, true, MAX_H3_BODY_BYTES).expect("must decompress");
            assert_eq!(enc, want);
            assert_eq!(out, payload);
            assert!(!truncated);
        }
    }

    #[test]
    fn brotli_is_tried_only_when_the_headers_declare_it() {
        let payload = b"hello world, this is a compressible body ".repeat(8);
        assert_eq!(
            decompress_body(&brotli(&payload), false, MAX_H3_BODY_BYTES),
            None
        );
        // The magic-number codings don't need the header.
        assert!(decompress_body(&gzip(&payload), false, MAX_H3_BODY_BYTES).is_some());
    }

    #[test]
    fn decompression_stops_at_the_cap_and_says_so() {
        let cap = MAX_H3_BODY_BYTES as usize;
        let (_, out, truncated) =
            decompress_body(&gzip(&vec![0; cap + 1]), false, MAX_H3_BODY_BYTES).unwrap();
        assert_eq!(out.len(), cap);
        assert!(truncated);
        let shown = DecodedBody {
            encoding: BodyEncoding::Gzip,
            stream_id: 0,
            bytes: out,
            truncated,
        };
        assert_eq!(shown.size_label(), format!("first {cap} bytes"));
        // Exactly the cap is the whole body, not a truncated one.
        let (_, out, truncated) =
            decompress_body(&gzip(&vec![0; cap]), false, MAX_H3_BODY_BYTES).unwrap();
        assert_eq!(out.len(), cap);
        assert!(!truncated);
    }

    /// A QPACK field section with an empty dynamic table, then `lines`.
    fn fields(lines: &[u8]) -> Vec<u8> {
        let mut f = vec![0x00, 0x00];
        f.extend_from_slice(lines);
        f
    }

    #[test]
    fn content_encoding_br_is_read_from_every_stateless_form() {
        // Static entry 42, `content-encoding: br`.
        assert!(fields_declare_brotli(&fields(&[0xc0 | 42])));
        // Static name 42 with a Huffman-coded `br` value (index 42 spills
        // past the 4-bit prefix: 15 + 27).
        assert!(fields_declare_brotli(&fields(&[
            0x5f, 0x1b, 0x82, 0x8e, 0xcf
        ])));
        // Static name 43 (`content-encoding: gzip`) with a plain `br` value.
        assert!(fields_declare_brotli(&fields(&[
            0x5f, 0x1c, 0x02, b'b', b'r'
        ])));
        // A literal name (length 16 = 7 + 9) and a plain value, after an
        // unrelated static `:status: 200` (index 25).
        let mut literal = vec![0xc0 | 25, 0x27, 0x09];
        literal.extend_from_slice(b"content-encoding");
        literal.extend_from_slice(&[0x02, b'b', b'r']);
        assert!(fields_declare_brotli(&fields(&literal)));
    }

    #[test]
    fn other_codings_and_unreadable_sections_are_not_brotli() {
        // Static entry 43, `content-encoding: gzip`.
        assert!(!fields_declare_brotli(&fields(&[0xc0 | 43])));
        // Static entry 31, `accept-encoding: gzip, deflate, br`.
        assert!(!fields_declare_brotli(&fields(&[0xc0 | 31])));
        // Dynamic-table entry 42: its content is unknown without decoder state.
        assert!(!fields_declare_brotli(&fields(&[0x80 | 42])));
        // Cut off inside an integer, and inside a string.
        assert!(!fields_declare_brotli(&fields(&[0x5f])));
        assert!(!fields_declare_brotli(&fields(&[0x5f, 0x1b, 0x82, 0x8e])));
        assert!(!fields_declare_brotli(&[]));
    }

    #[test]
    fn extract_stream_chunk_no_len_runs_to_end() {
        // STREAM with OFF set, LEN clear (type 0x0c): data runs to end.
        let mut frame = vec![0x0c];
        frame.extend(varint(248)); // stream id
        frame.extend(varint(92775)); // offset
        frame.extend_from_slice(b"tail-data");
        let chunks = extract_stream_chunks(&frame);
        assert_eq!(chunks.len(), 1);
        assert_eq!(chunks[0].stream_id, 248);
        assert_eq!(chunks[0].offset, 92775);
        assert_eq!(chunks[0].data, b"tail-data");
    }

    #[test]
    fn ack_frame_then_stream_is_walked() {
        // ACK (0x02): largest=10, delay=0, range_count=0, first_range=3.
        let mut frames = vec![0x02];
        frames.extend(varint(10));
        frames.extend(varint(0));
        frames.extend(varint(0));
        frames.extend(varint(3));
        // Followed by a STREAM frame we must still find.
        frames.extend(stream_frame(0, 0, b"after-ack"));
        let chunks = extract_stream_chunks(&frames);
        assert_eq!(chunks.len(), 1);
        assert_eq!(chunks[0].data, b"after-ack");
    }

    #[test]
    fn h3_data_skips_headers_frame() {
        // A HEADERS frame (QPACK bytes we can't read) followed by DATA.
        let mut stream = varint(H3_FRAME_HEADERS);
        let fake_qpack = [0xaa, 0xbb, 0xcc];
        stream.extend(varint(fake_qpack.len() as u64));
        stream.extend_from_slice(&fake_qpack);
        stream.extend(h3_data_frame(b"real-body"));
        let payload = h3_data_payload(&stream).expect("must find DATA after HEADERS");
        assert_eq!(payload.body, b"real-body");
        assert!(!payload.brotli);
    }

    /// Build an HTTP/3 HEADERS frame carrying a QPACK field section.
    fn h3_headers_frame(section: &[u8]) -> Vec<u8> {
        let mut f = varint(H3_FRAME_HEADERS);
        f.extend(varint(section.len() as u64));
        f.extend_from_slice(section);
        f
    }

    #[test]
    fn reassembler_decodes_brotli_only_under_a_br_header() {
        let body = b"a brotli response body ".repeat(40);
        let data = h3_data_frame(&brotli(&body));

        let mut declared = h3_headers_frame(&fields(&[0xc0 | 42]));
        declared.extend_from_slice(&data);
        let mut r = H3StreamReassembler::new();
        r.ingest(false, &stream_frame(0, 0, &declared));
        let bodies = r.decoded_bodies();
        assert_eq!(bodies.len(), 1);
        assert_eq!(bodies[0].encoding, BodyEncoding::Brotli);
        assert_eq!(bodies[0].bytes, body);
        assert_eq!(bodies[0].size_label(), format!("{} bytes", body.len()));

        let mut undeclared = h3_headers_frame(&fields(&[0xc0 | 25]));
        undeclared.extend_from_slice(&data);
        let mut r = H3StreamReassembler::new();
        r.ingest(false, &stream_frame(0, 0, &undeclared));
        assert!(r.decoded_bodies().is_empty());
    }

    #[test]
    fn reassembler_decodes_body_split_across_three_packets() {
        let body = b"the quick brown fox jumps over the lazy dog ".repeat(40);
        let h3 = h3_data_frame(&gzip(&body)); // the HTTP/3 stream bytes
        let n = h3.len();
        let (a, b, c) = (&h3[..n / 3], &h3[n / 3..2 * n / 3], &h3[2 * n / 3..]);

        let mut r = H3StreamReassembler::new();
        r.ingest(false, &stream_frame(0, 0, a));
        assert!(
            r.decoded_bodies().is_empty(),
            "a partial gzip stream must not decode yet"
        );
        r.ingest(false, &stream_frame(0, (n / 3) as u64, b));
        r.ingest(false, &stream_frame(0, (2 * n / 3) as u64, c));

        let bodies = r.decoded_bodies();
        assert_eq!(bodies.len(), 1);
        assert_eq!(bodies[0].encoding, BodyEncoding::Gzip);
        assert_eq!(bodies[0].stream_id, 0);
        assert_eq!(bodies[0].bytes, body);
    }

    #[test]
    fn reassembler_handles_out_of_order_fragments() {
        let body = b"compressible payload ".repeat(64);
        let h3 = h3_data_frame(&gzip(&body));
        let mid = h3.len() / 2;

        let mut r = H3StreamReassembler::new();
        // Tail fragment arrives first — no contiguous prefix from 0 yet.
        r.ingest(false, &stream_frame(4, mid as u64, &h3[mid..]));
        assert!(r.decoded_bodies().is_empty(), "no head yet");
        // Head fills the gap; now the whole prefix is contiguous.
        r.ingest(false, &stream_frame(4, 0, &h3[..mid]));

        let bodies = r.decoded_bodies();
        assert_eq!(bodies.len(), 1);
        assert_eq!(bodies[0].stream_id, 4);
        assert_eq!(bodies[0].bytes, body);
    }

    #[test]
    fn reassembler_never_decodes_a_gap() {
        // Only a mid-stream fragment (offset > 0, no head): must not decode.
        let body = b"x".repeat(200);
        let h3 = h3_data_frame(&gzip(&body));
        let mut r = H3StreamReassembler::new();
        r.ingest(false, &stream_frame(8, 4096, &h3));
        assert!(r.decoded_bodies().is_empty());
    }

    #[test]
    fn reassembler_single_packet_parity() {
        // A body that fits one packet is just the single-chunk case.
        let body = b"single packet body ".repeat(8);
        let h3 = h3_data_frame(&gzip(&body));
        let mut r = H3StreamReassembler::new();
        r.ingest(false, &stream_frame(0, 0, &h3));
        let bodies = r.decoded_bodies();
        assert_eq!(bodies.len(), 1);
        assert_eq!(bodies[0].bytes, body);
    }

    #[test]
    fn reassembler_separates_request_and_response_on_same_stream() {
        // A QUIC bidirectional stream (id 0) carries the request (c→s) and the
        // response (s→c) at *independent* offset spaces both starting at 0.
        // Keying by direction must keep them from overwriting each other —
        // without it, the two would corrupt one buffer.
        let req = b"this is the gzipped request body ".repeat(40);
        let resp = b"and this is the gzipped response body ".repeat(40);
        let mut r = H3StreamReassembler::new();
        r.ingest(true, &stream_frame(0, 0, &h3_data_frame(&gzip(&req)))); // request
        r.ingest(false, &stream_frame(0, 0, &h3_data_frame(&gzip(&resp)))); // response

        let bodies = r.decoded_bodies();
        assert_eq!(bodies.len(), 2, "request and response must both survive");
        let got: Vec<&Vec<u8>> = bodies.iter().map(|b| &b.bytes).collect();
        assert!(got.contains(&&req), "request body intact");
        assert!(got.contains(&&resp), "response body intact");
    }

    #[test]
    fn reassembler_ignores_non_request_streams() {
        // Control / QPACK / unidirectional streams (id % 4 != 0) aren't HTTP/3
        // request/response streams and must not be buffered or decoded.
        let h3 = h3_data_frame(&gzip(&b"not a request stream ".repeat(20)));
        let mut r = H3StreamReassembler::new();
        r.ingest(false, &stream_frame(2, 0, &h3)); // client unidirectional
        r.ingest(false, &stream_frame(3, 0, &h3)); // server unidirectional
        assert!(r.decoded_bodies().is_empty());
    }

    #[test]
    fn one_flow_holds_at_most_its_cap() {
        // Buffered data: 40 streams of 2 MiB each would be 80 MiB.
        let chunk = vec![0x21; MAX_H3_STREAM_BYTES];
        let mut r = H3StreamReassembler::new();
        for id in 0..40 {
            r.ingest(false, &stream_frame(id * 4, 0, &chunk));
            assert!(r.held_bytes() <= MAX_H3_FLOW_BYTES);
        }
        assert_eq!(r.held_bytes(), MAX_H3_FLOW_BYTES);

        // Decoded bodies count too: 20 bodies of 4 MiB would be 80 MiB. The
        // one that meets the cap is cut short, and none decodes after it.
        let bomb = h3_data_frame(&gzip(&vec![0; MAX_H3_BODY_BYTES as usize]));
        let mut r = H3StreamReassembler::new();
        for id in 0..20 {
            r.ingest(false, &stream_frame(id * 4, 0, &bomb));
        }
        let bodies = r.decoded_bodies();
        assert_eq!(r.held_bytes(), MAX_H3_FLOW_BYTES);
        assert!(bodies.len() < 20);
        let (last, whole) = bodies.split_last().unwrap();
        assert!(whole.iter().all(|b| !b.truncated));
        assert!(last.truncated);
        assert!((last.bytes.len() as u64) < MAX_H3_BODY_BYTES);
        // Asking again changes nothing.
        assert_eq!(r.decoded_bodies(), bodies);
    }
}
