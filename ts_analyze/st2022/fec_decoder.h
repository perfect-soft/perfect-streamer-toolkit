/*
 * Copyright 2026 Perfect Soft
 * SPDX-License-Identifier: Apache-2.0
 */
#pragma once
/*
 * fec_decoder.h — SMPTE ST 2022-1 FEC (Pro-MPEG COP3) receive side and the
 * RTP helpers the ST 2022-7 merge shares with it. Pure: no clock, no thread,
 * no socket; one thread drives it (the merge that owns it).
 */

#include "st2022_types.h"

#include <map>
#include <vector>

namespace St2022
{

// The bytes after the fixed 12-byte RTP header (CSRC list, extension, payload, padding): what 2022-1 FEC protects.
static const uint MaxRegion = 1500 - 12;
static const uint TsPacket = 188;

/// The RTP header fields the receiver uses; offsets are from the start of the datagram.
struct RtpHeader
{
    uint8 pt = 0;
    bool marker = false;
    uint16 seq = 0;
    uint32 ts = 0;
    uint32 ssrc = 0;
    uint payloadOff = 0;        // 12 + CSRC list + extension
    uint payloadLen = 0;        // without padding
};

/// Parses an RTP v2 header (CSRC list, extension, padding); false when the datagram is not RTP or is truncated.
bool parseRtp(const uchar* data, uint len, RtpHeader & h);

/// The 16-bit sequence number s extended to 64 bits next to ref (an extended number already seen): the nearest one.
/// Extended numbers start at 2^32, so ref - 32768 never wraps below zero.
inline uint64 unwrap16(uint16 s, uint64 ref)
{
    return ref + (int64)(int16)(uint16)(s - (uint16)ref);
}

/// FNV-1a 64: the content identity of a datagram's protected bytes (the merge compares the legs' copies by it).
uint64 contentHash(const uchar* data, uint len);

/// What FEC recovery reads from and writes into the merge's ring of datagrams.
class IMediaRing
{
public:
    virtual ~IMediaRing() {}
    // The protected bytes of datagram `ext` while the ring holds them (held or released); null when it never arrived,
    // was given up, or the ring no longer holds it.
    virtual const uchar* region(uint64 ext, uint & len, uint32 & ts) const = 0;
    // Still worth recovering: not released or given up yet, and inside the ring.
    virtual bool wanted(uint64 ext) const = 0;
    // A rebuilt datagram: `region` is fecLen bytes; `len` is the length the FEC header says (it may be wrong: some
    // senders do not XOR it). The ring checks the content and stores it; false = refused (not counted as recovered).
    virtual bool recovered(uint64 ext, const uchar* region, uint fecLen, uint len, uint32 ts, bool row) = 0;
};

/// ST 2022-1 FEC decoder: keeps the column and row FEC packets of the window and rebuilds a missing datagram from any
/// FEC packet that misses exactly that one, repeatedly (2D: a column rebuild can complete a row and the other way).
/// Placement follows each FEC packet's own SNBase, offset and NA (2022-1 8.5): no fixed matrix grid, so 1D (column
/// only), 2D, row only, block-aligned and staggered senders all work, with any constant datagram size. FEC packets of
/// both legs of a 2022-7 pair are one set: a copy (same type and SNBase) is dropped.
class FecDecoder
{
public:
    struct Stat
    {
        uint64 received[2] = { 0, 0 };     // [0] column (first stream, port+2), [1] row (second stream, port+4)
        uint64 dup = 0;                     // a copy of an FEC packet already held (the other leg's)
        uint64 badHeader = 0;               // not RTP, E = 0, type not XOR, NA or offset 0, too short
        uint64 ssrcNonZero = 0;             // 2022-1 8.3 wants SSRC 0; used anyway
        uint64 recovered[2] = { 0, 0 };     // datagrams rebuilt by column / row FEC
        uint64 refused = 0;                 // rebuilt bytes the ring refused (no TS sync: a wrong FEC packet)
        uint L = 0, D = 0;                  // the matrix seen: L from the row NA or the column offset, D the column NA
    };

    /// An FEC datagram (RTP header + 16-byte FEC header + XOR payload); its SNBase is placed next to ref (the merge's
    /// newest extended sequence number). False when malformed (counted).
    bool push(const uchar* data, uint len, uint64 ref, int64 now);
    /// Rebuilds what it can; groups wholly below `low` (released and no longer needed) are skipped. True when something
    /// was rebuilt. Cheap when nothing arrived since the last pass.
    bool recover(IMediaRing & ring, uint64 low);
    /// Something arrived that may complete an FEC group (a media datagram or an FEC packet).
    void touch() { _dirty = true; }
    /// FEC packets arrive: one seen within `windowNs` (2 s, or longer for slow streams whose matrix outlasts it).
    bool active(int64 now, int64 windowNs = 2000000000LL) const { return _lastNs && now - _lastNs <= windowNs; }
    bool seen() const { return _lastNs != 0; }
    /// How long a gap waits for FEC: until the column FEC of a matrix can have arrived - 2022-1 8.5 sends it at most
    /// L x D datagrams after the last one it protects, plus a matrix of shift for staggered senders - at `intervalNs`
    /// per datagram, plus 20 ms; within 20 ms..MaxWaitNs. Before the matrix is known: 20 x 5 (the largest 2022-2
    /// allows). MaxWaitNs is long: an analyzer has no latency to protect, and a 10 x 10 matrix of a 1 Mbit/s stream
    /// lasts over a second, so its column FEC comes more than 2 s after the gap.
    static const int64 MaxWaitNs = 10000000000LL;
    int64 waitNs(int64 intervalNs) const;
    /// Drops the FEC packets whose datagrams all lie below `low`.
    void prune(uint64 low);
    void reset();
    /// A new stream under the merge (its restart): the FEC packets and the matrix seen go, the counters stay - as the
    /// merge's own.
    void restart();
    const Stat & stat() const { return _stat; }

private:
    struct Entry
    {
        bool row = false;
        bool done = false;
        uint64 base = 0;        // SNBase, extended
        uint offset = 0, na = 0;
        uint16 lenRecovery = 0;
        uint32 tsRecovery = 0;
        std::vector<uchar> data;
    };
    static const size_t MaxEntries = 4096;
    std::map<uint64, Entry> _entries;       // key: base * 2 + row
    Stat _stat;
    int64 _lastNs = 0;
    bool _dirty = false;
};

} // namespace St2022
