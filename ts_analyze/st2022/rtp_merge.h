/*
 * Copyright 2026 Perfect Soft
 * SPDX-License-Identifier: Apache-2.0
 */
#pragma once
/*
 * rtp_merge.h — SMPTE ST 2022-7:2019 seamless reconstruction of an RTP
 * stream received over one or two paths ("legs"), with ST 2022-1 FEC applied
 * to what both legs lost. Pure: the caller gives the time (monotonic ns) with
 * every call and drives poll() while waiting(); one thread.
 */

#include "fec_decoder.h"

#include <functional>

namespace St2022
{

/// Merge of the legs by RTP sequence number into one in-order stream:
/// - the first copy of a datagram wins, a later copy is a duplicate (compared by content: legs that differ are never
///   interleaved - only the primary leg is used then);
/// - datagrams are released in sequence order as soon as they are contiguous: no added latency while nothing is lost,
///   the output follows the earlier leg;
/// - a gap waits for the later leg, for FEC, or for reordering, and is given up at once when nothing can fill it any
///   more: every live leg has delivered `reorder` datagrams past it and FEC cannot arrive in time (the early skip);
///   a leg alive but behind is waited for at most `waitNs` (path-skew-ms: 450 ms = class C for streams below
///   270 Mbit/s, ST 2022-7:2019 Table 1), FEC for FecDecoder::waitNs;
/// - one leg works the same way: then `waitNs` is the reorder wait.
/// The ring holds the window from the oldest datagram FEC may still need to the newest; it grows with the bit rate up
/// to `maxSlots` and releases early when even that is too short. A copy older than the ring is classified (duplicate
/// or late) by a bitmap of the last 64K sequence numbers.
class RtpMerge: private IMediaRing
{
public:
    struct Params
    {
        int legs = 1;                       // 1 or 2
        int64 waitNs = 450000000LL;         // the longest a gap waits for a live leg that is behind
        uint reorder = 10;                  // a leg passed a gap when it delivered this many past it (2022-1 8.6)
        // A leg silent longer than this, waitNs and 4 datagram intervals is down: not waited for. Not shorter than
        // waitNs: a path whose latency jumps (within the class) is silent that long and must still be waited for.
        int64 legSilentNs = 100000000LL;
        int64 settleNs = 200000000LL;       // two legs: the start waits this long to see both (it starts on the earlier)
        bool fec = false;                   // FEC streams are expected: gaps wait for FEC from the start (2 s at most
                                            // while none has come)
        uint8 payloadType = 33;             // MPEG-TS (2022-2); then every rebuilt datagram must carry TS sync bytes
        bool tsSync = true;                 // ... unless false: an encrypted payload has none
        uint maxSlots = 32768;              // power of two, at most half the 16-bit sequence space
    };

    enum class Reset { Ssrc, Primary };

    // A released payload (no RTP header), its RTP timestamp and the arrival time of the copy used (0: rebuilt by FEC).
    // Return false to stop releasing in this call (the caller closed); the merge must stay alive for the whole call.
    typedef std::function<bool(const uchar* data, uint len, uint32 ts, int64 arrival)> OnData;
    // The stream changed under the merge (a new SSRC on the primary leg, or the primary leg replaced): it restarted.
    typedef std::function<void(Reset reason)> OnReset;

    struct LegStat
    {
        bool up = false;            // a datagram in the last second
        uint64 received = 0;
        uint64 lost = 0;            // missing in this leg's own sequence (later fills taken back)
        uint64 dup = 0;             // the other leg's copy came first
        uint64 late = 0;            // came after its datagram was given up
        uint64 protoErrors = 0;     // not RTP, or another payload type
        uint64 ssrcChanges = 0;
        uint64 ignored = 0;         // not used: the legs differ, or another SSRC than the primary leg
        uint32 ssrc = 0;
    };
    struct Stat
    {
        LegStat leg[2];
        uint64 released = 0;
        uint64 lost = 0;            // given up: neither leg nor FEC had it
        uint64 repaired = 0;        // released from one leg only while both were used, and no copy of the other came
                                    // within the window (the wait or the measured path differential, + 200 ms)
        uint64 overflow = 0;        // given up early: the window outgrew the ring
        uint64 compares = 0, mismatches = 0;    // second copies compared by content
        uint64 lenFixups = 0;       // a rebuilt datagram's length taken from the stream (the FEC length field was not XOR)
        bool legsDiffer = false;    // their copies differ, or the other leg carries another SSRC
        bool verified = false;      // two legs: their copies compared equal, both are used
        int primary = 0;
        int skewSamples = 0;
        int64 skewP50Ns = 0;        // arrival(leg 1) - arrival(leg 0) of one datagram, last 10 s
        int64 skewMaxNs = 0;        // the largest |difference|, last 10 s
        int64 waitNs = 0;           // what a gap waits now (effectiveWaitNs)
        uint slots = 0;
        FecDecoder::Stat fec;
    };

    RtpMerge(const Params & p, OnData onData, OnReset onReset = nullptr);

    /// A media datagram (whole RTP packet) from leg 0 or 1.
    void pushMedia(int leg, const uchar* data, uint len, int64 now);
    /// An FEC datagram (whole RTP packet), column or row by its header, from either leg.
    void pushFec(int leg, const uchar* data, uint len, int64 now);
    /// Releases and gives up what waited long enough; call it while waiting(), every 10 ms or more often.
    void poll(int64 now);
    /// Something is held behind a gap (or the start waits for the second leg).
    bool waiting() const;
    /// The longest a gap waits now: the measured path differential when both legs live (+ the silence margin), or
    /// FEC's wait, whichever is longer; at most Params::waitNs plus FEC's.
    int64 effectiveWaitNs(int64 now) const;
    Stat stat(int64 now) const;
    int legs() const { return _p.legs; }
    void reset();

    /// Ring size for a stream of `kbps` (1316-byte datagrams) and a wait: the window of waitNs + 1 s of FEC, at least
    /// 1024, a power of two up to Params::maxSlots.
    static uint slotsFor(uint64 kbps, int64 waitNs, uint maxSlots = 32768);

private:
    enum SlotState : uint8 { Empty, Held, Released, Skipped };
    struct Slot
    {
        uint64 ext = 0;
        int64 arrival = 0;
        uint32 ts = 0;
        uint16 len = 0;             // protected bytes (after the fixed 12-byte header)
        uint16 payOff = 0;          // payload within them
        uint16 payLen = 0;
        uint8 state = Empty;
        uint8 legs = 0;             // bit per leg that delivered it; 0 = rebuilt by FEC
    };
    struct Leg
    {
        bool seen = false;
        bool ssrcKnown = false;
        uint64 first = 0, highest = 0;
        uint64 jumpLo = 0;          // its highest before it last skipped ahead by more than `reorder`, and when
        int64 jumpNs = 0;
        int64 lastNs = 0;
        LegStat st;
    };

    Params _p;
    OnData _onData;
    OnReset _onReset;
    Leg _leg[2];
    FecDecoder _fec;

    std::vector<Slot> _slots;
    std::vector<uchar> _data;       // _slots.size() x MaxRegion
    std::vector<uint8> _relBits;    // released (1) or given up (0) per sequence number mod 65536: copies older than the ring
    uint64 _mask = 0;
    uint64 _next = 0;               // the next datagram to release
    uint64 _newest = 0;
    uint64 _startExt = 0;           // copies below the start are dropped silently (the later leg's head)
    bool _started = false;
    int64 _firstNs = 0;
    int64 _intervalNs = 0;          // between new datagrams: the mean over ~1 s (the mean so far until then)
    int64 _rateStartNs = 0;         // the second being measured: its start and the new datagrams since
    uint64 _rateCount = 0;
    bool _rateKnown = false;
    int64 _lastNewNs = 0;
    uint64 _gapExt = 0;             // the gap being waited for, and since when (a burst shares its start)
    int64 _gapSince = 0;
    // `repaired`, by sequence number (not by slot: a slot may be reused before the later leg's copy comes):
    // a datagram released from one leg while both were used is marked, with its release time (ms, 16 bits); any later
    // copy clears the mark; settle() counts the marks whose window closed.
    std::vector<uint8> _oneBits;    // per sequence number mod 65536 (two legs only)
    std::vector<uint16> _relMs;
    uint64 _settle = 0;             // the next released datagram settle() looks at
    int64 _skewWinNs = 0;           // the largest |path differential| of the last 10 s (grows at once, shrinks each s)
    bool _stop = false;

    // The stream's constant shape (2022-2 6.3: TS packets per datagram kept for the session): rebuilt datagrams use it.
    uint _sessLen = 0, _sessPayOff = 0;

    // Content guard: second copies compared per second; two legs whose copies differ are not one stream. Until 20
    // copies compared equal (verified) only the primary leg - the one the merge started on - is used.
    int _primary = 0;
    bool _differ = false;
    bool _verified = false;
    uint _vCompares = 0, _vMismatches = 0;
    int _cleanSecs = 0;
    int64 _bucketNs = 0;
    uint64 _bucketCompares = 0, _bucketMismatches = 0;
    // The other leg's datagrams this second, and those of another SSRC than the primary's (a path fed by another sender
    // must not be dropped unseen): most of them for 3 s = the legs differ; none for 5 s = they no longer do.
    uint64 _bucketOther = 0, _bucketForeign = 0;
    int _ssrcBadSecs = 0, _ssrcCleanSecs = 0;
    bool _ssrcDiffer = false;
    std::vector<std::pair<uint64, uint64>> _hash2;      // (ext, hash) of the other leg's copies while one leg is used
    std::vector<std::pair<uint64, uint64>> _hashHist;   // (ext, hash) of the primary's, for copies the ring no longer holds
    int64 _primaryLostNs = 0;

    struct SkewSample { int64 at, d; };
    std::vector<SkewSample> _skew;
    int64 _lastSkewNs = 0;

    Stat _st;

    Slot & slot(uint64 ext) { return _slots[ext & _mask]; }
    const Slot & slot(uint64 ext) const { return _slots[ext & _mask]; }
    uchar* slotData(uint64 ext) { return &_data[(ext & _mask) * MaxRegion]; }
    const uchar* slotData(uint64 ext) const { return &_data[(ext & _mask) * MaxRegion]; }
    uint64 lowNeed() const;
    bool live(int l, int64 now) const;
    int64 silentNs() const;
    bool single() const { return _p.legs == 2 && (_differ || _ssrcDiffer || !_verified); }
    bool fecActive(int64 now) const;
    void noteCompare(bool mismatch);
    void start(int64 now);
    void room(uint64 ext, int64 now);
    void grow();
    void drain(int64 now);
    bool gapDone(uint64 g, int64 now);
    bool release(Slot & s, int64 now);
    void clearOne(uint64 ext);
    void settle(int64 now);
    void compare(const uchar* a, uint alen, const uchar* b, uint blen);
    void skewSample(const Slot & s, int l, int64 now);
    void bucket(int64 now);
    void restart(Reset reason);

    // IMediaRing
    const uchar* region(uint64 ext, uint & len, uint32 & ts) const override;
    bool wanted(uint64 ext) const override;
    bool recovered(uint64 ext, const uchar* region, uint fecLen, uint len, uint32 ts, bool row) override;
};

} // namespace St2022
