/*
 * Copyright 2026 Perfect Soft
 * SPDX-License-Identifier: Apache-2.0
 */
#include "rtp_merge.h"

#include <algorithm>
#include <cstring>

namespace St2022
{

static const int64 Sec = 1000000000LL;
static const uint InitialSlots = 1024;
static const size_t HashSlots = 32768;     // content hashes kept for the start's check: class C at 70 000 datagrams/s

uint RtpMerge::slotsFor(uint64 kbps, int64 waitNs, uint maxSlots)
{
    const uint64 pps = kbps * 1000 / (1316 * 8) + 1;
    const uint64 need = pps * (uint64)(waitNs + Sec) / Sec;
    uint s = InitialSlots;
    while (s < need && s * 2 <= maxSlots)
        s *= 2;
    return s;
}

RtpMerge::RtpMerge(const Params & p, OnData onData, OnReset onReset):
        _p(p), _onData(onData), _onReset(onReset)
{
    _p.legs = std::min(2, std::max(1, _p.legs));
    uint m = InitialSlots;
    while (m * 2 <= _p.maxSlots && m < 32768)
        m *= 2;
    _p.maxSlots = m;
    _slots.resize(InitialSlots);
    _data.resize((size_t)InitialSlots * MaxRegion);
    _mask = InitialSlots - 1;
    _relBits.assign(8192, 0);
    if (_p.legs == 2)
    {
        _hash2.resize(HashSlots);
        _hashHist.resize(HashSlots);
        _oneBits.assign(8192, 0);
        _relMs.assign(65536, 0);
    }
}

void RtpMerge::reset()
{
    restart(Reset::Ssrc);
    for (Leg & l : _leg)
        l = Leg();
    _st = Stat();
    _fec.reset();
    _primary = 0;
}

// The stream starts anew (a new SSRC, a new primary leg): the counters stay, the state goes.
void RtpMerge::restart(Reset reason)
{
    for (Leg & l : _leg)
    {
        const LegStat keep = l.st;
        l = Leg();
        l.st = keep;
    }
    _fec.restart();
    std::fill(_slots.begin(), _slots.end(), Slot());
    _relBits.assign(8192, 0);
    _next = _newest = _startExt = 0;
    _started = false;
    _firstNs = _intervalNs = _lastNewNs = 0;
    _rateStartNs = 0;
    _rateCount = 0;
    _rateKnown = false;
    _gapExt = 0;
    _gapSince = 0;
    // The open windows are dropped, not counted: at a source's SSRC change the later leg's copies are still in flight.
    std::fill(_oneBits.begin(), _oneBits.end(), 0);
    _settle = 0;
    _skewWinNs = 0;
    _sessLen = _sessPayOff = 0;
    _differ = false;
    _verified = false;
    _vCompares = _vMismatches = 0;
    _cleanSecs = 0;
    _bucketNs = 0;
    _bucketCompares = _bucketMismatches = 0;
    _bucketOther = _bucketForeign = 0;
    _ssrcBadSecs = _ssrcCleanSecs = 0;
    _ssrcDiffer = false;
    std::fill(_hash2.begin(), _hash2.end(), std::make_pair((uint64)0, (uint64)0));
    std::fill(_hashHist.begin(), _hashHist.end(), std::make_pair((uint64)0, (uint64)0));
    _primaryLostNs = 0;
    _skew.clear();
    _lastSkewNs = 0;
    if (_onReset && reason == Reset::Primary)
        _onReset(reason);
}

int64 RtpMerge::silentNs() const
{
    return std::max(std::max(_p.legSilentNs, _p.waitNs), 4 * _intervalNs);
}

bool RtpMerge::fecActive(int64 now) const
{
    return _fec.active(now, std::max(2 * Sec, _fec.waitNs(_intervalNs)))
            || (_p.fec && !_fec.seen() && _firstNs && now - _firstNs < 2 * Sec);
}

bool RtpMerge::live(int l, int64 now) const
{
    return _leg[l].seen && now - _leg[l].lastNs <= silentNs();
}

// The oldest datagram the ring must keep: the next to release, less what FEC may still XOR with (a staggered column
// reaches back about two matrices); before the start, the first datagram of the earliest leg.
uint64 RtpMerge::lowNeed() const
{
    if (!_started)
    {
        uint64 lo = _newest;
        for (int l = 0; l < _p.legs; l++)
            if (_leg[l].seen && _leg[l].first < lo)
                lo = _leg[l].first;
        return lo;
    }
    uint64 keep = 0;
    const FecDecoder::Stat & f = _fec.stat();
    if (f.L)
        keep = std::min<uint64>((uint64)f.L * (2 * (f.D ? f.D : 1) + 1) + _p.reorder, _slots.size() / 2);
    return _next > keep ? _next - keep : 0;
}

void RtpMerge::grow()
{
    const size_t n = _slots.size() * 2;
    const uint64 nm = n - 1;
    std::vector<Slot> ns(n);
    std::vector<uchar> nd(n * MaxRegion);
    for (size_t i = 0; i < _slots.size(); i++)
    {
        const Slot & s = _slots[i];
        if (s.state == Empty)
            continue;
        ns[s.ext & nm] = s;
        memcpy(&nd[(s.ext & nm) * MaxRegion], &_data[i * MaxRegion], s.len);
    }
    _slots.swap(ns);
    _data.swap(nd);
    _mask = nm;
}

// Makes the ring hold `ext` with everything from lowNeed(): grows it, and at its limit releases or gives up the oldest.
void RtpMerge::room(uint64 ext, int64 now)
{
    while (_slots.size() < _p.maxSlots && ext >= lowNeed() && ext - lowNeed() >= _slots.size())
        grow();
    if (!_started && ext >= lowNeed() && ext - lowNeed() >= _slots.size())
        start(now);                 // legs farther apart than the ring: start on what we have
    while (_started && ext >= lowNeed() && ext - lowNeed() >= _slots.size())
    {
        Slot & s = slot(_next);
        if (s.ext == _next && s.state == Held)
            release(s, now);
        else
        {
            s = Slot();
            s.ext = _next;
            s.state = Skipped;
            _relBits[(_next >> 3) & 8191] &= (uint8)~(1 << (_next & 7));
            _st.lost++;
            _st.overflow++;
        }
        _next++;
        _gapExt = 0;
    }
}

void RtpMerge::start(int64 now)
{
    // On the earlier leg: the later one's head (datagrams the earlier delivered before we joined) is not waited for.
    // Legs farther apart than half the ring are not two paths of one stream: the primary's.
    uint64 s = 0;
    bool any = false;
    for (int l = 0; l < _p.legs; l++)
        if (_leg[l].seen && (!any || _leg[l].first > s))
        {
            s = _leg[l].first;
            _primary = l;
            any = true;
        }
    if (_p.legs == 2 && _leg[0].seen && _leg[1].seen)
    {
        const uint64 d = _leg[0].first > _leg[1].first ? _leg[0].first - _leg[1].first : _leg[1].first - _leg[0].first;
        if (d >= _p.maxSlots / 2)
        {
            _primary = 0;
            s = _leg[0].first;
        }
    }
    _next = _startExt = _settle = s;
    _started = true;
    _gapExt = 0;
    if (_p.legs == 2)
    {
        // Until the legs are verified only the primary is used: the other's copies held before the start are only
        // compared when the primary's arrive.
        for (uint64 e = s; e <= _newest; e++)
        {
            Slot & h = slot(e);
            if (h.ext == e && h.state == Held && !(h.legs & (1 << _primary)))
            {
                _hash2[e % HashSlots] = std::make_pair(e, contentHash(slotData(e), h.len));
                h = Slot();
            }
        }
    }
    drain(now);
}

void RtpMerge::pushMedia(int l, const uchar* data, uint len, int64 now)
{
    _stop = false;                  // OnData's "stop releasing" holds for one call
    if (l < 0 || l >= _p.legs)
        return;
    RtpHeader h;
    if (!parseRtp(data, len, h) || h.pt != _p.payloadType || h.payloadLen == 0 || len - 12 > MaxRegion)
    {
        _leg[l].st.protoErrors++;
        return;
    }
    bucket(now);
    Leg & lg = _leg[l];
    lg.st.received++;
    lg.lastNs = now;
    if (!lg.ssrcKnown)
    {
        lg.ssrcKnown = true;
        lg.st.ssrc = h.ssrc;
    }
    else if (lg.st.ssrc != h.ssrc)
    {
        lg.st.ssrc = h.ssrc;
        lg.st.ssrcChanges++;
        // The stream behind the primary leg (or the only one alive) changed: start anew on it.
        if (_p.legs == 1 || l == _primary || !live(1 - l, now))
        {
            restart(Reset::Ssrc);
            if (_onReset)
                _onReset(Reset::Ssrc);
            _leg[l].ssrcKnown = true;
            _leg[l].lastNs = now;
        }
    }
    const int o = 1 - l;
    if (_p.legs == 2 && l != _primary)
        _bucketOther++;
    if (_p.legs == 2 && l != _primary && _leg[o].ssrcKnown && _leg[o].st.ssrc != h.ssrc && live(o, now))
    {
        lg.st.ignored++;            // 2022-7 copies carry identical headers: another SSRC is another stream
        _bucketForeign++;
        return;
    }
    if (!_firstNs)
    {
        _firstNs = now;
        _newest = (1ULL << 32) + h.seq;
    }
    const uint64 e = unwrap16(h.seq, _newest);
    if (!lg.seen)
    {
        lg.seen = true;
        lg.first = lg.highest = e;
    }
    else if (e > lg.highest)
    {
        if (e > lg.highest + _p.reorder)
        {
            lg.jumpLo = lg.highest;     // skipped ahead: what it jumped over may still be in flight on it
            lg.jumpNs = now;
        }
        lg.st.lost += e - lg.highest - 1;
        lg.highest = e;
    }
    else if (lg.st.lost)
        lg.st.lost--;               // a fill of this leg's own earlier gap
    if (!_started && (_p.legs == 1 || (_leg[0].seen && _leg[1].seen)))
        start(now);
    if (_started && e < _startExt)
        return;                     // the later leg's head, before the start

    const uchar* reg = data + 12;
    const uint rlen = len - 12;
    if (_started && single() && l != _primary)
    {
        // Not verified yet, or the legs differ: the other leg's copy is only compared, never used. (Before the start
        // both legs are kept: the primary is chosen then, the other's held copies go - see start.)
        lg.st.ignored++;
        const Slot & s = slot(e);
        if (s.ext == e && (s.state == Held || s.state == Released))
            compare(slotData(e), s.len, reg, rlen);
        else if (_hashHist[e % HashSlots].first == e)
        {
            noteCompare(_hashHist[e % HashSlots].second != contentHash(reg, rlen));
            _hashHist[e % HashSlots].first = 0;
        }
        else
            _hash2[e % HashSlots] = std::make_pair(e, contentHash(reg, rlen));
        return;
    }
    if (_started && e < _next)
    {
        // A copy of what went out already (a duplicate, compared while the ring still holds it) or of what was given up
        // (late): the 64K-number bitmap knows, the ring keeps only what may still be released or XORed.
        const Slot & s = slot(e);
        if (s.ext == e && s.state == Released)
        {
            lg.st.dup++;
            compare(slotData(e), s.len, reg, rlen);
            skewSample(s, l, now);
            clearOne(e);                    // this leg had it too: not repaired
        }
        else if (_next - e < 32768 && (_relBits[(e >> 3) & 8191] >> (e & 7) & 1))
        {
            lg.st.dup++;
            clearOne(e);
        }
        else
            lg.st.late++;
        return;
    }
    room(e, now);
    if (_started && e < _next)
    {
        lg.st.late++;               // given up just now to make room
        return;
    }
    Slot & s = slot(e);
    if (s.ext == e && s.state == Held)
    {
        lg.st.dup++;
        compare(slotData(e), s.len, reg, rlen);
        skewSample(s, l, now);
        s.legs |= (uint8)(1 << l);
        return;
    }
    s = Slot();
    s.ext = e;
    s.state = Held;
    s.arrival = now;
    s.legs = (uint8)(1 << l);
    s.ts = h.ts;
    s.len = (uint16)rlen;
    s.payOff = (uint16)(h.payloadOff - 12);
    s.payLen = (uint16)h.payloadLen;
    memcpy(slotData(e), reg, rlen);
    if (single())
    {
        const uint64 hsh = contentHash(reg, rlen);
        if (_hash2[e % HashSlots].first == e)
        {
            noteCompare(_hash2[e % HashSlots].second != hsh);
            _hash2[e % HashSlots].first = 0;
        }
        else
            _hashHist[e % HashSlots] = std::make_pair(e, hsh);
    }
    if (!_sessLen)
    {
        _sessLen = rlen;
        _sessPayOff = s.payOff;
    }
    if (e > _newest)
    {
        // The stream's datagram interval: the mean over about a second (until the first second: the mean so far). An
        // EWMA of single gaps followed a sender's bursts - one PCR's datagrams back to back, as GStreamer and ffmpeg
        // send - and right after a burst it read a fraction of the mean, which shrank FEC's wait below the matrix
        // (with GStreamer's 1D FEC, 40 % of what column FEC could rebuild was given up).
        if (!_rateStartNs)
            _rateStartNs = now;
        else
        {
            _rateCount++;
            const int64 span = now - _rateStartNs;
            if (!_rateKnown && span > 0)
                _intervalNs = span / (int64)_rateCount;
            if (span >= Sec)
            {
                if (span <= 2 * Sec)        // not across a pause of the sender
                {
                    _intervalNs = span / (int64)_rateCount;
                    _rateKnown = true;
                }
                _rateStartNs = now;
                _rateCount = 0;
            }
        }
        _lastNewNs = now;
        _newest = e;
    }
    _fec.touch();
    if (_started)
        drain(now);
}

void RtpMerge::pushFec(int l, const uchar* data, uint len, int64 now)
{
    _stop = false;
    if (l < 0 || l >= _p.legs || !_started)
        return;                     // placed next to the media: none yet
    if (single() && l != _primary)
        return;
    if (_fec.push(data, len, _newest, now))
        drain(now);
}

void RtpMerge::poll(int64 now)
{
    _stop = false;
    bucket(now);
    if (!_started)
    {
        if (_firstNs && now - _firstNs >= _p.settleNs)
            start(now);
        return;
    }
    // One leg used (not verified, or the legs differ): when it is gone for a second, the other one becomes the stream.
    if (single())
    {
        const int o = 1 - _primary;
        if (live(_primary, now) || !live(o, now))
            _primaryLostNs = 0;
        else if (!_primaryLostNs)
            _primaryLostNs = now;
        else if (now - _primaryLostNs >= Sec)
        {
            _primary = o;
            restart(Reset::Primary);
            return;
        }
    }
    drain(now);
}

bool RtpMerge::waiting() const
{
    return _started ? _newest >= _next : _firstNs != 0;
}

void RtpMerge::drain(int64 now)
{
    // Not after OnData said stop in this call - also when room() released.
    while (!_stop)
    {
        Slot & s = slot(_next);
        if (s.ext == _next && s.state == Held)
        {
            _gapExt = 0;
            _next++;
            release(s, now);
            continue;
        }
        if (_newest <= _next)
            break;                  // nothing beyond it yet: no gap known
        if (_fec.recover(*this, lowNeed()))
            continue;
        if (_gapExt != _next)
        {
            _gapExt = _next;
            _gapSince = now;
        }
        if (!gapDone(_next, now))
            break;
        s = Slot();
        s.ext = _next;
        s.state = Skipped;
        _relBits[(_next >> 3) & 8191] &= (uint8)~(1 << (_next & 7));
        _st.lost++;
        _next++;
        _gapExt = _next;            // a burst: the next missing one shares this gap's start
    }
    if (_fec.stat().L && (_next & 63) == 0)
        _fec.prune(lowNeed());
    settle(now);
}

/// The early skip: a gap is given up as soon as nothing can fill it any more - every live leg delivered `reorder`
/// datagrams past it and FEC cannot arrive in time - and a live leg that is behind is waited for at most waitNs.
bool RtpMerge::gapDone(uint64 g, int64 now)
{
    const int64 el = now - _gapSince;
    bool legPending = false;
    for (int l = 0; l < _p.legs; l++)
    {
        if (single() && l != _primary)
            continue;
        // Passed the gap: delivered `reorder` datagrams beyond it - unless it jumped over the gap lately: a path whose
        // latency dropped delivers its new datagrams before the old ones still in flight on it.
        const Leg & lg = _leg[l];
        const bool passed = lg.highest >= g + _p.reorder && !(g > lg.jumpLo && lg.jumpNs && now - lg.jumpNs < _p.waitNs);
        if (live(l, now) && !passed)
            legPending = true;
    }
    if (legPending && el < _p.waitNs)
        return false;
    if (fecActive(now) && el < _fec.waitNs(_intervalNs))
        return false;
    return true;
}

bool RtpMerge::release(Slot & s, int64 now)
{
    s.state = Released;             // before the callback: it may reset the merge
    if (_p.legs == 2)
    {
        // From one leg while both are used (not rebuilt by FEC: legs 0): `repaired` unless the other's copy comes.
        const uint64 e = s.ext;
        if (!single() && (s.legs == 1 || s.legs == 2))
            _oneBits[(e >> 3) & 8191] |= (uint8)(1 << (e & 7));
        else
            _oneBits[(e >> 3) & 8191] &= (uint8)~(1 << (e & 7));
        _relMs[e & 0xFFFF] = (uint16)(now / 1000000);
    }
    _relBits[(s.ext >> 3) & 8191] |= (uint8)(1 << (s.ext & 7));
    _st.released++;
    // The caller said stop in this call (it closed): what is still released is not handed over any more.
    if (_stop)
        return false;
    if (!_onData(slotData(s.ext) + s.payOff, s.payLen, s.ts, s.legs ? s.arrival : 0))
        _stop = true;
    return !_stop;
}

void RtpMerge::clearOne(uint64 ext)
{
    if (_p.legs == 2)
        _oneBits[(ext >> 3) & 8191] &= (uint8)~(1 << (ext & 7));
}

/// `repaired`: a datagram released from one leg while both were used, counted once no copy of the other came within its
/// window - the wait, or the measured path differential if longer, + 200 ms (5 s at most) - by sequence number, so a
/// reused slot, a give-up or a restart cannot bend it. Monotonic (derived from the legs' loss counts it would go down
/// when a leg's late datagrams fill its own gaps).
void RtpMerge::settle(int64 now)
{
    if (_p.legs != 2)
    {
        _settle = _next;
        return;
    }
    const int64 win = std::min<int64>(std::max(_p.waitNs, _skewWinNs) + 200000000LL, 5 * Sec);
    const uint16 nowMs = (uint16)(now / 1000000);
    while (_settle < _next)
    {
        const uint64 e = _settle;
        uint8 & byte = _oneBits[(e >> 3) & 8191];
        const uint8 bit = (uint8)(1 << (e & 7));
        if (byte & bit)
        {
            // Within its window it waits - unless the sequence space is half way round (the marks would alias).
            if ((int64)(uint16)(nowMs - _relMs[e & 0xFFFF]) * 1000000LL < win && _next - e < 32768)
                break;
            _st.repaired++;
            byte &= (uint8)~bit;
        }
        _settle++;
    }
}

void RtpMerge::compare(const uchar* a, uint alen, const uchar* b, uint blen)
{
    noteCompare(alen != blen || memcmp(a, b, alen) != 0);
}

void RtpMerge::noteCompare(bool mismatch)
{
    _st.compares++;
    _bucketCompares++;
    if (mismatch)
    {
        _st.mismatches++;
        _bucketMismatches++;
    }
    if (_p.legs != 2 || _verified || _differ)
        return;
    // The start's check: 20 copies equal - one stream on two paths, merge them; most of them differ - not one stream.
    _vCompares++;
    _vMismatches += mismatch ? 1 : 0;
    if (_vCompares < 20)
        return;
    if (_vMismatches == 0)
        _verified = true;
    else if (_vMismatches * 2 > _vCompares)
        _differ = true;
    _vCompares = _vMismatches = 0;
}

// Path differential: arrival(leg 1) - arrival(leg 0) of one datagram, one sample per 50 ms, 10 s kept.
void RtpMerge::skewSample(const Slot & s, int l, int64 now)
{
    const int o = 1 - l;
    if (!(s.legs & (1 << o)) || now - _lastSkewNs < 50000000LL)
        return;
    _lastSkewNs = now;
    const int64 d = now - s.arrival;
    if (_skew.size() >= 256)
        _skew.erase(_skew.begin());
    _skew.push_back(SkewSample{ now, l == 1 ? d : -d });
    _skewWinNs = std::max(_skewWinNs, d);      // the repaired window grows at once; bucket() shrinks it
}

/// Content guard, per second: copies of one datagram from the two legs are compared byte for byte; most of 20 or
/// more differing = the legs carry different streams (two encoders, a wrong group): only the primary is used then,
/// until 5 clean seconds. 2022-7 requires identical RTP header and payload in every copy (ST 2022-7:2019 6).
void RtpMerge::bucket(int64 now)
{
    if (_bucketNs && now - _bucketNs < Sec)
        return;
    if (_bucketNs)
    {
        if (_bucketCompares >= 20 && _bucketMismatches * 2 > _bucketCompares)
        {
            _differ = true;
            _cleanSecs = 0;
        }
        else if (_differ && _bucketCompares >= 20 && _bucketMismatches == 0 && ++_cleanSecs >= 5)
        {
            _differ = false;
            _verified = true;
        }
        // Another SSRC on the other leg (a path fed by another sender): only the primary is used meanwhile; a source's
        // own SSRC change reaches the later leg within the skew, never for 3 s.
        if (_bucketForeign >= 20 && _bucketForeign * 2 > _bucketOther)
        {
            _ssrcCleanSecs = 0;
            if (++_ssrcBadSecs >= 3)
                _ssrcDiffer = true;
        }
        else
        {
            _ssrcBadSecs = 0;
            if (_ssrcDiffer && _bucketForeign == 0 && ++_ssrcCleanSecs >= 5)
                _ssrcDiffer = false;
        }
        _skewWinNs = 0;
        for (const SkewSample & k : _skew)
            if (now - k.at <= 10 * Sec)
                _skewWinNs = std::max(_skewWinNs, k.d < 0 ? -k.d : k.d);
    }
    _bucketNs = now;
    _bucketCompares = _bucketMismatches = 0;
    _bucketOther = _bucketForeign = 0;
}

int64 RtpMerge::effectiveWaitNs(int64 now) const
{
    int64 w = 0;
    if (_p.legs == 2 && live(0, now) && live(1, now))
    {
        int64 mx = 0;
        for (const SkewSample & k : _skew)
            if (now - k.at <= 10 * Sec)
                mx = std::max(mx, k.d < 0 ? -k.d : k.d);
        w = mx + silentNs();
    }
    else
        w = (int64)(_p.reorder + 1) * _intervalNs;
    w = std::min(w, _p.waitNs);
    if (fecActive(now))
        w = std::max(w, _fec.waitNs(_intervalNs));
    return w;
}

RtpMerge::Stat RtpMerge::stat(int64 now) const
{
    Stat st = _st;
    for (int l = 0; l < 2; l++)
    {
        st.leg[l] = _leg[l].st;
        // An RTP datagram of the stream's payload type in the last second, used or not: a path carrying another SSRC
        // receives, it is not down. Not RTP or another payload type still counts as nothing received (protoErrors).
        st.leg[l].up = _leg[l].lastNs && now - _leg[l].lastNs <= Sec;
    }
    st.legsDiffer = _differ || _ssrcDiffer;
    st.verified = _verified;
    st.primary = _primary;
    st.slots = (uint)_slots.size();
    st.fec = _fec.stat();
    st.waitNs = effectiveWaitNs(now);
    std::vector<int64> d;
    for (const SkewSample & k : _skew)
        if (now - k.at <= 10 * Sec)
        {
            d.push_back(k.d);
            st.skewMaxNs = std::max(st.skewMaxNs, k.d < 0 ? -k.d : k.d);
        }
    st.skewSamples = (int)d.size();
    if (!d.empty())
    {
        std::sort(d.begin(), d.end());
        st.skewP50Ns = d[d.size() / 2];
    }
    return st;
}

// --- IMediaRing (FEC) -----------------------------------------------------------------------------------------------

const uchar* RtpMerge::region(uint64 ext, uint & len, uint32 & ts) const
{
    const Slot & s = slot(ext);
    if (s.ext != ext || (s.state != Held && s.state != Released))
        return nullptr;
    len = s.len;
    ts = s.ts;
    return slotData(ext);
}

bool RtpMerge::wanted(uint64 ext) const
{
    if (!_started || ext < _next || ext < lowNeed() || ext - lowNeed() >= _slots.size())
        return false;
    const Slot & s = slot(ext);
    return !(s.ext == ext && s.state == Held);
}

/// A datagram rebuilt by FEC. Its length is the XOR of the group's lengths (2022-1 length recovery); a sender that
/// does not XOR that field (some copy the first datagram's) gives a wrong one - then the stream's constant length is
/// used (2022-2 6.3: TS packets per datagram constant for the session). For MPEG-TS every 188-byte packet must start
/// with the sync byte, or the rebuild is refused: a wrong FEC packet never becomes data.
bool RtpMerge::recovered(uint64 ext, const uchar* reg, uint fecLen, uint len, uint32 ts, bool row)
{
    if (!wanted(ext) || !_sessLen)
        return false;
    const bool ts188 = _p.payloadType == 33;
    auto valid = [&] (uint l)
    {
        return l > _sessPayOff && l <= fecLen && (!ts188 || (l - _sessPayOff) % TsPacket == 0);
    };
    uint l = len;
    if (!valid(l))
    {
        if (!valid(_sessLen))
            return false;
        l = _sessLen;
        _st.lenFixups++;
    }
    if (ts188 && _p.tsSync)
        for (uint i = _sessPayOff; i < l; i += TsPacket)
            if (reg[i] != 0x47)
                return false;
    Slot & s = slot(ext);
    s = Slot();
    s.ext = ext;
    s.state = Held;
    s.arrival = _lastNewNs;
    s.legs = 0;
    s.ts = ts;
    s.len = (uint16)l;
    s.payOff = (uint16)_sessPayOff;
    s.payLen = (uint16)(l - _sessPayOff);
    memcpy(slotData(ext), reg, l);
    if (ext > _newest)
        _newest = ext;
    (void)row;
    return true;
}

} // namespace St2022
