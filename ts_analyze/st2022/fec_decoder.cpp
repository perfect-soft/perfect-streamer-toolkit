/*
 * Copyright 2026 Perfect Soft
 * SPDX-License-Identifier: Apache-2.0
 */
#include "fec_decoder.h"

#include <algorithm>
#include <cstring>

namespace St2022
{

bool parseRtp(const uchar* data, uint len, RtpHeader & h)
{
    if (len < 12 || (data[0] >> 6) != 2)
        return false;
    uint off = 12 + 4 * (data[0] & 0x0f);
    if (len < off)
        return false;
    if (data[0] & 0x10)
    {
        if (len < off + 4)
            return false;
        off += 4 + 4 * ((uint)data[off + 2] << 8 | data[off + 3]);
        if (len < off)
            return false;
    }
    uint pad = 0;
    if (data[0] & 0x20)
    {
        pad = data[len - 1];
        if (pad == 0 || off + pad > len)
            return false;
    }
    h.marker = data[1] & 0x80;
    h.pt = data[1] & 0x7f;
    h.seq = (uint16)((uint)data[2] << 8 | data[3]);
    h.ts = (uint32)data[4] << 24 | (uint32)data[5] << 16 | (uint32)data[6] << 8 | data[7];
    h.ssrc = (uint32)data[8] << 24 | (uint32)data[9] << 16 | (uint32)data[10] << 8 | data[11];
    h.payloadOff = off;
    h.payloadLen = len - off - pad;
    return true;
}

uint64 contentHash(const uchar* data, uint len)
{
    uint64 h = 14695981039346656037ULL;
    for (uint i = 0; i < len; i++)
    {
        h ^= data[i];
        h *= 1099511628211ULL;
    }
    return h;
}

bool FecDecoder::push(const uchar* data, uint len, uint64 ref, int64 now)
{
    RtpHeader h;
    if (!parseRtp(data, len, h) || h.payloadLen < 16 + 1 || h.payloadLen - 16 > MaxRegion)
    {
        _stat.badHeader++;
        return false;
    }
    const uchar* f = data + h.payloadOff;
    const bool e = f[4] & 0x80;
    const bool row = f[12] & 0x40;
    const uint type = (f[12] >> 3) & 0x07;
    const uint offset = f[13], na = f[14];
    // E = 1 (the extended 2022-1 header), XOR, a non-empty group; mask and index are not used by 2022-1 (8.4).
    if (!e || type != 0 || offset == 0 || na == 0)
    {
        _stat.badHeader++;
        return false;
    }
    if (h.ssrc)
        _stat.ssrcNonZero++;
    _stat.received[row ? 1 : 0]++;
    if (row)
        _stat.L = na;
    else
    {
        _stat.L = offset;
        _stat.D = na;
    }
    _lastNs = now;
    const uint64 base = unwrap16((uint16)((uint)f[0] << 8 | f[1]), ref);
    const uint64 key = base * 2 + (row ? 1 : 0);
    if (_entries.count(key))
    {
        _stat.dup++;
        return true;
    }
    if (_entries.size() >= MaxEntries)
        _entries.erase(_entries.begin());
    Entry & en = _entries[key];
    en.row = row;
    en.base = base;
    en.offset = offset;
    en.na = na;
    en.lenRecovery = (uint16)((uint)f[2] << 8 | f[3]);
    en.tsRecovery = (uint32)f[8] << 24 | (uint32)f[9] << 16 | (uint32)f[10] << 8 | f[11];
    en.data.assign(f + 16, f + 16 + (h.payloadLen - 16));
    _dirty = true;
    return true;
}

bool FecDecoder::recover(IMediaRing & ring, uint64 low)
{
    if (!_dirty)
        return false;
    _dirty = false;
    bool any = false, progress = true;
    uchar buf[MaxRegion];
    // A rebuild can complete another group (2D: a column rebuild leaves one missing in a row): repeat while it helps.
    for (int round = 0; progress && round < 16; round++)
    {
        progress = false;
        for (auto & kv : _entries)
        {
            Entry & e = kv.second;
            if (e.done || e.base + (uint64)(e.na - 1) * e.offset < low)
                continue;
            uint missing = 0;
            uint64 miss = 0;
            bool dead = false;
            for (uint k = 0; k < e.na && missing < 2; k++)
            {
                const uint64 m = e.base + (uint64)k * e.offset;
                uint l;
                uint32 t;
                if (ring.region(m, l, t))
                    continue;
                if (!ring.wanted(m))
                {
                    dead = true;            // given up or gone: this FEC packet can no longer rebuild anything
                    break;
                }
                missing++;
                miss = m;
            }
            if (dead || missing == 0)
            {
                e.done = true;
                continue;
            }
            if (missing > 1)
                continue;
            const uint fecLen = (uint)e.data.size();
            memset(buf, 0, sizeof(buf));
            memcpy(buf, e.data.data(), fecLen);
            uint lenX = e.lenRecovery;
            uint32 tsX = e.tsRecovery;
            bool bad = false;
            for (uint k = 0; k < e.na; k++)
            {
                const uint64 m = e.base + (uint64)k * e.offset;
                if (m == miss)
                    continue;
                uint l;
                uint32 t;
                const uchar* r = ring.region(m, l, t);
                if (!r || l > fecLen)
                {
                    bad = true;             // the FEC payload covers the longest datagram of its group
                    break;
                }
                for (uint i = 0; i < l; i++)
                    buf[i] ^= r[i];
                lenX ^= l;
                tsX ^= t;
            }
            e.done = true;
            if (!bad && ring.recovered(miss, buf, fecLen, lenX & 0xffff, tsX, e.row))
            {
                _stat.recovered[e.row ? 1 : 0]++;
                any = progress = true;
            }
            else
                _stat.refused++;
        }
    }
    return any;
}

int64 FecDecoder::waitNs(int64 intervalNs) const
{
    const int64 L = _stat.L ? _stat.L : 20;
    const int64 D = _stat.L ? _stat.D : 5;
    const int64 n = D ? 2 * L * D + L : 2 * L;
    // The interval clamped first: n * an interval of days would overflow; past 1 s the wait is at its limit anyway.
    intervalNs = std::min<int64>(std::max<int64>(intervalNs, 0), 1000000000LL);
    int64 w = n * intervalNs + 20000000LL;
    if (w < 20000000LL)
        w = 20000000LL;
    if (w > MaxWaitNs)
        w = MaxWaitNs;
    return w;
}

void FecDecoder::prune(uint64 low)
{
    for (auto it = _entries.begin(); it != _entries.end(); )
    {
        const Entry & e = it->second;
        if (e.base + (uint64)(e.na - 1) * e.offset < low)
            it = _entries.erase(it);
        else
            ++it;
    }
}

void FecDecoder::reset()
{
    restart();
    _stat = Stat();
}

/// A new stream under the merge: the FEC packets and the matrix go, the counters stay (an SSRC change must not zero
/// the FEC counters while the merge's own stay).
void FecDecoder::restart()
{
    _entries.clear();
    _stat.L = _stat.D = 0;
    _lastNs = 0;
    _dirty = false;
}

} // namespace St2022
