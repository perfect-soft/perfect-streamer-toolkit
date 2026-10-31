/*
 * Copyright 2026 Perfect Soft
 * SPDX-License-Identifier: Apache-2.0
 */
#pragma once
/*
 * ts_common.h — MPEG-TS constants, structures, PCR extraction
 *
 * References:
 *   ISO/IEC 13818-1  (MPEG-2 Systems)
 *   ETSI TR 101 290  (Measurement guidelines for DVB systems)
 */

#include <cstdint>
#include <cstring>
#include <string>
#include <sstream>
#include <iomanip>

#include "colors.h"

// ─── TS packet constants ────────────────────────────────────────────
static constexpr int TS_PACKET_SIZE = 188;
static constexpr uint8_t TS_SYNC_BYTE = 0x47;
static constexpr uint16_t TS_PID_PAT = 0x0000;
static constexpr uint16_t TS_PID_NULL = 0x1FFF;

// ─── PCR clock ──────────────────────────────────────────────────────
static constexpr int64_t PCR_CLOCK_HZ = 27000000LL;       // 27 MHz
static constexpr int64_t PCR_BASE_HZ = 90000LL;          // 90 kHz (base)
static constexpr int64_t PCR_EXT_DIVISOR = 300LL;            // base*300+ext
static constexpr int64_t PCR_MAX = (1LL << 33) * 300 + 299; // max 42-bit value

// ─── TR 101 290 limits ──────────────────────────────────────────────
static constexpr double TR101290_PCR_INTERVAL_MAX_S = 0.040;      // 40 ms  (2.3a)
static constexpr double TR101290_PCR_INTERVAL_REC_S = 0.025;      // 25 ms  (recommended)
static constexpr double TR101290_PCR_ACCURACY_NS = 500.0;      // ±500 ns (2.4)
static constexpr double TR101290_PCR_ACCURACY_S = 500.0e-9;

// ─── T-STD transport buffer sizes (ISO 13818-1 Table 2-36) ──────────
static constexpr int TSTD_TB_VIDEO = 512;              // bytes (TBn for video)
static constexpr int TSTD_TB_AUDIO = 512;              // bytes (TBn for audio)
static constexpr int TSTD_TB_OTHER = 512;              // bytes
static constexpr int TSTD_MB_VIDEO = 6000000 / 8;     // ~750 KB (Bmax = 6 Mbit)
static constexpr int TSTD_RXN_LEAK_RATE = 1200000;         // Rxn for video (bps)

// ─── TS packet header ───────────────────────────────────────────────
struct TsHeader
{
    uint16_t pid;
    uint8_t continuity_counter;
    bool payload_unit_start;
    bool has_adaptation_field;
    bool has_payload;
    uint8_t scrambling;
};

inline TsHeader parse_ts_header(const uint8_t *pkt)
{
    TsHeader h
    { };
    h.pid = (uint16_t) (((pkt[1] & 0x1F) << 8) | pkt[2]);
    h.payload_unit_start = (pkt[1] & 0x40) != 0;
    h.scrambling = (pkt[3] >> 6) & 0x03;
    uint8_t afc = (pkt[3] >> 4) & 0x03;
    h.has_adaptation_field = (afc & 0x02) != 0;
    h.has_payload = (afc & 0x01) != 0;
    h.continuity_counter = pkt[3] & 0x0F;
    return h;
}

// ─── PCR value ──────────────────────────────────────────────────────
struct PcrValue
{
    int64_t raw;           // full 42-bit PCR in 27 MHz ticks
    int64_t base;          // 33-bit base (90 kHz)
    int ext;          // 9-bit extension
    bool valid;
    bool discontinuity;

    double to_seconds() const
    {
        return (double) raw / PCR_CLOCK_HZ;
    }

    static int64_t delta(int64_t a, int64_t b)
    {
        int64_t d = a - b;
        if (d < 0)
            d += PCR_MAX + 1;    // handle wraparound
        return d;
    }

    static double delta_seconds(int64_t a, int64_t b)
    {
        return (double) delta(a, b) / PCR_CLOCK_HZ;
    }
};

inline PcrValue extract_pcr(const uint8_t *pkt)
{
    PcrValue pcr
    { };
    pcr.valid = false;

    TsHeader h = parse_ts_header(pkt);
    if (!h.has_adaptation_field)
        return pcr;

    uint8_t af_len = pkt[4];
    if (af_len < 7)
        return pcr;          // need at least 7 bytes for PCR

    uint8_t af_flags = pkt[5];
    pcr.discontinuity = (af_flags & 0x80) != 0;

    if (!(af_flags & 0x10))
        return pcr;  // PCR flag not set

    const uint8_t *p = pkt + 6;
    pcr.base = ((int64_t) p[0] << 25) | ((int64_t) p[1] << 17) | ((int64_t) p[2] << 9) | ((int64_t) p[3] << 1)
            | ((int64_t) (p[4] >> 7) & 0x01);

    pcr.ext = ((int) (p[4] & 0x01) << 8) | (int) p[5];
    pcr.raw = pcr.base * 300 + pcr.ext;
    pcr.valid = true;
    return pcr;
}

// ─── Formatting helpers ─────────────────────────────────────────────
inline std::string format_pid(uint16_t pid)
{
    std::ostringstream os;
    os << "0x" << std::hex << std::setfill('0') << std::setw(4) << pid << " (" << std::dec << pid << ")";
    return os.str();
}

inline std::string format_us(double seconds)
{
    std::ostringstream os;
    os << std::fixed << std::setprecision(3) << (seconds * 1e6) << " µs";
    return os.str();
}

inline std::string format_ms(double seconds)
{
    std::ostringstream os;
    os << std::fixed << std::setprecision(3) << (seconds * 1e3) << " ms";
    return os.str();
}

inline std::string format_ns(double seconds)
{
    std::ostringstream os;
    os << std::fixed << std::setprecision(1) << (seconds * 1e9) << " ns";
    return os.str();
}

inline std::string pass_fail(bool ok)
{
    return ok ? Color::wrap(Color::GREEN, "PASS")
              : Color::wrap(Color::RED,   "FAIL");
}
