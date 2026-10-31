/*
 * Copyright 2026 Perfect Soft
 * SPDX-License-Identifier: Apache-2.0
 */
#pragma once
/*
 * tr101290_defs.h — Central definitions for ETSI TR 101 290 V1.4.1
 *
 * All three priority levels:
 *   Priority 1: TS decodability checks
 *   Priority 2: Recommended monitoring
 *   Priority 3: Extended monitoring
 */

#include <cstdint>
#include <string>

// ─── Well-known SI PIDs (ISO/IEC 13818-1 Table 2-3) ──────────────────
static constexpr uint16_t TS_PID_CAT   = 0x0001;
static constexpr uint16_t TS_PID_TSDT  = 0x0002;
static constexpr uint16_t TS_PID_NIT   = 0x0010;
static constexpr uint16_t TS_PID_SDT   = 0x0011;  // also BAT
static constexpr uint16_t TS_PID_EIT   = 0x0012;
static constexpr uint16_t TS_PID_RST   = 0x0013;
static constexpr uint16_t TS_PID_TDT   = 0x0014;  // also TOT

// ─── TR 101 290 interval limits ──────────────────────────────────────
// Priority 1
static constexpr double TR101290_PAT_INTERVAL_MAX_S   = 0.500;   // 500 ms
static constexpr double TR101290_PMT_INTERVAL_MAX_S   = 0.500;   // 500 ms
static constexpr double TR101290_PID_ABSENCE_MAX_S    = 5.0;     // 5 s

// ISO/IEC 13818-1 §2.4.2.2 — hard upper bound on PCR repetition.
// TR 101 290 1.4 default of 40 ms is a stricter recommendation; an
// occasional encoder slot-skip can put a single interval between 40 ms
// and this hard limit without breaking decoder clock recovery, so we
// reserve the OVERALL fail for genuine ISO violations.
static constexpr double ISO13818_PCR_HARD_MAX_S       = 0.100;   // 100 ms
// Priority 2
static constexpr double TR101290_PCR_DISCONT_MAX_S    = 0.100;   // 100 ms
static constexpr double TR101290_PTS_INTERVAL_MAX_S   = 0.700;   // 700 ms
static constexpr double TR101290_CAT_INTERVAL_MAX_S   = 0.500;   // 500 ms
// Priority 3
static constexpr double TR101290_NIT_INTERVAL_MAX_S   = 10.0;    // 10 s
static constexpr double TR101290_SDT_INTERVAL_MAX_S   = 2.0;     // 2 s
static constexpr double TR101290_EIT_PF_MAX_S         = 2.0;     // 2 s  (EN 300 468 Annex C)
static constexpr double TR101290_EIT_OTHER_PF_MAX_S   = 20.0;    // 20 s (EN 300 468 Annex C)
static constexpr double TR101290_EIT_SCH_MAX_S        = 10.0;    // 10 s per sub-table (EN 300 468 Annex C)
static constexpr double TR101290_TDT_INTERVAL_MAX_S   = 30.0;    // 30 s

// ─── Minimum analysis duration thresholds ─────────────────────────
static constexpr double ANALYSIS_MIN_DURATION_S    = 2.0;    // hard minimum
static constexpr double ANALYSIS_P3_DURATION_S     = 10.0;   // P3 interval checks reliable
static constexpr double ANALYSIS_FULL_DURATION_S   = 30.0;   // all checks including TDT

// PCR drift confidence thresholds.
//   < ANALYSIS_FULL_DURATION_S       skip (measurement noise dominates)
//   < DRIFT_HARD_FAIL_DURATION_S     measured but flagged as WARN — single
//                                    short-window outlier shouldn't gate
//                                    OVERALL on a marginal source
//   >= DRIFT_HARD_FAIL_DURATION_S    measured and FAIL gates OVERALL
// 300 s PCR-drift assessment window (product default; TR 101 290
// fixes no measurement interval).
static constexpr double DRIFT_HARD_FAIL_DURATION_S = 300.0;

// ─── Maximum section sizes (ISO/IEC 13818-1, ETSI EN 300 468) ─────
// PSI tables (ISO 13818-1): max 1024 bytes
static constexpr int PSI_SECTION_MAX_BYTES     = 1024;   // PAT, CAT, PMT
// DVB SI tables (EN 300 468): max 1024 bytes (except EIT)
static constexpr int DVB_SI_SECTION_MAX_BYTES  = 1024;   // NIT, SDT, BAT, RST
// EIT: standard allows up to 4096 bytes (EN 300 468 §5.2.4)
static constexpr int EIT_SECTION_MAX_BYTES     = 4096;
// EIT: practical STB compatibility limit
static constexpr int EIT_SECTION_STB_COMPAT_BYTES = 1024;

// ─── SI table_id values (ISO/IEC 13818-1 Table 2-31, ETSI EN 300 468) ─
static constexpr uint8_t TID_PAT             = 0x00;
static constexpr uint8_t TID_CAT             = 0x01;
static constexpr uint8_t TID_PMT             = 0x02;
static constexpr uint8_t TID_NIT_ACTUAL      = 0x40;
static constexpr uint8_t TID_NIT_OTHER       = 0x41;
static constexpr uint8_t TID_SDT_ACTUAL      = 0x42;
static constexpr uint8_t TID_SDT_OTHER       = 0x46;
static constexpr uint8_t TID_BAT             = 0x4A;
static constexpr uint8_t TID_EIT_ACTUAL_PF   = 0x4E;
static constexpr uint8_t TID_EIT_OTHER_PF    = 0x4F;
static constexpr uint8_t TID_EIT_ACTUAL_SCH_MIN = 0x50;
static constexpr uint8_t TID_EIT_ACTUAL_SCH_MAX = 0x5F;
static constexpr uint8_t TID_EIT_OTHER_SCH_MIN  = 0x60;
static constexpr uint8_t TID_EIT_OTHER_SCH_MAX  = 0x6F;
static constexpr uint8_t TID_TDT             = 0x70;
static constexpr uint8_t TID_RST             = 0x71;
static constexpr uint8_t TID_TOT             = 0x73;

// ─── CRC-32/MPEG (polynomial 0x04C11DB7) ─────────────────────────────
// Used by all DVB PSI/SI sections (except TDT which has no CRC).
inline uint32_t crc32_mpeg(const uint8_t* data, size_t len) {
    uint32_t crc = 0xFFFFFFFF;
    for (size_t i = 0; i < len; i++) {
        crc ^= static_cast<uint32_t>(data[i]) << 24;
        for (int j = 0; j < 8; j++) {
            if (crc & 0x80000000U)
                crc = (crc << 1) ^ 0x04C11DB7U;
            else
                crc <<= 1;
        }
    }
    return crc;
}

// Returns true if CRC-32 appended to a PSI section is valid.
// section_len = total bytes including the 4-byte CRC trailer.
inline bool check_psi_crc(const uint8_t* section, size_t section_len) {
    if (section_len < 4) return false;
    return crc32_mpeg(section, section_len) == 0;
}

// ─── PSI section header parsing ───────────────────────────────────────
// Returns section_length from bytes 1-2 (12-bit field).
// Total section size = 3 + section_length.
inline int psi_section_length(const uint8_t* section) {
    return ((section[1] & 0x0F) << 8) | section[2];
}

// Returns version_number from byte 5 of a long-form section (5-bit field).
inline uint8_t psi_section_version(const uint8_t* section) {
    return (section[5] >> 1) & 0x1F;
}

// Returns table_id_extension from bytes 3-4 of a long-form section.
// For PAT this is transport_stream_id, for PMT this is program_number.
inline uint16_t psi_table_id_extension(const uint8_t* section) {
    return (static_cast<uint16_t>(section[3]) << 8) | section[4];
}

// True for ES stream types that deliver continuous A/V data, suitable for:
//   - 1.6 PID absence check (must appear within 5 s)
//   - T-STD buffer model (constant-drain assumption holds)
// Excluded:
//   0x05         private sections / KLV / event triggers
//   0x0B/0x0C/0x0D  DSM-CC streams (data carousel, bursty)
//   0x86         SCTE-35 splice info (event-only, may be silent for hours)
inline bool is_continuous_av_stream_type(uint8_t st) {
    switch (st) {
    case 0x01: case 0x02:                       // MPEG-2 Video
    case 0x03: case 0x04:                       // MPEG-1/2 Audio
    case 0x06:                                  // PES private (DVB subtitles, AC-3 in DVB)
    case 0x0F: case 0x11:                       // AAC, MPEG-4 AAC LATM
    case 0x10:                                  // MPEG-4 Visual
    case 0x1B:                                  // H.264/AVC
    case 0x24:                                  // H.265/HEVC
    case 0x25:                                  // H.266/VVC
        return true;
    default:
        return false;
    }
}
