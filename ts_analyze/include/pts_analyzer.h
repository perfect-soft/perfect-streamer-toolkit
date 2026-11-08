/*
 * Copyright 2026 Perfect Soft
 * SPDX-License-Identifier: Apache-2.0
 */
#pragma once
/*
 * pts_analyzer.h — TR 101 290 PTS interval checks
 *
 * Implements:
 *   2.5   PTS error          — PTS repetition interval > 700 ms
 *   TSTD.under  Empty buffer error — no PES payload data (informational)
 *
 * PTS is extracted from PES headers on elementary stream PIDs.
 * PTS values are 33-bit, 90 kHz clock.
 */

#include "events.h"
#include "ts_common.h"
#include "tr101290_defs.h"

#include <algorithm>
#include <map>
#include <vector>
#include <cstdint>
#include <cmath>

// ─── PTS clock helpers ────────────────────────────────────────────────
static constexpr int64_t PTS_CLOCK_HZ = 90000LL;
static constexpr int64_t PTS_MAX      = (1LL << 33);

inline int64_t pts_delta_ticks(int64_t a, int64_t b) {
    int64_t d = a - b;
    if (d < -(PTS_MAX / 2)) d += PTS_MAX;
    if (d >  (PTS_MAX / 2)) d -= PTS_MAX;
    return d;
}

inline double pts_delta_seconds(int64_t a, int64_t b) {
    return static_cast<double>(pts_delta_ticks(a, b)) / static_cast<double>(PTS_CLOCK_HZ);
}

// ─── Per-ES PTS statistics ────────────────────────────────────────────
struct PtsPidStats {
    uint16_t es_pid       = 0;
    uint8_t  stream_type  = 0;
    bool     is_video     = false;

    int64_t  pts_count            = 0;
    int64_t  pts_interval_errors  = 0;   // 2.5: interval > 700 ms
    double   pts_max_interval_s   = 0;
    double   pts_sum_interval_s   = 0;

    int64_t  last_pts             = -1;  // 90 kHz ticks
    double   last_pts_t           = -1;  // stream time of the last PES with a PTS
    double   first_pes_t          = -1;  // stream time of the first PES
    bool     gap_counted          = false;   // this PTS-less run already raised 2.5

    double pts_avg_interval_s() const {
        return pts_count > 1
            ? pts_sum_interval_s / static_cast<double>(pts_count - 1)
            : 0.0;
    }
};

// ─── PtsAnalyzer ──────────────────────────────────────────────────────
class PtsAnalyzer {
public:
    PtsAnalyzer() = default;

    // Register an ES PID for monitoring (from SI discovery)
    void register_es(uint16_t es_pid, uint8_t stream_type) {
        auto& st       = stats_[es_pid];
        st.es_pid      = es_pid;
        st.stream_type = stream_type;
        st.is_video    = is_video_type(stream_type);
    }

    // Feed a raw 188-byte TS packet with its stream time
    /// 2.5 from two sides: a PTS value step > 700 ms, and PES that keep coming without a PTS for > 700 ms of stream
    /// time (counted once per run, which also suppresses the value step when the PTS returns).
    void process_packet(const uint8_t* pkt, double t) {
        TsHeader h = parse_ts_header(pkt);

        auto it = stats_.find(h.pid);
        if (it == stats_.end()) return;

        // Only PES start: payload_unit_start=1
        if (!h.payload_unit_start) return;
        if (!h.has_payload) return;

        PtsPidStats& st = it->second;

        // Locate TS payload (skip AF, NO pointer_field for PES)
        int offset = 4;
        if (h.has_adaptation_field) {
            uint8_t af_len = pkt[4];
            offset += 1 + af_len;
        }
        if (offset >= TS_PACKET_SIZE) return;

        const uint8_t* payload = pkt + offset;
        int payload_len = TS_PACKET_SIZE - offset;

        // PES start code: 0x00 0x00 0x01
        if (payload_len < 9) return;
        if (payload[0] != 0x00 || payload[1] != 0x00 || payload[2] != 0x01)
            return;

        // PES header: stream_id at byte 3, PES_packet_length at bytes 4-5
        // Optional PES header starts at byte 6 for stream_ids >= 0xBC
        uint8_t stream_id = payload[3];

        // Not all stream_ids have optional PES header with PTS
        // Skip padding stream, program stream map, etc.
        if (stream_id == 0xBC || stream_id == 0xBE || stream_id == 0xBF ||
            stream_id == 0xF0 || stream_id == 0xF1 || stream_id == 0xF2 ||
            stream_id == 0xFF)
            return;

        // Optional PES header: byte 6 = flags, byte 7 = pts_dts_flags + others, byte 8 = header_data_length
        // (payload_len >= 9 already guaranteed above)
        // A PES without a usable PTS: no PTS flag, or a PTS field cut short or with bad marker bits.
        uint8_t pts_dts_flags = (payload[7] >> 6) & 0x03;
        uint8_t header_data_len = payload[8];
        int64_t pts = -1;
        if ((pts_dts_flags & 0x02) && header_data_len >= 5 && payload_len >= 9 + static_cast<int>(header_data_len))
            pts = parse_pts_field(payload + 9);
        if (st.first_pes_t < 0)
            st.first_pes_t = t;
        if (pts < 0) {
            // TR 101 290 allows it up to 700 ms after the last PTS (or the first PES, for a PID that never had one).
            double ref = st.last_pts_t >= 0 ? st.last_pts_t : st.first_pes_t;
            if (!st.gap_counted && t - ref > TR101290_PTS_INTERVAL_MAX_S) {
                st.gap_counted = true;
                st.pts_interval_errors++;
                if (Events::on())
                    Events::get().note("2.5", h.pid, "PES without PTS for over "
                                       + std::to_string((int) (TR101290_PTS_INTERVAL_MAX_S * 1e3)) + " ms",
                                       ref + TR101290_PTS_INTERVAL_MAX_S);
            }
            return;
        }

        st.pts_count++;

        if (st.last_pts >= 0) {
            double interval = pts_delta_seconds(pts, st.last_pts);
            // Only consider positive, reasonable intervals
            if (interval > 0 && interval < 10.0) {
                if (interval > st.pts_max_interval_s)
                    st.pts_max_interval_s = interval;
                st.pts_sum_interval_s += interval;

                // 2.5: PTS interval > 700 ms (not again for a PTS-less run already counted)
                if (interval > TR101290_PTS_INTERVAL_MAX_S && !st.gap_counted) {
                    st.pts_interval_errors++;
                    // Timed when the limit ran out after the last PTS (by stream time; never after this
                    // PES, as a wrong -b hint can make the stream time shorter than the PTS step).
                    if (Events::on())
                        Events::get().note("2.5", h.pid, "PTS interval " + std::to_string((int) (interval * 1e3)) + " ms",
                                           st.last_pts_t >= 0 ? std::min(t, st.last_pts_t + TR101290_PTS_INTERVAL_MAX_S) : -1);
                }
            }
        }

        st.last_pts = pts;
        st.last_pts_t = t;
        st.gap_counted = false;
    }

    const std::map<uint16_t, PtsPidStats>& stats() const { return stats_; }

    // Total 2.5 violations across all ES
    int64_t total_pts_errors() const {
        int64_t n = 0;
        for (auto& [pid, st] : stats_)
            n += st.pts_interval_errors;
        return n;
    }

private:
    std::map<uint16_t, PtsPidStats> stats_;

    static bool is_video_type(uint8_t st) {
        return st == 0x01 || st == 0x02 || st == 0x10
            || st == 0x1B || st == 0x24 || st == 0x25;
    }

    // Parse 5-byte PTS/DTS field (ISO/IEC 13818-1 Table 2-21)
    static int64_t parse_pts_field(const uint8_t* d) {
        // Check marker bits: d[0] bit 0, d[2] bit 0, d[4] bit 0 must be 1
        if (!(d[0] & 0x01) || !(d[2] & 0x01) || !(d[4] & 0x01))
            return -1;

        int64_t pts = (static_cast<int64_t>((d[0] >> 1) & 0x07) << 30)
                    | (static_cast<int64_t>(d[1]) << 22)
                    | (static_cast<int64_t>((d[2] >> 1) & 0x7F) << 15)
                    | (static_cast<int64_t>(d[3]) << 7)
                    | (static_cast<int64_t>((d[4] >> 1) & 0x7F));
        return pts;
    }
};
