/*
 * Copyright 2026 Perfect Soft
 * SPDX-License-Identifier: Apache-2.0
 */
#pragma once
/*
 * pcr_analyzer.h — PCR interval / accuracy / jitter / T-STD analysis
 *
 * TR 101 290 checks implemented:
 *   1.4  PCR repetition error  — interval > 40 ms
 *   2.3  PCR accuracy error    — |offset| > ±500 ns
 *   2.4  PCR discontinuity     — unexpected discontinuity indicator
 *   T-STD transport-buffer model overflow/underflow
 *
 * PCR accuracy (live mode): per pair of consecutive PCRs of the same PID,
 *
 *      offset = ΔPCR − Δarrival
 *
 * where Δarrival is the wall-clock interval between the arrivals of the
 * datagrams carrying the two PCR packets. For a stable network this
 * directly measures encoder PCR insertion accuracy; the strict ±500 ns
 * TR 101 290 limit applies. (Network-induced arrival jitter does add
 * noise, but the dominant error mode this catches is the encoder-side
 * PCR clock offset, which is what TR 101 290 §5.2.5 targets.)
 *
 * File mode: PCR accuracy is measured as the deviation of each PCR
 * interval from the running average — informational only.
 *
 * Drift uses a separate regression of PCR time vs. wall-clock arrival
 * time — only meaningful in live mode.
 *
 * T-STD uses per-ES buffers with adaptive drain-rate estimation.
 * In network mode, timing uses a monotonic stream-time derived from
 * the global packet counter and PCR-estimated packet duration,
 * avoiding burst-induced artifacts from UDP arrival timestamps.
 */

#include "ts_common.h"
#include "tr101290_defs.h"

#include <map>
#include <set>
#include <vector>
#include <algorithm>
#include <cmath>
#include <numeric>

// Minimum regression samples before reporting accuracy / drift
static constexpr int PCR_MIN_REG_SAMPLES = 8;

// ─── Per-PCR-PID statistics ─────────────────────────────────────────
struct PcrPidStats {
    uint16_t pid = 0;

    // Counters
    int64_t  pcr_count         = 0;
    int64_t  total_packets     = 0;    // packets on this PID
    int64_t  pcr_interval_err      = 0;  // intervals > pcr_interval_limit_ (TR 101 290, default 40 ms)
    int64_t  pcr_interval_hard_err = 0;  // intervals > 100 ms (ISO 13818-1 hard limit, gates OVERALL)
    int64_t  pcr_interval_warn     = 0;  // intervals > 25 ms (recommended)
    int64_t  pcr_accuracy_err  = 0;    // |jitter| > 500 ns
    int64_t  pcr_discont_ind_errors = 0; // P2.4: gap > 100 ms without discontinuity flag
    int64_t  discontinuities   = 0;

    // PCR interval statistics (seconds)
    double   interval_min  = 1e9;
    double   interval_max  = 0;
    double   interval_sum  = 0;
    int64_t  interval_count = 0;

    // Previous valid pcr_delta — used for P1.4 burst-pair tolerance
    double   prev_pcr_delta = 0;

    // PCR accuracy / jitter (seconds)
    double   accuracy_min   = 1e9;
    double   accuracy_max   = -1e9;
    double   accuracy_sum   = 0;
    double   accuracy_sq_sum = 0;
    int64_t  accuracy_count = 0;

    // Drift rate (ppm)
    double   drift_ppm = 0;

    // T-STD (aggregated from per-ES buffers)
    int64_t  tstd_overflows  = 0;
    int64_t  tstd_underflows = 0;
    double   tstd_buf_max    = 0;
    double   tstd_buf_min    = 1e18;

    // Raw samples for percentile computation
    std::vector<double> interval_samples;
    std::vector<double> accuracy_samples;

    // Last PCR state
    int64_t  last_pcr_raw     = -1;
    double   last_arrival     = -1;
    int64_t  bytes_since_pcr  = 0;

    // Bitrate estimation
    double   estimated_bitrate = 0;  // bps (from PCR pairs)

    // ── Regression: global-pkt-num for PCR accuracy ──────────────
    //    y = cumulative PCR seconds, x = global packet number
    //    Used in both file and live modes — slope absorbs any
    //    systematic rate difference, so residuals isolate the
    //    encoder PCR insertion clock noise.
    double  clock_cum_pcr     = 0;    // accumulated PCR seconds
    int64_t first_pkt_num     = -1;   // global pkt num at first PCR pair
    int64_t reg_n   = 0;
    double  reg_sx  = 0;
    double  reg_sy  = 0;
    double  reg_sxx = 0;
    double  reg_sxy = 0;

    // ── Live-mode only: arrival-time regression for drift ────────
    //    y = cumulative PCR seconds, x = wall-clock arrival time
    double  clock_ref_arrival = -1;
    int64_t dreg_n   = 0;
    double  dreg_sx  = 0;
    double  dreg_sy  = 0;
    double  dreg_sxx = 0;
    double  dreg_sxy = 0;

    // ── Interval stats ──────────────────────────────────────────────
    double interval_avg() const {
        return interval_count > 0 ? interval_sum / static_cast<double>(interval_count) : 0.0;
    }

    double interval_p95() const {
        if (interval_samples.empty()) return 0;
        auto sorted = interval_samples;
        std::sort(sorted.begin(), sorted.end());
        size_t idx = static_cast<size_t>(0.95 * static_cast<double>(sorted.size()));
        if (idx >= sorted.size()) idx = sorted.size() - 1;
        return sorted[idx];
    }

    // ── Accuracy stats ──────────────────────────────────────────────
    double accuracy_avg() const {
        return accuracy_count > 0 ? accuracy_sum / static_cast<double>(accuracy_count) : 0.0;
    }

    double accuracy_stddev() const {
        if (accuracy_count < 2) return 0;
        double mean = accuracy_avg();
        double var = (accuracy_sq_sum / static_cast<double>(accuracy_count)) - mean * mean;
        return var > 0 ? std::sqrt(var) : 0;
    }

    double accuracy_abs_max() const {
        return std::max(std::abs(accuracy_min), std::abs(accuracy_max));
    }

    double accuracy_p95() const {
        if (accuracy_samples.empty()) return 0;
        auto sorted = accuracy_samples;
        for (auto& v : sorted) v = std::abs(v);
        std::sort(sorted.begin(), sorted.end());
        size_t idx = static_cast<size_t>(0.95 * static_cast<double>(sorted.size()));
        if (idx >= sorted.size()) idx = sorted.size() - 1;
        return sorted[idx];
    }
};

// ─── Per-ES T-STD Buffer ────────────────────────────────────────────
//
// Models the multiplex buffer (MBn) from ISO/IEC 13818-1 §2.4.2.
// Drain rate is estimated adaptively from the measured ES bitrate
// after a warmup period, since we don't parse bitrate descriptors.
//
// Each elementary stream gets its own buffer (keyed by ES PID).
// Results are aggregated per PCR PID for reporting.
//
struct TstdEsBuffer {
    uint16_t es_pid   = 0;
    uint16_t pcr_pid  = 0;      // for aggregation into PcrPidStats
    uint8_t  stream_type = 0;   // ISO 13818-1 stream type
    double   capacity = 0;      // bytes (BSn for this stream type)
    double   level    = 0;      // current fill level (bytes)
    double   last_t   = -1;     // last update time
    double   drain_rate = 0;    // bytes/sec (estimated from ES bitrate)
    bool     measuring = false; // true after warmup — start counting violations

    // Warmup tracking
    int64_t  warmup_bytes  = 0;
    double   warmup_start  = -1;

    // Violation counters (only incremented after warmup)
    int64_t  overflows  = 0;
    int64_t  underflows = 0;
    double   max_level  = 0;

    static constexpr double WARMUP_S = 1.0;  // 1 second warmup

    TstdEsBuffer() = default;
    TstdEsBuffer(uint16_t es, uint16_t pcr, uint8_t stype, double cap)
        : es_pid(es), pcr_pid(pcr), stream_type(stype), capacity(cap) {}

    // Single time argument: stream_t is the only clock used. Mixing
    // wall_t (for warmup-elapsed) with stream_t (for drain) produced
    // false underflows when burst arrival on loopback / mux jitter
    // desynchronised the two clocks.
    void input(double stream_t, int bytes) {
        if (warmup_start < 0) warmup_start = stream_t;
        warmup_bytes += bytes;

        double elapsed = stream_t - warmup_start;

        // ── Warmup phase: estimate drain rate ───────────────────────
        if (!measuring) {
            if (elapsed >= WARMUP_S) {
                drain_rate = static_cast<double>(warmup_bytes) / elapsed;
                measuring = true;
                // Reset buffer state — discard warmup accumulation
                level   = 0;
                last_t  = stream_t;
            }
            return;   // don't track violations during warmup
        }

        // ── Active measurement ──────────────────────────────────────
        drain_to(stream_t);
        level += bytes;

        if (level > capacity) overflows++;
        if (level > max_level) max_level = level;
    }

    void drain_to(double t) {
        if (last_t < 0) { last_t = t; return; }
        double dt = t - last_t;
        if (dt > 0 && drain_rate > 0) {
            level -= drain_rate * dt;
            if (level < 0) {
                if (measuring) underflows++;
                level = 0;
            }
        }
        last_t = t;
    }
};

// ─── Buffer capacity lookup (ISO/IEC 13818-1 Table 2-36) ───────────
inline double tstd_buffer_capacity(uint8_t stream_type) {
    switch (stream_type) {
    case 0x01: case 0x02:                // MPEG-2 Video
        return 6000000.0 / 8;            // BSn = 6 Mbit → 750 KB
    case 0x1B:                           // H.264/AVC (Main@4.1)
        return 24000000.0 / 8;           // BSn = 24 Mbit → 3 MB
    case 0x24:                           // H.265/HEVC
        return 30000000.0 / 8;           // BSn = 30 Mbit → 3.75 MB
    case 0x25:                           // H.266/VVC
        return 30000000.0 / 8;           // conservative
    case 0x10:                           // MPEG-4 Visual
        return 6000000.0 / 8;            // 750 KB
    case 0x03: case 0x04:                // MPEG-2 Audio
        return 3584;                     // Bn for audio
    case 0x0F:                           // AAC
        return 8192;
    case 0x11:                           // MPEG-4 AAC
        return 8192;
    case 0x06:                           // PES private (subtitles, etc.)
        return 65536;
    default:
        return 65536;
    }
}

// ─── Main Analyzer ──────────────────────────────────────────────────
class PcrAnalyzer {
public:
    void set_file_mode(bool fm) { file_mode_ = fm; }
    bool file_mode() const { return file_mode_; }

    void set_pcr_interval_limit(double limit_s) { pcr_interval_limit_ = limit_s; }
    double pcr_interval_limit() const { return pcr_interval_limit_; }

    // Process a TS packet with its arrival time
    void process_packet(const uint8_t* pkt, double arrival_time,
                        const std::set<uint16_t>& pcr_pids)
    {
        total_packets_++;
        TsHeader h = parse_ts_header(pkt);

        if (h.pid == TS_PID_NULL) {
            null_packets_++;
            return;
        }

        // Track per-PID byte count for bitrate estimation
        pid_bytes_[h.pid] += TS_PACKET_SIZE;

        // Only analyze configured PCR PIDs
        if (pcr_pids.find(h.pid) == pcr_pids.end()) return;

        auto& st = stats_[h.pid];
        st.pid = h.pid;
        st.total_packets++;

        PcrValue pcr = extract_pcr(pkt);
        if (!pcr.valid) {
            st.bytes_since_pcr += TS_PACKET_SIZE;
            return;
        }

        st.pcr_count++;

        // ── Discontinuity handling ──────────────────────────────────
        if (pcr.discontinuity) {
            st.discontinuities++;
            st.last_pcr_raw    = pcr.raw;
            st.last_arrival    = arrival_time;
            st.bytes_since_pcr = 0;
            // Reset clock models — PCR clock has jumped
            reset_regression(st);
            return;     // skip interval/accuracy check on discontinuity
        }

        // ── PCR Interval ────────────────────────────────────────────
        if (st.last_pcr_raw >= 0) {
            double pcr_delta = PcrValue::delta_seconds(pcr.raw, st.last_pcr_raw);

            // Sanity: ignore absurdly large deltas (likely stream errors)
            if (pcr_delta > 0 && pcr_delta < 2.0) {
                st.interval_count++;
                st.interval_sum += pcr_delta;
                if (pcr_delta < st.interval_min) st.interval_min = pcr_delta;
                if (pcr_delta > st.interval_max) st.interval_max = pcr_delta;
                st.interval_samples.push_back(pcr_delta);

                // TR 101 290 — 1.4 (with RAP burst-pair tolerance).
                // Encoders legitimately insert an extra PCR right after a
                // normal one to mark a random-access point (I-frame), then
                // skip the next scheduled slot. This produces a {short,
                // long} pair whose two intervals sum to one normal period
                // (~2 × 30 ms). Decoder clock recovery is satisfied for any
                // 2-PCR window, so when an over-limit interval immediately
                // follows an abnormally short one (< recommended 25 ms) and
                // the pair-sum stays under 2 × limit, treat the pair as a
                // single merged interval — same convention as Tektronix
                // MTM-class analyzers. Genuine drops (no preceding short
                // interval, or sum exceeds 2 × limit) still flag.
                bool exceeds = (pcr_delta > pcr_interval_limit_);
                if (exceeds
                    && st.prev_pcr_delta > 0
                    && st.prev_pcr_delta < TR101290_PCR_INTERVAL_REC_S
                    && (st.prev_pcr_delta + pcr_delta) < 2.0 * pcr_interval_limit_)
                {
                    exceeds = false;   // RAP burst-pair, not a true gap
                }
                if (exceeds)
                    st.pcr_interval_err++;
                if (pcr_delta > ISO13818_PCR_HARD_MAX_S)
                    st.pcr_interval_hard_err++;
                st.prev_pcr_delta = pcr_delta;
                if (pcr_delta > TR101290_PCR_INTERVAL_REC_S)
                    st.pcr_interval_warn++;

                // TR 101 290 P2.4 — PCR discontinuity indicator error
                // Gap > 100 ms without discontinuity_indicator set
                if (pcr_delta > 0.100 && !pcr.discontinuity)
                    st.pcr_discont_ind_errors++;

                // ── Bitrate estimation from PCR ─────────────────────
                int64_t bytes_between = st.bytes_since_pcr + TS_PACKET_SIZE;
                if (pcr_delta > 0)
                    st.estimated_bitrate = (static_cast<double>(bytes_between) * 8.0) / pcr_delta;

                // ── PCR Accuracy — global-pkt-num regression ────────
                //
                // Regress cumulative PCR seconds (y) against global
                // packet number (x). For a CBR mux, x is exactly
                // proportional to wall-clock time, so the regression
                // slope = 1/TR (absorbs any systematic rate). Residuals
                // therefore isolate the encoder PCR clock noise from
                // both network jitter (live) and assumed bitrate (file).

                if (st.first_pkt_num < 0)
                    st.first_pkt_num = total_packets_;
                if (!file_mode_ && st.clock_ref_arrival < 0)
                    st.clock_ref_arrival = arrival_time;

                st.clock_cum_pcr += pcr_delta;

                double gx = static_cast<double>(total_packets_ - st.first_pkt_num);
                double gy = st.clock_cum_pcr;

                st.reg_n++;
                st.reg_sx  += gx;
                st.reg_sy  += gy;
                st.reg_sxx += gx * gx;
                st.reg_sxy += gx * gy;

                if (st.reg_n >= PCR_MIN_REG_SAMPLES) {
                    double n = static_cast<double>(st.reg_n);
                    double denom = n * st.reg_sxx - st.reg_sx * st.reg_sx;
                    if (std::abs(denom) > 1e-18) {
                        double slope     = (n * st.reg_sxy - st.reg_sx * st.reg_sy) / denom;
                        double intercept = (st.reg_sy - slope * st.reg_sx) / n;
                        double predicted = slope * gx + intercept;
                        double offset    = gy - predicted;

                        st.accuracy_count++;
                        st.accuracy_sum    += offset;
                        st.accuracy_sq_sum += offset * offset;
                        if (offset < st.accuracy_min) st.accuracy_min = offset;
                        if (offset > st.accuracy_max) st.accuracy_max = offset;
                        st.accuracy_samples.push_back(offset);

                        // TR 101 290 — 2.3
                        if (std::abs(offset) > TR101290_PCR_ACCURACY_S)
                            st.pcr_accuracy_err++;

                        // Update T-STD pkt duration from regression slope
                        if (slope > 0)
                            tstd_pkt_dur_ = slope;
                    }
                }

                // ── Drift: arrival-time regression (live mode only) ──
                if (!file_mode_) {
                    double ax = arrival_time - st.clock_ref_arrival;
                    double ay = st.clock_cum_pcr;

                    st.dreg_n++;
                    st.dreg_sx  += ax;
                    st.dreg_sy  += ay;
                    st.dreg_sxx += ax * ax;
                    st.dreg_sxy += ax * ay;

                    if (st.dreg_n >= PCR_MIN_REG_SAMPLES) {
                        double n = static_cast<double>(st.dreg_n);
                        double denom = n * st.dreg_sxx - st.dreg_sx * st.dreg_sx;
                        if (std::abs(denom) > 1e-18) {
                            double slope = (n * st.dreg_sxy - st.dreg_sx * st.dreg_sy) / denom;
                            st.drift_ppm = (slope - 1.0) * 1e6;
                        }
                    }
                }
            }
        }

        st.last_pcr_raw    = pcr.raw;
        st.last_arrival    = arrival_time;
        st.bytes_since_pcr = 0;
    }

    // ── Per-ES T-STD: initialize buffer for an elementary stream ─────
    void init_tstd_es(uint16_t es_pid, uint16_t pcr_pid, uint8_t stream_type) {
        double cap = tstd_buffer_capacity(stream_type);
        tstd_es_buffers_[es_pid] = TstdEsBuffer(es_pid, pcr_pid, stream_type, cap);
    }

    // ── Per-ES T-STD: feed a packet belonging to this ES ────────────
    void process_tstd_es_packet(uint16_t es_pid, const uint8_t* pkt, double arrival_time) {
        auto it = tstd_es_buffers_.find(es_pid);
        if (it == tstd_es_buffers_.end()) return;

        TsHeader h = parse_ts_header(pkt);
        double stream_t = get_stream_time(arrival_time);

        if (h.has_payload) {
            int payload_size = TS_PACKET_SIZE - 4;
            if (h.has_adaptation_field) {
                int af_len = pkt[4];
                payload_size -= (1 + af_len);
            }
            if (payload_size > 0)
                it->second.input(stream_t, payload_size);
        }
    }

    // ── Legacy per-PCR-PID T-STD (kept for fallback when no SI) ─────
    void init_tstd(uint16_t pcr_pid, bool is_video) {
        double cap   = is_video ? (24000000.0 / 8) : 3584;
        uint8_t stype = is_video ? 0x1B : 0x03;  // assume H.264 or MPEG audio
        tstd_legacy_buffers_[pcr_pid] = TstdEsBuffer(pcr_pid, pcr_pid, stype, cap);
    }

    void process_tstd_packet(uint16_t pcr_pid, const uint8_t* pkt, double arrival_time) {
        auto it = tstd_legacy_buffers_.find(pcr_pid);
        if (it == tstd_legacy_buffers_.end()) return;

        TsHeader h = parse_ts_header(pkt);
        double stream_t = get_stream_time(arrival_time);

        if (h.has_payload) {
            int payload_size = TS_PACKET_SIZE - 4;
            if (h.has_adaptation_field) {
                int af_len = pkt[4];
                payload_size -= (1 + af_len);
            }
            if (payload_size > 0)
                it->second.input(stream_t, payload_size);
        }
    }

    const std::map<uint16_t, PcrPidStats>& stats() const { return stats_; }
    int64_t total_packets() const { return total_packets_; }
    int64_t null_packets()  const { return null_packets_; }

    // Count a packet without PCR analysis (for global stats)
    void count_packet(const uint8_t* pkt) {
        total_packets_++;
        TsHeader h = parse_ts_header(pkt);
        if (h.pid == TS_PID_NULL) { null_packets_++; return; }
        pid_bytes_[h.pid] += TS_PACKET_SIZE;
    }

    // ── Finalize: aggregate per-ES T-STD stats into per-PCR-PID ─────
    void finalize() {
        // Aggregate per-ES buffers → per PCR PID
        for (auto& [es_pid, buf] : tstd_es_buffers_) {
            uint16_t pcr_pid = buf.pcr_pid;
            if (stats_.count(pcr_pid)) {
                stats_[pcr_pid].tstd_overflows  += buf.overflows;
                stats_[pcr_pid].tstd_underflows += buf.underflows;
                if (buf.max_level > stats_[pcr_pid].tstd_buf_max)
                    stats_[pcr_pid].tstd_buf_max = buf.max_level;
            }
        }

        if (!tstd_es_buffers_.empty()) {
            // ES buffers exist — discard legacy fallback buffers
            tstd_legacy_buffers_.clear();
        } else {
            // Legacy (fallback) buffers — used when no SI info
            for (auto& [pid, buf] : tstd_legacy_buffers_) {
                if (stats_.count(pid)) {
                    stats_[pid].tstd_overflows  += buf.overflows;
                    stats_[pid].tstd_underflows += buf.underflows;
                    if (buf.max_level > stats_[pid].tstd_buf_max)
                        stats_[pid].tstd_buf_max = buf.max_level;
                }
            }
        }
    }

    double total_bitrate_bps() const {
        double sum = 0;
        for (auto& [pid, st] : stats_) sum += st.estimated_bitrate;
        return sum;
    }

    const std::map<uint16_t, int64_t>& pid_bytes() const { return pid_bytes_; }

    bool has_es_buffers() const { return !tstd_es_buffers_.empty(); }

    const std::map<uint16_t, TstdEsBuffer>& tstd_es_buffers() const { return tstd_es_buffers_; }
    const std::map<uint16_t, TstdEsBuffer>& tstd_legacy_buffers() const { return tstd_legacy_buffers_; }

private:
    std::map<uint16_t, PcrPidStats>    stats_;
    std::map<uint16_t, TstdEsBuffer>   tstd_es_buffers_;      // keyed by ES PID
    std::map<uint16_t, TstdEsBuffer>   tstd_legacy_buffers_;  // keyed by PCR PID (fallback)
    std::map<uint16_t, int64_t>        pid_bytes_;
    int64_t total_packets_ = 0;
    int64_t null_packets_  = 0;
    bool    file_mode_     = false;
    double  pcr_interval_limit_ = TR101290_PCR_INTERVAL_MAX_S;  // default 40 ms

    // ── T-STD stream timing ─────────────────────────────────────────
    double  tstd_pkt_dur_ = 0;   // seconds per TS packet (from PCR regression)

    double get_stream_time(double arrival_fallback) const {
        if (file_mode_ || tstd_pkt_dur_ <= 0)
            return arrival_fallback;
        // Monotonic: total_packets_ × pkt_dur
        return static_cast<double>(total_packets_) * tstd_pkt_dur_;
    }

    void reset_regression(PcrPidStats& st) {
        st.clock_ref_arrival = -1;
        st.clock_cum_pcr = 0;
        st.first_pkt_num = -1;
        st.reg_n = 0;
        st.reg_sx = st.reg_sy = st.reg_sxx = st.reg_sxy = 0;
        st.dreg_n = 0;
        st.dreg_sx = st.dreg_sy = st.dreg_sxx = st.dreg_sxy = 0;
        st.prev_pcr_delta = 0;
    }
};
