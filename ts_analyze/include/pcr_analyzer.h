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
 * T-STD uses per-ES buffers on the program clock: a PES's bytes leave
 * at its DTS (else PTS). Each packet's time is interpolated between its
 * two neighbouring PCRs by position, independent of arrival timestamps.
 */

#include "events.h"
#include "ts_common.h"
#include "tr101290_defs.h"

#include <map>
#include <set>
#include <deque>
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
    int64_t  pcr_interval_err      = 0;  // intervals > 40 ms (TR 101 290 2.3a)
    int64_t  pcr_interval_hard_err = 0;  // intervals > 100 ms (ISO 13818-1 hard limit, gates OVERALL)
    int64_t  pcr_interval_warn     = 0;  // intervals > 25 ms (recommended)
    int64_t  pcr_accuracy_err  = 0;    // |jitter| > 500 ns
    int64_t  pcr_discont_ind_errors = 0; // 2.3b: gap > 100 ms without discontinuity flag
    int64_t  discontinuities   = 0;

    // PCR interval statistics (seconds)
    double   interval_min  = 1e9;
    double   interval_max  = 0;
    double   interval_sum  = 0;
    int64_t  interval_count = 0;

    // Previous valid pcr_delta — used for 1.4 burst-pair tolerance
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
    int64_t  last_pcr_pkt     = -1;   // total_packets_ at the last PCR
    double   pcr_time         = -1;   // the program clock at the last PCR (unwrapped seconds)
    int      last_cc          = -1;   // CC of the last payload packet on this PID
    bool     cc_break         = false;    // a CC break since the last PCR: packets were lost
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
    std::deque<std::pair<double, double>> delay_win;   // (arrival, delivery delay) of the last 10 s

    // ── PCR_AC rate: PCR time per packet of the last 15 intervals without a CC break ──
    std::deque<double> acc_ratio;

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
// The elementary-stream buffer of the ISO/IEC 13818-1 §2.4.2 T-STD on the
// program's clock: a PES's bytes enter when its packets arrive and leave at
// its decode time (DTS, else PTS). Time is the program's PCR time, each
// packet placed between its two neighbouring PCRs by position (exact for VBR),
// so neither CPU load nor network bursts nor the -b hint move it. TBn (the 512 B transport buffer)
// is not modelled.
//
// Each elementary stream gets its own buffer (keyed by ES PID).
// Results are aggregated per PCR PID for reporting.
//
struct TstdEsBuffer {
    uint16_t es_pid   = 0;
    uint16_t pcr_pid  = 0;      // for aggregation into PcrPidStats
    uint8_t  stream_type = 0;   // ISO 13818-1 stream type
    double   capacity = 0;      // bytes (ISO BSn for this stream type; overflow_limit() judges)
    double   level    = 0;      // bytes arrived and not yet decoded
    double   drain_rate = 0;    // bytes/sec: the measured ES rate (reports)
    bool     measuring = false; // the clock is known and a timed PES started

    int64_t  overflows  = 0;    // episodes above the capacity
    int64_t  underflows = 0;    // access units late or missing at their decode time
    double   max_level  = 0;

    // decode lead vs the program clock: decode time − arrival of each timed PES's first packet
    int64_t  lead_n = 0;
    double   lead_sum = 0, lead_min = 1e9, lead_max = -1e9;
    int64_t  lead_episodes = 0; // episodes above lead_limit_s() (TSTD.lead, a warning)
    double   lead_avg() const { return lead_n ? lead_sum / static_cast<double>(lead_n) : 0; }

    TstdEsBuffer() = default;
    TstdEsBuffer(uint16_t es, uint16_t pcr, uint8_t stype, double cap)
        : es_pid(es), pcr_pid(pcr), stream_type(stype), capacity(cap) {}

    /// A PES starts at `now` (PCR time, s). ts_valid: it carries a DTS/PTS, `dec` its decode time on the same clock.
    void start_pes(double now, bool ts_valid, double dec) {
        if (!ts_valid) {
            // Untimed PES: decoded with the last timed one still queued (or at once).
            cur_late_ = late_counted_ = false;
            if (q_.empty())
                q_.push_back({ now, 0.0 });
            cur_open_ = true;
            return;
        }
        if (!measuring) {
            measuring = true;
            t_first_ = now;
        }
        // Lead: decode time minus the arrival of the PES's first packet.
        const double lead = dec - now;
        lead_n++;
        lead_sum += lead;
        lead_min = std::min(lead_min, lead);
        lead_max = std::max(lead_max, lead);
        if (t_last_ - t_first_ >= 1.0 && lead > lead_limit_s()) {
            if (!lead_over_) {
                lead_over_ = true;
                lead_episodes++;
                if (Events::on())
                    Events::get().note("TSTD.lead", es_pid, "lead " + std::to_string((int) (lead * 1e3)) + " ms > "
                                       + std::to_string((int) (lead_limit_s() * 1e3)) + " ms", ev_time(now));
            }
        } else
            lead_over_ = false;
        q_.push_back({ dec, 0.0 });
        cur_open_ = true;
        cur_late_ = dec <= now;     // already due when it starts: its bytes all come late
        late_counted_ = false;
        starved_ = false;
    }

    /// TS payload bytes of the current PES arrive at `now`.
    void input(double now, double bytes) {
        if (!measuring || !cur_open_)
            return;
        bytes_ += bytes;
        t_last_ = now;
        if (t_last_ > t_first_)
            drain_rate = bytes_ / (t_last_ - t_first_);
        if (cur_late_) {
            // Data of an access unit after its decode time: an underflow, once per PES.
            if (!late_counted_) {
                late_counted_ = true;
                underflows++;
                note_under(now, now, "access unit late");
            }
            return;
        }
        late_counted_ = false;
        q_.back().bytes += bytes;
        level += bytes;
        if (level > max_level)
            max_level = level;
        // Judged once the rate is measured over 1 s (overflow_limit needs it).
        if (t_last_ - t_first_ >= 1.0 && level > overflow_limit()) {
            if (!over_) {
                over_ = true;
                overflows++;
                if (Events::on())
                    Events::get().note("TSTD.over", es_pid, std::to_string((int) level) + " B > "
                                       + std::to_string((int) overflow_limit()) + " B", ev_time(now));
            }
        } else
            over_ = false;
    }

    /// Overflow is judged on the ISO BSn or 1 s of the ES's measured rate, whichever is larger: field
    /// streams keep 0.5-0.7 s of audio ahead of its PTS, above the 3584 B of BSn, and decoders hold it. A gross early
    /// delivery (more than 1 s ahead) still overflows; max_level next to capacity shows the real lead.
    double overflow_limit() const { return std::max(capacity, drain_rate * 1.0); }

    /// The same limits in seconds of lead at the ES's measured rate: practical = max(ISO BSn / rate, 1 s),
    /// above it TSTD.lead warns; ISO = BSn / rate, for information. 0 while the rate is unknown.
    double lead_limit_s() const { return drain_rate > 0 ? overflow_limit() / drain_rate : 0; }
    double lead_iso_s() const { return drain_rate > 0 ? capacity / drain_rate : 0; }

    /// Decodes everything due by `now`; an empty buffer past the next expected decode time is a starvation.
    void decode_to(double now) {
        while (!q_.empty() && q_.front().t <= now) {
            const Au au = q_.front();
            q_.pop_front();
            if (q_.empty() && cur_open_) {
                cur_late_ = true;           // the PES still arriving reached its decode time
                late_counted_ = false;
            }
            level -= au.bytes;
            if (last_dec_ >= 0) {
                double d = au.t - last_dec_;
                if (d > 0 && d < 2.0)
                    period_ = period_ > 0 ? 0.9 * period_ + 0.1 * d : d;
            }
            last_dec_ = au.t;
        }
        if (level < 0)
            level = 0;
        if (level <= overflow_limit())
            over_ = false;
        // Not for PES private data (0x06): DVB subtitles come when there is something to show.
        if (measuring && stream_type != 0x06 && q_.empty() && !starved_ && last_dec_ >= 0 && period_ > 0
            && now > last_dec_ + std::max(1.5 * period_, 0.1)) {
            starved_ = true;
            underflows++;
            note_under(now, last_dec_ + period_, "buffer empty at the next decode time");
        }
    }

    /// The program clock jumped (PCR discontinuity or step): what is queued has no valid time any more.
    void reset_clock() {
        q_.clear();
        level = 0;
        cur_open_ = cur_late_ = late_counted_ = over_ = starved_ = false;
        last_dec_ = -1;
    }

private:
    struct Au { double t; double bytes; };      // decode time (PCR time, s), bytes in the buffer
    std::deque<Au> q_;
    bool   cur_open_ = false;       // q_.back() is the PES still arriving
    bool   cur_late_ = false;       // ... and its decode time has passed
    bool   late_counted_ = false;
    bool   over_ = false;
    bool   lead_over_ = false;
    bool   starved_ = false;
    double last_dec_ = -1, period_ = 0;
    double bytes_ = 0, t_first_ = 0, t_last_ = 0;

    // Event time: the current packet's analysis time (the PCR packet whose arrival replays the queue, program
    // clock ref_) moved by the program-clock difference.
    double ev_time(double at) const { return std::max(0.0, Events::get().now() + (at - ref_)); }
    void note_under(double /*now*/, double at, const char *what) const {
        if (Events::on())
            Events::get().note("TSTD.under", es_pid, what, ev_time(at));
    }

public:
    double ref_ = 0;                // program clock of the current packet (set by the analyzer)
    int    last_cc_ = -1;           // CC of the last payload packet of this ES (set by the analyzer)

    /// Packets of this ES were lost (a CC break): the PES arriving is incomplete and the bytes up to the next PES
    /// start belong to an unknown access unit (its header may be what was lost), so they are not counted as late.
    void lose() { cur_open_ = cur_late_ = late_counted_ = false; }
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
    case 0x03: case 0x04:                // MPEG-1/2 Audio
        return 3584;                     // BSn for audio
    case 0x0F:                           // AAC (ISO/IEC 13818-7)
        return 3584;
    case 0x11:                           // MPEG-4 AAC (LATM)
        return 3584;
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

        // CC since the last PCR: a break means packets were lost, so a long PCR
        // difference is a gap in the delivery, not a value step (pcr_step).
        if (pkt[3] & 0x10) {
            const int cc = pkt[3] & 0x0F;
            const bool di = (pkt[3] & 0x20) && pkt[4] > 0 && (pkt[5] & 0x80);
            if (st.last_cc >= 0 && !di && cc != st.last_cc && cc != ((st.last_cc + 1) & 0x0F))
                st.cc_break = true;
            st.last_cc = cc;
        }

        PcrValue pcr = extract_pcr(pkt);
        if (!pcr.valid) {
            st.bytes_since_pcr += TS_PACKET_SIZE;
            return;
        }

        st.pcr_count++;

        // ── Discontinuity handling ──────────────────────────────────
        if (pcr.discontinuity) {
            st.discontinuities++;
            set_program_clock(st, pcr.raw, true, 0);
            st.last_pcr_raw    = pcr.raw;
            st.last_arrival    = arrival_time;
            st.last_pcr_pkt    = total_packets_;
            st.bytes_since_pcr = 0;
            st.cc_break        = false;
            // Reset clock models — PCR clock has jumped
            reset_regression(st);
            return;     // skip interval/accuracy check on discontinuity
        }

        // ── PCR Interval ────────────────────────────────────────────
        if (st.last_pcr_raw >= 0) {
            double pcr_delta = PcrValue::delta_seconds(pcr.raw, st.last_pcr_raw);

            if (pcr_step(st, pcr_delta, arrival_time, h.pid)) {
                set_program_clock(st, pcr.raw, true, 0);
                st.last_pcr_raw    = pcr.raw;
                st.last_arrival    = arrival_time;
                st.last_pcr_pkt    = total_packets_;
                st.bytes_since_pcr = 0;
                st.cc_break        = false;
                return;
            }

            // Sanity: ignore absurdly large deltas (likely stream errors)
            if (pcr_delta > 0 && pcr_delta < 2.0) {
                st.interval_count++;
                st.interval_sum += pcr_delta;
                if (pcr_delta < st.interval_min) st.interval_min = pcr_delta;
                if (pcr_delta > st.interval_max) st.interval_max = pcr_delta;
                st.interval_samples.push_back(pcr_delta);

                // TR 101 290 2.3a (with RAP burst-pair tolerance).
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
                if (exceeds) {
                    st.pcr_interval_err++;
                    if (Events::on())
                        Events::get().note("2.3a", h.pid, "PCR interval " + std::to_string((int) (pcr_delta * 1e3)) + " ms");
                }
                if (pcr_delta > ISO13818_PCR_HARD_MAX_S)
                    st.pcr_interval_hard_err++;
                st.prev_pcr_delta = pcr_delta;
                if (pcr_delta > TR101290_PCR_INTERVAL_REC_S)
                    st.pcr_interval_warn++;

                // TR 101 290 2.3b — PCR discontinuity indicator error
                // Gap > 100 ms without discontinuity_indicator set
                if (pcr_delta > 0.100 && !pcr.discontinuity) {
                    st.pcr_discont_ind_errors++;
                    if (Events::on())
                        Events::get().note("2.3b", h.pid, "PCR step " + std::to_string((int) (pcr_delta * 1e3)) + " ms without the discontinuity flag");
                }

                // ── Bitrate estimation from PCR ─────────────────────
                int64_t bytes_between = st.bytes_since_pcr + TS_PACKET_SIZE;
                if (pcr_delta > 0)
                    st.estimated_bitrate = (static_cast<double>(bytes_between) * 8.0) / pcr_delta;

                // ── PCR Accuracy — global-pkt-num regression ────────
                //
                // Regress cumulative PCR seconds (y) against global
                // packet number (x). For a CBR mux, x is exactly
                // proportional to wall-clock time, so the regression
                // slope = 1/TR (absorbs any systematic rate). Each PCR is
                // then judged against the previous one plus the packets
                // between at that rate, free of network jitter (live)
                // and of the assumed bitrate (file).

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
                        // TR 101 290 PCR_AC: this PCR against the one expected from the previous PCR and the
                        // packets between them at the regressed TS rate. Per interval, so one lost datagram is
                        // at most one error, not a constant offset to the end (the old residual of the global
                        // fit kept it); an interval with a CC break on this PID (packets lost) is not judged.
                        // The rate is the median PCR time per packet of the last 15 intervals without a CC break
                        // (the regression slope until 8 exist): a single loss is an outlier the median ignores, so
                        // it biases nothing, while a clock that drifts moves the median along (drift is PCR.drift,
                        // not an accuracy error).
                        const double dn = static_cast<double>(total_packets_ - st.last_pcr_pkt);
                        const bool judged = !st.cc_break && dn > 0;
                        double rate = slope;
                        if (st.acc_ratio.size() >= PCR_MIN_REG_SAMPLES) {
                            std::vector<double> r(st.acc_ratio.begin(), st.acc_ratio.end());
                            std::nth_element(r.begin(), r.begin() + r.size() / 2, r.end());
                            rate = r[r.size() / 2];
                        }
                        double offset    = pcr_delta - dn * rate;
                        if (judged) {
                            st.acc_ratio.push_back(pcr_delta / dn);
                            if (st.acc_ratio.size() > 15)
                                st.acc_ratio.pop_front();
                        }

                        if (judged) {
                        st.accuracy_count++;
                        st.accuracy_sum    += offset;
                        st.accuracy_sq_sum += offset * offset;
                        if (offset < st.accuracy_min) st.accuracy_min = offset;
                        if (offset > st.accuracy_max) st.accuracy_max = offset;
                        st.accuracy_samples.push_back(offset);

                        // TR 101 290 2.4 PCR_accuracy_error
                        if (std::abs(offset) > TR101290_PCR_ACCURACY_S) {
                            st.pcr_accuracy_err++;
                            if (Events::on())
                                Events::get().note("2.4", h.pid, "offset " + std::to_string((int) (offset * 1e9)) + " ns");
                        }
                        }

                        // Packet duration for the program clock between PCRs (T-STD)
                        if (slope > 0)
                            tstd_pkt_dur_ = slope;
                    }
                }

                // ── Drift: arrival-time regression (live mode only) ──
                // A sample delivered off time (a stall's backlog; a datagram rebuilt by FEC) is skipped: its
                // delivery delay (arrival − PCR time) is more than 50 ms off the median of the last 10 s. The
                // estimate is used once it spans 10 s, so a fresh regression never replaces it from a few samples.
                if (!file_mode_ && drift_sample_on_time(st, arrival_time - st.clock_ref_arrival - st.clock_cum_pcr,
                                                        arrival_time)) {
                    double ax = arrival_time - st.clock_ref_arrival;
                    double ay = st.clock_cum_pcr;

                    st.dreg_n++;
                    st.dreg_sx  += ax;
                    st.dreg_sy  += ay;
                    st.dreg_sxx += ax * ax;
                    st.dreg_sxy += ax * ay;

                    if (st.dreg_n >= PCR_MIN_REG_SAMPLES && ax >= 10.0) {
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

        {
            const double d = st.last_pcr_raw >= 0 ? PcrValue::delta_seconds(pcr.raw, st.last_pcr_raw) : -1;
            set_program_clock(st, pcr.raw, !(d >= 0 && d < 2.0), d);
        }
        st.last_pcr_raw    = pcr.raw;
        st.last_arrival    = arrival_time;
        st.last_pcr_pkt    = total_packets_;
        st.bytes_since_pcr = 0;
        st.cc_break        = false;
    }

    // ── Per-ES T-STD: initialize buffer for an elementary stream ─────
    void init_tstd_es(uint16_t es_pid, uint16_t pcr_pid, uint8_t stream_type) {
        double cap = tstd_buffer_capacity(stream_type);
        tstd_es_buffers_[es_pid] = TstdEsBuffer(es_pid, pcr_pid, stream_type, cap);
    }

    // ── Per-ES T-STD: feed a packet belonging to this ES ────────────
    void process_tstd_es_packet(uint16_t es_pid, const uint8_t* pkt, double /*arrival_time*/) {
        auto it = tstd_es_buffers_.find(es_pid);
        if (it != tstd_es_buffers_.end())
            feed_tstd(it->second, pkt);
    }

    // ── Legacy per-PCR-PID T-STD (kept for fallback when no SI) ─────
    void init_tstd(uint16_t pcr_pid, bool is_video) {
        double cap   = is_video ? (24000000.0 / 8) : 3584;
        uint8_t stype = is_video ? 0x1B : 0x03;  // assume H.264 or MPEG audio
        tstd_legacy_buffers_[pcr_pid] = TstdEsBuffer(pcr_pid, pcr_pid, stype, cap);
    }

    void process_tstd_packet(uint16_t pcr_pid, const uint8_t* pkt, double /*arrival_time*/) {
        auto it = tstd_legacy_buffers_.find(pcr_pid);
        if (it != tstd_legacy_buffers_.end())
            feed_tstd(it->second, pkt);
    }

    const std::map<uint16_t, PcrPidStats>& stats() const { return stats_; }
    int64_t total_packets() const { return total_packets_; }
    int64_t null_packets()  const { return null_packets_; }

    // Count a packet without PCR analysis (for global stats)
    // A packet with a bad sync byte: it holds its byte position, nothing else.
    void count_unparsed() { total_packets_++; }

    void count_packet(const uint8_t* pkt) {
        total_packets_++;
        TsHeader h = parse_ts_header(pkt);
        if (h.pid == TS_PID_NULL) { null_packets_++; return; }
        pid_bytes_[h.pid] += TS_PACKET_SIZE;
    }

    // ── Finalize: aggregate per-ES T-STD stats into per-PCR-PID ─────
    void finalize() {
        // What is still queued after the last PCR has no PCR after it to be timed by: it is not counted (the rule
        // note's "between the PCR packets before and after"; an extrapolation set the lead of a file's last PES).
        tstd_pending_.clear();
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
    double  pcr_interval_limit_ = TR101290_PCR_INTERVAL_MAX_S;  // 40 ms

    // ── T-STD stream timing ─────────────────────────────────────────
    double  tstd_pkt_dur_ = 0;   // seconds per TS packet (from PCR regression)

    // ES packets since the last PCR of their program, replayed on its next PCR.
    struct TstdPending {
        TstdEsBuffer *buf;
        int64_t pkt;            // total_packets_ at the packet
        int bytes;              // TS payload bytes
        bool pes_start;
        int64_t ts;             // its DTS (else PTS), 90 kHz; -1 none
        bool loss;              // a CC break before it on this ES
    };
    std::map<uint16_t, std::vector<TstdPending>> tstd_pending_;     // keyed by PCR PID

    /// At each PCR of a program: its clock goes on by the PCR difference, and the ES packets queued since the last
    /// PCR are replayed at times interpolated between the two PCRs by packet position. That is exact for a VBR mux
    /// as well (a mux-wide average packet duration put AAC tens of ms off and read as late access units on a transcoder's
    /// output). A jump (discontinuity, step, a gap > 2 s) drops the queue and restarts the program's buffers. So the
    /// T-STD follows the PCR, not the arrival: CPU load, network bursts and the file -b hint do not move it.
    void set_program_clock(PcrPidStats& st, int64_t raw, bool jumped, double d) {
        if (st.pcr_time >= 0 && !jumped) {
            replay(st.pid, st.pcr_time, st.last_pcr_pkt, st.pcr_time + d, total_packets_);
            st.pcr_time += d;
            return;
        }
        tstd_pending_[st.pid].clear();
        if (st.pcr_time >= 0)
            for (auto *bufs : { &tstd_es_buffers_, &tstd_legacy_buffers_ })
                for (auto &[pid, b] : *bufs)
                    if (b.pcr_pid == st.pid)
                        b.reset_clock();
        st.pcr_time = static_cast<double>(raw) / PCR_CLOCK_HZ;
    }

    // Replays a program's queue on [t0 at packet n0, t1 at packet n1], then decodes what is due at t1 (so a
    // starved ES, with no packets of its own, is noticed at every PCR).
    void replay(uint16_t pcr_pid, double t0, int64_t n0, double t1, int64_t n1) {
        auto &q = tstd_pending_[pcr_pid];
        for (auto &e : q) {
            double t = n1 > n0 ? t0 + (t1 - t0) * static_cast<double>(e.pkt - n0) / static_cast<double>(n1 - n0) : t1;
            TstdEsBuffer &b = *e.buf;
            b.ref_ = t1;
            b.decode_to(t);
            if (e.loss)
                b.lose();
            if (e.pes_start) {
                bool ok = false;
                double dec = 0;
                if (e.ts >= 0) {
                    const double wrap = static_cast<double>(1LL << 33);
                    double dd = static_cast<double>(e.ts) - std::fmod(t * 90000.0, wrap);
                    if (dd > wrap / 2) dd -= wrap;
                    if (dd < -wrap / 2) dd += wrap;
                    dec = t + dd / 90000.0;
                    ok = std::abs(dd / 90000.0) < 10.0;     // further off: not this clock
                }
                b.start_pes(t, ok, dec);
            }
            b.input(t, e.bytes);
        }
        q.clear();
        for (auto *bufs : { &tstd_es_buffers_, &tstd_legacy_buffers_ })
            for (auto &[pid, b] : *bufs)
                if (b.pcr_pid == pcr_pid) {
                    b.ref_ = t1;
                    b.decode_to(t1);
                }
    }

    static int64_t pes_timestamp(const uint8_t *d) {
        if (!(d[0] & 0x01) || !(d[2] & 0x01) || !(d[4] & 0x01))
            return -1;
        return (static_cast<int64_t>((d[0] >> 1) & 0x07) << 30) | (static_cast<int64_t>(d[1]) << 22)
             | (static_cast<int64_t>((d[2] >> 1) & 0x7F) << 15) | (static_cast<int64_t>(d[3]) << 7)
             | static_cast<int64_t>((d[4] >> 1) & 0x7F);
    }

    // One ES packet: queued with its position (and, at a PES start, its DTS, else PTS) until the next PCR.
    void feed_tstd(TstdEsBuffer &b, const uint8_t *pkt) {
        auto it = stats_.find(b.pcr_pid);
        if (it == stats_.end() || it->second.pcr_time < 0)
            return;                 // no clock yet
        TsHeader h = parse_ts_header(pkt);
        if (!h.has_payload)
            return;
        int off = 4 + (h.has_adaptation_field ? 1 + pkt[4] : 0);
        if (off >= TS_PACKET_SIZE)
            return;
        const bool di = h.has_adaptation_field && pkt[4] > 0 && (pkt[5] & 0x80);
        const bool loss = b.last_cc_ >= 0 && !di && h.continuity_counter != b.last_cc_
                          && h.continuity_counter != ((b.last_cc_ + 1) & 0x0F);
        b.last_cc_ = h.continuity_counter;
        int64_t ts = -1;
        if (h.payload_unit_start) {
            const uint8_t *p = pkt + off;
            const int n = TS_PACKET_SIZE - off;
            if (n >= 14 && p[0] == 0 && p[1] == 0 && p[2] == 1) {
                const int flags = (p[7] >> 6) & 0x03;
                if (flags == 3 && n >= 19 && p[8] >= 10)
                    ts = pes_timestamp(p + 14);
                else if ((flags & 0x02) && p[8] >= 5)
                    ts = pes_timestamp(p + 9);
            }
        }
        tstd_pending_[b.pcr_pid].push_back({ &b, total_packets_, TS_PACKET_SIZE - off, h.payload_unit_start, ts, loss });
    }

    /// An unflagged PCR value step: the difference to the last PCR is outside 0..100 ms (negative, or above 2 s, is a
    /// step too), the PID's CC ran unbroken since the last PCR, and the difference does not match the transport time
    /// between the two PCR packets: packet count × the regressed packet duration, and on live input at least their
    /// arrival interval (a sender stall). It is 2.3b; 2.3a is judged on that transport interval, so a step alone is
    /// not also a repetition error. A real gap (packets lost: a CC break, or a stall: the arrival interval) stays on
    /// the normal path with 2.3a and 2.3b. The clock models go on across the step by the transport time.
    bool pcr_step(PcrPidStats& st, double pcr_delta, double arrival_time, uint16_t pid) {
        const double wrap = static_cast<double>(PCR_MAX + 1) / PCR_CLOCK_HZ;
        double est = (tstd_pkt_dur_ > 0 && st.last_pcr_pkt >= 0)
            ? static_cast<double>(total_packets_ - st.last_pcr_pkt) * tstd_pkt_dur_ : -1;
        if (est > 0 && !file_mode_ && st.last_arrival >= 0)
            est = std::max(est, arrival_time - st.last_arrival);
        const bool out_of_range = !(pcr_delta > 0 && pcr_delta < 2.0);
        if (st.cc_break || pcr_delta == 0)
            return false;
        if (!out_of_range && (pcr_delta <= 0.100 || est <= 0
                              || std::abs(pcr_delta - est) <= std::max(0.010, 0.25 * est)))
            return false;
        const double step = pcr_delta > wrap / 2 ? pcr_delta - wrap : pcr_delta;
        st.pcr_discont_ind_errors++;
        if (Events::on())
            Events::get().note("2.3b", pid, "PCR step " + std::to_string((int) (step * 1e3))
                               + " ms without the discontinuity flag");
        if (est > 0) {
            st.interval_count++;
            st.interval_sum += est;
            if (est < st.interval_min) st.interval_min = est;
            if (est > st.interval_max) st.interval_max = est;
            st.interval_samples.push_back(est);
            if (est > pcr_interval_limit_) {
                st.pcr_interval_err++;
                if (Events::on())
                    Events::get().note("2.3a", pid, "PCR interval " + std::to_string((int) (est * 1e3))
                                       + " ms (transport time; the PCR value stepped)");
            }
            if (est > ISO13818_PCR_HARD_MAX_S)
                st.pcr_interval_hard_err++;
            if (est > TR101290_PCR_INTERVAL_REC_S)
                st.pcr_interval_warn++;
            st.prev_pcr_delta = est;
            // Accuracy and drift go on: the PCR time advances by the transport time, not by the step.
            if (st.first_pkt_num >= 0)
                st.clock_cum_pcr += est;
        } else
            reset_regression(st);       // too early to bridge the step: start the clock models anew
        return true;
    }

    /// Drift input filter: a sample whose delivery delay (arrival − PCR time) is more than 50 ms off the median delay
    /// of the last 10 s says nothing about the encoder clock: late ones queued behind a pause (a stall's backlog),
    /// early ones stamped with a predecessor's arrival (datagrams rebuilt by FEC). The median, unlike the least
    /// delay, is not moved by a few such samples.
    static bool drift_sample_on_time(PcrPidStats& st, double delay, double arrival) {
        st.delay_win.emplace_back(arrival, delay);
        while (st.delay_win.front().first < arrival - 10.0)
            st.delay_win.pop_front();
        std::vector<double> d;
        d.reserve(st.delay_win.size());
        for (auto &[t, v] : st.delay_win)
            d.push_back(v);
        std::nth_element(d.begin(), d.begin() + d.size() / 2, d.end());
        return std::abs(delay - d[d.size() / 2]) <= 0.050;
    }

    void reset_regression(PcrPidStats& st) {
        st.clock_ref_arrival = -1;
        st.clock_cum_pcr = 0;
        st.first_pkt_num = -1;
        st.reg_n = 0;
        st.reg_sx = st.reg_sy = st.reg_sxx = st.reg_sxy = 0;
        st.dreg_n = 0;
        st.delay_win.clear();
        st.acc_ratio.clear();
        st.dreg_sx = st.dreg_sy = st.dreg_sxx = st.dreg_sxy = 0;
        st.prev_pcr_delta = 0;
    }
};
