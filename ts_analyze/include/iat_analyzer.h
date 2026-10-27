/*
 * Copyright 2026 Perfect Soft
 * SPDX-License-Identifier: Apache-2.0
 */
#pragma once
/*
 * iat_analyzer.h — UDP datagram Inter-Arrival Time (IAT) statistics.
 *
 * Measures the variability of UDP datagram arrival times (network jitter
 * on the delivery path). Each IPTV UDP datagram typically carries 7 TS
 * packets (1316 B), so IAT is a datagram-level metric, not a per-TS-packet
 * metric.
 *
 * Only meaningful for live network input (UDP). In file mode, packet
 * "arrival times" are synthesized from the assumed bitrate and have no
 * relation to network behavior — the analyzer is therefore not attached.
 *
 * Reported quantities:
 *   min / max / avg / stddev IAT
 *   95th and 99th percentile IAT
 *   max jitter (max |IAT - mean|)
 *   gaps over IAT_GAP_THRESHOLD_S (default 100 ms) — likely outage or
 *     significant burst loss
 *
 * No hard PASS/FAIL verdict per TR 101 290 — IAT is informational. A
 * separate gap-count violation acts as a soft warning.
 */

#include <vector>
#include <algorithm>
#include <cmath>
#include <cstdint>

// A single inter-arrival gap exceeding this is treated as a delivery anomaly.
static constexpr double IAT_GAP_THRESHOLD_S = 0.100;   // 100 ms

class IatAnalyzer
{
public:
    // Record arrival time of a UDP datagram (monotonic seconds).
    void add_arrival(double t)
    {
        if (count_ > 0)
        {
            double iat = t - prev_t_;
            if (iat >= 0.0)
            {
                intervals_.push_back(iat);
                if (iat < min_iat_) min_iat_ = iat;
                if (iat > max_iat_) max_iat_ = iat;
                sum_    += iat;
                sum_sq_ += iat * iat;
                if (iat > IAT_GAP_THRESHOLD_S) gap_events_++;
            }
        }
        prev_t_ = t;
        count_++;
    }

    int64_t datagram_count() const { return count_; }
    int64_t interval_count() const { return (int64_t) intervals_.size(); }
    int64_t gap_events()     const { return gap_events_; }

    double min()    const { return intervals_.empty() ? 0.0 : min_iat_; }
    double max()    const { return intervals_.empty() ? 0.0 : max_iat_; }
    double avg()    const { return intervals_.empty() ? 0.0 : sum_ / (double) intervals_.size(); }

    double stddev() const
    {
        if (intervals_.size() < 2) return 0.0;
        double n    = (double) intervals_.size();
        double mean = sum_ / n;
        double var  = sum_sq_ / n - mean * mean;
        return var > 0.0 ? std::sqrt(var) : 0.0;
    }

    // Maximum deviation of any IAT from the mean — peak jitter measure.
    double max_jitter() const
    {
        if (intervals_.empty()) return 0.0;
        double mean = avg();
        double mj = 0.0;
        for (double iat : intervals_)
        {
            double dev = std::fabs(iat - mean);
            if (dev > mj) mj = dev;
        }
        return mj;
    }

    // p in [0.0, 1.0]. Sorts a copy lazily; cheap for typical sample counts.
    double percentile(double p) const
    {
        if (intervals_.empty()) return 0.0;
        std::vector<double> sorted = intervals_;
        std::sort(sorted.begin(), sorted.end());
        size_t idx = (size_t) (p * (double) (sorted.size() - 1));
        if (idx >= sorted.size()) idx = sorted.size() - 1;
        return sorted[idx];
    }

private:
    double  prev_t_     = 0.0;
    double  sum_        = 0.0;
    double  sum_sq_     = 0.0;
    double  min_iat_    = 1e18;
    double  max_iat_    = 0.0;
    int64_t count_      = 0;
    int64_t gap_events_ = 0;
    std::vector<double> intervals_;
};
