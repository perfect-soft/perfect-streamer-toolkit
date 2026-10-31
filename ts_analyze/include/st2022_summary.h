/*
 * Copyright 2026 Perfect Soft
 * SPDX-License-Identifier: Apache-2.0
 */
#pragma once
/*
 * st2022_summary.h — options and end-of-run totals of the ST 2022-1 /
 * 2022-7 input, as the reports and the verdict read them.
 */

#include "iat_analyzer.h"

#include <cstdint>
#include <string>

struct St2022Options
{
    bool rtp = false;               // --rtp
    bool fec = false;               // --fec
    std::string path2;              // --path2 udp://[iface@]addr:port
    double path_skew_ms = 450.0;    // --path-skew-ms

    bool enabled() const { return rtp || fec || !path2.empty(); }
};

struct St2022PathSummary
{
    bool present = false;
    std::string source;
    bool up = false;                // received within the silence limit at the end
    double down_s = 0;              // total time silent longer than the limit
    int64_t down_events = 0;
    uint64_t received = 0, lost = 0, dup = 0, late = 0;
    uint64_t proto_errors = 0, ssrc_changes = 0, ignored = 0;
    uint32_t ssrc = 0;
    uint64_t fec_datagrams = 0;     // datagrams on this path's FEC ports
    IatAnalyzer iat;
};

struct St2022Summary
{
    bool enabled = false;
    bool fec = false;
    bool two_paths = false;
    double silence_limit_ms = 0;    // the largest limit in force (S.3)
    double skew_limit_ms = 0;       // --path-skew-ms (S.5)
    double wait_ms = 0;             // what a gap waited at the end

    St2022PathSummary path[2];

    uint64_t released = 0;
    uint64_t unrecoverable = 0;     // given up: no path and no FEC had it
    uint64_t overflow = 0;          // given up early: the window outgrew the ring
    uint64_t start_check_lost = 0;  // of those, lost before the paths were first verified equal (not gated)
    uint64_t repaired = 0;          // released from one path while both were used
    uint64_t compares = 0, mismatches = 0;
    uint64_t resets = 0;            // the stream restarted (new SSRC or primary path)
    bool paths_differ = false;      // at any time during the run
    bool verified = false;          // the two paths carry the same stream (at the end)
    double skew_p50_ms = 0;         // path 2 minus path 1, last 10 s
    double skew_max_ms = 0;         // largest |difference| over the run

    uint64_t fec_received[2] = { 0, 0 };    // [0] column, [1] row
    uint64_t fec_dup = 0, fec_bad = 0, fec_ssrc_nonzero = 0;
    uint64_t fec_recovered[2] = { 0, 0 };
    uint64_t fec_refused = 0, fec_len_fixups = 0;
    unsigned fec_L = 0, fec_D = 0;
    double fec_absent_s = 0;        // time with no valid FEC in the last 2 s (after the first 2 s)

    uint64_t unrecovered_total() const { return unrecoverable + overflow; }
    uint64_t gated_loss() const { return unrecovered_total() - start_check_lost; }
};
