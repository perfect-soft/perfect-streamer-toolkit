/*
 * Copyright 2026 Perfect Soft
 * SPDX-License-Identifier: Apache-2.0
 */
#pragma once
/*
 * ts_checker.h — TR 101 290 low-level TS packet checks
 *
 * Implements:
 *   1.1  TS_sync_loss             — 2+ consecutive bad sync bytes
 *   1.2  Sync_byte_error          — sync byte != 0x47
 *   1.4  Continuity count error   — CC not incremented / skipped without discontinuity
 *   1.6  PID error                — expected PID absent for > 5 seconds
 *   2.1  Transport error          — transport_error_indicator = 1
 */

#include "events.h"
#include "ts_common.h"
#include "tr101290_defs.h"

#include <map>
#include <set>
#include <vector>
#include <cstdint>

// ─── Per-PID continuity counter state ─────────────────────────────────
struct CcState {
    uint8_t last_cc     = 0;
    bool    initialized = false;
};

// ─── Aggregated statistics ────────────────────────────────────────────
struct TsCheckerStats {
    // 1.1 — individual sync byte errors
    int64_t sync_byte_errors      = 0;

    // 1.2 — sync loss events (2+ consecutive sync errors)
    int64_t sync_loss_events      = 0;

    // 1.4 — continuity counter errors (total and per-PID)
    int64_t cc_errors             = 0;
    std::map<uint16_t, int64_t> cc_errors_per_pid;

    // 1.6 — PID absence errors
    int64_t pid_absence_errors    = 0;
    std::set<uint16_t> pid_absent_set;

    // 2.1 — transport error indicator
    int64_t transport_errors      = 0;
    std::set<uint16_t> tei_pids;
};

// ─── TsChecker ────────────────────────────────────────────────────────
class TsChecker {
public:
    TsChecker() = default;

    // Register PIDs that must be present (from PAT/PMT discovery).
    void register_expected_pids(const std::set<uint16_t>& pids) {
        for (auto pid : pids)
            expected_pids_.insert(pid);
    }

    // Feed every raw 188-byte TS packet with monotonic stream time.
    /// Per-packet P1/P2 header checks: 1.1 sync loss, 1.2 sync byte, 1.4 CC, 2.1 TEI; a TEI or bad-sync packet keeps its PID's CC chain but is never a CC error.
    void process_packet(const uint8_t* pkt, double stream_time) {
        // 1.2 Sync_byte_error / 1.1 TS_sync_loss (2+ in a row). Such a
        // packet's header is not trusted: no TEI count, and below it only
        // keeps its PID's CC chain going (like a TEI packet).
        const bool bad_sync = pkt[0] != TS_SYNC_BYTE;
        if (bad_sync) {
            stats_.sync_byte_errors++;
            consecutive_sync_errs_++;
            Events::get().note("1.2", -1, sync_detail(pkt[0]));
            if (consecutive_sync_errs_ == 2) {
                stats_.sync_loss_events++;
                Events::get().note("1.1");
            }
        } else {
            consecutive_sync_errs_ = 0;
        }

        TsHeader h = parse_ts_header(pkt);

        // 2.1 — transport_error_indicator (bit 7 of byte 1). The packet
        // stays in the continuity check below: an intact packet carrying
        // TEI must not break the CC chain of its PID.
        const bool tei = !bad_sync && (pkt[1] & 0x80) != 0;
        if (tei) {
            stats_.transport_errors++;
            stats_.tei_pids.insert(h.pid);
            Events::get().note("2.1", h.pid);
        }

        // 1.6 — PID presence tracking (not from a TEI packet: its PID
        // may be the corrupted part)
        if (!tei && !bad_sync && expected_pids_.count(h.pid))
            pid_last_seen_[h.pid] = stream_time;

        // Null packets: no CC check
        if (h.pid == TS_PID_NULL)
            return;

        // 1.4 — continuity counter check
        uint8_t afc = (pkt[3] >> 4) & 0x03;
        if (afc == 0x00)
            return;  // reserved/invalid AFC, skip

        bool has_payload = (afc & 0x01) != 0;
        bool has_af      = (afc & 0x02) != 0;
        bool discontinuity = false;

        if (has_af && pkt[4] > 0)
            discontinuity = (pkt[5] & 0x80) != 0;

        auto& cc_st = cc_state_[h.pid];

        if (tei || bad_sync) {
            // A TEI or bad-sync packet's header may be corrupt: it advances the chain
            // when its CC fits, and is never counted as a CC error itself.
            if (cc_st.initialized && !discontinuity
                && h.continuity_counter == ((cc_st.last_cc + (has_payload ? 1 : 0)) & 0x0F))
                cc_st.last_cc = h.continuity_counter;
            return;
        }

        if (!cc_st.initialized) {
            cc_st.last_cc     = h.continuity_counter;
            cc_st.initialized = true;
            return;
        }

        if (discontinuity) {
            // Discontinuity indicated — CC may jump, reset state
            cc_st.last_cc = h.continuity_counter;
            return;
        }

        if (!has_payload) {
            // Adaptation-only packet: CC must NOT change
            if (h.continuity_counter != cc_st.last_cc) {
                stats_.cc_errors++;
                stats_.cc_errors_per_pid[h.pid]++;
                note_cc(h.pid, cc_st.last_cc, h.continuity_counter);
            }
        } else {
            // Payload present: CC must be (last + 1) mod 16
            uint8_t expected = (cc_st.last_cc + 1) & 0x0F;
            if (h.continuity_counter == cc_st.last_cc) {
                // Duplicate packet — allowed (not an error)
            } else if (h.continuity_counter != expected) {
                stats_.cc_errors++;
                stats_.cc_errors_per_pid[h.pid]++;
                note_cc(h.pid, expected, h.continuity_counter);
            }
        }

        cc_st.last_cc = h.continuity_counter;
    }

    // Call at end of analysis to detect PIDs absent > 5 seconds.
    void check_pid_absence(double final_time) {
        for (auto pid : expected_pids_) {
            auto it = pid_last_seen_.find(pid);
            if (it == pid_last_seen_.end()) {
                // Never seen
                stats_.pid_absent_set.insert(pid);
                stats_.pid_absence_errors++;
                Events::get().note("1.6", pid, "never seen", final_time);
            } else if ((final_time - it->second) > TR101290_PID_ABSENCE_MAX_S) {
                stats_.pid_absent_set.insert(pid);
                stats_.pid_absence_errors++;
                Events::get().note("1.6", pid, "absent since then",
                                   it->second + TR101290_PID_ABSENCE_MAX_S);
            }
        }
    }

    const TsCheckerStats& stats() const { return stats_; }

private:
    static std::string sync_detail(uint8_t b) {
        if (!Events::on()) return std::string();
        char buf[32];
        snprintf(buf, sizeof(buf), "sync byte 0x%02X", b);
        return buf;
    }
    static void note_cc(uint16_t pid, int want, int got) {
        if (Events::on())
            Events::get().note("1.4", pid, "expected " + std::to_string(want) + ", got " + std::to_string(got));
    }

public:

private:
    TsCheckerStats              stats_;
    std::set<uint16_t>          expected_pids_;
    std::map<uint16_t, CcState> cc_state_;
    std::map<uint16_t, double>  pid_last_seen_;
    int                         consecutive_sync_errs_ = 0;
};
