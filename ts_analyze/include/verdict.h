/*
 * Copyright 2026 Perfect Soft
 * SPDX-License-Identifier: Apache-2.0
 */
#pragma once
/*
 * verdict.h — the single OVERALL verdict shared by every report mode.
 *
 * The full, short and XML reports print the checks in their own layouts,
 * but none of them decides OVERALL by itself: they all call
 * Verdict::overall(), so the verdict and the exit code do not depend on
 * the report mode.
 *
 * Gated (FAIL turns OVERALL to FAIL):
 *   P1 1.1 1.2 1.3 1.3a 1.4 1.5 1.5a 1.6
 *   P2 2.1 2.2 2.3 (ISO 100 ms hard limit) 2.4 2.5 (live) 2.6 2.7 (if scrambled)
 *   P3 3.1 (unless --no-nit) 3.2 (if seen) 3.5 3.6 (if seen)
 *      3.7 (unless --no-eit) 3.12 3.13 3.14 (live)
 *   SI section size above the ISO/EN limit
 *   PCR drift beyond ±30 ppm in the hard window (live, >= 300 s)
 * Not gated: 2.3 soft limit (TR 40 ms), 3.4 unreferenced PIDs,
 *   3.8-3.10 (optional EIT, WARN only), EIT > 1024 B STB warning, IAT.
 */

#include "ts_common.h"
#include "pcr_analyzer.h"
#include "ts_checker.h"
#include "si_monitor.h"
#include "pts_analyzer.h"
#include "tr101290_defs.h"

#include <cmath>
#include <cstdint>

struct Verdict
{
    /// OVERALL for every report mode and the exit code: all gated checks of the list above pass (P3 included).
    static bool overall(const PcrAnalyzer &analyzer,
                        const TsChecker &ts_checker,
                        const SiMonitor &si_monitor,
                        const PtsAnalyzer &pts_analyzer,
                        double duration_s)
    {
        const auto &stats = analyzer.stats();
        const auto &ts = ts_checker.stats();
        bool live = !analyzer.file_mode();

        auto si_err = [](const SiTableStats &st) {
            return st.interval_violations + st.crc_errors;
        };

        int64_t pmt_err = 0, pmt_ver_err = 0;
        for (auto &[pid, st] : si_monitor.pmt_stats())
        {
            pmt_err += si_err(st);
            pmt_ver_err += st.version_errors;
        }

        int64_t pcr_hard = 0, pcr_disc = 0, pcr_acc = 0, tstd_uf = 0, tstd_of = 0;
        for (auto &[pid, st] : stats)
        {
            pcr_hard += st.pcr_interval_hard_err;
            pcr_disc += st.pcr_discont_ind_errors;
            pcr_acc += st.pcr_accuracy_err;
            tstd_uf += st.tstd_underflows;
            tstd_of += st.tstd_overflows;
        }

        bool nit_on = !si_monitor.nit_is_disabled();
        bool eit_on = !si_monitor.eit_is_disabled();

        // {errors, applicable} per gated check, in report order.
        const struct { int64_t errors; bool applicable; } gated[] = {
            {ts.sync_byte_errors, true},                                    // 1.1
            {ts.sync_loss_events, true},                                    // 1.2
            {si_err(si_monitor.pat_stats()), true},                         // 1.3
            {si_monitor.pat_stats().version_errors, true},                  // 1.3a
            {ts.cc_errors, true},                                           // 1.4
            {pmt_err, true},                                                // 1.5
            {pmt_ver_err, true},                                            // 1.5a
            {ts.pid_absence_errors, true},                                  // 1.6
            {ts.transport_errors, true},                                    // 2.1
            {si_monitor.total_crc_errors(), true},                          // 2.2
            {pcr_hard, true},                                               // 2.3
            {pcr_disc, true},                                               // 2.4
            {pcr_acc, live},                                                // 2.5
            {pts_analyzer.total_pts_errors(), true},                        // 2.6
            {si_err(si_monitor.cat_stats()), si_monitor.scrambling_detected()}, // 2.7
            {si_err(si_monitor.nit_actual_stats()), nit_on},                // 3.1
            {si_err(si_monitor.nit_other_stats()),
             nit_on && si_monitor.nit_other_stats().seen_at_least_once},    // 3.2
            {si_err(si_monitor.sdt_actual_stats()), true},                  // 3.5
            {si_err(si_monitor.sdt_other_stats()),
             si_monitor.sdt_other_stats().seen_at_least_once},              // 3.6
            {si_err(si_monitor.eit_actual_pf_stats()), eit_on},             // 3.7
            {si_monitor.tdt_stats().interval_violations, true},             // 3.12
            {tstd_uf, live},                                                // 3.13
            {tstd_of, live},                                                // 3.14
            {si_monitor.total_section_size_errors(), true},                 // SI size
        };
        for (auto &c : gated)
            if (c.applicable && c.errors != 0)
                return false;

        if (live && duration_s >= DRIFT_HARD_FAIL_DURATION_S)
            for (auto &[pid, st] : stats)
                if (std::abs(st.drift_ppm) > 30.0)
                    return false;

        return true;
    }
};
