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
 *   TR 101 290 P1 1.1 1.2 1.3 1.4 1.5 1.6
 *              P2 2.1 2.2 2.3a 2.3b 2.4 (live) 2.5 2.6 (if scrambled)
 *              P3 3.1a (unless --no-nit) 3.1b (if seen) 3.5a 3.5b (if seen)
 *                 3.6a (unless --no-eit) 3.8
 *   PAT.version PMT.version, TSTD.under TSTD.over (live)
 *   SI.size: a section above the ISO/EN limit
 *   PCR drift beyond ±30 ppm in the hard window (live, >= 300 s)
 *   With --rtp / --fec / --path2: the applicable S.1-S.6 checks
 *   (st2022_checks.h).
 * Not gated: 3.4 unreferenced PIDs, 3.6b and EIT.sch_* (optional EIT, WARN
 *   only), SI.eit1024, IAT.gap.
 */

#include "ts_common.h"
#include "pcr_analyzer.h"
#include "ts_checker.h"
#include "si_monitor.h"
#include "pts_analyzer.h"
#include "tr101290_defs.h"
#include "st2022_checks.h"

#include <cmath>
#include <cstdint>
#include <vector>

struct Verdict
{
    struct Gated
    {
        const char *id;         // TR 101 290 check, or "SI.size"
        int64_t errors;
        bool applicable;

        bool fail() const { return applicable && errors != 0; }
    };

    /// The gated TR 101 290 checks with their counts, in report order: what OVERALL is made of.
    static std::vector<Gated> tr_checks(const PcrAnalyzer &analyzer,
                                        const TsChecker &ts_checker,
                                        const SiMonitor &si_monitor,
                                        const PtsAnalyzer &pts_analyzer)
    {
        const auto &stats = analyzer.stats();
        const auto &ts = ts_checker.stats();
        bool live = !analyzer.file_mode();

        auto si_err = [](const SiTableStats &st) {
            return st.interval_violations;
        };

        int64_t pmt_err = 0, pmt_ver_err = 0;
        for (auto &[pid, st] : si_monitor.pmt_stats())
        {
            pmt_err += si_err(st);
            pmt_ver_err += st.version_errors;
        }

        int64_t pcr_rep = 0, pcr_disc = 0, pcr_acc = 0, tstd_uf = 0, tstd_of = 0;
        for (auto &[pid, st] : stats)
        {
            pcr_rep += st.pcr_interval_err;
            pcr_disc += st.pcr_discont_ind_errors;
            pcr_acc += st.pcr_accuracy_err;
            tstd_uf += st.tstd_underflows;
            tstd_of += st.tstd_overflows;
        }

        bool nit_on = !si_monitor.nit_is_disabled();
        bool eit_on = !si_monitor.eit_is_disabled();

        return {
            {"1.1", ts.sync_loss_events, true},
            {"1.2", ts.sync_byte_errors, true},
            {"1.3", si_err(si_monitor.pat_stats()), true},
            {"PAT.version", si_monitor.pat_stats().version_errors, true},
            {"1.4", ts.cc_errors, true},
            {"1.5", pmt_err, true},
            {"PMT.version", pmt_ver_err, true},
            {"1.6", ts.pid_absence_errors, true},
            {"2.1", ts.transport_errors, true},
            {"2.2", si_monitor.total_crc_errors(), true},
            {"2.3a", pcr_rep, true},
            {"2.3b", pcr_disc, true},
            {"2.4", pcr_acc, live},
            {"2.5", pts_analyzer.total_pts_errors(), true},
            {"2.6", si_err(si_monitor.cat_stats()), si_monitor.scrambling_detected()},
            {"3.1a", si_err(si_monitor.nit_actual_stats()), nit_on},
            {"3.1b", si_err(si_monitor.nit_other_stats()),
             nit_on && si_monitor.nit_other_stats().seen_at_least_once},
            {"3.5a", si_err(si_monitor.sdt_actual_stats()), true},
            {"3.5b", si_err(si_monitor.sdt_other_stats()), si_monitor.sdt_other_stats().seen_at_least_once},
            {"3.6a", si_err(si_monitor.eit_actual_pf_stats()), eit_on},
            {"3.8", si_monitor.tdt_stats().interval_violations, true},
            {"TSTD.under", tstd_uf, live},
            {"TSTD.over", tstd_of, live},
            {"SI.size", si_monitor.total_section_size_errors(), true},
        };
    }

    /// PCR drift beyond ±30 ppm in the hard window (live, >= 300 s): gates OVERALL.
    static bool drift_fail(const PcrAnalyzer &analyzer, double duration_s)
    {
        if (analyzer.file_mode() || duration_s < DRIFT_HARD_FAIL_DURATION_S)
            return false;
        for (auto &[pid, st] : analyzer.stats())
            if (std::abs(st.drift_ppm) > 30.0)
                return true;
        return false;
    }

    /// OVERALL for every report mode and the exit code: all gated checks of the list above pass (P3 included).
    static bool overall(const PcrAnalyzer &analyzer,
                        const TsChecker &ts_checker,
                        const SiMonitor &si_monitor,
                        const PtsAnalyzer &pts_analyzer,
                        double duration_s,
                        const St2022Summary *st2022 = nullptr)
    {
        if (st2022 && st2022->enabled)
            for (const auto &c : st2022_checks(*st2022))
                if (c.fail())
                    return false;
        for (const auto &c : tr_checks(analyzer, ts_checker, si_monitor, pts_analyzer))
            if (c.fail())
                return false;
        return !drift_fail(analyzer, duration_s);
    }
};
