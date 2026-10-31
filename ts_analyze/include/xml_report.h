/*
 * Copyright 2026 Perfect Soft
 * SPDX-License-Identifier: Apache-2.0
 */
#pragma once
/*
 * xml_report.h — structured XML report generator for ts_analyze.
 *
 * Produces a single self-contained XML document on the supplied stream.
 * Intended for machine consumption (CI / monitoring): same data as the
 * human-readable Report::print, no ANSI colors, no diagnostic chatter.
 *
 * Returns true when OVERALL = PASS, false on FAIL — same contract as
 * Report::print, used by main() to set the process exit code.
 */

#include "ts_common.h"
#include "pcr_analyzer.h"
#include "si_parser.h"
#include "ts_checker.h"
#include "si_monitor.h"
#include "pts_analyzer.h"
#include "iat_analyzer.h"
#include "tr101290_defs.h"
#include "verdict.h"
#include "st2022_report.h"
#include "version.h"

#include <iostream>
#include <iomanip>
#include <string>
#include <sstream>
#include <ctime>
#include <set>
#include <cmath>

class XmlReport
{
public:
    /// XML report on stdout; <overall> and the return value come from Verdict::overall, the same as the text reports.
    static bool print(std::ostream &out,
            const PcrAnalyzer &analyzer,
            const SiParser &si,
            const TsChecker &ts_checker,
            const SiMonitor &si_monitor,
            const PtsAnalyzer &pts_analyzer,
            const IatAnalyzer &iat_analyzer,
            const std::set<uint16_t> &unreferenced_pids,
            const std::string &source,
            double duration_s,
            const St2022Summary *st2022 = nullptr)
    {
        const auto &stats = analyzer.stats();
        const auto &programs = si.programs();
        const auto &ts_stats = ts_checker.stats();
        bool is_file = analyzer.file_mode();
        const bool all_pass = Verdict::overall(analyzer, ts_checker, si_monitor,
                                               pts_analyzer, duration_s, st2022);

        char time_buf[32];
        std::time_t now = std::time(nullptr);
        std::strftime(time_buf, sizeof(time_buf), "%Y-%m-%dT%H:%M:%S%z", std::localtime(&now));

        double total_bytes = static_cast<double>(analyzer.total_packets()) * TS_PACKET_SIZE;
        double ts_bitrate  = (duration_s > 0) ? (total_bytes * 8.0) / duration_s : 0;

        out << "<?xml version=\"1.0\" encoding=\"UTF-8\"?>\n";
        out << "<ts_analyze version=\"" << TS_ANALYZE_VERSION << "\">\n";
        out << "  <source>" << esc(source) << "</source>\n";
        out << "  <timestamp>" << time_buf << "</timestamp>\n";
        out << "  <duration_s>" << fmt(duration_s, 2) << "</duration_s>\n";
        out << "  <packets total=\"" << analyzer.total_packets()
            << "\" null=\"" << analyzer.null_packets() << "\"/>\n";
        out << "  <ts_bitrate_mbps>" << fmt(ts_bitrate / 1e6, 3) << "</ts_bitrate_mbps>\n";

        // ── Programs ───────────────────────────────────────────────────
        out << "  <programs>\n";
        for (auto& [pn, pi] : programs)
        {
            out << "    <program number=\"" << pn
                << "\" pmt_pid=\"" << pid_hex(pi.pmt_pid) << "\"";
            if (pi.pcr_pid_known)
                out << " pcr_pid=\"" << pid_hex(pi.pcr_pid) << "\"";
            out << ">\n";
            for (auto &es : pi.es_list)
                out << "      <es pid=\"" << pid_hex(es.pid)
                    << "\" stream_type=\"0x" << std::hex << std::setw(2)
                    << std::setfill('0') << (int) es.stream_type << std::dec
                    << "\" name=\"" << esc(pi.stream_type_name(es.stream_type))
                    << "\"/>\n";
            out << "    </program>\n";
        }
        out << "  </programs>\n";

        // ── TR 101 290 checks ──────────────────────────────────────────
        out << "  <tr101290>\n";

        emit_check(out, "1.1",  "TS Sync Loss",
                   ts_stats.sync_loss_events, true);
        emit_check(out, "1.2",  "Sync Byte Error",
                   ts_stats.sync_byte_errors, true);
        {
            auto& ps = si_monitor.pat_stats();
            emit_check(out, "1.3",  "PAT Error",
                       ps.interval_violations, true);
        }
        emit_check(out, "PAT.version", "PAT version change",
                   si_monitor.pat_stats().version_errors, true);
        emit_check(out, "1.4",  "Continuity Count Error",
                   ts_stats.cc_errors, true);
        {
            int64_t pmt_err = 0;
            for (auto& [pid, st] : si_monitor.pmt_stats())
                pmt_err += st.interval_violations;
            emit_check(out, "1.5",  "PMT Error", pmt_err, true);
        }
        {
            int64_t pmt_ver_err = 0;
            for (auto& [pid, st] : si_monitor.pmt_stats())
                pmt_ver_err += st.version_errors;
            emit_check(out, "PMT.version", "PMT version change", pmt_ver_err, true);
        }
        emit_check(out, "1.6",  "PID Error (5s absence)",
                   ts_stats.pid_absence_errors, true);

        emit_check(out, "2.1",  "Transport Error", ts_stats.transport_errors, true);
        emit_check(out, "2.2",  "CRC Error", si_monitor.total_crc_errors(), true);

        // 2.3a: intervals above 40 ms (TR 101 290) are the
        // errors; the ISO 100 ms count is an attribute.
        {
            int64_t err = 0, iso = 0;
            for (auto& [pid, st] : stats) {
                err += st.pcr_interval_err;
                iso += st.pcr_interval_hard_err;
            }
            emit_check(out, "2.3a", "PCR Repetition Error", err, true,
                       " limit_ms=\"" + fmt(analyzer.pcr_interval_limit() * 1e3, 0)
                       + "\" iso_violations=\"" + std::to_string(iso) + "\"");
        }

        {
            int64_t pcr_disc_err = 0;
            for (auto& [pid, st] : stats) pcr_disc_err += st.pcr_discont_ind_errors;
            emit_check(out, "2.3b", "PCR Discontinuity Indicator Error",
                       pcr_disc_err, true);
        }
        {
            int64_t pcr_acc_err = 0;
            for (auto& [pid, st] : stats) pcr_acc_err += st.pcr_accuracy_err;
            emit_check(out, "2.4", "PCR Accuracy Error",
                       pcr_acc_err, !is_file);
        }
        emit_check(out, "2.5", "PTS Error", pts_analyzer.total_pts_errors(), true);
        {
            auto& cs = si_monitor.cat_stats();
            int64_t cat_err = cs.interval_violations;
            emit_check(out, "2.6", "CAT Error", cat_err,
                       si_monitor.scrambling_detected());
        }

        {
            auto& ns = si_monitor.nit_actual_stats();
            emit_check(out, "3.1a", "NIT Actual Error",
                       ns.interval_violations,
                       !si_monitor.nit_is_disabled());
        }
        {
            auto& ns = si_monitor.nit_other_stats();
            emit_check(out, "3.1b", "NIT Other Error",
                       ns.interval_violations,
                       ns.seen_at_least_once && !si_monitor.nit_is_disabled());
        }
        emit_info(out, "3.4", "Unreferenced PIDs",
                  static_cast<int64_t>(unreferenced_pids.size()));
        {
            auto& ss = si_monitor.sdt_actual_stats();
            emit_check(out, "3.5a", "SDT Actual Error",
                       ss.interval_violations, true);
        }
        {
            auto& ss = si_monitor.sdt_other_stats();
            emit_check(out, "3.5b", "SDT Other Error",
                       ss.interval_violations,
                       ss.seen_at_least_once);
        }
        {
            auto& es = si_monitor.eit_actual_pf_stats();
            emit_check(out, "3.6a", "EIT Actual P/F",
                       es.interval_violations,
                       !si_monitor.eit_is_disabled());
        }
        emit_check(out, "3.8", "TDT Error",
                   si_monitor.tdt_stats().interval_violations, true);

        {
            int64_t tstd_uf = 0;
            for (auto& [pid, st] : stats) tstd_uf += st.tstd_underflows;
            emit_check(out, "TSTD.under", "T-STD buffer underflow",
                       tstd_uf, !is_file);
        }
        {
            int64_t tstd_of = 0;
            for (auto& [pid, st] : stats) tstd_of += st.tstd_overflows;
            emit_check(out, "TSTD.over", "T-STD buffer overflow",
                       tstd_of, !is_file);
        }

        out << "  </tr101290>\n";

        // ── SI section size ────────────────────────────────────────────
        out << "  <si_section_size oversize_total=\""
            << si_monitor.total_section_size_errors()
            << "\" eit_stb_warn_total=\""
            << si_monitor.total_eit_stb_warnings() << "\">\n";
        emit_section(out, si_monitor.pat_stats());
        for (auto& [pid, st] : si_monitor.pmt_stats()) emit_section(out, st);
        emit_section(out, si_monitor.cat_stats());
        emit_section(out, si_monitor.nit_actual_stats());
        emit_section(out, si_monitor.nit_other_stats());
        emit_section(out, si_monitor.sdt_actual_stats());
        emit_section(out, si_monitor.sdt_other_stats());
        emit_section(out, si_monitor.eit_actual_pf_stats());
        emit_section(out, si_monitor.eit_other_pf_stats());
        for (auto& [tid, st] : si_monitor.eit_actual_sch_sub()) emit_section(out, st);
        for (auto& [tid, st] : si_monitor.eit_other_sch_sub())  emit_section(out, st);
        emit_section(out, si_monitor.tdt_stats());
        out << "  </si_section_size>\n";

        // ── UDP IAT (live network only) ────────────────────────────────
        if (!is_file && iat_analyzer.interval_count() > 0)
        {
            out << "  <iat datagrams=\"" << iat_analyzer.datagram_count()
                << "\" intervals=\"" << iat_analyzer.interval_count()
                << "\" min_ms=\""    << fmt(iat_analyzer.min() * 1e3, 3)
                << "\" max_ms=\""    << fmt(iat_analyzer.max() * 1e3, 3)
                << "\" avg_ms=\""    << fmt(iat_analyzer.avg() * 1e3, 3)
                << "\" stddev_ms=\"" << fmt(iat_analyzer.stddev() * 1e3, 3)
                << "\" p95_ms=\""    << fmt(iat_analyzer.percentile(0.95) * 1e3, 3)
                << "\" p99_ms=\""    << fmt(iat_analyzer.percentile(0.99) * 1e3, 3)
                << "\" max_jitter_ms=\"" << fmt(iat_analyzer.max_jitter() * 1e3, 3)
                << "\" gap_threshold_ms=\"" << fmt(IAT_GAP_THRESHOLD_S * 1e3, 1)
                << "\" gaps_over_threshold=\"" << iat_analyzer.gap_events()
                << "\"/>\n";
        }

        // ── Per-PCR-PID detail ─────────────────────────────────────────
        bool drift_measured    = !is_file && (duration_s >= ANALYSIS_FULL_DURATION_S);
        bool drift_hard_window = !is_file && (duration_s >= DRIFT_HARD_FAIL_DURATION_S);

        out << "  <pcr_pids>\n";
        for (auto& [pid, st] : stats)
        {
            int program_number = -1;
            for (auto& [pn, pi] : programs)
                if (pi.pcr_pid_known && pi.pcr_pid == pid) { program_number = pn; break; }

            out << "    <pcr_pid value=\"" << pid_hex(pid) << "\"";
            if (program_number >= 0)
                out << " sid=\"" << program_number << "\"";
            out << " pcr_count=\"" << st.pcr_count
                << "\" discontinuities=\"" << st.discontinuities
                << "\" estimated_bitrate_mbps=\"" << fmt(st.estimated_bitrate / 1e6, 3)
                << "\">\n";

            // Interval
            if (st.interval_count > 0) {
                bool intv_ok = (st.pcr_interval_err == 0);
                out << "      <interval samples=\""    << st.interval_count
                    << "\" min_ms=\""                  << fmt(st.interval_min * 1e3, 3)
                    << "\" max_ms=\""                  << fmt(st.interval_max * 1e3, 3)
                    << "\" avg_ms=\""                  << fmt(st.interval_avg() * 1e3, 3)
                    << "\" p95_ms=\""                  << fmt(st.interval_p95() * 1e3, 3)
                    << "\" iso_hard_violations=\""     << st.pcr_interval_hard_err
                    << "\" tr_soft_violations=\""      << st.pcr_interval_err
                    << "\" rec_violations=\""          << st.pcr_interval_warn
                    << "\" result=\""                  << pf(intv_ok)
                    << "\"/>\n";
            }

            // Accuracy
            if (!is_file && st.accuracy_count > 0) {
                bool acc_ok = (st.pcr_accuracy_err == 0);
                out << "      <accuracy samples=\""    << st.accuracy_count
                    << "\" min_ns=\""                  << fmt(st.accuracy_min * 1e9, 1)
                    << "\" max_ns=\""                  << fmt(st.accuracy_max * 1e9, 1)
                    << "\" abs_max_ns=\""              << fmt(st.accuracy_abs_max() * 1e9, 1)
                    << "\" avg_ns=\""                  << fmt(st.accuracy_avg() * 1e9, 1)
                    << "\" stddev_ns=\""               << fmt(st.accuracy_stddev() * 1e9, 1)
                    << "\" p95_ns=\""                  << fmt(st.accuracy_p95() * 1e9, 1)
                    << "\" violations=\""              << st.pcr_accuracy_err
                    << "\" result=\""                  << pf(acc_ok)
                    << "\"/>\n";
            }

            // Drift
            if (!is_file) {
                out << "      <drift";
                if (!drift_measured) {
                    out << " measured=\"false\""
                        << " reason=\"duration_below_30s\""
                        << " result=\"SKIP\"/>\n";
                } else {
                    bool drift_in_spec = (std::abs(st.drift_ppm) <= 30.0);
                    const char *result;
                    if (drift_in_spec)        result = "PASS";
                    else if (drift_hard_window) result = "FAIL";
                    else                      result = "WARN";
                    out << " measured=\"true\""
                        << " ppm=\""           << fmt(st.drift_ppm, 3)
                        << "\" limit_ppm=\"30\""
                        << " verdict_mode=\""  << (drift_hard_window ? "hard" : "informational")
                        << "\" result=\""      << result
                        << "\"/>\n";
                }
            }

            // T-STD
            if (!is_file) {
                bool tstd_ok = (st.tstd_overflows == 0);
                out << "      <tstd overflows=\""  << st.tstd_overflows
                    << "\" underflows=\""          << st.tstd_underflows
                    << "\" max_fill_bytes=\""      << fmt(st.tstd_buf_max, 0)
                    << "\" result=\""              << pf(tstd_ok)
                    << "\">\n";
                for (auto& [es_pid, buf] : analyzer.tstd_es_buffers()) {
                    if (buf.pcr_pid != pid) continue;
                    out << "        <es_buffer es_pid=\"" << pid_hex(es_pid)
                        << "\" stream_type=\"0x" << std::hex << std::setw(2)
                        << std::setfill('0') << (int) buf.stream_type << std::dec
                        << "\" capacity_bytes=\"" << fmt(buf.capacity, 0)
                        << "\" measuring=\""      << (buf.measuring ? "true" : "false");
                    if (buf.measuring) {
                        out << "\" es_bitrate_mbps=\"" << fmt(buf.drain_rate * 8.0 / 1e6, 3)
                            << "\" max_fill_bytes=\"" << fmt(buf.max_level, 0)
                            << "\" overflows=\""  << buf.overflows
                            << "\" underflows=\"" << buf.underflows;
                    }
                    out << "\"/>\n";
                }
                out << "      </tstd>\n";
            }

            out << "    </pcr_pid>\n";
        }
        out << "  </pcr_pids>\n";

        // ── Unreferenced PIDs (3.4 detail) ────────────────────────────
        out << "  <unreferenced_pids count=\"" << unreferenced_pids.size() << "\">\n";
        for (auto p : unreferenced_pids)
            out << "    <pid value=\"" << pid_hex(p) << "\"/>\n";
        out << "  </unreferenced_pids>\n";

        if (st2022 && st2022->enabled)
            St2022Report::xml(out, *st2022);

        // ── Overall ────────────────────────────────────────────────────
        out << "  <overall result=\"" << pf(all_pass) << "\"/>\n";
        out << "</ts_analyze>\n";
        return all_pass;
    }

private:
    static std::string esc(const std::string &s) {
        std::string r; r.reserve(s.size());
        for (char c : s) {
            switch (c) {
            case '<':  r += "&lt;";   break;
            case '>':  r += "&gt;";   break;
            case '&':  r += "&amp;";  break;
            case '"':  r += "&quot;"; break;
            case '\'': r += "&apos;"; break;
            default:   r += c;
            }
        }
        return r;
    }

    static std::string pid_hex(uint16_t pid) {
        std::ostringstream os;
        os << "0x" << std::hex << std::setw(4) << std::setfill('0') << pid;
        return os.str();
    }

    static std::string fmt(double v, int prec) {
        std::ostringstream os;
        os << std::fixed << std::setprecision(prec) << v;
        return os.str();
    }

    static const char *pf(bool ok) { return ok ? "PASS" : "FAIL"; }

    // Standard P-check element with PASS/FAIL/N/A.
    static void emit_check(std::ostream &out, const char *id, const char *name,
                           int64_t errors, bool applicable,
                           const std::string &extra_attrs = "")
    {
        bool ok = !applicable || (errors == 0);
        const char *result = !applicable ? "N/A" : (ok ? "PASS" : "FAIL");
        out << "    <check id=\"" << id
            << "\" name=\""       << esc(name)
            << "\" applicable=\"" << (applicable ? "true" : "false")
            << "\" errors=\""     << errors
            << "\" result=\""     << result << "\""
            << extra_attrs << "/>\n";
    }

    // Informational P-check (no PASS/FAIL, count only).
    static void emit_info(std::ostream &out, const char *id, const char *name,
                          int64_t count)
    {
        out << "    <check id=\"" << id
            << "\" name=\""       << esc(name)
            << "\" applicable=\"true\""
            << " count=\""        << count
            << "\" result=\"INFO\"/>\n";
    }

    static void emit_section(std::ostream &out, const SiTableStats &st)
    {
        if (!st.seen_at_least_once) return;
        bool is_eit = (st.section_std_limit == EIT_SECTION_MAX_BYTES);
        const char *verdict =
            (st.section_size_errors > 0) ? "ERROR" :
            (is_eit && st.section_size_warnings > 0) ? "WARN_STB" : "ok";
        out << "    <table name=\"" << esc(st.name)
            << "\" max_bytes=\""    << st.section_max_bytes
            << "\" std_limit=\""    << st.section_std_limit
            << "\" oversize=\""     << st.section_size_errors
            << "\" eit_stb_warn=\"" << (is_eit ? st.section_size_warnings : 0)
            << "\" result=\""       << verdict << "\"/>\n";
    }
};
