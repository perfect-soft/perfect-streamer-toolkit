/*
 * Copyright 2026 Perfect Soft
 * SPDX-License-Identifier: Apache-2.0
 */
#pragma once
/*
 * report.h — Report generator (full & short modes)
 *
 * Full TR 101 290 compliance report with Priority 1/2/3 sections.
 * Version is taken from version.h.
 */

#include "ts_common.h"
#include "pcr_analyzer.h"
#include "si_parser.h"
#include "ts_checker.h"
#include "si_monitor.h"
#include "pts_analyzer.h"
#include "iat_analyzer.h"
#include "verdict.h"
#include "version.h"

#include <iostream>
#include <iomanip>
#include <string>
#include <sstream>
#include <ctime>
#include <set>

class Report
{
public:
    enum Mode
    {
        FULL, SHORT
    };

    // Returns true when OVERALL compliance is PASS, false on FAIL — used
    // by the CLI to set a non-zero exit code on standards violations.
    /// Text report (FULL or SHORT layout); OVERALL and the return value come from Verdict::overall, never from the printed lines.
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
            Mode mode)
    {
        auto now = std::time(nullptr);
        // localtime_r writes into a caller-supplied tm — std::localtime
        // returns a pointer to a process-wide static buffer that another
        // thread can overwrite between the call and the consumption inside
        // strftime. ts_analyze itself is single-threaded today but this
        // header lives in a public include directory and may be reused
        // from multi-threaded callers.
        std::tm tm_buf;
        localtime_r(&now, &tm_buf);
        char time_buf[64];
        std::strftime(time_buf, sizeof(time_buf), "%Y-%m-%d %H:%M:%S %Z", &tm_buf);

        const bool all_pass = Verdict::overall(analyzer, ts_checker, si_monitor,
                                               pts_analyzer, duration_s);

        if (mode == FULL)
            print_full(out, analyzer, si, ts_checker, si_monitor, pts_analyzer, iat_analyzer,
                       unreferenced_pids, source, duration_s, time_buf, all_pass);
        else
            print_short(out, analyzer, si, ts_checker, si_monitor, pts_analyzer, iat_analyzer,
                        unreferenced_pids, source, duration_s, time_buf, all_pass);
        return all_pass;
    }

private:
    static void separator(std::ostream &out, char ch = '=', int w = 72)
    {
        out << std::string(w, ch) << "\n";
    }

    static std::string stream_type_label(uint8_t st)
    {
        switch (st)
        {
        case 0x01: case 0x02: return "MPEG-2 Video";
        case 0x03: case 0x04: return "MPEG-2 Audio";
        case 0x06: return "PES private";
        case 0x0F: return "AAC Audio";
        case 0x10: return "MPEG-4 Visual";
        case 0x11: return "MPEG-4 AAC";
        case 0x1B: return "H.264/AVC";
        case 0x24: return "H.265/HEVC";
        case 0x25: return "H.266/VVC";
        default:   return "type=" + std::to_string(st);
        }
    }

    // ─── TR 101 290 check line helper ──────────────────────────────────
    static void check_line(std::ostream &out, const char* id, const char* name,
                           int64_t errors, bool applicable,
                           const std::string &detail = "")
    {
        bool ok = !applicable || (errors == 0);
        const char *verdict = !applicable ? "N/A" : (ok ? "PASS" : "FAIL");
        const char *verdict_color = !applicable ? nullptr
                                                : (ok ? Color::GREEN : Color::RED);

        out << "  |  " << std::left << std::setw(6) << id
            << std::setw(30) << name << ": ";
        if (!applicable)
            out << std::setw(17) << "N/A";
        else
            out << std::right << std::setw(8) << errors
                << "         ";
        out << Color::padded(verdict_color, verdict, 6);
        if (!detail.empty())
            out << "  " << detail;
        out << "\n";
    }

    static void check_line_info(std::ostream &out, const char* id, const char* name,
                                int64_t count, const std::string &detail = "")
    {
        out << "  |  " << std::left << std::setw(6) << id
            << std::setw(30) << name << ": "
            << std::right << std::setw(8) << count
            << "         INFO";
        if (!detail.empty())
            out << "  " << detail;
        out << "\n";
    }

    static void check_line_warn(std::ostream &out, const char* id, const char* name,
                                int64_t count, const std::string &detail = "")
    {
        out << "  |  " << std::left << std::setw(6) << id
            << std::setw(30) << name << ": "
            << std::right << std::setw(8) << count
            << "         " << Color::wrap(Color::YELLOW, "WARN");
        if (!detail.empty())
            out << "  " << detail;
        out << "\n";
    }

    // Print a table's section size stats (one line)
    static void section_size_line(std::ostream &out, const SiTableStats& st) {
        if (!st.seen_at_least_once) return;
        bool is_eit = (st.section_std_limit == EIT_SECTION_MAX_BYTES);

        out << "  |  " << std::left << std::setw(20) << st.name
            << "  max=" << std::right << std::setw(5) << st.section_max_bytes << " B"
            << "  limit=" << std::setw(5) << st.section_std_limit << " B";
        if (st.section_size_errors > 0)
            out << "  oversize=" << st.section_size_errors << " "
                << Color::wrap(Color::RED, "ERROR");
        if (is_eit && st.section_size_warnings > 0)
            out << "  >1024=" << st.section_size_warnings << " "
                << Color::wrap(Color::YELLOW, "WARN(STB)");
        if (st.section_size_errors == 0 && !(is_eit && st.section_size_warnings > 0))
            out << "  ok";
        out << "\n";
    }

    // ─── Full report ───────────────────────────────────────────────────
    static void print_full(std::ostream &out,
            const PcrAnalyzer &analyzer,
            const SiParser &si,
            const TsChecker &ts_checker,
            const SiMonitor &si_monitor,
            const PtsAnalyzer &pts_analyzer,
            const IatAnalyzer &iat_analyzer,
            const std::set<uint16_t> &unreferenced_pids,
            const std::string &source,
            double duration_s,
            const char *time_str,
            bool all_pass)
    {
        const auto &stats = analyzer.stats();
        const auto &programs = si.programs();
        const auto &ts_stats = ts_checker.stats();
        bool is_file = analyzer.file_mode();

        separator(out);
        out << "  MPEG-TS ANALYZER v" TS_ANALYZE_VERSION " — TR 101 290 FULL REPORT\n"
            << "  Perfect Streamer Toolkit https://meshwork.pstreamer.tv\n";
        separator(out);

        out << "  Source     : " << source << "\n"
            << "  Timestamp  : " << time_str << "\n"
            << "  Duration   : " << std::fixed << std::setprecision(2) << duration_s << " s\n"
            << "  Packets    : " << analyzer.total_packets() << " total, "
            << analyzer.null_packets() << " null\n";

        double total_bytes = static_cast<double>(analyzer.total_packets()) * TS_PACKET_SIZE;
        double ts_bitrate = (duration_s > 0) ? (total_bytes * 8.0) / duration_s : 0;
        out << "  TS bitrate : " << std::fixed << std::setprecision(3) << (ts_bitrate / 1e6) << " Mbit/s\n";

        // Duration adequacy warning
        if (duration_s < ANALYSIS_P3_DURATION_S)
            out << "  " << Color::wrap(Color::YELLOW, "WARNING")
                << "    : short duration — P3 interval checks "
                   "(NIT, EIT schedule, PID absence) may be unreliable\n";
        else if (duration_s < ANALYSIS_FULL_DURATION_S)
            out << "  NOTE       : TDT interval check (30s) may have insufficient data\n";

        separator(out, '-');

        // ── Program table ───────────────────────────────────────────
        out << "  PROGRAMS DETECTED\n";
        separator(out, '-');
        for (auto& [pn, pi] : programs)
        {
            out << "  Program " << pn
                << "  PMT PID=" << format_pid(pi.pmt_pid)
                << "  PCR PID=" << (pi.pcr_pid_known ? format_pid(pi.pcr_pid) : "unknown") << "\n";
            for (auto &es : pi.es_list)
            {
                out << "    ES PID=" << format_pid(es.pid) << "  "
                    << pi.stream_type_name(es.stream_type) << "\n";
            }
        }
        separator(out, '-');

        // ════════════════════════════════════════════════════════════════
        //  TR 101 290 PRIORITY 1 — TS DECODABILITY
        // ════════════════════════════════════════════════════════════════
        out << "\n";
        separator(out);
        out << "  TR 101 290 — PRIORITY 1 (TS decodability)\n";
        separator(out);

        // P1.1 TS sync byte error
        check_line(out, "1.1", "TS Sync Byte",
                   ts_stats.sync_byte_errors, true);

        // P1.2 Sync byte error (sync loss)
        check_line(out, "1.2", "Sync Byte (sync loss)",
                   ts_stats.sync_loss_events, true);

        // P1.3 PAT error
        {
            auto& ps = si_monitor.pat_stats();
            int64_t pat_err = ps.interval_violations + ps.crc_errors;
            check_line(out, "1.3", "PAT",
                       pat_err, true);
        }

        // P1.3a PAT error 2 (version)
        check_line(out, "1.3a", "PAT Version",
                   si_monitor.pat_stats().version_errors, true);

        // P1.4 Continuity Count Error
        {
            std::string cc_detail;
            if (ts_stats.cc_errors > 0) {
                cc_detail = "PIDs:";
                int n = 0;
                for (auto& [pid, cnt] : ts_stats.cc_errors_per_pid) {
                    if (n++ > 5) { cc_detail += " ..."; break; }
                    cc_detail += " " + format_pid(pid) + "(" + std::to_string(cnt) + ")";
                }
            }
            check_line(out, "1.4", "Continuity Count",
                       ts_stats.cc_errors, true, cc_detail);
        }

        // P1.5 PMT error
        {
            int64_t pmt_err = 0;
            for (auto& [pid, st] : si_monitor.pmt_stats())
                pmt_err += st.interval_violations + st.crc_errors;
            check_line(out, "1.5", "PMT",
                       pmt_err, true);
        }

        // P1.5a PMT error 2 (version)
        {
            int64_t pmt_ver_err = 0;
            for (auto& [pid, st] : si_monitor.pmt_stats())
                pmt_ver_err += st.version_errors;
            check_line(out, "1.5a", "PMT Version",
                       pmt_ver_err, true);
        }

        // P1.6 PID error
        {
            std::string pid_detail;
            if (!ts_stats.pid_absent_set.empty()) {
                pid_detail = "absent:";
                for (auto pid : ts_stats.pid_absent_set)
                    pid_detail += " " + format_pid(pid);
            }
            check_line(out, "1.6", "PID Absence (5s)",
                       ts_stats.pid_absence_errors, true, pid_detail);
        }

        // ════════════════════════════════════════════════════════════════
        //  TR 101 290 PRIORITY 2 — RECOMMENDED MONITORING
        // ════════════════════════════════════════════════════════════════
        out << "\n";
        separator(out);
        out << "  TR 101 290 — PRIORITY 2 (recommended monitoring)\n";
        separator(out);

        // P2.1 Transport error indicator
        {
            std::string tei_detail;
            if (ts_stats.transport_errors > 0) {
                tei_detail = "PIDs:";
                int n = 0;
                for (auto pid : ts_stats.tei_pids) {
                    if (n++ > 5) { tei_detail += " ..."; break; }
                    tei_detail += " " + format_pid(pid);
                }
            }
            check_line(out, "2.1", "Transport (TEI)",
                       ts_stats.transport_errors, true, tei_detail);
        }

        // P2.2 CRC error
        check_line(out, "2.2", "CRC",
                   si_monitor.total_crc_errors(), true);

        // P2.3 PCR repetition error.
        // OVERALL gate uses the ISO 13818-1 §2.4.2.2 hard limit (100 ms).
        // The TR 101 290 P2.3 recommendation (default 40 ms) is reported
        // separately in the per-PCR-PID detail and as a soft warning here.
        {
            int64_t pcr_hard_err = 0;
            int64_t pcr_soft_err = 0;
            for (auto& [pid, st] : stats) {
                pcr_hard_err += st.pcr_interval_hard_err;
                pcr_soft_err += st.pcr_interval_err;
            }
            check_line(out, "2.3", "PCR Repetition",
                       pcr_hard_err, true);
            if (pcr_hard_err == 0 && pcr_soft_err > 0)
                check_line_warn(out, "2.3a", "PCR Repetition (>40ms)",
                                pcr_soft_err, "within ISO 100 ms hard limit");
        }

        // P2.4 PCR discontinuity indicator error
        {
            int64_t pcr_disc_err = 0;
            for (auto& [pid, st] : stats)
                pcr_disc_err += st.pcr_discont_ind_errors;
            check_line(out, "2.4", "PCR Discont. Indicator",
                       pcr_disc_err, true);
        }

        // P2.5 PCR accuracy error
        {
            int64_t pcr_acc_err = 0;
            for (auto& [pid, st] : stats)
                pcr_acc_err += st.pcr_accuracy_err;
            check_line(out, "2.5", "PCR Accuracy",
                       pcr_acc_err, !is_file);
        }

        // P2.6 PTS error
        check_line(out, "2.6", "PTS Interval",
                   pts_analyzer.total_pts_errors(), true);

        // P2.7 CAT error
        {
            auto& cs = si_monitor.cat_stats();
            int64_t cat_err = cs.interval_violations + cs.crc_errors;
            bool cat_applicable = si_monitor.scrambling_detected();
            check_line(out, "2.7", "CAT",
                       cat_err, cat_applicable);
        }

        // ════════════════════════════════════════════════════════════════
        //  TR 101 290 PRIORITY 3 — EXTENDED MONITORING
        // ════════════════════════════════════════════════════════════════
        out << "\n";
        separator(out);
        out << "  TR 101 290 — PRIORITY 3 (extended monitoring)\n";
        separator(out);

        // P3.1 NIT actual
        {
            auto& ns = si_monitor.nit_actual_stats();
            int64_t nit_err = ns.interval_violations + ns.crc_errors;
            std::string detail = si_monitor.nit_is_disabled() ? "disabled (--no-nit)" : "";
            check_line(out, "3.1", "NIT Actual",
                       nit_err, !si_monitor.nit_is_disabled(), detail);
        }

        // P3.2 NIT other
        {
            auto& ns = si_monitor.nit_other_stats();
            bool seen = ns.seen_at_least_once;
            int64_t nit_err = ns.interval_violations + ns.crc_errors;
            bool applicable = seen && !si_monitor.nit_is_disabled();
            std::string detail = si_monitor.nit_is_disabled() ? "disabled (--no-nit)" : "";
            check_line(out, "3.2", "NIT Other",
                       nit_err, applicable, detail);
        }

        // P3.4 Unreferenced PID
        check_line_info(out, "3.4", "Unreferenced PIDs",
                        static_cast<int64_t>(unreferenced_pids.size()));

        // P3.5 SDT actual
        {
            auto& ss = si_monitor.sdt_actual_stats();
            int64_t sdt_err = ss.interval_violations + ss.crc_errors;
            check_line(out, "3.5", "SDT Actual",
                       sdt_err, true);
        }

        // P3.6 SDT other
        {
            auto& ss = si_monitor.sdt_other_stats();
            bool seen = ss.seen_at_least_once;
            int64_t sdt_err = ss.interval_violations + ss.crc_errors;
            check_line(out, "3.6", "SDT Other",
                       sdt_err, seen);
        }

        // P3.7 EIT actual p/f — mandatory, ERROR if absent or interval > 2s
        {
            auto& es = si_monitor.eit_actual_pf_stats();
            int64_t eit_err = es.interval_violations + es.crc_errors;
            std::string detail = si_monitor.eit_is_disabled() ? "disabled (--no-eit)" : "";
            check_line(out, "3.7", "EIT Actual P/F",
                       eit_err, !si_monitor.eit_is_disabled(), detail);
        }

        // P3.8 EIT other p/f — optional, WARN only
        if (si_monitor.eit_is_disabled()) {
            check_line(out, "3.8", "EIT Other P/F", 0, false,
                       "disabled (--no-eit)");
        } else {
            auto& es = si_monitor.eit_other_pf_stats();
            if (es.seen_at_least_once) {
                int64_t eit_w = es.interval_violations + es.crc_errors;
                if (eit_w > 0)
                    check_line_warn(out, "3.8", "EIT Other P/F",
                                    eit_w, "interval limit 20s");
                else
                    check_line(out, "3.8", "EIT Other P/F",
                               0, true);
            } else {
                check_line(out, "3.8", "EIT Other P/F", 0, false);
            }
        }

        // P3.9 EIT actual schedule — optional, per sub-table, WARN only
        if (si_monitor.eit_is_disabled()) {
            check_line(out, "3.9", "EIT Actual Schedule", 0, false,
                       "disabled (--no-eit)");
        } else {
            auto agg = si_monitor.eit_actual_sch_aggregated();
            if (agg.any_seen) {
                std::string detail = std::to_string(agg.sub_tables_seen) + " sub-tables";
                if (agg.sub_tables_with_violations > 0)
                    detail += ", " + std::to_string(agg.sub_tables_with_violations)
                            + " exceed 10s limit"
                            + " (worst " + format_ms(agg.worst_max_interval) + ")";
                int64_t total_w = agg.total_interval_violations + agg.total_crc_errors;
                if (total_w > 0)
                    check_line_warn(out, "3.9", "EIT Actual Schedule", total_w, detail);
                else
                    check_line(out, "3.9", "EIT Actual Schedule", 0, true, detail);
            } else {
                check_line(out, "3.9", "EIT Actual Schedule", 0, false);
            }
        }

        // P3.10 EIT other schedule — optional, per sub-table, WARN only
        if (si_monitor.eit_is_disabled()) {
            check_line(out, "3.10", "EIT Other Schedule", 0, false,
                       "disabled (--no-eit)");
        } else {
            auto agg = si_monitor.eit_other_sch_aggregated();
            if (agg.any_seen) {
                std::string detail = std::to_string(agg.sub_tables_seen) + " sub-tables";
                if (agg.sub_tables_with_violations > 0)
                    detail += ", " + std::to_string(agg.sub_tables_with_violations)
                            + " exceed 10s limit";
                int64_t total_w = agg.total_interval_violations + agg.total_crc_errors;
                if (total_w > 0)
                    check_line_warn(out, "3.10", "EIT Other Schedule", total_w, detail);
                else
                    check_line(out, "3.10", "EIT Other Schedule", 0, true, detail);
            } else {
                check_line(out, "3.10", "EIT Other Schedule", 0, false);
            }
        }

        // P3.12 TDT error
        {
            auto& ts = si_monitor.tdt_stats();
            int64_t tdt_err = ts.interval_violations;
            check_line(out, "3.12", "TDT",
                       tdt_err, true);
        }

        // P3.13 Empty buffer error (T-STD underflow)
        {
            int64_t tstd_uf = 0;
            for (auto& [pid, st] : stats)
                tstd_uf += st.tstd_underflows;
            check_line(out, "3.13", "Empty Buffer (T-STD)",
                       tstd_uf, !is_file);
        }

        // P3.14 Data delay error (T-STD overflow)
        {
            int64_t tstd_of = 0;
            for (auto& [pid, st] : stats)
                tstd_of += st.tstd_overflows;
            check_line(out, "3.14", "Data Delay (T-STD)",
                       tstd_of, !is_file);
        }

        // ════════════════════════════════════════════════════════════════
        //  SI SECTION SIZE CHECK
        // ════════════════════════════════════════════════════════════════
        {
            int64_t size_err  = si_monitor.total_section_size_errors();
            int64_t stb_warn  = si_monitor.total_eit_stb_warnings();

            out << "\n";
            separator(out);
            out << "  SI SECTION SIZE (ISO 13818-1, EN 300 468)\n";
            separator(out);

            section_size_line(out, si_monitor.pat_stats());
            for (auto& [pid, st] : si_monitor.pmt_stats())
                section_size_line(out, st);
            section_size_line(out, si_monitor.cat_stats());
            section_size_line(out, si_monitor.nit_actual_stats());
            section_size_line(out, si_monitor.nit_other_stats());
            section_size_line(out, si_monitor.sdt_actual_stats());
            section_size_line(out, si_monitor.sdt_other_stats());
            section_size_line(out, si_monitor.eit_actual_pf_stats());
            section_size_line(out, si_monitor.eit_other_pf_stats());
            for (auto& [tid, st] : si_monitor.eit_actual_sch_sub())
                section_size_line(out, st);
            for (auto& [tid, st] : si_monitor.eit_other_sch_sub())
                section_size_line(out, st);
            section_size_line(out, si_monitor.tdt_stats());

            if (size_err > 0)
                out << "  |  TOTAL: " << size_err << " sections exceed standard limit  "
                    << Color::wrap(Color::RED, "FAIL") << "\n";
            if (stb_warn > 0)
                out << "  |  " << Color::wrap(Color::YELLOW, "WARNING") << ": "
                    << stb_warn << " EIT sections > 1024 B (STB compatibility risk)\n";
            if (size_err == 0 && stb_warn == 0)
                out << "  |  All sections within standard limits\n";
        }

        // ════════════════════════════════════════════════════════════════
        //  UDP DATAGRAM IAT (network jitter) — live network input only
        // ════════════════════════════════════════════════════════════════
        if (!is_file)
        {
            out << "\n";
            separator(out);
            out << "  UDP DATAGRAM IAT (Inter-Arrival Time)\n";
            separator(out);

            int64_t dgram_n   = iat_analyzer.datagram_count();
            int64_t intv_n    = iat_analyzer.interval_count();
            int64_t gap_n     = iat_analyzer.gap_events();

            if (intv_n == 0)
            {
                out << "  |  No datagrams received (cannot compute IAT)\n";
            }
            else
            {
                out << "  |  Datagrams   : " << dgram_n << "\n"
                    << "  |  Intervals   : " << intv_n << "\n"
                    << "  |  Min IAT     : " << format_ms(iat_analyzer.min())    << "\n"
                    << "  |  Max IAT     : " << format_ms(iat_analyzer.max())    << "\n"
                    << "  |  Average     : " << format_ms(iat_analyzer.avg())    << "\n"
                    << "  |  Std dev     : " << format_ms(iat_analyzer.stddev()) << "\n"
                    << "  |  95th pctl   : " << format_ms(iat_analyzer.percentile(0.95)) << "\n"
                    << "  |  99th pctl   : " << format_ms(iat_analyzer.percentile(0.99)) << "\n"
                    << "  |  Max jitter  : " << format_ms(iat_analyzer.max_jitter())
                    << "  (peak |IAT - mean|)\n"
                    << "  |  Gap thresh. : " << format_ms(IAT_GAP_THRESHOLD_S) << "\n"
                    << "  |  Gaps>thresh : " << gap_n;
                if (gap_n > 0)
                    out << "   " << Color::wrap(Color::YELLOW, "WARN")
                        << "  (likely network outage or burst loss)";
                out << "\n";
            }
        }

        // ════════════════════════════════════════════════════════════════
        //  DETAILED PCR ANALYSIS PER PID
        // ════════════════════════════════════════════════════════════════
        for (auto& [pid, st] : stats)
        {
            out << "\n";
            separator(out, '-');
            out << "  PCR PID " << format_pid(pid);
            for (auto& [pn, pi] : programs)
            {
                if (pi.pcr_pid_known && pi.pcr_pid == pid)
                    out << "  SID " << pn;
            }
            out << "\n";
            separator(out, '-');

            out << "  PCR packets received  : " << st.pcr_count << "\n"
                << "  Discontinuities       : " << st.discontinuities << "\n"
                << "  Estimated bitrate     : " << std::fixed << std::setprecision(3)
                << (st.estimated_bitrate / 1e6) << " Mbit/s\n\n";

            // ── PCR Interval ────────────────────────────────────────
            out << "  +-  PCR INTERVAL (TR 101 290 P1.4) -----------------\n";
            if (st.interval_count > 0)
            {
                bool interval_ok = (st.pcr_interval_hard_err == 0);

                double intv_limit = analyzer.pcr_interval_limit();
                bool custom_limit = (intv_limit != TR101290_PCR_INTERVAL_MAX_S);

                out << "  |  Samples     : " << st.interval_count << "\n"
                    << "  |  Min         : " << format_ms(st.interval_min) << "\n"
                    << "  |  Max         : " << format_ms(st.interval_max) << "\n"
                    << "  |  Average     : " << format_ms(st.interval_avg()) << "\n"
                    << "  |  95th pctl   : " << format_ms(st.interval_p95()) << "\n"
                    << "  |  Limits      : " << format_ms(ISO13818_PCR_HARD_MAX_S)
                    << " (ISO hard), " << format_ms(intv_limit)
                    << " (TR 101 290" << (custom_limit ? " custom" : "") << "), "
                    << format_ms(TR101290_PCR_INTERVAL_REC_S) << " (rec)\n"
                    << "  |  Violations  : " << st.pcr_interval_hard_err
                    << " (>" << format_ms(ISO13818_PCR_HARD_MAX_S) << " ISO), "
                    << st.pcr_interval_err << " (>" << format_ms(intv_limit) << " TR), "
                    << st.pcr_interval_warn << " (>25ms rec)\n"
                    << "  |  Result      : " << pass_fail(interval_ok) << "\n";
            }
            else
            {
                out << "  |  No PCR intervals measured\n";
            }
            out << "  +---------------------------------------------------\n\n";

            // ── PCR Accuracy ────────────────────────────────────────
            out << "  +-  PCR ACCURACY (TR 101 290 P2.5) -----------------\n";
            if (is_file)
            {
                out << "  |  Not measured (file mode — no reference clock)\n";
            }
            else if (st.accuracy_count > 0)
            {
                out << "  |  Samples     : " << st.accuracy_count << "\n"
                    << "  |  Min offset  : " << format_ns(st.accuracy_min) << "\n"
                    << "  |  Max offset  : " << format_ns(st.accuracy_max) << "\n"
                    << "  |  Abs max     : " << format_ns(st.accuracy_abs_max()) << "\n"
                    << "  |  Average     : " << format_ns(st.accuracy_avg()) << "\n"
                    << "  |  Std dev     : " << format_ns(st.accuracy_stddev()) << "\n"
                    << "  |  95th pctl   : " << format_ns(st.accuracy_p95()) << "\n"
                    << "  |  Limit       : +-" << format_ns(TR101290_PCR_ACCURACY_S) << "\n"
                    << "  |  Violations  : " << st.pcr_accuracy_err << "\n"
                    << "  |  Result      : " << pass_fail(st.pcr_accuracy_err == 0) << "\n";
            }
            else
            {
                out << "  |  No accuracy measurements available\n";
            }
            out << "  +---------------------------------------------------\n\n";

            // ── PCR Drift ────────────────────────────────────────────
            // Standard: ISO/IEC 13818-1 §2.4.2.1 + ETSI TR 101 290 — PCR
            // clock tolerance is ±30 ppm. Two-tier confidence gating:
            //   < 30 s     skip (noise dominates the ±30 ppm window)
            //   30..300 s  measured; out-of-spec → WARN, doesn't gate OVERALL
            //   ≥ 300 s    measured; out-of-spec → FAIL, gates OVERALL
            // 300 s acceptance-test window (product default;
            // TR 101 290 fixes no measurement interval).
            out << "  +-  PCR DRIFT (ISO 13818-1 / TR 101 290) -----------\n";
            if (is_file)
            {
                out << "  |  Not measured (file mode — no reference clock)\n";
            }
            else if (duration_s < ANALYSIS_FULL_DURATION_S)
            {
                out << "  |  Skipped — analysis duration "
                    << std::fixed << std::setprecision(1) << duration_s
                    << " s is below the " << std::setprecision(0)
                    << ANALYSIS_FULL_DURATION_S << " s required for a\n"
                    << "  |          reliable ±30 ppm measurement. Re-run with "
                    << "-t " << std::setprecision(0)
                    << ANALYSIS_FULL_DURATION_S << " or longer; for high\n"
                    << "  |          confidence (≤2 ppm uncertainty) use -t "
                    << std::setprecision(0) << DRIFT_HARD_FAIL_DURATION_S << ".\n";
            }
            else
            {
                double accum_us = st.drift_ppm * duration_s;
                bool drift_in_spec = (std::abs(st.drift_ppm) <= 30.0);
                bool hard_window   = (duration_s >= DRIFT_HARD_FAIL_DURATION_S);

                out << "  |  Drift rate   : " << std::fixed << std::setprecision(3)
                    << st.drift_ppm << " ppm\n"
                    << "  |  Accumulated  : " << std::fixed << std::setprecision(1)
                    << accum_us << " us over " << std::setprecision(1)
                    << duration_s << " s\n"
                    << "  |  Limit        : +-30 ppm (ISO 13818-1 §2.4.2.1)\n"
                    << "  |  Verdict mode : "
                    << (hard_window
                            ? std::string("hard (T >= ")
                                  + std::to_string((int) DRIFT_HARD_FAIL_DURATION_S)
                                  + " s) — out-of-spec drift FAILs OVERALL"
                            : std::string("informational (")
                                  + std::to_string((int) ANALYSIS_FULL_DURATION_S)
                                  + " s <= T < "
                                  + std::to_string((int) DRIFT_HARD_FAIL_DURATION_S)
                                  + " s) — out-of-spec drift WARNs, does not affect OVERALL")
                    << "\n";
                if (drift_in_spec) {
                    out << "  |  Result       : " << pass_fail(true) << "\n";
                } else if (hard_window) {
                    out << "  |  Result       : " << pass_fail(false) << "\n"
                        << "  |  Note         : high drift may indicate stuffing or clock mismatch\n";
                } else {
                    out << "  |  Result       : " << Color::wrap(Color::YELLOW, "WARN")
                        << "  (re-run with -t "
                        << (int) DRIFT_HARD_FAIL_DURATION_S
                        << " for hard verdict)\n";
                }
            }
            out << "  +---------------------------------------------------\n\n";

            // ── T-STD ───────────────────────────────────────────────
            out << "  +-  T-STD BUFFER MODEL (ISO 13818-1 S2.4.2) --------\n";
            if (is_file)
            {
                out << "  |  Not measured (file mode — no real-time packet timing)\n";
            }
            else
            {
                auto print_es_buffers = [&](const std::map<uint16_t, TstdEsBuffer>& bufs) {
                    for (auto& [es_pid, buf] : bufs)
                    {
                        if (buf.pcr_pid != pid) continue;
                        out << "  |\n";
                        out << "  |  ES PID " << format_pid(es_pid) << "  "
                            << stream_type_label(buf.stream_type) << "\n";
                        out << "  |    Buffer cap : " << std::fixed << std::setprecision(0)
                            << buf.capacity << " bytes\n";
                        if (buf.measuring)
                        {
                            double drain_mbps = (buf.drain_rate * 8.0) / 1e6;
                            out << "  |    ES bitrate : " << std::fixed << std::setprecision(3)
                                << drain_mbps << " Mbit/s (measured)\n";
                            out << "  |    Max fill   : " << std::fixed << std::setprecision(0)
                                << buf.max_level << " bytes";
                            if (buf.capacity > 0)
                                out << " (" << std::setprecision(1)
                                    << (buf.max_level / buf.capacity * 100.0) << "%)";
                            out << "\n";
                            out << "  |    Overflows  : " << buf.overflows << "\n";
                            out << "  |    Underflows : " << buf.underflows << "\n";
                        }
                        else
                        {
                            out << "  |    (warmup not complete)\n";
                        }
                    }
                };

                print_es_buffers(analyzer.tstd_es_buffers());
                print_es_buffers(analyzer.tstd_legacy_buffers());

                out << "  |\n";
                bool tstd_ok = (st.tstd_overflows == 0);
                out << "  |  Total overflows  : " << st.tstd_overflows << "\n"
                    << "  |  Total underflows : " << st.tstd_underflows << " (informational)\n"
                    << "  |  Result           : " << pass_fail(tstd_ok) << "\n";
            }
            out << "  +---------------------------------------------------\n";
        }

        // ── PTS per-ES details ──────────────────────────────────────
        if (!pts_analyzer.stats().empty())
        {
            out << "\n";
            separator(out, '-');
            out << "  PTS INTERVAL DETAILS (TR 101 290 P2.6)\n";
            separator(out, '-');
            for (auto& [es_pid, ps] : pts_analyzer.stats())
            {
                if (ps.pts_count == 0) continue;
                out << "  ES PID " << format_pid(es_pid)
                    << "  PTS count=" << ps.pts_count
                    << "  max interval=" << format_ms(ps.pts_max_interval_s)
                    << "  avg=" << format_ms(ps.pts_avg_interval_s())
                    << "  violations=" << ps.pts_interval_errors
                    << "  " << pass_fail(ps.pts_interval_errors == 0) << "\n";
            }
        }

        // ── Overall ─────────────────────────────────────────────────
        out << "\n";
        separator(out);
        out << "  OVERALL COMPLIANCE: " << pass_fail(all_pass);
        if (all_pass)
            out << "  — stream is TR 101 290 compliant\n";
        else
            out << "  — standard violations detected\n";
        separator(out);
    }

    // ─── Short report ───────────────────────────────────────────────
    static void print_short(std::ostream &out,
            const PcrAnalyzer &analyzer,
            const SiParser &si,
            const TsChecker &ts_checker,
            const SiMonitor &si_monitor,
            const PtsAnalyzer &pts_analyzer,
            const IatAnalyzer &iat_analyzer,
            const std::set<uint16_t> &unreferenced_pids,
            const std::string &source,
            double duration_s,
            const char *time_str,
            bool all_pass)
    {
        const auto &stats = analyzer.stats();
        const auto &programs = si.programs();
        const auto &ts_stats = ts_checker.stats();
        bool is_file = analyzer.file_mode();

        out << "MPEG-TS Analyzer v" TS_ANALYZE_VERSION " | Perfect Streamer Toolkit https://meshwork.pstreamer.tv\n";
        out << "TR 101 290 Summary | " << source << " | " << std::fixed
            << std::setprecision(1) << duration_s << "s | " << time_str << "\n";
        separator(out, '-', 100);

        // TR 101 290 summary line
        out << "  P1: sync=" << ts_stats.sync_byte_errors
            << " CC=" << ts_stats.cc_errors
            << " PAT=" << (si_monitor.pat_stats().interval_violations + si_monitor.pat_stats().crc_errors);
        {
            int64_t pmt_err = 0;
            for (auto& [pid, st] : si_monitor.pmt_stats())
                pmt_err += st.interval_violations + st.crc_errors;
            out << " PMT=" << pmt_err;
        }
        out << " PID=" << ts_stats.pid_absence_errors;

        out << "  P2: TEI=" << ts_stats.transport_errors
            << " CRC=" << si_monitor.total_crc_errors()
            << " PTS=" << pts_analyzer.total_pts_errors();

        out << "  P3: NIT=";
        if (si_monitor.nit_is_disabled())
            out << "off";
        else
            out << (si_monitor.nit_actual_stats().interval_violations
                    + si_monitor.nit_actual_stats().crc_errors);
        out << " SDT=" << (si_monitor.sdt_actual_stats().interval_violations
                          + si_monitor.sdt_actual_stats().crc_errors)
            << " EIT=";
        if (si_monitor.eit_is_disabled())
            out << "off";
        else
            out << (si_monitor.eit_actual_pf_stats().interval_violations
                    + si_monitor.eit_actual_pf_stats().crc_errors);
        out << " TDT=" << si_monitor.tdt_stats().interval_violations
            << " unref=" << unreferenced_pids.size();

        {
            int64_t sec_err = si_monitor.total_section_size_errors();
            int64_t stb_w   = si_monitor.total_eit_stb_warnings();
            if (sec_err > 0)
                out << "  SecSize=" << sec_err << "err";
            if (stb_w > 0)
                out << "  EIT>1024=" << stb_w << "warn";
        }
        out << "\n";

        // IAT one-line summary (network only)
        if (!is_file && iat_analyzer.interval_count() > 0)
        {
            out << "  IAT: dgrams=" << iat_analyzer.datagram_count()
                << " avg=" << format_ms(iat_analyzer.avg())
                << " max=" << format_ms(iat_analyzer.max())
                << " stddev=" << format_ms(iat_analyzer.stddev())
                << " p99=" << format_ms(iat_analyzer.percentile(0.99))
                << " gaps>" << format_ms(IAT_GAP_THRESHOLD_S) << "=" << iat_analyzer.gap_events();
            if (iat_analyzer.gap_events() > 0)
                out << "  " << Color::wrap(Color::YELLOW, "WARN");
            out << "\n";
        }

        separator(out, '-', 100);

        // Per-PCR-PID table
        out << std::left << std::setw(14) << "PCR PID"
            << std::setw(8) << "SID"
            << std::setw(10) << "Count"
            << std::setw(14) << "Intv max"
            << std::setw(14) << "Jitter max"
            << std::setw(10) << "Drift"
            << std::setw(10) << "Interval"
            << std::setw(10) << "Accuracy"
            << std::setw(8) << "T-STD"
            << "\n";
        separator(out, '-', 100);

        // PCR drift columns: skip < 30 s, WARN 30–300 s, FAIL ≥ 300 s.
        // The columns are per PID; OVERALL comes from Verdict::overall.
        bool drift_measured     = !is_file && (duration_s >= ANALYSIS_FULL_DURATION_S);
        bool drift_hard_window  = !is_file && (duration_s >= DRIFT_HARD_FAIL_DURATION_S);

        for (auto& [pid, st] : stats)
        {
            bool intv_ok  = (st.pcr_interval_hard_err == 0 && st.interval_count > 0);
            bool acc_ok   = is_file ? true : (st.pcr_accuracy_err == 0);
            bool drift_in_spec = !drift_measured ? true : (std::abs(st.drift_ppm) <= 30.0);

            std::ostringstream pid_s;
            pid_s << "0x" << std::hex << std::setfill('0') << std::setw(4) << pid;

            std::string sid_str = "-";
            for (auto& [pn, pi] : programs)
            {
                if (pi.pcr_pid_known && pi.pcr_pid == pid)
                {
                    sid_str = std::to_string(pn);
                    break;
                }
            }

            // Drift cell: pad-then-colorize so std::setw(10) below stays
            // aligned regardless of ANSI escapes. Yellow when out-of-spec
            // in the soft (30..300 s) window, red only in the hard window.
            std::string drift_str;
            if (is_file)              drift_str = Color::padded(nullptr, "N/A", 10, true);
            else if (!drift_measured) drift_str = Color::padded(nullptr, "skip", 10, true);
            else {
                const char *drift_color =
                    drift_in_spec   ? Color::GREEN  :
                    drift_hard_window ? Color::RED  :
                                        Color::YELLOW;
                std::string val = std::to_string((int) st.drift_ppm) + "ppm";
                drift_str = Color::padded(drift_color, val, 10, true);
            }
            std::string jit_str   = is_file ? "N/A" : format_ns(st.accuracy_abs_max());

            // Status fields: pad to width first, then colorize — std::setw on a
            // string containing ANSI escapes counts the invisible bytes too.
            const char *intv_color = intv_ok ? Color::GREEN : Color::RED;
            const char *acc_color  = is_file ? nullptr
                                             : (acc_ok ? Color::GREEN : Color::RED);
            const char *tstd_color = is_file ? nullptr
                                             : (st.tstd_overflows == 0   ? Color::GREEN : Color::RED);
            std::string intv_field = Color::padded(intv_color, intv_ok ? "PASS" : "FAIL", 10, true);
            std::string acc_field  = Color::padded(acc_color,
                                                   is_file ? "N/A" : (acc_ok ? "PASS" : "FAIL"),
                                                   10, true);
            std::string tstd_field = Color::padded(tstd_color,
                                                   is_file ? "N/A" : (st.tstd_overflows == 0 ? "PASS" : "FAIL"),
                                                   8, true);

            out << std::left << std::setw(14) << pid_s.str()
                << std::setw(8) << sid_str
                << std::setw(10) << st.pcr_count
                << std::setw(14) << format_ms(st.interval_max)
                << std::setw(14) << jit_str
                << drift_str
                << intv_field
                << acc_field
                << tstd_field
                << "\n";
        }

        separator(out, '-', 100);
        out << "OVERALL: " << pass_fail(all_pass) << "\n";
    }
};
