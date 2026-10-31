/*
 * Copyright 2026 Perfect Soft
 * SPDX-License-Identifier: Apache-2.0
 */
#pragma once
/*
 * json_report.h — the compact JSON report (--json), schema "ts_analyze/1".
 *
 * Made for programs and AI agents: the verdict first, then only the
 * problems (failed and warned checks) with what they mean, where (PIDs) and
 * when (first/last occurrence, the first events), and a hint at the likely
 * cause where one can be given reliably. Passed checks are a list of ids.
 * OVERALL and the exit code are the same as in the other reports.
 */

#include "events.h"
#include "verdict.h"
#include "si_parser.h"
#include "iat_analyzer.h"
#include "st2022_checks.h"
#include "version.h"

#include <cmath>
#include <ctime>
#include <iomanip>
#include <ostream>
#include <set>
#include <sstream>
#include <string>
#include <vector>

// A minimal JSON writer: compact, commas handled per nesting level.
class JsonWriter
{
public:
    explicit JsonWriter(std::ostream &out) : out_(out) {}

    JsonWriter &obj(const char *key = nullptr) { open(key, '{'); return *this; }
    JsonWriter &arr(const char *key = nullptr) { open(key, '['); return *this; }
    JsonWriter &end()
    {
        out_ << (kind_.back() == '{' ? '}' : ']');
        kind_.pop_back();
        first_.pop_back();
        return *this;
    }
    JsonWriter &str(const char *key, const std::string &v) { put(key); quote(v); return *this; }
    JsonWriter &num(const char *key, double v, int prec = 3)
    {
        put(key);
        if (!std::isfinite(v))
            out_ << "null";
        else if (v == std::floor(v) && std::fabs(v) < 1e15)
            out_ << (long long) v;
        else
            out_ << std::fixed << std::setprecision(prec) << v << std::defaultfloat;
        return *this;
    }
    JsonWriter &integer(const char *key, long long v) { put(key); out_ << v; return *this; }
    JsonWriter &boolean(const char *key, bool v) { put(key); out_ << (v ? "true" : "false"); return *this; }
    JsonWriter &null(const char *key) { put(key); out_ << "null"; return *this; }

private:
    void put(const char *key)
    {
        if (!first_.empty())
        {
            if (!first_.back())
                out_ << ',';
            first_.back() = false;
        }
        if (key)
        {
            quote(key);
            out_ << ':';
        }
    }
    void open(const char *key, char c)
    {
        put(key);
        out_ << c;
        kind_.push_back(c);
        first_.push_back(true);
    }
    void quote(const std::string &s)
    {
        out_ << '"';
        for (unsigned char c : s)
        {
            switch (c)
            {
            case '"': out_ << "\\\""; break;
            case '\\': out_ << "\\\\"; break;
            case '\n': out_ << "\\n"; break;
            case '\t': out_ << "\\t"; break;
            default:
                if (c < 0x20)
                {
                    char b[8];
                    snprintf(b, sizeof(b), "\\u%04x", c);
                    out_ << b;
                }
                else
                    out_ << c;
            }
        }
        out_ << '"';
    }

    std::ostream &out_;
    std::vector<char> kind_;
    std::vector<bool> first_;
};

struct JsonReport
{
    struct Meta
    {
        const char *id, *name, *ref, *meaning;
    };

    static const Meta *meta(const std::string &id)
    {
        static const Meta m[] = {
            { "1.1", "TS_sync_loss", "TR 101 290 1.1", "2 or more consecutive packets with a bad sync byte: TS synchronisation lost" },
            { "1.2", "Sync_byte_error", "TR 101 290 1.2", "a TS packet whose sync byte is not 0x47" },
            { "1.3", "PAT_error", "TR 101 290 1.3", "no valid PAT section on PID 0 within 0.5 s" },
            { "1.4", "Continuity_count_error", "TR 101 290 1.4", "continuity counter out of order: packets lost, duplicated wrongly or reordered" },
            { "1.5", "PMT_error", "TR 101 290 1.5", "no valid PMT section of a program within 0.5 s" },
            { "1.6", "PID_error", "TR 101 290 1.6", "a PID announced by the PMT carried no packets for 5 s" },
            { "2.1", "Transport_error", "TR 101 290 2.1", "packets with transport_error_indicator set: uncorrectable errors flagged upstream" },
            { "2.2", "CRC_error", "TR 101 290 2.2", "PSI/SI sections with a wrong CRC" },
            { "2.3a", "PCR_repetition_error", "TR 101 290 2.3a", "more than 40 ms between consecutive PCRs of a PID" },
            { "2.3b", "PCR_discontinuity_indicator_error", "TR 101 290 2.3b", "a PCR step outside 0..100 ms without the discontinuity flag" },
            { "2.4", "PCR_accuracy_error", "TR 101 290 2.4", "a PCR off by more than 500 ns" },
            { "2.5", "PTS_error", "TR 101 290 2.5", "more than 700 ms between PTS of an elementary stream" },
            { "2.6", "CAT_error", "TR 101 290 2.6", "scrambled packets present but no valid CAT within 0.5 s" },
            { "3.1a", "NIT_actual_error", "TR 101 290 3.1a", "no NIT actual within 10 s" },
            { "3.1b", "NIT_other_error", "TR 101 290 3.1b", "no NIT other within 10 s (once it was seen)" },
            { "3.4", "Unreferenced_PID", "TR 101 290 3.4", "PIDs with packets that no PSI table references" },
            { "3.5a", "SDT_actual_error", "TR 101 290 3.5a", "no SDT actual within 2 s" },
            { "3.5b", "SDT_other_error", "TR 101 290 3.5b", "no SDT other within 2 s (once it was seen)" },
            { "3.6a", "EIT_actual_error", "TR 101 290 3.6a", "no EIT present/following actual within 2 s" },
            { "3.6b", "EIT_other_error", "TR 101 290 3.6b", "EIT present/following other later than 20 s (optional table)" },
            { "3.8", "TDT_error", "TR 101 290 3.8", "no TDT within 30 s" },
            { "PAT.version", "PAT_version_change", "ISO/IEC 13818-1 2.4.4.3", "the PAT version_number changed for the same transport stream" },
            { "PMT.version", "PMT_version_change", "ISO/IEC 13818-1 2.4.4.8", "a PMT version_number changed for the same program" },
            { "EIT.sch_act", "EIT_schedule_actual", "EN 300 468 Annex C", "an EIT schedule actual sub-table later than 10 s (optional)" },
            { "EIT.sch_oth", "EIT_schedule_other", "EN 300 468 Annex C", "an EIT schedule other sub-table later than 10 s (optional)" },
            { "TSTD.under", "T-STD_underflow", "ISO/IEC 13818-1 2.4.2", "the T-STD buffer model of an elementary stream ran empty" },
            { "TSTD.over", "T-STD_overflow", "ISO/IEC 13818-1 2.4.2", "the T-STD buffer model of an elementary stream overflowed" },
            { "SI.size", "Section_size_error", "ISO/IEC 13818-1, EN 300 468", "a PSI/SI section larger than its standard limit" },
            { "SI.eit1024", "EIT_section_over_1024", "EN 300 468 (receiver practice)", "EIT sections above 1024 bytes, which some set-top boxes reject" },
            { "PCR.drift", "PCR_drift", "ISO/IEC 13818-1 2.4.2.1", "PCR clock drift beyond 30 ppm" },
            { "IAT.gap", "Datagram_gap", "network", "gaps between UDP datagrams above the threshold" },
            { "S.1", "Unrecoverable_loss", "SMPTE ST 2022-7 / ST 2022-1", "datagrams lost on every path and not rebuilt by FEC" },
            { "S.2", "RTP_protocol_error", "SMPTE ST 2022-2", "datagrams that are not RTP or carry another payload type on the media port" },
            { "S.3", "Path_down", "SMPTE ST 2022-7", "a path silent longer than the silence limit" },
            { "S.4", "Paths_differ", "SMPTE ST 2022-7", "the two paths do not carry the same stream" },
            { "S.5", "Path_skew", "SMPTE ST 2022-7", "the delay between the paths above --path-skew-ms" },
            { "S.6", "FEC_absent", "SMPTE ST 2022-1", "no valid FEC packet for 2 s" },
        };
        for (const auto &x : m)
            if (id == x.id)
                return &x;
        return nullptr;
    }

    struct Problem
    {
        std::string id;
        bool fail;
        int64_t count;
        std::vector<int> pids;          // when known without events
        std::string detail;             // a summary line where events have none
        std::string hint;
        std::string confidence;
    };

    /// The JSON report; returns OVERALL (the same as Verdict::overall).
    static bool print(std::ostream &out,
            const PcrAnalyzer &analyzer, const SiParser &si, const TsChecker &ts_checker,
            const SiMonitor &si_monitor, const PtsAnalyzer &pts_analyzer, const IatAnalyzer &iat,
            const std::set<uint16_t> &unreferenced_pids, const std::string &source, double duration_s,
            double start_utc, const St2022Summary *st2022)
    {
        const bool all_pass = Verdict::overall(analyzer, ts_checker, si_monitor, pts_analyzer, duration_s, st2022);
        const bool live = !analyzer.file_mode();

        std::vector<Problem> problems;
        std::vector<std::string> passed, na;
        std::map<std::string, int64_t> count;

        for (const auto &c : Verdict::tr_checks(analyzer, ts_checker, si_monitor, pts_analyzer))
        {
            count[c.id] = c.errors;
            if (!c.applicable)
                na.push_back(c.id);
            else if (c.fail())
                problems.push_back({ c.id, true, c.errors, {}, "", "", "" });
            else
                passed.push_back(c.id);
        }
        if (st2022 && st2022->enabled)
            for (const auto &c : st2022_checks(*st2022))
            {
                if (!c.applicable)
                    na.push_back(c.id);
                else if (c.fail())
                    problems.push_back({ c.id, true, c.errors, {}, c.detail, "", "" });
                else
                    passed.push_back(c.id);
            }

        // Drift: measured from 30 s live; FAIL in the 300 s window, WARN before.
        if (live && duration_s >= ANALYSIS_FULL_DURATION_S)
        {
            Problem p { "PCR.drift", Verdict::drift_fail(analyzer, duration_s), 0, {}, "", "", "" };
            std::ostringstream d;
            for (auto &[pid, st] : analyzer.stats())
                if (std::abs(st.drift_ppm) > 30.0)
                {
                    p.count++;
                    p.pids.push_back(pid);
                    d << (d.tellp() ? "; " : "") << "PID " << pid << ": " << std::fixed << std::setprecision(1)
                      << st.drift_ppm << " ppm";
                }
            p.detail = d.str();
            if (p.count)
                problems.push_back(p);
        }

        // Warnings (not gated).
        auto warn = [&](const char *id, int64_t n, std::vector<int> pids = {}, std::string detail = "") {
            if (n > 0)
                problems.push_back({ id, false, n, pids, detail, "", "" });
        };
        {
            std::vector<int> u(unreferenced_pids.begin(), unreferenced_pids.end());
            warn("3.4", (int64_t) u.size(), u);
        }
        int64_t eit_o = si_monitor.eit_other_pf_stats().interval_violations;
        if (!si_monitor.eit_is_disabled())
        {
            warn("3.6b", eit_o);
            warn("EIT.sch_act", si_monitor.eit_actual_sch_aggregated().total_interval_violations);
            warn("EIT.sch_oth", si_monitor.eit_other_sch_aggregated().total_interval_violations);
        }
        warn("SI.eit1024", si_monitor.total_eit_stb_warnings());
        if (live)
            warn("IAT.gap", iat.gap_events(), {}, iat.interval_count() ? "max " + fmt_ms(iat.max()) : "");

        for (auto &p : problems)
            add_hint(p, analyzer, count, live, iat, st2022);

        // ── output ──
        JsonWriter j(out);
        j.obj()
            .str("schema", "ts_analyze/1")
            .str("tool", "ts_analyze")
            .str("version", TS_ANALYZE_VERSION)
            .str("verdict", all_pass ? "PASS" : "FAIL")
            .integer("exit_code", all_pass ? 0 : 65)
            .str("source", source)
            .str("input", live ? "live" : "file");
        if (live && start_utc > 0)
            j.str("start_utc", utc(start_utc));
        else
            j.null("start_utc");
        double bytes = (double) analyzer.total_packets() * TS_PACKET_SIZE;
        j.num("duration_s", duration_s)
            .num("bitrate_mbps", duration_s > 0 ? bytes * 8 / duration_s / 1e6 : 0)
            .integer("packets", analyzer.total_packets());

        int nfail = 0, nwarn = 0;
        for (auto &p : problems)
            (p.fail ? nfail : nwarn)++;
        j.obj("checks").integer("failed", nfail).integer("warned", nwarn);
        j.arr("passed");
        for (auto &id : passed)
            j.str(nullptr, id);
        j.end().arr("not_applicable");
        for (auto &id : na)
            j.str(nullptr, id);
        j.end().end();

        j.arr("problems");
        for (auto &p : problems)
            write_problem(j, p, live, start_utc);
        j.end();

        write_context(j, analyzer, si, live, iat, st2022);
        j.end();
        out << "\n";
        return all_pass;
    }

    /// Exits without a report (no data, no PCR, bad input) as a JSON object too.
    static void print_error(std::ostream &out, int exit_code, const std::string &message, const std::string &source)
    {
        JsonWriter j(out);
        j.obj()
            .str("schema", "ts_analyze/1")
            .str("tool", "ts_analyze")
            .str("version", TS_ANALYZE_VERSION)
            .str("verdict", "ERROR")
            .integer("exit_code", exit_code)
            .str("source", source)
            .str("error", message)
            .end();
        out << "\n";
    }

private:
    static std::string fmt_ms(double s)
    {
        std::ostringstream o;
        o << std::fixed << std::setprecision(1) << s * 1e3 << " ms";
        return o.str();
    }

    static std::string utc(double epoch)
    {
        time_t t = (time_t) epoch;
        std::tm tm;
        gmtime_r(&t, &tm);
        char b[64];
        int ms = (int) ((epoch - std::floor(epoch)) * 1000) % 1000;
        snprintf(b, sizeof(b), "%04d-%02d-%02dT%02d:%02d:%02d.%03dZ", tm.tm_year + 1900, tm.tm_mon + 1,
                 tm.tm_mday, tm.tm_hour, tm.tm_min, tm.tm_sec, ms);
        return b;
    }

    static void when(JsonWriter &j, const char *key, double t, bool live, double start_utc)
    {
        j.obj(key).num("t_s", t);
        if (live && start_utc > 0)
            j.str("utc", utc(start_utc + t));
        j.end();
    }

    static void write_problem(JsonWriter &j, const Problem &p, bool live, double start_utc)
    {
        const Meta *m = meta(p.id);
        const EventSeries *ev = Events::get().find(p.id);
        j.obj()
            .str("id", p.id)
            .str("name", m ? m->name : p.id)
            .str("ref", m ? m->ref : "")
            .str("severity", p.fail ? "fail" : "warn")
            .str("meaning", m ? m->meaning : "")
            .integer("count", p.count);
        std::set<int> pids(p.pids.begin(), p.pids.end());
        if (ev)
            pids.insert(ev->pids.begin(), ev->pids.end());
        j.arr("pids");
        for (int pid : pids)
            j.integer(nullptr, pid);
        j.end();
        if (!p.detail.empty())
            j.str("detail", p.detail);
        if (ev && ev->count)
        {
            when(j, "first", ev->first, live, start_utc);
            when(j, "last", ev->last, live, start_utc);
            j.arr("events");
            for (const auto &e : ev->events)
            {
                j.obj().num("t_s", e.t);
                if (live && start_utc > 0)
                    j.str("utc", utc(start_utc + e.t));
                if (e.pid >= 0)
                    j.integer("pid", e.pid);
                if (!e.detail.empty())
                    j.str("detail", e.detail);
                j.end();
            }
            j.end();
            if (ev->count > (int64_t) ev->events.size())
                j.integer("events_more", ev->count - (int64_t) ev->events.size());
        }
        if (!p.hint.empty())
            j.obj("hint").str("text", p.hint).str("confidence", p.confidence).end();
        j.end();
    }

    // Hints only where the evidence in this run supports them.
    static void add_hint(Problem &p, const PcrAnalyzer &analyzer,
                         const std::map<std::string, int64_t> &count, bool live, const IatAnalyzer &iat,
                         const St2022Summary *st)
    {
        auto n = [&](const char *id) { auto it = count.find(id); return it == count.end() ? 0 : it->second; };
        auto set = [&](const std::string &text, const char *conf) { p.hint = text; p.confidence = conf; };
        const EventSeries *ev = Events::get().find(p.id);
        auto never_seen = [&]() {
            return ev && !ev->events.empty() && ev->events[0].detail.find("never seen") != std::string::npos;
        };

        if (p.id == "1.4")
        {
            if (n("2.1") || n("1.2"))
                set("packets were corrupted on the way (TEI or sync errors in the same run): a transmission or "
                    "demodulation problem upstream", "likely");
            else if (live && iat.gap_events() > 0)
                set("datagram gaps on the network (IAT gaps in the same run): packets were lost between the "
                    "sender and this receiver", "likely");
        }
        else if (p.id == "1.1" || p.id == "1.2")
            set(n("1.1") ? "runs of corrupted packets: bit errors on the transport, or the input is not 188-byte TS"
                         : "isolated corrupted bytes on the transport (bit errors)", "likely");
        else if (p.id == "2.1")
            set("an upstream receiver or demodulator marked these packets as uncorrectable", "certain");
        else if (p.id == "2.2")
        {
            if (!n("1.4") && !n("2.1") && !n("1.2"))
                set("no loss or corruption on the transport in this run: the sections leave the source with a "
                    "wrong CRC (table generator)", "likely");
            else
                set("sections corrupted together with other transport errors in this run", "possible");
        }
        else if (p.id == "1.3" || p.id == "1.5")
        {
            if (!n("1.4") && !n("2.1") && !n("1.2"))
                set("no packet loss in this run: the multiplexer sends this table too rarely or paused it", "likely");
        }
        else if (p.id == "2.3a")
        {
            int64_t intervals = 0, errs = 0;
            double maxv = 0, sum = 0;
            for (auto &[pid, s] : analyzer.stats())
            {
                intervals += s.interval_count;
                errs += s.pcr_interval_err;
                sum += s.interval_sum;
                maxv = std::max(maxv, s.interval_max);
            }
            // Nearly every interval above 40 ms and none above 100 ms: a setting, not a loss.
            if (intervals && errs * 10 >= intervals * 9 && maxv <= 0.100)
            {
                std::ostringstream o;
                o << "systematic: the source inserts PCR about every " << std::fixed << std::setprecision(0)
                  << (sum / intervals * 1e3) << " ms; set the encoder or multiplexer to at most 40 ms";
                set(o.str(), "likely");
            }
        }
        else if (p.id == "2.3b")
            set("a PCR jump that was not signalled: a source switch, splice or encoder restart", "likely");
        else if (p.id == "1.6")
            set("the PID stopped: an elementary stream of the program ended at the source", "likely");
        else if ((p.id == "3.5a" || p.id == "3.6a" || p.id == "3.1a") && never_seen())
            set(std::string("the table was never seen: the multiplex does not carry it")
                    + (p.id == "3.6a" ? "; --no-eit skips EIT checks where that is intended"
                       : p.id == "3.1a" ? "; --no-nit skips NIT checks where that is intended" : ""),
                "certain");
        else if (p.id == "PCR.drift")
            set("the source's system clock is off its nominal 27 MHz", "likely");
        else if (st && p.id == "S.1")
        {
            bool both = st->two_paths && st->path[0].lost && st->path[1].lost;
            set(both ? "both paths lost the same datagrams: a common segment or the sender itself"
                     : (st->two_paths ? "loss while only one path delivered" : "loss on the only path, with no "
                        "second path or FEC to repair it"), "possible");
        }
        else if (p.id == "S.2")
            set("the media port receives non-RTP datagrams or another payload type: FEC sent in the media port "
                "(not supported) or a wrong stream", "likely");
        else if (p.id == "S.3")
            set("the path was interrupted; see the down times", "certain");
        else if (p.id == "S.4")
            set("the two paths carry different streams (another SSRC or other content)", "certain");
        else if (p.id == "S.5")
            set("the delay between the paths exceeds --path-skew-ms: the networks differ more than allowed",
                "certain");
        else if (p.id == "S.6")
            set("no FEC on port+2/+4: FEC off at the sender, other ports, or a non-standard FEC form", "likely");
    }

    static void write_context(JsonWriter &j, const PcrAnalyzer &analyzer, const SiParser &si, bool live,
                              const IatAnalyzer &iat, const St2022Summary *st)
    {
        j.obj("context");
        j.arr("programs");
        for (auto &[pn, pi] : si.programs())
        {
            j.obj().integer("number", pn).integer("pmt_pid", pi.pmt_pid);
            if (pi.pcr_pid_known)
                j.integer("pcr_pid", pi.pcr_pid);
            j.arr("es");
            for (auto &es : pi.es_list)
            {
                char t[8];
                snprintf(t, sizeof(t), "0x%02x", es.stream_type);
                j.obj().integer("pid", es.pid).str("type", t).str("name", pi.stream_type_name(es.stream_type)).end();
            }
            j.end().end();
        }
        j.end();
        j.arr("pcr");
        for (auto &[pid, s] : analyzer.stats())
        {
            j.obj().integer("pid", pid).integer("count", s.pcr_count);
            j.num("interval_max_ms", s.interval_max * 1e3).num("interval_avg_ms", s.interval_avg() * 1e3);
            if (live && s.accuracy_count)
                j.num("accuracy_abs_max_ns", s.accuracy_abs_max() * 1e9, 1);
            j.end();
        }
        j.end();
        if (live && iat.interval_count())
            j.obj("iat").integer("datagrams", iat.datagram_count()).num("avg_ms", iat.avg() * 1e3)
                .num("max_ms", iat.max() * 1e3).num("p99_ms", iat.percentile(0.99) * 1e3)
                .integer("gaps", iat.gap_events()).end();
        if (st && st->enabled)
        {
            j.obj("st2022").boolean("fec", st->fec).boolean("two_paths", st->two_paths)
                .num("silence_limit_ms", st->silence_limit_ms).num("skew_limit_ms", st->skew_limit_ms);
            j.arr("paths");
            for (int i = 0; i < 2; i++)
            {
                const auto &p = st->path[i];
                if (!p.present)
                    continue;
                j.obj().integer("n", i + 1).str("source", p.source).boolean("up", p.up)
                    .integer("received", (long long) p.received).integer("lost", (long long) p.lost)
                    .integer("dup", (long long) p.dup).integer("late", (long long) p.late)
                    .integer("proto_errors", (long long) p.proto_errors)
                    .integer("down_events", p.down_events).num("down_s", p.down_s).end();
            }
            j.end();
            j.obj("merge").integer("released", (long long) st->released)
                .integer("unrecoverable", (long long) st->unrecovered_total())
                .integer("start_check_lost", (long long) st->start_check_lost)
                .integer("repaired", (long long) st->repaired).boolean("verified", st->verified)
                .boolean("paths_differ", st->paths_differ).num("skew_p50_ms", st->skew_p50_ms)
                .num("skew_max_ms", st->skew_max_ms).end();
            if (st->fec)
                j.obj("fec").integer("L", st->fec_L).integer("D", st->fec_D)
                    .integer("column_received", (long long) st->fec_received[0])
                    .integer("row_received", (long long) st->fec_received[1])
                    .integer("recovered_column", (long long) st->fec_recovered[0])
                    .integer("recovered_row", (long long) st->fec_recovered[1])
                    .integer("bad_header", (long long) st->fec_bad).end();
            j.end();
        }
        j.end();
    }
};
