/*
 * Copyright 2026 Perfect Soft
 * SPDX-License-Identifier: Apache-2.0
 */
/*
 * main.cpp — MPEG-TS Analyzer (version in version.h)
 *
 * Full TR 101 290 compliance checking (Priority 1/2/3).
 *
 * Usage:
 *   ts_analyze [options] <input>
 *
 * Input:
 *   udp://239.1.1.1:1234          — UDP multicast
 *   udp://eth0@239.1.1.1:1234     — UDP multicast, specific interface
 *   udp://192.168.1.100:1234      — UDP unicast
 *   /path/to/file.ts              — TS file
 *
 * Options:
 *   -t, --time <seconds>          — analysis duration (default: 30)
 *   -s, --short                   — short summary report
 *   -f, --full                    — full detailed report (default)
 *   -b, --bitrate <Mbit/s>        — hint TS bitrate for file mode (default: 38.8)
 *   -p, --pcr-pid <pid>           — analyze only this PCR PID (decimal or 0xHHHH)
 *   -l, --pcr-limit <ms>          — PCR interval error limit in ms (default: 40)
 *       --no-eit                  — skip EIT analysis (P3.7..P3.10 → N/A)
 *       --no-nit                  — skip NIT analysis (P3.1, P3.2 → N/A)
 *       --no-color                — disable ANSI color output for status verdicts
 *       --xml                     — emit structured XML report on stdout
 *                                   (suppresses diagnostic chatter; errors stay on stderr)
 *   -h, --help                    — show help
 *
 * Requirements:
 *   libdvbpsi >= 1.3 (system package, or fetched by CMake by default)
 *
 * Build:
 *   cmake -S . -B build && cmake --build build   (see CMakeLists.txt)
 */

#include "ts_common.h"
#include "ts_input.h"
#include "si_parser.h"
#include "pcr_analyzer.h"
#include "tr101290_defs.h"
#include "ts_checker.h"
#include "si_monitor.h"
#include "pts_analyzer.h"
#include "iat_analyzer.h"
#include "report.h"
#include "xml_report.h"
#include "version.h"

#include <iostream>
#include <memory>
#include <set>
#include <csignal>
#include <cstdlib>
#include <cstring>
#include <getopt.h>

// ─── Globals for signal handling ────────────────────────────────────
static volatile sig_atomic_t g_running        = 1;
static volatile sig_atomic_t g_caught_signal  = 0;   // SIGINT or SIGTERM number

static void signal_handler(int sig)
{
    g_caught_signal = sig;
    g_running = 0;
}

// ─── Usage ──────────────────────────────────────────────────────────
static void print_usage(const char *prog)
{
    std::cerr << "MPEG-TS Analyzer v" TS_ANALYZE_VERSION " — TR 101 290 (Perfect Streamer Toolkit https://meshwork.pstreamer.tv)\n"
            << "\n" << "Usage: " << prog << " [options] <input>\n" << "\n" << "Input:\n"
            << "  udp://239.1.1.1:1234          UDP multicast stream\n"
            << "  udp://eth0@239.1.1.1:1234     UDP multicast on interface\n"
            << "  udp://192.168.1.100:1234      UDP unicast stream\n"
            << "  /path/to/file.ts              TS file\n"
            << "\n" << "Options:\n"
            << "  -t, --time <seconds>   Analysis duration (default: 30)\n"
            << "  -s, --short            Short summary report\n"
            << "  -f, --full             Full detailed report (default)\n"
            << "  -b, --bitrate <Mbps>   TS bitrate hint for file mode (default: 38.8)\n"
            << "  -p, --pcr-pid <pid>    Analyze specific PCR PID (decimal or 0xHHHH)\n"
            << "  -l, --pcr-limit <ms>   PCR interval error limit in ms (default: 40)\n"
            << "      --no-eit           Skip EIT analysis (P3.7..P3.10 reported as N/A)\n"
            << "      --no-nit           Skip NIT analysis (P3.1, P3.2 reported as N/A)\n"
            << "      --no-color         Disable ANSI color output for status verdicts\n"
            << "      --xml              Emit structured XML on stdout (quiet stderr)\n"
            << "  -h, --help             Show this help\n"
            << "\n" << "TR 101 290 checks:\n"
            << "  Priority 1: sync, CC, PAT/PMT interval, PID presence\n"
            << "  Priority 2: TEI, CRC, PCR interval/accuracy/discont, PTS, CAT\n"
            << "  Priority 3: NIT, SDT, EIT, TDT intervals, unreferenced PIDs\n"
            << "  T-STD buffer model (ISO/IEC 13818-1 S2.4.2)\n" << "\n";
}

// ─── Parse PID (decimal or hex) ─────────────────────────────────────
static uint16_t parse_pid(const char *s)
{
    unsigned long v;
    if (s[0] == '0' && (s[1] == 'x' || s[1] == 'X'))
        v = strtoul(s, nullptr, 16);
    else
        v = strtoul(s, nullptr, 10);
    if (v > 0x1FFF)
    {
        std::cerr << "Error: PID out of range: " << s << "\n";
        exit(1);
    }
    return (uint16_t) v;
}

// ─── Parse input URI, extract interface if present ──────────────────
static void parse_input_uri(const std::string &raw, std::string &uri, std::string &iface)
{
    if (raw.substr(0, 6) == "udp://")
    {
        std::string rest = raw.substr(6);
        auto at = rest.find('@');
        if (at != std::string::npos)
        {
            iface = rest.substr(0, at);
            uri   = "udp://" + rest.substr(at + 1);
        }
        else
        {
            iface = "";
            uri   = raw;
        }
    }
    else
    {
        uri   = raw;
        iface = "";
    }
}

// ─── Main ───────────────────────────────────────────────────────────
/// CLI entry: exit 0 = OVERALL PASS, 65 = OVERALL FAIL, 1 = usage/input error, 2 = no PCR found, 3 = no data or too short, 128+N = signal.
int main(int argc, char *argv[])
{
    // Defaults
    double duration_s = 30.0;
    Report::Mode report_mode = Report::FULL;
    double bitrate_mbps = 0.0;
    uint16_t forced_pid = 0xFFFF;   // 0xFFFF = auto-detect
    double pcr_limit_ms = 0.0;      // 0 = use TR 101 290 default (40 ms)
    bool   xml_mode    = false;     // --xml: structured stdout, quiet stderr
    bool   no_eit      = false;     // --no-eit: skip EIT analysis
    bool   no_nit      = false;     // --no-nit: skip NIT analysis

    // Long-only option codes (values outside short-option alphabet)
    enum { OPT_NO_COLOR = 1000, OPT_XML, OPT_NO_EIT, OPT_NO_NIT };

    static struct option long_opts[] =
    {
    { "time", required_argument, nullptr, 't' },
    { "short", no_argument, nullptr, 's' },
    { "full", no_argument, nullptr, 'f' },
    { "bitrate", required_argument, nullptr, 'b' },
    { "pcr-pid", required_argument, nullptr, 'p' },
    { "pcr-limit", required_argument, nullptr, 'l' },
    { "no-color", no_argument, nullptr, OPT_NO_COLOR },
    { "no-eit", no_argument, nullptr, OPT_NO_EIT },
    { "no-nit", no_argument, nullptr, OPT_NO_NIT },
    { "xml", no_argument, nullptr, OPT_XML },
    { "help", no_argument, nullptr, 'h' },
    { nullptr, 0, nullptr, 0 } };

    int opt;
    while ((opt = getopt_long(argc, argv, "t:sfb:p:l:h", long_opts, nullptr)) != -1)
    {
        switch (opt)
        {
        case 't':
            duration_s = std::atof(optarg);
            break;
        case 's':
            report_mode = Report::SHORT;
            break;
        case 'f':
            report_mode = Report::FULL;
            break;
        case 'b':
            bitrate_mbps = std::atof(optarg);
            break;
        case 'p':
            forced_pid = parse_pid(optarg);
            break;
        case 'l':
            pcr_limit_ms = std::atof(optarg);
            break;
        case OPT_NO_COLOR:
            Color::enabled = false;
            break;
        case OPT_XML:
            xml_mode = true;
            Color::enabled = false;   // ANSI escapes are nonsense inside XML
            break;
        case OPT_NO_EIT:
            no_eit = true;
            break;
        case OPT_NO_NIT:
            no_nit = true;
            break;
        case 'h':
            print_usage(argv[0]);
            return 0;
        default:
            print_usage(argv[0]);
            return 1;
        }
    }

    if (optind >= argc)
    {
        std::cerr << "Error: no input specified.\n\n";
        print_usage(argv[0]);
        return 1;
    }

    std::string raw_input = argv[optind];
    std::string uri, iface;
    parse_input_uri(raw_input, uri, iface);

    // ── Signal handling ─────────────────────────────────────────────
    signal(SIGINT, signal_handler);
    signal(SIGTERM, signal_handler);

    // ── Open input ──────────────────────────────────────────────────
    std::unique_ptr<TsInput> input;
    try
    {
        input = create_input(uri, iface, bitrate_mbps);
    } catch (const std::exception &e)
    {
        std::cerr << "Error: " << e.what() << "\n";
        return 1;
    }

    // A file ends before -t when it holds less stream time (at the -b hint):
    // show and track progress against what will really be analysed.
    double expected_s = duration_s;
    if (input->span_s() > 0.0 && input->span_s() < expected_s)
        expected_s = input->span_s();

    if (!xml_mode)
    {
        std::cerr << "MPEG-TS Analyzer v" TS_ANALYZE_VERSION " — TR 101 290"
                     " (Perfect Streamer Toolkit https://meshwork.pstreamer.tv)\n"
                  << "Analyzing: " << input->source_name() << "\n";
        if (auto *f = dynamic_cast<TsFileInput *>(input.get()))
            std::cerr << "Duration : " << std::fixed << std::setprecision(1) << expected_s
                      << " s (file at " << std::setprecision(3) << f->bitrate_bps() / 1e6
                      << " Mbit/s, -b; limit -t " << std::setprecision(1) << duration_s
                      << " s)\n";
        else
            std::cerr << "Duration : " << duration_s << " s\n";
        std::cerr << "Report   : " << (report_mode == Report::FULL ? "full" : "short") << "\n"
                  << "Waiting for stream data...\n";
    }

    // ── Analysis objects ────────────────────────────────────────────
    SiParser    si;
    PcrAnalyzer analyzer;
    TsChecker   ts_checker;
    SiMonitor   si_monitor;
    PtsAnalyzer pts_analyzer;
    IatAnalyzer iat_analyzer;

    // Apply --no-eit / --no-nit before any packet is processed: these
    // setters drop the EIT/NIT assemblers from si_monitor so the matching
    // TS packets are filtered out at process_packet() and contribute
    // nothing to CRC, section-size, or interval statistics.
    if (no_eit) si_monitor.disable_eit();
    if (no_nit) si_monitor.disable_nit();

    bool is_file_mode = (uri.substr(0, 6) != "udp://");
    analyzer.set_file_mode(is_file_mode);
    if (pcr_limit_ms > 0.0)
        analyzer.set_pcr_interval_limit(pcr_limit_ms / 1000.0);

    // IAT (network jitter) only applies to live network sources.
    if (input->is_network())
        input->set_iat_analyzer(&iat_analyzer);

    std::set<uint16_t> active_pcr_pids;
    if (forced_pid != 0xFFFF)
        active_pcr_pids.insert(forced_pid);

    bool si_phase = true;
    int si_timeout_packets = 50000;
    bool tstd_es_initialized = false;
    bool pts_es_initialized = false;

    // PIDs referenced by SI — for P3.4 unreferenced PID detection (don't flag these)
    std::set<uint16_t> referenced_pids;
    // Well-known SI PIDs are always considered referenced (not flagged as unreferenced)
    referenced_pids.insert(TS_PID_PAT);
    referenced_pids.insert(TS_PID_CAT);
    referenced_pids.insert(TS_PID_TSDT);
    referenced_pids.insert(TS_PID_NIT);
    referenced_pids.insert(TS_PID_SDT);
    referenced_pids.insert(TS_PID_EIT);
    referenced_pids.insert(TS_PID_RST);
    referenced_pids.insert(TS_PID_TDT);

    // PIDs expected to be present — for P1.6 PID absence check (must appear in stream)
    // Only PAT is unconditionally required; PMT/PCR/ES PIDs added after SI discovery
    std::set<uint16_t> expected_pids;
    expected_pids.insert(TS_PID_PAT);

    // ── Main loop ───────────────────────────────────────────────────
    uint8_t pkt[TS_PACKET_SIZE];
    double arrival = 0;
    double start_time = 0;
    bool started = false;
    int64_t pkt_count = 0;
    // Skip the very first progress update (elapsed≈0): "PCR PIDs discovered"
    // and similar one-shot setup messages still print before that, and a
    // 0%-line above them would push subsequent updates to a new terminal
    // line. Starting at 0.0 makes the first refresh land at elapsed≥1s,
    // after the setup phase has finished.
    double last_progress_s = 0.0;

    while (g_running)
    {
        if (!input->read_packet(pkt, &arrival))
            break;

        if (!started)
        {
            start_time = arrival;
            started = true;
            if (!xml_mode)
                std::cerr << "Stream locked.\n";
        }

        double elapsed = arrival - start_time;
        if (elapsed >= duration_s)
            break;

        pkt_count++;

        // ── TR 101 290 P1 low-level checks (every packet) ──────────
        ts_checker.process_packet(pkt, elapsed);

        // ── SI monitoring (every packet) ────────────────────────────
        si_monitor.process_packet(pkt, elapsed);

        // ── PTS monitoring ──────────────────────────────────────────
        if (pts_es_initialized)
            pts_analyzer.process_packet(pkt);

        // ── SI parsing phase: discover PCR PIDs ─────────────────────
        if (si_phase)
        {
            si.push_packet(pkt);

            if (forced_pid == 0xFFFF)
                active_pcr_pids = si.pcr_pids();

            // For MPTS we want to know about every program before leaving
            // the SI phase, otherwise the "PCR PIDs discovered" line lists
            // only the first PMT received and per-PID buffers/expected_pids
            // miss the rest until the late-SI loop catches them. Wait for
            // all PMTs (has_all_pcr_pids) or fall back to the packet timeout.
            if (si.has_all_pcr_pids() || pkt_count > si_timeout_packets)
            {
                si_phase = false;

                if (active_pcr_pids.empty() && !xml_mode)
                {
                    std::cerr << "Warning: no PCR PIDs discovered via SI. "
                            "Scanning all PIDs for PCR fields.\n";
                }

                // ── Register PIDs from SI discovery ──────────────────
                for (auto& [pn, pi] : si.programs())
                {
                    referenced_pids.insert(pi.pmt_pid);
                    expected_pids.insert(pi.pmt_pid);   // PMT PID must be present
                    si_monitor.register_pmt_pid(pi.pmt_pid, pn);

                    if (pi.pcr_pid_known)
                    {
                        referenced_pids.insert(pi.pcr_pid);
                        expected_pids.insert(pi.pcr_pid);  // PCR PID must be present

                        for (auto &es : pi.es_list)
                        {
                            referenced_pids.insert(es.pid);
                            // P1.6 / T-STD apply only to continuous A/V streams.
                            // Event-driven types (SCTE-35, DSM-CC, private sections)
                            // may be silent for hours and use bursty delivery.
                            if (is_continuous_av_stream_type(es.stream_type)) {
                                expected_pids.insert(es.pid);
                                analyzer.init_tstd_es(es.pid, pi.pcr_pid, es.stream_type);
                            }
                            pts_analyzer.register_es(es.pid, es.stream_type);
                        }
                        tstd_es_initialized = true;
                        pts_es_initialized = true;
                    }
                }

                // P1.6: only PIDs from PAT/PMT are expected to be present
                ts_checker.register_expected_pids(expected_pids);

                // Fallback: if no ES info but we have PCR PIDs, use legacy per-PID buffer
                if (!tstd_es_initialized)
                {
                    for (auto p : active_pcr_pids)
                        analyzer.init_tstd(p, true);
                }

                if (!active_pcr_pids.empty() && !xml_mode)
                {
                    std::cerr << "PCR PIDs discovered:";
                    for (auto p : active_pcr_pids)
                        std::cerr << " " << format_pid(p);
                    std::cerr << "\n";
                }
            }
        }

        // ── Continue feeding SI parser (for late PMTs) ──────────────
        si.push_packet(pkt);
        if (forced_pid == 0xFFFF)
            active_pcr_pids = si.pcr_pids();

        // ── Late SI: initialize new ES buffers as late PMTs arrive ────
        if (!si_phase && !tstd_es_initialized)
        {
            for (auto& [pn, pi] : si.programs())
            {
                if (pi.pcr_pid_known && !pi.es_list.empty())
                {
                    for (auto &es : pi.es_list)
                    {
                        referenced_pids.insert(es.pid);
                        // T-STD only for continuous A/V (see is_continuous_av_stream_type).
                        if (is_continuous_av_stream_type(es.stream_type))
                            analyzer.init_tstd_es(es.pid, pi.pcr_pid, es.stream_type);
                        pts_analyzer.register_es(es.pid, es.stream_type);
                    }
                    tstd_es_initialized = true;
                    pts_es_initialized = true;
                }
            }
        }

        // ── PCR analysis ────────────────────────────────────────────
        TsHeader h = parse_ts_header(pkt);

        // If no SI-discovered PIDs, check every packet for PCR
        if (active_pcr_pids.empty())
        {
            PcrValue pcr = extract_pcr(pkt);
            if (pcr.valid)
            {
                active_pcr_pids.insert(h.pid);
                if (!tstd_es_initialized)
                    analyzer.init_tstd(h.pid, true);
            }
        }

        if (active_pcr_pids.count(h.pid) || active_pcr_pids.empty())
        {
            analyzer.process_packet(pkt, arrival, active_pcr_pids);
        }
        else
        {
            analyzer.count_packet(pkt);
        }

        // ── T-STD: feed ES packets into per-ES buffers ──────────────
        if (tstd_es_initialized)
        {
            for (auto& [pn, pi] : si.programs())
            {
                if (pi.pcr_pid_known)
                {
                    for (const auto &es : pi.es_list)
                    {
                        if (es.pid == h.pid)
                            analyzer.process_tstd_es_packet(es.pid, pkt, arrival);
                    }
                }
            }
        }
        else
        {
            for (auto& [pn, pi] : si.programs())
            {
                if (pi.pcr_pid_known)
                {
                    for (const auto &es : pi.es_list)
                    {
                        if (es.pid == h.pid)
                            analyzer.process_tstd_packet(pi.pcr_pid, pkt, arrival);
                    }
                }
            }
        }

        // Progress: refresh once per second of elapsed stream time.
        // Tied to elapsed (not packet count) so the % bar advances at the
        // same rate regardless of bitrate, and stays correct even on very
        // low-rate streams where 500k packets would never come up.
        if (elapsed >= last_progress_s + 1.0 && !xml_mode)
        {
            last_progress_s = elapsed;
            double pct = expected_s > 0 ? (elapsed / expected_s) * 100.0 : 0.0;
            if (pct > 100.0) pct = 100.0;
            std::cerr << "\r  Progress: " << std::fixed << std::setprecision(1)
                      << pct << "%  (" << std::setprecision(1)
                      << elapsed << "s / " << expected_s << "s, "
                      << pkt_count << " packets)        " << std::flush;
        }
    }

    // ── Interrupted by SIGINT / SIGTERM: report nothing, exit 128+sig ───
    if (g_caught_signal != 0)
    {
        std::cerr << "\r\nAnalysis interrupted by signal "
                  << (int) g_caught_signal
                  << ((g_caught_signal == SIGINT)  ? " (SIGINT)" :
                      (g_caught_signal == SIGTERM) ? " (SIGTERM)" : "")
                  << " — no report produced.\n";
        return 128 + (int) g_caught_signal;   // POSIX shell convention
    }

    double actual_duration = started ? (arrival - start_time) : 0;
    if (!xml_mode)
        std::cerr << "\r  Captured " << pkt_count << " packets in " << std::fixed
                  << std::setprecision(2) << actual_duration << " s\n\n";

    // ── Duration check ──────────────────────────────────────────────
    // Distinguish three cases so the error message is actionable:
    //   pkt_count == 0   → no UDP traffic at all (sender absent / wrong addr / firewall)
    //   !started         → packets arrived but never crossed the start barrier
    //   actual < 2 s     → started but stream ended too early
    if (pkt_count == 0)
    {
        std::cerr << "Error: no data received from " << input->source_name() << "\n"
                  << "  Possible causes: source not transmitting, wrong address/port,\n"
                  << "  multicast group not joined, firewall, or wrong interface (use\n"
                  << "  iface@addr form, e.g. udp://eth0@239.1.1.1:1234).\n";
        return 3;
    }
    if (actual_duration < ANALYSIS_MIN_DURATION_S)
    {
        std::cerr << "Error: stream duration " << std::fixed << std::setprecision(2)
                  << actual_duration << " s is below the minimum "
                  << ANALYSIS_MIN_DURATION_S << " s required for TR 101 290 analysis.\n"
                  << "  T-STD warmup incomplete, PAT/PMT intervals unverifiable.\n"
                  << "  Use a longer recording or increase -t for live streams.\n";
        return 3;
    }
    if (actual_duration < ANALYSIS_P3_DURATION_S && !xml_mode)
    {
        std::cerr << "Warning: short duration (" << std::fixed << std::setprecision(1)
                  << actual_duration << " s) — P3 interval checks (NIT 10s, EIT schedule 10s, "
                  << "PID absence 5s) may have insufficient data.\n";
    }
    else if (actual_duration < ANALYSIS_FULL_DURATION_S && !xml_mode)
    {
        std::cerr << "Note: duration " << std::fixed << std::setprecision(1)
                  << actual_duration << " s — TDT interval (30s) may have insufficient data.\n";
    }

    // ── Finalize ────────────────────────────────────────────────────
    analyzer.finalize();
    ts_checker.check_pid_absence(actual_duration);
    si_monitor.finalize(actual_duration);

    // Compute unreferenced PIDs (P3.4)
    std::set<uint16_t> unreferenced_pids =
        si_monitor.find_unreferenced_pids(analyzer.pid_bytes(), referenced_pids);

    if (analyzer.stats().empty())
    {
        std::cerr << "Error: no PCR data found in the stream.\n";
        return 2;
    }

    // ── Report ──────────────────────────────────────────────────────
    bool all_pass;
    if (xml_mode) {
        all_pass = XmlReport::print(std::cout, analyzer, si,
                      ts_checker, si_monitor, pts_analyzer, iat_analyzer,
                      unreferenced_pids,
                      input->source_name(), actual_duration);
    } else {
        all_pass = Report::print(std::cout, analyzer, si,
                      ts_checker, si_monitor, pts_analyzer, iat_analyzer,
                      unreferenced_pids,
                      input->source_name(), actual_duration, report_mode);
    }

    // Exit code: 0 = OVERALL PASS, 65 = OVERALL FAIL.
    // 65 == EX_DATAERR from <sysexits.h>: "input data was incorrect" — the
    // analysed transport stream violates one or more TR 101 290 / ISO
    // 13818-1 requirements that are gated for OVERALL.
    return all_pass ? 0 : 65;
}
