/*
 * Copyright 2026 Perfect Soft
 * SPDX-License-Identifier: Apache-2.0
 */
#pragma once
/*
 * st2022_report.h — the "ST 2022" section of the full, short and XML
 * reports (only with --rtp, --fec or --path2).
 */

#include "st2022_checks.h"
#include "colors.h"

#include <iomanip>
#include <ostream>
#include <sstream>
#include <string>

namespace St2022Report
{

inline std::string ms(double v, int prec = 3)
{
    std::ostringstream os;
    os << std::fixed << std::setprecision(prec) << v << " ms";
    return os.str();
}

inline std::string hex32(uint32_t v)
{
    std::ostringstream os;
    os << "0x" << std::hex << std::setw(8) << std::setfill('0') << v;
    return os.str();
}

inline std::string xml_esc(const std::string &s)
{
    std::string r;
    for (char c : s)
    {
        switch (c)
        {
        case '<': r += "&lt;"; break;
        case '>': r += "&gt;"; break;
        case '&': r += "&amp;"; break;
        case '"': r += "&quot;"; break;
        default: r += c;
        }
    }
    return r;
}

inline const char *result(const St2022Check &c)
{
    return !c.applicable ? "N/A" : (c.fail() ? "FAIL" : "PASS");
}

inline void full(std::ostream &out, const St2022Summary &s)
{
    std::string sep(72, '=');
    out << "\n" << sep << "\n"
        << "  ST 2022 — RTP input"
        << (s.fec ? ", ST 2022-1 FEC" : "")
        << (s.two_paths ? ", ST 2022-7 seamless (2 paths)" : "") << "\n"
        << sep << "\n";

    for (const auto &c : st2022_checks(s))
    {
        out << "  |  " << std::left << std::setw(12) << c.id << std::setw(30) << c.name << ": ";
        if (!c.applicable)
            out << std::setw(17) << "N/A";
        else
            out << std::right << std::setw(8) << c.errors << "         ";
        const char *col = !c.applicable ? nullptr : (c.fail() ? Color::RED : Color::GREEN);
        out << Color::padded(col, result(c), 6);
        if (!c.detail.empty())
            out << "  " << c.detail;
        out << "\n";
    }

    for (int i = 0; i < 2; i++)
    {
        const St2022PathSummary &p = s.path[i];
        if (!p.present)
            continue;
        out << "  |\n"
            << "  |  Path " << (i + 1) << "      : " << p.source << "  "
            << (p.up ? Color::wrap(Color::GREEN, "up") : Color::wrap(Color::RED, "down")) << "\n"
            << "  |    Datagrams : " << p.received << " received, " << p.lost << " lost, "
            << p.dup << " duplicate, " << p.late << " late\n"
            << "  |    RTP       : SSRC " << hex32(p.ssrc) << ", " << p.ssrc_changes << " SSRC changes, "
            << p.proto_errors << " protocol errors, " << p.ignored << " not used\n"
            << "  |    Down      : " << p.down_events << " times, " << std::fixed << std::setprecision(2)
            << p.down_s << " s (silent > " << std::setprecision(0) << s.silence_limit_ms << " ms)\n";
        if (p.iat.interval_count() > 0)
            out << "  |    IAT       : avg " << ms(p.iat.avg() * 1e3) << ", max " << ms(p.iat.max() * 1e3)
                << ", p99 " << ms(p.iat.percentile(0.99) * 1e3) << "\n";
        if (s.fec)
            out << "  |    FEC       : " << p.fec_datagrams << " datagrams on port+2/+4\n";
        if (p.proto_errors)
            out << "  |    Hint      : datagrams of another payload type on the media port"
                   " (FEC in the media port is not supported)\n";
    }

    out << "  |\n"
        << "  |  Merge       : " << s.released << " released, " << s.unrecovered_total() << " unrecoverable";
    if (s.start_check_lost)
        out << " (" << s.start_check_lost << " during the start check)";
    if (s.two_paths)
        out << ", " << s.repaired << " repaired by the other path";
    out << ", " << s.resets << " restarts\n";
    if (s.two_paths)
        out << "  |  Paths       : "
            << (s.paths_differ ? Color::wrap(Color::RED, "differ") : (s.verified ? "verified equal" : "not verified"))
            << ", skew p50 " << ms(s.skew_p50_ms, 1) << ", max " << ms(s.skew_max_ms, 1)
            << " (limit " << ms(s.skew_limit_ms, 0) << ")\n"
            << "  |                until the paths are verified equal (20 copies compared), only the\n"
            << "  |                primary path is used: a loss on it then is not repaired\n";
    if (s.fec)
    {
        out << "  |  FEC         : " << s.fec_received[0] << " column, " << s.fec_received[1] << " row";
        if (s.fec_L || s.fec_D)
            out << " (L=" << s.fec_L << " D=" << s.fec_D << ")";
        out << "; recovered " << s.fec_recovered[0] << " by column, " << s.fec_recovered[1] << " by row\n"
            << "  |                " << s.fec_refused << " refused, " << s.fec_bad << " bad FEC headers, "
            << s.fec_dup << " duplicate, " << s.fec_len_fixups << " length fix-ups\n";
    }
}

inline void short_lines(std::ostream &out, const St2022Summary &s)
{
    out << "  ST2022:";
    for (const auto &c : st2022_checks(s))
    {
        out << " " << c.id << "=";
        if (!c.applicable)
            out << "n/a";
        else
            out << c.errors;
    }
    out << "  released=" << s.released << " unrecov=" << s.unrecovered_total();
    if (s.two_paths)
        out << " repaired=" << s.repaired << " skew_max=" << std::fixed << std::setprecision(1) << s.skew_max_ms
            << "ms";
    if (s.fec)
        out << "  FEC col=" << s.fec_received[0] << " row=" << s.fec_received[1] << " rec=" << s.fec_recovered[0]
            << "/" << s.fec_recovered[1];
    out << "\n";
    for (int i = 0; i < 2; i++)
    {
        const St2022PathSummary &p = s.path[i];
        if (!p.present)
            continue;
        out << "  path" << (i + 1) << ": " << (p.up ? "up" : "DOWN") << " rx=" << p.received << " lost=" << p.lost
            << " dup=" << p.dup << " late=" << p.late << " proto=" << p.proto_errors << " down=" << p.down_events
            << "/" << std::fixed << std::setprecision(2) << p.down_s << "s\n";
    }
}

inline void xml(std::ostream &out, const St2022Summary &s)
{
    auto f = [](double v, int prec) {
        std::ostringstream os;
        os << std::fixed << std::setprecision(prec) << v;
        return os.str();
    };
    out << "  <st2022 fec=\"" << (s.fec ? "true" : "false") << "\" two_paths=\"" << (s.two_paths ? "true" : "false")
        << "\" silence_limit_ms=\"" << f(s.silence_limit_ms, 0) << "\" skew_limit_ms=\"" << f(s.skew_limit_ms, 0)
        << "\">\n";
    for (const auto &c : st2022_checks(s))
        out << "    <check id=\"" << c.id << "\" name=\"" << xml_esc(c.name) << "\" applicable=\""
            << (c.applicable ? "true" : "false") << "\" errors=\"" << c.errors << "\" result=\"" << result(c)
            << "\" detail=\"" << xml_esc(c.detail) << "\"/>\n";
    for (int i = 0; i < 2; i++)
    {
        const St2022PathSummary &p = s.path[i];
        if (!p.present)
            continue;
        out << "    <path n=\"" << (i + 1) << "\" source=\"" << xml_esc(p.source) << "\" up=\""
            << (p.up ? "true" : "false") << "\" received=\"" << p.received << "\" lost=\"" << p.lost << "\" dup=\""
            << p.dup << "\" late=\"" << p.late << "\" proto_errors=\"" << p.proto_errors << "\" ssrc=\""
            << hex32(p.ssrc) << "\" ssrc_changes=\"" << p.ssrc_changes << "\" ignored=\"" << p.ignored
            << "\" down_events=\"" << p.down_events << "\" down_s=\"" << f(p.down_s, 3) << "\" fec_datagrams=\""
            << p.fec_datagrams << "\" iat_avg_ms=\"" << f(p.iat.avg() * 1e3, 3) << "\" iat_max_ms=\""
            << f(p.iat.max() * 1e3, 3) << "\" iat_p99_ms=\"" << f(p.iat.percentile(0.99) * 1e3, 3) << "\"/>\n";
    }
    out << "    <merge released=\"" << s.released << "\" unrecoverable=\"" << s.unrecoverable << "\" overflow=\""
        << s.overflow << "\" start_check_lost=\"" << s.start_check_lost << "\" repaired=\"" << s.repaired << "\" restarts=\"" << s.resets << "\" verified=\""
        << (s.verified ? "true" : "false") << "\" paths_differ=\"" << (s.paths_differ ? "true" : "false")
        << "\" skew_p50_ms=\"" << f(s.skew_p50_ms, 3) << "\" skew_max_ms=\"" << f(s.skew_max_ms, 3)
        << "\" wait_ms=\"" << f(s.wait_ms, 1) << "\"/>\n";
    if (s.fec)
        out << "    <fec column_received=\"" << s.fec_received[0] << "\" row_received=\"" << s.fec_received[1]
            << "\" L=\"" << s.fec_L << "\" D=\"" << s.fec_D << "\" recovered_column=\"" << s.fec_recovered[0]
            << "\" recovered_row=\"" << s.fec_recovered[1] << "\" refused=\"" << s.fec_refused << "\" bad_header=\""
            << s.fec_bad << "\" dup=\"" << s.fec_dup << "\" ssrc_nonzero=\"" << s.fec_ssrc_nonzero
            << "\" len_fixups=\"" << s.fec_len_fixups << "\" absent_s=\"" << f(s.fec_absent_s, 1) << "\"/>\n";
    out << "  </st2022>\n";
}

} // namespace St2022Report
