/*
 * Copyright 2026 Perfect Soft
 * SPDX-License-Identifier: Apache-2.0
 */
#pragma once
/*
 * st2022_checks.h — the S.1..S.6 checks of an ST 2022-1 / 2022-7 input.
 *
 * One list for the verdict and for every report, so what is printed and
 * what gates OVERALL cannot drift apart. A check that does not apply to the
 * options given (S.3-S.5 without --path2, S.6 without --fec) is N/A.
 */

#include "st2022_summary.h"

#include <cstdio>
#include <string>
#include <vector>

struct St2022Check
{
    const char *id;
    const char *name;
    int64_t errors;         // what the report prints as the count
    bool applicable;
    std::string detail;

    bool fail() const { return applicable && errors != 0; }
};

inline std::string st2022_fmt(const char *f, double a, double b = 0)
{
    char buf[128];
    snprintf(buf, sizeof(buf), f, a, b);
    return buf;
}

/// The ST 2022 checks in report order; FAIL of any gates OVERALL (Verdict::overall).
inline std::vector<St2022Check> st2022_checks(const St2022Summary &s)
{
    std::vector<St2022Check> c;

    std::string ld;
    if (s.overflow)
        ld = std::to_string(s.overflow) + " given up early (window)";
    if (s.start_check_lost)
        ld += (ld.empty() ? "" : "; ") + std::to_string(s.start_check_lost)
              + " more lost during the start check, before the paths were verified equal (not counted)";
    c.push_back({ "S.1", "Unrecoverable loss", (int64_t) s.gated_loss(), true, ld });

    int64_t proto = 0;
    std::string pd;
    for (int i = 0; i < 2; i++)
        if (s.path[i].present && s.path[i].proto_errors)
        {
            proto += (int64_t) s.path[i].proto_errors;
            pd += (pd.empty() ? "path " : ", path ") + std::to_string(i + 1);
        }
    c.push_back({ "S.2", "RTP protocol errors", proto, true,
                  pd.empty() ? "" : pd + ": not RTP or another payload type"
                                    " (FEC in the media port is not supported)" });

    int64_t down = 0;
    std::string dd;
    for (int i = 0; i < 2; i++)
        if (s.path[i].present && s.path[i].down_events)
        {
            down += s.path[i].down_events;
            dd += (dd.empty() ? "" : "; ") + std::string("path ") + std::to_string(i + 1) + ": "
                  + st2022_fmt("%.2f s", s.path[i].down_s);
        }
    c.push_back({ "S.3", "Path down", down, s.two_paths,
                  st2022_fmt("silent > %.0f ms", s.silence_limit_ms) + (dd.empty() ? "" : "; " + dd) });

    c.push_back({ "S.4", "Paths differ", s.paths_differ ? 1 : 0, s.two_paths,
                  s.paths_differ ? "the paths do not carry the same stream" : "" });

    bool skew = s.skew_max_ms > s.skew_limit_ms;
    c.push_back({ "S.5", "Path skew", skew ? 1 : 0, s.two_paths,
                  st2022_fmt("max %.1f ms, limit %.0f ms", s.skew_max_ms, s.skew_limit_ms) });

    c.push_back({ "S.6", "FEC absent", s.fec_absent_s > 0 ? 1 : 0, s.fec,
                  s.fec_absent_s > 0 ? st2022_fmt("%.1f s without valid FEC", s.fec_absent_s) : "" });
    return c;
}
