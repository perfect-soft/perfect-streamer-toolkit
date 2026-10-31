/*
 * Copyright 2026 Perfect Soft
 * SPDX-License-Identifier: Apache-2.0
 */
#pragma once
/*
 * events.h — when each problem happened, for the JSON report (--json).
 *
 * The analyzers note an event where they count an error; the time is the
 * stream time of the packet being processed (set by the main loop), or an
 * explicit one for what is decided at the end. Off unless --json is given:
 * the other reports never read it and pay one branch per noted error.
 */

#include <cstdint>
#include <map>
#include <set>
#include <string>
#include <vector>

struct Event
{
    double t;               // seconds from the first packet
    int pid;                // -1: none or not trusted
    std::string detail;
};

struct EventSeries
{
    int64_t count = 0;
    double first = -1, last = -1;
    std::vector<Event> events;          // the first Events::MaxKept
    std::set<int> pids;                 // up to Events::MaxPids
};

class Events
{
public:
    static const size_t MaxKept = 10;
    static const size_t MaxPids = 32;

    static Events &get()
    {
        static Events e;
        return e;
    }
    static bool on() { return get().enabled_; }

    void enable() { enabled_ = true; }
    void set_now(double t) { now_ = t; }
    double now() const { return now_; }
    // Monotonic time of the first packet: inputs that see time before the
    // main loop (the RTP merge) convert with it.
    void set_origin(double mono) { origin_ = mono; }
    double rel(double mono) const { return origin_ > 0 && mono > origin_ ? mono - origin_ : 0; }

    /// Notes one occurrence of check `id`; t < 0: the current packet's time.
    void note(const std::string &id, int pid = -1, const std::string &detail = std::string(), double t = -1)
    {
        if (!enabled_)
            return;
        if (t < 0)
            t = now_;
        EventSeries &s = series_[id];
        s.count++;
        if (s.first < 0 || t < s.first)
            s.first = t;
        if (t > s.last)
            s.last = t;
        if (s.events.size() < MaxKept)
            s.events.push_back({ t, pid, detail });
        if (pid >= 0 && s.pids.size() < MaxPids)
            s.pids.insert(pid);
    }

    const EventSeries *find(const std::string &id) const
    {
        auto it = series_.find(id);
        return it == series_.end() ? nullptr : &it->second;
    }

private:
    bool enabled_ = false;
    double now_ = 0;
    double origin_ = 0;
    std::map<std::string, EventSeries> series_;
};

// The TR 101 290 check an SI table's interval / version events belong to.
inline const char *si_interval_check(const std::string &table)
{
    if (table == "PAT") return "1.3";
    if (table.rfind("PMT", 0) == 0) return "1.5";
    if (table == "CAT") return "2.6";
    if (table == "NIT_actual") return "3.1a";
    if (table == "NIT_other") return "3.1b";
    if (table == "SDT_actual") return "3.5a";
    if (table == "SDT_other") return "3.5b";
    if (table == "EIT_actual_pf") return "3.6a";
    if (table == "EIT_other_pf") return "3.6b";
    if (table.rfind("EIT_sch/0x5", 0) == 0) return "EIT.sch_act";
    if (table.rfind("EIT_sch/0x6", 0) == 0) return "EIT.sch_oth";
    if (table == "TDT") return "3.8";
    return nullptr;
}

inline const char *si_version_check(const std::string &table)
{
    if (table == "PAT") return "PAT.version";
    if (table.rfind("PMT", 0) == 0) return "PMT.version";
    return nullptr;
}
