/*
 * Copyright 2026 Perfect Soft
 * SPDX-License-Identifier: Apache-2.0
 */
#pragma once
/*
 * si_monitor.h — TR 101 290 SI table interval and CRC monitoring
 *
 * Implements:
 *   P1.3   PAT error           — no PAT within 500 ms; CRC error
 *   P1.3a  PAT error 2         — version change without tsid change
 *   P1.5   PMT error           — no PMT within 500 ms; CRC error
 *   P1.5a  PMT error 2         — version change without program_number change
 *   P2.2   CRC error           — CRC error in any PSI/SI section
 *   P2.7   CAT error           — no CAT within 500 ms when scrambling detected
 *   P3.1   NIT actual error    — NIT_actual absent or interval > 10 s
 *   P3.2   NIT other error     — NIT_other interval > 10 s
 *   P3.4   Unreferenced PID    — PID present but not referenced by SI
 *   P3.5   SDT actual error    — SDT_actual absent or interval > 2 s
 *   P3.6   SDT other error     — SDT_other interval > 2 s
 *   P3.7   EIT actual p/f      — absent or interval > 2 s
 *   P3.8   EIT other p/f       — interval > 20 s (EN 300 468 Annex C)
 *   P3.9   EIT actual schedule — interval > 10 s per sub-table
 *   P3.10  EIT other schedule  — interval > 10 s per sub-table
 *   P3.12  TDT error           — absent or interval > 30 s
 *
 * EIT schedule is tracked per sub-table (table_id 0x50–0x5F, 0x60–0x6F)
 * as required by EN 300 468 Annex C.
 *
 * Uses raw PSI section assembly (no extra libdvbpsi headers beyond PAT/PMT).
 */

#include "ts_common.h"
#include "tr101290_defs.h"

#include <map>
#include <set>
#include <vector>
#include <string>
#include <cstdint>

// ─── Per-table tracking state ─────────────────────────────────────────
struct SiTableStats {
    std::string  name;
    uint16_t     pid              = 0;
    double       interval_limit_s = 0;

    // Interval tracking
    double       last_seen        = -1;
    double       max_interval     = 0;
    int64_t      interval_count   = 0;
    int64_t      interval_violations = 0;
    bool         seen_at_least_once   = false;

    // Version consistency (P1.3a / P1.5a)
    uint8_t      last_version     = 0xFF;
    uint16_t     last_context_id  = 0xFFFF;
    int64_t      version_errors   = 0;

    // CRC errors (P2.2)
    int64_t      crc_errors       = 0;

    // Section size tracking
    int          section_max_bytes = 0;
    int          section_std_limit = 0;
    int64_t      section_size_errors = 0;
    int64_t      section_size_warnings = 0;  // EIT > 1024 but <= 4096

    bool pass() const {
        return (interval_violations == 0) && (crc_errors == 0)
            && (version_errors == 0) && (section_size_errors == 0);
    }
};

// ─── Section assembler for one PID ────────────────────────────────────
struct PsiAssembler {
    std::vector<uint8_t> buf;
    int  expected_len = 0;
    bool started      = false;
    double start_time = -1;

    void reset() {
        buf.clear();
        expected_len = 0;
        started      = false;
        start_time   = -1;
    }
};

// ─── Aggregated EIT schedule stats (summary across sub-tables) ────────
struct EitScheduleAggregated {
    int64_t total_interval_violations = 0;
    int64_t total_crc_errors          = 0;
    int64_t total_section_size_errors = 0;
    int64_t total_section_size_warnings = 0;
    int     section_max_bytes         = 0;
    double  worst_max_interval        = 0;
    int     sub_tables_seen           = 0;
    int     sub_tables_with_violations = 0;
    bool    any_seen                  = false;
};

// ─── SiMonitor ────────────────────────────────────────────────────────
class SiMonitor {
public:
    SiMonitor() {
        init_table(pat_,            "PAT",            TS_PID_PAT,  TR101290_PAT_INTERVAL_MAX_S, PSI_SECTION_MAX_BYTES);
        init_table(cat_,            "CAT",            TS_PID_CAT,  TR101290_CAT_INTERVAL_MAX_S, PSI_SECTION_MAX_BYTES);
        init_table(nit_actual_,     "NIT_actual",     TS_PID_NIT,  TR101290_NIT_INTERVAL_MAX_S, DVB_SI_SECTION_MAX_BYTES);
        init_table(nit_other_,      "NIT_other",      TS_PID_NIT,  TR101290_NIT_INTERVAL_MAX_S, DVB_SI_SECTION_MAX_BYTES);
        init_table(sdt_actual_,     "SDT_actual",     TS_PID_SDT,  TR101290_SDT_INTERVAL_MAX_S, DVB_SI_SECTION_MAX_BYTES);
        init_table(sdt_other_,      "SDT_other",      TS_PID_SDT,  TR101290_SDT_INTERVAL_MAX_S, DVB_SI_SECTION_MAX_BYTES);
        init_table(eit_actual_pf_,  "EIT_actual_pf",  TS_PID_EIT,  TR101290_EIT_PF_MAX_S, EIT_SECTION_MAX_BYTES);
        init_table(eit_other_pf_,   "EIT_other_pf",   TS_PID_EIT,  TR101290_EIT_OTHER_PF_MAX_S, EIT_SECTION_MAX_BYTES);
        init_table(tdt_,            "TDT",            TS_PID_TDT,  TR101290_TDT_INTERVAL_MAX_S, DVB_SI_SECTION_MAX_BYTES);

        // EIT schedule sub-tables are created dynamically in on_section_complete()

        // Create assemblers for well-known SI PIDs
        assemblers_[TS_PID_PAT];
        assemblers_[TS_PID_CAT];
        assemblers_[TS_PID_NIT];
        assemblers_[TS_PID_SDT];
        assemblers_[TS_PID_EIT];
        assemblers_[TS_PID_TDT];
    }

    // Disable NIT analysis (P3.1, P3.2 + NIT contributions to P2.2 / section size).
    // Must be called before process_packet(): erasing the assembler entry causes
    // process_packet() to skip every TS packet on PID 0x0010 (TS_PID_NIT), so no
    // NIT section is ever assembled and no NIT stats accumulate. The disabled
    // flag also suppresses the "absent" verdict in finalize() — without it the
    // missing NIT_actual would be flagged as a P3.1 interval violation by
    // flag_missing() once total_duration exceeds the 10 s limit.
    void disable_nit() {
        nit_disabled_ = true;
        assemblers_.erase(TS_PID_NIT);
    }

    // Disable EIT analysis (P3.7..P3.10 + EIT contributions to P2.2, section
    // size, STB-compat warnings). Same mechanism as disable_nit().
    void disable_eit() {
        eit_disabled_ = true;
        assemblers_.erase(TS_PID_EIT);
    }

    bool nit_is_disabled() const { return nit_disabled_; }
    bool eit_is_disabled() const { return eit_disabled_; }

    // Register a PMT PID discovered from PAT
    void register_pmt_pid(uint16_t pmt_pid, uint16_t program_number) {
        auto& st              = pmt_[pmt_pid];
        st.name               = "PMT/" + std::to_string(program_number);
        st.pid                = pmt_pid;
        st.interval_limit_s   = TR101290_PMT_INTERVAL_MAX_S;
        st.section_std_limit  = PSI_SECTION_MAX_BYTES;
        st.last_context_id    = program_number;
        assemblers_[pmt_pid];
    }

    // Feed every raw 188-byte TS packet + stream time
    void process_packet(const uint8_t* pkt, double stream_time) {
        if (pkt[0] != TS_SYNC_BYTE) return;

        TsHeader h = parse_ts_header(pkt);

        // Track scrambling for CAT check (P2.7)
        if (h.scrambling != 0)
            scrambling_detected_ = true;

        // Only process PIDs we have assemblers for
        auto asm_it = assemblers_.find(h.pid);
        if (asm_it == assemblers_.end()) return;

        PsiAssembler& asmb = asm_it->second;

        // Locate payload
        int offset = 4;
        if (h.has_adaptation_field) {
            uint8_t af_len = pkt[4];
            offset += 1 + af_len;
        }
        if (!h.has_payload || offset >= TS_PACKET_SIZE)
            return;

        const uint8_t* payload = pkt + offset;
        int payload_len = TS_PACKET_SIZE - offset;

        if (h.payload_unit_start) {
            // payload_len >= 1 guaranteed by (offset < TS_PACKET_SIZE) check above
            uint8_t ptr = payload[0];
            payload++;
            payload_len--;

            // Finish previous section if pointer_field > 0
            if (ptr > 0 && asmb.started && ptr <= payload_len) {
                feed_bytes(asmb, h.pid, payload, ptr);
                payload += ptr;
                payload_len -= ptr;
            }

            asmb.reset();
            asmb.started    = true;
            asmb.start_time = stream_time;
        }

        if (asmb.started && payload_len > 0) {
            feed_bytes(asmb, h.pid, payload, payload_len);
        }
    }

    // Call at end of analysis to flag missing tables
    void finalize(double total_duration_s) {
        flag_missing(pat_,           total_duration_s);
        if (!nit_disabled_) flag_missing(nit_actual_,    total_duration_s);
        flag_missing(sdt_actual_,    total_duration_s);
        if (!eit_disabled_) flag_missing(eit_actual_pf_, total_duration_s);
        flag_missing(tdt_,           total_duration_s);
        for (auto& [pid, st] : pmt_)
            flag_missing(st, total_duration_s);
        if (scrambling_detected_)
            flag_missing(cat_, total_duration_s);
        // EIT schedule sub-tables: flag only those that were seen then went silent.
        // When EIT is disabled, the assembler is erased so no sub-table is ever
        // created — these loops would be empty regardless, but the guard makes
        // the intent explicit and is cheap.
        if (!eit_disabled_) {
            for (auto& [tid, st] : eit_actual_sch_sub_)
                flag_missing(st, total_duration_s);
            for (auto& [tid, st] : eit_other_sch_sub_)
                flag_missing(st, total_duration_s);
        }
    }

    // ── Accessors ────────────────────────────────────────────────────
    const SiTableStats& pat_stats()             const { return pat_; }
    const SiTableStats& cat_stats()             const { return cat_; }
    const SiTableStats& nit_actual_stats()      const { return nit_actual_; }
    const SiTableStats& nit_other_stats()       const { return nit_other_; }
    const SiTableStats& sdt_actual_stats()      const { return sdt_actual_; }
    const SiTableStats& sdt_other_stats()       const { return sdt_other_; }
    const SiTableStats& eit_actual_pf_stats()   const { return eit_actual_pf_; }
    const SiTableStats& eit_other_pf_stats()    const { return eit_other_pf_; }
    const SiTableStats& tdt_stats()             const { return tdt_; }
    const std::map<uint16_t, SiTableStats>& pmt_stats() const { return pmt_; }

    // Per-sub-table EIT schedule maps (keyed by table_id)
    const std::map<uint8_t, SiTableStats>& eit_actual_sch_sub() const { return eit_actual_sch_sub_; }
    const std::map<uint8_t, SiTableStats>& eit_other_sch_sub()  const { return eit_other_sch_sub_; }

    // Aggregated EIT schedule stats (P3.9 / P3.10)
    EitScheduleAggregated eit_actual_sch_aggregated() const {
        return aggregate_eit_sch(eit_actual_sch_sub_);
    }
    EitScheduleAggregated eit_other_sch_aggregated() const {
        return aggregate_eit_sch(eit_other_sch_sub_);
    }

    bool scrambling_detected() const { return scrambling_detected_; }

    // Total CRC errors across all monitored tables (P2.2)
    int64_t total_crc_errors() const {
        int64_t n = pat_.crc_errors + cat_.crc_errors
                  + nit_actual_.crc_errors + nit_other_.crc_errors
                  + sdt_actual_.crc_errors + sdt_other_.crc_errors
                  + eit_actual_pf_.crc_errors + eit_other_pf_.crc_errors
                  + tdt_.crc_errors;
        for (auto& [pid, st] : pmt_) n += st.crc_errors;
        for (auto& [tid, st] : eit_actual_sch_sub_) n += st.crc_errors;
        for (auto& [tid, st] : eit_other_sch_sub_)  n += st.crc_errors;
        return n;
    }

    // Total section size errors (standard violations)
    int64_t total_section_size_errors() const {
        int64_t n = pat_.section_size_errors + cat_.section_size_errors
                  + nit_actual_.section_size_errors + nit_other_.section_size_errors
                  + sdt_actual_.section_size_errors + sdt_other_.section_size_errors
                  + eit_actual_pf_.section_size_errors + eit_other_pf_.section_size_errors
                  + tdt_.section_size_errors;
        for (auto& [pid, st] : pmt_) n += st.section_size_errors;
        for (auto& [tid, st] : eit_actual_sch_sub_) n += st.section_size_errors;
        for (auto& [tid, st] : eit_other_sch_sub_)  n += st.section_size_errors;
        return n;
    }

    // Total EIT STB compatibility warnings (> 1024 B but <= 4096 B)
    int64_t total_eit_stb_warnings() const {
        int64_t n = eit_actual_pf_.section_size_warnings + eit_other_pf_.section_size_warnings;
        for (auto& [tid, st] : eit_actual_sch_sub_) n += st.section_size_warnings;
        for (auto& [tid, st] : eit_other_sch_sub_)  n += st.section_size_warnings;
        return n;
    }

    // Max EIT section size observed across all EIT types
    int max_eit_section_size() const {
        int m = eit_actual_pf_.section_max_bytes;
        if (eit_other_pf_.section_max_bytes > m) m = eit_other_pf_.section_max_bytes;
        for (auto& [tid, st] : eit_actual_sch_sub_)
            if (st.section_max_bytes > m) m = st.section_max_bytes;
        for (auto& [tid, st] : eit_other_sch_sub_)
            if (st.section_max_bytes > m) m = st.section_max_bytes;
        return m;
    }

    // Unreferenced PIDs (P3.4)
    std::set<uint16_t> find_unreferenced_pids(
        const std::map<uint16_t, int64_t>& all_pid_bytes,
        const std::set<uint16_t>& referenced_pids) const
    {
        std::set<uint16_t> result;
        for (auto& [pid, bytes] : all_pid_bytes) {
            if (pid == TS_PID_NULL) continue;
            if (!referenced_pids.count(pid))
                result.insert(pid);
        }
        return result;
    }

private:
    static void init_table(SiTableStats& st, const char* name, uint16_t pid,
                           double limit, int sec_limit = 0) {
        st.name              = name;
        st.pid               = pid;
        st.interval_limit_s  = limit;
        st.section_std_limit = sec_limit;
    }

    // Get or create an EIT schedule sub-table tracker
    SiTableStats& get_eit_sch_sub(std::map<uint8_t, SiTableStats>& map, uint8_t table_id) {
        auto it = map.find(table_id);
        if (it != map.end()) return it->second;
        auto& st = map[table_id];
        std::ostringstream name;
        name << "EIT_sch/0x" << std::hex << std::setfill('0')
             << std::setw(2) << static_cast<int>(table_id);
        st.name             = name.str();
        st.pid              = TS_PID_EIT;
        st.interval_limit_s = TR101290_EIT_SCH_MAX_S;
        st.section_std_limit = EIT_SECTION_MAX_BYTES;
        return st;
    }

    // Aggregate per-sub-table stats into a summary
    static EitScheduleAggregated aggregate_eit_sch(const std::map<uint8_t, SiTableStats>& subs) {
        EitScheduleAggregated agg;
        for (auto& [tid, st] : subs) {
            if (st.seen_at_least_once) agg.sub_tables_seen++;
            agg.total_interval_violations += st.interval_violations;
            agg.total_crc_errors          += st.crc_errors;
            agg.total_section_size_errors += st.section_size_errors;
            agg.total_section_size_warnings += st.section_size_warnings;
            if (st.section_max_bytes > agg.section_max_bytes)
                agg.section_max_bytes = st.section_max_bytes;
            if (st.max_interval > agg.worst_max_interval)
                agg.worst_max_interval = st.max_interval;
            if (st.interval_violations > 0)
                agg.sub_tables_with_violations++;
            if (st.seen_at_least_once) agg.any_seen = true;
        }
        return agg;
    }

    // Feed assembled bytes to the section buffer
    void feed_bytes(PsiAssembler& asmb, uint16_t pid,
                    const uint8_t* data, int len)
    {
        // Clamp to avoid runaway accumulation (4096 + margin for oversize detection)
        int room = 4200 - static_cast<int>(asmb.buf.size());
        if (len > room) len = room;
        if (len <= 0) return;

        asmb.buf.insert(asmb.buf.end(), data, data + len);

        // Need at least 3 bytes to parse section header
        if (asmb.expected_len == 0 && asmb.buf.size() >= 3) {
            int sec_len = psi_section_length(asmb.buf.data());
            asmb.expected_len = 3 + sec_len;
            if (asmb.expected_len > 4200) {
                asmb.reset();
                return;
            }
        }

        // Check if section is complete
        if (asmb.expected_len > 0 &&
            static_cast<int>(asmb.buf.size()) >= asmb.expected_len)
        {
            on_section_complete(pid, asmb.buf.data(), asmb.expected_len, asmb.start_time);
            asmb.reset();
        }
    }

    // Dispatch a complete PSI section
    void on_section_complete(uint16_t pid, const uint8_t* section, int len, double t) {
        if (len < 3) return;
        uint8_t table_id = section[0];

        switch (pid) {
        case TS_PID_PAT:
            process_section(pat_, section, len, t, true);
            break;
        case TS_PID_CAT:
            process_section(cat_, section, len, t, true);
            break;
        case TS_PID_NIT:
            if (table_id == TID_NIT_ACTUAL)
                process_section(nit_actual_, section, len, t, true);
            else if (table_id == TID_NIT_OTHER)
                process_section(nit_other_, section, len, t, true);
            break;
        case TS_PID_SDT:
            if (table_id == TID_SDT_ACTUAL)
                process_section(sdt_actual_, section, len, t, true);
            else if (table_id == TID_SDT_OTHER)
                process_section(sdt_other_, section, len, t, true);
            break;
        case TS_PID_EIT:
            if (table_id == TID_EIT_ACTUAL_PF)
                process_section(eit_actual_pf_, section, len, t, true);
            else if (table_id == TID_EIT_OTHER_PF)
                process_section(eit_other_pf_, section, len, t, true);
            else if (table_id >= TID_EIT_ACTUAL_SCH_MIN && table_id <= TID_EIT_ACTUAL_SCH_MAX)
                process_section(get_eit_sch_sub(eit_actual_sch_sub_, table_id),
                                section, len, t, true);
            else if (table_id >= TID_EIT_OTHER_SCH_MIN && table_id <= TID_EIT_OTHER_SCH_MAX)
                process_section(get_eit_sch_sub(eit_other_sch_sub_, table_id),
                                section, len, t, true);
            break;
        case TS_PID_TDT:
            if (table_id == TID_TDT)
                process_section(tdt_, section, len, t, false);
            else if (table_id == TID_TOT)
                process_section(tdt_, section, len, t, true);
            break;
        default:
            if (pmt_.count(pid) && table_id == TID_PMT)
                process_section(pmt_[pid], section, len, t, true);
            break;
        }
    }

    // Process a complete section: size check, CRC check, interval update, version check
    void process_section(SiTableStats& st, const uint8_t* section, int len,
                         double t, bool has_crc)
    {
        // Section size tracking
        if (len > st.section_max_bytes)
            st.section_max_bytes = len;
        if (st.section_std_limit > 0 && len > st.section_std_limit)
            st.section_size_errors++;
        if (st.section_std_limit == EIT_SECTION_MAX_BYTES
            && len > EIT_SECTION_STB_COMPAT_BYTES
            && len <= EIT_SECTION_MAX_BYTES)
            st.section_size_warnings++;

        // CRC check (P2.2)
        if (has_crc) {
            if (!check_psi_crc(section, static_cast<size_t>(len))) {
                st.crc_errors++;
                return;
            }
        }

        // Interval update
        if (st.last_seen >= 0 && t > st.last_seen) {
            double interval = t - st.last_seen;
            if (interval > st.max_interval)
                st.max_interval = interval;
            st.interval_count++;
            if (st.interval_limit_s > 0 && interval > st.interval_limit_s)
                st.interval_violations++;
        }
        st.last_seen          = t;
        st.seen_at_least_once = true;

        // Version check (P1.3a, P1.5a)
        if (has_crc && len >= 6) {
            uint8_t  version    = psi_section_version(section);
            uint16_t context_id = psi_table_id_extension(section);
            if (st.last_version != 0xFF) {
                if (version != st.last_version && context_id == st.last_context_id)
                    st.version_errors++;
            }
            st.last_version    = version;
            st.last_context_id = context_id;
        }
    }

    void flag_missing(SiTableStats& st, double total_duration_s) {
        if (!st.seen_at_least_once && st.interval_limit_s > 0) {
            if (total_duration_s > st.interval_limit_s)
                st.interval_violations++;
        }
    }

    // ── State ─────────────────────────────────────────────────────────
    SiTableStats pat_, cat_;
    SiTableStats nit_actual_, nit_other_;
    SiTableStats sdt_actual_, sdt_other_;
    SiTableStats eit_actual_pf_, eit_other_pf_;
    SiTableStats tdt_;
    std::map<uint16_t, SiTableStats> pmt_;

    // EIT schedule: per sub-table (keyed by table_id)
    std::map<uint8_t, SiTableStats> eit_actual_sch_sub_;  // 0x50–0x5F
    std::map<uint8_t, SiTableStats> eit_other_sch_sub_;   // 0x60–0x6F

    std::map<uint16_t, PsiAssembler> assemblers_;
    bool scrambling_detected_ = false;
    bool nit_disabled_        = false;   // set by disable_nit()
    bool eit_disabled_        = false;   // set by disable_eit()
};
