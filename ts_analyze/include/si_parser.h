/*
 * Copyright 2026 Perfect Soft
 * SPDX-License-Identifier: Apache-2.0
 */
#pragma once
/*
 * si_parser.h — PAT/PMT parsing via libdvbpsi to discover PCR PIDs
 */

#include "ts_common.h"

#include <map>
#include <set>
#include <vector>
#include <mutex>
#include <functional>
#include <cstdio>
#include <memory>

#include <dvbpsi/dvbpsi.h>
#include <dvbpsi/psi.h>
#include <dvbpsi/descriptor.h>
#include <dvbpsi/pat.h>
#include <dvbpsi/pmt.h>

// ─── Program info ───────────────────────────────────────────────────
struct ProgramInfo
{
    uint16_t program_number = 0;
    uint16_t pmt_pid = 0;
    uint16_t pcr_pid = 0;
    bool pcr_pid_known = false;

    struct EsInfo
    {
        uint16_t pid;
        uint8_t stream_type;
    };
    std::vector<EsInfo> es_list;

    std::string stream_type_name(uint8_t st) const
    {
        switch (st)
        {
        case 0x01:
        case 0x02:
            return "MPEG-2 Video";
        case 0x03:
        case 0x04:
            return "MPEG-2 Audio";
        case 0x06:
            return "PES private";
        case 0x0F:
            return "AAC Audio";
        case 0x11:
            return "MPEG-4 AAC";
        case 0x1B:
            return "H.264/AVC";
        case 0x24:
            return "H.265/HEVC";
        case 0x25:
            return "H.266/VVC";
        default:
            return "type=" + std::to_string(st);
        }
    }

    bool is_video_stream_type(uint8_t st) const
    {
        return st == 0x01 || st == 0x02 || st == 0x1B || st == 0x24 || st == 0x25 || st == 0x10;
    }
};

// ─── SI Parser ──────────────────────────────────────────────────────
class SiParser
{
public:
    SiParser()
    {
        pat_dvbpsi_ = dvbpsi_new(&msg_cb, DVBPSI_MSG_NONE);
        if (!pat_dvbpsi_)
            throw std::runtime_error("dvbpsi_new() failed for PAT");
        dvbpsi_pat_attach(pat_dvbpsi_, pat_callback, this);
    }

    ~SiParser()
    {
        if (pat_dvbpsi_)
        {
            dvbpsi_pat_detach(pat_dvbpsi_);
            dvbpsi_delete(pat_dvbpsi_);
        }
        for (auto& [pid, handle] : pmt_handles_)
        {
            dvbpsi_pmt_detach(handle);
            dvbpsi_delete(handle);
        }
    }

    // Feed a raw 188-byte TS packet
    void push_packet(const uint8_t *pkt)
    {
        TsHeader h = parse_ts_header(pkt);

        if (h.pid == TS_PID_PAT)
        {
            dvbpsi_packet_push(pat_dvbpsi_, (uint8_t*) pkt);
        }
        else if (pmt_handles_.count(h.pid))
        {
            dvbpsi_packet_push(pmt_handles_[h.pid], (uint8_t*) pkt);
        }
    }

    // Get all discovered programs
    const std::map<uint16_t, ProgramInfo>& programs() const
    {
        return programs_;
    }

    // Get set of all PCR PIDs
    std::set<uint16_t> pcr_pids() const
    {
        std::set<uint16_t> pids;
        for (auto& [pn, pi] : programs_)
        {
            if (pi.pcr_pid_known)
                pids.insert(pi.pcr_pid);
        }
        return pids;
    }

    bool has_pcr_pids() const
    {
        for (auto& [pn, pi] : programs_)
            if (pi.pcr_pid_known)
                return true;
        return false;
    }

    // True only when PAT has been parsed AND every program announced in PAT
    // has its PCR PID known (i.e. all PMTs have been received). For MPTS
    // streams this is the right condition to leave the SI discovery phase
    // — otherwise we'd commit to whichever single PMT arrived first.
    bool has_all_pcr_pids() const
    {
        if (programs_.empty()) return false;
        for (auto& [pn, pi] : programs_)
            if (!pi.pcr_pid_known)
                return false;
        return true;
    }

private:
    dvbpsi_t *pat_dvbpsi_ = nullptr;
    std::map<uint16_t, dvbpsi_t*> pmt_handles_;   // pmt_pid → handle
    std::map<uint16_t, ProgramInfo> programs_;       // program_number → info

    static void msg_cb(dvbpsi_t*, const dvbpsi_msg_level_t, const char*)
    {
    }

    static void pat_callback(void *opaque, dvbpsi_pat_t *pat)
    {
        auto *self = (SiParser*) opaque;
        dvbpsi_pat_program_t *prog = pat->p_first_program;
        while (prog)
        {
            uint16_t pn = prog->i_number;
            uint16_t pid = prog->i_pid;
            if (pn != 0 && !self->pmt_handles_.count(pid))
            {
                // New PMT PID
                self->programs_[pn].program_number = pn;
                self->programs_[pn].pmt_pid = pid;

                dvbpsi_t *pmt_h = dvbpsi_new(&msg_cb, DVBPSI_MSG_NONE);
                dvbpsi_pmt_attach(pmt_h, pn, pmt_callback, self);
                self->pmt_handles_[pid] = pmt_h;
            }
            prog = prog->p_next;
        }
        dvbpsi_pat_delete(pat);
    }

    static void pmt_callback(void *opaque, dvbpsi_pmt_t *pmt)
    {
        auto *self = (SiParser*) opaque;
        uint16_t pn = pmt->i_program_number;
        auto &pi = self->programs_[pn];
        pi.pcr_pid = pmt->i_pcr_pid;
        pi.pcr_pid_known = true;

        pi.es_list.clear();
        dvbpsi_pmt_es_t *es = pmt->p_first_es;
        while (es)
        {
            pi.es_list.push_back(
            { es->i_pid, es->i_type });
            es = es->p_next;
        }
        dvbpsi_pmt_delete(pmt);
    }
};
