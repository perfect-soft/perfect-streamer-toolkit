/*
 * Copyright 2026 Perfect Soft
 * SPDX-License-Identifier: Apache-2.0
 */
#pragma once
/*
 * st2022_input.h — RTP input with SMPTE ST 2022-1 FEC and ST 2022-7
 * seamless protection (--rtp, --fec, --path2).
 *
 * Only the standard transport is accepted: media on the path's port, column
 * FEC on port+2 and row FEC on port+4 of the same address (ST 2022-1 8.5).
 * FEC multiplexed into the media port is not supported: such datagrams carry
 * another payload type and count as protocol errors on that path.
 *
 * The datagrams of both paths and their FEC go into one RtpMerge; the TS
 * packets it releases (in RTP sequence order, gaps filled by the other path
 * or by FEC) feed the analyzers. Their time is the release time, i.e. what a
 * receiver after the merge sees.
 */

#include "ts_input.h"
#include "iat_analyzer.h"
#include "st2022_summary.h"
#include "events.h"
#include "rtp_merge.h"

#include <algorithm>
#include <array>
#include <deque>
#include <memory>
#include <string>

// Splits "udp://addr:port" (the iface is parsed off before) into its parts.
inline void parse_udp_uri(const std::string &uri, std::string &addr, uint16_t &port)
{
    if (uri.substr(0, 6) != "udp://")
        throw std::runtime_error("not a udp:// URI: " + uri);
    std::string rest = uri.substr(6);
    auto colon = rest.rfind(':');
    if (colon == std::string::npos)
        throw std::runtime_error("UDP URI must be udp://address:port");
    addr = rest.substr(0, colon);
    int p = std::stoi(rest.substr(colon + 1));
    if (p <= 0 || p > 65535)
        throw std::runtime_error("bad UDP port in " + uri);
    port = (uint16_t) p;
}

class St2022Input: public TsInput
{
public:
    struct Path
    {
        std::string uri;            // udp://addr:port
        std::string iface;
    };

    St2022Input(const St2022Options &opt, const Path &p1, const Path *p2) :
            opt_(opt)
    {
        paths_ = p2 ? 2 : 1;
        for (int i = 0; i < paths_; i++)
        {
            const Path &p = i == 0 ? p1 : *p2;
            std::string addr;
            uint16_t port = 0;
            parse_udp_uri(p.uri, addr, port);
            if (opt_.fec && port > 65535 - 4)
                throw std::runtime_error("FEC needs port+2 and port+4: port too high in " + p.uri);
            track_[i].source = std::string("udp://") + (p.iface.empty() ? "" : p.iface + "@")
                               + addr + ":" + std::to_string(port)
                               + (is_multicast_addr(addr) ? " (multicast)" : " (unicast)");
            add_fd(open_udp_socket(addr, port, p.iface), i, Kind::Media);
            if (opt_.fec)
            {
                add_fd(open_udp_socket(addr, (uint16_t) (port + 2), p.iface), i, Kind::Fec);
                add_fd(open_udp_socket(addr, (uint16_t) (port + 4), p.iface), i, Kind::Fec);
            }
        }

        St2022::RtpMerge::Params mp;
        mp.legs = paths_;
        mp.waitNs = (int64_t) (opt_.path_skew_ms * 1e6);
        mp.legSilentNs = std::max<int64_t>(mp.legSilentNs, mp.waitNs);
        mp.fec = opt_.fec;
        merge_ = std::make_unique<St2022::RtpMerge>(mp,
                [this](const uchar *d, uint len, uint32_t, int64_t arrival) { return on_data(d, len, arrival); },
                [this](St2022::RtpMerge::Reset) { resets_++; });
    }

    ~St2022Input() override
    {
        for (auto &f : fds_)
            close(f.fd);
    }

    bool read_packet(uint8_t pkt[TS_PACKET_SIZE], double *arrival_time) override
    {
        while (pkts_.empty())
        {
            double now = monotonic_time();
            bool waiting = merge_->waiting();
            if (!waiting && (last_any_ > 0 ? now - last_any_ >= 1.0 : now - opened_ >= first_wait_s_))
                return false;       // 1 s of silence on every path (or none within --wait-s): the end

            std::vector<pollfd> pfds(fds_.size());
            for (size_t i = 0; i < fds_.size(); i++)
                pfds[i] = { fds_[i].fd, POLLIN, 0 };
            int ret = poll(pfds.data(), pfds.size(), waiting ? 10 : 100);
            if (ret < 0)
                return false;
            for (size_t i = 0; i < fds_.size(); i++)
                if (pfds[i].revents & POLLIN)
                    drain(fds_[i]);

            now = monotonic_time();
            cur_now_ = now;
            if (merge_->waiting())
                merge_->poll(ns(now));
            sample(now);
        }
        *arrival_time = pkts_.front().t;
        memcpy(pkt, pkts_.front().d.data(), TS_PACKET_SIZE);
        pkts_.pop_front();
        return true;
    }

    std::string source_name() const override
    {
        if (paths_ == 1)
            return track_[0].source;
        return track_[0].source + " + " + track_[1].source;
    }

    bool is_network() const override { return true; }
    void set_iat_analyzer(IatAnalyzer *a) override { iat_main_ = a; }
    void set_first_wait(double s) override { first_wait_s_ = s; }

    /// Totals for the reports and the verdict; `now` closes an open silence.
    St2022Summary summary(double now) const
    {
        St2022Summary s;
        s.enabled = true;
        s.fec = opt_.fec;
        s.two_paths = paths_ == 2;
        s.skew_limit_ms = opt_.path_skew_ms;
        double lim = max_limit_s_;
        for (int i = 0; i < paths_; i++)
            lim = std::max(lim, limit_s(i));
        s.silence_limit_ms = lim * 1e3;

        const St2022::RtpMerge::Stat st = merge_->stat(ns(now));
        for (int i = 0; i < paths_; i++)
        {
            St2022PathSummary &p = s.path[i];
            const Track &t = track_[i];
            const auto &l = st.leg[i];
            p.present = true;
            p.source = t.source;
            p.down_s = t.down_s;
            p.down_events = t.down_events;
            double ref = t.seen ? t.last : first_any_;
            double limit = limit_s(i);
            double down = first_any_ > 0 && now - ref > limit ? down_part(i, ref, now) : 0;
            if (down > limit)
            {
                p.down_s += down;
                p.down_events++;
                p.up = false;
                if (Events::on())
                    Events::get().note("S.3", -1, "path " + std::to_string(i + 1) + " silent until the end",
                                       Events::get().rel(ref));
            }
            else
                p.up = t.seen;
            if (first_any_ == 0)
            {
                p.down_s = now - opened_;
                p.down_events = 1;
            }
            p.received = l.received;
            p.lost = l.lost;
            p.dup = l.dup;
            p.late = l.late;
            p.proto_errors = l.protoErrors;
            p.ssrc_changes = l.ssrcChanges;
            p.ignored = l.ignored;
            p.ssrc = l.ssrc;
            p.fec_datagrams = t.fec_datagrams;
            p.iat = t.iat;
        }
        s.released = st.released;
        s.unrecoverable = st.lost;
        s.overflow = st.overflow;
        s.start_check_lost = verified_once_ ? start_lost_ : 0;
        s.repaired = st.repaired;
        s.compares = st.compares;
        s.mismatches = st.mismatches;
        s.resets = resets_;
        s.paths_differ = differ_seen_ || st.legsDiffer;
        s.verified = st.verified;
        s.skew_p50_ms = st.skewP50Ns / 1e6;
        s.skew_max_ms = std::max(skew_max_ns_, std::abs(st.skewMaxNs)) / 1e6;
        s.wait_ms = st.waitNs / 1e6;
        s.fec_received[0] = st.fec.received[0];
        s.fec_received[1] = st.fec.received[1];
        s.fec_dup = st.fec.dup;
        s.fec_bad = st.fec.badHeader;
        s.fec_ssrc_nonzero = st.fec.ssrcNonZero;
        s.fec_recovered[0] = st.fec.recovered[0];
        s.fec_recovered[1] = st.fec.recovered[1];
        s.fec_refused = st.fec.refused;
        s.fec_len_fixups = st.lenFixups;
        s.fec_L = st.fec.L;
        s.fec_D = st.fec.D;
        s.fec_absent_s = fec_absent_s_;
        return s;
    }

private:
    enum class Kind { Media, Fec };
    struct Fd
    {
        int fd;
        int path;
        Kind kind;
    };
    struct Track
    {
        std::string source;
        bool seen = false;
        double last = 0;
        double interval = 0;        // EWMA of the datagram interval
        double gap_from = 0, gap_to = 0;    // its last silence (> 50 ms)
        double down_s = 0;
        int64_t down_events = 0;
        uint64_t fec_datagrams = 0;
        IatAnalyzer iat;
    };
    struct Pkt
    {
        std::array<uint8_t, TS_PACKET_SIZE> d;
        double t;
    };

    static int64_t ns(double s) { return (int64_t) (s * 1e9); }

    void add_fd(int fd, int path, Kind kind)
    {
        fds_.push_back({ fd, path, kind });
    }

    /// S.3 silence limit: a path is down while silent longer than max(--path-skew-ms, 100 ms, 4 datagram intervals).
    double limit_s(int path) const
    {
        return std::max({ opt_.path_skew_ms / 1e3, 0.1, 4 * track_[path].interval });
    }

    // How much of this path's silence [from, to] the path was down: the part the other path was not silent too (both
    // silent at once is a pause of the source, not lost redundancy). With one path all of it.
    double down_part(int path, double from, double to) const
    {
        if (paths_ < 2)
            return to - from;
        const Track &o = track_[1 - path];
        auto overlap = [&](double a, double b) { return std::max(0.0, std::min(b, to) - std::max(a, from)); };
        double both = overlap(o.gap_from, o.gap_to) + overlap(o.seen ? o.last : first_any_, to);
        return std::max(0.0, to - from - both);
    }

    void drain(const Fd &f)
    {
        while (true)
        {
            ssize_t n = recv(f.fd, buf_, sizeof(buf_), MSG_DONTWAIT);
            if (n <= 0)
                return;
            double now = monotonic_time();
            cur_now_ = now;
            if (first_any_ == 0)
                first_any_ = now;
            last_any_ = now;
            Track &t = track_[f.path];
            if (f.kind == Kind::Fec)
            {
                t.fec_datagrams++;
                merge_->pushFec(f.path, buf_, (uint) n, ns(now));
                continue;
            }
            arrival(f.path, now);
            merge_->pushMedia(f.path, buf_, (uint) n, ns(now));
            if (paths_ == 2 && !verified_once_)
                start_check(now);
        }
    }

    void arrival(int path, double now)
    {
        Track &t = track_[path];
        double ref = t.seen ? t.last : first_any_;
        double gap = now - ref;
        double limit = limit_s(path);
        max_limit_s_ = std::max(max_limit_s_, limit);
        double down = gap > limit ? down_part(path, ref, now) : 0;
        if (gap > 0.05)
        {
            t.gap_from = ref;           // the last silence, for the other path's down_part
            t.gap_to = now;
        }
        if (down > limit)
        {
            t.down_s += down;
            t.down_events++;
            if (Events::on())
                Events::get().note("S.3", -1, "path " + std::to_string(path + 1) + " silent "
                                   + std::to_string((int) (down * 1e3)) + " ms", Events::get().rel(ref));
        }
        else if (t.seen && gap <= limit)
            t.interval = t.interval > 0 ? 0.9 * t.interval + 0.1 * gap : gap;
        t.seen = true;
        t.last = now;
        t.iat.add_arrival(now);
        if (path == 0 && iat_main_)
            iat_main_->add_arrival(now);
    }

    // The merge releases payloads (TS packets) in sequence order. Their time is the arrival of the copy used, not the
    // release: a datagram held behind a gap (seconds while FEC may still come) keeps its own time for PCR accuracy
    // and T-STD. A rebuilt one (arrival 0) takes its predecessor's; times never go back.
    bool on_data(const uchar *d, uint len, int64_t arrival)
    {
        double t = arrival > 0 ? arrival / 1e9 : last_out_t_;
        if (t < last_out_t_ || t <= 0)
            t = last_out_t_ > 0 ? last_out_t_ : cur_now_;
        last_out_t_ = t;
        uint i = 0;
        const bool aligned = len % TS_PACKET_SIZE == 0;     // whole packets: by offset
        while (i + TS_PACKET_SIZE <= len)
        {
            if (!aligned && d[i] != TS_SYNC_BYTE)
            {
                i++;
                continue;
            }
            Pkt p;
            memcpy(p.d.data(), d + i, TS_PACKET_SIZE);
            p.t = t;
            pkts_.push_back(p);
            i += TS_PACKET_SIZE;
        }
        return true;
    }

    // Until the paths are first verified equal the merge uses path 1 only; what it lost until then is the start
    // check's (a receiver merging from the first datagram might have repaired it). Never verified: none is.
    void start_check(double now)
    {
        const St2022::RtpMerge::Stat st = merge_->stat(ns(now));
        if (!st.verified)
            return;
        verified_once_ = true;
        start_lost_ = st.lost + st.overflow;
    }

    // Every 100 ms: what the merge's 10 s windows would forget.
    void sample(double now)
    {
        if (first_any_ == 0 || now - last_sample_ < 0.1)
            return;
        double dt = last_sample_ > 0 ? now - last_sample_ : 0;
        last_sample_ = now;
        const St2022::RtpMerge::Stat st = merge_->stat(ns(now));
        if (Events::on())
            note_changes(st, now);
        skew_max_ns_ = std::max(skew_max_ns_, std::abs(st.skewMaxNs));
        if (st.legsDiffer)
            differ_seen_ = true;
        if (opt_.fec)
        {
            uint64_t fec = st.fec.received[0] + st.fec.received[1];
            if (fec != fec_seen_count_)
            {
                fec_seen_count_ = fec;
                last_fec_ = now;
            }
            double ref = last_fec_ > 0 ? last_fec_ : first_any_;
            if (now - first_any_ >= 2.0 && now - ref > 2.0)
            {
                if (fec_absent_s_ == 0 || now - last_absent_ > 0.15)
                    Events::get().note("S.6", -1, "no valid FEC for 2 s", Events::get().rel(now));
                fec_absent_s_ += dt;
                last_absent_ = now;
            }
        }
    }

    // Events for the JSON report: when the merge's counters moved.
    void note_changes(const St2022::RtpMerge::Stat &st, double now)
    {
        double t = Events::get().rel(now);
        uint64_t lost = st.lost + st.overflow;
        if (lost > ev_lost_)
            Events::get().note("S.1", -1, std::to_string(lost - ev_lost_) + " datagrams", t);
        ev_lost_ = lost;
        for (int i = 0; i < paths_; i++)
        {
            if (st.leg[i].protoErrors > ev_proto_[i])
                Events::get().note("S.2", -1, "path " + std::to_string(i + 1) + ": "
                                   + std::to_string(st.leg[i].protoErrors - ev_proto_[i]) + " datagrams", t);
            ev_proto_[i] = st.leg[i].protoErrors;
        }
        if (st.legsDiffer && !differ_seen_)
            Events::get().note("S.4", -1, "paths differ", t);
        double skew = std::abs(st.skewMaxNs) / 1e6;
        if (skew > opt_.path_skew_ms && !ev_skew_)
            Events::get().note("S.5", -1, "skew " + std::to_string((int) skew) + " ms", t);
        ev_skew_ = skew > opt_.path_skew_ms;
    }

    uint64_t ev_lost_ = 0, ev_proto_[2] = { 0, 0 };
    bool ev_skew_ = false;
    double last_absent_ = 0;

    St2022Options opt_;
    int paths_ = 1;
    std::vector<Fd> fds_;
    std::unique_ptr<St2022::RtpMerge> merge_;
    Track track_[2];
    std::deque<Pkt> pkts_;
    uint8_t buf_[65536];
    IatAnalyzer *iat_main_ = nullptr;
    double opened_ = monotonic_time();
    double first_wait_s_ = 10.0;
    double first_any_ = 0, last_any_ = 0, cur_now_ = 0, last_sample_ = 0;
    double last_out_t_ = 0;               // time of the last released TS packet
    bool verified_once_ = false;          // the paths were verified equal at least once
    uint64_t start_lost_ = 0;             // lost before that
    double max_limit_s_ = 0;
    int64_t skew_max_ns_ = 0;
    bool differ_seen_ = false;
    uint64_t fec_seen_count_ = 0;
    double last_fec_ = 0;
    double fec_absent_s_ = 0;
    uint64_t resets_ = 0;
};
