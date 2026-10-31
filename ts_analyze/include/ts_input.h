/*
 * Copyright 2026 Perfect Soft
 * SPDX-License-Identifier: Apache-2.0
 */
#pragma once
/*
 * ts_input.h — TS packet reader: file (.ts) and UDP (multicast + unicast)
 */

#include "ts_common.h"
#include "iat_analyzer.h"

#include <string>
#include <stdexcept>
#include <cstdio>
#include <cstring>
#include <cerrno>

#include <sys/types.h>
#include <sys/socket.h>
#include <netinet/in.h>
#include <arpa/inet.h>
#include <unistd.h>
#include <fcntl.h>
#include <poll.h>
#include <sys/time.h>
#include <memory>

// ─── High-resolution monotonic clock ────────────────────────────────
#include <time.h>

inline double monotonic_time()
{
    struct timespec ts;
    clock_gettime(CLOCK_MONOTONIC, &ts);
    return (double) ts.tv_sec + (double) ts.tv_nsec * 1e-9;
}

// ─── Abstract base ──────────────────────────────────────────────────
class TsInput
{
public:
    virtual ~TsInput() = default;

    // Read one 188-byte TS packet; returns false on EOF/timeout.
    // *arrival_time is set to monotonic time when packet was received.
    virtual bool read_packet(uint8_t pkt[TS_PACKET_SIZE], double *arrival_time) = 0;

    // Descriptive source name
    virtual std::string source_name() const = 0;

    // Stream time the input holds in seconds, or 0 when unknown (live).
    virtual double span_s() const { return 0.0; }

    // Live inputs: how long to wait for the first datagram (--wait-s).
    virtual void set_first_wait(double /*seconds*/) {}

    // True for live network sources (UDP). False for file-based input.
    // Used to gate network-only metrics like IAT.
    virtual bool is_network() const { return false; }

    // Attach an IAT analyzer; called once per UDP datagram on arrival.
    // Network inputs override this; file input ignores it.
    virtual void set_iat_analyzer(IatAnalyzer * /*analyzer*/) {}
};

// ─── File input ─────────────────────────────────────────────────────
/// File input: packet times are synthesized from the -b bitrate hint (default 38.8 Mbit/s), so timing checks follow the hint, not the file.
class TsFileInput: public TsInput
{
    FILE *fp_ = nullptr;
    std::string path_;
    int64_t pkt_count_ = 0;
    double start_time_ = 0;
    double bitrate_estimate_ = 0;   // if 0, use default 38.8 Mbit/s
    long   data_bytes_ = 0;         // from the first sync byte to EOF

public:
    explicit TsFileInput(const std::string &path, double bitrate_mbps = 0.0) :
            path_(path)
    {
        fp_ = fopen(path.c_str(), "rb");
        if (!fp_)
            throw std::runtime_error("Cannot open file: " + path + " (" + strerror(errno) + ")");

        // Detect packet size (handle 204-byte packets → skip to 188)
        // Simple approach: seek to first sync byte
        int c;
        long sync_pos = -1;
        while ((c = fgetc(fp_)) != EOF)
        {
            if (c == TS_SYNC_BYTE)
            {
                // Verify next sync byte at +188
                long pos = ftell(fp_) - 1;
                fseek(fp_, pos + TS_PACKET_SIZE, SEEK_SET);
                int c2 = fgetc(fp_);
                if (c2 == TS_SYNC_BYTE)
                {
                    sync_pos = pos;
                    break;
                }
                fseek(fp_, pos + 1, SEEK_SET);
            }
        }
        if (sync_pos < 0)
            throw std::runtime_error("No valid TS sync found in: " + path);

        fseek(fp_, 0, SEEK_END);
        data_bytes_ = ftell(fp_) - sync_pos;
        fseek(fp_, sync_pos, SEEK_SET);

        if (bitrate_mbps > 0.0)
            bitrate_estimate_ = bitrate_mbps * 1e6;
        else
            bitrate_estimate_ = 38800000.0;   // ~38.8 Mbit/s DVB default

        start_time_ = monotonic_time();
    }

    ~TsFileInput() override
    {
        if (fp_)
            fclose(fp_);
    }

    bool read_packet(uint8_t pkt[TS_PACKET_SIZE], double *arrival_time) override
    {
        if (!fp_)
            return false;

        size_t n = fread(pkt, 1, TS_PACKET_SIZE, fp_);
        if (n < (size_t) TS_PACKET_SIZE)
            return false;

        // Resync if needed. A bad sync byte on a packet whose successor is
        // aligned (or the file ends) is a sync byte error of this packet, not
        // a lost alignment: it is returned as it is for the checker to count.
        bool aligned = true;
        if (pkt[0] != TS_SYNC_BYTE)
        {
            // Alignment holds when one of the next 4 packet starts (or the
            // end of the file) is where it should be: a run of bad sync
            // bytes up to that length is counted, not resynchronised.
            aligned = false;
            long here = ftell(fp_);
            for (int k = 0; k < 4 && !aligned; k++)
            {
                if (fseek(fp_, here + (long) k * TS_PACKET_SIZE, SEEK_SET) != 0)
                    break;
                int c = fgetc(fp_);
                aligned = c == EOF || c == TS_SYNC_BYTE;
            }
            fseek(fp_, here, SEEK_SET);
        }
        if (!aligned)
        {
            // Scan for next sync
            for (int i = 1; i < TS_PACKET_SIZE; i++)
            {
                if (pkt[i] == TS_SYNC_BYTE)
                {
                    // Read remaining bytes
                    memmove(pkt, pkt + i, TS_PACKET_SIZE - i);
                    n = fread(pkt + TS_PACKET_SIZE - i, 1, i, fp_);
                    if (n < (size_t) i)
                        return false;
                    break;
                }
            }
            if (pkt[0] != TS_SYNC_BYTE)
                return false;
        }

        // Simulate arrival time based on packet number and bitrate
        pkt_count_++;
        double pkt_duration = (TS_PACKET_SIZE * 8.0) / bitrate_estimate_;
        *arrival_time = start_time_ + static_cast<double>(pkt_count_) * pkt_duration;

        return true;
    }

    std::string source_name() const override
    {
        return "file://" + path_;
    }

    double span_s() const override
    {
        return static_cast<double>(data_bytes_ / TS_PACKET_SIZE)
               * (TS_PACKET_SIZE * 8.0) / bitrate_estimate_;
    }

    double bitrate_bps() const { return bitrate_estimate_; }
};

// ─── Multicast address detection ────────────────────────────────────
// IPv4 multicast: 224.0.0.0 – 239.255.255.255 (first octet 224–239)
inline bool is_multicast_addr(const std::string &addr)
{
    struct in_addr ia
    { };
    if (inet_pton(AF_INET, addr.c_str(), &ia) != 1)
        return false;
    uint32_t host = ntohl(ia.s_addr);
    return (host >> 28) == 0x0E;   // 0xE0..0xEF = 224..239
}

// Opens a UDP receive socket on addr:port (multicast joined on iface when the
// address is a group; unicast bound to it); throws on failure.
inline int open_udp_socket(const std::string &addr, uint16_t port, const std::string &iface)
{
    bool multicast = is_multicast_addr(addr);

    int sock = socket(AF_INET, SOCK_DGRAM, 0);
    if (sock < 0)
        throw std::runtime_error(std::string("socket(): ") + strerror(errno));

    int reuse = 1;
    setsockopt(sock, SOL_SOCKET, SO_REUSEADDR, &reuse, sizeof(reuse));
#ifdef SO_REUSEPORT
    setsockopt(sock, SOL_SOCKET, SO_REUSEPORT, &reuse, sizeof(reuse));
#endif

    // Increase receive buffer
    int rcvbuf = 4 * 1024 * 1024;
    setsockopt(sock, SOL_SOCKET, SO_RCVBUF, &rcvbuf, sizeof(rcvbuf));

    struct sockaddr_in sa
    { };
    sa.sin_family = AF_INET;
    sa.sin_port = htons(port);

    if (multicast)
    {
        // Multicast: bind to the group address for kernel-level filtering
        sa.sin_addr.s_addr = inet_addr(addr.c_str());

        if (bind(sock, (struct sockaddr*) &sa, sizeof(sa)) < 0)
            throw std::runtime_error(std::string("bind(): ") + strerror(errno));

        struct ip_mreq mreq
        { };
        mreq.imr_multiaddr.s_addr = inet_addr(addr.c_str());

        if (!iface.empty())
        {
            // Interface can be an IP address or a name
            struct in_addr if_addr
            { };
            if (inet_pton(AF_INET, iface.c_str(), &if_addr) == 1)
            {
                mreq.imr_interface = if_addr;
            }
            else
            {
                // Try as interface name via SO_BINDTODEVICE
                mreq.imr_interface.s_addr = htonl(INADDR_ANY);
                if (setsockopt(sock, SOL_SOCKET, SO_BINDTODEVICE, iface.c_str(), static_cast<socklen_t>(iface.size() + 1))
                        < 0)
                    throw std::runtime_error("SO_BINDTODEVICE(" + iface + "): " + strerror(errno));
            }
        }
        else
        {
            mreq.imr_interface.s_addr = htonl(INADDR_ANY);
        }

        if (setsockopt(sock, IPPROTO_IP, IP_ADD_MEMBERSHIP, &mreq, sizeof(mreq)) < 0)
            throw std::runtime_error(std::string("IP_ADD_MEMBERSHIP: ") + strerror(errno));
    }
    else
    {
        // Unicast: bind to the specific address + port
        sa.sin_addr.s_addr = inet_addr(addr.c_str());

        // Bind to interface if specified
        if (!iface.empty())
        {
            if (setsockopt(sock, SOL_SOCKET, SO_BINDTODEVICE, iface.c_str(), static_cast<socklen_t>(iface.size() + 1)) < 0)
                throw std::runtime_error("SO_BINDTODEVICE(" + iface + "): " + strerror(errno));
        }

        if (bind(sock, (struct sockaddr*) &sa, sizeof(sa)) < 0)
            throw std::runtime_error(std::string("bind(): ") + strerror(errno));
    }
    return sock;
}

// ─── UDP input (multicast + unicast) ────────────────────────────────
class TsUdpInput: public TsInput
{
    int sock_ = -1;
    std::string addr_;
    uint16_t port_;
    std::string iface_;
    bool multicast_ = false;

    // Internal buffer: UDP datagrams may carry multiple TS packets (7×188 typical)
    uint8_t buf_[65536];
    int buf_len_ = 0;
    int buf_pos_ = 0;
    bool aligned_ = false;          // the TS payload is whole packets: serve by offset
    bool got_any_ = false;          // a datagram arrived
    int first_wait_ms_ = 10000;     // wait for the first one; then 1 s of silence ends
    double dgram_arrival_ = 0;

    IatAnalyzer *iat_analyzer_ = nullptr;

public:
    TsUdpInput(const std::string &addr, uint16_t port, const std::string &iface = "") :
            addr_(addr), port_(port), iface_(iface)
    {
        multicast_ = is_multicast_addr(addr);
        sock_ = open_udp_socket(addr, port, iface);
    }

    ~TsUdpInput() override
    {
        if (sock_ >= 0)
            close(sock_);
    }

    /// Whole-packet datagrams are served by offset (a bad sync byte stays in place); waits --wait-s for the first datagram, then 1 s of silence ends the input.
    bool read_packet(uint8_t pkt[TS_PACKET_SIZE], double *arrival_time) override
    {
        while (true)
        {
            // Serve from buffer. A datagram of whole TS packets is served
            // by offset, so a corrupted sync byte reaches the checker as a
            // sync byte error instead of shifting the packet boundaries.
            if (buf_pos_ + TS_PACKET_SIZE <= buf_len_)
            {
                // Find sync byte
                while (!aligned_ && buf_pos_ + TS_PACKET_SIZE <= buf_len_ && buf_[buf_pos_] != TS_SYNC_BYTE)
                    buf_pos_++;

                if (buf_pos_ + TS_PACKET_SIZE <= buf_len_)
                {
                    memcpy(pkt, buf_ + buf_pos_, TS_PACKET_SIZE);
                    buf_pos_ += TS_PACKET_SIZE;
                    *arrival_time = dgram_arrival_;
                    return true;
                }
            }

            // Read new datagram
            struct pollfd pfd
            { };
            pfd.fd = sock_;
            pfd.events = POLLIN;
            int ret = poll(&pfd, 1, got_any_ ? 1000 : first_wait_ms_);
            if (ret <= 0)
                return false;
            got_any_ = true;

            dgram_arrival_ = monotonic_time();
            ssize_t n = recv(sock_, buf_, sizeof(buf_), 0);
            if (n <= 0)
                return false;

            // Record datagram arrival for IAT analysis (network jitter).
            if (iat_analyzer_)
                iat_analyzer_->add_arrival(dgram_arrival_);

            buf_len_ = (int) n;
            buf_pos_ = 0;

            // Handle RTP header (if present): starts with 0x80, not 0x47, and
            // the datagram is not whole TS packets
            if (buf_len_ > 12 && buf_[0] != TS_SYNC_BYTE && (buf_[0] & 0xC0) == 0x80
                && buf_len_ % TS_PACKET_SIZE != 0)
            {
                int rtp_hdr = 12;
                int cc = buf_[0] & 0x0F;
                rtp_hdr += cc * 4;
                if (buf_[0] & 0x10)
                {  // extension
                    if (rtp_hdr + 4 <= buf_len_)
                    {
                        int ext_len = (buf_[rtp_hdr + 2] << 8) | buf_[rtp_hdr + 3];
                        rtp_hdr += 4 + ext_len * 4;
                    }
                }
                buf_pos_ = rtp_hdr;
            }
            aligned_ = buf_pos_ < buf_len_ && (buf_len_ - buf_pos_) % TS_PACKET_SIZE == 0;
        }
    }

    std::string source_name() const override
    {
        std::string name = "udp://";
        if (!iface_.empty())
            name += iface_ + "@";
        name += addr_ + ":" + std::to_string(port_);
        name += multicast_ ? " (multicast)" : " (unicast)";
        return name;
    }

    bool is_network() const override { return true; }
    void set_iat_analyzer(IatAnalyzer *a) override { iat_analyzer_ = a; }
    void set_first_wait(double s) override { first_wait_ms_ = (int) (s * 1000); }
};

// ─── Factory ────────────────────────────────────────────────────────
// Parse input string:  "udp://239.1.1.1:1234"  or  "file.ts"
// Multicast is auto-detected from IP range 224.0.0.0/4
inline std::unique_ptr<TsInput> create_input(const std::string &uri, const std::string &iface = "", double bitrate_mbps = 0.0)
{
    if (uri.substr(0, 6) == "udp://")
    {
        // Parse  udp://addr:port
        std::string rest = uri.substr(6);
        auto colon = rest.rfind(':');
        if (colon == std::string::npos)
            throw std::runtime_error("UDP URI must be udp://address:port");
        std::string addr = rest.substr(0, colon);
        uint16_t port = (uint16_t) std::stoi(rest.substr(colon + 1));
        return std::make_unique<TsUdpInput>(addr, port, iface);
    }
    // Default: file
    std::string path = uri;
    if (path.substr(0, 7) == "file://")
        path = path.substr(7);
    return std::make_unique<TsFileInput>(path, bitrate_mbps);
}
