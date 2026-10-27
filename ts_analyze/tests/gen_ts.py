#!/usr/bin/env python3
# Copyright 2026 Perfect Soft
# SPDX-License-Identifier: Apache-2.0
"""Write a small synthetic, TR 101 290-clean MPEG-TS file for the smoke test.

One program (number 1): PAT on PID 0, PMT on PID 0x100, one video-typed PID
0x101 that carries the PCR and PES headers with PTS, and SDT / empty EIT p/f
so the Priority 3 presence checks pass. Payload bytes are dummy; nothing is
encoded. Constant bitrate, PCR every 20 ms, PSI/SI every 100 ms.

usage: gen_ts.py [--no-si] <out.ts> [seconds]

--no-si leaves out SDT and EIT (the stream then fails P3 3.5 and 3.7).
"""
import struct
import sys

TS = 188
BITRATE = 2_000_000          # bit/s
PMT_PID, ES_PID = 0x100, 0x101


def crc32_mpeg(data):
    crc = 0xFFFFFFFF
    for b in data:
        crc ^= b << 24
        for _ in range(8):
            crc = ((crc << 1) ^ 0x04C11DB7) if crc & 0x80000000 else crc << 1
            crc &= 0xFFFFFFFF
    return crc


def section(table_id, ext, body, private=False):
    # section_syntax_indicator=1, '0' ('1' for DVB SI), reserved; length
    # covers ext..CRC
    length = 5 + len(body) + 4
    flags = 0xF000 if private else 0xB000
    head = struct.pack(">BHHBBB", table_id, flags | length, ext,
                       0xC1, 0, 0)   # version 0, current_next=1, sect 0/0
    sec = head + body
    return sec + struct.pack(">I", crc32_mpeg(sec))


PAT = section(0x00, 1, struct.pack(">HH", 1, 0xE000 | PMT_PID))
PMT = section(0x02, 1, struct.pack(">HH", 0xE000 | ES_PID, 0xF000) +
              struct.pack(">BHH", 0x02, 0xE000 | ES_PID, 0xF000))

_NAMES = b"\x07example" + b"\x05smoke"
SDT = section(0x42, 1, struct.pack(">HB", 1, 0xFF) +
              struct.pack(">HBH", 1, 0xFD, 0x8000 | (2 + 1 + len(_NAMES))) +
              bytes([0x48, 1 + len(_NAMES), 0x01]) + _NAMES, private=True)
EIT_PF = section(0x4E, 1, struct.pack(">HHBB", 1, 1, 0, 0x4E), private=True)


class Mux:
    def __init__(self, out):
        self.out = out
        self.cc = {}
        self.n = 0                 # packets written

    def time27(self):              # 27 MHz time of the current packet start
        return self.n * TS * 8 * 27_000_000 // BITRATE

    def packet(self, pid, payload, pusi=False, pcr=None):
        cc = self.cc.get(pid, 0)
        self.cc[pid] = (cc + 1) & 0xF
        hdr = struct.pack(">BHB", 0x47, (0x4000 if pusi else 0) | pid,
                          0x30 | cc)
        af = b""
        room = TS - 4
        if pcr is not None:
            base, ext = pcr // 300, pcr % 300
            af = bytes([0x10]) + struct.pack(
                ">IH", (base >> 1) & 0xFFFFFFFF,
                ((base & 1) << 15) | 0x7E00 | ext)
        need = room - len(payload)
        if af or need > 0:
            fill = room - 1 - len(af) - len(payload)
            if fill < 0:
                raise ValueError("payload too long")
            if not af and fill > 0:
                af = b"\x00"
                fill -= 1
            af = bytes([len(af) + fill]) + af + b"\xFF" * fill
        pkt = hdr + af + payload
        assert len(pkt) == TS
        self.out.write(pkt)
        self.n += 1

    def psi(self, pid, sec):
        self.packet(pid, b"\x00" + sec, pusi=True)


def pes_header(pts):
    p = (0x21 | ((pts >> 29) & 0x0E), ((pts >> 14) & 0xFFFE) | 1,
         ((pts << 1) & 0xFFFE) | 1)
    return (b"\x00\x00\x01\xE0\x00\x00\x80\x80\x05" +
            struct.pack(">BHH", *p))


def main():
    args = sys.argv[1:]
    with_si = "--no-si" not in args
    args = [a for a in args if a != "--no-si"]
    out_path = args[0]
    seconds = float(args[1]) if len(args) > 1 else 5.0
    total = int(seconds * BITRATE / 8 / TS)
    pcr_step = 27_000_000 // 50        # 20 ms
    psi_step = 27_000_000 // 10        # 100 ms
    frame_step = 27_000_000 // 25      # 40 ms, PES per frame
    with open(out_path, "wb") as f:
        m = Mux(f)
        next_pcr = next_psi = next_pes = 0
        while m.n < total:
            t = m.time27()
            if t >= next_psi:
                m.psi(0, PAT)
                m.psi(PMT_PID, PMT)
                if with_si:
                    m.psi(0x11, SDT)
                    m.psi(0x12, EIT_PF)
                next_psi += psi_step
                continue
            if t >= next_pes:
                pts = (t // 300 + 90_000 // 2) & ((1 << 33) - 1)  # +500 ms
                m.packet(ES_PID, pes_header(pts) + b"\x00" * 100,
                         pusi=True, pcr=t if t >= next_pcr else None)
                if t >= next_pcr:
                    next_pcr += pcr_step
                next_pes += frame_step
                continue
            if t >= next_pcr:
                m.packet(ES_PID, b"\x00" * 100, pcr=t)
                next_pcr += pcr_step
                continue
            m.packet(ES_PID, b"\x00" * (TS - 4))


if __name__ == "__main__":
    main()
