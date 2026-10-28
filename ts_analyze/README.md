# ts_analyze

A command-line MPEG-TS analyzer that gives an **ETSI TR 101 290** compliance verdict for a live
UDP stream or a TS file, with a pass/fail exit code for scripts and monitoring.

`ts_analyze` comes from the [Perfect Streamer](https://meshwork.pstreamer.tv) project.

## What it checks

- **TR 101 290 Priority 1** (decodability): TS sync and sync loss, PAT and PMT, continuity
  counter, PID absence.
- **TR 101 290 Priority 2** (recommended monitoring): transport error indicator, CRC, PCR
  repetition, discontinuity and accuracy, PTS interval, CAT.
- **TR 101 290 Priority 3** (extended monitoring): NIT, SDT, EIT and TDT intervals,
  unreferenced PIDs.
- **ISO/IEC 13818-1 T-STD** buffer model for each elementary stream.
- **PCR accuracy** (±500 ns limit) and **PCR drift** in ppm (±30 ppm limit).
- **SI section sizes** against the ISO/IEC 13818-1 and EN 300 468 limits. It also warns
  when an EIT section is larger than 1024 bytes, which some set-top boxes cannot handle.
- **UDP inter-arrival time** statistics: datagram-level network jitter.

PCR PIDs are found automatically from the PAT and PMT.

## Usage

```
ts_analyze [options] <input>
```

### Input

| Input | Meaning |
|:------|:--------|
| `udp://239.1.1.1:1234` | UDP multicast |
| `udp://eth0@239.1.1.1:1234` | UDP multicast received on a given interface |
| `udp://192.168.1.100:1234` | UDP unicast |
| `recording.ts` | A TS file |

RTP-encapsulated UDP is detected automatically: the RTP header is skipped and the TS
packets inside are analysed.

A file has no real arrival times, so packet times come from the bitrate hint `-b`. The
metrics that depend on arrival time are therefore reported as `N/A` in file mode: PCR
accuracy, PCR drift, the T-STD model and the inter-arrival time.

### Options

| Option | Meaning | Default |
|:-------|:--------|:--------|
| `-t, --time <s>` | Analysis duration in seconds | `30` |
| `-s, --short` | Short summary report | |
| `-f, --full` | Full report | yes |
| `--xml` | Structured XML report on stdout; stderr stays quiet unless something fails | |
| `-b, --bitrate <Mbit/s>` | TS bitrate hint for file mode | `38.8` |
| `-p, --pcr-pid <pid>` | Analyze only this PCR PID (decimal or `0xHHHH`) | all |
| `-l, --pcr-limit <ms>` | PCR repetition limit | `40` |
| `--no-eit` | Skip EIT analysis: P3.7–P3.10 become `N/A` | EIT on |
| `--no-nit` | Skip NIT analysis: P3.1 and P3.2 become `N/A` | NIT on |
| `--no-color` | No ANSI colours | colours on |
| `-h, --help` | Show help | |

`--no-eit` and `--no-nit` are for streams that leave those tables out on purpose, such as
closed networks or lab feeds. Without these options, such a stream would always fail the
Priority 3 checks. All other checks run as usual.

### Examples

```bash
# 30-second check of a multicast stream, full report
ts_analyze udp://239.1.1.1:1234

# one-minute check, short summary into a log file
ts_analyze -s --no-color -t 60 udp://239.1.1.1:1234 > report.txt

# a TS file recorded at about 20 Mbit/s
ts_analyze -b 20 recording.ts

# XML for a monitoring system
ts_analyze --xml -t 30 udp://239.1.1.1:1234 > result.xml
```

## Reports

- **Full** (default): every TR 101 290 check by priority with its error count and verdict,
  the programs found, SI section sizes, PCR and T-STD details per PCR PID, and an
  `OVERALL` line.
- **Short** (`-s`): one summary block and one line per PCR PID.
- **XML** (`--xml`): the same content as the full report in one well-formed UTF-8 document.
  A check that does not apply still appears, with `applicable="false"` and `result="N/A"`,
  so the document shape stays stable. `<overall>` matches the exit code.

All three reports give the same `OVERALL` verdict and the same exit code; they differ only
in how much detail they print.

Short report of a clean 5-second test stream:

```
MPEG-TS Analyzer v2.5 | Perfect Streamer Toolkit https://meshwork.pstreamer.tv
TR 101 290 Summary | file://s.ts | 5.0s | 2026-10-27 23:16:49 UTC
----------------------------------------------------------------------------------------------------
  P1: sync=0 CC=0 PAT=0 PMT=0 PID=0  P2: TEI=0 CRC=0 PTS=0  P3: NIT=0 SDT=0 EIT=0 TDT=0 unref=0
----------------------------------------------------------------------------------------------------
PCR PID       SID     Count     Intv max      Jitter max    Drift     Interval  Accuracy  T-STD
----------------------------------------------------------------------------------------------------
0x0101        1       250       23.312 ms     N/A           N/A       PASS      N/A       N/A
----------------------------------------------------------------------------------------------------
OVERALL: PASS
```

### Analysis duration

The default 30 seconds covers all TR 101 290 checks. A run shorter than 2 seconds is refused
(exit code 3). Below 10 seconds the longer interval checks (NIT, EIT schedule, PID absence)
may not have enough data, and below 30 seconds the TDT check; the report says so. A file is
analysed to its end or for `-t` seconds of stream time, whichever comes first.

PCR drift needs a long window, because measurement noise falls as the window grows:

| Window | Out-of-spec drift is reported as | Effect on OVERALL |
|:-------|:---------------------------------|:------------------|
| under 30 s | skipped | none |
| 30 s to 5 min | WARN | none |
| 5 min or more | FAIL | OVERALL = FAIL |

Run with `-t 300` or longer for a hard drift verdict.

## Exit codes

| Code | Meaning |
|:-----|:--------|
| `0` | OVERALL = PASS |
| `65` | OVERALL = FAIL: the stream violates TR 101 290 or ISO/IEC 13818-1 (`EX_DATAERR`) |
| `1` | Usage or input error |
| `2` | No PCR in the stream |
| `3` | No data, or the recording is shorter than the minimum |
| `128+N` | Stopped by signal N (130 for Ctrl+C, 143 for SIGTERM); no report |

```bash
ts_analyze -t 60 udp://239.1.1.1:1234 > report.txt
case $? in
    0)  echo "compliant" ;;
    65) echo "not compliant, see report.txt" >&2 ;;
    *)  echo "analysis did not complete" >&2 ;;
esac
```

## Building

You need CMake 3.20 or newer and a C11/C++20 compiler.

```bash
cmake -S . -B build && cmake --build build
```

By default CMake downloads libdvbpsi 1.3.3 from VideoLAN, checks its SHA-256 and builds it
in. To use the system package instead (`libdvbpsi-dev` or `libdvbpsi-devel`, found through
pkg-config):

```bash
cmake -S . -B build -DTS_ANALYZE_SYSTEM_DVBPSI=ON
```

A fully static x86_64 binary (Alpine/musl) builds in a container:

```bash
podman build -f Containerfile -o type=local,dest=dist .   # or docker build
# result: dist/ts_analyze
```

Ready-made binaries are attached to the GitHub releases.

## ts_analyze and TSDuck

[TSDuck](https://tsduck.io) is a large, general-purpose toolkit: many plugins, tables for
DVB, ATSC and ISDB, multiplexing and demultiplexing. `ts_analyze` is one small static binary
with one job. A single run gives a TR 101 290 verdict with a pass/fail exit code, PCR
accuracy and drift and a T-STD model, as a short, full or XML report for monitoring
scripts. If you need a full toolbox, use TSDuck; if you need a quick compliance verdict
from a script, use `ts_analyze`.

## Third-party software

`ts_analyze` links [libdvbpsi](https://www.videolan.org/developers/libdvbpsi.html)
(VideoLAN) statically. libdvbpsi is licensed under the GNU LGPL version 2.1 or later; it is
not part of this repository: the build downloads the upstream release or uses the system
library.

## License

Apache License 2.0, as the whole [Perfect Streamer Toolkit](../): see [LICENSE](../LICENSE)
and [NOTICE](../NOTICE).
