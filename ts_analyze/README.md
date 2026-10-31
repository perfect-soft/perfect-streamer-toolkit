# ts_analyze

A command-line MPEG-TS analyzer that gives an **ETSI TR 101 290** compliance verdict for a live
UDP stream or a TS file, with a pass/fail exit code for scripts and monitoring.

`ts_analyze` is part of the Perfect Streamer Toolkit by Perfect Soft for [Perfect Streamer Meshwork](https://meshwork.pstreamer.tv).
Changes between versions are in [CHANGELOG.md](CHANGELOG.md).

## What it checks

- **TR 101 290 Priority 1** (decodability): TS sync and sync loss, PAT and PMT, continuity
  counter, PID absence.
- **TR 101 290 Priority 2** (recommended monitoring): transport error indicator, CRC, PCR
  repetition (more than 40 ms between PCRs is an error), discontinuity and accuracy, PTS
  interval, CAT.
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
| `--json` | Compact JSON report on stdout: verdict, problems with times and hints (see below) | |
| `-b, --bitrate <Mbit/s>` | TS bitrate hint for file mode | `38.8` |
| `-p, --pcr-pid <pid>` | Analyze only this PCR PID (decimal or `0xHHHH`) | all |
| `--no-eit` | Skip EIT analysis: 3.6a, 3.6b and `EIT.sch_*` become `N/A` | EIT on |
| `--no-nit` | Skip NIT analysis: 3.1a and 3.1b become `N/A` | NIT on |
| `--no-color` | No ANSI colours | colours on |
| `--wait-s <s>` | UDP: how long to wait for the first datagram | `10` |
| `-V, --version` | Show the version and the attribution | |
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

## RTP, ST 2022-1 FEC and ST 2022-7

For a UDP input that carries RTP, `ts_analyze` can also check the transport and repair
it the way a receiver would. These options are off by default; without them the analysis
and its output are the same as before.

| Option | Meaning |
|:-------|:--------|
| `--rtp` | The input is RTP: sequence numbers, losses, payload type and SSRC are checked |
| `--fec` | SMPTE ST 2022-1 FEC: column FEC on port+2, row FEC on port+4 of the input's address; 1D and 2D are detected from the stream, lost datagrams are rebuilt (implies `--rtp`) |
| `--path2 <udp://...>` | SMPTE ST 2022-7: the second path of the same stream; the two paths are merged seamlessly by RTP sequence number (implies `--rtp`) |
| `--path-skew-ms <ms>` | The largest delay between the two paths that is waited for and allowed (default 450) |

Only the standard transport is supported: FEC on its own ports, with the standard FEC
header. FEC sent in the media port shows up as protocol errors.

The TR 101 290 checks then run on the repaired stream, and the report gets an "ST 2022"
section with six more checks, which take part in `OVERALL` and the exit code like the
others:

| Check | Fails when |
|:------|:-----------|
| S.1 Unrecoverable loss | a datagram was lost on every path and FEC could not rebuild it (losses during the start check are reported but not counted, see below) |
| S.2 RTP protocol errors | a path received datagrams that are not RTP or carry another payload type |
| S.3 Path down | a path was silent longer than the limit shown in the report (`--path-skew-ms`, at least 100 ms) while the other path kept delivering; both paths silent together is a pause of the source and does not count |
| S.4 Paths differ | the two paths do not carry the same stream |
| S.5 Path skew | the delay between the paths exceeded `--path-skew-ms` |
| S.6 FEC absent | with `--fec`, no valid FEC packet arrived for 2 seconds |

It also reports, per path, the datagrams received, lost, duplicated and late, the time the
path was down and its inter-arrival times; for the merge, how many datagrams the other
path repaired and the path skew; for FEC, the matrix size and the datagrams rebuilt by
column and by row.

```bash
# Pro-MPEG / ST 2022-1 FEC (1D or 2D) on one path
ts_analyze --fec udp://239.1.1.1:5000

# ST 2022-7: two paths of one stream, no FEC
ts_analyze --path2 udp://eth1@239.2.2.2:5000 udp://eth0@239.1.1.1:5000

# both: two paths, each with its FEC
ts_analyze --fec --path2 udp://eth1@239.2.2.2:5000 udp://eth0@239.1.1.1:5000
```

Until two paths have been seen to carry identical datagrams (20 copies compared, a fraction
of a second), only the first path is used, so a loss on it at the very start is not
repaired. Such losses are shown as "during the start check" and do not fail S.1; the
TR 101 290 checks still see the missing packets.

A lost datagram waits for its FEC as long as the FEC matrix needs, up to 10 seconds: in a
slow stream a 10 x 10 matrix lasts over a second, and its column FEC follows it. The TS
packets are timed by the arrival of the datagram that carried them, not by the moment the
merge released them, so a datagram held behind a gap does not distort PCR accuracy.

Limits: the FEC decoder is new in this release. It has been checked against independent
ST 2022-1 senders (1D and 2D), but not yet across the whole range of encoders in use.

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
MPEG-TS Analyzer v2.6 | Perfect Streamer Toolkit https://meshwork.pstreamer.tv
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

## Check ids

Every report uses the same ids.

- **TR 101 290 checks carry the standard's own numbers**, letters included: `1.1`-`1.6`,
  `2.1`, `2.2`, `2.3a`, `2.3b`, `2.4`-`2.6`, `3.1a`, `3.1b`, `3.4`, `3.5a`, `3.5b`, `3.6a`,
  `3.6b`, `3.8`.
- **Checks that are not in TR 101 290** have an id of the form `AREA.name`, which can never be
  read as a TR 101 290 number. The ST 2022 checks are `S.1`-`S.6`.

| Id | Check | Source | Gates OVERALL |
|:---|:------|:-------|:-------------|
| `1.1` | TS_sync_loss: 2 or more consecutive bad sync bytes | TR 101 290 | yes |
| `1.2` | Sync_byte_error: a sync byte other than 0x47 | TR 101 290 | yes |
| `1.3` | PAT_error: no valid PAT within 0.5 s | TR 101 290 | yes |
| `1.4` | Continuity_count_error | TR 101 290 | yes |
| `1.5` | PMT_error: no valid PMT within 0.5 s | TR 101 290 | yes |
| `1.6` | PID_error: a PID of the PMT absent for 5 s | TR 101 290 | yes |
| `2.1` | Transport_error (TEI) | TR 101 290 | yes |
| `2.2` | CRC_error | TR 101 290 | yes |
| `2.3a` | PCR_repetition_error: more than 40 ms between PCRs | TR 101 290 | yes |
| `2.3b` | PCR_discontinuity_indicator_error | TR 101 290 | yes |
| `2.4` | PCR_accuracy_error: more than 500 ns (live input) | TR 101 290 | yes |
| `2.5` | PTS_error: more than 700 ms between PTS | TR 101 290 | yes |
| `2.6` | CAT_error (when scrambled) | TR 101 290 | yes |
| `3.1a`, `3.1b` | NIT_actual_error, NIT_other_error | TR 101 290 | yes |
| `3.4` | Unreferenced_PID | TR 101 290 | no (warning) |
| `3.5a`, `3.5b` | SDT_actual_error, SDT_other_error | TR 101 290 | yes |
| `3.6a` | EIT_actual_error (present/following) | TR 101 290 | yes |
| `3.6b` | EIT_other_error (present/following) | TR 101 290 | no (warning) |
| `3.8` | TDT_error | TR 101 290 | yes |
| `PAT.version`, `PMT.version` | a PAT/PMT version change for the same stream/program | ISO/IEC 13818-1 | yes |
| `EIT.sch_act`, `EIT.sch_oth` | EIT schedule sub-table later than 10 s | EN 300 468 | no (warning) |
| `TSTD.under`, `TSTD.over` | T-STD buffer model underflow / overflow (live input) | ISO/IEC 13818-1 | yes |
| `SI.size` | a PSI/SI section above its size limit | ISO/IEC 13818-1, EN 300 468 | yes |
| `SI.eit1024` | EIT sections above 1024 bytes | receiver practice | no (warning) |
| `PCR.drift` | PCR drift beyond 30 ppm | ISO/IEC 13818-1 | from 300 s (live) |
| `IAT.gap` | UDP datagram gaps | network | no (warning) |
| `S.1`-`S.6` | RTP / ST 2022-1 / ST 2022-7 checks (see above) | SMPTE ST 2022 | yes, with the options |

## JSON report

`--json` prints one compact JSON object on stdout (stderr stays quiet), made for
scripts and AI agents: the verdict first, then only what is wrong, with times. The exit
code is the same as in the other modes. The text and XML reports are unchanged.

```bash
ts_analyze --json -t 60 udp://239.1.1.1:1234 > result.json
```

Schema `ts_analyze/1` (fields are added, never renamed, within one schema version):

| Field | Meaning |
|:------|:--------|
| `schema`, `tool`, `version` | `"ts_analyze/1"`, `"ts_analyze"`, the program version |
| `verdict`, `exit_code` | `"PASS"`/`0` or `"FAIL"`/`65`; `"ERROR"` with the exit code and an `error` text when no report could be made (codes 1, 2, 3) |
| `source`, `input` | the input, and `"live"` or `"file"` |
| `start_utc` | wall-clock time of the first packet (live input; `null` for files) |
| `duration_s`, `bitrate_mbps`, `packets` | what was analysed |
| `checks` | `failed` and `warned` counts; `passed` and `not_applicable` as lists of check ids |
| `problems[]` | one entry per failed (`severity: "fail"`) or warned (`"warn"`) check |
| `context` | `programs` with their PIDs, `pcr` per PCR PID, `iat` (live), `st2022` (with `--rtp`, `--fec`, `--path2`) |

Each problem has:

| Field | Meaning |
|:------|:--------|
| `id` | the check id, as in the other reports (`1.4`, `2.3a`, `PCR.drift`, `S.3`, ...; see Check ids) |
| `name`, `ref`, `meaning` | the check's name, the clause of the standard (for TR 101 290 checks the same as the id), one line on what it means |
| `count` | the same count as in the other reports |
| `pids` | the PIDs involved, where known |
| `first`, `last` | `t_s` (seconds from the first packet) and, for live input, `utc` |
| `events[]` | the first 10 occurrences with `t_s`, `utc`, `pid` and a `detail` such as "expected 5, got 7"; `events_more` counts the rest |
| `detail` | a summary where there are no single events (e.g. PCR drift) |
| `hint` | a likely cause, only where this run's evidence supports it: `text` and `confidence` (`certain`, `likely`, `possible`). It is a hint, not a finding |

Warned (not gating) problems: `3.4` unreferenced PIDs, `3.6b` and `EIT.sch_*` optional EIT,
`SI.eit1024` EIT sections above 1024 bytes, `IAT.gap` datagram gaps, `PCR.drift` before
the 300 s window.

## Exit codes

| Code | Meaning |
|:-----|:--------|
| `0` | OVERALL = PASS |
| `65` | OVERALL = FAIL: the stream violates TR 101 290 or ISO/IEC 13818-1 (`EX_DATAERR`) |
| `1` | Usage or input error |
| `2` | No PCR in the stream |
| `3` | No data (none within `--wait-s` on UDP), or the recording is shorter than the minimum |
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
and [NOTICE](../NOTICE). Redistributions keep the NOTICE, which names the toolkit by
Perfect Soft for Perfect Streamer Meshwork (https://meshwork.pstreamer.tv).
