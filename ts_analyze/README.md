# ts_analyze

A command-line MPEG-TS analyzer that gives an **ETSI TR 101 290** compliance verdict for a live
UDP stream or a TS file, with a pass/fail exit code for scripts and monitoring.

`ts_analyze` is part of the Perfect Streamer Toolkit by Perfect Soft for [Perfect Streamer Meshwork](https://meshwork.pstreamer.tv).
Changes between versions are in [CHANGELOG.md](CHANGELOG.md).

**Requirements:** Linux x86-64; the release binary is static and has no runtime dependencies.
Building from source needs CMake 3.20 or newer and a C11/C++20 compiler.

## Quick start

Download `ts_analyze-<version>-linux-x86_64` from the
[Releases](https://github.com/perfect-soft/perfect-streamer-toolkit/releases) page, then:

```bash
chmod +x ts_analyze-*-linux-x86_64
./ts_analyze-*-linux-x86_64 udp://239.1.1.1:1234
echo $?        # 0 = compliant, 65 = not compliant
```

## Contents

- [What it checks](#what-it-checks)
- [Usage](#usage): input, options, examples
- [RTP, ST 2022-1 FEC and ST 2022-7](#rtp-st-2022-1-fec-and-st-2022-7)
- [Reports](#reports) and [analysis duration](#analysis-duration)
- [Check ids](#check-ids), the [T-STD model](#t-std-model) and [PCR accuracy](#pcr-accuracy-24)
- [JSON report](#json-report)
- [Exit codes](#exit-codes)
- [Building](#building)
- [When to use ts_analyze](#when-to-use-ts_analyze)
- [Third-party software](#third-party-software) and [License](#license)

## What it checks

- **TR 101 290 Priority 1** (decodability): TS sync and sync loss, PAT and PMT, continuity
  counter, PID absence.
- **TR 101 290 Priority 2** (recommended monitoring): transport error indicator, CRC, PCR
  repetition (more than 40 ms between PCRs is an error), discontinuity and accuracy, PTS
  interval, CAT (scrambled streams).
- **TR 101 290 Priority 3** (extended monitoring): NIT, SDT, EIT and TDT intervals,
  unreferenced PIDs (warning only).
- **ISO/IEC 13818-1 T-STD** buffer model for each elementary stream, and the **decode lead**:
  how far ahead of its decode time each stream is delivered.
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
packets inside are analyzed.

A file has no real arrival times, so packet times come from the bitrate hint `-b`. The
metrics that depend on arrival time are therefore reported as `N/A` in file mode: PCR
accuracy, PCR drift, the T-STD verdict and the inter-arrival time. The decode lead is
still measured, because it runs on the PCR clock.

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
| `--no-color` | No ANSI colors | colors on |
| `--wait-s <s>` | UDP: how long to wait for the first datagram, and for more after a pause, before the input ends | `10` |
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
it the way a receiver would. These options are off by default. Without them, RTP is only
stripped, and the output has no ST 2022 section.

| Option | Meaning | Default |
|:-------|:--------|:--------|
| `--rtp` | The input is RTP: sequence numbers, losses, payload type and SSRC are checked | off |
| `--fec` | SMPTE ST 2022-1 FEC: column FEC on port+2, row FEC on port+4 of the input's address; 1D and 2D are detected from the stream, lost datagrams are rebuilt (implies `--rtp`) | off |
| `--path2 <udp://...>` | SMPTE ST 2022-7: the second path of the same stream; the two paths are merged seamlessly by RTP sequence number (implies `--rtp`) | off |
| `--path-skew-ms <ms>` | The largest delay between the two paths that is waited for and allowed | `450` |

Only the standard transport is supported: FEC on its own ports, with the standard FEC
header. FEC sent in the media port shows up as protocol errors.

The TR 101 290 checks then run on the repaired stream, and the report gets an "ST 2022"
section with six more checks. They count towards `OVERALL` and the exit code like the
others:

| Check | Fails when |
|:------|:-----------|
| S.1 Unrecoverable loss | a datagram was lost on every path and FEC could not rebuild it (losses during the start check are reported but not counted, see below) |
| S.2 RTP protocol errors | a path received datagrams that are not RTP or carry another payload type (TS payloads of another type are still analyzed) |
| S.3 Path down | a path was silent for longer than `--path-skew-ms` (at least 100 ms; the value used is printed) while the other path kept delivering; both paths silent at once is a pause of the source and does not count |
| S.4 Paths differ | the two paths do not carry the same stream |
| S.5 Path skew | the delay between the paths exceeded `--path-skew-ms` |
| S.6 FEC absent | with `--fec`, no valid FEC packet arrived for 2 seconds |

The report also shows:
- per path: the datagrams received, lost, duplicated and late, the time the path was down,
  and its inter-arrival times;
- for the merge: how many datagrams the other path repaired, and the path skew;
- for FEC: the matrix size and the datagrams rebuilt by column and by row.

```bash
# Pro-MPEG / ST 2022-1 FEC (1D or 2D) on one path
ts_analyze --fec udp://239.1.1.1:5000

# ST 2022-7: two paths of one stream, no FEC
ts_analyze --path2 udp://eth1@239.2.2.2:5000 udp://eth0@239.1.1.1:5000

# both: two paths, each with its FEC
ts_analyze --fec --path2 udp://eth1@239.2.2.2:5000 udp://eth0@239.1.1.1:5000
```

Until the two paths have been seen to carry identical datagrams (20 matching datagrams,
usually a fraction of a second), only the first path is used, so a loss on it at the very
start is not repaired. Such losses are shown as "during the start check" and do not fail
S.1; the TR 101 290 checks still see the missing packets.

A lost datagram waits for its FEC as long as the FEC matrix needs, up to 10 seconds: in a
slow stream a 10 x 10 matrix lasts over a second, and its column FEC follows it. The TS
packets are timed by the arrival of the datagram that carried them, not by the moment the
merge released them, so a datagram held behind a gap does not distort PCR accuracy.

Limits: the FEC decoder was added in 2.6. It has been checked against independent
ST 2022-1 senders (1D and 2D), but not yet against the whole range of encoders in use.

## Reports

- **Full** (default): every TR 101 290 check by priority with its error count and verdict,
  the programs found, SI section sizes, PCR and T-STD details per PCR PID, and an
  `OVERALL` line.
- **Short** (`-s`): one summary block and one line per PCR PID.
- **XML** (`--xml`): the same content as the full report in one well-formed UTF-8 document.
  The root `<ts_analyze version="…" toolkit="…">` carries the toolkit attribution.
  A check that does not apply still appears, with `applicable="false"` and `result="N/A"`,
  so the document shape stays stable. `<overall>` matches the exit code.
- **JSON** (`--json`): the verdict and only what is wrong, with times (see
  [JSON report](#json-report)).

All four reports give the same `OVERALL` verdict and the same exit code; they differ only
in how much detail they print.

Short report of a clean 5-second test stream:

```
MPEG-TS Analyzer v2.6.2 | Perfect Streamer Toolkit https://meshwork.pstreamer.tv
TR 101 290 Summary | file://recording.ts | 5.0s | 2026-11-08 03:25:21 UTC
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
analyzed to its end or for `-t` seconds of stream time, whichever comes first.

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
| `2.5` | PTS_error: no usable PTS for more than 700 ms | TR 101 290 | yes |
| `2.6` | CAT_error (when scrambled) | TR 101 290 | yes |
| `3.1a`, `3.1b` | NIT_actual_error, NIT_other_error | TR 101 290 | yes |
| `3.4` | Unreferenced_PID | TR 101 290 | no (warning) |
| `3.5a`, `3.5b` | SDT_actual_error, SDT_other_error | TR 101 290 | yes |
| `3.6a` | EIT_actual_error (present/following) | TR 101 290 | yes |
| `3.6b` | EIT_other_error (present/following) | TR 101 290 | no (warning) |
| `3.8` | TDT_error | TR 101 290 | yes |
| `PAT.version`, `PMT.version` | a PAT/PMT version change for the same stream/program | ISO/IEC 13818-1 | yes |
| `EIT.sch_act`, `EIT.sch_oth` | EIT schedule sub-table not repeated within 10 s | EN 300 468 | no (warning) |
| `TSTD.under`, `TSTD.over` | T-STD buffer model underflow / overflow (live input) | ISO/IEC 13818-1 | yes |
| `TSTD.lead` | a stream delivered further ahead of its decode time than its buffer limit (see below) | ISO/IEC 13818-1 | no (warning) |
| `SI.size` | a PSI/SI section above its size limit | ISO/IEC 13818-1, EN 300 468 | yes |
| `SI.eit1024` | EIT sections above 1024 bytes | receiver practice | no (warning) |
| `PCR.drift` | PCR drift beyond 30 ppm | ISO/IEC 13818-1 | yes from a 300 s window (live); WARN below |
| `IAT.gap` | UDP datagram gaps | network | no (warning) |
| `S.1`-`S.6` | RTP / ST 2022-1 / ST 2022-7 checks (see above) | SMPTE ST 2022 | yes, with the options |

### T-STD model

Each elementary stream has a buffer on the program clock (the PCR). The bytes of each PES
enter the buffer as its packets arrive and leave it at the PES's decode time (DTS, else PTS).
- `TSTD.under`: an access unit arrives after its decode time, or the buffer is empty past
  the next expected decode time (a starvation).
- `TSTD.over`: the buffer holds more than its ISO/IEC 13818-1 size (BSn), or more than
  1 s of the stream's measured rate, whichever is larger. Many streams deliver audio
  0.5-0.7 s ahead of its PTS, more than the 3584-byte audio BSn, and decoders cope with it;
  so only grossly early delivery counts.
- The full and XML reports show the largest fill next to the ISO size, so the real lead
  stays visible.
- **Decode lead** per stream, for files and live input alike:
  - the lead is the decode time (DTS, else PTS) minus the arrival of the first packet of
    each timed PES, on the program clock;
  - it is shown as min, avg and max in ms;
  - the lead limit is the overflow limit expressed in time: max(BSn ÷ ES rate, 1 s). A PES
    whose lead exceeds it starts a `TSTD.lead` warning episode, which never fails the run;
  - the strict ISO lead, BSn ÷ rate, is shown for information;
  - text `Decode lead`; XML `lead_min_ms`, `lead_avg_ms`, `lead_max_ms`, `lead_limit_ms`,
    `lead_iso_ms`, `lead_warn` on `es_buffer` (live) or `pes_lead` (file); JSON
    `context.tstd`.

### PCR accuracy (2.4)

- Each PCR is compared with the value expected from the previous PCR plus the packets
  between them at the TS rate. This is TR 101 290's PCR_AC.
  - The rate is the median PCR time per packet over the last 15 intervals, so a single lost
    packet does not bias it, and a drifting clock is tracked (reported as `PCR.drift`).
  - When drift sets in abruptly, a few PCRs fail 2.4 until the median catches up.
- An interval with lost packets on the PCR PID (a CC break) is not judged.
- PCR_AC is defined against a constant TS rate. On a VBR mux, such as a transcoder
  output without null-packet stuffing, 2.4 reads offsets of milliseconds even when the
  PCR is right. Judge 2.4 only on CBR streams.

## JSON report

`--json` prints one compact JSON object on stdout (stderr stays quiet), made for
scripts and AI agents: the verdict first, then only what is wrong, with times. The exit
code is the same as in the other modes. The text and XML reports are unchanged.

```bash
ts_analyze --json -t 60 udp://239.1.1.1:1234 > result.json
```

A file with a dropped video packet about once a second gives, shortened:

```json
{"schema":"ts_analyze/1","tool":"ts_analyze","version":"2.6.2","verdict":"FAIL","exit_code":65,
 "problems":[{"id":"1.4","name":"Continuity_count_error","severity":"fail","count":62,"pids":[257],
   "first":{"t_s":0.156},"events":[{"t_s":0.156,"pid":257,"detail":"expected 8, got 9"}, ...]}], ...}
```

Schema `ts_analyze/1` (fields are added, never renamed, within one schema version):

| Field | Meaning |
|:------|:--------|
| `schema`, `tool`, `version` | `"ts_analyze/1"`, `"ts_analyze"`, the program version |
| `toolkit` | the attribution `"Perfect Streamer Toolkit by Perfect Soft — https://meshwork.pstreamer.tv"`, also in error objects |
| `verdict`, `exit_code` | `"PASS"`/`0` or `"FAIL"`/`65`; `"ERROR"` with the exit code and an `error` text when no report could be made (codes 1, 2, 3; an unknown option only prints the usage to stderr) |
| `source`, `input` | the input, and `"live"` or `"file"` |
| `start_utc` | wall-clock time of the first packet (live input; `null` for files) |
| `duration_s`, `bitrate_mbps`, `packets` | what was analyzed |
| `checks` | `failed` and `warned` counts; `passed` and `not_applicable` as lists of check ids |
| `problems[]` | one entry per failed (`severity: "fail"`) or warned (`"warn"`) check |
| `context` | `programs` with their PIDs, `pcr` per PCR PID, `tstd` per stream (decode lead and its limits), `iat` (live), `st2022` (with `--rtp`, `--fec`, `--path2`) |

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
`SI.eit1024` EIT sections above 1024 bytes, `TSTD.lead` early delivery, `IAT.gap` datagram
gaps, and `PCR.drift` before the 300 s window.

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

Ready-made binaries are attached to the
[GitHub releases](https://github.com/perfect-soft/perfect-streamer-toolkit/releases).

## When to use ts_analyze

`ts_analyze` does one job. A single run gives a TR 101 290 verdict with a pass/fail exit
code, PCR accuracy and drift, a T-STD model with the decode lead, and RTP / ST 2022 checks,
as a short, full, XML or JSON report for monitoring scripts. It is one small static binary.
It is not a multiplexer or a general-purpose TS toolbox: for remultiplexing, table editing
or format conversion, use a general transport-stream toolkit.

## Third-party software

`ts_analyze` links [libdvbpsi](https://www.videolan.org/developers/libdvbpsi.html)
(VideoLAN) statically. libdvbpsi is licensed under the GNU LGPL version 2.1 or later; it is
not part of this repository: the build downloads the upstream release or uses the system
library.

## License

Apache License 2.0, like the rest of the [Perfect Streamer Toolkit](../): see
[LICENSE](../LICENSE) and [NOTICE](../NOTICE). Redistributions keep the NOTICE, which names
the toolkit by Perfect Soft for Perfect Streamer Meshwork (https://meshwork.pstreamer.tv).
