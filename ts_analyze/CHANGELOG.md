# ts_analyze changelog

## 2.6.2

- The XML root (`<ts_analyze toolkit="…">`) and the JSON object (`"toolkit"`, in
  error objects too) carry the attribution of NOTICE: "Perfect Streamer Toolkit
  by Perfect Soft — https://meshwork.pstreamer.tv". The text output and `-V`
  already did.
- No other change. 2.6.2 is the first public release with the 2.6.1 changes
  below.

## 2.6.1

Fixes. Each one changes a verdict or a report field on some streams. Plus one
addition, the decode lead.

- **New: decode lead per ES.**
  - The lead is the decode time minus the arrival of the PES's first packet, on
    the PCR clock, for files and live input alike. Packets after the last PCR
    are not timed and not counted.
  - Reported as min, avg and max in ms, next to its limit:
    max(ISO BSn ÷ ES rate, 1 s), the overflow rule in ms of lead. The strict
    ISO lead is shown for information.
  - Above the limit: the warning `TSTD.lead`, never gated.
  - Text `Decode lead`; XML `lead_*_ms` / `lead_warn` (`pes_lead` for files);
    JSON `context.tstd` and the problem `TSTD.lead`.

- **No PCR.** A stream whose PCR PID is named in the PMT but carries no PCR
  now exits 2 ("no PCR in the stream"), as documented. Before, it passed.
- **1.6 PID_error.** An expected PID absent for more than 5 s and then back is
  an error, one per gap. Before, only an absence lasting to the end counted.
- **2.5 PTS_error.** PES that keep coming without a usable PTS for more than
  700 ms of stream time raise 2.5 once per run. Shorter runs stay within the
  TR 101 290 allowance.
  - A usable PTS is one that is present, complete and has valid marker bits.
  - The run is counted from the last PTS, or from the first PES for a PID that
    never had one.
- **Tables lost to the end.** A required table seen and then missing for longer
  than its limit up to the end of the analysis is an interval violation:
  - PAT (1.3), PMT (1.5), SDT actual (3.5a);
  - NIT actual, EIT actual p/f, TDT and the EIT schedule sub-tables.

  Before, only a table never seen at all counted. A PMT whose program the last
  PAT no longer lists is not missing.
- **Interval event times.** In JSON, the events of 1.3, 1.5, 3.x and the other
  interval checks carry the time the table went missing (last + limit). Before,
  they carried the time it came back.
- **2.3a / 2.3b on a PCR value step.**
  - An unflagged PCR step is 2.3b. A step is a difference outside 0..100 ms
    (negative or above 2 s too) where the PID's CC ran unbroken and the
    difference does not match the transport time between the two PCR packets.
    The transport time is the packet count at the regressed packet duration;
    live, it is at least the arrival interval.
  - 2.3a is judged on the transport time, so the step alone is not also a
    repetition error.
  - A real gap stays a 2.3a and a 2.3b, as before. A real gap is either packets
    lost (a CC break) or a stall (the arrival interval).
  - Accuracy and drift continue across the step by the transport time.
  - Before, a step above 2 s or below 0 raised nothing.
- **T-STD model.** The buffer model is now the one of ISO/IEC 13818-1 2.4.2.
  - **How it works:** a PES's bytes enter the elementary-stream buffer when its
    packets arrive and leave at its decode time (DTS, else PTS). The clock is the
    program's PCR: each packet is placed between its two neighbouring PCRs by
    position, which is exact for VBR muxes too.
  - **Before:** each buffer drained at a constant rate estimated from a 1 s
    warm-up. Its small error built up, so clean streams read as underflows in the
    first seconds (bursty AAC), as overflows after minutes, or as either under
    CPU load.
  - **Underflow:** an access unit's data arrives after its decode time, or the
    buffer is empty past the next expected decode time (a starvation). Both are
    detectable from the first decoded access unit.
  - **Overflow:** counted once per episode, no longer per packet. An episode is
    a fill above the ISO BSn or 1 s of the ES's measured rate, whichever is larger.
    - Field streams keep 0.5-0.7 s of audio ahead of its PTS, above the
      3584-byte audio BSn.
    - The audio size is now the ISO 3584 bytes for AAC too (was 8192).
    - The reports show the largest fill next to the ISO size, and XML has
      `overflow_limit_bytes`.
  - The model is independent of arrival timing (CPU load, network bursts). A PCR
    discontinuity or step restarts the buffers of its program.
  - The XML `es_bitrate_mbps` is the measured ES rate.
- **2.4 PCR_accuracy.**
  - Each PCR is now judged against the one expected from the previous PCR and
    the packets between (TR 101 290 PCR_AC). The TS rate is the median PCR time
    per packet of the last 15 intervals, so it follows a drifting clock and
    ignores a single loss.
  - Before, it was the residual of one fit over the whole run. A single lost
    datagram then shifted every later PCR by the missing packets, and 2.4
    failed to the end.
  - Now a loss is at most one error, and an interval with a CC break on the
    PCR PID is not judged.
  - PCR_AC assumes a constant TS rate. On VBR muxes 2.4 reads millisecond
    offsets (README).
- **T-STD after a loss.** A CC break on an ES closes its current PES. Bytes up
  to the next PES start are not counted as a late access unit.
- **PCR.drift.**
  - Samples delivered late are skipped: their delivery delay is more than 50 ms
    above the least delay of the last 10 s. A stall's backlog no longer reads as
    clock drift.
  - The estimate is used once it spans 10 s.
  - The JSON event carries the ppm.
- **Live pauses.** After the first datagram, a pause ends the input only after
  `--wait-s` (default 10 s) of silence, and never past `-t`.
  - Before, 1 s of silence ended the analysis early.
  - A pause shows as `IAT.gap`.
  - When the input does end in a pause, the pause is part of the analyzed
    time, so tables and PIDs missing in it are reported.
- **RTP with another payload type.** With `--rtp`, a datagram of another
  payload type whose payload is still whole TS packets (a dynamic PT such as 96)
  counts as S.2 and is analyzed. Before, the input gave exit 3 ("no data").
  FEC in the media port is still dropped.
- **JSON times.** `3.4` (first and last packet of each unreferenced PID),
  `IAT.gap` and `PCR.drift` (the end of the window) now carry `first`, `last` and
  `events`.

## 2.6

### New: RTP, ST 2022-1 FEC and ST 2022-7 inputs

These are off by default. Without the new options, the analysis works as in 2.5,
apart from the TR 101 290 changes listed under "Changed".

- `--rtp`: the UDP input is RTP. The tool checks sequence numbers, losses, payload
  type and SSRC.
- `--fec`: SMPTE ST 2022-1 (Pro-MPEG) FEC.
  - Column FEC arrives on port+2 and row FEC on port+4 of the input's address.
  - 1D and 2D matrices are detected from the stream, and lost datagrams are
    rebuilt.
  - The tool waits for FEC up to 10 s, depending on the matrix.
  - Implies `--rtp`.
- `--path2 <udp://...>`: SMPTE ST 2022-7. The tool merges the second path of the
  same stream seamlessly by RTP sequence number.
  - `--path-skew-ms` (default 450) is the allowed difference between the paths.
  - Losses before the two paths are first verified equal are reported apart, as
    `start_check_lost`.
  - Implies `--rtp`.
- New checks S.1-S.6 in every report, and in the verdict when the options are
  given:
  - S.1 unrecoverable loss;
  - S.2 RTP protocol errors;
  - S.3 path down, counting only silence that the other path did not share;
  - S.4 paths differ;
  - S.5 path skew;
  - S.6 FEC absent.
- FEC is supported only on port+2 and port+4. FEC in the media port, and
  non-standard forms, are not.

### New: JSON report

- `--json` prints one compact JSON object (schema `ts_analyze/1`) for scripts and
  AI agents.
- The object holds:
  - the verdict and exit code;
  - one entry per failed or warned check, with its standard clause, count, PIDs,
    first and last time and the first events;
  - a short context of programs, PCR, IAT and ST 2022.
- Errors (exit 1, 2 or 3) print an error object.

### Changed: TR 101 290 behavior

- Check ids follow ETSI TR 101 290 in every output (text, XML, JSON).
  - TR 101 290 checks keep its numbers.
  - Checks the standard does not have get `AREA.name` ids.
  - Old ids are not kept.

  | 2.5 | 2.6 |
  |:--|:--|
  | 1.3a, 1.5a | PAT.version, PMT.version |
  | 2.3, 2.4, 2.5, 2.6, 2.7 | 2.3a, 2.3b, 2.4, 2.5, 2.6 |
  | 3.1, 3.2 | 3.1a, 3.1b |
  | 3.5, 3.6 | 3.5a, 3.5b |
  | 3.7, 3.8 | 3.6a, 3.6b |
  | 3.12 | 3.8 |
  | 3.9, 3.10 | EIT.sch_act, EIT.sch_oth |
  | 3.13, 3.14 | TSTD.under, TSTD.over |

- 2.3a PCR_repetition_error fails above 40 ms, the TR 101 290 limit.
  - Streams that send PCR every 80 ms now fail 2.3a.
  - `-l/--pcr-limit` is removed, and giving it is an error.
  - The ISO 13818-1 count of intervals above 100 ms stays as information. In XML it
    is `iso_violations`, and `limit_ms` replaces `soft_violations`.
- 1.1 and 1.2 follow TR 101 290:
  - 1.1 TS_sync_loss = 2 or more bad sync bytes in a row;
  - 1.2 Sync_byte_error = each bad sync byte.

  A bad sync byte no longer shifts the packet boundaries.
- CRC errors count only in 2.2. The section-interval checks (1.3, 1.5, 2.6, 3.x)
  count only valid sections.
- A packet with the transport error indicator set stays in the continuity check,
  and an intact one causes no CC error after it.
- UDP inputs wait for the first datagram up to `--wait-s` (default 10 s). After
  that, 1 s of silence ends the analysis, as before.
- `-V/--version` prints the version.
- The output and NOTICE carry the attribution "Perfect Streamer Toolkit by Perfect
  Soft — https://meshwork.pstreamer.tv".

## 2.5

First public release in the Perfect Streamer Toolkit.
