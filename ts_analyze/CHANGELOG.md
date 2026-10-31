# ts_analyze changelog

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

### Changed: TR 101 290 behaviour

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
