# Perfect Streamer Toolkit

**Command-line tools for MPEG transport streams: TR 101 290 verdicts for scripts and
monitoring.** Static Linux binaries on the [Releases](https://github.com/perfect-soft/perfect-streamer-toolkit/releases) page.

Small tools by Perfect Soft for [Perfect Streamer Meshwork](https://meshwork.pstreamer.tv).
Each tool lives in its own folder with its own README and build files.

## Tools

| Tool | What it does |
|:-----|:-------------|
| [`ts_analyze`](ts_analyze/) | ETSI TR 101 290 compliance verdict for a live UDP stream or a TS file, with a pass/fail exit code for scripts and monitoring; T-STD model and decode lead; RTP with ST 2022-1 FEC and ST 2022-7 seamless inputs |

## Releases

Each tool is released on its own, tagged `<tool>-v<version>` (for example
`ts_analyze-v2.6.2`). Ready-made static Linux x86_64 binaries are attached to the releases.

## License

Apache License 2.0; see [LICENSE](LICENSE) and [NOTICE](NOTICE). As section 4(d) of the
License requires, redistributions and derivative works keep the NOTICE file with its
attribution line, "Perfect Streamer Toolkit by Perfect Soft — https://meshwork.pstreamer.tv".
Third-party libraries keep their own licenses, listed in NOTICE and in each tool's README.
