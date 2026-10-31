# Perfect Streamer Toolkit

Small command-line tools for MPEG transport streams, by Perfect Soft for
[Perfect Streamer Meshwork](https://meshwork.pstreamer.tv). Each tool lives in its own
folder with its own README and build files.

## Tools

| Tool | What it does |
|:-----|:-------------|
| [`ts_analyze`](ts_analyze/) | ETSI TR 101 290 compliance verdict for a live UDP stream or a TS file, with a pass/fail exit code for scripts and monitoring; RTP with ST 2022-1 FEC and ST 2022-7 seamless inputs |

## Releases

Each tool is released on its own, tagged `<tool>-v<version>` (for example
`ts_analyze-v2.6`). Ready-made static Linux x86_64 binaries are attached to the releases.

## License

Apache License 2.0; see [LICENSE](LICENSE) and [NOTICE](NOTICE). Redistributions and
derivative works keep the NOTICE with its attribution to Perfect Streamer Meshwork.
Third-party libraries keep their own licences, listed in NOTICE and in each tool's README.
