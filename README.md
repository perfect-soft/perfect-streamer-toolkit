# Perfect Streamer Toolkit

Small command-line tools for MPEG transport streams, from the
[Perfect Streamer](https://meshwork.pstreamer.tv) project. Each tool lives in its own
folder with its own README and build files.

## Tools

| Tool | What it does |
|:-----|:-------------|
| [`ts_analyze`](ts_analyze/) | ETSI TR 101 290 compliance verdict for a live UDP stream or a TS file, with a pass/fail exit code for scripts and monitoring |

## Releases

Each tool is released on its own, tagged `<tool>-v<version>` (for example
`ts_analyze-v2.5`). Ready-made static Linux x86_64 binaries are attached to the releases.

## License

Apache License 2.0; see [LICENSE](LICENSE) and [NOTICE](NOTICE). Third-party libraries
keep their own licences, listed in NOTICE and in each tool's README.
