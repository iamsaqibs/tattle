# Changelog

## 0.1.0 (unreleased)

First release.

- `tattle run`: preload hooks (via `NODE_OPTIONS=--import`) for `fs`, `fs/promises`, `net`, `tls`, `http(s)`, `fetch`, `dns`, `dgram`, `child_process` and `process.env`, inherited by grandchild Node processes. Exit code and stdio pass through.
- Event schema v1 (JSONL), names and sizes only.
- Analysis: host classification, sensitive-path rule pack (Linux, macOS, Windows paths), read-then-send chains, heuristics, four verdicts.
- Signed receipts (ed25519), shareable SVG card (optional PNG), `verify`, `show`, `list`, `diff`, `key`.
- `verify --strict`: a missing `events.jsonl` is a failure instead of a note.
- Windows path handling: `%USERPROFILE%`, `%APPDATA%`, `%LOCALAPPDATA%`, backslashes, extended-length and UNC prefixes, case-insensitive matching (unit-tested by simulation; see docs/windows.md for what is untested on real Windows).
- Packaging: tarball smoke test (`npm run smoke`), CI matrix (ubuntu/macos/windows, Node 18/20/22/24).
- Hall of Shame tooling (`hall/`), docs (how it works, FAQ, Windows), ethics and disclosure policy.
- New verdict `NOT OBSERVED` (no Node process ran under the hooks; never CLEAN when nothing was observed) and `analysis.coverage` with a partial-coverage note when the top-level command is not Node. `npm run release:check`.
- Verified on Node 18.20.8 and 22.x locally. Node 18.19.0 exactly was not run.
