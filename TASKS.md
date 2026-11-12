# Tattle — Build Tasks

> The lie detector for AI CLI tools. `npx tattle run <any-cli>` → in-process hooks capture every
> file read, network connection, and child process → a signed, meme-able verdict receipt.
>
> **Status:** v0.1.0 built (Phases 0–4 + local Phase 5 tooling) · repo: github.com/iamsaqibs/tattle

---

## North-star scope guards

**In scope** (MVP): Node-based CLIs (which agent tools overwhelmingly are), one-command run, zero
certs/root/proxy, full-signal receipts (network + fs + child_process + env/clipboard heuristics),
verdict card, signed local receipts.

**Out of scope until proven:** blocking/malware-prevention (we observe, we don't police),
non-Node binaries (Phase 6), browser extensions, cloud anything.

**Non-goals (say it in the README):** Tattle is not an antivirus, not a firewall, and makes no
legal claims. It produces evidence, not judgments — the verdict labels must stay defensible
("read 3 secret-shaped files, opened 1 connection to an unclassified host" not "it stole your keys").

---

## Phase 0 — Foundations

- [ ] **T0.1 Package scaffold** — `package.json` (name `tattle`, `bin: {tattle: dist/cli.js}`, ESM,
      `"engines": { "node": ">=18.19" }` — pinned because `node:module.register()` landed in 18.19/20.6).
      Zero-runtime-deps policy if achievable (ANSI colors hand-rolled), devDeps: typescript, vitest, tsup (or unbuild), @types/node.
- [ ] **T0.2 Build + test rig** — `tsconfig.json` strict ESM, tsup for dual dist (ESM), vitest with
      fixtures dir. DoD: `npm run build && npm test` green on an empty core.
- [ ] **T0.3 Interception architecture ADR** (`docs/adr-001-interception.md`) — decide and document:
      (a) `module.register()` loader hooks vs (b) preload monkey-patching via `--import`
      (patch `require('dns')`, ESM namespace globals, globalThis.fetch) vs (c) hybrid.
      Decision driver: some tools use plain `https`, some undici, some raw sockets — the hook must
      catch all three. Write the threat matrix per API path *before* writing hooks.
      **This is the single highest-risk design decision in the project — write the ADR first.**
- [ ] **T0.4 Event schema v1** — `docs/schema.md` + `src/events.ts`: JSONL lines
      `{ts, pid, phase, cat: net|dns|fs|proc|env|clip, op, target, bytes?, verdictHint?, detail}`,
      append-only writer with atomic rotation, schema-version field (receipts must be forward-parseable).

## Phase 1 — Interception engine (the heart)

- [ ] **T1.1 Harness** — `tattle run <cmd...>`: spawn child with `--import <tattle-preload>` +
      event-log env var; stream child stdio through verbatim; on exit, aggregate. DoD: runs `node -e 'console.log(1)'`, log has lifecycle events, exit code propagates.
- [ ] **T1.2 Network hooks** — dns.lookup/resolve*, net.Socket.connect, tls.connect, http.request,
      https.request, globalThis.fetch (+ undici pool if reachable). Capture: host, port, byte
      counts up/down (wrap socket write/read), first-bytes hash. DoD: fixture tool doing
      http+https+fetch+raw-tcp logs all four with correct hosts/counts.
- [ ] **T1.3 FS hooks** — fs promises/callback/sync read+write+stat, `fs.createReadStream`.
      Classify: read/write/target-path; tag sensitive matches (see T1.6). DoD: fixture reading
      `.env` + writing temp file emits both with classification.
- [ ] **T1.4 Process hooks** — child_process spawn/exec/execFile (capture argv, not env),
      plus detection of clipboard reads via subprocess (`pbpaste`, `xclip`, `powershell Get-Clipboard`)
      and curl/wget/network fetchers as "external network escapes". DoD: fixture spawning curl
      and pbpaste both flagged with the exact argv.
- [ ] **T1.5 Env+cwd surface audit** — static, cheap, honest: record *which* env-var NAMES the child
      reads (document the limitation pre-fork vs post-fork), `process.cwd()`, argv, TTY-ness,
      keychain/credential-store paths accessed. DoD: docs state exactly what env coverage is real.
- [ ] **T1.6 Sensitive-surface library** — `src/sensitive.ts`: glob/rule pack — dotenv/env files,
      `~/.ssh/*`, `~/.aws/*`, `~/.kube/config`, browser cookie stores (Chrome/Firefox/Edge paths —
      a *huge* 2026 scare surface), `~/.netrc`, shell histories, wallet dirs (`Ethereum`, `Electrum`),
      token files (`~/.config/gh/hosts.yml` etc.). Seed via a generated rule table with sources
      in comments. DoD: >25 rules, each with a docs citation, and a test that hits 10 of them.
- [ ] **T1.7 Fixture suite** — `fixtures/guilty`, `fixtures/clean`, `fixtures/noisy`: deterministic
      offline CLIs (no real network! raw-socket to localhost, temp .env) that exercise every hook.
      DoD: `npm test` asserts exact event types per fixture — this suite is the project's spec.

## Phase 2 — Analysis & verdict engine

- [ ] **T2.1 Host intelligence (local, no cloud)** — bundled JSON of well-known-good domains
      (registries, official model vendors' API hosts) + well-known-telemetry (analytics vendors).
      Unclassified = "unknown". Source list with citations; update script, offline by default.
- [ ] **T2.2 Escape-chain graph** — correlate: sensitive-file read → buffer size → socket write
      size+timing → host. Flag chains (read 1.2 KB `.env` then POST 1.1 KB to unknown host within
      N ms = "correlated escape"). This causal-link layer is what no incumbent ships. DoD: fixture
      guilty-CLI produces a correlated-chain finding; clean fixture produces none.
- [ ] **T2.3 Covert-channel heuristics v0** — flags for: raw IPs / odd TLD DNS queries, high-rate
      TXT lookups (DNS tunneling smell), long-lived sockets at high writes, cert-pin evasion hint
      (TLS failures on known-interception ports left as "unclassified" not "malicious"). DoD: 3 heuristics + tests.
- [ ] **T2.4 Verdict computation** — deterministic score: CLEAN / PHONING HOME / READING SECRETS /
      🚨 ESCAPE CHAIN, with a reasons array (each reason = evidence pointer into the JSONL).
      Verdicts must be explainable line-by-line in the card. DoD: verdict snapshots per fixture.

## Phase 3 — Receipt card & terminal UX

- [ ] **T3.1 Terminal modes** — live ticker (`--watch`: one-line-per-event, ANSI-dimmed noise),
      final summary block, `--quiet`/`--json`/`--no-color`. DoD: pleasant on 80 cols, no emoji-soup.
- [ ] **T3.2 Card renderer** — satori + resvg (same proven stack as local wrapped tools) →
      1200×630 PNG + SVG: verdict banner, top-5 findings, host tally (good/telemetry/unknown),
      sensitive-file count, escape-chain mini-graph, receipt ID + timestamp + `tattle verify` line.
      Design pass: must be *readable at feed scale* — that's the share-artifact test.
- [ ] **T3.3 Signed receipts** — local ed25519 keypair per machine (`~/.tattle/`), sign card JSON +
      hash of raw JSONL; `tattle verify <receipt.json>`; receipt ID = hash short-form.
      Posture line printed on card: "events captured in-process, nothing left this machine".
- [ ] **T3.4 `tattle show` / `tattle diff`** — re-render stored receipt; `diff` two receipts of the
      same tool across versions (supply-chain story: "v1.2 started reading .ssh").

## Phase 4 — CLI packaging, docs, distribution

- [ ] **T4.1 README in the 7-second formula** — hook line → **verdict-card GIF** →
      `npx tattle run <tool>` → 3 use cases → non-goals → architecture diagram. GIF via
      `vhs` (tape file in repo, regenerable).
- [ ] **T4.2 npm packaging + smoke CI** — publish check (`npm pack` install-from-tarball test),
      GitHub Actions matrix (mac+linux, node 18/20/22+), fixture suite on CI.
- [ ] **T4.3 Windows honesty pass** — document what works (hooks are Node-level → should work),
      path rule pack for win (`%USERPROFILE%`), CI job, known-unsupported list. DoD: no false "unsupported" marketing.
- [ ] **T4.4 Docs site stub + FAQ** — how it works (preload diagram), privacy posture, limitations
      table (what Tattle CANNOT see), comparison: vs proxies (redactai/egressor) and vs one-off
      harnesses (grok-monitor) — honest table, link them with respect (they'll HN-comment; be kind).

## Phase 5 — Hall of Shame & launch

- [ ] **T5.1 HoS runner** — `hall/run.sh`: batch `tattle run` across a curated list of top agent
      CLIs (config list, timeout + network opt-in flags), emit receipts + build `HALL_OF_SHAME.md`
      table (verdict, hosts, secrets touched) + card thumbnails.
- [ ] **T5.2 First 20 receipts** — run them for real, redact responsibly, publish. Every claim in
      the table must be reproducible from the raw receipt.
- [ ] **T5.3 Ethics & disclosure policy** — README section: what we publish, 72h notice to
      vendors before naming, how to contest a receipt, no-paywall-no-drama-farming stance.
      Publish *before* the first finding (trust is the product).
- [ ] **T5.4 Launch kit** — HN draft (personal story + top finding as hook), LinkedIn/X variants,
      Show HN checklist (Tue–Thu 8–10am EST), awesome-list PRs (awesome-s Supply chain/awesome-agents),
      demo GIF + 3 ready receipts as launch media.

## Phase 6 — Depth (post-launch moat)

- [ ] **T6.1 Install-time mode** — `tattle install <pkg>`: run `npm install` of a package under
      hooks (install scripts are the classic supply-chain escape) → install-phase receipt.
- [ ] **T6.2 strace/dtrace backend** — non-Node binaries; Linux first (bubblewrap/seccomp-notify
      research doc before code).
- [ ] **T6.3 Surface-diff verifier** — declared API endpoints in package metadata vs actual
      connections observed → "undeclared endpoint" findings.
- [ ] **T6.4 MCP server** — `tattle-mcp`: lets *agents* tattle a tool before they run it;
      the 2026-native distribution channel (skills/agent marketplaces), aligns with the security-audit-skill wave.

---

## Dependencies & critical path

T0.3 (ADR) → T0.4 → T1.1 → {T1.2, T1.3, T1.4, T1.5} → T1.7 → T2.x → T3.x → T4.x → T5.x.
T1.6 and T3.2 can parallelize early (content + design work, no engine dependency).
MVP = Phase 0–4. **Launch-blocking = Phase 5** (receipts + policy before attention).

## Open decisions (park until ADR)

1. Loader vs monkey-patch per Node API surface (T0.3)
2. Byte-count fidelity on chunked/streams (approximation acceptable? document error bars)
3. Verdict thresholds — where does "noisy" end and "phoning home" begin
4. In-process hooking vs sandbox for adversarial tools (evasion: tools can detect hooks —
   document as accepted limitation v1; sandbox = Phase 6 research)
