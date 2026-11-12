# FAQ

**Is Tattle an antivirus or a firewall?** No. It observes and never blocks. It makes no legal claims and produces evidence, not judgments.

**Why does my receipt say NOT OBSERVED?** No Node.js process ran under Tattle's hooks, typically because the command is a native binary (Go, Rust, Mach-O/ELF). Tattle cannot see inside native binaries, so it reports that nothing was observed rather than CLEAN. If a native binary launches Node processes, those are hooked and the receipt notes `partial coverage`.

**Does a CLEAN verdict mean the tool is safe?** No. It means the hooks saw nothing that met the thresholds in this run. See [what Tattle cannot see](how-it-works.md#what-tattle-cannot-see).

**Why did a tool I know talks to the network show no hosts?** Possible reasons: the command exited before doing so (try the real workflow), the tool is not Node (a Go or Rust binary), it uses a native addon, or it did the work in an eval worker. The receipt lists the processes it saw.

**Does Tattle see my secrets?** It never records file contents, request bodies or environment values; only paths, hosts, sizes and variable names. It does hold the same permissions as the tool you run, because it runs inside it.

**Does it send anything anywhere?** No. No network calls, no telemetry.

**Will it slow my tool down?** Each hooked call adds a small synchronous append. Module-loader reads and `node_modules` reads are elided from the log. We have not published benchmarks.

**It says "secret-shaped". Why not "secret"?** Because a path match (`~/.aws/credentials`, a `.env`) tells you a sensitive *location* was read, not what the tool did with it. Wording stays defensible on purpose.

**How do I share a receipt?** `tattle show --json <id> > receipt.json`, or `tattle run --out receipt.json`. Check it first: it contains real paths. Include `events.jsonl` if you want `tattle verify --strict` to pass for the recipient.

**What does `verify` prove?** The signature matches the body, the id matches the body and, if `events.jsonl` is present, that it hashes to the signed value. It does not prove the run was honest or who the signer is; use `--trust <fingerprint>` with a fingerprint you obtained out of band.

**Does it work on Windows?** Probably for the main path; see [windows.md](windows.md) for what has and has not been tested.

**Can I run it in CI?** Yes: `tattle run --quiet -- <cmd>`, then `tattle diff --fail-on-new <baseline> <new>`.

**Does it work with `npx some-tool`?** Yes: `tattle run -- npx some-tool`. `NODE_OPTIONS` is inherited by the Node processes npx launches.

**A tool strips `NODE_OPTIONS`. Now what?** Tattle re-adds its variables when a hooked tool spawns a child with an explicit `env`; if a tool deliberately removes them, that child is unhooked and you will see the spawn but not its activity.

**Which Node versions?** 18.19 and newer. CI covers 18, 20, 22 and 24.

**What is the hidden `--include-local` flag?** it makes loopback hosts count as "unknown" so the test fixtures (which use localhost servers) exercise the analysis.

**How do I report a wrong or unfair verdict?** See Ethics & disclosure in the [README](../README.md#ethics--disclosure).
