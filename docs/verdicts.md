# Verdicts and thresholds

Resolves open decision #3 ("where does noisy end and phoning home begin"). Implementation:
`src/analyze/{index,chains,heuristics,verdict}.ts`. The analysis is pure and deterministic.

## Precedence (first match wins)

0. **NOT OBSERVED** - zero hooked processes reported any event (`analysis.coverage.hookedProcesses === 0`): no Node.js process ran under the preload, so nothing was observed. Message: "no Node.js process was observed - Tattle cannot see inside native binaries; this is not a clean bill of health". It is checked first, is neutral (gray), and ranks below CLEAN in `diff` (changes to or from it are not labelled better/worse). A receipt must never say CLEAN when nothing was observed.
1. **ESCAPE CHAIN** - at least one correlated chain (see below), any confidence.
2. **READING SECRETS** - any sensitive read (successful `fs/read` tagged sensitive, or a clipboard read) of severity >= medium. Low-severity sensitive reads (e.g. shell history) are listed as reasons but do not change a CLEAN verdict.
   **Failed** accesses (`detail.error` set, e.g. ENOENT) to secret-shaped paths are *probes*, not reads: they are counted separately (`analysis.probes`), reported as one low-severity `PROBED_SECRETS` reason ("probed N secret-shaped paths (not found)"), and never trigger READING SECRETS or escape chains by themselves.
3. **PHONING HOME** - any connection to a host classed `telemetry`, `unknown` or `raw-ip` (non-local), or any heuristic finding of severity >= medium.
4. **CLEAN** - everything else (connections only to `good` hosts, loopback, or nothing).

Hosts of class `good` (the tool's own API vendor, package registries) never trigger anything and
are never chain sinks. `local` (loopback) is ignored unless `includeLocal` is set (hidden CLI flag
`--include-local`, used by fixtures/tests): then loopback hosts are analysed as `unknown`
(reported with `local: true`). Hence the noisy fixture is CLEAN by default and PHONING HOME with
`--include-local`; the guilty fixture is ESCAPE CHAIN with it.

## Coverage

`analysis.coverage = { hookedProcesses, rootHooked, note? }`. `hookedProcesses` is the number of distinct pids that reported events. `rootHooked` is whether the top-level command's own pid was among them. When it is not but descendants were (a native binary or a shell wrapper that launches `node`), the verdict is still computed from what was seen and an info-level `PARTIAL_COVERAGE` reason is added: "partial coverage: <argv0> is not a Node process; only N Node descendants observed". It is shown in the terminal summary and on the card. Receipts from before this field have no `coverage`.

## Chain thresholds (defaults, all configurable via `AnalyzeOptions`)

| rule | default |
|---|---|
| time window, read -> first socket write (or proc spawn) | 5000 ms (`windowMs`) |
| size: `bytesWritten >= ratio * bytesRead` | 0.8 (`sizeRatio`) |
| pid | same pid, or sink in a descendant (via `ppid`) |
| sink host | `unknown`, `telemetry`, `raw-ip` |

Confidence: **high** = same pid + size-verified + measured `firstWriteTs`; **medium** = descendant
pid, unverifiable read size, missing `firstWriteTs`, network-tool spawns (`curl`, `nc`, ...) and
clipboard-to-network. A chain is a correlation of pid/time/size, never proof of causation; the
explanation string says so.

## Heuristic thresholds

| code | severity | trigger |
|---|---|---|
| `RAW_IP_CONNECTION` | medium (public) / low (private range) | connect target is an IP literal |
| `ODD_TLD_DNS` | medium | DNS name under a short abused-TLD list (cited in `heuristics.ts`) |
| `DNS_TXT_BURST` | medium | more than 10 TXT lookups within 10 s |
| `LONG_LIVED_HIGH_WRITE` | low | socket open >= 30 s and >= 1 MiB written |
| `TLS_NO_DATA` | low | TLS connection closed with 0 bytes both ways; left "unclassified" |

## Severity table and score

| severity | reasons | score weight |
|---|---|---|
| critical | high-confidence escape chain | 60 |
| high | medium-confidence chain; high-severity sensitive read | 35 |
| medium | medium-severity sensitive read, clipboard read, unclassified host, medium heuristics | 12 |
| low | telemetry host, low-severity read, network-tool spawn, low heuristics | 3 |

`score` = sum of weights, capped at 100. It is for ranking/presentation; the verdict comes only
from the precedence rules above.

## Evidence pointers

Every reason carries `evidence: {line, pid, seq}[]`. `line` is the 0-based index into the event list
sorted by `(ts, pid, seq)` (what `readEventLog()` returns; async reads are emitted late with their
call-time `ts`, so raw file order differs). `pid`+`seq` identify the raw JSONL line regardless.

## Wording

Reasons state observations ("read 3 secret-shaped files", "opened 1 connection to an unclassified
host") and never intent.
