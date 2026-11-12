# Event schema v1

Events are JSON Lines: one object per line, appended to `$TATTLE_LOG` (normally
`$TATTLE_HOME/receipts/<id>/events.jsonl`, default `~/.tattle`). Implementation: `src/events.ts`.

## Envelope

| field | type | notes |
|---|---|---|
| `v` | number | schema version (currently `1`). Parsers must accept larger values best-effort. |
| `ts` | number | ms since epoch, sub-ms float (`performance.timeOrigin + now()`). For events emitted at *completion* (`fs/read` via callback/promise, streams) `ts` is the **call** time. |
| `pid`, `ppid` | number | process ids. Worker threads share the pid. |
| `seq` | number | per-process counter; with `ts`,`pid` gives a total order. |
| `phase` | string | `"run"` (reserved: `"install"`). |
| `cat` | `net`\|`dns`\|`fs`\|`proc`\|`env`\|`clip`\|`life` | |
| `op` | string | see below |
| `target` | string | host:port / URL / absolute path / program / env NAME |
| `bytes` | number? | see per-event notes |
| `verdictHint` | `sensitive`\|`escape`\|`noise`? | hint for the analyser, not a verdict |
| `detail` | object? | op-specific, free-form, additive |

Unknown top-level or `detail` fields must be preserved and ignored. `parseEventLine` (tolerant
parser) requires only numeric `ts`, string `cat` and `op`.

## Rotation

When the log exceeds `TATTLE_LOG_MAX_BYTES` (default 256 MiB; checked every 128 events per process)
the file is renamed atomically to `events.N.jsonl` (N = first free integer) and a new `events.jsonl`
is opened. Other processes keep their open fd and finish writing into the rotated inode, so no event
is lost; ordering across parts is by `(ts, pid, seq)`. `readEventLog()` merges all parts.

## Events

| cat/op | target | bytes | detail |
|---|---|---|---|
| `life/start` | script or exec path | | `argv, cwd, isTTY{stdin,stdout,stderr}, node, platform, execArgv, thread, runId, hookErrors?` |
| `life/exit` | script or exec path | | `code, elidedFs` (module-loader fs events not emitted) |
| `net/connect` | `host:port` or `unix:<path>` | | `sid, tls, servername?` (emitted at `Socket#connect`, so dns precedes the connection) |
| `net/close` | same | bytes written (egress) | `sid, tls, bytesWritten, bytesRead, connectTs, firstWriteTs?, lastWriteTs?, firstWriteLen?, firstWriteHash?, remoteAddress?, partial?` — `partial:true` = still open at process exit. TLS counts are plaintext. `firstWriteHash` = first 16 hex of sha256 over the first <=64 bytes of the first write. |
| `net/http.request` | `proto://host[:port]/path` (query stripped) | | `method, module, hasQuery?` |
| `net/fetch` | URL (query stripped, no userinfo) | | `method, hasQuery?` |
| `net/tls.connect` | servername or `host:port` | | `host, port` |
| `net/dgram.send` | `udp:addr:port` | payload bytes | `family` |
| `dns/lookup` | hostname (IP literals skipped) | | `promises?` |
| `dns/resolve` | hostname | | `rrtype, promises?` |
| `fs/read` `write` `stat` `readdir` `delete` `rename` `copy` | absolute path | exact for `readFile*`, `writeFile*`/`appendFile*` payload, stream totals | `via` (API used), `error?` (code), `to?` (rename/copy dest), `partial?`, and for sensitive paths `rule, label, severity, category` (+ `verdictHint:"sensitive"`). `fs/read|write` also emitted for `open*` with intent from flags (`detail.flags`). |
| `proc/<spawn,spawnSync,exec,execSync,execFile,execFileSync,fork>` | program (`sh` for exec*) | | `argv, shell, cwd?, clipboard?, networkEscape?, tool?` (+ `verdictHint:"escape"` when `networkEscape`). **Environment is never recorded.** |
| `clip/read` | clipboard tool | | `via, argv` (always `verdictHint:"sensitive"`) |
| `env/read` | variable NAME | | `via` (`get`/`has`), `runtime?` (Node itself reads it). Values never recorded. Deduped per process. |
| `env/enumerate` | `*` | | `count` (whole-environment read: spread, `Object.keys`, child env copy) |
| `env/cwd` | the cwd | | first `process.cwd()` call only |

## Env coverage (what is real)

- **Seen:** reads through the JS `process.env` object after the preload ran: `process.env.X`,
  `'X' in process.env`, destructuring, `import {env} from 'node:process'`, and reads made by
  Node's own JS (tagged `runtime`). One event per distinct name per process. Whole-environment
  reads (including `child_process` copying the env) collapse into `env/enumerate`; individual reads
  in the same synchronous turn are treated as part of it (a genuine single read in that turn is
  missed).
- **Not seen:** native code / addons reading `environ`; `/proc/self/environ` (the sensitive rule
  flags `/proc/*/environ`); anything executed before the preload (Node bootstrap; `--require`
  modules loaded earlier); a worker thread's private env copy; non-Node children.
- **Pre-fork vs post-fork:** the OS snapshots the environment at `exec`. Values the child inherited
  were set by its parent and cannot be attributed to the tool; Tattle only reports which names the
  tool *looked at*, never values, and never claims a name was exfiltrated.
- Other surface: `process.cwd()` (first call), argv/TTY-ness (`life/start`), credential-store
  paths via the sensitive-path rules (category `keychain`).
