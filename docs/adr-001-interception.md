# ADR-001: How Tattle intercepts a Node CLI

Status: accepted (Phase 0). Probed on Node v22.23.1 / macOS arm64. Minimum supported: Node 18.19.
Everything in the "Verified" column below was checked with a throwaway probe script, not
assumed from the docs. Items marked **(untested)** are reasoned, not measured.

## Decision

**Option (b): preload monkey-patching**, loaded with `--import <file URL of dist/preload.js>` and
injected via `NODE_OPTIONS` by the `tattle run` harness so every grandchild `node` process is
hooked too. Patches are applied to the *builtin module objects* (`fs`, `fs/promises`, `net`, `tls`,
`http`, `https`, `dns`, `dns/promises`, `dgram`, `child_process`, `globalThis.fetch`,
`process.env`), followed by `module.syncBuiltinESMExports()`.

Rejected: **(a) `module.register()` loader hooks.** They run on a separate thread and see module
*resolution and loading* (`resolve`/`load`), not runtime calls such as `fs.readFileSync(...)` or
`socket.connect(...)`. They cannot observe what a tool does, only which files it imports.
**(c) hybrid:** no benefit for interception; loader hooks are reserved for possible future static
analysis (e.g. "which packages were loaded") and are not used now.

Why preload at all (vs. sandbox/ptrace/proxy): zero root, zero certs, zero proxy config, works
unchanged on macOS/Linux/Windows, sees plaintext before TLS, and sees `fs`/`child_process`
activity that a network proxy never could.

## Design rules (binding)

1. Capture original functions before patching; the event writer uses only the originals and
   never emits events (no recursion).
2. A hook never throws into user code, never alters arguments/return values, except the single
   documented exception below (env propagation to children).
3. A depth flag suppresses nested hooked calls made *by* a hooked call (e.g. `exec` -> patched
   `execFile`; `createReadStream` -> `fs.open`), so one user action yields one event.
4. Async fs variants (`readFile`) wrap the callback / chain the promise so bytes can be reported;
   the promise variant returns the *derived* promise so unhandled-rejection semantics are kept.
5. Preload does nothing unless `TATTLE_LOG` is set.

## Threat matrix: API path -> hook point -> covered? -> caveat

"Covered" means: an event is emitted for that call. Verified = measured by probe on Node 22.

### Network

| API path | Hook point | Covered? | Verified / caveat |
|---|---|---|---|
| `net.connect` / `net.createConnection` / `new Socket().connect(...)` | `net.Socket.prototype.connect` | Yes | Verified. **`connect` receives either `[options, cb]` (an array, when called via `net.connect`/`http`/`undici`) or raw `(port, host, cb)` / `(path)` args.** Both shapes must be parsed. Port may be a string (undici passes `"55604"`). |
| `http.request/get` | `Socket.connect` (socket level) + `http.request`/`http.get` (URL+method) | Yes | Verified. `http.get` calls an internal `request`, so both exports are patched; `https.get` likewise. |
| `https.request/get`, `tls.connect` | same; `tls.connect` also patched for `servername` | Yes | Verified: `tls.connect` -> exactly one `Socket.prototype.connect` call. Bytes on a `TLSSocket` (`bytesWritten`/`bytesRead`) count **plaintext** (probe: wrote 5, read 4 -> 5/4), not wire bytes. |
| `globalThis.fetch` (undici bundled in Node) | `Socket.prototype.connect` + `globalThis.fetch` wrapper | Yes | Verified: fetch reaches `Socket.prototype.connect` with options `{host:"localhost", port:"NNNN"}`. A wrapper on `fetch` adds URL+method. A tool that captured `const f = fetch` *before* preload is impossible (preload runs first). |
| `undici` npm package (`require('undici')`) | `Socket.prototype.connect` | Yes **(untested separately)** | undici builds connections with `net.connect`/`tls.connect`; request-level URL event is NOT emitted (only socket-level). |
| `http2.connect` | `Socket.prototype.connect` | Yes (socket level) | Verified for cleartext h2c. No request-level event. |
| Raw TCP, Unix sockets | `Socket.prototype.connect` | Yes | Verified. Unix path recorded as `unix:<path>`. |
| Inbound connections (`net.Server`) | none | No (by design) | Servers do not call `Socket.connect`. A tool opening a *listener* is not recorded in v1. |
| `dns.lookup` | `dns.lookup` | Yes | Verified: `net` resolves hostnames through the **patched `dns.lookup` property at connect time** (it reads `dns.lookup` lazily), so a tool-level lookup and a net-internal lookup are both seen; the net-internal one is a second event. IP literals are skipped. |
| `dns.promises.lookup` (`dns/promises`) | `dns.promises.lookup` | Yes, **separately** | Verified: it does **not** go through `dns.lookup`; must be patched on its own object. |
| `dns.resolve*`, `Resolver#resolve*`, `dns.promises.resolve*` | each function + `Resolver.prototype` | Yes | Not routed through `lookup`. rrtype recorded (TXT matters for DNS-tunnelling heuristics). |
| `dgram` `send` | `dgram.Socket.prototype.send` | Yes | Argument forms `(msg, port, addr)`, `(msg, off, len, port, addr)` and connected `(msg)` parsed. Bytes = payload length. |
| DNS via native code / DoH via `fetch` | covered only as the socket/`fetch` they use | Partial | DoH shows as an HTTPS connection to the resolver, not a DNS event. |
| `worker_threads` | `--import` preload | **Partial** | Verified: file-based workers run the `NODE_OPTIONS --import` preload (threadId 1 observed). **`new Worker(code, {eval:true})` does NOT run the `--import` preload** (observed), although it does run a `--require` preload. Eval-workers are a blind spot. Mitigation if needed later: also ship a CJS preload and use `--require`. |
| Native addons / `process.binding` / `process.dlopen` | none | **No** | Verified `process.binding('fs')` is reachable and returns the raw binding; code calling it (or a `.node` addon doing libc `connect()`/`open()`) bypasses every JS hook. |
| Non-Node child processes (Go/Rust/Python binaries) | none | **No** | Only the *spawn* is seen (argv), not what the binary does. Phase 6 (strace/dtrace). |

### Filesystem

| API path | Hook point | Covered? | Verified / caveat |
|---|---|---|---|
| `fs.readFileSync` etc. via `import fs from 'fs'` | patch property on `fs` object | Yes | Verified. |
| ESM **named** import `import {readFileSync} from 'node:fs'` | patch + `syncBuiltinESMExports()` | Yes | Verified: with the preload patch + sync, a later named import sees the patched function (also via `import * as ns`, `createRequire`, dynamic `import()`). Without the sync call, named imports would NOT see the patch. |
| CJS `const {readFileSync} = require('fs')` in user code | patch before user code runs | Yes | Verified. Only breaks if the binding was destructured *before* preload; impossible for `--import` preload. |
| `fs.promises.*` / `require('fs/promises')` / `import {readFile} from 'fs/promises'` | patch `fs.promises` object (same object as `fs/promises`) + sync | Yes | Verified: `fs.promises === require('fs/promises')`; named & namespace & default imports all saw the patch. |
| `fs.readFile` (callback) | own patch | Yes | Verified: callback `readFile` and `promises.readFile` do **not** route through a patched `readFileSync`; each public entry point must be patched individually. |
| `fs.createReadStream` / `createWriteStream` | own patch (bytes at stream `close`) | Yes | Verified: not via `readFileSync`. Streams internally call public `fs.open` -> suppressed duplicate. |
| `FileHandle` methods (`fs.promises.open(...).then(h => h.readFile())`) | only the `open` is seen | Partial | Read via handle is recorded as `open` (mode) without byte counts. |
| `fs.openSync` + `readSync(fd)` / `fs.read(fd)` | `open*` only | Partial | We record the open (with read/write intent) but not per-fd byte counts. |
| Node's own module loader | reads sources through public `fs.readFileSync` | Noise | Module `.js/.mjs/.cjs/.json/.node/.wasm` reads and anything under `node_modules/` are **elided** unless sensitive; elided count is reported in `life/exit.detail.elidedFs`. |
| `process.binding('fs')`, `internalBinding`, native addons | none | **No** | See above. |
| Memory-mapped / `mmap` / FUSE | none | No | Out of scope. |

### Processes and environment

| API path | Hook point | Covered? | Verified / caveat |
|---|---|---|---|
| `child_process.spawn/spawnSync/exec/execSync/execFile/execFileSync/fork` | patch each property | Yes | Verified: `exec` calls the patched `execFile` via module exports (double-count unless depth-guarded; guarded). `fork` shares the same property patching. |
| Grandchild **node** processes | `NODE_OPTIONS` inherited | Yes | Verified: nested `spawnSync(process.execPath, ...)` runs the preload. |
| Grandchild with explicit `env: {}` (no NODE_OPTIONS) | proc hook injects `NODE_OPTIONS`+`TATTLE_LOG` into an explicit `env` object | Yes (**deviation**: the only place we modify a call) | Verified without injection: `env: {}` loses the preload. We copy the env object and add the two variables so propagation survives. If the tool strips them on purpose (evasion) the child is unhooked. |
| Shell scripts that launch node (`#!/bin/sh` -> `node x.js`) | `NODE_OPTIONS` inherited | Yes | env var is inherited through shells. |
| `process.env.X` reads | `process.env = new Proxy(process.env, ...)`, then `syncBuiltinESMExports()` | Yes for JS reads | Verified: assignment works; `import {env} from 'node:process'` and `process.env` stay identical; `execSync` etc. read the proxy; Node internals also read through it (e.g. `NODE_V8_COVERAGE`). **Enumeration** (`{...process.env}`, `Object.keys`, child_process env copy) triggers `ownKeys` followed by a `get` per key; we treat gets in the same synchronous turn as enumeration and emit one `env/enumerate` instead of N reads. A genuine single read in the same sync turn as an enumeration is therefore missed (accepted). |
| Env values | never recorded | n/a | Names only. |
| Env of native code / `/proc/self/environ` / `environ` in addons | none | **No** | The environment was snapshotted by the OS at `exec`; anything that reads it without going through the JS `process.env` object is invisible. Reading `/proc/<pid>/environ` is flagged by the sensitive-path rule instead. |
| Env **pre-fork vs post-fork** | n/a | Document | Before the preload runs (Node bootstrap, `--require`d code that ran earlier, `NODE_OPTIONS` parse) reads are not seen. Values the child *inherits* were set by the parent and cannot be attributed. Worker threads get their own copy of `process.env`; reads there are not seen unless the preload runs in that worker. |
| `process.cwd()` | patched, deduped (one event) | Yes | |
| Clipboard | subprocess heuristic only (`pbpaste`, `xclip`, `xsel`, `wl-paste`, `powershell Get-Clipboard`, `osascript ... clipboard`) | Partial | Native clipboard libs (addons) are invisible. |

## Hook detection and evasion (accepted limitation, v1)

Tattle runs **in the same process and privilege domain** as the tool. A hostile tool can:
- inspect `Function.prototype.toString` on `fs.readFileSync` (verified: patched functions print as our wrapper source) or compare against `process.binding`;
- delete/override `TATTLE_LOG`, `NODE_OPTIONS`, `process.env` proxy, or call `process.binding('fs')`/native addons directly;
- spawn a non-Node binary or use `--no-experimental-*`/`node --import` stripping tricks;
- use eval-workers (above).

So Tattle is evidence for *honest-but-curious* and *accidentally-chatty* tools, and for
supply-chain code that is not specifically evading it. It is not a sandbox and cannot prove absence
of activity. Every receipt carries this posture. A sandboxed backend (strace/dtrace/bubblewrap) is
Phase 6 research.

## Byte-count fidelity

`bytesWritten`/`bytesRead` are read from the socket at `close` (exact for the socket as the app
sees it: plaintext for TLS, no TCP/IP overhead). Sockets still open at process exit are flushed as
`net/close` with `detail.partial=true`. fs byte counts are exact for `readFile*`/`writeFile*`
(result/payload length) and stream totals; absent for fd-level IO. Hard-killed processes (SIGKILL)
lose open-socket flushes.

## Late findings (discovered while implementing the hooks)

- First-write timing is taken by wrapping `net.Socket.prototype.write` (looked up per socket in the tracked-socket map), NOT a per-instance `write` wrapper: `net.Socket#connect` resets `this.write` to the prototype method, and an own `write` property would also change `write.length` and `Object.keys(socket)`. Accepted server sockets are never tracked.
- `fs.writeFile`/`appendFile` (callback) call the public `fs.open` synchronously; `ReadStream`/`WriteStream` call it on `nextTick`. The first is handled by the depth guard, the second by a per-path counter.
- `sh -c '<line>'` / `bash -c` payloads are classified like `exec` shell lines (clipboard readers, curl/nc/etc. inside).
- Events emitted at completion (async `readFile`, streams) carry the *call* time in `ts`, so a log is sorted by `ts`, not file order.

- **Env Proxy must forward `set` with the real target as receiver.** A Proxy without a `set` trap makes `process.env.X = v` run OrdinarySet with Receiver = proxy, i.e. `proxy.[[DefineOwnProperty]](X, {value})` with a *partial* descriptor, which Node's env object rejects (`ERR_INVALID_OBJECT_DEFINE_PROPERTY`). npm writes `process.env.npm_config_*` at startup, so every npm command exited 1 with no output. Regression fixture: `fixtures/compat/env-writes.cjs`. `TATTLE_DISABLE=net,fs,env,proc` skips hook groups for bisecting such breakage.

## Transparency suite and limitations

`test/transparency.test.ts` runs every probe in `fixtures/compat/` plain and hooked and requires byte-identical stdout and exit code (env, fs, net/http, dns, child_process/fork/worker, fetch, ESM named imports, exit/uncaught/unhandled-rejection lifecycles). Divergences it found and fixed:
- `util.promisify(dns.lookup)` / `promisify(exec|execFile)`: the wrapper dropped the function's own properties (`kCustomPromisifyArgs`, `util.promisify.custom`, `.native`). `patch()` now copies all own properties (symbols included); the `exec`/`execFile` custom promisify is itself hooked so promisified calls are still recorded.
- `socket.write.length` / own enumerable `write` on client sockets (see above).
- Our own `process.on('exit')` ran before user handlers (changing `listenerCount('exit')`, losing fs events from user exit handlers, recording a stale exit code). We now wrap `process.emit('exit')` and finalize afterwards.
- `process.env.hasOwnProperty`/`toString` probing is no longer reported as an env var read.
- Socket ids collided between main thread and workers of one pid; targets for IPv6 hosts are now bracketed.

Residual, unavoidable differences (documented, not tested): `util.types.isProxy(process.env)` is true; `createReadStream/createWriteStream` instances carry one extra `close` listener (`listenerCount('close')` is +1); `Function.prototype.toString` of hooked functions shows the wrapper; child processes spawned with an explicit `env` get `NODE_OPTIONS`/`TATTLE_LOG` added (required to keep them observed); `process.emit` is an own property of `process`.

Node-version artifact (not caused by Tattle): on Node 18.19, *any* `--import` preload — even an empty file — makes core register its own `handleProcessExit` 'exit' listener, so `process.listenerCount('exit')` is +1 versus a run with no preload. Node 22 does not do this. The transparency suite detects the behaviour at runtime and then compares against an empty-`--import` baseline, which isolates exactly what Tattle's hooks change.

## Consequences

- One tiny self-contained preload bundle (no shared chunks) is loaded in every node process.
- Verified on Node 18.19.0 (exact engines minimum), 18.20.8 and 22.23.1 on macOS: full test suite + pack smoke green. Windows/Linux are covered only by the CI matrix (not yet run).
- Open follow-ups: CJS `--require` preload to also cover eval-workers; `FileHandle` hooks; optional `Function.prototype.toString` masking (rejected for v1: it is itself an evasion-arms-race feature).
