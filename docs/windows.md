# Windows

Tattle's hooks are at the Node API level, so they do not depend on the operating system. That is why we expect the main path to work on Windows. **Expectation is not verification**: as of 0.1.0 the author's test machine is macOS, so Windows behaviour has been checked by simulation and by a CI matrix that includes `windows-latest`, not by hand on real hardware.

## What works (by design; path logic simulated in unit tests)

- Hook preload through `NODE_OPTIONS=--import file:///C:/...`. The preload URL is built with `pathToFileURL`, so drive letters and spaces are encoded correctly.
- Path rule pack: `%USERPROFILE%` (also `%HOMEDRIVE%%HOMEPATH%`) becomes `~`; `%APPDATA%` and `%LOCALAPPDATA%` are honoured even when relocated off the profile; backslashes, forward slashes and mixed separators; case-insensitive drive letters and directories; `\\?\` extended-length and `\\?\UNC\` prefixes; UNC paths. Windows locations covered: Chrome/Edge/Brave/Firefox profiles, Credential Manager and DPAPI folders, SSH under `AppData\Roaming\Microsoft\SSH`, PowerShell PSReadLine history, GitHub CLI, gcloud, 1Password/Bitwarden, Discord/Slack/Signal, Electrum/Exodus/Solana/Bitcoin and others.
- Clipboard detection recognises `powershell Get-Clipboard` (plus `pbpaste`, `xclip`, `xsel`, `wl-paste` and `osascript` clipboard reads on other platforms).
- Receipts, signing, verify, show, list, diff, card (SVG) are plain Node and file I/O.

## Verified by Windows CI

`windows-latest` x Node 18/20/22/24 runs build, typecheck, the full vitest suite and the pack-and-install smoke test on every push (all green as of CI run 43230400828). That covers, on real Windows:

- `tattle run` end to end, including resolution of `.cmd`/`.bat` shims (`npx`, `npm`): on Windows `tattle run` resolves batch shims and runs them through the shell with proper quoting (Node refuses to spawn them directly since CVE-2024-27980); plain executables are spawned directly.
- Preload injection via `NODE_OPTIONS=--import file:///...`, event capture, receipts, signing, `verify --strict`, exit-code propagation.
- Installing the packed tarball and running the installed `tattle.cmd` / `npx tattle`.
- The transparency suite (hooked output equals unhooked output) minus the POSIX-only probe.

CI is a headless GitHub runner, not an interactive desktop, so it does not exercise a real console or Ctrl+C.

## Still untested on real Windows

- Interactive console behaviour and signal handling: Windows has no POSIX signals; forwarding of Ctrl+C and the exit code of a signalled child differ from the POSIX path.
- Key file permissions: the key is created with mode 0600, which Windows ignores. The key is protected only by the directory ACLs of your profile.
- `.env`-style files with the 8.3 short-name form of the profile (`ALICE~1`) are not expanded, so rule matches on such paths can be missed (documented in a test).
- WSL: a process inside WSL is Linux and uses the Linux rules. Windows files reached through `/mnt/c/Users/...` are not mapped to `~`, so they match only the path-anywhere rules (`**/.env`, `**/*.pem`, ...).
- The optional PNG card (`@resvg/resvg-js`): native module, not tried on Windows.

## Known unsupported

- Anything listed under [what Tattle cannot see](how-it-works.md#what-tattle-cannot-see): native addons, eval workers, non-Node binaries' own activity, hook evasion. On Windows this includes native Windows APIs called by addons.
- Non-Node tools (including Python/Go/Rust CLIs and `.exe` agents): only the spawn is visible.
- Blocking or redaction (Tattle only observes, on every platform).

## Tests that skip on Windows

The suite skips, cleanly, tests that need POSIX tools (including the `proc-full.cjs` transparency probe, which drives `sh` builtins): the guilty ESM fixture (stubs `pbpaste` with an `sh` script and may call `curl`), the shell-line process-hook test (uses `sh`), signal-exit tests, and permission-bit tests. The HTTPS-server tests skip themselves when `openssl` is not on PATH. The Windows path logic is covered by simulation in `test/sensitive.test.ts` on every platform.

If you run Tattle on Windows, a report of what worked and what did not (an issue with the `windows` label and the receipt) is the most useful contribution.
