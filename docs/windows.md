# Windows

Tattle's hooks are at the Node API level, so they do not depend on the operating system. That is why we expect the main path to work on Windows. **Expectation is not verification**: as of 0.1.0 the author's test machine is macOS, so Windows behaviour has been checked by simulation and by a CI matrix that includes `windows-latest`, not by hand on real hardware.

## What works (by design, simulated in unit tests)

- Hook preload through `NODE_OPTIONS=--import file:///C:/...`. The preload URL is built with `pathToFileURL`, so drive letters and spaces are encoded correctly.
- Path rule pack: `%USERPROFILE%` (also `%HOMEDRIVE%%HOMEPATH%`) becomes `~`; `%APPDATA%` and `%LOCALAPPDATA%` are honoured even when relocated off the profile; backslashes, forward slashes and mixed separators; case-insensitive drive letters and directories; `\\?\` extended-length and `\\?\UNC\` prefixes; UNC paths. Windows locations covered: Chrome/Edge/Brave/Firefox profiles, Credential Manager and DPAPI folders, SSH under `AppData\Roaming\Microsoft\SSH`, PowerShell PSReadLine history, GitHub CLI, gcloud, 1Password/Bitwarden, Discord/Slack/Signal, Electrum/Exodus/Solana/Bitcoin and others.
- Clipboard detection recognises `powershell Get-Clipboard` (plus `pbpaste`, `xclip`, `xsel`, `wl-paste` and `osascript` clipboard reads on other platforms).
- Receipts, signing, verify, show, list, diff, card (SVG) are plain Node and file I/O.

## Untested on real Windows

- The whole `tattle run` flow end to end, including `.cmd` shims (`npx`, `npm`) and how `spawn` resolves them. Node spawns `.cmd` files only through a shell, so wrapping `tattle run -- npx foo` may need `tattle run -- npx.cmd foo`. We have not confirmed.
- Signal behaviour: Windows has no POSIX signals; forwarding of Ctrl+C and the exit code of a signalled child differ from the POSIX path.
- Key file permissions: the key is created with mode 0600, which Windows ignores. The key is protected only by the directory ACLs of your profile.
- `.env`-style files with the 8.3 short-name form of the profile (`ALICE~1`) are not expanded, so rule matches on such paths can be missed (documented in a test).
- WSL: a process inside WSL is Linux and uses the Linux rules. Windows files reached through `/mnt/c/Users/...` are not mapped to `~`, so they match only the path-anywhere rules (`**/.env`, `**/*.pem`, ...).
- The optional PNG card (`@resvg/resvg-js`): native module, not tried on Windows.

## Known unsupported

- Anything listed under [what Tattle cannot see](how-it-works.md#what-tattle-cannot-see): native addons, eval workers, non-Node binaries' own activity, hook evasion. On Windows this includes native Windows APIs called by addons.
- Non-Node tools (including Python/Go/Rust CLIs and `.exe` agents): only the spawn is visible.
- Blocking or redaction (Tattle only observes, on every platform).

## Tests that skip on Windows

The suite skips, cleanly, tests that need POSIX tools: the guilty ESM fixture (stubs `pbpaste` with an `sh` script and may call `curl`), the shell-line process-hook test (uses `sh`), signal-exit tests, and permission-bit tests. The HTTPS-server tests skip themselves when `openssl` is not on PATH. The Windows path logic is covered by simulation in `test/sensitive.test.ts` on every platform.

If you run Tattle on Windows, a report of what worked and what did not (an issue with the `windows` label and the receipt) is the most useful contribution.
