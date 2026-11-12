import { randomBytes } from 'node:crypto';
import fs from 'node:fs';
import os from 'node:os';
import path from 'node:path';
import { spawn, type ChildProcess } from 'node:child_process';
import { fileURLToPath, pathToFileURL } from 'node:url';
import { analyze } from './analyze/index.js';
import { diffReceipts } from './diff.js';
import { readEventLog } from './events.js';
import { buildReceiptBody } from './receipt.js';
import { createStyle, detectColor, supportsUnicode, truncate, type Style } from './render/ansi.js';
import { writeCard } from './render/card.js';
import { formatBytes, renderSummary, verdictLine } from './render/summary.js';
import { startTicker, type Ticker } from './render/ticker.js';
import { loadOrCreateKey, sha256File, signReceipt, verifyReceipt } from './sign.js';
import { listReceipts, resolveReceipt, tattleHome } from './store.js';

export { tattleHome };

// ---- help ---------------------------------------------------------------------------------------

const USAGE = `tattle - observe what an AI CLI tool really does

Usage:
  tattle run [flags] [--] <command...>   run a command with Tattle hooks attached
  tattle verify <receipt|dir|id>         check a receipt's signature, id and events hash
  tattle show [<id|dir|latest>]          re-render a stored receipt's summary
  tattle list                            list stored receipts
  tattle diff <a> <b>                    compare two receipts (new hosts, secrets, processes)
  tattle key                             print this machine's signing key fingerprint
  tattle install <pkg>                   planned (Phase 6)

Global:
  -h, --help       help (also: tattle <command> --help)
  -v, --version    print version

Receipts live in $TATTLE_HOME/receipts (default ~/.tattle/receipts).
`;

const HELP: Record<string, string> = {
  run: `tattle run [flags] [--] <command...>

Run a command with the Tattle preload attached (also in every node process it spawns), then
print a verdict and write a signed receipt + card into the receipt directory.
The child's stdio is inherited and untouched; Tattle output goes to stderr.

Flags:
  --watch          live ticker: one line per event on stderr while the child runs
  -q, --quiet      print only the verdict line
  --json           print the signed receipt JSON to stdout after the child exits.
                   NOTE: the child's own stdout is interleaved before it, so with
                   --json also pass --out <file> to get a clean copy.
  --out <file>     also write the signed receipt JSON to <file>
  --no-card        do not write card.svg / card.png
  --no-color       disable ANSI colors (also: NO_COLOR; FORCE_COLOR forces them on)
  -h, --help
`,
  verify: `tattle verify [--strict] [--trust <fingerprint>]... [--json] <receipt.json | receipt dir | id | id-prefix>

Checks the ed25519 signature, that the id matches the body, and that events.jsonl next to the
receipt still hashes to the signed value (skipped, with a note, when the events file is not
there, e.g. a lone receipt.json that was shared). Exit 0 if everything holds, 1 otherwise.
--strict treats a missing events.jsonl as a failure (the events hash must be checked), which is
what you want when verifying a receipt someone else claims is complete.
--trust pins accepted signer fingerprints (repeatable); see 'tattle key'.
`,
  show: `tattle show [--card] [--json] [<id | dir | receipt.json | latest>]   (default: latest)

Re-render a stored receipt. --card regenerates card.svg (and card.png when available).
`,
  list: `tattle list [--json]

List stored receipts, newest first: id, date, verdict, tool argv.
`,
  diff: `tattle diff [--json] [--fail-on-new] <a> <b>

Compare two receipts (e.g. one tool across versions): verdict change, new/removed hosts,
sensitive-rule hits and process argv0s, and byte deltas per host.
Exit 0 always; with --fail-on-new exit 1 if anything new/worse appeared (CI use).
`,
  key: `tattle key

Print the signing key fingerprint and the public key path (creates the key on first use).
`,
  install: `tattle install <pkg>

Planned (Phase 6): run npm install under Tattle hooks. Not implemented yet.
`,
};

// ---- flag parsing -------------------------------------------------------------------------------

interface Spec {
  bool?: Record<string, string>; // flag -> canonical name
  value?: Record<string, string>;
  stopAtPositional?: boolean;
}
interface Parsed {
  flags: Record<string, boolean | string | string[]>;
  rest: string[];
  error?: string;
}

function parseFlags(argv: string[], spec: Spec): Parsed {
  const flags: Parsed['flags'] = {};
  const rest: string[] = [];
  let i = 0;
  for (; i < argv.length; i++) {
    const a = argv[i]!;
    if (a === '--') {
      i++;
      break;
    }
    if (!a.startsWith('-') || a === '-') {
      if (spec.stopAtPositional) break;
      rest.push(a);
      continue;
    }
    const eq = a.indexOf('=');
    const name = eq > 0 && a.startsWith('--') ? a.slice(0, eq) : a;
    if (spec.bool?.[name] && eq < 0) flags[spec.bool[name]!] = true;
    else if (spec.value?.[name]) {
      const key = spec.value[name]!;
      const v = eq > 0 ? a.slice(eq + 1) : argv[++i];
      if (v === undefined) return { flags, rest, error: `${name} needs a value` };
      const cur = flags[key];
      flags[key] = Array.isArray(cur) ? [...cur, v] : cur !== undefined ? [cur as string, v] : v;
    } else return { flags, rest, error: `unknown flag: ${a}` };
  }
  rest.push(...argv.slice(i));
  return { flags, rest };
}
const asList = (v: boolean | string | string[] | undefined): string[] => (Array.isArray(v) ? v : typeof v === 'string' ? [v] : []);

// ---- env helpers --------------------------------------------------------------------------------

function pkgVersion(): string {
  try {
    return JSON.parse(fs.readFileSync(new URL('../package.json', import.meta.url), 'utf8')).version as string;
  } catch {
    return '0.0.0';
  }
}

function newRunId(): string {
  const d = new Date();
  const p = (n: number, w = 2) => String(n).padStart(w, '0');
  const stamp = `${d.getUTCFullYear()}${p(d.getUTCMonth() + 1)}${p(d.getUTCDate())}-${p(d.getUTCHours())}${p(d.getUTCMinutes())}${p(d.getUTCSeconds())}`;
  return `${stamp}-${randomBytes(3).toString('hex')}`;
}

/** NODE_OPTIONS with our preload appended once; existing options are preserved. */
/**
 * Windows cannot CreateProcess a `.cmd`/`.bat` shim (npm, npx, yarn...), and since CVE-2024-27980 Node
 * refuses to spawn them without a shell. Resolve the command via PATH/PATHEXT; only for a batch file do
 * we go through cmd.exe, with every argument escaped so the user's argv is passed through verbatim.
 * Everything else (real executables, POSIX) is spawned directly with no shell.
 */
export function resolveWinCommand(file: string, env: NodeJS.ProcessEnv, cwd = process.cwd()): string | undefined {
  const exts = (env.PATHEXT || '.COM;.EXE;.BAT;.CMD').split(';').filter(Boolean);
  const hasExt = exts.some((e) => file.toLowerCase().endsWith(e.toLowerCase()));
  const names = hasExt ? [file, ...exts.map((e) => file + e)] : [...exts.map((e) => file + e), file];
  const dirs = /[\\/]/.test(file) ? [''] : [cwd, ...(env.Path ?? env.PATH ?? '').split(';').filter(Boolean)];
  for (const d of dirs) {
    for (const n of names) {
      const full = d ? path.join(d, n) : n;
      try {
        if (fs.statSync(full).isFile()) return full;
      } catch {
        /* keep looking */
      }
    }
  }
  return undefined;
}

const CMD_META = /([()%!^"<>&|;, ])/g;
export function escapeCmdArg(arg: string): string {
  const q = '"' + arg.replace(/(\\*)"/g, '$1$1\\"').replace(/(\\*)$/, '$1$1') + '"';
  return q.replace(CMD_META, '^$1');
}

function spawnCommand(file: string, args: string[], env: NodeJS.ProcessEnv): ChildProcess {
  if (process.platform === 'win32') {
    const full = resolveWinCommand(file, env);
    if (full && /\.(?:cmd|bat)$/i.test(full)) {
      const line = [escapeCmdArg(full), ...args.map(escapeCmdArg)].join(' ');
      return spawn(line, [], { stdio: 'inherit', env, shell: true });
    }
  }
  return spawn(file, args, { stdio: 'inherit', env });
}

export function buildNodeOptions(existing: string | undefined, preloadUrl: string): string {
  if (existing && existing.includes(preloadUrl)) return existing;
  return [existing, `--import ${preloadUrl}`].filter(Boolean).join(' ');
}

const errOut = (s: string) => process.stderr.write(s);
const termWidth = (): number => Math.max(40, Math.min(process.stderr.columns || 80, 80));
const errStyle = (noColor = false): Style => createStyle(detectColor({ noColor, stream: process.stderr }));
const outStyle = (noColor = false): Style => createStyle(detectColor({ noColor, stream: process.stdout }));

function usageError(cmd: string, msg: string): number {
  errOut(`tattle ${cmd}: ${msg}\n\n${HELP[cmd] ?? USAGE}`);
  return 2;
}

// ---- run ----------------------------------------------------------------------------------------

const RUN_SPEC: Spec = {
  stopAtPositional: true,
  bool: {
    '-q': 'quiet',
    '--quiet': 'quiet',
    '--json': 'json',
    '--watch': 'watch',
    '--no-card': 'noCard',
    '--no-color': 'noColor',
    '--include-local': 'includeLocal', // hidden: analyse localhost as unclassified (fixtures/tests)
    '-h': 'help',
    '--help': 'help',
  },
  value: { '--out': 'out' },
};

async function run(argv: string[]): Promise<number> {
  const p = parseFlags(argv, RUN_SPEC);
  if (p.flags.help) {
    process.stdout.write(HELP.run!);
    return 0;
  }
  if (p.error) return usageError('run', p.error);
  if (p.rest.length === 0) return usageError('run', 'no command given');
  const cmd = p.rest;
  const f = p.flags;
  const quiet = !!f.quiet;
  const json = !!f.json;
  const style = errStyle(!!f.noColor);
  const unicode = supportsUnicode();

  const runId = newRunId();
  let logPath = process.env.TATTLE_LOG;
  // Receipt dir we created ourselves (vs. a caller-supplied TATTLE_LOG); removed if the spawn fails.
  let ownedDir: string | undefined;
  if (!logPath) {
    const dir = path.join(tattleHome(), 'receipts', runId);
    ownedDir = dir;
    fs.mkdirSync(dir, { recursive: true });
    logPath = path.join(dir, 'events.jsonl');
  } else {
    fs.mkdirSync(path.dirname(logPath), { recursive: true });
  }
  fs.writeFileSync(logPath, '', { flag: 'a' });
  const eventsPath = logPath;

  const preloadUrl = pathToFileURL(path.join(path.dirname(fileURLToPath(import.meta.url)), 'preload.js')).href;
  const env = {
    ...process.env,
    TATTLE_LOG: logPath,
    TATTLE_RUN_ID: runId,
    NODE_OPTIONS: buildNodeOptions(process.env.NODE_OPTIONS, preloadUrl),
  };

  const ticker: Ticker | undefined = f.watch ? startTicker(eventsPath, errOut, style, termWidth(), unicode) : undefined;
  const [file, ...rest] = cmd;
  const startMs = Date.now();
  let childPid: number | undefined;

  const { exitCode, spawnFailed } = await new Promise<{ exitCode: number; spawnFailed: boolean }>((resolve) => {
    const child = spawnCommand(file!, rest, env);
    childPid = child.pid;
    const forward = (sig: NodeJS.Signals) => () => {
      try {
        child.kill(sig);
      } catch {
        /* already gone */
      }
    };
    const handlers: Array<[NodeJS.Signals, () => void]> = (['SIGINT', 'SIGTERM', 'SIGHUP'] as NodeJS.Signals[]).map((s) => [s, forward(s)]);
    for (const [s, h] of handlers) process.on(s, h);
    child.on('error', (err: NodeJS.ErrnoException) => {
      errOut(`tattle: cannot run ${file}: ${err.code === 'ENOENT' ? 'command not found' : err.message}\n`);
      resolve({ exitCode: 127, spawnFailed: true });
    });
    child.on('close', (code, signal) => {
      for (const [s, h] of handlers) process.off(s, h);
      resolve({ exitCode: code !== null ? code : 128 + (signal ? (os.constants.signals[signal] ?? 0) : 0), spawnFailed: false });
    });
  });
  ticker?.stop();
  if (spawnFailed) {
    // Nothing ran, so there is nothing to attest: don't leave an orphan receipt dir behind.
    if (ownedDir) fs.rmSync(ownedDir, { recursive: true, force: true });
    return exitCode;
  }

  try {
    const events = readEventLog(eventsPath);
    const analysis = analyze(events, { includeLocal: !!f.includeLocal }, { pid: childPid, argv0: file });
    const receiptDir = path.dirname(eventsPath);
    const body = buildReceiptBody({ argv: cmd, start: startMs, end: Date.now(), exitCode, eventsFile: path.basename(eventsPath), analysis, version: pkgVersion() });
    const key = loadOrCreateKey(tattleHome());
    const signed = signReceipt(body, await sha256File(eventsPath), key);
    const text = JSON.stringify(signed, null, 2) + '\n';
    fs.writeFileSync(path.join(receiptDir, 'receipt.json'), text);
    if (typeof f.out === 'string') {
      fs.mkdirSync(path.dirname(path.resolve(f.out)), { recursive: true });
      fs.writeFileSync(f.out, text);
    }
    let cardPath: string | undefined;
    if (!f.noCard) {
      try {
        cardPath = (await writeCard(receiptDir, { analysis, id: signed.id, timestamp: body.meta.endedAt, argv: cmd })).svg;
      } catch (e) {
        errOut(`tattle: card failed: ${(e as Error).message}\n`);
      }
    }
    if (json) process.stdout.write(text);
    else if (quiet) errOut(verdictLine(analysis, signed.id, style) + '\n');
    else errOut(renderSummary(analysis, { style, unicode, width: termWidth(), receiptId: signed.id, receiptDir, cardPath }) + '\n');
  } catch (err) {
    errOut(`tattle: analysis failed: ${(err as Error).message}\n`);
  }
  return exitCode;
}

// ---- verify / key / show / list / diff ----------------------------------------------------------

async function cmdVerify(argv: string[]): Promise<number> {
  const p = parseFlags(argv, { bool: { '--json': 'json', '--strict': 'strict', '-h': 'help', '--help': 'help' }, value: { '--trust': 'trust' } });
  if (p.flags.help) return process.stdout.write(HELP.verify!), 0;
  if (p.error) return usageError('verify', p.error);
  if (p.rest.length !== 1) return usageError('verify', 'expected exactly one receipt (path, dir or id)');
  let loaded;
  try {
    loaded = resolveReceipt(p.rest[0]!);
  } catch (e) {
    errOut(`tattle verify: ${(e as Error).message}\n`);
    return 1;
  }
  const { receipt, dir } = loaded;
  const evName = path.basename(String((receipt as any)?.body?.meta?.eventsFile ?? 'events.jsonl'));
  const trust = asList(p.flags.trust);
  const evPath = path.join(dir, evName);
  const haveEvents = fs.existsSync(evPath);
  const res = await verifyReceipt(receipt, { eventsPath: haveEvents ? evPath : undefined, trustedFingerprints: trust.length ? trust : undefined });
  const fp = (receipt as any)?.signature?.fingerprint as string | undefined;
  if (p.flags.strict && !haveEvents) {
    res.ok = false;
    res.errors.push(`--strict: ${evName} not found next to the receipt, so the events hash could not be checked`);
  }
  if (p.flags.json) {
    process.stdout.write(JSON.stringify({ id: receipt.id, signer: fp, strict: !!p.flags.strict, ...res }, null, 2) + '\n');
    return res.ok ? 0 : 1;
  }
  const st = outStyle();
  const mark = (ok: boolean, label: string) => `  ${ok ? st.green('ok  ') : st.red('FAIL')} ${label}`;
  const out = [`tattle verify ${receipt.id}: ${res.ok ? st.green('OK') : st.red('FAILED')}`];
  out.push(mark(res.checks.signature, 'ed25519 signature'));
  out.push(mark(res.checks.idMatches, 'receipt id matches body'));
  if (!haveEvents) out.push(p.flags.strict ? `  ${st.red('FAIL')} ${evName} not found: events hash not checked (--strict)` : `  info ${evName} not found next to the receipt: events hash NOT checked (use --strict to fail on this)`);
  if (res.checks.eventsHash !== undefined) out.push(mark(res.checks.eventsHash === 'match', `events hash ${res.checks.eventsHash} (${evName})`));
  if (res.checks.trusted !== undefined) out.push(mark(res.checks.trusted, `signer ${fp ?? '?'} ${res.checks.trusted ? 'is trusted' : 'is NOT in --trust list'}`));
  else out.push(`  info signer ${fp ?? '?'} (not pinned; use --trust <fingerprint>)`);
  for (const e of res.errors) out.push(`  ${st.red('!')} ${e}`);
  process.stdout.write(out.join('\n') + '\n');
  return res.ok ? 0 : 1;
}

function cmdKey(argv: string[]): number {
  if (argv.includes('-h') || argv.includes('--help')) return process.stdout.write(HELP.key!), 0;
  if (argv.length) return usageError('key', `unexpected argument: ${argv[0]}`);
  const home = tattleHome();
  const key = loadOrCreateKey(home);
  process.stdout.write(`fingerprint: ${key.fingerprint}\npublic key:  ${path.join(home, 'key.pub')}\n`);
  return 0;
}

async function cmdShow(argv: string[]): Promise<number> {
  const p = parseFlags(argv, { bool: { '--card': 'card', '--json': 'json', '--no-color': 'noColor', '-h': 'help', '--help': 'help' } });
  if (p.flags.help) return process.stdout.write(HELP.show!), 0;
  if (p.error) return usageError('show', p.error);
  if (p.rest.length > 1) return usageError('show', 'expected at most one receipt');
  let loaded;
  try {
    loaded = resolveReceipt(p.rest[0] ?? 'latest');
  } catch (e) {
    errOut(`tattle show: ${(e as Error).message}\n`);
    return 1;
  }
  const { receipt, dir, file } = loaded;
  if (p.flags.json) {
    process.stdout.write(fs.readFileSync(file, 'utf8'));
    return 0;
  }
  let cardPath: string | undefined;
  if (p.flags.card) cardPath = (await writeCard(dir, { analysis: receipt.body.analysis, id: receipt.id, timestamp: receipt.body.meta.endedAt, argv: receipt.body.meta.tool.argv })).svg;
  const st = outStyle(!!p.flags.noColor);
  const v = await verifyReceipt(receipt, { eventsPath: path.join(dir, path.basename(receipt.body.meta.eventsFile ?? 'events.jsonl')) });
  const head = `${receipt.id}  ${receipt.body.meta.startedAt}  $ ${receipt.body.meta.tool.argv.join(' ')}`;
  process.stdout.write(
    st.bold(truncate(head, 100)) + '\n' +
      renderSummary(receipt.body.analysis, { style: st, unicode: supportsUnicode(), width: Math.max(40, Math.min(process.stdout.columns || 80, 80)), receiptId: receipt.id, receiptDir: dir, cardPath }) + '\n' +
      (v.ok ? st.dim('signature and events hash verified') : st.red(`WARNING: receipt does not verify (${v.errors.join('; ')}); run tattle verify`)) + '\n',
  );
  return 0;
}

function cmdList(argv: string[]): number {
  const p = parseFlags(argv, { bool: { '--json': 'json', '--no-color': 'noColor', '-h': 'help', '--help': 'help' } });
  if (p.flags.help) return process.stdout.write(HELP.list!), 0;
  if (p.error || p.rest.length) return usageError('list', p.error ?? `unexpected argument: ${p.rest[0]}`);
  const all = listReceipts();
  const rows = all.map((l) => ({ id: l.receipt.id, date: l.receipt.body.meta.startedAt, verdict: l.receipt.body.analysis.verdict, argv: l.receipt.body.meta.tool.argv, dir: l.dir }));
  if (p.flags.json) {
    process.stdout.write(JSON.stringify(rows, null, 2) + '\n');
    return 0;
  }
  if (!rows.length) {
    process.stdout.write('no receipts yet. Try: tattle run -- <command>\n');
    return 0;
  }
  const st = outStyle(!!p.flags.noColor);
  const cols = process.stdout.columns || 100;
  for (const r of rows) {
    const date = r.date.slice(0, 16).replace('T', ' ');
    const verdict = r.verdict.padEnd(15);
    const argvRoom = Math.max(10, cols - (r.id.length + date.length + 15 + 6));
    process.stdout.write(`${r.id}  ${st.dim(date)}  ${st.verdict(r.verdict, verdict)}  ${truncate(r.argv.join(' '), argvRoom)}\n`);
  }
  return 0;
}

function cmdDiff(argv: string[]): number {
  const p = parseFlags(argv, { bool: { '--json': 'json', '--fail-on-new': 'failOnNew', '--no-color': 'noColor', '-h': 'help', '--help': 'help' } });
  if (p.flags.help) return process.stdout.write(HELP.diff!), 0;
  if (p.error) return usageError('diff', p.error);
  if (p.rest.length !== 2) return usageError('diff', 'expected two receipts: tattle diff <a> <b>');
  let A, B;
  try {
    A = resolveReceipt(p.rest[0]!);
    B = resolveReceipt(p.rest[1]!);
  } catch (e) {
    errOut(`tattle diff: ${(e as Error).message}\n`);
    return 1;
  }
  const d = diffReceipts(A.receipt.body, B.receipt.body);
  const code = p.flags.failOnNew && d.hasNew ? 1 : 0;
  if (p.flags.json) {
    const { a: va, b: vb, ...restD } = d;
    process.stdout.write(JSON.stringify({ a: { id: A.receipt.id, ...va }, b: { id: B.receipt.id, ...vb }, ...restD }, null, 2) + '\n');
    return code;
  }
  const st = outStyle(!!p.flags.noColor);
  const o: string[] = [`tattle diff ${A.receipt.id} -> ${B.receipt.id}`];
  o.push(`  tool a: ${A.receipt.body.meta.tool.argv.join(' ')}`, `  tool b: ${B.receipt.body.meta.tool.argv.join(' ')}`);
  o.push(d.verdictChanged ? `  verdict: ${d.a.verdict} -> ${st.verdict(d.b.verdict, d.b.verdict)}${d.a.verdict === 'NOT OBSERVED' || d.b.verdict === 'NOT OBSERVED' ? '' : d.worse ? st.red(' (worse)') : st.green(' (better)')}` : `  verdict: ${d.b.verdict} (unchanged)`);
  const sect = (label: string, c: { added: string[]; removed: string[] }) => {
    if (!c.added.length && !c.removed.length) return o.push(`  ${label}: no change`);
    o.push(`  ${label}:`);
    for (const x of c.added) o.push(st.red(`    + ${x}`));
    for (const x of c.removed) o.push(st.green(`    - ${x}`));
  };
  sect('hosts', d.hosts);
  sect('sensitive rules', d.sensitive);
  sect('process argv0', d.procs);
  const sgn = (n: number) => (n >= 0 ? '+' : '-') + formatBytes(Math.abs(n));
  if (d.bytes.length) {
    o.push('  bytes per host (b - a):');
    for (const b of d.bytes) o.push(`    ${b.host}  up ${sgn(b.up)}  down ${sgn(b.down)}`);
  } else o.push('  bytes per host: no change');
  process.stdout.write(o.join('\n') + '\n');
  return code;
}

// ---- main ---------------------------------------------------------------------------------------

async function main(argv: string[]): Promise<number> {
  const [sub, ...rest] = argv;
  if (!sub || sub === '-h' || sub === '--help' || sub === 'help') {
    const topic = sub === 'help' ? rest[0] : undefined;
    process.stdout.write(topic && HELP[topic] ? HELP[topic]! : USAGE);
    return sub ? 0 : 1;
  }
  if (sub === '-v' || sub === '--version' || sub === 'version') {
    process.stdout.write(pkgVersion() + '\n');
    return 0;
  }
  switch (sub) {
    case 'run':
      return run(rest);
    case 'verify':
      return cmdVerify(rest);
    case 'key':
      return cmdKey(rest);
    case 'show':
      return cmdShow(rest);
    case 'list':
    case 'ls':
      return cmdList(rest);
    case 'diff':
      return cmdDiff(rest);
    case 'install':
      errOut('tattle install: planned (Phase 6): running `npm install` under Tattle hooks is not implemented yet.\n');
      return 2;
  }
  errOut(`tattle: unknown command: ${sub}\nRun \`tattle --help\` for the list of commands.\n`);
  return 2;
}

main(process.argv.slice(2)).then(
  (code) => {
    process.exitCode = code;
  },
  (err) => {
    process.stderr.write(`tattle: ${(err as Error).message}\n`);
    process.exitCode = 1;
  },
);
