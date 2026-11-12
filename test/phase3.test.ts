import { spawn } from 'node:child_process';
import fs from 'node:fs';
import path from 'node:path';
import { afterAll, beforeAll, describe, expect, it } from 'vitest';
import { analyze } from '../src/analyze/index.js';
import { renderCardSvg, xmlEscape } from '../src/render/card.js';
import { createStyle, detectColor, stripAnsi, supportsUnicode } from '../src/render/ansi.js';
import { diffReceipts } from '../src/diff.js';
import { CLI, ensureBuilt, ROOT, startHttp, startTcp, tmpDir, type Server } from './helpers.js';

beforeAll(ensureBuilt);

interface Out {
  code: number | null;
  stdout: string;
  stderr: string;
}
function cli(args: string[], env: Record<string, string | undefined> = {}): Promise<Out> {
  const full: NodeJS.ProcessEnv = { ...process.env, FORCE_COLOR: undefined, NO_COLOR: undefined, ...env };
  for (const k of Object.keys(full)) if (full[k] === undefined) delete full[k];
  return new Promise((resolve, reject) => {
    const c = spawn(process.execPath, [CLI, ...args], { env: full });
    let stdout = '';
    let stderr = '';
    c.stdout.on('data', (d) => (stdout += d));
    c.stderr.on('data', (d) => (stderr += d));
    c.on('error', reject);
    c.on('close', (code) => resolve({ code, stdout, stderr }));
  });
}

describe('ansi', () => {
  it('honors NO_COLOR, FORCE_COLOR, --no-color and TTY-ness', () => {
    const tty = { isTTY: true };
    expect(detectColor({ stream: tty, env: {} })).toBe(true);
    expect(detectColor({ stream: { isTTY: false }, env: {} })).toBe(false);
    expect(detectColor({ stream: tty, env: { NO_COLOR: '1' } })).toBe(false);
    expect(detectColor({ stream: tty, env: {}, noColor: true })).toBe(false);
    expect(detectColor({ stream: { isTTY: false }, env: { FORCE_COLOR: '1' } })).toBe(true);
    expect(detectColor({ stream: tty, env: { FORCE_COLOR: '0' } })).toBe(false);
    expect(detectColor({ stream: tty, env: { NO_COLOR: '1', FORCE_COLOR: '1' } })).toBe(false);
    expect(detectColor({ stream: tty, env: { TERM: 'dumb' } })).toBe(false);
  });
  it('emits escapes only when enabled', () => {
    expect(createStyle(false).red('x')).toBe('x');
    expect(createStyle(true).red('x')).toBe('\x1b[31mx\x1b[39m');
    expect(stripAnsi(createStyle(true).banner('ESCAPE CHAIN', ' A '))).toBe(' A ');
    expect(supportsUnicode({ LANG: 'en_US.UTF-8' }, 'linux')).toBe(true);
    expect(supportsUnicode({ LANG: 'C' }, 'linux')).toBe(false);
  });
});

describe('card svg', () => {
  it('NOT OBSERVED card is gray and carries the full message', () => {
    const svg = renderCardSvg({ analysis: analyze([]), id: 'tt_abc', timestamp: '2026-01-02T03:04:05.000Z', argv: ['/bin/echo', 'hi'] });
    expect(svg).toContain('NOT OBSERVED');
    expect(svg).toContain('#6e7681');
    expect(svg).toContain('native');
    expect(svg).not.toContain('Nothing suspicious');
  });

  const analysis = analyze([{ v: 1, ts: 1, pid: 1, ppid: 0, seq: 0, phase: 'run', cat: 'life', op: 'start', target: 'node' } as any]);
  it('is 1200x630, shows the verdict and escapes all text', () => {
    const svg = renderCardSvg({ analysis, id: 'tt_abc', timestamp: '2026-01-02T03:04:05.000Z', argv: ['node', '<evil>&"x".js'] });
    expect(svg).toMatch(/^<svg [^>]*width="1200" height="630"/);
    expect(svg).toContain('CLEAN');
    expect(svg).toContain('tattle verify tt_abc');
    expect(svg).toContain('nothing left this machine');
    expect(svg).toContain('&lt;evil&gt;&amp;');
    expect(svg).not.toContain('<evil>');
    expect(svg.trim().endsWith('</svg>')).toBe(true);
    // tiny well-formedness check: balanced non-self-closing tags
    const tags = [...svg.matchAll(/<(\/?)([a-zA-Z]+)[^>]*?(\/?)>/g)].filter((m) => !m[3]);
    const stack: string[] = [];
    for (const [, close, name] of tags) {
      if (close) expect(stack.pop()).toBe(name);
      else stack.push(name!);
    }
    expect(stack).toEqual([]);
  });
  it('xmlEscape handles specials and control chars', () => {
    expect(xmlEscape(`<a href="x">&'\u0001`)).toBe('&lt;a href=&quot;x&quot;&gt;&amp;&apos;?');
  });
});

describe('receipt workflow (signed receipts, verify, show, list, diff)', () => {
  let http: Server, tcp: Server;
  const home = tmpDir('tattle-p3home-');
  const user = tmpDir('tattle-p3user-');
  let guiltyDir: string;
  let cleanDir: string;
  let guiltyId: string;
  let cleanId: string;
  let guiltyRun: Out;

  beforeAll(async () => {
    http = await startHttp();
    tcp = await startTcp();
    fs.writeFileSync(path.join(user, '.env'), 'SECRET=1\n');
    guiltyRun = await cli(['run', '--include-local', '--', 'node', path.join(ROOT, 'fixtures/guilty/guilty.cjs')], {
      TATTLE_HOME: home,
      HOME: user,
      GUILTY_HOME: user,
      GUILTY_HTTP_PORT: String(http.port),
      GUILTY_TCP_PORT: String(tcp.port),
    });
    await new Promise((r) => setTimeout(r, 1100)); // distinct start times for ordering
    await cli(['run', '--', 'node', path.join(ROOT, 'fixtures/clean/clean.cjs')], { TATTLE_HOME: home, CLEAN_OUT: tmpDir() });
    const dirs = fs.readdirSync(path.join(home, 'receipts')).sort();
    expect(dirs).toHaveLength(2);
    guiltyDir = path.join(home, 'receipts', dirs[0]!);
    cleanDir = path.join(home, 'receipts', dirs[1]!);
    guiltyId = JSON.parse(fs.readFileSync(path.join(guiltyDir, 'receipt.json'), 'utf8')).id;
    cleanId = JSON.parse(fs.readFileSync(path.join(cleanDir, 'receipt.json'), 'utf8')).id;
  });
  afterAll(async () => {
    await http.close();
    await tcp.close();
  });
  const env = () => ({ TATTLE_HOME: home });

  it('run prints a consistent boxed summary with receipt id, verify hint, posture; writes card', () => {
    expect(guiltyRun.code).toBe(0);
    expect(guiltyRun.stderr).toContain('ESCAPE CHAIN');
    expect(guiltyRun.stderr).toContain(`tattle verify ${guiltyId}`);
    expect(guiltyRun.stderr).toContain('events captured in-process, nothing left this machine');
    expect(guiltyRun.stderr).not.toMatch(/\x1b\[/);
    expect(guiltyRun.stderr).not.toMatch(/\u{1F6A8}/u);
    // one event count only
    const counts = [...guiltyRun.stderr.matchAll(/(\d+) events/g)].map((m) => m[1]);
    expect(new Set(counts).size).toBe(1);
    const svg = fs.readFileSync(path.join(guiltyDir, 'card.svg'), 'utf8');
    expect(svg).toContain('ESCAPE CHAIN');
    expect(svg).toContain(guiltyId);
  });

  it('FORCE_COLOR adds ANSI, --no-color / NO_COLOR win', async () => {
    const node = ['node', '-e', '0'];
    const a = await cli(['run', '--', ...node], { ...env(), FORCE_COLOR: '1' });
    expect(a.stderr).toMatch(/\x1b\[/);
    const b = await cli(['run', '--no-color', '--', ...node], { ...env(), FORCE_COLOR: '1' });
    expect(b.stderr).not.toMatch(/\x1b\[/);
    const c = await cli(['run', '--', ...node], { ...env(), FORCE_COLOR: '1', NO_COLOR: '1' });
    expect(c.stderr).not.toMatch(/\x1b\[/);
  });

  it('--quiet prints only the verdict line; --json prints a parseable signed receipt on stdout', async () => {
    const q = await cli(['run', '-q', '--', 'node', '-e', '0'], env());
    expect(q.stderr.trim().split('\n')).toHaveLength(1);
    expect(q.stderr).toMatch(/^tattle: CLEAN \(tt_[0-9a-f]{12}\)$/m);
    const out = path.join(tmpDir(), 'r.json');
    const j = await cli(['run', '--json', '--out', out, '--', 'node', '-e', 'console.log("child")'], env());
    expect(j.stdout.startsWith('child\n')).toBe(true);
    const parsed = JSON.parse(j.stdout.slice('child\n'.length));
    expect(parsed.receiptVersion).toBe(1);
    expect(parsed.body.analysis.verdict).toBe('CLEAN');
    expect(JSON.parse(fs.readFileSync(out, 'utf8')).id).toBe(parsed.id);
    expect(j.stderr).toBe('');
    const v = await cli(['verify', out], env());
    expect(v.code).toBe(0);
    expect(v.stdout).toMatch(/NOT checked/);
    const strict = await cli(['verify', '--strict', out], env());
    expect(strict.code).toBe(1);
    expect(strict.stdout).toMatch(/FAILED/);
    expect(strict.stdout).toMatch(/--strict/);
    const sj = await cli(['verify', '--strict', '--json', out], env());
    expect(sj.code).toBe(1);
    expect(JSON.parse(sj.stdout)).toMatchObject({ ok: false, strict: true });
  });

  it('--watch prints one dimmed/plain line per event to stderr, leaving stdout clean', async () => {
    const r = await cli(['run', '--watch', '--', 'node', '-e', 'console.log("hi")'], env());
    expect(r.stdout).toBe('hi\n');
    expect(r.stderr).toMatch(/life\/start/);
    expect(r.stderr).toMatch(/life\/exit/);
    for (const line of r.stderr.split('\n').filter((l) => /^\d\d:\d\d:/.test(l))) expect(line.length).toBeLessThanOrEqual(80);
  });

  it('--no-card skips the card', async () => {
    const before = new Set(fs.readdirSync(path.join(home, 'receipts')));
    await cli(['run', '--no-card', '-q', '--', 'node', '-e', '0'], env());
    const added = fs.readdirSync(path.join(home, 'receipts')).filter((d) => !before.has(d));
    expect(added).toHaveLength(1);
    expect(fs.existsSync(path.join(home, 'receipts', added[0]!, 'card.svg'))).toBe(false);
    expect(fs.existsSync(path.join(home, 'receipts', added[0]!, 'receipt.json'))).toBe(true);
  });

  it('key prints fingerprint and public key path', async () => {
    const r = await cli(['key'], env());
    expect(r.code).toBe(0);
    expect(r.stdout).toMatch(/fingerprint: [0-9a-f]{16}/);
    expect(r.stdout).toContain(path.join(home, 'key.pub'));
  });

  it('verify: dir / file / id / prefix all resolve; --trust pins the signer', async () => {
    for (const ref of [guiltyDir, path.join(guiltyDir, 'receipt.json'), guiltyId, guiltyId.slice(0, 7)]) {
      const r = await cli(['verify', ref], env());
      expect(r.code, ref).toBe(0);
      expect(r.stdout).toContain('OK');
    }
    const fp = /fingerprint: (\w+)/.exec((await cli(['key'], env())).stdout)![1]!;
    expect((await cli(['verify', guiltyId, '--trust', fp], env())).code).toBe(0);
    const bad = await cli(['verify', guiltyId, '--trust', 'deadbeefdeadbeef'], env());
    expect(bad.code).toBe(1);
    expect(bad.stdout).toMatch(/NOT in --trust/);
    expect((await cli(['verify', 'tt_nonexistent'], env())).code).toBe(1);
  });

  it('verify detects tampering with the receipt body and with events.jsonl', async () => {
    const copy = tmpDir('tattle-tamper-');
    for (const f of ['receipt.json', 'events.jsonl']) fs.copyFileSync(path.join(guiltyDir, f), path.join(copy, f));
    expect((await cli(['verify', copy], env())).code).toBe(0);

    const r = JSON.parse(fs.readFileSync(path.join(copy, 'receipt.json'), 'utf8'));
    r.body.analysis.verdict = 'CLEAN';
    fs.writeFileSync(path.join(copy, 'receipt.json'), JSON.stringify(r));
    const t1 = await cli(['verify', copy], env());
    expect(t1.code).toBe(1);
    expect(t1.stdout).toMatch(/FAILED/);
    fs.copyFileSync(path.join(guiltyDir, 'receipt.json'), path.join(copy, 'receipt.json'));

    fs.appendFileSync(path.join(copy, 'events.jsonl'), '{"v":1,"ts":1,"cat":"fs","op":"read","target":"/x"}\n');
    const t2 = await cli(['verify', copy], env());
    expect(t2.code).toBe(1);
    expect(t2.stdout).toMatch(/events hash mismatch/);
  });

  it('list and show', async () => {
    const l = await cli(['list'], env());
    expect(l.stdout).toContain(guiltyId);
    expect(l.stdout).toContain('ESCAPE CHAIN');
    expect(l.stdout).toContain(cleanId);
    const lj = JSON.parse((await cli(['list', '--json'], env())).stdout);
    expect(lj.map((r: any) => r.id)).toContain(cleanId);
    expect(lj[0]).toHaveProperty('verdict');

    const s = await cli(['show', guiltyId.slice(0, 8)], env());
    expect(s.code).toBe(0);
    expect(s.stdout).toContain('ESCAPE CHAIN');
    expect(s.stdout).toContain('verified');
    const latest = await cli(['show', 'latest', '--json'], env());
    expect(JSON.parse(latest.stdout).id).toMatch(/^tt_/);

    fs.rmSync(path.join(cleanDir, 'card.svg'), { force: true });
    await cli(['show', cleanId, '--card'], env());
    expect(fs.readFileSync(path.join(cleanDir, 'card.svg'), 'utf8')).toContain('CLEAN');
  });

  it('diff: guilty vs clean, human + json + --fail-on-new', async () => {
    const d = await cli(['diff', cleanId, guiltyId], env());
    expect(d.code).toBe(0);
    expect(d.stdout).toMatch(/CLEAN -> ESCAPE CHAIN/);
    expect(d.stdout).toMatch(/\+ 127\.0\.0\.1/);
    expect(d.stdout).toMatch(/\+ dotenv/);
    const j = JSON.parse((await cli(['diff', '--json', cleanId, guiltyId], env())).stdout);
    expect(j.worse).toBe(true);
    expect(j.hosts.added).toContain('127.0.0.1');
    expect(j.sensitive.added).toContain('dotenv');
    expect(j.bytes[0].up).toBeGreaterThan(0);
    expect(j.a.id).toBe(cleanId);
    expect((await cli(['diff', '--fail-on-new', cleanId, guiltyId], env())).code).toBe(1);
    expect((await cli(['diff', '--fail-on-new', guiltyId, cleanId], env())).code).toBe(0);
    const rev = diffReceipts(JSON.parse(fs.readFileSync(path.join(guiltyDir, 'receipt.json'), 'utf8')).body, JSON.parse(fs.readFileSync(path.join(cleanDir, 'receipt.json'), 'utf8')).body);
    expect(rev.hosts.removed).toContain('127.0.0.1');
    expect(rev.hasNew).toBe(false);
  });

  it('help, version, usage errors', async () => {
    expect((await cli(['--help'])).stdout).toMatch(/tattle verify/);
    for (const c of ['run', 'verify', 'show', 'list', 'diff', 'key']) {
      const r = await cli([c, '--help']);
      expect(r.code, c).toBe(0);
      expect(r.stdout).toContain(`tattle ${c}`);
    }
    const v = await cli(['--version']);
    expect(v.stdout.trim()).toBe(JSON.parse(fs.readFileSync(path.join(ROOT, 'package.json'), 'utf8')).version);
    expect((await cli(['diff', 'onlyone'])).code).toBe(2);
    expect((await cli(['run', '--bogus', 'x'])).code).toBe(2);
  });
});
