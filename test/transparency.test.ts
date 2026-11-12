/**
 * Transparency suite: every probe under fixtures/compat runs twice (plain node, and with the Tattle
 * preload) and must produce byte-identical stdout and the same exit code. A hook that changes what
 * the observed program can see is a ship-blocker, however good the event log is.
 */
import { spawnSync } from 'node:child_process';
import fs from 'node:fs';
import path from 'node:path';
import { pathToFileURL } from 'node:url';
import { describe, expect, it } from 'vitest';
import { ensureBuilt, ROOT, tmpDir } from './helpers.js';

ensureBuilt();
const dir = path.join(ROOT, 'fixtures', 'compat');
const preload = pathToFileURL(path.join(ROOT, 'dist', 'preload.js')).href;

interface Res { code: number | null; signal: string | null; stdout: string; stderr: string }

/**
 * Some Node versions (e.g. 18.19) change observable state merely because ANY `--import` preload is
 * present: core registers its own `handleProcessExit` 'exit' listener. That is Node's doing, not a
 * Tattle hook's (documented in ADR-001). Detect it at runtime (not by version string) and, when present,
 * compare against an *empty* `--import` baseline so the suite still isolates exactly what Tattle's hooks change.
 */
const emptyPreload = path.join(tmpDir('tattle-tp-empty-'), 'empty.mjs');
fs.writeFileSync(emptyPreload, '');
const probeExitListeners = (opts: string | undefined) => {
  const env: NodeJS.ProcessEnv = { ...process.env };
  delete env.NODE_OPTIONS;
  if (opts) env.NODE_OPTIONS = opts;
  return spawnSync(process.execPath, ['-e', 'console.log(process.listenerCount("exit"))'], { env, encoding: 'utf8' }).stdout.trim();
};
const emptyImportOpts = `--import ${pathToFileURL(emptyPreload).href}`;
const nodePerturbsWithImport = probeExitListeners(undefined) !== probeExitListeners(emptyImportOpts);

function run(file: string, hooked: boolean, work: string, extraEnv: Record<string, string> = {}): Res {
  const env: NodeJS.ProcessEnv = { ...process.env, ...extraEnv };
  delete env.NODE_OPTIONS;
  delete env.TATTLE_LOG;
  if (hooked) {
    env.NODE_OPTIONS = `--import ${preload}`;
    env.TATTLE_LOG = path.join(tmpDir('tattle-tp-'), 'events.jsonl');
  } else if (nodePerturbsWithImport) {
    env.NODE_OPTIONS = emptyImportOpts;
  }
  const r = spawnSync(process.execPath, [file, work], { env, encoding: 'utf8', timeout: 60_000 });
  return { code: r.status, signal: r.signal, stdout: r.stdout, stderr: r.stderr };
}

/** Scratch dirs differ between runs; scrub them (and pids) so only semantics are compared. */
const scrub = (s: string, w: string) => s.split(w).join('<W>');

// proc-full.cjs drives POSIX shell builtins and tools (echo a; exit 5, pwd, cat, printf, /bin/echo, $((..))),
// which cmd.exe cannot run: the probe itself is POSIX-only. Child-process transparency on Windows is covered
// by the cli/hooks tests that spawn node children.
const POSIX_ONLY = new Set(['proc-full.cjs']);
const probes = fs
  .readdirSync(dir)
  .filter((f) => /\.(cjs|mjs)$/.test(f) && !f.startsWith('_') && !f.startsWith('perf-'))
  .filter((f) => !(process.platform === 'win32' && POSIX_ONLY.has(f)))
  .sort();

describe('transparency: hooked output === unhooked output', () => {
  for (const p of probes) {
    it(p, () => {
      const file = path.join(dir, p);
      const w1 = tmpDir('tattle-w-');
      const w2 = tmpDir('tattle-w-');
      const plain = run(file, false, w1);
      const hooked = run(file, true, w2);
      expect(plain.stdout.length, `probe ${p} printed nothing unhooked: ${plain.stderr}`).toBeGreaterThan(0);
      expect(scrub(hooked.stdout, w2)).toBe(scrub(plain.stdout, w1));
      expect(hooked.code).toBe(plain.code);
      expect(hooked.signal).toBe(plain.signal);
      // stderr: only compare for the lifecycle probes' first line shape (stack frames legitimately differ)
      if (p.startsWith('life-unhandled') || p.startsWith('life-uncaught')) {
        expect(hooked.stderr.includes('Error')).toBe(plain.stderr.includes('Error'));
      }
    });
  }

  it('probes actually exercised something (guard against silently-empty probes)', () => {
    const w = tmpDir('tattle-w-');
    const r = run(path.join(dir, 'fs-full.cjs'), false, w);
    expect(r.stdout).toContain('readFileSync-ENOENT:');
    expect(r.stdout).not.toMatch(/THROW (ERR_INVALID_ARG_TYPE|TypeError) .*is not a function/);
  });

  it('hooks are really active in the hooked runs (events were written)', () => {
    const w = tmpDir('tattle-w-');
    const log = path.join(tmpDir('tattle-tp-'), 'events.jsonl');
    const env = { ...process.env, NODE_OPTIONS: `--import ${preload}`, TATTLE_LOG: log };
    spawnSync(process.execPath, [path.join(dir, 'fs-full.cjs'), w], { env, encoding: 'utf8' });
    const text = fs.readFileSync(log, 'utf8');
    expect(text).toContain('"cat":"fs"');
    expect(text).toContain('"op":"exit"');
  });
});

describe('exit lifecycle recording', () => {
  const evs = (f: string, args: string[] = []) => {
    const log = path.join(tmpDir('tattle-tp-'), 'events.jsonl');
    const r = spawnSync(process.execPath, [path.join(dir, f), ...args], { env: { ...process.env, NODE_OPTIONS: `--import ${preload}`, TATTLE_LOG: log }, encoding: 'utf8' });
    return { r, events: fs.readFileSync(log, 'utf8').trim().split('\n').map((l) => JSON.parse(l)) };
  };
  it('fs activity inside user exit handlers is still recorded, and life/exit carries the FINAL exit code', () => {
    const { events } = evs('life-exit-order.cjs', [tmpDir()]);
    const exit = events.find((e) => e.cat === 'life' && e.op === 'exit');
    expect(exit?.detail.code).toBe(9); // set by the user's exit handler
    const lastRead = events.map((e, i) => [e, i] as const).filter(([e]) => e.cat === 'fs' && e.op === 'read' && e.target.endsWith('x.txt'));
    expect(lastRead.length).toBeGreaterThan(0);
    expect(events.indexOf(exit)).toBeGreaterThan(lastRead[lastRead.length - 1]![1]);
  });
  it('process.exit(n) and uncaught exceptions still produce life/exit', () => {
    expect(evs('life-exit-call.cjs').events.find((e) => e.op === 'exit')?.detail.code).toBe(3);
    expect(evs('life-uncaught-nohandler.cjs').events.find((e) => e.op === 'exit')?.detail.code).toBe(1);
  });
});

describe('socket ids across worker threads', () => {
  it('main thread and worker connections get distinct sids (same pid)', async () => {
    const { startTcp, runTattle } = await import('./helpers.js');
    const srv = await startTcp();
    try {
      const code = `const net=require('net');const {Worker,isMainThread}=require('worker_threads');
      const go=(cb)=>{const s=net.connect(${srv.port},'127.0.0.1',()=>{s.end('x');});s.on('close',cb);};
      if(isMainThread){const w=new Worker(__filename);w.on('exit',()=>go(()=>{}));}else go(()=>{});`;
      const f = path.join(tmpDir(), 'w.cjs');
      fs.writeFileSync(f, code);
      const r = await runTattle(['node', f]);
      const closes = r.events.filter((e) => e.cat === 'net' && e.op === 'close');
      expect(closes).toHaveLength(2);
      expect(new Set(closes.map((e) => (e.detail as any).sid)).size).toBe(2);
    } finally {
      await srv.close();
    }
  });
});

describe('performance under hooks', () => {
  it('20k statSync calls stay within a sane factor of unhooked', () => {
    const file = path.join(dir, 'perf-stat.cjs');
    const ms = (r: Res) => Number(/PERF_MS ([\d.]+)/.exec(r.stderr)?.[1]);
    const best = (hooked: boolean) => Math.min(...[0, 1, 2].map(() => ms(run(file, hooked, tmpDir()))));
    const plain = best(false);
    const hooked = best(true);
    const factor = hooked / Math.max(plain, 1);
    console.log(`perf: unhooked ${plain.toFixed(0)}ms hooked ${hooked.toFixed(0)}ms factor ${factor.toFixed(1)}x`);
    expect(hooked).toBeLessThan(Math.max(plain * 8, 1500));
  });
});
