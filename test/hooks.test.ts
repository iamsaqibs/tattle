/** Focused per-API hook checks using inline scripts run through the real built CLI. */
import dgram from 'node:dgram';
import fs from 'node:fs';
import path from 'node:path';
import { beforeAll, describe, expect, it } from 'vitest';
import { ensureBuilt, runTattle, tmpDir, type RunResult } from './helpers.js';

beforeAll(ensureBuilt);
const runEsm = (code: string, env: Record<string, string | undefined> = {}): Promise<RunResult> => runTattle(['node', '--input-type=module', '-e', code], env);
const runCjs = (code: string, env: Record<string, string | undefined> = {}): Promise<RunResult> => runTattle(['node', '-e', code], env);
const only = (r: RunResult, cat: string) => r.events.filter((e) => e.cat === cat);

describe('fs hooks', () => {
  it('callback, promises (named ESM import) and stream APIs each yield exactly one event', async () => {
    const dir = tmpDir();
    const f = path.join(dir, 'data.txt');
    fs.writeFileSync(f, '0123456789');
    const code = `
      import { readFile as pReadFile, writeFile as pWriteFile } from 'node:fs/promises';
      import { readFile, createReadStream, createWriteStream } from 'node:fs';
      await new Promise((r) => readFile(${JSON.stringify(f)}, r));
      await pReadFile(${JSON.stringify(f)});
      await pWriteFile(${JSON.stringify(path.join(dir, 'out.txt'))}, 'abc');
      await new Promise((r) => createReadStream(${JSON.stringify(f)}).on('close', r).resume());
      await new Promise((r) => createWriteStream(${JSON.stringify(path.join(dir, 'ws.txt'))}).on('close', r).end('hello'));
      await pReadFile(${JSON.stringify(path.join(dir, 'missing.txt'))}).catch((e) => console.log(e.code));
    `;
    const r = await runEsm(code);
    expect(r.stdout.trim()).toBe('ENOENT'); // semantics preserved: rejection still reaches the caller
    const evs = only(r, 'fs').map((e) => `${e.op} ${path.basename(e.target)} ${e.bytes ?? '-'} ${(e.detail as any).via}${(e.detail as any).error ? ' ' + (e.detail as any).error : ''}`);
    expect(evs).toEqual([
      'read data.txt 10 readFile',
      'read data.txt 10 promises.readFile',
      'write out.txt 3 promises.writeFile',
      'read data.txt 10 createReadStream',
      'write ws.txt 5 createWriteStream',
      'read missing.txt - promises.readFile ENOENT',
    ].map((s) => s));
  });

  it('does not tag .env.example or ordinary files, and elides node_modules reads', async () => {
    const dir = tmpDir();
    fs.writeFileSync(path.join(dir, '.env.example'), 'A=');
    fs.mkdirSync(path.join(dir, 'node_modules', 'x'), { recursive: true });
    fs.writeFileSync(path.join(dir, 'node_modules', 'x', 'index.txt'), 'x');
    const r = await runCjs(`const fs=require('fs');fs.readFileSync(${JSON.stringify(path.join(dir, '.env.example'))});fs.readFileSync(${JSON.stringify(path.join(dir, 'node_modules/x/index.txt'))})`);
    const reads = only(r, 'fs');
    expect(reads).toHaveLength(1);
    expect(reads[0]!.verdictHint).toBeUndefined();
    expect(r.events.find((e) => e.op === 'exit')!.detail).toMatchObject({ elidedFs: expect.any(Number) });
    expect((r.events.find((e) => e.op === 'exit')!.detail as any).elidedFs).toBeGreaterThanOrEqual(1);
  });
});

describe('network hooks', () => {
  it('dgram.send and dns.promises.lookup', async () => {
    const sock = dgram.createSocket('udp4');
    await new Promise<void>((r) => sock.bind(0, '127.0.0.1', r));
    const port = sock.address().port;
    const r = await runCjs(`
      const dgram = require('dgram'); const dns = require('dns');
      const s = dgram.createSocket('udp4');
      s.send('hello', ${port}, '127.0.0.1', () => { s.close(); dns.promises.lookup('localhost').then(() => {}); });
    `);
    sock.close();
    const dg = r.events.find((e) => e.op === 'dgram.send')!;
    expect(dg).toMatchObject({ cat: 'net', target: `udp:127.0.0.1:${port}`, bytes: 5 });
    expect(only(r, 'dns').map((e) => [e.op, e.target, (e.detail as any)?.promises])).toEqual([['lookup', 'localhost', true]]);
  });
});

describe('process hooks', () => {
  it.skipIf(process.platform === 'win32')('exec of a shell line yields one proc event and flags clipboard readers / escapes', async () => {
    const r = await runCjs(`
      const cp = require('child_process');
      cp.exec('xclip -o', () => {
        cp.execFile('wget', ['--version'], () => {
          cp.spawnSync('sh', ['-c', 'echo hi | nc -h']);
          try { cp.execSync('powershell -c Get-Clipboard', { stdio: 'ignore' }); } catch {}
        });
      });
    `);
    const procs = only(r, 'proc').map((e) => [e.op, e.target, (e.detail as any).argv, (e.detail as any).clipboard, (e.detail as any).networkEscape]);
    expect(procs).toEqual([
      ['exec', 'sh', ['xclip -o'], 'xclip', undefined],
      ['execFile', 'wget', ['wget', '--version'], undefined, true],
      ['spawnSync', 'sh', ['sh', '-c', 'echo hi | nc -h'], undefined, true],
      ['execSync', 'sh', ['powershell -c Get-Clipboard'], 'Get-Clipboard', undefined],
    ]);
    expect(only(r, 'clip').map((e) => e.target)).toEqual(['xclip', 'Get-Clipboard']);
  });

  it('never records env: spawn options.env values are absent from the log', async () => {
    const r = await runCjs(`require('child_process').spawnSync(process.execPath, ['-e', '0'], { env: { PATH: process.env.PATH, VERY_SECRET: 'topsecret' + 'value123' } })`);
    expect(r.logText).not.toContain('topsecretvalue123');
  });
});

describe('env hooks', () => {
  it('records names once, handles `in`, and collapses enumeration into one event', async () => {
    const r = await runCjs(`
      const a = process.env.ALPHA; const b = process.env.ALPHA; 'BETA' in process.env;
      const copy = { ...process.env }; const keys = Object.keys(process.env);
      process.env.GAMMA = 'set-not-read';
    `, { ALPHA: 'a-value-xyz' });
    const env = only(r, 'env');
    expect(env.filter((e) => e.op === 'read').map((e) => e.target)).toEqual(['ALPHA', 'BETA']);
    expect(env.filter((e) => e.op === 'enumerate')).toHaveLength(1);
    expect(r.logText).not.toContain('a-value-xyz');
    expect(env.some((e) => e.op === 'cwd')).toBe(false);
  });
});

describe('regression: hooks must not change semantics (npm breakage)', () => {
  const fixture = path.join(path.resolve(path.dirname(new URL(import.meta.url).pathname), '..'), 'fixtures', 'compat', 'env-writes.cjs');
  it('process.env writes/defineProperty/delete behave identically hooked and unhooked', async () => {
    const { execFileSync } = await import('node:child_process');
    const base: NodeJS.ProcessEnv = { ...process.env };
    delete base.NODE_OPTIONS;
    delete base.TATTLE_LOG;
    const expected = execFileSync(process.execPath, [fixture], { env: base, encoding: 'utf8' });
    const r = await runTattle(['node', fixture]);
    expect(r.code).toBe(0);
    expect(r.stdout).toBe(expected);
    expect(expected).toContain('assign:"x"'); // sanity: the unhooked run really executed the writes
    expect(expected).toContain('defineProperty-partial:THROW ERR_INVALID_OBJECT_DEFINE_PROPERTY');
  });
  it('TATTLE_DISABLE skips the named hook groups', async () => {
    const r = await runTattle(['node', '-e', 'process.env.A_B=1;require("fs").readFileSync(__filename.replace(/.*/,process.execPath))'], { TATTLE_DISABLE: 'env,fs' });
    expect(r.events.filter((e) => e.cat === 'env' && e.op === 'read')).toHaveLength(0);
    expect(r.events.filter((e) => e.cat === 'fs')).toHaveLength(0);
  });
});
