/**
 * The fixture suite is the project's executable spec: each fixture is run through the REAL built
 * CLI (`node dist/cli.js run -- node fixtures/...`) against localhost servers, and the exact
 * event types/targets are asserted.
 */
import fs from 'node:fs';
import path from 'node:path';
import { afterAll, beforeAll, describe, expect, it } from 'vitest';
import { ensureBuilt, has, ROOT, runTattle, sigs, startHttp, startHttps, startTcp, tmpDir, type RunResult, type Server } from './helpers.js';

beforeAll(ensureBuilt);
const fx = (...p: string[]) => path.join(ROOT, 'fixtures', ...p);
const SECRETS = { OPENAI: 'sk-test-123', AWS: 'awssecret', DOTENV: 'SECRET_TOKEN=hunter2\n' };

// The guilty ESM fixture stubs pbpaste with a /bin/sh script and may use curl: POSIX only
describe.skipIf(process.platform === 'win32')('guilty fixture (ESM, named imports)', () => {
  let http: Server, tcp: Server, tls: Server | null;
  let home: string;
  let bin: string;
  let r: RunResult;
  const curl = has('curl') && process.platform !== 'win32';

  beforeAll(async () => {
    http = await startHttp();
    tcp = await startTcp();
    tls = await startHttps();
    home = tmpDir('tattle-home-');
    fs.mkdirSync(path.join(home, '.aws'));
    fs.mkdirSync(path.join(home, '.ssh'));
    fs.writeFileSync(path.join(home, '.env'), SECRETS.DOTENV);
    fs.writeFileSync(path.join(home, '.aws', 'credentials'), '[default]\naws_secret_access_key=zzz\n');
    fs.writeFileSync(path.join(home, '.ssh', 'id_rsa'), 'PRIVATE');
    fs.writeFileSync(path.join(home, '.npmrc'), 'token');
    // Deterministic clipboard reader stub, first on PATH (never touches the real clipboard)
    bin = path.join(home, 'bin');
    fs.mkdirSync(bin);
    fs.writeFileSync(path.join(bin, 'pbpaste'), '#!/bin/sh\necho clip\n', { mode: 0o755 });
    r = await runTattle(['node', fx('guilty', 'guilty.mjs')], {
      HOME: home,
      USERPROFILE: home,
      GUILTY_HOME: home,
      GUILTY_HTTP_PORT: String(http.port),
      GUILTY_TCP_PORT: String(tcp.port),
      GUILTY_HTTPS_PORT: tls ? String(tls.port) : undefined,
      GUILTY_CURL: curl ? '1' : undefined,
      PATH: bin + path.delimiter + process.env.PATH,
      OPENAI_API_KEY: SECRETS.OPENAI,
      AWS_SECRET_ACCESS_KEY: SECRETS.AWS,
    });
  });
  afterAll(async () => {
    await http?.close();
    await tcp?.close();
    await tls?.close();
  });

  const main = () => {
    const pid = r.events.find((e) => e.op === 'start' && String(e.target).endsWith('guilty.mjs'))!.pid;
    return r.events.filter((e) => e.pid === pid);
  };

  it('exits 0 and the tool still worked (hooks changed nothing)', () => {
    expect(r.code).toBe(0);
    expect(http.bodies[0]).toBe(SECRETS.DOTENV + SECRETS.OPENAI + SECRETS.AWS);
    expect(http.urls).toContain('POST /f?token=abc');
    expect(tcp.bodies).toEqual(['100']);
    if (tls) expect(tls.bodies).toEqual(['secure-body']);
    if (curl) expect(http.urls).toContain('POST /curl');
  });

  it('emits exactly the expected event types (main process, excluding env/life)', () => {
    const expected = ['clip/read', 'dns/lookup', 'fs/read', 'net/close', 'net/connect', 'net/fetch', 'net/http.request', 'proc/spawnSync'];
    if (tls) expected.push('net/tls.connect');
    const got = sigs(main().filter((e) => e.cat !== 'env' && e.cat !== 'life'));
    expect(got).toEqual(expected.sort());
  });

  it('classifies sensitive reads with rule ids and exact byte counts', () => {
    const reads = main().filter((e) => e.cat === 'fs' && e.op === 'read');
    expect(reads.map((e) => e.target)).toEqual([path.join(home, '.env'), path.join(home, '.aws', 'credentials')]);
    expect(reads.every((e) => e.verdictHint === 'sensitive')).toBe(true);
    expect(reads.map((e) => (e.detail as any).rule)).toEqual(['dotenv', 'aws-credentials']);
    expect(reads[0]!.bytes).toBe(Buffer.byteLength(SECRETS.DOTENV));
  });

  it('logs http, fetch, https and raw tcp with correct hosts, methods and counts', () => {
    const m = main();
    const connects = m.filter((e) => e.op === 'connect').map((e) => e.target);
    const expected = [`127.0.0.1:${http.port}`, `localhost:${http.port}`, `127.0.0.1:${tcp.port}`];
    if (tls) expected.push(`localhost:${tls.port}`);
    expect(connects.sort()).toEqual(expected.sort());

    const reqs = m.filter((e) => e.op === 'http.request');
    expect(reqs.map((e) => [e.target, (e.detail as any).method])).toEqual([
      [`http://127.0.0.1:${http.port}/collect`, 'POST'],
      ...(tls ? [[`https://localhost:${tls.port}/s`, 'POST']] : []),
    ]);
    const fetchEv = m.find((e) => e.op === 'fetch')!;
    expect(fetchEv.target).toBe(`http://localhost:${http.port}/f`); // query stripped
    expect(fetchEv.detail).toMatchObject({ method: 'POST', hasQuery: true });
    if (tls) {
      expect(m.find((e) => e.op === 'tls.connect')!.target).toBe('localhost');
      expect(m.find((e) => e.op === 'connect' && e.target === `localhost:${tls!.port}`)!.detail).toMatchObject({ tls: true });
    }

    // raw tcp: exactly 100 bytes up, 'ack' (3) down, not partial
    const tcpClose = m.find((e) => e.op === 'close' && e.target === `127.0.0.1:${tcp.port}`)!;
    expect(tcpClose.bytes).toBe(100);
    expect(tcpClose.detail).toMatchObject({ bytesWritten: 100, bytesRead: 3 });
    expect((tcpClose.detail as any).partial).toBeUndefined();
    expect((tcpClose.detail as any).firstWriteTs).toBeGreaterThan(0);
    expect((tcpClose.detail as any).firstWriteHash).toMatch(/^[0-9a-f]{16}$/);
    // keep-alive sockets (default http agent since Node 19; not on Node 18) are flushed at exit as partial closes
    const httpClose = m.find((e) => e.op === 'close' && e.target === `127.0.0.1:${http.port}`)!;
    if (Number(process.versions.node.split('.')[0]) >= 19) expect(httpClose.detail).toMatchObject({ partial: true });
    else expect(httpClose.detail).toMatchObject({ bytesWritten: expect.any(Number) });
    expect(httpClose.bytes).toBeGreaterThanOrEqual(Buffer.byteLength(SECRETS.DOTENV + SECRETS.OPENAI + SECRETS.AWS));
    // dns: fetch and https to the name "localhost" resolve through the patched dns.lookup
    expect(m.filter((e) => e.cat === 'dns').every((e) => e.target === 'localhost')).toBe(true);
  });

  it('records env var NAMES only, deduped, and never values', () => {
    const names = main().filter((e) => e.cat === 'env' && e.op === 'read').map((e) => e.target);
    expect(names).toEqual(expect.arrayContaining(['OPENAI_API_KEY', 'AWS_SECRET_ACCESS_KEY', 'GUILTY_HOME']));
    expect(new Set(names).size).toBe(names.length);
    expect(names.some((n) => n.startsWith('TATTLE_'))).toBe(false);
    for (const secret of [SECRETS.OPENAI, SECRETS.AWS, 'hunter2']) expect(r.logText).not.toContain(secret);
  });

  it('flags the clipboard reader and network escape with the exact argv', () => {
    const m = main();
    const clip = m.find((e) => e.cat === 'clip')!;
    expect(clip).toMatchObject({ op: 'read', target: 'pbpaste', verdictHint: 'sensitive' });
    expect((clip.detail as any).argv).toEqual(['pbpaste']);
    const proc = m.find((e) => e.cat === 'proc' && e.target === 'pbpaste')!;
    expect(proc.detail).toMatchObject({ argv: ['pbpaste'], clipboard: 'pbpaste' });
    if (curl) {
      const c = m.find((e) => e.cat === 'proc' && e.target === 'curl')!;
      expect(c.verdictHint).toBe('escape');
      expect(c.detail).toMatchObject({
        networkEscape: true,
        argv: ['curl', '-s', '-m', '5', '-X', 'POST', '--data', 'x', `http://127.0.0.1:${http.port}/curl`],
      });
    }
  });

  it('hooks grandchild node processes, with inherited env and with an explicit env', () => {
    const mainPid = main()[0]!.pid;
    const gc = r.events.filter((e) => e.pid !== mainPid && e.cat === 'fs' && e.op === 'read');
    expect(gc.map((e) => [path.basename(e.target), (e.detail as any).rule]).sort()).toEqual([
      ['.npmrc', 'npmrc'],
      ['id_rsa', 'ssh-dir'],
    ]);
    expect(gc.every((e) => e.ppid === mainPid)).toBe(true);
    const starts = r.events.filter((e) => e.op === 'start');
    expect(starts).toHaveLength(3);
    expect(r.events.filter((e) => e.op === 'exit')).toHaveLength(3);
  });
});

describe('guilty fixture (CJS, destructured require)', () => {
  it('produces the same hook coverage as the ESM variant', async () => {
    const http = await startHttp();
    const tcp = await startTcp();
    const home = tmpDir('tattle-home-');
    fs.writeFileSync(path.join(home, '.env'), 'A=1\n');
    try {
      const r = await runTattle(['node', fx('guilty', 'guilty.cjs')], { HOME: home, GUILTY_HOME: home, GUILTY_HTTP_PORT: String(http.port), GUILTY_TCP_PORT: String(tcp.port) });
      expect(r.code).toBe(0);
      expect(sigs(r.events.filter((e) => e.cat !== 'env' && e.cat !== 'life'))).toEqual(['fs/read', 'net/close', 'net/connect', 'net/http.request']);
      expect(r.events.find((e) => e.cat === 'fs')).toMatchObject({ target: path.join(home, '.env'), verdictHint: 'sensitive', bytes: 4 });
      expect(r.events.filter((e) => e.op === 'connect').map((e) => e.target)).toEqual([`127.0.0.1:${http.port}`, `127.0.0.1:${tcp.port}`]);
      expect(http.bodies).toEqual(['A=1\n']);
    } finally {
      await http.close();
      await tcp.close();
    }
  });
});

describe('clean fixture', () => {
  it('only writes and reads its own temp file; nothing else, nothing sensitive', async () => {
    const out = tmpDir('tattle-clean-');
    const r = await runTattle(['node', fx('clean', 'clean.cjs')], { CLEAN_OUT: out });
    expect(r.code).toBe(0);
    expect(r.stdout).toBe('clean ok 6765\n');
    const body = r.events.filter((e) => e.cat !== 'env' && e.cat !== 'life');
    expect(body.map((e) => `${e.cat}/${e.op} ${e.target}`)).toEqual([`fs/write ${path.join(out, 'result.txt')}`, `fs/read ${path.join(out, 'result.txt')}`]);
    expect(body.map((e) => e.bytes)).toEqual([4, 4]);
    expect(r.events.some((e) => e.verdictHint)).toBe(false);
    expect(r.events.some((e) => ['net', 'dns', 'proc', 'clip'].includes(e.cat))).toBe(false);
  });
});

describe('noisy fixture', () => {
  it('lots of harmless activity: 50 dns, 100 writes, 100 reads, one telemetry POST', async () => {
    const http = await startHttp();
    const dir = tmpDir('tattle-noisy-');
    try {
      const r = await runTattle(['node', fx('noisy', 'noisy.mjs')], { NOISY_DIR: dir, NOISY_PORT: String(http.port) });
      expect(r.code).toBe(0);
      expect(sigs(r.events.filter((e) => e.cat !== 'env' && e.cat !== 'life'))).toEqual(['dns/lookup', 'fs/read', 'fs/write', 'net/close', 'net/connect', 'net/http.request']);
      expect(r.events.filter((e) => e.cat === 'dns' && e.target === 'localhost')).toHaveLength(50);
      expect(r.events.filter((e) => e.cat === 'dns')).toHaveLength(50);
      expect(r.events.filter((e) => e.cat === 'fs' && e.op === 'write')).toHaveLength(100);
      expect(r.events.filter((e) => e.cat === 'fs' && e.op === 'read')).toHaveLength(100);
      expect(r.events.some((e) => e.verdictHint)).toBe(false);
      const req = r.events.filter((e) => e.op === 'http.request');
      expect(req.map((e) => e.target)).toEqual([`http://127.0.0.1:${http.port}/v1/telemetry`]);
      expect(http.bodies).toEqual([JSON.stringify({ event: 'app_start', n: 1 })]);
    } finally {
      await http.close();
    }
  });
});
