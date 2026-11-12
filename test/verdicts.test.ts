/** Per-fixture verdicts (T2.4 DoD), asserted explicitly. Real CLI runs, localhost only. */
import fs from 'node:fs';
import path from 'node:path';
import { afterAll, beforeAll, describe, expect, it } from 'vitest';
import { analyze } from '../src/analyze/index.js';
import { ensureBuilt, ROOT, runTattle, startHttp, startTcp, tmpDir } from './helpers.js';

beforeAll(ensureBuilt);
const fx = (...p: string[]) => path.join(ROOT, 'fixtures', ...p);

describe('fixture verdicts', () => {
  it('guilty => ESCAPE CHAIN with includeLocal (high confidence, .env -> http POST); CLEAN-of-chains by default', async () => {
    const http = await startHttp();
    const tcp = await startTcp();
    const home = tmpDir('tattle-home-');
    fs.writeFileSync(path.join(home, '.env'), 'SECRET_TOKEN=hunter2\n');
    try {
      const r = await runTattle(['node', fx('guilty', 'guilty.cjs')], { HOME: home, GUILTY_HOME: home, GUILTY_HTTP_PORT: String(http.port), GUILTY_TCP_PORT: String(tcp.port) }, ['--include-local']);
      expect(r.code).toBe(0);
      const a = analyze(r.events, { includeLocal: true });
      expect(a.verdict).toBe('ESCAPE CHAIN');
      expect(a.chains.length).toBeGreaterThanOrEqual(1);
      expect(a.chains[0]).toMatchObject({ kind: 'file-to-socket', confidence: 'high' });
      expect(a.chains[0]!.sources[0]!.target).toBe(path.join(home, '.env'));
      expect(a.sensitiveReads.map((s) => s.rule)).toContain('dotenv');
      // without includeLocal the loopback sink is ignored: the secret read remains
      const b = analyze(r.events);
      expect(b.chains).toHaveLength(0);
      expect(b.verdict).toBe('READING SECRETS');
      // CLI wrote a receipt draft with the same verdict and a matching events hash
      const receipt = JSON.parse(fs.readFileSync(path.join(path.dirname(r.logPath), 'receipt.json'), 'utf8'));
      expect(receipt.body.analysis.verdict).toBe('ESCAPE CHAIN');
      expect(receipt.body.meta.exitCode).toBe(0);
      expect(receipt.body.meta.tool.argv[0]).toBe('node');
      expect(receipt.eventsSha256).toMatch(/^[0-9a-f]{64}$/);
      expect(r.stderr).toMatch(/ESCAPE CHAIN/);
    } finally {
      await http.close();
      await tcp.close();
    }
  });

  it('clean => CLEAN, no reasons', async () => {
    const out = tmpDir('tattle-clean-');
    const r = await runTattle(['node', fx('clean', 'clean.cjs')], { CLEAN_OUT: out });
    const a = analyze(r.events, { includeLocal: true });
    expect(a.verdict).toBe('CLEAN');
    expect(a.reasons).toEqual([]);
    expect(a.chains).toEqual([]);
    expect(a.score).toBe(0);
    expect(r.stderr).toMatch(/CLEAN/);
  });

  describe('noisy', () => {
    let http: Awaited<ReturnType<typeof startHttp>>;
    let events: Awaited<ReturnType<typeof runTattle>>['events'];
    beforeAll(async () => {
      http = await startHttp();
      const r = await runTattle(['node', fx('noisy', 'noisy.mjs')], { NOISY_DIR: tmpDir('tattle-noisy-'), NOISY_PORT: String(http.port) });
      events = r.events;
    });
    afterAll(() => http?.close());

    // Documented rule (docs/verdicts.md): loopback traffic is benign by default, so noisy is CLEAN;
    // with includeLocal its one POST goes to an unclassified host and the verdict is PHONING HOME.
    it('=> CLEAN by default (loopback is benign)', () => {
      expect(analyze(events).verdict).toBe('CLEAN');
    });
    it('=> PHONING HOME with includeLocal, never worse (no secrets, no chain)', () => {
      const a = analyze(events, { includeLocal: true });
      expect(a.verdict).toBe('PHONING HOME');
      expect(a.chains).toEqual([]);
      expect(a.sensitiveReads).toEqual([]);
      expect(a.hosts).toHaveLength(1);
      expect(a.hosts[0]).toMatchObject({ host: '127.0.0.1', local: true, connections: 1 });
    });
  });
});
