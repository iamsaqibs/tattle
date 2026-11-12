/** Compare two receipt bodies: what changed between runs of the "same" tool. */
import type { Verdict } from './analyze/types.js';
import type { ReceiptBody } from './receipt.js';

const RANK: Record<Verdict, number> = { 'NOT OBSERVED': -1, CLEAN: 0, 'PHONING HOME': 1, 'READING SECRETS': 2, 'ESCAPE CHAIN': 3 };

export interface HostDelta {
  host: string;
  bytesUp: number;
  bytesDown: number;
}
export interface DiffResult {
  a: { verdict: Verdict; score: number };
  b: { verdict: Verdict; score: number };
  verdictChanged: boolean;
  worse: boolean;
  hosts: { added: string[]; removed: string[] };
  sensitive: { added: string[]; removed: string[] };
  procs: { added: string[]; removed: string[] };
  /** per-host byte deltas (b - a); hosts only in one side count from/to zero */
  bytes: Array<{ host: string; up: number; down: number }>;
  hasNew: boolean;
}

const sorted = (s: Iterable<string>) => [...s].sort();
const minus = (x: Set<string>, y: Set<string>) => sorted([...x].filter((v) => !y.has(v)));

export function sensitiveKeys(b: ReceiptBody): Set<string> {
  return new Set(b.analysis.sensitiveReads.map((s) => s.rule ?? `${s.kind}:${s.target}`));
}
export function procKeys(b: ReceiptBody): Set<string> {
  return new Set(b.analysis.procs.map((p) => p.argv?.[0] ?? p.target).filter(Boolean));
}

export function diffReceipts(a: ReceiptBody, b: ReceiptBody): DiffResult {
  const ha = new Map(a.analysis.hosts.map((h) => [h.host.toLowerCase(), h]));
  const hb = new Map(b.analysis.hosts.map((h) => [h.host.toLowerCase(), h]));
  const ka = new Set(ha.keys());
  const kb = new Set(hb.keys());
  const bytes: DiffResult['bytes'] = [];
  for (const k of sorted(new Set([...ka, ...kb]))) {
    const up = (hb.get(k)?.bytesUp ?? 0) - (ha.get(k)?.bytesUp ?? 0);
    const down = (hb.get(k)?.bytesDown ?? 0) - (ha.get(k)?.bytesDown ?? 0);
    if (up || down) bytes.push({ host: (hb.get(k) ?? ha.get(k))!.host, up, down });
  }
  const sa = sensitiveKeys(a);
  const sb = sensitiveKeys(b);
  const pa = procKeys(a);
  const pb = procKeys(b);
  const va = a.analysis.verdict;
  const vb = b.analysis.verdict;
  const r: DiffResult = {
    a: { verdict: va, score: a.analysis.score },
    b: { verdict: vb, score: b.analysis.score },
    verdictChanged: va !== vb,
    worse: RANK[vb] > RANK[va],
    hosts: { added: minus(kb, ka).map((k) => hb.get(k)!.host), removed: minus(ka, kb).map((k) => ha.get(k)!.host) },
    sensitive: { added: minus(sb, sa), removed: minus(sa, sb) },
    procs: { added: minus(pb, pa), removed: minus(pa, pb) },
    bytes,
    hasNew: false,
  };
  r.hasNew = r.worse || r.hosts.added.length > 0 || r.sensitive.added.length > 0 || r.procs.added.length > 0;
  return r;
}
