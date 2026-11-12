import type { TattleEvent } from '../events.js';
import { compareEvents } from '../events.js';
import { classifyHost, type HostClass, type HostClassification } from './hosts.js';
import type { AnalyzeOptions, EvidencePointer, Severity } from './types.js';

export const DEFAULTS: Required<AnalyzeOptions> = {
  includeLocal: false,
  windowMs: 5000,
  sizeRatio: 0.8,
  txtCount: 10,
  txtWindowMs: 10_000,
  longLivedMs: 30_000,
  longLivedBytes: 1024 * 1024,
};

export function resolveOptions(o?: AnalyzeOptions): Required<AnalyzeOptions> {
  return { ...DEFAULTS, ...(o ?? {}) };
}

/** Stable sort by (ts, pid, seq, original index). Returns a new array. */
export function sortEvents(events: TattleEvent[]): TattleEvent[] {
  return events
    .map((e, i) => [e, i] as const)
    .sort((a, b) => compareEvents(a[0], b[0]) || a[1] - b[1])
    .map((x) => x[0]);
}

export const ptr = (events: TattleEvent[], i: number): EvidencePointer => ({ line: i, pid: events[i]!.pid, seq: events[i]!.seq });

export const sevRank: Record<Severity, number> = { info: 0, low: 1, medium: 2, high: 3, critical: 4 };

export function hostOf(target: string): string {
  const t = target.trim();
  if (t.startsWith('[')) {
    const end = t.indexOf(']');
    if (end > 0) return t.slice(1, end);
  }
  if ((t.match(/:/g) ?? []).length === 1) return t.slice(0, t.indexOf(':'));
  return t;
}

/** Host of a URL-ish target (`proto://host[:port]/path`) or host:port. */
export function hostOfUrl(s: string): string | null {
  const m = /^[a-z][a-z0-9+.-]*:\/\/(?:[^/@]*@)?([^/:?#]+|\[[^\]]+\])/i.exec(s);
  if (m) return hostOf(m[1]!);
  return null;
}

export interface EffectiveClass extends HostClassification {
  /** true when the host is local and includeLocal is on, so it is analysed as "unknown" */
  localAsUnknown?: boolean;
}

/** Classification used for verdicts/chains: local is benign unless includeLocal. */
export function effectiveClass(host: string, includeLocal: boolean): EffectiveClass {
  const c = classifyHost(host);
  if (c.class === 'local' && includeLocal) return { class: 'unknown', localAsUnknown: true };
  return c;
}

export const isEligibleSink = (c: HostClass): boolean => c === 'unknown' || c === 'telemetry' || c === 'raw-ip';

export interface Conn {
  pid: number;
  sid: number | undefined;
  target: string;
  host: string;
  port: string;
  tls: boolean;
  connectTs: number;
  firstWriteTs?: number;
  closeTs?: number;
  bytesWritten: number;
  bytesRead: number;
  partial: boolean;
  closed: boolean;
  evidence: number[];
}

/** Pair net/connect with net/close (by pid+sid). A close without a connect still yields a Conn. */
export function buildConns(events: TattleEvent[]): Conn[] {
  const bySid = new Map<string, Conn>();
  const out: Conn[] = [];
  events.forEach((e, i) => {
    if (e.cat !== 'net' || (e.op !== 'connect' && e.op !== 'close')) return;
    if (e.target.startsWith('unix:')) return;
    const d = (e.detail ?? {}) as Record<string, unknown>;
    const sid = typeof d.sid === 'number' ? d.sid : undefined;
    const key = sid !== undefined ? `${e.pid}:${sid}` : undefined;
    let c = key ? bySid.get(key) : undefined;
    if (!c) {
      const host = hostOf(e.target);
      c = {
        pid: e.pid,
        sid,
        target: e.target,
        host,
        port: e.target.slice(e.target.lastIndexOf(':') + 1),
        tls: !!d.tls,
        connectTs: typeof d.connectTs === 'number' ? d.connectTs : e.ts,
        bytesWritten: 0,
        bytesRead: 0,
        partial: false,
        closed: false,
        evidence: [],
      };
      out.push(c);
      if (key) bySid.set(key, c);
    }
    c.evidence.push(i);
    if (e.op === 'close') {
      c.closed = true;
      c.closeTs = e.ts;
      c.partial = !!d.partial;
      c.bytesWritten = typeof d.bytesWritten === 'number' ? d.bytesWritten : (e.bytes ?? 0);
      c.bytesRead = typeof d.bytesRead === 'number' ? d.bytesRead : 0;
      if (typeof d.firstWriteTs === 'number') c.firstWriteTs = d.firstWriteTs;
      if (typeof d.connectTs === 'number') c.connectTs = d.connectTs;
    }
  });
  return out;
}

/** pid -> ppid map from every event seen. */
export function parentMap(events: TattleEvent[]): Map<number, number> {
  const m = new Map<number, number>();
  for (const e of events) if (!m.has(e.pid)) m.set(e.pid, e.ppid);
  return m;
}

/** true when `pid` is `ancestor` or a descendant of it. */
export function isSameOrDescendant(pid: number, ancestor: number, parents: Map<number, number>): boolean {
  let p: number | undefined = pid;
  for (let n = 0; p !== undefined && n < 64; n++) {
    if (p === ancestor) return true;
    p = parents.get(p);
  }
  return false;
}

export const plural = (n: number, one: string, many = one + 's'): string => `${n} ${n === 1 ? one : many}`;
