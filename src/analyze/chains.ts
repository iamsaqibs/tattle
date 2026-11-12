/**
 * T2.2 Escape-chain graph.
 *
 * A chain links a sensitive source (secret-shaped file read, clipboard read) to a LATER outbound
 * sink (socket write or network-capable child process) that is causally plausible:
 *
 *   - pid: sink is in the same process as the read, or in a descendant (via ppid)
 *   - time: sink's firstWriteTs (socket) / spawn ts (proc) is 0..windowMs after the read ts
 *     (default 5000 ms; `opts.windowMs`). `ts` of an async read is its CALL time, so a write that
 *     happens after the call but before the read "completes" still counts.
 *   - size: socket bytesWritten >= sizeRatio * bytes read (default 0.8). Rationale: an exfil of a
 *     file carries at least the file; the 20% slack absorbs encodings that shrink payloads
 *     (gzip, base64 is larger so it is covered) and byte counts that miss framing. It is a
 *     correlation filter, NOT proof of causation: only evidence of coincidence in pid/time/size.
 *   - sink host: class unknown | telemetry | raw-ip. "good" hosts (the tool's own API vendor, package
 *     registries) are never sinks. "local" hosts are ignored unless opts.includeLocal, in which case
 *     they are analysed as "unknown" (this is how fixtures talking to localhost are exercised).
 *
 * Confidence:
 *   high   - same pid, size-verified read, socket has a measured firstWriteTs
 *   medium - anything else that passes the filters: descendant pid, size not verifiable (read
 *            bytes unknown), missing firstWriteTs (connect time used), proc escapes, clipboard.
 */
import type { TattleEvent } from '../events.js';
import { effectiveClass, hostOf, hostOfUrl, isEligibleSink, isSameOrDescendant, parentMap, plural, ptr, resolveOptions, type Conn } from './model.js';
import { buildConns } from './model.js';
import type { AnalyzeOptions, Chain, ChainSource, SensitiveProbe, SensitiveRead, Severity } from './types.js';

const SEVS = new Set(['low', 'medium', 'high']);

/** Successful sensitive file reads and clipboard reads, in time order. */
export function collectSensitiveReads(events: TattleEvent[]): SensitiveRead[] {
  const out: SensitiveRead[] = [];
  events.forEach((e, i) => {
    const d = (e.detail ?? {}) as Record<string, unknown>;
    if (e.cat === 'fs' && e.op === 'read' && e.verdictHint === 'sensitive' && !d.error) {
      const sev = typeof d.severity === 'string' && SEVS.has(d.severity) ? (d.severity as Severity) : 'medium';
      out.push({
        kind: 'file',
        target: e.target,
        rule: typeof d.rule === 'string' ? d.rule : undefined,
        label: typeof d.label === 'string' ? d.label : undefined,
        category: typeof d.category === 'string' ? d.category : undefined,
        severity: sev,
        bytes: e.bytes,
        pid: e.pid,
        ts: e.ts,
        evidence: ptr(events, i),
      });
    } else if (e.cat === 'clip' && e.op === 'read') {
      out.push({ kind: 'clipboard', target: e.target, label: 'clipboard', category: 'clipboard', severity: 'medium', pid: e.pid, ts: e.ts, evidence: ptr(events, i) });
    }
  });
  return out;
}

/** Failed accesses (detail.error set) to paths tagged sensitive: "probed", not "read". */
export function collectSensitiveProbes(events: TattleEvent[]): SensitiveProbe[] {
  const out: SensitiveProbe[] = [];
  events.forEach((e, i) => {
    const d = (e.detail ?? {}) as Record<string, unknown>;
    if (e.cat !== 'fs' || e.verdictHint !== 'sensitive' || !d.error) return;
    out.push({ target: e.target, error: String(d.error), rule: typeof d.rule === 'string' ? d.rule : undefined, label: typeof d.label === 'string' ? d.label : undefined, pid: e.pid, ts: e.ts, evidence: ptr(events, i) });
  });
  return out;
}

const src = (r: SensitiveRead): ChainSource => ({ kind: r.kind, target: r.target, bytes: r.bytes, ts: r.ts, rule: r.rule, evidence: r.evidence });

export function findChains(events: TattleEvent[], reads: SensitiveRead[], optsIn?: AnalyzeOptions, conns?: Conn[]): Chain[] {
  const o = resolveOptions(optsIn);
  const parents = parentMap(events);
  const chains: Chain[] = [];
  const files = reads.filter((r) => r.kind === 'file');
  const clips = reads.filter((r) => r.kind === 'clipboard');
  const related = (sinkPid: number, r: SensitiveRead) => isSameOrDescendant(sinkPid, r.pid, parents);

  // ---- socket sinks ----
  for (const c of conns ?? buildConns(events)) {
    if (c.bytesWritten <= 0) continue;
    const cls = effectiveClass(c.host, o.includeLocal);
    if (!isEligibleSink(cls.class)) continue;
    const t = c.firstWriteTs ?? c.connectTs;
    const inWindow = (r: SensitiveRead) => t - r.ts >= 0 && t - r.ts <= o.windowMs && related(c.pid, r);
    const mk = (kind: Chain['kind'], rs: SensitiveRead[], verified: boolean) => {
      const latest = Math.max(...rs.map((r) => r.ts));
      const samePid = rs.every((r) => r.pid === c.pid);
      const confidence: Chain['confidence'] = verified && samePid && c.firstWriteTs !== undefined ? 'high' : 'medium';
      const readBytes = rs.reduce((n, r) => n + (r.bytes ?? 0), 0);
      const why: string[] = [];
      why.push(samePid ? 'same process' : 'sink is in a descendant process');
      why.push(verified ? `bytes written (${c.bytesWritten}) >= ${o.sizeRatio} x bytes read (${readBytes})` : 'read size not verifiable');
      if (c.firstWriteTs === undefined) why.push('first-write time unavailable, connect time used');
      const what = kind === 'clipboard-to-socket' ? 'the clipboard' : plural(rs.length, 'secret-shaped file');
      chains.push({
        id: '',
        kind,
        confidence,
        explanation: `Read ${what}, then wrote ${c.bytesWritten} bytes to ${c.target} (${cls.class}) ${Math.round(t - latest)} ms later (${why.join('; ')}). Correlation, not proof of causation.`,
        sources: rs.map(src),
        sink: { kind: 'socket', host: c.host, hostClass: cls.class, target: c.target, bytesWritten: c.bytesWritten, firstWriteTs: c.firstWriteTs, pid: c.pid, evidence: c.evidence.map((i) => ptr(events, i)) },
        deltaMs: Math.round(t - latest),
        evidence: [...rs.map((r) => r.evidence), ...c.evidence.map((i) => ptr(events, i))],
      });
    };
    const cand = files.filter(inWindow);
    const verified = cand.filter((r) => r.bytes !== undefined && r.bytes > 0 && c.bytesWritten >= o.sizeRatio * r.bytes);
    if (verified.length) mk('file-to-socket', verified, true);
    else if (cand.some((r) => !r.bytes)) mk('file-to-socket', cand.filter((r) => !r.bytes), false);
    const clipCand = clips.filter(inWindow);
    if (clipCand.length) mk('clipboard-to-socket', clipCand, false);
  }

  // ---- network-escape process sinks (curl / wget / nc ... spawned after a sensitive read) ----
  events.forEach((e, i) => {
    const d = (e.detail ?? {}) as Record<string, unknown>;
    if (e.cat !== 'proc' || d.networkEscape !== true) return;
    const argv = Array.isArray(d.argv) ? d.argv.map(String) : [];
    let host: string | null = null;
    for (const a of argv) {
      host = hostOfUrl(a);
      if (host) break;
    }
    const cls = host ? effectiveClass(host, o.includeLocal) : { class: 'unknown' as const };
    if (!isEligibleSink(cls.class)) return;
    const rs = [...files, ...clips].filter((r) => e.ts - r.ts >= 0 && e.ts - r.ts <= o.windowMs && related(e.pid, r));
    if (!rs.length) return;
    const latest = Math.max(...rs.map((r) => r.ts));
    chains.push({
      id: '',
      kind: 'file-to-proc',
      confidence: 'medium',
      explanation: `Read ${plural(rs.length, 'sensitive source')}, then spawned ${e.target} (a network-capable tool) ${Math.round(e.ts - latest)} ms later${host ? ` targeting ${host}` : ''}. Transfer size is not observable for child processes, so confidence is capped at medium.`,
      sources: rs.map(src),
      sink: { kind: 'proc', host: host ?? '(unspecified)', hostClass: cls.class, target: e.target, pid: e.pid, evidence: [ptr(events, i)] },
      deltaMs: Math.round(e.ts - latest),
      evidence: [...rs.map((r) => r.evidence), ptr(events, i)],
    });
  });

  chains.sort((a, b) => (a.confidence === b.confidence ? 0 : a.confidence === 'high' ? -1 : 1) || a.evidence[0]!.line - b.evidence[0]!.line);
  chains.forEach((c, n) => (c.id = `chain-${n + 1}`));
  return chains;
}

export { hostOf };
