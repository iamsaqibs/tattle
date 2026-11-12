/**
 * analyze(): pure, deterministic. Same events + options => identical Analysis (no clock, no RNG).
 * Evidence `line` numbers index the time-sorted event list (compareEvents order).
 */
import type { TattleEvent } from '../events.js';
import { collectSensitiveProbes, collectSensitiveReads, findChains } from './chains.js';
import { runHeuristics } from './heuristics.js';
import { buildConns, effectiveClass, ptr, resolveOptions, sortEvents } from './model.js';
import type { Analysis, AnalyzeOptions, Coverage, HostSummary, ProcInfo, RootInfo } from './types.js';
import { computeVerdict, NOT_OBSERVED_NOTE } from './verdict.js';

export type { Analysis, AnalyzeOptions, Chain, Finding, HostSummary, ProcInfo, Reason, SensitiveRead, Verdict, Severity, EvidencePointer, Coverage, RootInfo } from './types.js';

export function analyze(input: TattleEvent[], optsIn?: AnalyzeOptions, root?: RootInfo): Analysis {
  const options = resolveOptions(optsIn);
  const events = sortEvents(input);
  const conns = buildConns(events);

  // hosts
  const hostMap = new Map<string, HostSummary>();
  for (const c of conns) {
    const cls = effectiveClass(c.host, options.includeLocal);
    if (cls.class === 'local') continue; // benign unless includeLocal
    const key = c.host.toLowerCase();
    let h = hostMap.get(key);
    if (!h) {
      h = { host: c.host, class: cls.class, ...(cls.localAsUnknown ? { local: true } : {}), ...(cls.vendor ? { vendor: cls.vendor } : {}), connections: 0, bytesUp: 0, bytesDown: 0, evidence: [] };
      hostMap.set(key, h);
    }
    h.connections++;
    h.bytesUp += c.bytesWritten;
    h.bytesDown += c.bytesRead;
    h.evidence.push(...c.evidence);
  }
  const hosts = [...hostMap.values()].sort((a, b) => b.bytesUp - a.bytesUp || a.host.localeCompare(b.host));
  for (const h of hosts) h.evidence = [...new Set(h.evidence)].sort((a, b) => a - b);

  const sensitiveReads = collectSensitiveReads(events);
  const probes = collectSensitiveProbes(events);
  const chains = findChains(events, sensitiveReads, options, conns);
  const heuristics = runHeuristics(events, options, conns);

  // procs + env + counts
  const procMap = new Map<number, ProcInfo>();
  const envNames = new Set<string>();
  const counts: Record<string, number> = {};
  const spawnEvidence: { tool: string; evidence: ReturnType<typeof ptr> }[] = [];
  events.forEach((e, i) => {
    counts[e.cat] = (counts[e.cat] ?? 0) + 1;
    if (e.cat === 'life') {
      const p = procMap.get(e.pid) ?? { pid: e.pid, ppid: e.ppid, target: e.target };
      const d = (e.detail ?? {}) as Record<string, unknown>;
      if (e.op === 'start') {
        p.startTs = e.ts;
        if (Array.isArray(d.argv)) p.argv = d.argv.map(String);
      } else if (e.op === 'exit') {
        p.endTs = e.ts;
        p.exitCode = typeof d.code === 'number' ? d.code : null;
      }
      procMap.set(e.pid, p);
    } else if (e.cat === 'env' && e.op === 'read' && !(e.detail as any)?.runtime) {
      envNames.add(e.target);
    } else if (e.cat === 'proc' && (e.detail as any)?.networkEscape === true) {
      spawnEvidence.push({ tool: String((e.detail as any).tool ?? e.target), evidence: ptr(events, i) });
    }
  });
  const procs = [...procMap.values()].sort((a, b) => (a.startTs ?? 0) - (b.startTs ?? 0) || a.pid - b.pid);

  const hookedPids = new Set(events.map((e) => e.pid));
  const rootHooked = root?.pid === undefined ? true : hookedPids.has(root.pid);
  const argv0 = root?.argv0 ? root.argv0.split(/[\\/]/).pop()! : undefined;
  const coverage: Coverage = { hookedProcesses: hookedPids.size, rootHooked };
  if (hookedPids.size === 0) coverage.note = NOT_OBSERVED_NOTE;
  else if (!rootHooked) coverage.note = `partial coverage: ${argv0 ?? 'the command'} is not a Node process; only ${hookedPids.size} Node descendant${hookedPids.size === 1 ? '' : 's'} observed`;

  const { verdict, score, reasons } = computeVerdict({ coverage, chains, sensitiveReads, probes, hosts, heuristics, procs, events, spawnEvidence });

  const firstTs = events.length ? events[0]!.ts : null;
  const lastTs = events.length ? events[events.length - 1]!.ts : null;
  return {
    schema: 1,
    verdict,
    score,
    coverage,
    reasons,
    hosts,
    sensitiveReads,
    probes,
    chains,
    heuristics,
    procs,
    envNames: [...envNames].sort(),
    counts,
    stats: {
      events: events.length,
      firstTs,
      lastTs,
      durationMs: firstTs === null || lastTs === null ? 0 : Math.round(lastTs - firstTs),
      pids: new Set(events.map((e) => e.pid)).size,
      connections: conns.length,
      bytesUp: conns.reduce((n, c) => n + c.bytesWritten, 0),
      bytesDown: conns.reduce((n, c) => n + c.bytesRead, 0),
    },
    options,
  };
}
