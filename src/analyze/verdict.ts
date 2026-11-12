/**
 * T2.4 Verdict computation. Deterministic, precedence-ordered (see docs/verdicts.md):
 *   NOT OBSERVED (zero hooked processes) > ESCAPE CHAIN > READING SECRETS > PHONING HOME > CLEAN
 * Wording rule: reasons state what was observed ("read 3 secret-shaped files"), never intent.
 */
import { plural, sevRank } from './model.js';
import type { Chain, Coverage, EvidencePointer, Finding, HostSummary, ProcInfo, Reason, SensitiveProbe, SensitiveRead, Severity, Verdict } from './types.js';
import type { TattleEvent } from '../events.js';

/** Score contribution per reason severity (score is capped at 100; it is presentation, not the verdict). */
export const SEVERITY_WEIGHT: Record<Severity, number> = { info: 0, low: 3, medium: 12, high: 35, critical: 60 };

export const NOT_OBSERVED_NOTE = 'no Node.js process was observed \u2014 Tattle cannot see inside native binaries; this is not a clean bill of health';

export interface VerdictInput {
  coverage?: Coverage;
  chains: Chain[];
  sensitiveReads: SensitiveRead[];
  probes?: SensitiveProbe[];
  hosts: HostSummary[];
  heuristics: Finding[];
  procs: ProcInfo[];
  events: TattleEvent[];
  spawnEvidence: { tool: string; evidence: EvidencePointer }[];
}

const list = (xs: string[], max = 3): string => (xs.length <= max ? xs.join(', ') : `${xs.slice(0, max).join(', ')} and ${xs.length - max} more`);

export function computeVerdict(inp: VerdictInput): { verdict: Verdict; score: number; reasons: Reason[] } {
  const reasons: Reason[] = [];
  if (inp.coverage && inp.coverage.hookedProcesses === 0) {
    return { verdict: 'NOT OBSERVED', score: 0, reasons: [{ code: 'NOT_OBSERVED', severity: 'info', text: NOT_OBSERVED_NOTE, evidence: [] }] };
  }

  for (const c of inp.chains) {
    reasons.push({
      code: 'ESCAPE_CHAIN',
      severity: c.confidence === 'high' ? 'critical' : 'high',
      text: `read ${c.kind === 'clipboard-to-socket' ? 'the clipboard' : plural(c.sources.length, 'secret-shaped file')}, then ${c.sink.kind === 'socket' ? `wrote ${c.sink.bytesWritten} bytes to` : 'spawned a network tool for'} ${c.sink.host} (${c.sink.hostClass}) ${c.deltaMs} ms later (${c.confidence} confidence)`,
      evidence: c.evidence,
    });
  }

  // sensitive reads, grouped by severity
  for (const sev of ['high', 'medium', 'low'] as const) {
    const rs = inp.sensitiveReads.filter((r) => r.kind === 'file' && r.severity === sev);
    if (!rs.length) continue;
    const labels = [...new Set(rs.map((r) => r.label ?? r.rule ?? r.target))].sort();
    reasons.push({ code: `SENSITIVE_READ_${sev.toUpperCase()}`, severity: sev, text: `read ${plural(rs.length, 'secret-shaped file')} (${sev} severity: ${list(labels)})`, evidence: rs.map((r) => r.evidence) });
  }
  const probes = inp.probes ?? [];
  if (probes.length) {
    const paths = new Set(probes.map((p) => p.target));
    reasons.push({ code: 'PROBED_SECRETS', severity: 'low', text: `probed ${plural(paths.size, 'secret-shaped path')} (not found)`, evidence: probes.map((p) => p.evidence) });
  }
  const clips = inp.sensitiveReads.filter((r) => r.kind === 'clipboard');
  if (clips.length) reasons.push({ code: 'CLIPBOARD_READ', severity: 'medium', text: `read the clipboard via ${list([...new Set(clips.map((c) => c.target))].sort())}`, evidence: clips.map((r) => r.evidence) });

  // hosts
  const idx = (hs: HostSummary[]): EvidencePointer[] => hs.flatMap((h) => h.evidence.map((i) => ({ line: i, pid: inp.events[i]!.pid, seq: inp.events[i]!.seq })));
  const unk = inp.hosts.filter((h) => (h.class === 'unknown' || h.class === 'raw-ip') && h.connections > 0);
  if (unk.length) {
    const n = unk.reduce((a, h) => a + h.connections, 0);
    reasons.push({ code: 'UNCLASSIFIED_HOST', severity: 'medium', text: `opened ${plural(n, 'connection')} to ${unk.length === 1 ? 'an unclassified host' : `${unk.length} unclassified hosts`} (${list(unk.map((h) => h.host))})`, evidence: idx(unk) });
  }
  const tel = inp.hosts.filter((h) => h.class === 'telemetry' && h.connections > 0);
  if (tel.length) {
    const n = tel.reduce((a, h) => a + h.connections, 0);
    reasons.push({ code: 'TELEMETRY_HOST', severity: 'low', text: `opened ${plural(n, 'connection')} to known telemetry hosts (${list(tel.map((h) => h.vendor ? `${h.host} [${h.vendor}]` : h.host))})`, evidence: idx(tel) });
  }

  for (const f of inp.heuristics) reasons.push({ code: f.code, severity: f.severity, text: f.text, evidence: f.evidence });

  if (inp.spawnEvidence.length) {
    const tools = [...new Set(inp.spawnEvidence.map((s) => s.tool))].sort();
    reasons.push({ code: 'NETWORK_TOOL_SPAWN', severity: 'low', text: `spawned ${plural(inp.spawnEvidence.length, 'network-capable child process', 'network-capable child processes')} (${list(tools)})`, evidence: inp.spawnEvidence.map((s) => s.evidence) });
  }

  if (inp.coverage && !inp.coverage.rootHooked && inp.coverage.note) reasons.push({ code: 'PARTIAL_COVERAGE', severity: 'info', text: inp.coverage.note, evidence: [] });

  reasons.sort((a, b) => sevRank[b.severity] - sevRank[a.severity] || (a.evidence[0]?.line ?? 0) - (b.evidence[0]?.line ?? 0) || a.code.localeCompare(b.code));

  const secretsMedPlus = inp.sensitiveReads.some((r) => sevRank[r.severity] >= sevRank.medium);
  const phoning = inp.hosts.some((h) => h.connections > 0 && h.class !== 'good' && h.class !== 'local') || inp.heuristics.some((f) => sevRank[f.severity] >= sevRank.medium);
  const verdict: Verdict = inp.chains.length ? 'ESCAPE CHAIN' : secretsMedPlus ? 'READING SECRETS' : phoning ? 'PHONING HOME' : 'CLEAN';
  const score = Math.min(100, reasons.reduce((n, r) => n + SEVERITY_WEIGHT[r.severity], 0));
  return { verdict, score, reasons };
}
