/**
 * T2.3 Covert-channel heuristics v0. Each heuristic returns Findings (evidence, not accusations):
 * they describe a pattern that is sometimes associated with covert channels and is also produced
 * by plenty of legitimate software, so severities stay low/medium and never alone yield the
 * strongest verdicts.
 */
import type { TattleEvent } from '../events.js';
import { classifyHost } from './hosts.js';
import { buildConns, hostOf, plural, ptr, resolveOptions, type Conn } from './model.js';
import type { AnalyzeOptions, Finding } from './types.js';

/**
 * TLDs with a disproportionate share of abuse, for the "odd TLD" smell. Deliberately short.
 * Sources: Spamhaus "The World's Most Abused TLDs" (spamhaus.org/reputation-statistics/most-abused-tlds/),
 * Interisle "Phishing Landscape" reports (interisle.net), and Google's 2023 launch of .zip/.mov
 * (security community advisories about confusable file-extension TLDs).
 */
export const ODD_TLDS: readonly string[] = ['zip', 'mov', 'top', 'xyz', 'tk', 'ml', 'ga', 'cf', 'gq', 'click', 'icu', 'work', 'rest', 'country', 'kim'];

function tldOf(host: string): string {
  const h = host.toLowerCase().replace(/\.+$/, '');
  return h.slice(h.lastIndexOf('.') + 1);
}

/** raw IP connections: the tool connected to an address with no hostname (nothing to classify). */
export function rawIpConnections(events: TattleEvent[], conns: Conn[]): Finding[] {
  const out: Finding[] = [];
  for (const c of conns) {
    const cls = classifyHost(c.host);
    if (cls.class !== 'raw-ip') continue;
    // IP literal connections made by an http client to a hostname we did dns for are still
    // hostnames at connect time; here the connect target itself is an IP literal.
    out.push({
      code: 'RAW_IP_CONNECTION',
      severity: cls.private ? 'low' : 'medium',
      text: `opened a connection to ${cls.private ? 'a private-range' : 'a public'} IP address (${c.host}) with no hostname`,
      evidence: c.evidence.map((i) => ptr(events, i)),
      detail: { host: c.host, port: c.port, private: !!cls.private },
    });
  }
  return out;
}

/** dns queries for hostnames under an abused TLD. */
export function oddTldDns(events: TattleEvent[]): Finding[] {
  const hits = new Map<string, number[]>();
  events.forEach((e, i) => {
    if (e.cat !== 'dns') return;
    const h = hostOf(e.target);
    if (ODD_TLDS.includes(tldOf(h))) (hits.get(h.toLowerCase()) ?? hits.set(h.toLowerCase(), []).get(h.toLowerCase())!).push(i);
  });
  return [...hits].map(([host, idx]) => ({
    code: 'ODD_TLD_DNS',
    severity: 'medium' as const,
    text: `resolved a hostname under an often-abused TLD (.${tldOf(host)}): ${host}`,
    evidence: idx.map((i) => ptr(events, i)),
    detail: { host, tld: tldOf(host), queries: idx.length },
  }));
}

/** more than txtCount TXT lookups inside a sliding txtWindowMs window (DNS tunnelling smell). */
export function txtBurst(events: TattleEvent[], optsIn?: AnalyzeOptions): Finding[] {
  const o = resolveOptions(optsIn);
  const idx: number[] = [];
  events.forEach((e, i) => {
    if (e.cat === 'dns' && e.op === 'resolve' && String((e.detail as any)?.rrtype ?? '').toUpperCase() === 'TXT') idx.push(i);
  });
  let best: number[] = [];
  for (let a = 0, b = 0; b < idx.length; b++) {
    while (events[idx[b]!]!.ts - events[idx[a]!]!.ts > o.txtWindowMs) a++;
    if (b - a + 1 > best.length) best = idx.slice(a, b + 1);
  }
  if (best.length <= o.txtCount) return [];
  const domains = new Set(best.map((i) => hostOf(events[i]!.target).split('.').slice(-2).join('.')));
  return [
    {
      code: 'DNS_TXT_BURST',
      severity: 'medium',
      text: `made ${best.length} TXT lookups within ${Math.round(o.txtWindowMs / 1000)}s (${plural(domains.size, 'domain')}), a rate sometimes associated with DNS tunnelling`,
      evidence: best.map((i) => ptr(events, i)),
      detail: { count: best.length, windowMs: o.txtWindowMs, domains: [...domains].sort() },
    },
  ];
}

/** sockets open a long time with a lot written. Local is ignored unless includeLocal. */
export function longLivedHighWrite(events: TattleEvent[], conns: Conn[], optsIn?: AnalyzeOptions): Finding[] {
  const o = resolveOptions(optsIn);
  const out: Finding[] = [];
  for (const c of conns) {
    if (!c.closed || c.closeTs === undefined) continue;
    if (classifyHost(c.host).class === 'local' && !o.includeLocal) continue;
    if (c.closeTs - c.connectTs >= o.longLivedMs && c.bytesWritten >= o.longLivedBytes) {
      out.push({
        code: 'LONG_LIVED_HIGH_WRITE',
        severity: 'low',
        text: `kept a connection to ${c.target} open for ${Math.round((c.closeTs - c.connectTs) / 1000)}s and wrote ${c.bytesWritten} bytes${c.partial ? ' (still open at exit)' : ''}`,
        evidence: c.evidence.map((i) => ptr(events, i)),
        detail: { target: c.target, bytesWritten: c.bytesWritten, openMs: Math.round(c.closeTs - c.connectTs) },
      });
    }
  }
  return out;
}

/**
 * TLS connections that closed without any application bytes in either direction. That is what a
 * rejected certificate (pinning, interception) looks like from inside the process, but it is
 * equally what an aborted request looks like, so it stays "unclassified" at low severity.
 */
export function tlsNoData(events: TattleEvent[], conns: Conn[], optsIn?: AnalyzeOptions): Finding[] {
  const o = resolveOptions(optsIn);
  const out: Finding[] = [];
  for (const c of conns) {
    if (!c.tls || !c.closed || c.partial || c.bytesWritten !== 0 || c.bytesRead !== 0) continue;
    if (classifyHost(c.host).class === 'local' && !o.includeLocal) continue;
    out.push({
      code: 'TLS_NO_DATA',
      severity: 'low',
      text: `TLS connection to ${c.target} closed without exchanging data (unclassified: may be a rejected certificate or an aborted request)`,
      evidence: c.evidence.map((i) => ptr(events, i)),
      detail: { target: c.target },
    });
  }
  return out;
}

export function runHeuristics(events: TattleEvent[], optsIn?: AnalyzeOptions, conns?: Conn[]): Finding[] {
  const cs = conns ?? buildConns(events);
  return [...rawIpConnections(events, cs), ...oddTldDns(events), ...txtBurst(events, optsIn), ...longLivedHighWrite(events, cs, optsIn), ...tlsNoData(events, cs, optsIn)];
}
