/** Terminal summary block for an Analysis (boxed, 80-col friendly). */
import type { Analysis, Severity } from '../analyze/index.js';
import { createStyle, truncate, type Style } from './ansi.js';

export const POSTURE = 'events captured in-process, nothing left this machine';

export function formatBytes(n: number): string {
  if (n < 1024) return `${n} B`;
  const u = ['KB', 'MB', 'GB', 'TB'];
  let v = n / 1024;
  let i = 0;
  while (v >= 1024 && i < u.length - 1) {
    v /= 1024;
    i++;
  }
  return `${v.toFixed(v < 10 ? 1 : 0)} ${u[i]}`;
}

export interface HostTally {
  good: number;
  telemetry: number;
  unknown: number;
  local: number;
}
/** Distinct-host tally. Loopback hosts analysed via --include-local count as "local"; raw-ip as unknown. */
export function hostTally(a: Pick<Analysis, 'hosts'>): HostTally {
  const t: HostTally = { good: 0, telemetry: 0, unknown: 0, local: 0 };
  for (const h of a.hosts) {
    if (h.class === 'good') t.good++;
    else if (h.class === 'telemetry') t.telemetry++;
    else if (h.class === 'local' || h.local) t.local++;
    else t.unknown++;
  }
  return t;
}

export interface SummaryOpts {
  style?: Style;
  unicode?: boolean;
  /** terminal columns; clamped to 40..80 */
  width?: number;
  max?: number;
  receiptId?: string;
  receiptDir?: string;
  cardPath?: string;
}

const SEV_ORDER: Severity[] = ['critical', 'high', 'medium', 'low', 'info'];
export const sevRank = (s: Severity): number => SEV_ORDER.indexOf(s);

export function verdictLine(a: Analysis, id?: string, style: Style = createStyle(false)): string {
  return `tattle: ${style.verdict(a.verdict, a.verdict)}${id ? ` (${id})` : ''}`;
}

export function renderSummary(a: Analysis, opts: SummaryOpts = {}): string {
  const st = opts.style ?? createStyle(false);
  const uni = opts.unicode ?? true;
  const max = opts.max ?? 5;
  const width = Math.max(40, Math.min(opts.width ?? 80, 80));
  const inner = width - 4;
  const ch = uni ? { tl: '┌', tr: '┐', bl: '└', br: '┘', h: '─', v: '│', dot: '·' } : { tl: '+', tr: '+', bl: '+', br: '+', h: '-', v: '|', dot: '-' };
  const lines: string[] = [];
  type Part = [string, ((s: string) => string)?];
  const row = (...parts: Part[]) => {
    let plain = parts.map((p) => p[0]).join('');
    let body: string;
    if (plain.length > inner) {
      plain = truncate(plain, inner, uni);
      body = plain;
    } else body = parts.map(([t, f]) => (f ? f(t) : t)).join('');
    lines.push(`${ch.v} ${body}${' '.repeat(inner - plain.length)} ${ch.v}`);
  };
  lines.push(ch.tl + ch.h + ' tattle ' + ch.h.repeat(width - 2 - 1 - 8) + ch.tr);

  const siren = a.verdict === 'ESCAPE CHAIN' && st.enabled && uni ? '\u{1F6A8} ' : '';
  const banner = ` ${a.verdict} `;
  const score = `score ${a.score}/100`;
  const sirenW = siren ? 3 : 0; // emoji renders two cells wide
  const gap = Math.max(1, inner - banner.length - score.length - sirenW);
  lines.push(`${ch.v} ${siren}${st.banner(a.verdict, banner)}${' '.repeat(gap)}${st.dim(score)} ${ch.v}`);
  const s = a.stats;
  row([`${s.events} events ${ch.dot} ${s.pids} process${s.pids === 1 ? '' : 'es'} ${ch.dot} ${formatBytes(s.bytesUp)} up ${ch.dot} ${formatBytes(s.bytesDown)} down`, st.dim]);
  row(['']);
  if (a.reasons.length === 0) row(['no findings', st.green]);
  else {
    row(['Top findings', st.bold]);
    const isCov = (code: string) => code === 'NOT_OBSERVED' || code === 'PARTIAL_COVERAGE';
    for (const r of [...a.reasons.filter((x) => isCov(x.code)), ...a.reasons.filter((x) => !isCov(x.code))].slice(0, max)) {
      if (isCov(r.code)) {
        let rest = r.text;
        const w = inner - 8;
        let first = true;
        while (rest.length) {
          let cut = rest.length <= w ? rest.length : rest.lastIndexOf(' ', w);
          if (cut <= 0) cut = Math.min(w, rest.length);
          row([first ? '  [note] ' : '         ', st.dim], [rest.slice(0, cut).trim()]);
          rest = rest.slice(cut).trim();
          first = false;
        }
        continue;
      }
      const tag = `[${r.severity}]`;
      const color = r.severity === 'critical' || r.severity === 'high' ? st.red : r.severity === 'medium' ? st.yellow : st.dim;
      row(['  ' + tag + ' ', color], [r.text]);
    }
    if (a.reasons.length > max) row([`  ... and ${a.reasons.length - max} more in receipt.json`, st.dim]);
  }
  row(['']);
  const t = hostTally(a);
  row(['Hosts      ', st.bold], [`good ${t.good}  telemetry ${t.telemetry}  unknown ${t.unknown}  local ${t.local}`]);
  row(['Sensitive  ', st.bold], [`${a.sensitiveReads.length} read${a.sensitiveReads.length === 1 ? '' : 's'}`], ['   Chains  ', st.bold], [String(a.chains.length)], ...((a.probes?.length ?? 0) ? [['   Probed  ', st.bold] as [string, any], [`${a.probes.length} (not found)`] as [string]] : []));
  if (opts.receiptId) {
    row(['Receipt    ', st.bold], [opts.receiptId]);
    row(['Verify     ', st.bold], [`tattle verify ${opts.receiptId}`, st.cyan]);
  }
  row(['']);
  row([POSTURE, st.dim]);
  lines.push(ch.bl + ch.h.repeat(width - 2) + ch.br);
  if (opts.receiptDir) lines.push(`receipt: ${opts.receiptDir}`);
  if (opts.cardPath) lines.push(`card:    ${opts.cardPath}`);
  return lines.join('\n');
}
