/**
 * Receipt card: hand-written 1200x630 SVG (no satori, zero deps; see docs/adr-002-card.md).
 * PNG is produced only when the optional dependency @resvg/resvg-js is importable.
 */
import fs from 'node:fs';
import path from 'node:path';
import type { Analysis, Verdict } from '../analyze/index.js';
import { formatBytes, hostTally, POSTURE } from './summary.js';

export interface CardInput {
  analysis: Analysis;
  id: string;
  /** ISO timestamp shown on the card */
  timestamp: string;
  argv: string[];
}

export const CARD_W = 1200;
export const CARD_H = 630;

const SANS = "ui-sans-serif, -apple-system, 'Segoe UI', Helvetica, Arial, sans-serif";
const MONO = "ui-monospace, SFMono-Regular, Menlo, Consolas, 'Liberation Mono', monospace";

const VERDICT_COLOR: Record<Verdict, { bg: string; fg: string }> = {
  'NOT OBSERVED': { bg: '#6e7681', fg: '#ffffff' },
  CLEAN: { bg: '#2ea043', fg: '#ffffff' },
  'PHONING HOME': { bg: '#e3b341', fg: '#1b1f24' },
  'READING SECRETS': { bg: '#db6d28', fg: '#ffffff' },
  'ESCAPE CHAIN': { bg: '#da3633', fg: '#ffffff' },
};
const SEV_COLOR: Record<string, string> = { critical: '#ff6a69', high: '#ff7b72', medium: '#e3b341', low: '#8b949e', info: '#6e7681' };
const HOST_COLOR = { good: '#2ea043', telemetry: '#e3b341', unknown: '#db6d28', local: '#6e7681' };

export function xmlEscape(s: string): string {
  return String(s)
    .replace(/[\u0000-\u0008\u000b\u000c\u000e-\u001f\u007f￾￿]/g, '?')
    .replace(/&/g, '&amp;')
    .replace(/</g, '&lt;')
    .replace(/>/g, '&gt;')
    .replace(/"/g, '&quot;')
    .replace(/'/g, '&apos;');
}

const clip = (s: string, n: number) => (s.length <= n ? s : s.slice(0, Math.max(0, n - 1)) + '…');
const flat = (s: string) => s.replace(/\s+/g, ' ').trim();

function text(x: number, y: number, size: number, fill: string, body: string, extra = ''): string {
  return `<text x="${x}" y="${y}" font-size="${size}" fill="${fill}" ${extra}>${xmlEscape(body)}</text>`;
}

export function renderCardSvg(input: CardInput): string {
  const a = input.analysis;
  const vc = VERDICT_COLOR[a.verdict] ?? VERDICT_COLOR.CLEAN;
  const o: string[] = [];
  o.push(`<svg xmlns="http://www.w3.org/2000/svg" width="${CARD_W}" height="${CARD_H}" viewBox="0 0 ${CARD_W} ${CARD_H}" role="img" aria-label="${xmlEscape(`Tattle receipt: ${a.verdict}`)}">`);
  o.push(`<defs><marker id="ar" viewBox="0 0 10 10" refX="9" refY="5" markerWidth="8" markerHeight="8" orient="auto"><path d="M0 0L10 5L0 10z" fill="#8b949e"/></marker></defs>`);
  o.push(`<g font-family="${xmlEscape(SANS)}">`);
  o.push(`<rect width="${CARD_W}" height="${CARD_H}" fill="#0d1117"/>`);
  // verdict banner
  o.push(`<rect width="${CARD_W}" height="140" fill="${vc.bg}"/>`);
  o.push(text(48, 98, 84, vc.fg, a.verdict, 'font-weight="800" letter-spacing="1"'));
  o.push(text(1152, 64, 36, vc.fg, `score ${a.score}/100`, 'text-anchor="end" font-weight="700"'));
  o.push(text(1152, 110, 26, vc.fg, `TATTLE  ${a.stats.events} events`, 'text-anchor="end" opacity="0.85" letter-spacing="2"'));
  // tool line
  o.push(text(48, 186, 26, '#8b949e', '$ ' + clip(flat(input.argv.join(' ')), 70), `font-family="${xmlEscape(MONO)}"`));

  // findings (left column)
  o.push(text(48, 236, 20, '#8b949e', 'TOP FINDINGS', 'letter-spacing="3" font-weight="700"'));
  const isCov = (code: string) => code === 'NOT_OBSERVED' || code === 'PARTIAL_COVERAGE';
  const top = [...a.reasons.filter((r) => isCov(r.code)), ...a.reasons.filter((r) => !isCov(r.code))].slice(0, 5);
  if (top.length === 0) o.push(text(48, 282, 28, '#3fb950', 'Nothing suspicious observed.', 'font-weight="600"'));
  let row = 0;
  for (const r of top) {
    const y = 282 + row * 42;
    o.push(`<circle cx="58" cy="${y - 9}" r="8" fill="${SEV_COLOR[r.severity] ?? '#8b949e'}"/>`);
    if (isCov(r.code)) {
      // coverage notes are the point of the card: wrap instead of clipping
      const words = flat(r.text).split(' ');
      const ls: string[] = [];
      for (const w of words) (ls.length && ls[ls.length - 1]!.length + w.length < 50 ? (ls[ls.length - 1] += ' ' + w) : ls.push(w));
      for (const l of ls.slice(0, 4)) o.push(text(80, 282 + row++ * 42, 26, '#e6edf3', l));
    } else {
      o.push(text(80, y, 26, '#e6edf3', clip(flat(r.text), 54)));
      row++;
    }
  }
  if (a.reasons.length > top.length && row < 6) o.push(text(80, 282 + row * 42 - 4, 20, '#8b949e', `+${a.reasons.length - top.length} more in receipt.json`));

  // right column: stats
  const rx = 760;
  const sens = a.sensitiveReads.length;
  o.push(text(rx, 236, 20, '#8b949e', 'SENSITIVE', 'letter-spacing="3" font-weight="700"'));
  o.push(text(rx, 306, 76, sens > 0 ? '#ff7b72' : '#e6edf3', String(sens), 'font-weight="800"'));
  o.push(text(rx + 200, 236, 20, '#8b949e', 'CHAINS', 'letter-spacing="3" font-weight="700"'));
  o.push(text(rx + 200, 306, 76, a.chains.length > 0 ? '#ff7b72' : '#e6edf3', String(a.chains.length), 'font-weight="800"'));
  // host tally bar
  const t = hostTally(a);
  const total = t.good + t.telemetry + t.unknown + t.local;
  o.push(text(rx, 352, 20, '#8b949e', total ? `HOSTS (${total})` : 'HOSTS', 'letter-spacing="3" font-weight="700"'));
  const bw = 392;
  o.push(`<rect x="${rx}" y="366" width="${bw}" height="28" rx="6" fill="#21262d"/>`);
  if (total > 0) {
    let x = rx;
    for (const k of ['good', 'telemetry', 'unknown', 'local'] as const) {
      if (!t[k]) continue;
      const w = Math.max(6, Math.round((t[k] / total) * bw));
      o.push(`<rect x="${x}" y="366" width="${Math.min(w, rx + bw - x)}" height="28" fill="${HOST_COLOR[k]}"/>`);
      x += w;
    }
  }
  (['good', 'telemetry', 'unknown', 'local'] as const).forEach((k, i) => {
    const lx = rx + (i % 2) * 200;
    const ly = 424 + Math.floor(i / 2) * 30;
    o.push(`<rect x="${lx}" y="${ly - 16}" width="16" height="16" rx="3" fill="${HOST_COLOR[k]}"/>`);
    o.push(text(lx + 26, ly, 22, '#e6edf3', `${k} ${t[k]}`));
  });

  // escape-chain mini-graph (file -> bytes -> host)
  const c = a.chains[0];
  const gy = 492;
  if (c) {
    const src = c.sources[0];
    const srcLabel = src ? (src.kind === 'clipboard' ? 'clipboard' : path.basename(src.target) || src.target) : '?';
    const bytes = c.sink.bytesWritten !== undefined ? formatBytes(c.sink.bytesWritten) : c.sink.kind === 'proc' ? 'spawn' : '? bytes';
    const node = (x: number, w: number, label: string, stroke: string, mono = true) =>
      `<rect x="${x}" y="${gy}" width="${w}" height="52" rx="10" fill="#161b22" stroke="${stroke}" stroke-width="3"/>` +
      text(x + w / 2, gy + 35, 24, '#e6edf3', clip(label, Math.floor(w / 14)), `text-anchor="middle"${mono ? ` font-family="${xmlEscape(MONO)}"` : ''}`);
    o.push(node(48, 330, srcLabel, '#db6d28'));
    o.push(`<line x1="384" y1="${gy + 26}" x2="436" y2="${gy + 26}" stroke="#8b949e" stroke-width="3" marker-end="url(#ar)"/>`);
    o.push(node(444, 200, bytes, '#8b949e', false));
    o.push(`<line x1="650" y1="${gy + 26}" x2="702" y2="${gy + 26}" stroke="#8b949e" stroke-width="3" marker-end="url(#ar)"/>`);
    o.push(node(710, 330, c.sink.host, '#da3633'));
    if (a.chains.length > 1) o.push(text(1060, gy + 33, 22, '#8b949e', `+${a.chains.length - 1} more`));
  } else {
    o.push(text(48, gy + 34, 24, '#8b949e', 'No escape chain: no sensitive read followed by an outbound write.'));
  }

  // footer
  o.push(`<line x1="48" y1="560" x2="1152" y2="560" stroke="#30363d" stroke-width="2"/>`);
  o.push(text(48, 592, 24, '#e6edf3', `${input.id}  ·  ${input.timestamp.replace('T', ' ').replace(/\.\d+Z$/, 'Z').replace(/:\d\dZ$/, ' UTC')}`, `font-family="${xmlEscape(MONO)}"`));
  o.push(text(1152, 592, 24, '#58a6ff', `tattle verify ${input.id}`, `text-anchor="end" font-family="${xmlEscape(MONO)}"`));
  o.push(text(48, 618, 18, '#8b949e', POSTURE));
  o.push('</g></svg>');
  return o.join('\n') + '\n';
}

/** PNG via the optional @resvg/resvg-js dependency; null when it is not installed or fails. */
export async function renderCardPng(svg: string): Promise<Buffer | null> {
  try {
    const name = '@resvg/resvg-js';
    const mod: any = await import(name);
    const Resvg = mod.Resvg ?? mod.default?.Resvg;
    if (!Resvg) return null;
    const r = new Resvg(svg, { fitTo: { mode: 'width', value: CARD_W }, font: { loadSystemFonts: true } });
    return Buffer.from(r.render().asPng());
  } catch {
    return null;
  }
}

export async function writeCard(dir: string, input: CardInput): Promise<{ svg: string; png?: string }> {
  const svg = renderCardSvg(input);
  const svgPath = path.join(dir, 'card.svg');
  fs.writeFileSync(svgPath, svg);
  const png = await renderCardPng(svg);
  if (png) {
    const pngPath = path.join(dir, 'card.png');
    fs.writeFileSync(pngPath, png);
    return { svg: svgPath, png: pngPath };
  }
  return { svg: svgPath };
}
