/** Hand-rolled ANSI styling (zero deps). Honors --no-color, NO_COLOR, FORCE_COLOR and non-TTY streams. */
import type { Verdict } from '../analyze/types.js';

export interface ColorOpts {
  /** --no-color */
  noColor?: boolean;
  stream?: { isTTY?: boolean };
  env?: NodeJS.ProcessEnv;
}

export function detectColor(opts: ColorOpts = {}): boolean {
  const env = opts.env ?? process.env;
  if (opts.noColor) return false;
  if (env.NO_COLOR !== undefined && env.NO_COLOR !== '') return false;
  const f = env.FORCE_COLOR;
  if (f !== undefined) return !(f === '0' || f.toLowerCase() === 'false');
  if (env.TERM === 'dumb') return false;
  return !!opts.stream?.isTTY;
}

export function supportsUnicode(env: NodeJS.ProcessEnv = process.env, platform: string = process.platform): boolean {
  const loc = `${env.LC_ALL ?? ''}${env.LC_CTYPE ?? ''}${env.LANG ?? ''}`;
  if (/utf-?8/i.test(loc)) return true;
  if (platform === 'win32') return !!(env.WT_SESSION || env.TERM_PROGRAM);
  return false;
}

export interface Style {
  enabled: boolean;
  bold(s: string): string;
  dim(s: string): string;
  red(s: string): string;
  green(s: string): string;
  yellow(s: string): string;
  cyan(s: string): string;
  gray(s: string): string;
  /** inverse banner in the verdict's color */
  banner(v: Verdict, s: string): string;
  /** foreground in the verdict's color */
  verdict(v: Verdict, s: string): string;
}

export function createStyle(enabled: boolean): Style {
  const w = (open: string, close: string) => (s: string) => (enabled ? `\x1b[${open}m${s}\x1b[${close}m` : s);
  const bold = w('1', '22');
  const dim = w('2', '22');
  const red = w('31', '39');
  const green = w('32', '39');
  const yellow = w('33', '39');
  const cyan = w('36', '39');
  const gray = w('90', '39');
  const bg: Record<Verdict, string> = { 'NOT OBSERVED': '1;97;100', CLEAN: '1;30;42', 'PHONING HOME': '1;30;43', 'READING SECRETS': '1;97;45', 'ESCAPE CHAIN': '1;97;41' };
  const fg: Record<Verdict, (s: string) => string> = { 'NOT OBSERVED': gray, CLEAN: green, 'PHONING HOME': yellow, 'READING SECRETS': (s) => (enabled ? `\x1b[35m${s}\x1b[39m` : s), 'ESCAPE CHAIN': red };
  return {
    enabled,
    bold,
    dim,
    red,
    green,
    yellow,
    cyan,
    gray,
    banner: (v, s) => (enabled ? `\x1b[${bg[v]}m${s}\x1b[0m` : s),
    verdict: (v, s) => bold(fg[v](s)),
  };
}

const ANSI_RE = /\x1b\[[0-9;]*m/g;
export const stripAnsi = (s: string): string => s.replace(ANSI_RE, '');

/** Cut to `width` characters, ending with an ellipsis. Operates on plain text only. */
export function truncate(s: string, width: number, unicode = true): string {
  if (width <= 0) return '';
  if (s.length <= width) return s;
  const ell = unicode ? '…' : '...';
  return s.slice(0, Math.max(0, width - ell.length)) + ell;
}
