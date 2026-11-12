/** `--watch`: tail the JSONL event log while the child runs and print one line per event to stderr. */
import fs from 'node:fs';
import { parseEventLine, type TattleEvent } from '../events.js';
import { truncate, type Style } from './ansi.js';

const NOISE_OPS = new Set(['dns/lookup', 'dns/resolve', 'fs/stat', 'fs/readdir', 'env/read', 'env/cwd', 'life/start', 'life/exit']);

export function formatEvent(e: TattleEvent, style: Style, width: number, unicode = true): string {
  const d = new Date(e.ts);
  const pad = (n: number, w = 2) => String(n).padStart(w, '0');
  const time = `${pad(d.getHours())}:${pad(d.getMinutes())}:${pad(d.getSeconds())}.${pad(d.getMilliseconds(), 3)}`;
  const kind = `${e.cat}/${e.op}`;
  const bytes = typeof e.bytes === 'number' ? ` ${e.bytes}B` : '';
  const flag = e.verdictHint === 'escape' ? ' !!' : e.verdictHint === 'sensitive' ? ' !' : '';
  const prefix = `${time} ${String(e.pid).padStart(5)} ${kind.padEnd(14)} `;
  const room = Math.max(8, width - prefix.length - 1);
  const rest = truncate(`${e.target}${bytes}${flag}`, room, unicode);
  const line = prefix + rest;
  if (e.verdictHint === 'escape') return style.red(style.bold(line));
  if (e.verdictHint === 'sensitive') return style.yellow(line);
  if (e.verdictHint === 'noise' || NOISE_OPS.has(kind)) return style.dim(line);
  return line;
}

export interface Ticker {
  /** read whatever is new, print it; call once more after the child exits */
  drain(): void;
  stop(): void;
}

export function startTicker(file: string, write: (s: string) => void, style: Style, width: number, unicode: boolean): Ticker {
  let offset = 0;
  let carry: Buffer = Buffer.alloc(0);
  const drain = () => {
    let fd: number | undefined;
    try {
      fd = fs.openSync(file, 'r');
      const size = fs.fstatSync(fd).size;
      if (size < offset) {
        offset = 0; // rotated
        carry = Buffer.alloc(0);
      }
      if (size === offset) return;
      const buf = Buffer.alloc(size - offset);
      const n = fs.readSync(fd, buf, 0, buf.length, offset);
      offset += n;
      const all = Buffer.concat([carry, buf.subarray(0, n)]);
      const nl = all.lastIndexOf(10);
      if (nl < 0) {
        carry = all;
        return;
      }
      carry = all.subarray(nl + 1);
      for (const p of all.subarray(0, nl).toString('utf8').split('\n')) {
        const e = p ? parseEventLine(p) : null;
        if (e) write(formatEvent(e, style, width, unicode) + '\n');
      }
    } catch {
      /* file not there yet */
    } finally {
      if (fd !== undefined) fs.closeSync(fd);
    }
  };
  const timer = setInterval(drain, 80);
  return {
    drain,
    stop() {
      clearInterval(timer);
      drain();
    },
  };
}
