/**
 * Event schema v1 + append-only JSONL writer + forward-tolerant parser.
 * See docs/schema.md.
 *
 * IMPORTANT: this module is loaded by the preload BEFORE any patching. The writer therefore
 * captures the original fs functions at module-evaluation time and only ever uses those,
 * so writing an event can never produce an event.
 */
import fs from 'node:fs';
import path from 'node:path';
import { performance } from 'node:perf_hooks';

export const SCHEMA_VERSION = 1;

export type EventCat = 'net' | 'dns' | 'fs' | 'proc' | 'env' | 'clip' | 'life';
export type VerdictHint = 'sensitive' | 'escape' | 'noise';

export interface TattleEvent {
  /** schema version */
  v: number;
  /** ms since epoch (float, sub-ms precision) */
  ts: number;
  pid: number;
  ppid: number;
  /** per-process (per-thread) monotonically increasing counter */
  seq: number;
  /** "run" for `tattle run`; reserved for "install" etc. */
  phase: string;
  cat: EventCat;
  op: string;
  target: string;
  bytes?: number;
  verdictHint?: VerdictHint;
  detail?: Record<string, unknown>;
  /** future fields are preserved untouched */
  [k: string]: unknown;
}

export interface EventInput {
  cat: EventCat;
  op: string;
  target: string;
  /** override the timestamp (e.g. call time for events emitted at completion) */
  ts?: number;
  bytes?: number;
  verdictHint?: VerdictHint;
  detail?: Record<string, unknown>;
}

// ---- captured originals (never patched by us) -------------------------------------------
const real = {
  openSync: fs.openSync,
  writeSync: fs.writeSync,
  closeSync: fs.closeSync,
  fstatSync: fs.fstatSync,
  renameSync: fs.renameSync,
  existsSync: fs.existsSync,
  readFileSync: fs.readFileSync,
  readdirSync: fs.readdirSync,
  mkdirSync: fs.mkdirSync,
};
const realNow = performance.now.bind(performance);
const timeOrigin = performance.timeOrigin;
const realStringify = JSON.stringify;

/** Wall-clock ms with sub-ms precision. */
export function nowMs(): number {
  return timeOrigin + realNow();
}

export const DEFAULT_MAX_BYTES = 256 * 1024 * 1024;

export interface WriterOptions {
  phase?: string;
  /** rotate to events.N.jsonl when the file exceeds this many bytes */
  maxBytes?: number;
}

export interface EventWriter {
  emit(ev: EventInput): void;
  close(): void;
  readonly path: string;
}

/** Next free `<base>.N.<ext>` sibling, e.g. events.1.jsonl */
function rotatedName(file: string): string {
  const ext = path.extname(file);
  const base = file.slice(0, file.length - ext.length);
  for (let n = 1; ; n++) {
    const cand = `${base}.${n}${ext}`;
    if (!real.existsSync(cand)) return cand;
  }
}

/**
 * Append-only JSONL writer. One `writeSync` per event on an `O_APPEND` fd, so lines from
 * several processes sharing the file do not interleave mid-line (single write calls to a
 * local file opened with 'a' are atomic in practice).
 *
 * Rotation: every 128 events we fstat; when the file exceeds `maxBytes` it is renamed
 * (atomic) to events.N.jsonl and a fresh file is opened. Other processes keep their old fd
 * and finish writing into the rotated inode - no event is lost, ordering across files is by `ts`.
 */
export function createEventWriter(file: string, opts: WriterOptions = {}): EventWriter {
  const phase = opts.phase ?? 'run';
  const maxBytes = opts.maxBytes ?? DEFAULT_MAX_BYTES;
  const pid = process.pid;
  const ppid = process.ppid;
  let seq = 0;
  let fd: number | null = null;
  try {
    real.mkdirSync(path.dirname(file), { recursive: true });
    fd = real.openSync(file, 'a');
  } catch {
    fd = null;
  }

  function rotate(): void {
    try {
      const target = rotatedName(file);
      real.renameSync(file, target);
      if (fd !== null) real.closeSync(fd);
      fd = real.openSync(file, 'a');
    } catch {
      /* keep writing to the current fd */
    }
  }

  return {
    path: file,
    emit(ev) {
      if (fd === null) return;
      try {
        const full: TattleEvent = {
          v: SCHEMA_VERSION,
          ts: ev.ts ?? nowMs(),
          pid,
          ppid,
          seq: seq++,
          phase,
          cat: ev.cat,
          op: ev.op,
          target: ev.target,
        };
        if (ev.bytes !== undefined) full.bytes = ev.bytes;
        if (ev.verdictHint !== undefined) full.verdictHint = ev.verdictHint;
        if (ev.detail !== undefined) full.detail = ev.detail;
        real.writeSync(fd, realStringify(full) + '\n');
        if (seq % 128 === 0 && real.fstatSync(fd).size > maxBytes) rotate();
      } catch {
        /* never throw into user code */
      }
    },
    close() {
      try {
        if (fd !== null) real.closeSync(fd);
      } catch {
        /* ignore */
      }
      fd = null;
    },
  };
}

// ---- parsing -----------------------------------------------------------------------------

/**
 * Parse one JSONL line. Tolerant: unknown fields are preserved, versions newer than ours are
 * accepted (best effort), garbage returns null. Required: object with numeric `ts`, string `cat`,
 * `op`; a missing `target` becomes ''.
 */
export function parseEventLine(line: string): TattleEvent | null {
  const s = line.trim();
  if (!s) return null;
  let o: unknown;
  try {
    o = JSON.parse(s);
  } catch {
    return null;
  }
  if (!o || typeof o !== 'object' || Array.isArray(o)) return null;
  const r = o as Record<string, unknown>;
  if (typeof r.cat !== 'string' || typeof r.op !== 'string' || typeof r.ts !== 'number') return null;
  const ev = { ...r } as TattleEvent;
  if (typeof ev.v !== 'number') ev.v = 1;
  if (typeof ev.target !== 'string') ev.target = '';
  if (typeof ev.pid !== 'number') ev.pid = 0;
  if (typeof ev.ppid !== 'number') ev.ppid = 0;
  if (typeof ev.seq !== 'number') ev.seq = 0;
  if (typeof ev.phase !== 'string') ev.phase = 'run';
  return ev;
}

export function parseEvents(text: string): TattleEvent[] {
  const out: TattleEvent[] = [];
  for (const line of text.split('\n')) {
    const ev = parseEventLine(line);
    if (ev) out.push(ev);
  }
  return out;
}

/** Sort key: ts, then pid, then seq (stable across rotated files). */
export function compareEvents(a: TattleEvent, b: TattleEvent): number {
  return a.ts - b.ts || a.pid - b.pid || a.seq - b.seq;
}

/** Read events.jsonl plus any rotated events.N.jsonl siblings, merged and time-sorted. */
export function readEventLog(file: string): TattleEvent[] {
  const dir = path.dirname(file);
  const ext = path.extname(file);
  const stem = path.basename(file, ext);
  const files = [file];
  try {
    for (const name of real.readdirSync(dir)) {
      if (name.startsWith(stem + '.') && name.endsWith(ext) && /^\d+$/.test(name.slice(stem.length + 1, name.length - ext.length))) {
        files.push(path.join(dir, name));
      }
    }
  } catch {
    /* dir missing */
  }
  const all: TattleEvent[] = [];
  for (const f of files) {
    try {
      all.push(...parseEvents(real.readFileSync(f, 'utf8')));
    } catch {
      /* missing file */
    }
  }
  return all.sort(compareEvents);
}
