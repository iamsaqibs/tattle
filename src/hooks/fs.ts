/**
 * Filesystem hooks. Every public entry point is patched individually (callback / sync /
 * promises / streams) because they do NOT route through each other (verified, ADR-001).
 *
 * One user action = one event: nested hooked calls made by Node internals are suppressed
 * with a depth counter (ctx.callOrig); the async `open` that streams issue on nextTick is
 * suppressed with a per-path counter.
 */
import fs from 'node:fs';
import path from 'node:path';
import { fileURLToPath } from 'node:url';
import { nowMs, type EventInput } from '../events.js';
import { matchSensitive } from '../sensitive.js';
import { callOrig, emit, guarded, nested } from './ctx.js';
import { patch } from './patch.js';

/** Count of non-sensitive module-loader style events we did not emit (reported at exit). */
export const elided = { fs: 0 };

// Resolve relative paths against the real cwd. Captured before process.cwd is patched.
const realCwd = process.cwd.bind(process);
const isWin = process.platform === 'win32';

export function toAbs(p: unknown): string | null {
  try {
    let s: string;
    if (typeof p === 'string') s = p;
    else if (p instanceof URL) s = fileURLToPath(p);
    else if (Buffer.isBuffer(p)) s = p.toString();
    else return null; // fd numbers etc.
    if (s === '') return null;
    // fast path (posix): already absolute and canonical => no resolve/normalize work
    if (!isWin && s.charCodeAt(0) === 47 && !s.includes('/.') && !s.includes('//') && s.charCodeAt(s.length - 1) !== 47) return s;
    return path.isAbsolute(s) ? path.normalize(s) : path.resolve(realCwd(), s);
  } catch {
    return null;
  }
}

/** Module-loader / dependency noise: source files and anything under node_modules. */
function isNoise(abs: string, op: string): boolean {
  if (op === 'write' || op === 'delete' || op === 'rename') return false;
  return /[\\/]node_modules[\\/]/.test(abs) || /\.(?:c|m)?js$|\.node$|\.wasm$/i.test(abs);
}

function errCode(e: unknown): string | undefined {
  const c = (e as { code?: unknown } | null)?.code;
  return typeof c === 'string' ? c : e ? 'ERR' : undefined;
}

interface RecordOpts {
  bytes?: number;
  detail?: Record<string, unknown>;
  ts?: number;
  /** secondary path checked for sensitivity (rename/copy destination) */
  alt?: unknown;
}

function record(op: string, rawPath: unknown, o: RecordOpts = {}): void {
  const abs = toAbs(rawPath);
  if (!abs) return;
  let m = matchSensitive(abs);
  let altAbs: string | null = null;
  if (o.alt !== undefined) {
    altAbs = toAbs(o.alt);
    if (!m && altAbs) m = matchSensitive(altAbs);
  }
  if (!m && isNoise(abs, op)) {
    elided.fs++;
    return;
  }
  const detail: Record<string, unknown> = { ...(o.detail ?? {}) };
  if (altAbs) detail.to = altAbs;
  if (m) {
    detail.rule = m.rule;
    detail.label = m.label;
    detail.severity = m.severity;
    detail.category = m.category;
  }
  const ev: EventInput = { cat: 'fs', op, target: abs };
  if (o.ts !== undefined) ev.ts = o.ts;
  if (o.bytes !== undefined) ev.bytes = o.bytes;
  if (m) ev.verdictHint = 'sensitive';
  if (Object.keys(detail).length) ev.detail = detail;
  emit(ev);
}

function byteLen(d: unknown, enc?: unknown): number | undefined {
  if (typeof d === 'string') return Buffer.byteLength(d, typeof enc === 'string' ? (enc as BufferEncoding) : 'utf8');
  if (d && typeof (d as ArrayBufferView).byteLength === 'number') return (d as ArrayBufferView).byteLength;
  return undefined;
}

function optEnc(o: unknown): unknown {
  return typeof o === 'string' ? o : (o as { encoding?: unknown } | undefined)?.encoding;
}

function openIntent(flags: unknown): 'read' | 'write' {
  if (flags === undefined || flags === null) return 'read';
  if (typeof flags === 'number') return (flags & 3) === 0 ? 'read' : 'write';
  return /^(?:r|rs|sr)$/.test(String(flags)) ? 'read' : 'write';
}

// ---- streams: the internal async open() must not double-count -------------------------------------
const streamOpens = new Map<string, number>();
function takeStreamOpen(abs: string | null): boolean {
  if (!abs) return false;
  const n = streamOpens.get(abs);
  if (!n) return false;
  if (n <= 1) streamOpens.delete(abs);
  else streamOpens.set(abs, n - 1);
  return true;
}

const pendingStreams = new Set<(partial: boolean) => void>();
/** Flush streams still open at exit (partial byte counts). */
export function flushOpenStreams(): void {
  guarded(() => {
    for (const f of [...pendingStreams]) f(true);
  });
}

// ---- generic wrappers ---------------------------------------------------------------------------------

type BytesFn = (args: any[], result: unknown) => number | undefined;

function wrapSync(mod: any, name: string, op: string, o: { pathArg?: number; altArg?: number; bytes?: BytesFn; opFn?: (a: any[]) => string } = {}): void {
  const pi = o.pathArg ?? 0;
  patch(mod, name, (orig) => function (this: any, ...a) {
    if (nested()) return orig.apply(this, a);
    let result: unknown;
    let err: unknown;
    let threw = false;
    try {
      result = callOrig(orig, this, a);
    } catch (e) {
      threw = true;
      err = e;
    }
    guarded(() => {
      const code = threw ? errCode(err) : undefined;
      record(o.opFn ? o.opFn(a) : op, a[pi], {
        bytes: threw ? undefined : o.bytes?.(a, result),
        detail: { via: name, ...(code ? { error: code } : {}) },
        alt: o.altArg !== undefined ? a[o.altArg] : undefined,
      });
    });
    if (threw) throw err;
    return result;
  });
}

function wrapCb(mod: any, name: string, op: string, o: { pathArg?: number; altArg?: number; bytes?: BytesFn; resultBytes?: boolean; opFn?: (a: any[]) => string } = {}): void {
  const pi = o.pathArg ?? 0;
  patch(mod, name, (orig) => function (this: any, ...a) {
    if (nested()) return orig.apply(this, a);
    const ci = a.length - 1;
    const cb = a[ci];
    const opName = o.opFn ? o.opFn(a) : op;
    if (o.resultBytes && typeof cb === 'function') {
      // readFile(cb): emit at completion so we can report bytes; ts stays the call time.
      const ts = nowMs();
      a[ci] = function (this: any, err: unknown, data: unknown) {
        guarded(() => {
          const code = errCode(err);
          record(opName, a[pi], { ts, bytes: err ? undefined : byteLen(data), detail: { via: name, ...(code ? { error: code } : {}) } });
        });
        return cb.apply(this, arguments as any);
      };
    } else {
      guarded(() => record(opName, a[pi], { bytes: o.bytes?.(a, undefined), detail: { via: name }, alt: o.altArg !== undefined ? a[o.altArg] : undefined }));
    }
    return callOrig(orig, this, a);
  });
}

function wrapPromise(mod: any, name: string, op: string, o: { pathArg?: number; altArg?: number; bytes?: BytesFn; resultBytes?: boolean; opFn?: (a: any[]) => string } = {}): void {
  const pi = o.pathArg ?? 0;
  patch(mod, name, (orig) => function (this: any, ...a) {
    if (nested()) return orig.apply(this, a);
    const opName = o.opFn ? o.opFn(a) : op;
    const ts = nowMs();
    const p = callOrig(orig, this, a);
    if (o.resultBytes && p && typeof p.then === 'function') {
      // Return the DERIVED promise so unhandled-rejection semantics are preserved.
      return p.then(
        (r: unknown) => {
          guarded(() => record(opName, a[pi], { ts, bytes: byteLen(r), detail: { via: `promises.${name}` } }));
          return r;
        },
        (e: unknown) => {
          guarded(() => record(opName, a[pi], { ts, detail: { via: `promises.${name}`, error: errCode(e) } }));
          throw e;
        },
      );
    }
    guarded(() => record(opName, a[pi], { ts, bytes: o.bytes?.(a, undefined), detail: { via: `promises.${name}` }, alt: o.altArg !== undefined ? a[o.altArg] : undefined }));
    return p;
  });
}

export function installFsHooks(): void {
  const fsp: any = (fs as any).promises;
  const dataBytes: BytesFn = (a) => byteLen(a[1], optEnc(a[2]));
  const readBytes: BytesFn = (_a, r) => byteLen(r);
  const openOp = (a: any[]) => openIntent(a[1]);

  // reads
  wrapSync(fs, 'readFileSync', 'read', { bytes: readBytes });
  wrapCb(fs, 'readFile', 'read', { resultBytes: true });
  wrapPromise(fsp, 'readFile', 'read', { resultBytes: true });
  // writes
  for (const n of ['writeFileSync', 'appendFileSync']) wrapSync(fs, n, 'write', { bytes: dataBytes });
  for (const n of ['writeFile', 'appendFile']) wrapCb(fs, n, 'write', { bytes: dataBytes });
  for (const n of ['writeFile', 'appendFile']) wrapPromise(fsp, n, 'write', { bytes: dataBytes });
  // stat family
  for (const n of ['statSync', 'lstatSync', 'existsSync', 'accessSync']) wrapSync(fs, n, 'stat');
  for (const n of ['stat', 'lstat', 'access']) wrapCb(fs, n, 'stat');
  for (const n of ['stat', 'lstat', 'access']) wrapPromise(fsp, n, 'stat');
  // directory listings
  wrapSync(fs, 'readdirSync', 'readdir');
  wrapCb(fs, 'readdir', 'readdir');
  wrapPromise(fsp, 'readdir', 'readdir');
  // deletes / renames / copies
  for (const n of ['unlinkSync', 'rmSync', 'rmdirSync']) wrapSync(fs, n, 'delete');
  for (const n of ['unlink', 'rm', 'rmdir']) wrapCb(fs, n, 'delete');
  for (const n of ['unlink', 'rm', 'rmdir']) wrapPromise(fsp, n, 'delete');
  wrapSync(fs, 'renameSync', 'rename', { altArg: 1 });
  wrapCb(fs, 'rename', 'rename', { altArg: 1 });
  wrapPromise(fsp, 'rename', 'rename', { altArg: 1 });
  wrapSync(fs, 'copyFileSync', 'copy', { altArg: 1 });
  wrapCb(fs, 'copyFile', 'copy', { altArg: 1 });
  wrapPromise(fsp, 'copyFile', 'copy', { altArg: 1 });

  // open: intent from flags; stream-internal opens are suppressed
  patch(fs, 'openSync', (orig) => function (this: any, ...a) {
    if (nested()) return orig.apply(this, a);
    let r: unknown;
    let err: unknown;
    let threw = false;
    try {
      r = callOrig(orig, this, a);
    } catch (e) {
      threw = true;
      err = e;
    }
    guarded(() => record(openOp(a), a[0], { detail: { via: 'openSync', flags: String(a[1] ?? 'r'), ...(threw ? { error: errCode(err) } : {}) } }));
    if (threw) throw err;
    return r;
  });
  patch(fs, 'open', (orig) => function (this: any, ...a) {
    if (!nested()) {
      guarded(() => {
        const abs = toAbs(a[0]);
        if (takeStreamOpen(abs)) return;
        record(openOp(a), a[0], { detail: { via: 'open', flags: String(typeof a[1] === 'function' ? 'r' : a[1] ?? 'r') } });
      });
    }
    return callOrig(orig, this, a);
  });
  patch(fsp, 'open', (orig) => function (this: any, ...a) {
    if (!nested()) guarded(() => record(openOp(a), a[0], { detail: { via: 'promises.open', flags: String(a[1] ?? 'r') } }));
    return callOrig(orig, this, a);
  });

  // streams: one event at close with exact stream byte counts
  for (const [name, op, counter] of [['createReadStream', 'read', 'bytesRead'], ['createWriteStream', 'write', 'bytesWritten']] as const) {
    patch(fs, name, (orig) => function (this: any, ...a) {
      const s = callOrig(orig, this, a);
      guarded(() => {
        const p = (s as any)?.path ?? a[0];
        const abs = toAbs(p);
        if (!abs) return;
        streamOpens.set(abs, (streamOpens.get(abs) ?? 0) + 1);
        const ts = nowMs();
        let done = false;
        const finish = (partial: boolean) => {
          if (done) return;
          done = true;
          pendingStreams.delete(finish);
          record(op, abs, { ts, bytes: (s as any)[counter], detail: { via: name, ...(partial ? { partial: true } : {}) } });
        };
        pendingStreams.add(finish);
        (s as any).once('close', () => guarded(() => finish(false)));
      });
      return s;
    });
  }
}
