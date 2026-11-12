/**
 * Tattle preload. Loaded into every node process of a `tattle run` via NODE_OPTIONS=--import.
 * Does nothing unless TATTLE_LOG is set. Order matters:
 *   1. the writer captures original fs functions (module evaluation of events.ts, already done)
 *   2. hooks are installed
 *   3. syncBuiltinESMExports() so ESM named imports (`import {readFileSync} from 'node:fs'`) see the patches
 */
import { syncBuiltinESMExports } from 'node:module';
import { isMainThread, threadId } from 'node:worker_threads';
import { createEventWriter, DEFAULT_MAX_BYTES } from './events.js';
import { setWriter, emit } from './hooks/ctx.js';
import { installEnvHooks } from './hooks/env.js';
import { elided, flushOpenStreams, installFsHooks } from './hooks/fs.js';
import { flushOpenSockets, installNetHooks } from './hooks/net.js';
import { installProcHooks } from './hooks/proc.js';
import { patch } from './hooks/patch.js';

const INSTALLED = Symbol.for('tattle.preload.installed');

function install(): void {
  const g = globalThis as any;
  const logPath = process.env.TATTLE_LOG;
  if (!logPath || g[INSTALLED]) return;
  g[INSTALLED] = true;

  const maxBytes = Number(process.env.TATTLE_LOG_MAX_BYTES) || DEFAULT_MAX_BYTES;
  const writer = createEventWriter(logPath, { phase: 'run', maxBytes });
  setWriter(writer);

  // Snapshot what we need for lifecycle events BEFORE patching anything.
  const argv = process.argv.slice();
  const cwd = process.cwd();
  const startDetail = {
    argv,
    cwd,
    isTTY: { stdin: !!process.stdin?.isTTY, stdout: !!process.stdout?.isTTY, stderr: !!process.stderr?.isTTY },
    node: process.version,
    platform: process.platform,
    execArgv: process.execArgv,
    thread: isMainThread ? 'main' : `worker:${threadId}`,
    ...(process.env.TATTLE_RUN_ID ? { runId: process.env.TATTLE_RUN_ID } : {}),
  };

  // Debugging switch: TATTLE_DISABLE=net,fs,env,proc skips those hook groups (bisecting breakage).
  const disabled = new Set((process.env.TATTLE_DISABLE ?? '').split(',').map((x) => x.trim().toLowerCase()).filter(Boolean));
  const all: Array<[string, () => void]> = [['fs', installFsHooks], ['net', installNetHooks], ['proc', installProcHooks], ['env', installEnvHooks]];
  const hooks = all.filter(([n]) => !disabled.has(n)).map(([, f]) => f);
  const failed: string[] = [];
  for (const h of hooks) {
    try {
      h();
    } catch (e) {
      failed.push(`${h.name}:${(e as Error)?.message}`);
    }
  }
  try {
    syncBuiltinESMExports();
  } catch {
    /* ignore */
  }

  emit({ cat: 'life', op: 'start', target: argv[1] ?? argv[0] ?? '', detail: { ...startDetail, ...(failed.length ? { hookErrors: failed } : {}) } });

  // Finalize AFTER the program's own 'exit' listeners have run (they may still touch fs/net, or set
  // process.exitCode). Registering our own 'exit' listener would run first and would also change
  // process.listenerCount('exit'), so wrap process.emit('exit') instead.
  let finalized = false;
  const finalize = (code: unknown): void => {
    if (finalized) return;
    finalized = true;
    try {
      flushOpenStreams();
      flushOpenSockets();
      emit({ cat: 'life', op: 'exit', target: argv[1] ?? argv[0] ?? '', detail: { code: process.exitCode ?? code, elidedFs: elided.fs } });
    } catch {
      /* never throw from exit */
    }
    try {
      writer.close();
    } catch {
      /* ignore */
    }
  };
  const realEmit = process.emit;
  const patched = patch(process, 'emit', (orig) => function (this: any, ev: any, ...rest: any[]) {
    if (ev !== 'exit') return orig.call(this, ev, ...rest);
    try {
      return orig.call(this, ev, ...rest);
    } finally {
      finalize(rest[0]);
    }
  });
  if (!patched || process.emit === realEmit) process.on('exit', (code) => finalize(code));
}

try {
  install();
} catch {
  /* a failing observer must never break the observed tool */
}
