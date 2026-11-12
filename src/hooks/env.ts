/**
 * Environment surface. Replaces process.env with a Proxy that records the NAMES (never values)
 * of variables read through the JS `process.env` object, deduped, one event each.
 *
 * Real coverage (see docs/schema.md "Env coverage"):
 *  - seen: JS reads `process.env.X`, `'X' in process.env`, destructuring, Node-internal JS reads
 *  - NOT seen: native code / addons reading `environ`, `/proc/self/environ`, anything that ran
 *    before the preload, and worker threads' own copies.
 *  - enumeration (`{...process.env}`, Object.keys, child_process env copy) is reported once as
 *    env/enumerate; reads made in the same synchronous turn are treated as part of it.
 */
import { emit, guarded } from './ctx.js';
import { patch } from './patch.js';

const seen = new Set<string>();
const MAX_NAMES = 5000;
// Variables Node itself consults from JS during startup/inspection; tagged, not hidden.
const RUNTIME = new Set(['NODE_V8_COVERAGE', 'NODE_DEBUG', 'NODE_DEBUG_NATIVE', 'NODE_PENDING_DEPRECATION', 'NODE_NO_WARNINGS', 'NODE_PATH', 'NODE_OPTIONS', 'NO_COLOR', 'FORCE_COLOR', 'NODE_DISABLE_COLORS', 'NODE_EXTRA_CA_CERTS', 'NODE_TLS_REJECT_UNAUTHORIZED', 'NODE_NO_READLINE', 'NODE_REPL_HISTORY', 'TZ', 'NODE_ENV', 'WATCH_REPORT_DEPENDENCIES']);

let enumerating = false;
let enumEvents = 0;

function readName(name: string, via: string): void {
  if (name.startsWith('TATTLE_')) return;
  if (name in Object.prototype) return; // process.env.hasOwnProperty / toString probing is not a variable read
  if (seen.has(name) || seen.size >= MAX_NAMES) return;
  seen.add(name);
  guarded(() => emit({ cat: 'env', op: 'read', target: name, detail: { via, ...(RUNTIME.has(name) ? { runtime: true } : {}) } }));
}

export function installEnvHooks(): void {
  const real = process.env;
  const proxy = new Proxy(real, {
    get(t, k, r) {
      if (typeof k === 'string' && !enumerating) readName(k, 'get');
      return Reflect.get(t, k, typeof r === 'object' ? t : r);
    },
    // Without this trap, `process.env.X = v` runs OrdinarySet with Receiver = the proxy, which makes the
    // engine call proxy.[[DefineOwnProperty]](X, {value: v}) (a PARTIAL descriptor). Node's env object
    // rejects partial descriptors (ERR_INVALID_OBJECT_DEFINE_PROPERTY), so every env write broke
    // (npm sets npm_config_* this way). Forward with the real target as receiver.
    set(t, k, v) {
      return Reflect.set(t, k, v);
    },
    has(t, k) {
      if (typeof k === 'string' && !enumerating) readName(k, 'has');
      return Reflect.has(t, k);
    },
    ownKeys(t) {
      if (!enumerating) {
        enumerating = true;
        queueMicrotask(() => {
          enumerating = false;
        });
        if (enumEvents++ < 20) guarded(() => emit({ cat: 'env', op: 'enumerate', target: '*', detail: { count: Object.keys(t).length } }));
      }
      return Reflect.ownKeys(t);
    },
  });
  try {
    (process as any).env = proxy;
  } catch {
    /* non-writable on exotic runtimes: skip env coverage */
  }

  // process.cwd(): record once
  let cwdSeen = false;
  patch(process, 'cwd', (orig) => function (this: any, ...a) {
    if (!cwdSeen) {
      cwdSeen = true;
      guarded(() => emit({ cat: 'env', op: 'cwd', target: orig.apply(this, a) }));
    }
    return orig.apply(this, a);
  });
}
