/**
 * child_process hooks: record argv (NEVER env), flag clipboard readers and network-capable
 * tools, and keep Tattle attached to children even when the caller passes an explicit env.
 */
import childProcess from 'node:child_process';
import path from 'node:path';
import { promisify } from 'node:util';
import { callOrig, emit, guarded, nested } from './ctx.js';
import { patch } from './patch.js';

const NET_TOOLS = new Set(['curl', 'wget', 'nc', 'ncat', 'netcat', 'ssh', 'scp', 'sftp', 'ftp', 'telnet', 'socat']);
const SHELLS = new Set(['sh', 'bash', 'zsh', 'dash', 'ksh', 'fish']);
const WRAPPERS = new Set(['sudo', 'env', 'nohup', 'time', 'exec', 'command', 'xargs', 'nice', 'stdbuf', 'timeout']);

function baseName(file: string): string {
  return path.basename(file.replace(/\\/g, '/')).replace(/\.(?:exe|cmd|bat)$/i, '').toLowerCase();
}

interface Classification {
  clipboard?: string; // the reader tool
  networkEscape?: string; // the tool
}

/** Classify one (program, args) pair. */
function classifyOne(file: string, args: string[]): Classification {
  const b = baseName(file);
  const out: Classification = {};
  if (b === 'pbpaste' || b === 'wl-paste') out.clipboard = b;
  else if (b === 'xclip' || b === 'xsel') {
    // writing is -i/-in/--input; anything else (-o, -out, bare with a tty) reads
    if (!args.some((x) => /^(?:-i|-in|--input)$/.test(x))) out.clipboard = b;
  } else if (b === 'powershell' || b === 'pwsh') {
    if (args.some((x) => /get-clipboard/i.test(x))) out.clipboard = 'Get-Clipboard';
  } else if (b === 'osascript') {
    if (args.some((x) => /clipboard/i.test(x))) out.clipboard = 'osascript:clipboard';
  }
  else if (SHELLS.has(b)) {
    // sh -c '<line>' : classify the command line it will run
    const i = args.findIndex((x) => /^-[a-z]*c$/i.test(x));
    if (i >= 0 && args[i + 1] !== undefined) return classifyShell(args[i + 1]!);
  }
  if (NET_TOOLS.has(b)) out.networkEscape = b;
  return out;
}

/** Heuristic scan of a shell command line: first word of each pipeline segment. */
function classifyShell(cmdline: string): Classification {
  const out: Classification = {};
  for (const seg of cmdline.split(/&&|\|\||[;|\n&(`]|\$\(/)) {
    const words = seg.trim().split(/\s+/).filter(Boolean);
    let i = 0;
    while (i < words.length && (/^[A-Za-z_][A-Za-z0-9_]*=/.test(words[i]!) || WRAPPERS.has(baseName(words[i]!)))) i++;
    if (i >= words.length) continue;
    const c = classifyOne(words[i]!, words.slice(i + 1));
    out.clipboard ??= c.clipboard;
    out.networkEscape ??= c.networkEscape;
    if (/get-clipboard/i.test(seg) && /powershell|pwsh/i.test(seg)) out.clipboard ??= 'Get-Clipboard';
  }
  return out;
}

interface Parsed {
  target: string;
  argv: string[];
  shell: boolean;
  cls: Classification;
  optsIndex: number; // index of the options object in the call args, or -1
}

function parseCall(fn: string, a: unknown[]): Parsed {
  const isExec = fn === 'exec' || fn === 'execSync';
  const isFork = fn === 'fork';
  const file = String(a[0]);
  let optsIndex = -1;
  let args: string[] = [];
  if (!isExec) {
    if (Array.isArray(a[1])) {
      args = (a[1] as unknown[]).map(String);
      if (a[2] && typeof a[2] === 'object') optsIndex = 2;
    } else if (a[1] && typeof a[1] === 'object') {
      optsIndex = 1;
    }
  } else if (a[1] && typeof a[1] === 'object') optsIndex = 1;
  const opts: any = optsIndex >= 0 ? a[optsIndex] : undefined;
  const shell = isExec || !!opts?.shell;
  // exec*: the single string is a shell command line; the shell binary is an implementation detail
  if (isExec) return { target: 'sh', argv: [file], shell: true, cls: classifyShell(file), optsIndex };
  if (isFork) return { target: file, argv: [process.execPath, file, ...args], shell: false, cls: {}, optsIndex };
  const cls = shell ? classifyShell([file, ...args].join(' ')) : classifyOne(file, args);
  return { target: file, argv: [file, ...args], shell, cls, optsIndex };
}

/**
 * If the caller passes an explicit `env` object, make sure the preload variables survive so the
 * child (if it is node) stays hooked. This is the ONLY place a hook modifies a call; env values are
 * never read for recording.
 */
function withPreloadEnv(a: unknown[], optsIndex: number): unknown[] {
  if (optsIndex < 0) return a; // no options => child inherits process.env (already carries NODE_OPTIONS)
  const opts: any = a[optsIndex];
  const env = opts?.env;
  if (!env || typeof env !== 'object') return a;
  const log = process.env.TATTLE_LOG;
  const preloadFlag = (process.env.NODE_OPTIONS ?? '').match(/--import[= ]\S*preload\S*/)?.[0];
  if (!log || !preloadFlag) return a;
  const have: string = typeof env.NODE_OPTIONS === 'string' ? env.NODE_OPTIONS : '';
  if (have.includes(preloadFlag) && env.TATTLE_LOG) return a;
  const nextEnv: Record<string, unknown> = {
    ...env,
    NODE_OPTIONS: have.includes(preloadFlag) ? have : `${have} ${preloadFlag}`.trim(),
    TATTLE_LOG: env.TATTLE_LOG ?? log,
  };
  for (const k of ['TATTLE_RUN_ID', 'TATTLE_LOG_MAX_BYTES']) if (process.env[k] && !(k in nextEnv)) nextEnv[k] = process.env[k];
  const copy = a.slice();
  copy[optsIndex] = { ...opts, env: nextEnv };
  return copy;
}

export function installProcHooks(): void {
  const custom = promisify.custom;
  for (const fn of ['spawn', 'spawnSync', 'exec', 'execSync', 'execFile', 'execFileSync', 'fork'] as const) {
    const make = (orig: (...a: any[]) => any) => function (this: any, ...a: any[]) {
      if (nested()) return orig.apply(this, a);
      let args = a;
      guarded(() => {
        const p = parseCall(fn, a);
        const detail: Record<string, unknown> = { argv: p.argv, shell: p.shell };
        if (p.cls.clipboard) detail.clipboard = p.cls.clipboard;
        if (p.cls.networkEscape) {
          detail.networkEscape = true;
          detail.tool = p.cls.networkEscape;
        }
        const opts: any = p.optsIndex >= 0 ? a[p.optsIndex] : undefined;
        if (opts?.cwd) detail.cwd = String(opts.cwd);
        emit({ cat: 'proc', op: fn, target: p.target, detail, ...(p.cls.networkEscape ? { verdictHint: 'escape' as const } : {}) });
        if (p.cls.clipboard) {
          emit({ cat: 'clip', op: 'read', target: p.cls.clipboard, verdictHint: 'sensitive', detail: { via: fn, argv: p.argv } });
        }
        args = withPreloadEnv(a, p.optsIndex);
      });
      return callOrig(orig, this, args);
    };
    // util.promisify(exec/execFile) uses a custom implementation that calls the ORIGINAL function
    // directly (resolving {stdout, stderr}); hook it too so promisified calls are seen, and keep it.
    const origCustom = (childProcess as any)[fn]?.[custom];
    patch(childProcess, fn, make);
    if (typeof origCustom === 'function') {
      try {
        const wrappedCustom = make(origCustom);
        Object.defineProperty(wrappedCustom, 'name', { value: origCustom.name, configurable: true });
        Object.defineProperty(wrappedCustom, 'length', { value: origCustom.length, configurable: true });
        Object.defineProperty((childProcess as any)[fn], custom, { value: wrappedCustom, enumerable: false, configurable: true, writable: false });
      } catch {
        /* leave the (already copied) original custom in place */
      }
    }
  }
}
