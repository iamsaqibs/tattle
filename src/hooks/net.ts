/**
 * Network hooks: net.Socket.prototype.connect (catches net/tls/http/https/undici-fetch/http2),
 * dns lookup/resolve*, tls.connect, http(s).request/get, fetch, dgram send.
 * See docs/adr-001-interception.md for what each hook point does and does not cover.
 */
import crypto from 'node:crypto';
import dgram from 'node:dgram';
import dns from 'node:dns';
import http from 'node:http';
import https from 'node:https';
import net from 'node:net';
import tls from 'node:tls';
import { threadId } from 'node:worker_threads';
import { nowMs } from '../events.js';
import { callOrig, emit, guarded, nested, safeUrl } from './ctx.js';
import { patch } from './patch.js';

interface SockInfo {
  sid: number;
  host?: string;
  port?: number;
  path?: string;
  tls: boolean;
  connectTs: number;
  firstWriteTs?: number;
  lastWriteTs?: number;
  firstWriteHash?: string;
  firstWriteLen?: number;
  remoteAddress?: string;
  closed: boolean;
  sock: net.Socket;
}

// Socket ids are unique per (pid, thread): workers share a pid but have their own module instance.
const SID_BASE = threadId * 1_000_000;
let sidCounter = 0;
const open = new Map<net.Socket, SockInfo>();

/** net.Socket#connect receives [options, cb] (normalized), (options, cb), (port, host, cb) or (path, cb). */
function parseConnectArgs(args: unknown[]): { host?: string; port?: number; path?: string; servername?: string } {
  let a0: any = args[0];
  if (Array.isArray(a0)) a0 = a0[0]; // normalized form from net.connect/createConnection
  if (a0 && typeof a0 === 'object') {
    if (typeof a0.path === 'string') return { path: a0.path };
    const port = a0.port !== undefined ? Number(a0.port) : undefined;
    return { host: String(a0.host ?? a0.hostname ?? 'localhost'), port, servername: typeof a0.servername === 'string' ? a0.servername : undefined };
  }
  if (typeof a0 === 'number' || (typeof a0 === 'string' && /^\d+$/.test(a0))) {
    return { port: Number(a0), host: typeof args[1] === 'string' ? (args[1] as string) : 'localhost' };
  }
  if (typeof a0 === 'string') return { path: a0 };
  return {};
}

function targetOf(i: { host?: string; port?: number; path?: string }): string {
  if (i.path !== undefined) return `unix:${i.path}`;
  const h = i.host ?? '?';
  return `${h.includes(':') && !h.startsWith('[') ? `[${h}]` : h}:${i.port ?? '?'}`; // bracket IPv6 so host:port stays parseable
}

function closeEvent(info: SockInfo, partial: boolean): void {
  if (info.closed) return;
  info.closed = true;
  open.delete(info.sock);
  const s = info.sock;
  emit({
    cat: 'net',
    op: 'close',
    target: targetOf(info),
    // `bytes` is the egress direction (bytes the app wrote); ingress is detail.bytesRead
    bytes: s.bytesWritten,
    detail: {
      sid: info.sid,
      tls: info.tls,
      bytesWritten: s.bytesWritten,
      bytesRead: s.bytesRead,
      connectTs: info.connectTs,
      firstWriteTs: info.firstWriteTs,
      lastWriteTs: info.lastWriteTs,
      firstWriteLen: info.firstWriteLen,
      firstWriteHash: info.firstWriteHash,
      remoteAddress: info.remoteAddress,
      ...(partial ? { partial: true } : {}),
    },
  });
}

/** Flush sockets still open at process exit as partial closes. */
export function flushOpenSockets(): void {
  guarded(() => {
    for (const info of [...open.values()]) closeEvent(info, true);
  });
}

function trackSocket(sock: net.Socket, args: unknown[]): void {
  if (open.has(sock)) return; // reconnect on the same object: keep first record
  const p = parseConnectArgs(args);
  const isTls = typeof (tls as any).TLSSocket === 'function' && sock instanceof (tls as any).TLSSocket;
  const info: SockInfo = { sid: SID_BASE + ++sidCounter, ...p, tls: isTls, connectTs: nowMs(), closed: false, sock };
  if (p.servername && isTls) (info as any).servername = p.servername;
  open.set(sock, info);

  emit({
    cat: 'net',
    op: 'connect',
    target: targetOf(info),
    detail: { sid: info.sid, tls: isTls, ...(p.servername ? { servername: p.servername } : {}) },
  });

  sock.once('connect', () => {
    try {
      info.remoteAddress = sock.remoteAddress;
    } catch {
      /* ignore */
    }
  });
  sock.once('close', () => guarded(() => closeEvent(info, false)));

}

/**
 * Timing + first-bytes hash. Hooked on Socket.prototype (not per instance): an own `write` property
 * would be visible via Object.keys(socket) and changes write.length. Only sockets we track
 * (client-side connect()) are timed; accepted server sockets pass straight through.
 */
function patchWrite(): void {
  patch(net.Socket.prototype, 'write', (ow) => function (this: net.Socket, chunk: any, ...rest: any[]) {
    const info = open.size ? open.get(this) : undefined;
    if (info) {
      guarded(() => {
        const t = nowMs();
        info.lastWriteTs = t;
        if (info.firstWriteTs === undefined) {
          info.firstWriteTs = t;
          try {
            const buf = typeof chunk === 'string' ? Buffer.from(chunk) : Buffer.isBuffer(chunk) || chunk instanceof Uint8Array ? Buffer.from(chunk.buffer, chunk.byteOffset, chunk.byteLength) : null;
            if (buf) {
              info.firstWriteLen = buf.length;
              info.firstWriteHash = crypto.createHash('sha256').update(buf.subarray(0, 64)).digest('hex').slice(0, 16);
            }
          } catch {
            /* ignore */
          }
        }
      });
    }
    return ow.call(this, chunk, ...rest);
  });
}

// ---- dns ---------------------------------------------------------------------------------------

const RESOLVE_FNS = ['resolve', 'resolve4', 'resolve6', 'resolveAny', 'resolveCaa', 'resolveCname', 'resolveMx', 'resolveNaptr', 'resolveNs', 'resolvePtr', 'resolveSoa', 'resolveSrv', 'resolveTxt', 'reverse'];

function dnsEvent(op: string, name: unknown, extra?: Record<string, unknown>): void {
  if (typeof name !== 'string' || !name || nested()) return;
  if (net.isIP(name)) return; // IP literals are not DNS queries
  emit({ cat: 'dns', op, target: name, ...(extra ? { detail: extra } : {}) });
}

function rrtypeOf(fn: string, args: unknown[]): string {
  if (fn === 'resolve') return typeof args[1] === 'string' ? (args[1] as string).toUpperCase() : 'A';
  if (fn === 'reverse') return 'PTR';
  return fn.replace(/^resolve/, '').toUpperCase() || 'A';
}

function patchDns(): void {
  patch(dns, 'lookup', (orig) => function (this: any, ...a) {
    guarded(() => dnsEvent('lookup', a[0]));
    return callOrig(orig, this, a);
  });
  const prom = (dns as any).promises;
  if (prom) {
    patch(prom, 'lookup', (orig) => function (this: any, ...a) {
      guarded(() => dnsEvent('lookup', a[0], { promises: true }));
      return callOrig(orig, this, a);
    });
  }
  for (const fn of RESOLVE_FNS) {
    const mk = (promises: boolean) => (orig: (...a: any[]) => any) =>
      function (this: any, ...a: any[]) {
        guarded(() => dnsEvent('resolve', a[0], { rrtype: rrtypeOf(fn, a), ...(promises ? { promises: true } : {}) }));
        return callOrig(orig, this, a);
      };
    patch(dns, fn, mk(false));
    if (prom) patch(prom, fn, mk(true));
    if ((dns as any).Resolver) patch((dns as any).Resolver.prototype, fn, mk(false));
    if (prom?.Resolver) patch(prom.Resolver.prototype, fn, mk(true));
  }
}

// ---- http / https / fetch ------------------------------------------------------------------------

function httpTarget(defaultProto: 'http:' | 'https:', args: unknown[]): { url: string; method: string; hasQuery: boolean } | null {
  let urlStr: string | null = null;
  let opts: any = null;
  const a0: any = args[0];
  if (typeof a0 === 'string') {
    urlStr = a0;
    if (args[1] && typeof args[1] === 'object') opts = args[1];
  } else if (a0 instanceof URL) {
    urlStr = a0.href;
    if (args[1] && typeof args[1] === 'object') opts = args[1];
  } else if (a0 && typeof a0 === 'object') {
    opts = a0;
  }
  let base: URL | null = null;
  if (urlStr) {
    try {
      base = new URL(urlStr);
    } catch {
      base = null;
    }
  }
  const proto = opts?.protocol ?? base?.protocol ?? defaultProto;
  const host = opts?.hostname ?? opts?.host ?? base?.hostname ?? 'localhost';
  const port = opts?.port ?? base?.port;
  const p = opts?.path ?? (base ? base.pathname + base.search : '/');
  const [pathname, query] = String(p).split('?');
  const defPort = proto === 'https:' ? '443' : '80';
  const hostPart = port && String(port) !== defPort ? `${host}:${port}` : String(host);
  return {
    url: `${proto}//${hostPart}${pathname ?? '/'}`,
    method: String(opts?.method ?? 'GET').toUpperCase(),
    hasQuery: !!query,
  };
}

function patchHttp(): void {
  for (const [mod, proto] of [[http, 'http:'], [https, 'https:']] as const) {
    for (const fn of ['request', 'get'] as const) {
      patch(mod, fn, (orig) => function (this: any, ...a) {
        guarded(() => {
          const t = httpTarget(proto, a);
          if (t) emit({ cat: 'net', op: 'http.request', target: t.url, detail: { method: t.method, ...(t.hasQuery ? { hasQuery: true } : {}), module: proto === 'https:' ? 'https' : 'http' } });
        });
        return orig.apply(this, a);
      });
    }
  }
}

function patchTls(): void {
  patch(tls, 'connect', (orig) => function (this: any, ...a) {
    guarded(() => {
      const first: any = a[0];
      let host: string | undefined;
      let port: number | undefined;
      let servername: string | undefined;
      if (first && typeof first === 'object') {
        host = first.host;
        port = first.port !== undefined ? Number(first.port) : undefined;
        servername = first.servername;
      } else {
        port = Number(first);
        host = typeof a[1] === 'string' ? a[1] : undefined;
        const o = a.find((x) => x && typeof x === 'object');
        servername = o?.servername;
      }
      emit({ cat: 'net', op: 'tls.connect', target: servername || `${host ?? 'localhost'}:${port ?? 443}`, detail: { host, port } });
    });
    return orig.apply(this, a);
  });
}

function patchFetch(): void {
  const g = globalThis as any;
  if (typeof g.fetch !== 'function') return;
  const orig = g.fetch;
  const wrapped = function fetch(this: any, input: any, init?: any) {
    guarded(() => {
      let urlStr: string | undefined;
      let method = 'GET';
      if (typeof input === 'string') urlStr = input;
      else if (input instanceof URL) urlStr = input.href;
      else if (input && typeof input.url === 'string') {
        urlStr = input.url;
        method = input.method ?? method;
      }
      if (init?.method) method = init.method;
      const s = urlStr ? safeUrl(urlStr) : null;
      emit({ cat: 'net', op: 'fetch', target: s?.url ?? String(urlStr ?? '?'), detail: { method: String(method).toUpperCase(), ...(s?.hasQuery ? { hasQuery: true } : {}) } });
    });
    return orig.call(this, input, init);
  };
  try {
    Object.defineProperty(wrapped, 'length', { value: orig.length, configurable: true });
  } catch {
    /* ignore */
  }
  g.fetch = wrapped;
}

function patchDgram(): void {
  patch((dgram as any).Socket.prototype, 'send', (orig) => function (this: any, ...a) {
    guarded(() => {
      const msg = a[0];
      let bytes = 0;
      if (typeof msg === 'string') bytes = Buffer.byteLength(msg);
      else if (Array.isArray(msg)) bytes = msg.reduce((n: number, m: any) => n + (typeof m === 'string' ? Buffer.byteLength(m) : m.byteLength), 0);
      else if (msg && typeof msg.byteLength === 'number') bytes = msg.byteLength;
      let port: unknown;
      let addr: unknown;
      if (typeof a[1] === 'number' && typeof a[2] === 'number') {
        bytes = Math.min(bytes - a[1], a[2]);
        port = a[3];
        addr = a[4];
      } else {
        port = a[1];
        addr = a[2];
      }
      if (typeof addr !== 'string') addr = this.remoteAddress ? (() => { try { return this.remoteAddress().address; } catch { return undefined; } })() : undefined;
      if (typeof port !== 'number') port = (() => { try { return this.remoteAddress().port; } catch { return undefined; } })();
      emit({ cat: 'net', op: 'dgram.send', target: `udp:${addr ?? '?'}:${port ?? '?'}`, bytes, detail: { family: this.type } });
    });
    return orig.apply(this, a);
  });
}

export function installNetHooks(): void {
  patch(net.Socket.prototype, 'connect', (orig) => function (this: net.Socket, ...a) {
    guarded(() => trackSocket(this, a));
    try {
      return orig.apply(this, a);
    } catch (e) {
      // connect() threw synchronously (bad args): no 'close' will ever come, forget the socket
      guarded(() => {
        const i = open.get(this);
        if (i) {
          i.closed = true;
          open.delete(this);
        }
      });
      throw e;
    }
  });
  patchWrite();
  patchDns();
  patchHttp();
  patchTls();
  patchFetch();
  patchDgram();
}
