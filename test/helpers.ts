import { execFileSync, spawn, spawnSync } from 'node:child_process';
import fs from 'node:fs';
import http from 'node:http';
import https from 'node:https';
import net from 'node:net';
import os from 'node:os';
import path from 'node:path';
import { fileURLToPath } from 'node:url';
import { readEventLog, type TattleEvent } from '../src/events.js';

export const ROOT = path.resolve(path.dirname(fileURLToPath(import.meta.url)), '..');
export const CLI = path.join(ROOT, 'dist', 'cli.js');

/** Build once if dist is missing (npm test always rebuilds; this makes `vitest` alone work). */
export function ensureBuilt(): void {
  if (!fs.existsSync(CLI) || !fs.existsSync(path.join(ROOT, 'dist', 'preload.js'))) {
    execFileSync('npx', ['tsup'], { cwd: ROOT, stdio: 'inherit' });
  }
}

export function tmpDir(prefix = 'tattle-test-'): string {
  return fs.realpathSync(fs.mkdtempSync(path.join(os.tmpdir(), prefix)));
}

export interface RunResult {
  code: number | null;
  stdout: string;
  stderr: string;
  events: TattleEvent[];
  logPath: string;
  logText: string;
}

/** Run `node dist/cli.js run -- <cmd...>` for real, asynchronously (so in-test servers keep serving). */
export async function runTattle(cmd: string[], env: Record<string, string | undefined> = {}, extraArgs: string[] = []): Promise<RunResult> {
  const work = tmpDir('tattle-run-');
  const logPath = path.join(work, 'log', 'events.jsonl');
  const fullEnv: NodeJS.ProcessEnv = { ...process.env, TATTLE_HOME: path.join(work, 'home'), TATTLE_LOG: logPath, FORCE_COLOR: undefined, NO_COLOR: undefined, ...env };
  for (const k of Object.keys(fullEnv)) if (fullEnv[k] === undefined) delete fullEnv[k];
  return new Promise((resolve, reject) => {
    const child = spawn(process.execPath, [CLI, 'run', ...extraArgs, '--', ...cmd], { env: fullEnv });
    let stdout = '';
    let stderr = '';
    child.stdout.on('data', (d) => (stdout += d));
    child.stderr.on('data', (d) => (stderr += d));
    child.on('error', reject);
    child.on('close', (code) => {
      const events = readEventLog(logPath);
      let logText = '';
      try {
        logText = fs.readFileSync(logPath, 'utf8');
      } catch {
        /* none */
      }
      resolve({ code, stdout, stderr, events, logPath, logText });
    });
  });
}

export const has = (cmd: string): boolean => spawnSync(process.platform === 'win32' ? 'where' : 'which', [cmd]).status === 0;

export const sig = (e: TattleEvent): string => `${e.cat}/${e.op}`;
export const sigs = (events: TattleEvent[]): string[] => [...new Set(events.map(sig))].sort();

// ---- localhost servers --------------------------------------------------------------------------

export interface Server {
  port: number;
  bodies: string[];
  urls: string[];
  close(): Promise<void>;
}

export async function startHttp(): Promise<Server> {
  const bodies: string[] = [];
  const urls: string[] = [];
  const srv = http.createServer((req, res) => {
    const chunks: Buffer[] = [];
    req.on('data', (c) => chunks.push(c));
    req.on('end', () => {
      bodies.push(Buffer.concat(chunks).toString());
      urls.push(`${req.method} ${req.url}`);
      res.end('ok');
    });
  });
  await new Promise<void>((r) => srv.listen(0, r)); // dual-stack: Node 18 fetch/http resolve 'localhost' to ::1 first
  return { port: (srv.address() as net.AddressInfo).port, bodies, urls, close: () => new Promise((r) => (srv.closeAllConnections?.(), srv.close(() => r()))) };
}

export async function startTcp(): Promise<Server> {
  const bodies: string[] = [];
  const srv = net.createServer((s) => {
    let n = 0;
    s.on('data', (c) => {
      n += c.length;
      if (n >= 100) s.write('ack');
    });
    s.on('end', () => bodies.push(String(n)));
    s.on('error', () => {});
  });
  await new Promise<void>((r) => srv.listen(0, '127.0.0.1', r));
  return { port: (srv.address() as net.AddressInfo).port, bodies, urls: [], close: () => new Promise((r) => srv.close(() => r())) };
}

/** HTTPS server with a throwaway self-signed cert; null when openssl is unavailable. */
export async function startHttps(): Promise<Server | null> {
  if (!has('openssl')) return null;
  const dir = tmpDir('tattle-tls-');
  const key = path.join(dir, 'k.pem');
  const crt = path.join(dir, 'c.pem');
  const gen = spawnSync('openssl', ['req', '-x509', '-newkey', 'rsa:2048', '-nodes', '-keyout', key, '-out', crt, '-days', '1', '-subj', '/CN=localhost'], { stdio: 'ignore' });
  if (gen.status !== 0) return null;
  const bodies: string[] = [];
  const urls: string[] = [];
  const srv = https.createServer({ key: fs.readFileSync(key), cert: fs.readFileSync(crt) }, (req, res) => {
    const chunks: Buffer[] = [];
    req.on('data', (c) => chunks.push(c));
    req.on('end', () => {
      bodies.push(Buffer.concat(chunks).toString());
      urls.push(`${req.method} ${req.url}`);
      res.end('ok');
    });
  });
  srv.on('tlsClientError', () => {});
  await new Promise<void>((r) => srv.listen(0, r)); // dual-stack: Node 18 fetch/http resolve 'localhost' to ::1 first
  return { port: (srv.address() as net.AddressInfo).port, bodies, urls, close: () => new Promise((r) => (srv.closeAllConnections?.(), srv.close(() => r()))) };
}
