// Regenerates docs/assets/sample-card.svg by running the *guilty fixture* (fake secrets, localhost
// servers, stubbed clipboard reader) under tattle with --include-local. It is a fixture, not a real tool.
// Usage: npm run build && node scripts/gen-sample-card.mjs
import { spawn } from 'node:child_process';
import fs from 'node:fs';
import http from 'node:http';
import net from 'node:net';
import os from 'node:os';
import path from 'node:path';
import { fileURLToPath } from 'node:url';

const root = path.resolve(path.dirname(fileURLToPath(import.meta.url)), '..');
const work = fs.mkdtempSync(path.join(os.tmpdir(), 'tattle-sample-'));
const home = path.join(work, 'home');
for (const d of ['.aws', '.ssh', 'bin']) fs.mkdirSync(path.join(home, d), { recursive: true });
fs.writeFileSync(path.join(home, '.env'), 'EXAMPLE=not-a-real-secret\n');
fs.writeFileSync(path.join(home, '.aws', 'credentials'), '[default]\naws_secret_access_key=not-a-real-secret\n');
fs.writeFileSync(path.join(home, '.ssh', 'id_rsa'), 'not-a-real-key');
fs.writeFileSync(path.join(home, 'bin', 'pbpaste'), '#!/bin/sh\necho clip\n', { mode: 0o755 });

const web = http.createServer((q, r) => (q.resume(), q.on('end', () => r.end('ok')))).listen(0, '127.0.0.1');
const tcp = net.createServer((s) => { let n = 0; s.on('data', (c) => { n += c.length; if (n >= 100) s.write('ack'); }); s.on('error', () => {}); }).listen(0, '127.0.0.1');
await Promise.all([new Promise((r) => web.once('listening', r)), new Promise((r) => tcp.once('listening', r))]);

const env = { ...process.env, TATTLE_HOME: path.join(work, 'tattle-home'), HOME: home, USERPROFILE: home, GUILTY_HOME: home, GUILTY_HTTP_PORT: String(web.address().port), GUILTY_TCP_PORT: String(tcp.address().port), PATH: path.join(home, 'bin') + path.delimiter + process.env.PATH, OPENAI_API_KEY: 'not-a-real-key' };
delete env.TATTLE_LOG;
const code = await new Promise((r) => spawn(process.execPath, [path.join(root, 'dist', 'cli.js'), 'run', '--include-local', '--no-color', '--', 'node', 'fixtures/guilty/guilty.mjs'], { env, cwd: root, stdio: 'inherit' }).on('close', r));
web.close(); tcp.close();
const recs = path.join(work, 'tattle-home', 'receipts');
const dir = path.join(recs, fs.readdirSync(recs)[0]);
fs.mkdirSync(path.join(root, 'docs', 'assets'), { recursive: true });
fs.copyFileSync(path.join(dir, 'card.svg'), path.join(root, 'docs', 'assets', 'sample-card.svg'));
console.log(`exit ${code}; wrote docs/assets/sample-card.svg`);
