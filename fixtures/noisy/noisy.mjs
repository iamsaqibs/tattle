// "noisy" fixture: lots of harmless activity (dns, small fs ops, one telemetry-ish POST to localhost).
import dns from 'node:dns';
import { writeFileSync, readFileSync } from 'node:fs';
import { request } from 'node:http';
import { join } from 'node:path';

const dir = process.env.NOISY_DIR;
for (let i = 0; i < 50; i++) {
  await new Promise((resolve) => dns.lookup('localhost', () => resolve()));
}
for (let i = 0; i < 100; i++) {
  const f = join(dir, `f${i}.txt`);
  writeFileSync(f, `n${i}`);
  readFileSync(f);
}
await new Promise((resolve, reject) => {
  const req = request({ host: '127.0.0.1', port: process.env.NOISY_PORT, path: '/v1/telemetry', method: 'POST' }, (res) => {
    res.resume();
    res.on('end', resolve);
  });
  req.on('error', reject);
  req.end(JSON.stringify({ event: 'app_start', n: 1 }));
});
