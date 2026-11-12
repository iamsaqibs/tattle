import fs from 'node:fs';
import path from 'node:path';
import { beforeAll, describe, expect, it } from 'vitest';
import { ensureBuilt, has, runTattle, sig, tmpDir } from './helpers.js';

beforeAll(ensureBuilt);

const flatten = (s: string) => s.replace(/[│|]/g, ' ').replace(/\[note\]/g, ' ').replace(/\s+/g, ' ');

describe('tattle run harness', () => {
  it('runs a command, streams stdio verbatim, logs lifecycle events', async () => {
    const r = await runTattle(['node', '-e', 'console.log(1)']);
    expect(r.code).toBe(0);
    expect(r.stdout).toBe('1\n');
    const life = r.events.filter((e) => e.cat === 'life').map(sig);
    expect(life).toEqual(['life/start', 'life/exit']);
    const start = r.events.find((e) => e.op === 'start')!;
    expect(start.detail).toMatchObject({ platform: process.platform, thread: 'main' });
    expect((start.detail as any).argv[0]).toBe(process.execPath);
    expect(r.events.find((e) => e.op === 'exit')!.detail).toMatchObject({ code: 0 });
    expect(r.stderr).toMatch(/\d+ events/);
    expect(r.stderr).toMatch(/CLEAN/);
  });

  it.skipIf(process.platform === 'win32')('native-binary-only command => NOT OBSERVED (never CLEAN)', async () => {
    const r = await runTattle(['/bin/echo', 'hi']);
    expect(r.code).toBe(0);
    expect(r.events.length).toBe(0);
    expect(r.stderr).toMatch(/NOT OBSERVED/);
    expect(r.stderr).not.toMatch(/CLEAN/);
    expect(flatten(r.stderr)).toMatch(/cannot see inside native binaries/);
  });

  it.skipIf(process.platform === 'win32')('shell launching node => normal verdict with a partial-coverage note', async () => {
    const r = await runTattle(['sh', '-c', 'node -e "1"; true']);
    expect(r.stderr).toMatch(/CLEAN/);
    expect(flatten(r.stderr)).toMatch(/partial coverage: sh is not a Node process; only 1 Node descendant observed/);
  });

  it('propagates exit codes (node and non-node)', async () => {
    expect((await runTattle(['node', '-e', 'process.exit(7)'])).code).toBe(7);
    expect((await runTattle(['node', '-e', 'process.exitCode = 3'])).code).toBe(3);
    if (process.platform !== 'win32') {
      expect((await runTattle(['sh', '-c', 'exit 5'])).code).toBe(5);
      const r = await runTattle(['sh', '-c', 'kill -TERM $$']);
      expect(r.code).toBe(128 + 15);
    }
    const missing = await runTattle(['definitely-not-a-command-xyz']);
    expect(missing.code).toBe(127);
    expect(missing.stderr).toMatch(/command not found/);
  });

  it('does not leave an orphan receipt dir when the command cannot be spawned', async () => {
    // Without TATTLE_LOG, tattle creates $TATTLE_HOME/receipts/<run>/ itself and must clean it up.
    const r = await runTattle(['definitely-not-a-command-xyz'], { TATTLE_LOG: undefined });
    expect(r.code).toBe(127);
    const receipts = path.join(path.dirname(path.dirname(r.logPath)), 'home', 'receipts');
    const left = fs.existsSync(receipts) ? fs.readdirSync(receipts) : [];
    expect(left).toEqual([]);
  });

  it('works with and without --', async () => {
    const r = await new Promise<number | null>((resolve) => {
      import('node:child_process').then(({ spawn }) => {
        const c = spawn(process.execPath, [path.resolve('dist/cli.js'), 'run', '-q', 'node', '-e', 'process.exit(4)'], { stdio: 'ignore' });
        c.on('close', resolve);
      });
    });
    expect(r).toBe(4);
  });

  it('preserves an existing NODE_OPTIONS and appends the preload', async () => {
    const r = await runTattle(['node', '-p', 'process.env.NODE_OPTIONS'], { NODE_OPTIONS: '--max-old-space-size=96' });
    expect(r.stdout).toMatch(/--max-old-space-size=96 --import file:\/\/.*preload\.js/);
  });

  it('hooks a node process launched by a shell script (non-node entry command)', async () => {
    if (process.platform === 'win32') return;
    const dir = tmpDir();
    const secret = path.join(dir, '.env');
    fs.writeFileSync(secret, 'A=1');
    const r = await runTattle(['sh', '-c', `node -e "require('fs').readFileSync(process.argv[1])" '${secret}'`]);
    expect(r.code).toBe(0);
    const read = r.events.find((e) => e.cat === 'fs' && e.op === 'read' && e.target === secret);
    expect(read?.verdictHint).toBe('sensitive');
  });

  it('hooks a grandchild started with an explicit empty env (preload propagation)', async () => {
    const dir = tmpDir();
    const secret = path.join(dir, '.env');
    fs.writeFileSync(secret, 'A=1');
    const code = `require('child_process').spawnSync(process.execPath, ['-e', "require('fs').readFileSync(process.env.F)"], { env: { F: ${JSON.stringify(secret)} } })`;
    const r = await runTattle(['node', '-e', code]);
    const pids = new Set(r.events.filter((e) => e.op === 'start').map((e) => e.pid));
    expect(pids.size).toBe(2);
    const read = r.events.find((e) => e.cat === 'fs' && e.target === secret);
    expect(read).toBeDefined();
    expect(read!.ppid).toBeDefined();
  });

  it('writes receipts under TATTLE_HOME when TATTLE_LOG is not set', async () => {
    const home = tmpDir();
    const { spawnSync } = await import('node:child_process');
    const env: NodeJS.ProcessEnv = { ...process.env, TATTLE_HOME: home };
    delete env.TATTLE_LOG;
    const res = spawnSync(process.execPath, [path.resolve('dist/cli.js'), 'run', '--', 'node', '-e', '0'], { env, encoding: 'utf8' });
    expect(res.status).toBe(0);
    const dirs = fs.readdirSync(path.join(home, 'receipts'));
    expect(dirs).toHaveLength(1);
    expect(fs.existsSync(path.join(home, 'receipts', dirs[0]!, 'events.jsonl'))).toBe(true);
  });

  it('install is a clear Phase 6 stub; unknown commands exit 2 with help', async () => {
    const { spawnSync } = await import('node:child_process');
    const run = (...a: string[]) => spawnSync(process.execPath, [path.resolve('dist/cli.js'), ...a], { encoding: 'utf8' });
    const inst = run('install', 'x');
    expect(inst.stderr).toMatch(/Phase 6/);
    expect(inst.status).toBe(2);
    const bad = run('frobnicate');
    expect(bad.status).toBe(2);
    expect(bad.stderr).toMatch(/unknown command: frobnicate/);
    expect(bad.stderr).toMatch(/--help/);
  });

  it('is a no-op for hooks when TATTLE_LOG is absent (preload loaded standalone)', async () => {
    const { spawnSync } = await import('node:child_process');
    const env = { ...process.env };
    delete env.TATTLE_LOG;
    const res = spawnSync(process.execPath, ['--import', path.resolve('dist/preload.js'), '-p', '1+1'], { env, encoding: 'utf8' });
    expect(res.stdout.trim()).toBe('2');
    expect(has('node')).toBe(true);
  });
});
