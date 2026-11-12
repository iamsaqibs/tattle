// Pack-and-install smoke test: `npm pack`, install the tarball into a fresh temp project, then run
// the *installed* tattle (version, run, verify). Needs no network beyond what `npm install` of the
// tarball's optional deps does; optional deps are skipped (--omit=optional) to keep it hermetic.
import { execFileSync, spawnSync } from 'node:child_process';
import fs from 'node:fs';
import os from 'node:os';
import path from 'node:path';
import { fileURLToPath } from 'node:url';

const root = path.resolve(path.dirname(fileURLToPath(import.meta.url)), '..');
const win = process.platform === 'win32';
const npm = win ? 'npm.cmd' : 'npm';
const sh = { shell: win, encoding: 'utf8' };
const tmp = fs.realpathSync(fs.mkdtempSync(path.join(os.tmpdir(), 'tattle-smoke-')));
let failed = false;
const check = (ok, msg) => {
  console.log(`${ok ? 'ok  ' : 'FAIL'} ${msg}`);
  if (!ok) failed = true;
};

try {
  if (!fs.existsSync(path.join(root, 'dist', 'cli.js'))) execFileSync(npm, ['run', 'build'], { cwd: root, stdio: 'inherit', shell: win });
  const packDir = path.join(tmp, 'pack');
  fs.mkdirSync(packDir);
  const packOut = JSON.parse(execFileSync(npm, ['pack', '--json', '--pack-destination', packDir], { cwd: root, encoding: 'utf8', shell: win, stdio: ['ignore', 'pipe', 'inherit'] }));
  const tgz = path.join(packDir, packOut[0].filename);
  const files = packOut[0].files.map((f) => f.path);
  for (const need of ['dist/cli.js', 'dist/preload.js', 'package.json', 'README.md', 'LICENSE']) check(files.includes(need), `tarball contains ${need}`);
  check(!files.some((f) => f.startsWith('src/') || f.startsWith('test/') || f.startsWith('fixtures/')), 'tarball has no src/test/fixtures');

  const proj = path.join(tmp, 'proj');
  fs.mkdirSync(proj);
  fs.writeFileSync(path.join(proj, 'package.json'), '{"name":"smoke","version":"0.0.0","private":true}\n');
  const inst = spawnSync(npm, ['install', '--no-audit', '--no-fund', '--omit=optional', tgz], { cwd: proj, ...sh });
  check(inst.status === 0, 'npm install <tarball>');
  if (inst.status !== 0) console.log(inst.stdout, inst.stderr);

  const home = path.join(tmp, 'home');
  const env = { ...process.env, TATTLE_HOME: home, NO_COLOR: '1' };
  delete env.TATTLE_LOG;
  const bin = path.join(proj, 'node_modules', '.bin', win ? 'tattle.cmd' : 'tattle');
  const want = JSON.parse(fs.readFileSync(path.join(root, 'package.json'), 'utf8')).version;

  const v = spawnSync(bin, ['--version'], { cwd: proj, env, ...sh });
  check(v.status === 0 && v.stdout.trim() === want, `tattle --version -> ${v.stdout?.trim()} (want ${want})`);

  const npx = spawnSync(npm === 'npm.cmd' ? 'npx.cmd' : 'npx', ['--no-install', 'tattle', '--version'], { cwd: proj, env, ...sh });
  check(npx.status === 0 && npx.stdout.trim() === want, 'npx tattle --version');

  // Child args go through cmd.exe on Windows (shell: true, no quoting), so keep them free of spaces/quotes:
  // use a script file and plain `node` from PATH rather than `node -e "<code>"` and a spaced execPath.
  const childScript = path.join(proj, 'child.cjs');
  fs.writeFileSync(childScript, "require('fs').readFileSync(__filename); console.log('child-output');\n");
  const r = spawnSync(bin, ['run', '--', 'node', childScript], { cwd: proj, env, ...sh });
  check(r.status === 0, 'tattle run exits 0');
  check(r.stdout.includes('child-output'), 'child stdout passed through');
  check(/tt_[0-9a-f]{12}/.test(r.stderr), 'receipt id printed');
  const recs = path.join(home, 'receipts');
  const dirs = fs.existsSync(recs) ? fs.readdirSync(recs) : [];
  check(dirs.length === 1 && fs.existsSync(path.join(recs, dirs[0], 'receipt.json')) && fs.existsSync(path.join(recs, dirs[0], 'card.svg')), 'receipt.json and card.svg written');
  if (dirs.length === 1) {
    const ver = spawnSync(bin, ['verify', '--strict', path.join(recs, dirs[0])], { cwd: proj, env, ...sh });
    check(ver.status === 0, 'tattle verify --strict on the fresh receipt');
  }
  const exitScript = path.join(proj, 'exit7.cjs');
  fs.writeFileSync(exitScript, 'process.exit(7);\n');
  const ex = spawnSync(bin, ['run', '--quiet', '--', 'node', exitScript], { cwd: proj, env, ...sh });
  check(ex.status === 7, 'child exit code propagates (7)');
} finally {
  fs.rmSync(tmp, { recursive: true, force: true });
}
if (failed) {
  console.error('smoke: FAILED');
  process.exit(1);
}
console.log('smoke: OK');
