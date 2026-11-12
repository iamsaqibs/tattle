// `npm run release:check`: reports ship-readiness. It never publishes and never modifies anything.
// Network is optional: the name-availability check degrades to "unknown" offline.
import { spawnSync } from 'node:child_process';
import fs from 'node:fs';
import path from 'node:path';
import { fileURLToPath } from 'node:url';

const root = path.resolve(path.dirname(fileURLToPath(import.meta.url)), '..');
const win = process.platform === 'win32';
const npm = win ? 'npm.cmd' : 'npm';
const pkg = JSON.parse(fs.readFileSync(path.join(root, 'package.json'), 'utf8'));
let failed = 0;
const line = (st, msg) => console.log(`${st.padEnd(5)} ${msg}`);
const run = (args, o = {}) => spawnSync(npm, args, { cwd: root, encoding: 'utf8', shell: win, timeout: o.timeout ?? 600000 });
const step = (label, args) => {
  const r = run(args);
  if (r.status === 0) line('ok', label);
  else {
    failed++;
    line('FAIL', `${label} (exit ${r.status})`);
    console.log((r.stdout + r.stderr).split('\n').slice(-15).join('\n'));
  }
};

step('build', ['run', 'build']);
step('typecheck', ['run', 'typecheck']);
step('tests', ['run', 'test:only']);
step('smoke (pack + install + run)', ['run', 'smoke']);

// package.json name availability (informational: taken is a warning, not a failure)
{
  const r = run(['view', pkg.name, 'name', 'version', '--json'], { timeout: 30000 });
  const out = (r.stdout ?? '') + (r.stderr ?? '');
  if (r.status === 0 && r.stdout.trim()) {
    let v = {};
    try { v = JSON.parse(r.stdout); } catch { /* keep raw */ }
    line('WARN', `npm name "${pkg.name}" is TAKEN (existing version ${v.version ?? '?'}); choose a scoped or alternative name before publishing`);
  } else if (/E404|404 Not Found|is not in this registry/.test(out)) line('ok', `npm name "${pkg.name}" appears free`);
  else line('skip', `npm name "${pkg.name}": could not determine (offline or registry error)`);
}

// files whitelist and tarball contents
{
  const files = pkg.files ?? [];
  const bad = ['hall', 'launch', 'fixtures', 'hall/work', 'test', 'src', 'scripts'];
  const leaked = files.filter((f) => bad.some((b) => f === b || f.startsWith(b + '/')));
  if (!files.length) { failed++; line('FAIL', 'package.json has no "files" whitelist'); }
  else if (leaked.length) { failed++; line('FAIL', `files whitelist includes: ${leaked.join(', ')}`); }
  else line('ok', 'files whitelist excludes hall/work, launch/, fixtures, test, src, scripts');
  const r = run(['pack', '--dry-run', '--json', '--ignore-scripts']);
  try {
    const paths = JSON.parse(r.stdout)[0].files.map((f) => f.path);
    const leak = paths.filter((p) => /^(hall|launch|fixtures|test|src|scripts)\//.test(p));
    if (leak.length) { failed++; line('FAIL', `tarball would contain: ${leak.slice(0, 5).join(', ')}`); }
    else line('ok', `npm pack --dry-run: ${paths.length} files, none from hall/launch/fixtures/test/src/scripts`);
  } catch { failed++; line('FAIL', 'npm pack --dry-run did not produce readable output'); }
}

// version vs CHANGELOG top entry
{
  const cl = fs.readFileSync(path.join(root, 'CHANGELOG.md'), 'utf8');
  const m = cl.match(/^##\s+v?(\d+\.\d+\.\d+[^\s]*)/m);
  if (!m) { failed++; line('FAIL', 'CHANGELOG.md has no "## <version>" entry'); }
  else if (m[1] !== pkg.version) { failed++; line('FAIL', `package.json version ${pkg.version} != CHANGELOG top entry ${m[1]}`); }
  else line('ok', `version ${pkg.version} matches CHANGELOG top entry`);
}

console.log(failed ? `\nrelease:check: ${failed} problem(s). Nothing was published.` : '\nrelease:check: all mechanical checks passed. Nothing was published; publishing is a manual step.');
process.exit(failed ? 1 : 0);
