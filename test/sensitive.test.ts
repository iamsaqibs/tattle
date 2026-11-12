import { describe, expect, it } from 'vitest';
import { globToRegExp, homeDir, matchSensitive, normalizePath, RULES } from '../src/sensitive.js';

const home = '/home/alice';
const mac = '/Users/alice';
const m = (p: string, h = home) => matchSensitive(p, { home: h, appData: '', localAppData: '' });

describe('rule pack hygiene', () => {
  it('has more than 25 rules, each with id, label, severity, patterns and a documentation source', () => {
    expect(RULES.length).toBeGreaterThan(25);
    const ids = new Set<string>();
    for (const r of RULES) {
      expect(ids.has(r.id), `duplicate id ${r.id}`).toBe(false);
      ids.add(r.id);
      expect(r.label.length).toBeGreaterThan(3);
      expect(['high', 'medium', 'low']).toContain(r.severity);
      expect(r.patterns.length).toBeGreaterThan(0);
      expect(r.source).toMatch(/^https:\/\/[^\s]+\.[^\s]+/);
    }
  });
  it('glob compiler: * stays in segment, ** crosses, X/** matches X', () => {
    expect(globToRegExp('~/.ssh/**').test('~/.ssh')).toBe(true);
    expect(globToRegExp('~/.ssh/**').test('~/.ssh/a/b')).toBe(true);
    expect(globToRegExp('~/a/*.txt').test('~/a/b/c.txt')).toBe(false);
    expect(globToRegExp('**/.env').test('/x/y/.env')).toBe(true);
    expect(globToRegExp('**/.env').test('.env')).toBe(true);
  });
});

describe('positive matches (>= 10 distinct rules)', () => {
  const cases: Array<[string, string, string?]> = [
    ['dotenv', `${home}/proj/.env`],
    ['dotenv', `${home}/proj/.env.production`],
    ['ssh-dir', `${home}/.ssh/id_ed25519`],
    ['aws-credentials', `${home}/.aws/credentials`],
    ['gcloud-credentials', `${home}/.config/gcloud/application_default_credentials.json`],
    ['azure-credentials', `${home}/.azure/accessTokens.json`],
    ['kube-config', `${home}/.kube/config`],
    ['docker-config', `${home}/.docker/config.json`],
    ['npmrc', `${home}/.npmrc`],
    ['pypirc', `${home}/.pypirc`],
    ['netrc', `${home}/.netrc`],
    ['gh-hosts', `${home}/.config/gh/hosts.yml`],
    ['git-credentials', `${home}/.git-credentials`],
    ['shell-history', `${home}/.zsh_history`],
    ['gnupg', `${home}/.gnupg/private-keys-v1.d/x.key`],
    ['browser-cookies-chrome', `${mac}/Library/Application Support/Google/Chrome/Default/Cookies`, mac],
    ['browser-logins-chrome', `${home}/.config/google-chrome/Default/Login Data`],
    ['browser-cookies-firefox', `${home}/.mozilla/firefox/abcd.default/cookies.sqlite`],
    ['browser-cookies-edge', `${home}/.config/microsoft-edge/Profile 1/Network/Cookies`],
    ['browser-cookies-brave', `${home}/.config/BraveSoftware/Brave-Browser/Default/Cookies`],
    ['browser-cookies-safari', `${mac}/Library/Cookies/Cookies.binarycookies`, mac],
    ['keychain-macos', `${mac}/Library/Keychains/login.keychain-db`, mac],
    ['wallet-ethereum', `${home}/.ethereum/keystore/UTC--2020--abc`],
    ['wallet-electrum', `${home}/.electrum/wallets/default_wallet`],
    ['wallet-exodus', `${mac}/Library/Application Support/Exodus/exodus.wallet/seed.seco`, mac],
    ['wallet-solana', `${home}/.config/solana/id.json`],
    ['password-manager-vaults', `${home}/Documents/vault.kdbx`],
    ['ai-cli-credentials', `${home}/.claude/.credentials.json`],
    ['system-auth', '/etc/shadow'],
    ['proc-environ', '/proc/1234/environ'],
  ];
  for (const [rule, p, h] of cases) {
    it(`${rule}: ${p}`, () => {
      expect(m(p, h)?.rule).toBe(rule);
    });
  }
  it('covers >= 10 distinct rules', () => {
    expect(new Set(cases.map((c) => c[0])).size).toBeGreaterThanOrEqual(10);
  });
  it('windows: %USERPROFILE%, %APPDATA% and %LOCALAPPDATA% expansion', () => {
    const o = { home: 'C:\\Users\\Alice', appData: 'C:\\Users\\Alice\\AppData\\Roaming', localAppData: 'D:\\Local' };
    expect(matchSensitive('C:\\Users\\Alice\\.aws\\credentials', o)?.rule).toBe('aws-credentials');
    expect(matchSensitive('C:\\Users\\Alice\\AppData\\Roaming\\Exodus\\exodus.wallet\\seed.seco', o)?.rule).toBe('wallet-exodus');
    expect(matchSensitive('D:\\Local\\Google\\Chrome\\User Data\\Default\\Login Data', o)?.rule).toBe('browser-logins-chrome');
    expect(normalizePath('c:\\users\\alice\\.ssh\\id_rsa', o)).toBe('~/.ssh/id_rsa');
  });
});

describe('negatives', () => {
  it.each([
    `${home}/proj/src/index.ts`,
    `${home}/proj/.env.example`,
    `${home}/proj/.env.sample`,
    `${home}/proj/README.md`,
    '/tmp/result.txt',
    `${home}/.sshfoo/readme`,
    `${home}/.config/gcloudish/x`,
    `${home}/Documents/notes.txt`,
    '/etc/hosts',
    '/usr/lib/node_modules/npm/package.json',
  ])('does not flag %s', (p) => {
    expect(m(p)).toBeNull();
  });
  it('severity ordering: a high rule wins over a low rule for the same path', () => {
    // ~/.config/git/credentials is high (git-credentials); ~/.config/git/config is low
    expect(m(`${home}/.config/git/credentials`)?.severity).toBe('high');
    expect(m(`${home}/.config/git/config`)?.severity).toBe('low');
  });
});

describe('win32 path handling (simulated, no Windows needed)', () => {
  const env = { USERPROFILE: 'C:\\Users\\Alice', APPDATA: 'C:\\Users\\Alice\\AppData\\Roaming', LOCALAPPDATA: 'C:\\Users\\Alice\\AppData\\Local' };
  const w = (p: string, extra: Record<string, unknown> = {}) => matchSensitive(p, { platform: 'win32', env, ...extra });

  it('homeDir prefers USERPROFILE, then HOMEDRIVE+HOMEPATH, on win32 only', () => {
    expect(homeDir('win32', { USERPROFILE: 'C:\\Users\\A' }, () => '/x')).toBe('C:\\Users\\A');
    expect(homeDir('win32', { HOMEDRIVE: 'D:', HOMEPATH: '\\u\\bob' }, () => '/x')).toBe('D:\\u\\bob');
    expect(homeDir('win32', {}, () => '/fallback')).toBe('/fallback');
    expect(homeDir('linux', { USERPROFILE: 'C:\\ignored' }, () => '/home/a')).toBe('/home/a');
  });
  it('resolves home from USERPROFILE without an explicit home option', () => {
    expect(w('C:\\Users\\Alice\\.ssh\\id_rsa')?.rule).toBe('ssh-dir');
    expect(w('C:\\Users\\Alice\\.aws\\credentials')?.rule).toBe('aws-credentials');
    expect(normalizePath('C:\\Users\\Alice\\.npmrc', { platform: 'win32', env })).toBe('~/.npmrc');
  });
  it('is case-insensitive for drive letter, directories and file names', () => {
    expect(w('c:\\users\\ALICE\\.SSH\\ID_RSA')?.rule).toBe('ssh-dir');
    expect(w('C:\\USERS\\alice\\appdata\\roaming\\microsoft\\credentials\\x')?.rule).toBe('credential-store-windows');
  });
  it('accepts forward slashes and mixed separators', () => {
    expect(w('C:/Users/Alice/.kube/config')?.rule).toBe('kube-config');
    expect(w('C:\\Users\\Alice/.docker\\config.json')?.rule).toBe('docker-config');
  });
  it('strips extended-length prefixes and handles UNC without crashing', () => {
    expect(w('\\\\?\\C:\\Users\\Alice\\.ssh\\id_rsa')?.rule).toBe('ssh-dir');
    expect(normalizePath('\\\\?\\UNC\\srv\\share\\x', { platform: 'win32', env })).toBe('//srv/share/x');
    expect(w('\\\\srv\\share\\prod\\.env')?.rule).toBe('dotenv');
  });
  it('uses %APPDATA%/%LOCALAPPDATA% even when relocated outside the profile', () => {
    const moved = { ...env, APPDATA: 'D:\\Roam', LOCALAPPDATA: 'E:\\Loc' };
    expect(matchSensitive('D:\\Roam\\Exodus\\seed.seco', { platform: 'win32', env: moved })?.rule).toBe('wallet-exodus');
    expect(matchSensitive('E:\\Loc\\Google\\Chrome\\User Data\\Default\\Login Data', { platform: 'win32', env: moved })?.rule).toBe('browser-logins-chrome');
  });
  it('env-file negatives and .env on Windows', () => {
    expect(w('C:\\proj\\.env')?.rule).toBe('dotenv');
    expect(w('C:\\proj\\.ENV.LOCAL')?.rule).toBe('dotenv');
    expect(w('C:\\proj\\.env.example')).toBeNull();
  });
  it('does not treat backslashes as separators on POSIX', () => {
    expect(matchSensitive('/home/a/notes\\.ssh\\id_rsa', { platform: 'linux', home: '/home/a', env: {} })).toBeNull();
    expect(normalizePath('/home/a/x\\y', { platform: 'linux', home: '/home/a', env: {} })).toBe('~/x\\y');
  });
  it('known gap: 8.3 short names (PROGRA~1) are not expanded', () => {
    expect(w('C:\\Users\\ALICE~1\\.aws\\credentials')).toBeNull();
  });
});
