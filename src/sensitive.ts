/**
 * Sensitive-surface rule pack. Each rule names a class of file that commonly holds credentials,
 * session material, private keys or personal data, with a documentation pointer in `source`
 * for WHY the path is where it is. (Pointers are documentation citations; they are not
 * link-checked by the test suite because tests never touch the network.)
 *
 * Patterns are small globs over a normalised path:
 *   - the user's home directory is rewritten to `~`
 *   - %APPDATA% / %LOCALAPPDATA% are rewritten to `~/AppData/Roaming` / `~/AppData/Local`
 *   - separators are `/`, matching is case-insensitive (macOS/Windows FS default)
 *   - `*` = within one segment, `**` = any depth, `X/**` also matches `X` itself
 *
 * A match means "a secret-shaped location was touched", never "a secret was stolen".
 */
import os from 'node:os';

export type Severity = 'high' | 'medium' | 'low';

export interface SensitiveRule {
  id: string;
  label: string;
  severity: Severity;
  category: string;
  patterns: string[];
  /** documentation URL explaining the location/format */
  source: string;
}

export interface SensitiveMatch {
  rule: string;
  label: string;
  severity: Severity;
  category: string;
}

// ---- rule table ------------------------------------------------------------------------------

/** Chromium-family browsers: [id, label, per-OS user-data roots, doc]. */
const CHROMIUM: Array<[string, string, string[], string]> = [
  [
    'chrome',
    'Chrome',
    ['~/Library/Application Support/Google/Chrome', '~/.config/google-chrome', '~/AppData/Local/Google/Chrome/User Data'],
    'https://chromium.googlesource.com/chromium/src/+/main/docs/user_data_dir.md',
  ],
  [
    'edge',
    'Edge',
    ['~/Library/Application Support/Microsoft Edge', '~/.config/microsoft-edge', '~/AppData/Local/Microsoft/Edge/User Data'],
    'https://learn.microsoft.com/en-us/deployedge/microsoft-edge-policies#userdatadir',
  ],
  [
    'brave',
    'Brave',
    [
      '~/Library/Application Support/BraveSoftware/Brave-Browser',
      '~/.config/BraveSoftware/Brave-Browser',
      '~/AppData/Local/BraveSoftware/Brave-Browser/User Data',
    ],
    'https://support.brave.com/hc/en-us/articles/360018163151-How-do-I-find-my-Brave-profile-folder',
  ],
];

const FIREFOX_ROOTS = ['~/Library/Application Support/Firefox/Profiles', '~/.mozilla/firefox', '~/AppData/Roaming/Mozilla/Firefox/Profiles'];

function chromiumRules(): SensitiveRule[] {
  const out: SensitiveRule[] = [];
  for (const [id, label, roots, source] of CHROMIUM) {
    out.push({
      id: `browser-cookies-${id}`,
      label: `${label} cookie store`,
      severity: 'high',
      category: 'browser',
      // "Local State" holds the os_crypt key material needed to decrypt cookies/passwords
      patterns: roots.flatMap((r) => [`${r}/**/Cookies`, `${r}/**/Cookies-journal`, `${r}/**/Network/Cookies`, `${r}/Local State`]),
      source,
    });
    out.push({
      id: `browser-logins-${id}`,
      label: `${label} saved-password store`,
      severity: 'high',
      category: 'browser',
      patterns: roots.flatMap((r) => [`${r}/**/Login Data`, `${r}/**/Login Data For Account`, `${r}/**/Web Data`]),
      source,
    });
  }
  return out;
}

export const RULES: SensitiveRule[] = [
  // ---- dotenv / secrets-in-repo -------------------------------------------------------
  {
    id: 'dotenv',
    label: 'dotenv / environment file',
    severity: 'high',
    category: 'env-file',
    patterns: ['**/.env', '**/.env.*', '**/*.env', '**/.envrc'],
    source: 'https://12factor.net/config',
  },
  {
    id: 'secrets-file',
    label: 'secrets / credentials file',
    severity: 'medium',
    category: 'env-file',
    patterns: ['**/credentials.json', '**/secrets.json', '**/secrets.yml', '**/secrets.yaml', '**/service-account*.json', '**/serviceaccount*.json', '**/.htpasswd'],
    source: 'https://cloud.google.com/iam/docs/keys-create-delete',
  },
  {
    id: 'terraform-secrets',
    label: 'Terraform state / variable files',
    severity: 'medium',
    category: 'env-file',
    patterns: ['**/terraform.tfstate', '**/terraform.tfstate.backup', '**/*.tfvars', '~/.terraform.d/credentials.tfrc.json'],
    source: 'https://developer.hashicorp.com/terraform/language/state/sensitive-data',
  },
  // ---- SSH / keys ---------------------------------------------------------------------
  {
    id: 'ssh-dir',
    label: 'SSH keys and config (~/.ssh)',
    severity: 'high',
    category: 'ssh',
    patterns: ['~/.ssh/**', '~/AppData/Roaming/Microsoft/SSH/**'],
    source: 'https://man.openbsd.org/ssh#FILES',
  },
  {
    id: 'private-key-file',
    label: 'private key / certificate bundle',
    severity: 'high',
    category: 'ssh',
    patterns: ['**/id_rsa', '**/id_dsa', '**/id_ecdsa', '**/id_ed25519', '**/*.pem', '**/*.ppk', '**/*.p12', '**/*.pfx', '**/*.jks', '**/*.keystore'],
    source: 'https://datatracker.ietf.org/doc/html/rfc7468',
  },
  {
    id: 'gnupg',
    label: 'GnuPG keyrings',
    severity: 'high',
    category: 'ssh',
    patterns: ['~/.gnupg/**', '~/AppData/Roaming/gnupg/**'],
    source: 'https://www.gnupg.org/documentation/manuals/gnupg/GPG-Configuration.html',
  },
  // ---- cloud & devops CLIs ------------------------------------------------------------
  {
    id: 'aws-credentials',
    label: 'AWS credentials/config',
    severity: 'high',
    category: 'cloud',
    patterns: ['~/.aws/**'],
    source: 'https://docs.aws.amazon.com/cli/v1/userguide/cli-configure-files.html',
  },
  {
    id: 'gcloud-credentials',
    label: 'Google Cloud credentials',
    severity: 'high',
    category: 'cloud',
    patterns: ['~/.config/gcloud/**', '~/AppData/Roaming/gcloud/**'],
    source: 'https://cloud.google.com/sdk/docs/configurations',
  },
  {
    id: 'azure-credentials',
    label: 'Azure CLI tokens',
    severity: 'high',
    category: 'cloud',
    patterns: ['~/.azure/**'],
    source: 'https://learn.microsoft.com/en-us/cli/azure/azure-cli-configuration',
  },
  {
    id: 'kube-config',
    label: 'Kubernetes kubeconfig',
    severity: 'high',
    category: 'cloud',
    patterns: ['~/.kube/**'],
    source: 'https://kubernetes.io/docs/concepts/configuration/organize-cluster-access-kubeconfig/',
  },
  {
    id: 'docker-config',
    label: 'Docker registry auth',
    severity: 'high',
    category: 'cloud',
    patterns: ['~/.docker/config.json'],
    source: 'https://docs.docker.com/reference/cli/docker/login/#credential-storage',
  },
  {
    id: 'devops-cli-tokens',
    label: 'DevOps CLI tokens (doctl, hcloud, Vault, OCI, rclone, s3cmd)',
    severity: 'high',
    category: 'cloud',
    patterns: ['~/.config/doctl/**', '~/.config/hcloud/**', '~/.vault-token', '~/.oci/**', '~/.config/rclone/rclone.conf', '~/.s3cfg', '~/.boto'],
    source: 'https://developer.hashicorp.com/vault/docs/commands/token-helper',
  },
  // ---- package registries / VCS -------------------------------------------------------
  {
    id: 'npmrc',
    label: 'npm auth config (.npmrc)',
    severity: 'high',
    category: 'registry',
    patterns: ['**/.npmrc', '~/.config/yarn/**/.yarnrc.yml', '**/.yarnrc.yml'],
    source: 'https://docs.npmjs.com/cli/configuring-npm/npmrc',
  },
  {
    id: 'pypirc',
    label: 'PyPI upload credentials (.pypirc)',
    severity: 'high',
    category: 'registry',
    patterns: ['~/.pypirc'],
    source: 'https://packaging.python.org/en/latest/specifications/pypirc/',
  },
  {
    id: 'registry-tokens-misc',
    label: 'Cargo/RubyGems/Maven/Composer/Hugging Face tokens',
    severity: 'high',
    category: 'registry',
    patterns: ['~/.cargo/credentials', '~/.cargo/credentials.toml', '~/.gem/credentials', '~/.m2/settings.xml', '~/.composer/auth.json', '~/.config/composer/auth.json', '~/.cache/huggingface/token', '~/.huggingface/token'],
    source: 'https://doc.rust-lang.org/cargo/reference/config.html#credentials',
  },
  {
    id: 'netrc',
    label: '.netrc (plaintext machine logins)',
    severity: 'high',
    category: 'registry',
    patterns: ['~/.netrc', '~/_netrc'],
    source: 'https://www.gnu.org/software/inetutils/manual/html_node/The-_002enetrc-file.html',
  },
  {
    id: 'gh-hosts',
    label: 'GitHub CLI token (hosts.yml)',
    severity: 'high',
    category: 'registry',
    patterns: ['~/.config/gh/hosts.yml', '~/AppData/Roaming/GitHub CLI/hosts.yml'],
    source: 'https://cli.github.com/manual/gh_help_environment',
  },
  {
    id: 'git-credentials',
    label: 'git credential store',
    severity: 'high',
    category: 'registry',
    patterns: ['~/.git-credentials', '~/.config/git/credentials'],
    source: 'https://git-scm.com/docs/git-credential-store',
  },
  {
    id: 'gitconfig',
    label: 'global git config (identity, URL rewrites, tokens)',
    severity: 'low',
    category: 'registry',
    patterns: ['~/.gitconfig', '~/.config/git/config'],
    source: 'https://git-scm.com/docs/git-config#FILES',
  },
  // ---- AI tooling credentials ---------------------------------------------------------
  {
    id: 'ai-cli-credentials',
    label: 'AI CLI credentials (Claude Code, Codex, Copilot)',
    severity: 'high',
    category: 'ai',
    patterns: ['~/.claude/.credentials.json', '~/.claude.json', '~/.codex/auth.json', '~/.config/github-copilot/**', '~/.config/openai/**', '~/.anthropic/**'],
    source: 'https://docs.anthropic.com/en/docs/claude-code/settings',
  },
  // ---- shell & REPL histories ---------------------------------------------------------
  {
    id: 'shell-history',
    label: 'shell history',
    severity: 'medium',
    category: 'history',
    patterns: ['~/.bash_history', '~/.zsh_history', '~/.zhistory', '~/.history', '~/.sh_history', '~/.local/share/fish/fish_history', '~/.zsh_sessions/**'],
    source: 'https://www.gnu.org/software/bash/manual/html_node/Bash-History-Facilities.html',
  },
  {
    id: 'repl-history',
    label: 'REPL / DB client history',
    severity: 'medium',
    category: 'history',
    patterns: ['~/.python_history', '~/.node_repl_history', '~/.psql_history', '~/.mysql_history', '~/.sqlite_history', '~/.rediscli_history', '~/.irb_history'],
    source: 'https://www.postgresql.org/docs/current/app-psql.html#APP-PSQL-FILES',
  },
  {
    id: 'powershell-history',
    label: 'PowerShell PSReadLine history',
    severity: 'medium',
    category: 'history',
    patterns: ['~/AppData/Roaming/Microsoft/Windows/PowerShell/PSReadLine/**', '~/.local/share/powershell/PSReadLine/**'],
    source: 'https://learn.microsoft.com/en-us/powershell/module/psreadline/about/about_psreadline#command-history',
  },
  {
    id: 'shell-rc',
    label: 'shell startup files (often export secrets)',
    severity: 'low',
    category: 'history',
    patterns: ['~/.bashrc', '~/.bash_profile', '~/.zshrc', '~/.zshenv', '~/.zprofile', '~/.profile'],
    source: 'https://www.gnu.org/software/bash/manual/html_node/Bash-Startup-Files.html',
  },
  // ---- browsers -----------------------------------------------------------------------
  ...chromiumRules(),
  {
    id: 'browser-cookies-firefox',
    label: 'Firefox cookie store',
    severity: 'high',
    category: 'browser',
    patterns: FIREFOX_ROOTS.flatMap((r) => [`${r}/**/cookies.sqlite`, `${r}/**/cookies.sqlite-wal`]),
    source: 'https://support.mozilla.org/en-US/kb/profiles-where-firefox-stores-user-data',
  },
  {
    id: 'browser-logins-firefox',
    label: 'Firefox saved logins and key database',
    severity: 'high',
    category: 'browser',
    patterns: FIREFOX_ROOTS.flatMap((r) => [`${r}/**/logins.json`, `${r}/**/key4.db`, `${r}/**/key3.db`]),
    source: 'https://support.mozilla.org/en-US/kb/recovering-important-data-from-an-old-profile',
  },
  {
    id: 'browser-cookies-safari',
    label: 'Safari cookie store',
    severity: 'high',
    category: 'browser',
    patterns: ['~/Library/Cookies/**', '~/Library/Containers/com.apple.Safari/Data/Library/Cookies/**'],
    source: 'https://developer.apple.com/documentation/foundation/httpcookiestorage',
  },
  {
    id: 'browser-data-safari',
    label: 'Safari history / form data',
    severity: 'medium',
    category: 'browser',
    patterns: ['~/Library/Safari/**', '~/Library/Containers/com.apple.Safari/Data/Library/Safari/**'],
    source: 'https://support.apple.com/guide/safari/welcome/mac',
  },
  {
    id: 'browser-wallet-extension',
    label: 'MetaMask extension storage',
    severity: 'high',
    category: 'wallet',
    // MetaMask's Chrome Web Store extension id
    patterns: ['**/Local Extension Settings/nkbihfbeogaeaoehlefnkodbefgpgknn/**'],
    source: 'https://support.metamask.io/configure/wallet/how-to-restore-your-metamask-wallet/',
  },
  // ---- OS credential stores / password managers ---------------------------------------
  {
    id: 'keychain-macos',
    label: 'macOS Keychain files',
    severity: 'high',
    category: 'keychain',
    patterns: ['~/Library/Keychains/**', '/Library/Keychains/**'],
    source: 'https://support.apple.com/guide/keychain-access/what-is-keychain-access-kyca1083/mac',
  },
  {
    id: 'keyring-linux',
    label: 'Linux keyrings / KWallet',
    severity: 'high',
    category: 'keychain',
    patterns: ['~/.local/share/keyrings/**', '~/.gnome2/keyrings/**', '~/.local/share/kwalletd/**'],
    source: 'https://specifications.freedesktop.org/secret-service-spec/latest/',
  },
  {
    id: 'credential-store-windows',
    label: 'Windows Credential Manager / DPAPI blobs',
    severity: 'high',
    category: 'keychain',
    patterns: ['~/AppData/Roaming/Microsoft/Credentials/**', '~/AppData/Local/Microsoft/Credentials/**', '~/AppData/Roaming/Microsoft/Protect/**', '~/AppData/Local/Microsoft/Vault/**'],
    source: 'https://learn.microsoft.com/en-us/windows/win32/secauthn/credentials-management',
  },
  {
    id: 'password-manager-vaults',
    label: 'password manager vaults (1Password, Bitwarden, KeePass, pass)',
    severity: 'high',
    category: 'keychain',
    patterns: [
      '~/Library/Group Containers/*.com.1password/**',
      '~/.config/1Password/**',
      '~/AppData/Local/1Password/**',
      '~/Library/Application Support/Bitwarden/**',
      '~/.config/Bitwarden/**',
      '~/AppData/Roaming/Bitwarden/**',
      '~/.password-store/**',
      '**/*.kdbx',
      '**/*.kdb',
    ],
    source: 'https://bitwarden.com/help/data-storage/',
  },
  // ---- crypto wallets -----------------------------------------------------------------
  {
    id: 'wallet-ethereum',
    label: 'Ethereum keystore',
    severity: 'high',
    category: 'wallet',
    patterns: ['~/Library/Ethereum/keystore/**', '~/.ethereum/keystore/**', '~/AppData/Roaming/Ethereum/keystore/**', '**/keystore/UTC--*'],
    source: 'https://geth.ethereum.org/docs/fundamentals/account-management',
  },
  {
    id: 'wallet-electrum',
    label: 'Electrum wallets',
    severity: 'high',
    category: 'wallet',
    patterns: ['~/.electrum/**', '~/Library/Application Support/Electrum/**', '~/AppData/Roaming/Electrum/**'],
    source: 'https://electrum.readthedocs.io/en/latest/faq.html',
  },
  {
    id: 'wallet-exodus',
    label: 'Exodus wallet data',
    severity: 'high',
    category: 'wallet',
    patterns: ['~/Library/Application Support/Exodus/**', '~/.config/Exodus/**', '~/AppData/Roaming/Exodus/**'],
    source: 'https://www.exodus.com/support/',
  },
  {
    id: 'wallet-solana',
    label: 'Solana keypair (id.json)',
    severity: 'high',
    category: 'wallet',
    patterns: ['~/.config/solana/**', '~/AppData/Roaming/solana/**'],
    source: 'https://docs.solanalabs.com/cli/wallets/file-system',
  },
  {
    id: 'wallet-bitcoin',
    label: 'Bitcoin Core wallet.dat',
    severity: 'high',
    category: 'wallet',
    patterns: ['**/wallet.dat', '~/.bitcoin/**', '~/Library/Application Support/Bitcoin/**', '~/AppData/Roaming/Bitcoin/**'],
    source: 'https://github.com/bitcoin/bitcoin/blob/master/doc/files.md',
  },
  // ---- chat apps / personal data ------------------------------------------------------
  {
    id: 'chat-app-sessions',
    label: 'chat app session stores (Discord, Slack, Signal, Telegram)',
    severity: 'high',
    category: 'personal',
    patterns: [
      '~/Library/Application Support/discord/**',
      '~/.config/discord/**',
      '~/AppData/Roaming/discord/**',
      '~/Library/Application Support/Slack/**',
      '~/.config/Slack/**',
      '~/AppData/Roaming/Slack/**',
      '~/Library/Application Support/Signal/**',
      '~/.config/Signal/**',
      '~/AppData/Roaming/Signal/**',
      '~/Library/Application Support/Telegram Desktop/**',
      '~/.local/share/TelegramDesktop/**',
    ],
    source: 'https://www.electronjs.org/docs/latest/api/app#appgetpathname',
  },
  {
    id: 'macos-personal-data',
    label: 'macOS Messages / Mail / Contacts databases',
    severity: 'medium',
    category: 'personal',
    patterns: ['~/Library/Messages/**', '~/Library/Mail/**', '~/Library/Application Support/AddressBook/**'],
    source: 'https://support.apple.com/guide/mac-help/protect-your-mac-from-malware-mh40596/mac',
  },
  // ---- system -------------------------------------------------------------------------
  {
    id: 'system-auth',
    label: 'system auth files (shadow, sudoers)',
    severity: 'high',
    category: 'system',
    patterns: ['/etc/shadow', '/etc/master.passwd', '/etc/sudoers', '/etc/sudoers.d/**'],
    source: 'https://man7.org/linux/man-pages/man5/shadow.5.html',
  },
  {
    id: 'proc-environ',
    label: 'process environment (/proc/*/environ)',
    severity: 'high',
    category: 'system',
    patterns: ['/proc/*/environ'],
    source: 'https://man7.org/linux/man-pages/man5/proc_pid_environ.5.html',
  },
];

// Files that look like env files but are conventionally committed, non-secret templates.
const NEGATIVE = /(?:^|\/)\.env\.(?:example|sample|template|dist|defaults?)$|(?:^|\/)[^/]*\.env\.(?:example|sample|template)$/i;

// ---- glob compilation -----------------------------------------------------------------------

function escapeRe(s: string): string {
  return s.replace(/[.+^${}()|[\]\\]/g, '\\$&');
}

/** Compile a rule glob into an anchored case-insensitive regex. Exported for tests. */
export function globToRegExp(glob: string): RegExp {
  let src = '';
  let g = glob;
  // `X/**` also matches X itself
  const trailingStar = g.endsWith('/**');
  if (trailingStar) g = g.slice(0, -3);
  for (let i = 0; i < g.length; i++) {
    const c = g[i]!;
    if (c === '*') {
      if (g[i + 1] === '*') {
        // `**/` = zero or more whole segments ; bare `**` = anything
        if (g[i + 2] === '/') {
          src += '(?:.*/)?';
          i += 2;
        } else {
          src += '.*';
          i += 1;
        }
      } else {
        src += '[^/]*';
      }
    } else if (c === '?') {
      src += '[^/]';
    } else {
      src += escapeRe(c);
    }
  }
  if (trailingStar) src += '(?:/.*)?';
  return new RegExp('^' + src + '$', 'i');
}

interface Compiled {
  rule: SensitiveRule;
  res: RegExp[];
}
let compiled: Compiled[] | null = null;
function getCompiled(): Compiled[] {
  if (!compiled) compiled = RULES.map((rule) => ({ rule, res: rule.patterns.map(globToRegExp) }));
  return compiled;
}

// ---- path normalisation ---------------------------------------------------------------------

export interface NormalizeOptions {
  home?: string;
  /** %APPDATA% */
  appData?: string;
  /** %LOCALAPPDATA% */
  localAppData?: string;
  /** defaults to process.platform; 'win32' makes every backslash a separator */
  platform?: NodeJS.Platform;
  /** environment used to find USERPROFILE/APPDATA when `home`/`appData` are not given (tests inject) */
  env?: Record<string, string | undefined>;
}

const WIN_ABS = /^(?:[A-Za-z]:[\\/]|\\\\)/;

/** Windows-style absolute path: drive letter, UNC, or extended-length (`\\?\C:\...`). */
export function looksWindowsPath(p: string): boolean {
  return WIN_ABS.test(p);
}

/**
 * The user's home directory as the OS reports it. On win32 that is %USERPROFILE% (what
 * os.homedir() reads), falling back to %HOMEDRIVE%%HOMEPATH%. Pure: pass `env`/`osHome` in tests.
 */
export function homeDir(platform: NodeJS.Platform = process.platform, env: Record<string, string | undefined> = process.env, osHome: () => string = os.homedir): string {
  if (platform === 'win32') {
    if (env.USERPROFILE) return env.USERPROFILE;
    if (env.HOMEDRIVE && env.HOMEPATH) return env.HOMEDRIVE + env.HOMEPATH;
  }
  return osHome();
}

function slash(p: string, winLike: boolean): string {
  let s = p;
  if (winLike) {
    // extended-length / device prefixes: \\?\C:\x -> C:\x ; \\?\UNC\srv\share -> \\srv\share
    s = s.replace(/^[\\/]{2}[?.][\\/]UNC[\\/]/i, '\\\\').replace(/^[\\/]{2}[?.][\\/]/, '');
    s = s.replace(/\\/g, '/');
  }
  return s.replace(/\/+$/, '').replace(/(?<=.)\/{2,}/g, '/') || '/';
}

/**
 * Rewrite an absolute path into the `~`-anchored form the rules use.
 * Pure function of (path, options) so tests can inject a fake home / platform.
 * Backslashes are only separators on win32 or for paths that are unmistakably Windows
 * (drive letter / UNC); on POSIX a backslash is a legal filename character.
 */
export function normalizePath(p: string, o: NormalizeOptions = {}): string {
  const platform = o.platform ?? process.platform;
  const env = o.env ?? process.env;
  const winLike = platform === 'win32' || looksWindowsPath(p);
  const home = slash(o.home ?? homeDir(platform, env), winLike || (o.home !== undefined && looksWindowsPath(o.home)));
  const appData = o.appData ?? env.APPDATA;
  const localAppData = o.localAppData ?? env.LOCALAPPDATA;
  let s = slash(p, winLike);
  const lower = s.toLowerCase();
  const swap = (prefix: string | undefined, repl: string): boolean => {
    if (!prefix) return false;
    const pre = slash(prefix, winLike || looksWindowsPath(prefix));
    const pl = pre.toLowerCase();
    if (lower === pl || lower.startsWith(pl + '/')) {
      s = repl + s.slice(pre.length);
      return true;
    }
    return false;
  };
  // %APPDATA% / %LOCALAPPDATA% first (they live under the profile but may be relocated)
  if (swap(appData, '~/AppData/Roaming')) return s;
  if (swap(localAppData, '~/AppData/Local')) return s;
  if (swap(home, '~')) return s;
  return s;
}

const cache = new Map<string, SensitiveMatch | null>();

/**
 * Return the first (highest-severity-first) rule matching `absPath`, or null.
 * `opts` lets tests inject a fake HOME; results are only cached for the default environment.
 */
export function matchSensitive(absPath: string, opts?: NormalizeOptions): SensitiveMatch | null {
  const useCache = opts === undefined;
  if (useCache) {
    const hit = cache.get(absPath);
    if (hit !== undefined) return hit;
  }
  const norm = normalizePath(absPath, opts);
  let result: SensitiveMatch | null = null;
  if (!NEGATIVE.test(norm)) {
    const order: Severity[] = ['high', 'medium', 'low'];
    outer: for (const sev of order) {
      for (const { rule, res } of getCompiled()) {
        if (rule.severity !== sev) continue;
        if (res.some((re) => re.test(norm))) {
          result = { rule: rule.id, label: rule.label, severity: rule.severity, category: rule.category };
          break outer;
        }
      }
    }
  }
  if (useCache) {
    if (cache.size > 5000) cache.clear();
    cache.set(absPath, result);
  }
  return result;
}
