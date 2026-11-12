import crypto from 'node:crypto';
import fs from 'node:fs';
import os from 'node:os';
import path from 'node:path';

export interface TattleKey {
  privateKey: crypto.KeyObject;
  publicKey: crypto.KeyObject;
  publicKeyPem: string;
  fingerprint: string;
}

export interface SignedReceipt {
  receiptVersion: 1;
  id: string;
  body: object;
  eventsSha256: string;
  signature: { alg: 'ed25519'; publicKey: string; fingerprint: string; sig: string };
}

export interface VerifyResult {
  ok: boolean;
  checks: {
    signature: boolean;
    idMatches: boolean;
    eventsHash?: 'match' | 'mismatch' | 'missing';
    trusted?: boolean;
  };
  errors: string[];
}

export function defaultHome(): string {
  return process.env.TATTLE_HOME ?? path.join(os.homedir(), '.tattle');
}

function fingerprintOf(pub: crypto.KeyObject): string {
  const spki = pub.export({ type: 'spki', format: 'der' });
  // Ed25519 SPKI DER is a 12-byte prefix followed by the 32-byte raw key.
  const raw = spki.subarray(spki.length - 32);
  return crypto.createHash('sha256').update(raw).digest('hex').slice(0, 16);
}

export function loadOrCreateKey(home: string = defaultHome()): TattleKey {
  const privPath = path.join(home, 'key');
  const pubPath = path.join(home, 'key.pub');
  let privateKey: crypto.KeyObject;
  if (fs.existsSync(privPath)) {
    privateKey = crypto.createPrivateKey(fs.readFileSync(privPath));
  } else {
    fs.mkdirSync(home, { recursive: true, mode: 0o700 });
    const pair = crypto.generateKeyPairSync('ed25519');
    privateKey = pair.privateKey;
    fs.writeFileSync(privPath, privateKey.export({ type: 'pkcs8', format: 'pem' }), { mode: 0o600 });
    try {
      fs.chmodSync(privPath, 0o600);
    } catch {}
  }
  const publicKey = crypto.createPublicKey(privateKey);
  const publicKeyPem = publicKey.export({ type: 'spki', format: 'pem' }).toString();
  if (!fs.existsSync(pubPath)) fs.writeFileSync(pubPath, publicKeyPem, { mode: 0o644 });
  return { privateKey, publicKey, publicKeyPem, fingerprint: fingerprintOf(publicKey) };
}

export function canonicalize(value: unknown): string {
  if (value === null) return 'null';
  switch (typeof value) {
    case 'string':
    case 'boolean':
      return JSON.stringify(value);
    case 'number':
      if (!Number.isFinite(value)) throw new TypeError('canonicalize: non-finite number');
      return JSON.stringify(value);
    case 'undefined':
    case 'function':
    case 'symbol':
    case 'bigint':
      throw new TypeError(`canonicalize: unsupported ${typeof value}`);
  }
  if (Array.isArray(value)) return '[' + value.map(canonicalize).join(',') + ']';
  const obj = value as Record<string, unknown>;
  return (
    '{' +
    Object.keys(obj)
      .sort()
      .map((k) => JSON.stringify(k) + ':' + canonicalize(obj[k]))
      .join(',') +
    '}'
  );
}

const sha256 = (s: string) => crypto.createHash('sha256').update(s).digest('hex');

export function sha256File(file: string): Promise<string> {
  return new Promise((resolve, reject) => {
    const h = crypto.createHash('sha256');
    const s = fs.createReadStream(file);
    s.on('error', reject);
    s.on('data', (c) => h.update(c));
    s.on('end', () => resolve(h.digest('hex')));
  });
}

const payload = (r: { id: string; body: object; eventsSha256: string }) =>
  canonicalize({ receiptVersion: 1, id: r.id, body: r.body, eventsSha256: r.eventsSha256 });

export function signReceipt(body: object, eventsSha256: string, key: TattleKey): SignedReceipt {
  const id = 'tt_' + sha256(canonicalize(body) + eventsSha256).slice(0, 12);
  const sig = crypto.sign(null, Buffer.from(payload({ id, body, eventsSha256 })), key.privateKey);
  return {
    receiptVersion: 1,
    id,
    body,
    eventsSha256,
    signature: {
      alg: 'ed25519',
      publicKey: key.publicKey.export({ type: 'spki', format: 'der' }).toString('base64'),
      fingerprint: key.fingerprint,
      sig: sig.toString('base64'),
    },
  };
}

export async function verifyReceipt(
  receipt: unknown,
  opts: { eventsPath?: string; trustedFingerprints?: string[] } = {},
): Promise<VerifyResult> {
  const res: VerifyResult = { ok: false, checks: { signature: false, idMatches: false }, errors: [] };
  try {
    const r = receipt as SignedReceipt;
    if (
      !r || typeof r !== 'object' || r.receiptVersion !== 1 || typeof r.id !== 'string' ||
      !r.body || typeof r.body !== 'object' || typeof r.eventsSha256 !== 'string' ||
      !r.signature || r.signature.alg !== 'ed25519' ||
      typeof r.signature.publicKey !== 'string' || typeof r.signature.sig !== 'string'
    ) {
      res.errors.push('malformed receipt');
      return res;
    }
    let pub: crypto.KeyObject | undefined;
    try {
      pub = crypto.createPublicKey({ key: Buffer.from(r.signature.publicKey, 'base64'), format: 'der', type: 'spki' });
      if (pub.asymmetricKeyType !== 'ed25519') throw new Error('not ed25519');
    } catch {
      res.errors.push('invalid public key');
    }
    res.checks.idMatches = r.id === 'tt_' + sha256(canonicalize(r.body) + r.eventsSha256).slice(0, 12);
    if (!res.checks.idMatches) res.errors.push('id does not match body');
    if (pub) {
      res.checks.signature = crypto.verify(null, Buffer.from(payload(r)), pub, Buffer.from(r.signature.sig, 'base64'));
      if (!res.checks.signature) res.errors.push('signature invalid');
      if (opts.trustedFingerprints) {
        res.checks.trusted = opts.trustedFingerprints.includes(fingerprintOf(pub));
        if (!res.checks.trusted) res.errors.push('signer not trusted');
      }
    } else if (opts.trustedFingerprints) {
      res.checks.trusted = false;
    }
    if (opts.eventsPath) {
      try {
        const h = await sha256File(opts.eventsPath);
        res.checks.eventsHash = h === r.eventsSha256 ? 'match' : 'mismatch';
        if (h !== r.eventsSha256) res.errors.push('events file hash mismatch');
      } catch {
        res.checks.eventsHash = 'missing';
        res.errors.push('events file missing');
      }
    }
    res.ok =
      res.checks.signature && res.checks.idMatches &&
      (res.checks.eventsHash === undefined || res.checks.eventsHash === 'match') &&
      (res.checks.trusted === undefined || res.checks.trusted);
  } catch (e) {
    res.ok = false;
    res.errors.push('verify error: ' + (e as Error).message);
  }
  return res;
}
