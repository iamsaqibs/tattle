import crypto from 'node:crypto';
import fs from 'node:fs';
import path from 'node:path';
import { describe, expect, it } from 'vitest';
import { canonicalize, loadOrCreateKey, sha256File, signReceipt, verifyReceipt } from '../src/sign.js';
import { tmpDir } from './helpers.js';

const body = { verdict: 'clean', n: 3, nested: { b: 1, a: [1, 2] } };

async function setup() {
  const dir = tmpDir();
  const key = loadOrCreateKey(path.join(dir, 'home'));
  const ev = path.join(dir, 'events.jsonl');
  fs.writeFileSync(ev, '{"a":1}\n');
  const receipt = signReceipt(body, await sha256File(ev), key);
  return { dir, key, ev, receipt };
}

describe('sign', () => {
  it('canonicalizes deterministically', () => {
    expect(canonicalize({ b: 1, a: { d: 2, c: [true, null] } })).toBe('{"a":{"c":[true,null],"d":2},"b":1}');
    expect(() => canonicalize({ a: undefined })).toThrow();
    expect(() => canonicalize(NaN)).toThrow();
    expect(() => canonicalize(() => 1)).toThrow();
  });

  it('roundtrips', async () => {
    const { receipt, ev, key } = await setup();
    expect(receipt.id).toMatch(/^tt_[0-9a-f]{12}$/);
    const r = await verifyReceipt(JSON.parse(JSON.stringify(receipt)), { eventsPath: ev, trustedFingerprints: [key.fingerprint] });
    expect(r.ok).toBe(true);
    expect(r.checks).toEqual({ signature: true, idMatches: true, eventsHash: 'match', trusted: true });
    expect((await verifyReceipt(receipt, { trustedFingerprints: ['0'] })).ok).toBe(false);
  });

  it('detects tampered body and id', async () => {
    const { receipt } = await setup();
    const b = structuredClone(receipt) as any;
    b.body.verdict = 'evil';
    const rb = await verifyReceipt(b);
    expect(rb.ok).toBe(false);
    expect(rb.checks.signature).toBe(false);
    const i = structuredClone(receipt) as any;
    i.id = 'tt_000000000000';
    const ri = await verifyReceipt(i);
    expect(ri.ok).toBe(false);
    expect(ri.checks.idMatches).toBe(false);
  });

  it('detects events tamper and missing', async () => {
    const { receipt, ev, dir } = await setup();
    fs.appendFileSync(ev, 'x');
    const r = await verifyReceipt(receipt, { eventsPath: ev });
    expect(r.ok).toBe(false);
    expect(r.checks.eventsHash).toBe('mismatch');
    expect((await verifyReceipt(receipt, { eventsPath: path.join(dir, 'nope') })).checks.eventsHash).toBe('missing');
  });

  it('rejects swapped public key', async () => {
    const { receipt } = await setup();
    const other = crypto.generateKeyPairSync('ed25519').publicKey;
    const s = structuredClone(receipt) as any;
    s.signature.publicKey = other.export({ type: 'spki', format: 'der' }).toString('base64');
    const r = await verifyReceipt(s);
    expect(r.ok).toBe(false);
    expect(r.checks.signature).toBe(false);
  });

  it('persists and reuses the key', () => {
    const home = path.join(tmpDir(), 'h');
    const a = loadOrCreateKey(home);
    const b = loadOrCreateKey(home);
    expect(b.fingerprint).toBe(a.fingerprint);
    expect(a.fingerprint).toMatch(/^[0-9a-f]{16}$/);
    expect(fs.existsSync(path.join(home, 'key.pub'))).toBe(true);
  });

  it.skipIf(process.platform === 'win32')('uses restrictive permissions', () => {
    const home = path.join(tmpDir(), 'h');
    loadOrCreateKey(home);
    expect(fs.statSync(path.join(home, 'key')).mode & 0o777).toBe(0o600);
    expect(fs.statSync(home).mode & 0o777).toBe(0o700);
  });

  it('never throws on malformed input', async () => {
    for (const bad of [null, undefined, 5, 'x', {}, { receiptVersion: 1 }, { receiptVersion: 1, id: 'a', body: {}, eventsSha256: 'x', signature: { alg: 'ed25519', publicKey: '!!', sig: '??' } }]) {
      const r = await verifyReceipt(bad as any);
      expect(r.ok).toBe(false);
    }
  });
});
