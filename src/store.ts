/** Receipt store: resolve ids / dirs / paths under TATTLE_HOME/receipts and load signed receipts. */
import fs from 'node:fs';
import os from 'node:os';
import path from 'node:path';
import type { StoredReceipt } from './receipt.js';

export function tattleHome(): string {
  return process.env.TATTLE_HOME || path.join(os.homedir(), '.tattle');
}
export const receiptsRoot = (home: string = tattleHome()): string => path.join(home, 'receipts');

export interface Loaded {
  dir: string;
  file: string;
  receipt: StoredReceipt;
}

export function readReceiptFile(file: string): StoredReceipt {
  return JSON.parse(fs.readFileSync(file, 'utf8')) as StoredReceipt;
}

function tryRead(file: string): StoredReceipt | null {
  try {
    return readReceiptFile(file);
  } catch {
    return null;
  }
}

/** All receipts under the store, newest first. */
export function listReceipts(home: string = tattleHome()): Loaded[] {
  const root = receiptsRoot(home);
  let names: string[] = [];
  try {
    names = fs.readdirSync(root);
  } catch {
    return [];
  }
  const out: Loaded[] = [];
  for (const n of names) {
    const dir = path.join(root, n);
    const file = path.join(dir, 'receipt.json');
    const receipt = tryRead(file);
    if (receipt && receipt.body && receipt.body.meta) out.push({ dir, file, receipt });
  }
  const t = (l: Loaded) => Date.parse(l.receipt.body.meta.startedAt) || 0;
  return out.sort((a, b) => t(b) - t(a) || b.dir.localeCompare(a.dir));
}

/** Resolve `<receipt.json | receipt dir | id | id-prefix | dir-name | latest>`. Throws with a helpful message. */
export function resolveReceipt(ref: string, home: string = tattleHome()): Loaded {
  if (ref === 'latest') {
    const all = listReceipts(home);
    if (!all.length) throw new Error(`no receipts found under ${receiptsRoot(home)}`);
    return all[0]!;
  }
  // explicit path (file or directory)
  try {
    const st = fs.statSync(ref);
    const file = st.isDirectory() ? path.join(ref, 'receipt.json') : ref;
    const dir = path.dirname(file);
    if (!fs.existsSync(file)) throw new Error(`no receipt.json in ${ref}`);
    let receipt: StoredReceipt;
    try {
      receipt = readReceiptFile(file);
    } catch (e) {
      throw new Error(`cannot parse ${file}: ${(e as Error).message}`);
    }
    return { dir, file, receipt };
  } catch (e) {
    if ((e as NodeJS.ErrnoException).code !== 'ENOENT') throw e;
  }
  // id / prefix lookup
  const want = ref.replace(/^tt_/, '');
  if (!/^[0-9a-zA-Z_-]+$/.test(want) || !want) throw new Error(`cannot find receipt: ${ref}`);
  const matches = listReceipts(home).filter((l) => l.receipt.id.replace(/^tt_/, '').startsWith(want) || path.basename(l.dir).startsWith(ref));
  if (matches.length === 1) return matches[0]!;
  if (matches.length > 1) throw new Error(`ambiguous receipt id "${ref}": ${matches.map((m) => m.receipt.id).join(', ')}`);
  throw new Error(`no receipt matches "${ref}" under ${receiptsRoot(home)}`);
}
