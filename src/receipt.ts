/** Receipt body (what gets signed) and helpers for reading signed receipts back. */
import type { Analysis } from './analyze/index.js';
import type { SignedReceipt } from './sign.js';

export interface ReceiptBody {
  schema: 1;
  meta: {
    tool: { argv: string[] };
    startedAt: string;
    endedAt: string;
    exitCode: number;
    /** file name (relative to the receipt dir) the eventsSha256 covers */
    eventsFile: string;
    tattleVersion: string;
  };
  analysis: Analysis;
}

export function buildReceiptBody(p: { argv: string[]; start: number; end: number; exitCode: number; eventsFile: string; analysis: Analysis; version: string }): ReceiptBody {
  const body: ReceiptBody = {
    schema: 1,
    meta: {
      tool: { argv: p.argv },
      startedAt: new Date(p.start).toISOString(),
      endedAt: new Date(p.end).toISOString(),
      exitCode: p.exitCode,
      eventsFile: p.eventsFile,
      tattleVersion: p.version,
    },
    analysis: p.analysis,
  };
  // drop undefined (canonicalize rejects it) by normalising through JSON
  return JSON.parse(JSON.stringify(body)) as ReceiptBody;
}

export type StoredReceipt = Omit<SignedReceipt, 'body'> & { body: ReceiptBody };
