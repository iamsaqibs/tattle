import fs from 'node:fs';
import path from 'node:path';
import { describe, expect, it } from 'vitest';
import { createEventWriter, parseEventLine, parseEvents, readEventLog, SCHEMA_VERSION } from '../src/events.js';
import { tmpDir } from './helpers.js';

describe('event writer', () => {
  it('writes one JSON line per event with the v1 envelope', () => {
    const file = path.join(tmpDir(), 'events.jsonl');
    const w = createEventWriter(file);
    w.emit({ cat: 'fs', op: 'read', target: '/x', bytes: 3, verdictHint: 'sensitive', detail: { rule: 'dotenv' } });
    w.emit({ cat: 'net', op: 'connect', target: 'localhost:1' });
    w.close();
    const lines = fs.readFileSync(file, 'utf8').trim().split('\n');
    expect(lines).toHaveLength(2);
    const [a, b] = lines.map((l) => JSON.parse(l));
    expect(a).toMatchObject({ v: SCHEMA_VERSION, pid: process.pid, ppid: process.ppid, seq: 0, phase: 'run', cat: 'fs', op: 'read', target: '/x', bytes: 3, verdictHint: 'sensitive' });
    expect(typeof a.ts).toBe('number');
    expect(a.ts).toBeGreaterThan(1.6e12);
    expect(b.seq).toBe(1);
    expect('bytes' in b).toBe(false);
  });

  it('rotates atomically to events.N.jsonl and readEventLog merges all parts', () => {
    const dir = tmpDir();
    const file = path.join(dir, 'events.jsonl');
    const w = createEventWriter(file, { maxBytes: 2000 });
    for (let i = 0; i < 300; i++) w.emit({ cat: 'fs', op: 'stat', target: `/p/${i}` });
    w.close();
    const names = fs.readdirSync(dir).sort();
    expect(names).toContain('events.1.jsonl');
    expect(names).toContain('events.jsonl');
    const all = readEventLog(file);
    expect(all).toHaveLength(300);
    expect(all.map((e) => e.seq)).toEqual([...Array(300).keys()]);
  });

  it('never throws when the log path is unusable', () => {
    // A path *under a regular file* is unusable on every OS (ENOTDIR). Don't use /proc/...: recursive
    // mkdir under /proc can spin forever on Linux's Node, which hung the Ubuntu CI job.
    const blocker = path.join(tmpDir(), 'a-file');
    fs.writeFileSync(blocker, 'x');
    const w = createEventWriter(path.join(blocker, 'sub', 'events.jsonl'));
    expect(() => w.emit({ cat: 'fs', op: 'read', target: '/x' })).not.toThrow();
  });
});

describe('event parser (forward compatible)', () => {
  it('preserves unknown fields and accepts future versions', () => {
    const e = parseEventLine(JSON.stringify({ v: 7, ts: 1, pid: 2, cat: 'net', op: 'connect', target: 'a:1', shiny: { new: true }, detail: { x: 1 } }));
    expect(e).not.toBeNull();
    expect(e!.v).toBe(7);
    expect(e!.shiny).toEqual({ new: true });
    expect(e!.seq).toBe(0); // defaulted
  });
  it('defaults a missing version to 1 and skips garbage', () => {
    expect(parseEventLine('{"ts":1,"cat":"fs","op":"read"}')!.v).toBe(1);
    expect(parseEventLine('not json')).toBeNull();
    expect(parseEventLine('[1,2]')).toBeNull();
    expect(parseEventLine('{"cat":"fs"}')).toBeNull();
    expect(parseEvents('\n{"ts":1,"cat":"a","op":"b"}\ngarbage\n{"ts":2,"cat":"a","op":"c"}\n')).toHaveLength(2);
  });
});
