/**
 * Shared hook plumbing: the emit function, re-entrancy guards and small helpers.
 * Nothing here may throw into user code.
 */
import type { EventInput, EventWriter } from '../events.js';

let writer: EventWriter | null = null;
let emitting = false; // inside writer.emit
let hooking = false; // inside hook logic (blocks nested hooked calls made by our own code)
let depth = 0; // inside an original function invoked by a hook (suppresses nested hooked calls)

export function setWriter(w: EventWriter): void {
  writer = w;
}

export function getWriter(): EventWriter | null {
  return writer;
}

/** Emit an event (never recursive, never throws). */
export function emit(ev: EventInput): void {
  if (emitting || !writer) return;
  emitting = true;
  try {
    writer.emit(ev);
  } catch {
    /* swallow */
  } finally {
    emitting = false;
  }
}

/** Run `fn` as hook logic: guarded against recursion and exceptions. Returns undefined on failure. */
export function guarded<T>(fn: () => T): T | undefined {
  if (hooking) return undefined;
  hooking = true;
  try {
    return fn();
  } catch {
    return undefined;
  } finally {
    hooking = false;
  }
}

/** True while an original function called by a hook is on the stack. */
export function nested(): boolean {
  return depth > 0;
}

/**
 * Call `orig` with `depth` raised so that hooked functions it calls internally (e.g. exec ->
 * execFile) do not produce duplicate events. Semantics of the call are untouched.
 */
export function callOrig<T>(orig: (...a: any[]) => T, self: unknown, args: unknown[]): T {
  depth++;
  try {
    return orig.apply(self, args);
  } finally {
    depth--;
  }
}

/** Strip credentials and query from a URL; never record secrets that ride in a query string. */
export function safeUrl(input: string): { url: string; hasQuery: boolean } | null {
  try {
    const u = new URL(input);
    const hasQuery = u.search.length > 1;
    u.username = '';
    u.password = '';
    u.search = '';
    u.hash = '';
    return { url: u.toString(), hasQuery };
  } catch {
    return null;
  }
}
