/** Tiny helper to replace a method with a wrapper while keeping its name/length. */
export function patch<T extends object>(obj: T, name: string, make: (orig: (...a: any[]) => any) => (this: any, ...a: any[]) => any): boolean {
  try {
    const orig = (obj as any)[name];
    if (typeof orig !== 'function') return false;
    const wrapped = make(orig);
    try {
      // Carry over every own property of the original (symbols included): util.promisify reads
      // `util.promisify.custom` and Node's internal kCustomPromisifyArgs off the function object
      // (dns.lookup, fs.exists, child_process.exec/execFile, fs.read...), and `fs.realpath.native`
      // is a property. Dropping them silently changes what util.promisify(fn) resolves to.
      for (const k of Reflect.ownKeys(orig)) {
        if (k === 'name' || k === 'length' || k === 'prototype' || k === 'arguments' || k === 'caller') continue;
        const d = Object.getOwnPropertyDescriptor(orig, k);
        if (d) Object.defineProperty(wrapped, k, d);
      }
    } catch {
      /* cosmetic only */
    }
    try {
      Object.defineProperty(wrapped, 'name', { value: orig.name, configurable: true });
      Object.defineProperty(wrapped, 'length', { value: orig.length, configurable: true });
    } catch {
      /* cosmetic only */
    }
    (obj as any)[name] = wrapped;
    return true;
  } catch {
    return false;
  }
}
