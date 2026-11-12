// Mimics how npm (and many CLIs) mutate process.env. Output must be identical hooked and unhooked.
const out = [];
const t = (n, f) => { try { out.push(n + ':' + JSON.stringify(f())); } catch (e) { out.push(n + ':THROW ' + e.code); } };
t('assign', () => { process.env.TT_A = 'x'; return process.env.TT_A; });
t('assign-number', () => { process.env.TT_N = 5; return process.env.TT_N; });
t('assign-undefined', () => { process.env.TT_U = undefined; return process.env.TT_U; });
t('Object.assign', () => { Object.assign(process.env, { TT_B: 'y' }); return process.env.TT_B; });
t('defineProperty-full', () => { Object.defineProperty(process.env, 'TT_C', { value: 'z', configurable: true, writable: true, enumerable: true }); return process.env.TT_C; });
t('defineProperty-partial', () => { Object.defineProperty(process.env, 'TT_D', { value: 'z' }); return 1; });
t('descriptor', () => Object.getOwnPropertyDescriptor(process.env, 'TT_A'));
t('in', () => ['TT_A' in process.env, 'TT_NOPE' in process.env]);
t('delete', () => { delete process.env.TT_A; return [process.env.TT_A, 'TT_A' in process.env]; });
t('keys', () => Object.keys(process.env).filter((k) => k.startsWith('TT_')).sort());
t('spread', () => Object.keys({ ...process.env }).filter((k) => k.startsWith('TT_')).sort());
t('same-object', () => process.env === require('process').env);
console.log(out.join('\n'));
