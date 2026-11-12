// User exit handlers: ordering, listener counts, mutation of exitCode inside handler, fs inside handler.
const fs = require('fs');
const data = require('path').join(process.argv[2] || require('os').tmpdir(), 'x.txt');
fs.writeFileSync(data, 'x');
console.log('count-at-start', process.listenerCount('exit'), process.listeners('exit').length, process.eventNames().filter((n) => n === 'exit').length);
process.on('exit', (c) => { console.log('first', c); });
process.prependListener('exit', () => console.log('prepended'));
process.once('exit', () => console.log('once'));
console.log('count-after-add', process.listenerCount('exit'));
process.on('exit', (c) => { console.log('last-sets-exitCode', c); process.exitCode = 9; try { fs.readFileSync(data); console.log('sync fs in exit ok'); } catch (e) { console.log('FAIL', e.message); } });
process.on('beforeExit', () => console.log('beforeExit'));
setTimeout(() => console.log('timer'), 5);
console.log('removeAll-count', (() => { const n = process.listenerCount('exit'); return n; })());
