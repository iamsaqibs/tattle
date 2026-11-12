const fsp = require('fs').promises;
process.on('unhandledRejection', (r) => { console.log('unhandledRejection', r.code); });
fsp.readFile('/definitely/not/here');
fsp.stat('/definitely/not/here');
// Threadpool completion order of concurrent fs calls is nondeterministic, so run the handled one
// after the unhandled ones have settled to keep stdout stable across runs.
setTimeout(() => {
  const p = fsp.readFile('/definitely/not/here'); p.catch(() => console.log('handled'));
}, 100);
setTimeout(() => {}, 250);
