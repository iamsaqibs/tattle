const fsp = require('fs').promises;
process.on('unhandledRejection', (r) => { console.log('unhandledRejection', r.code); });
fsp.readFile('/definitely/not/here');
fsp.stat('/definitely/not/here');
const p = fsp.readFile('/definitely/not/here'); p.catch(() => console.log('handled'));
setTimeout(() => {}, 20);
