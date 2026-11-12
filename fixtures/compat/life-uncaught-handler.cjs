const fs = require('fs');
console.log('uncaught-count', process.listenerCount('uncaughtException'), process.listenerCount('unhandledRejection'));
process.on('uncaughtException', (e, origin) => { console.log('caught', e.message, origin); process.exitCode = 4; });
process.on('exit', (c) => console.log('exit', c));
setTimeout(() => { throw new Error('boom'); }, 5);
setTimeout(() => console.log('still alive'), 30);
