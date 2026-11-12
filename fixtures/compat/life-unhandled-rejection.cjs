process.on('exit', (c) => console.log('exit', c));
Promise.reject(new Error('rej'));
require('fs').promises.readFile('/definitely/not/here'); // unhandled fs rejection must still be unhandled
