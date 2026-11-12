process.on('exit', (c) => console.log('exit', c));
require('fs').promises.readFile('/definitely/not/here');
