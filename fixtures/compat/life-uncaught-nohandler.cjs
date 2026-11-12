process.on('exit', (c) => console.log('exit', c, process.exitCode));
setTimeout(() => { throw new Error('boom'); }, 5);
