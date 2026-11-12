process.on('exit', (c) => console.log('exit', c));
setTimeout(() => { console.log('calling process.exit(3)'); process.exit(3); }, 5);
setTimeout(() => console.log('never'), 1000);
