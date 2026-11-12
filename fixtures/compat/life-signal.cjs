process.on('SIGTERM', () => { console.log('got SIGTERM'); process.exit(0); });
process.on('exit', (c) => console.log('exit', c));
console.log('ready');
setTimeout(() => process.kill(process.pid, 'SIGTERM'), 10);
setTimeout(() => {}, 1000);
