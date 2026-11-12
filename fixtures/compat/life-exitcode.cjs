process.exitCode = 7;
console.log('exitCode-set', process.exitCode);
process.on('exit', (c) => console.log('exit handler code', c, process.exitCode));
