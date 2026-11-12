process.removeAllListeners('exit');
console.log('after-removeAll', process.listenerCount('exit'));
process.on('exit', () => console.log('user-exit'));
