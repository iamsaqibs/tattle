// big write to a pipe right before process.exit must not be truncated or reordered
const big = 'x'.repeat(200000);
process.stdout.write(big + '\n');
process.on('exit', () => console.log('exit-handler'));
process.exit(2);
