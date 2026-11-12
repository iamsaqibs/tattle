const fs = require('fs');
const f = process.argv[2] || __filename;
const t0 = process.hrtime.bigint();
let n = 0;
for (let i = 0; i < 20000; i++) { if (fs.statSync(f).size > 0) n++; }
const ms = Number(process.hrtime.bigint() - t0) / 1e6;
console.error('PERF_MS ' + ms.toFixed(1));
console.log(n);
