const { parentPort, workerData } = require('worker_threads');
const fs = require('fs');
process.env.TT_W = 'w';
parentPort.postMessage({ data: workerData, read: fs.readFileSync(workerData.file, 'utf8'), env: process.env.TT_W, parentEnv: process.env.TT_PROBE || null, keys: Object.keys(process.env).includes('PATH') });
