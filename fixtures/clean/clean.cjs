// "clean" fixture: pure computation, writes then reads one temp file, never touches the network.
'use strict';
const fs = require('fs');
const path = require('path');

function fib(n) {
  return n < 2 ? n : fib(n - 1) + fib(n - 2);
}
const out = path.join(process.env.CLEAN_OUT, 'result.txt');
fs.writeFileSync(out, String(fib(20)));
const back = fs.readFileSync(out, 'utf8');
if (back !== '6765') process.exit(9);
console.log('clean ok', back);
