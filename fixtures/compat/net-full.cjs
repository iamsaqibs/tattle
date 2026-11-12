// net/http/tls probe, localhost only. argv[2] = scratch dir (for unix sockets).
const net = require('net');
const http = require('http');
const path = require('path');
const dir = process.argv[2];
const out = [];
const log = (n, v) => out.push(n + ':' + JSON.stringify(v));
const wait = (ms) => new Promise((r) => setTimeout(r, ms));

(async () => {
  // ---- raw TCP echo server: accepted sockets must be untouched
  const accepted = [];
  const srvInfo = [];
  const srv = net.createServer((s) => {
    accepted.push(s);
    srvInfo.push([s.constructor.name, typeof s.remoteAddress, Object.keys(s).includes('write'), s.write === net.Socket.prototype.write, s.write.length, s.write.name]);
    s.setEncoding('utf8');
    s.on('data', (d) => { s.write('echo:' + d); });
    s.on('end', () => s.end());
  });
  await new Promise((r) => srv.listen(0, '127.0.0.1', r));
  const port = srv.address().port;

  const c = net.connect(port, '127.0.0.1');
  log('connect-returns-socket', [c instanceof net.Socket, c.connecting]);
  log('write-before-connect', c.write('a'));
  c.setEncoding('utf8');
  const got = [];
  c.on('data', (d) => got.push(d));
  await new Promise((r) => c.once('connect', r));
  log('after-connect', [c.connecting, c.remotePort === port, c.remoteAddress, c.readyState]);
  const wr = await new Promise((r) => { const ret = c.write('b', 'utf8', () => r(['cb-called', ret])); });
  log('write-cb', wr);
  log('write-ret-buffer', c.write(Buffer.from('c')));
  log('write-ret-u8', c.write(new Uint8Array([100])));
  log('write-returns-bool-big', typeof c.write(Buffer.alloc(1 << 20)));
  log('write-fn-props', [c.write.length, c.write.name]);
  log('end-chunk-returns-self', c.end('z') === c);
  await new Promise((r) => c.once('close', r));
  log('bytes', [c.bytesWritten, c.bytesRead > 0, got.join('').startsWith('echo:')]);
  log('own-write-prop-hidden', [Object.keys(c).filter((k) => /tattle/i.test(k)), Object.keys(c).includes('write'), Object.getOwnPropertyNames(c).includes('write'), c.write === net.Socket.prototype.write]);

  // connect overloads
  for (const [name, mk] of [
    ['port,host', () => net.connect(port, '127.0.0.1')],
    ['port,host,cb', () => net.connect(port, '127.0.0.1', () => {})],
    ['options', () => net.connect({ port, host: '127.0.0.1' })],
    ['options,cb', () => net.createConnection({ port, host: '127.0.0.1' }, () => {})],
    ['port-only', () => net.connect(port)],
    ['string-port', () => net.connect(String(port), '127.0.0.1')],
    ['new+connect(opts)', () => { const s = new net.Socket(); s.connect({ port, host: '127.0.0.1' }); return s; }],
    ['new+connect(port,host)', () => { const s = new net.Socket(); s.connect(port, '127.0.0.1'); return s; }],
    ['new+connect(opts,cb)', () => { const s = new net.Socket(); s.connect({ port, host: '127.0.0.1' }, () => {}); return s; }],
    ['allowHalfOpen', () => net.connect({ port, host: '127.0.0.1', allowHalfOpen: true })],
  ]) {
    const s = mk();
    const r = await new Promise((res) => { s.once('connect', () => res('connected')); s.once('error', (e) => res('error ' + e.code)); });
    log('connect:' + name, [r, s.remotePort === port]);
    s.destroy();
    await new Promise((r2) => s.once('close', r2));
  }
  for (const [name, f] of [['bad-port', () => net.connect(-1)], ['no-args', () => new net.Socket().connect()], ['bad-type', () => net.connect({})], ['port-65536', () => net.connect(65536, '127.0.0.1')]]) {
    try { const s = f(); s.on('error', () => {}); log('connect-throw:' + name, 'no-throw'); s.destroy(); } catch (e) { log('connect-throw:' + name, [e.code, e.name]); }
  }
  // refused
  const refused = await new Promise((res) => { const s = net.connect(1, '127.0.0.1'); s.on('error', (e) => res([e.code, e.syscall])); });
  log('refused', refused);

  // ---- unix / IPC socket
  if (process.platform !== 'win32') {
    const sp = path.join(dir, 'u.sock');
    const us = net.createServer((s) => { s.on('data', (d) => s.end('u:' + d)); });
    await new Promise((r) => us.listen(sp, r));
    for (const [name, mk] of [['path-string', () => net.connect(sp)], ['path-opt', () => net.connect({ path: sp })], ['new+connect(path)', () => { const s = new net.Socket(); s.connect(sp); return s; }], ['connect(path,cb)', () => net.connect(sp, () => {})]]) {
      const s = mk();
      s.setEncoding('utf8');
      const r = await new Promise((res) => { let d = ''; s.on('data', (x) => (d += x)); s.on('connect', () => s.write('hi')); s.on('close', () => res(d)); s.on('error', (e) => res('error ' + e.code)); });
      log('unix:' + name, r);
    }
    us.close();
  }

  // ---- http
  const hs = http.createServer((req, res) => {
    let b = '';
    req.on('data', (d) => (b += d));
    req.on('end', () => { res.setHeader('x-m', req.method); res.end(JSON.stringify([req.method, req.url, b, req.headers.connection || null])); });
  });
  await new Promise((r) => hs.listen(0, '127.0.0.1', r));
  const hp = hs.address().port;
  const body = (res) => new Promise((r) => { let d = ''; res.setEncoding('utf8'); res.on('data', (x) => (d += x)); res.on('end', () => r([res.statusCode, res.headers['x-m'], d])); });
  log('http.get(url)', await new Promise((r) => http.get(`http://127.0.0.1:${hp}/g?x=1`, (res) => body(res).then(r))));
  log('http.get(URL)', await new Promise((r) => http.get(new URL(`http://127.0.0.1:${hp}/gu`), (res) => body(res).then(r))));
  log('http.get(opts)', await new Promise((r) => http.get({ host: '127.0.0.1', port: hp, path: '/go' }, (res) => body(res).then(r))));
  log('http.get(url,opts,cb)', await new Promise((r) => http.get(`http://127.0.0.1:${hp}/guo`, { headers: { a: 'b' } }, (res) => body(res).then(r))));
  log('http.request(url,opts,cb)', await new Promise((r) => { const q = http.request(`http://127.0.0.1:${hp}/p`, { method: 'POST' }, (res) => body(res).then(r)); q.end('payload'); }));
  log('http.request(opts)+response-event', await new Promise((r) => { const q = http.request({ host: '127.0.0.1', port: hp, path: '/r', method: 'PUT' }); q.on('response', (res) => body(res).then(r)); q.end('pp'); }));
  log('http.request-returns', await new Promise((r) => { const q = http.request({ host: '127.0.0.1', port: hp }); r([q.constructor.name, typeof q.write, q.method, q.path, q.host]); q.on('error', () => {}); q.destroy(); }));
  log('req.write-ret+cb', await new Promise((r) => { const q = http.request({ host: '127.0.0.1', port: hp, method: 'POST' }, (res) => res.resume()); const ret = q.write('x', () => {}); q.end(); r(ret); }));
  log('http.request-bad', (() => { try { http.request({ protocol: 'ftp:' }); } catch (e) { return e.code; } })());
  log('http.request-bad2', (() => { try { http.request('http://[bad'); } catch (e) { return e.code; } })());
  log('http.get-ECONNREFUSED', await new Promise((r) => http.get('http://127.0.0.1:1/', () => {}).on('error', (e) => r(e.code))));
  log('http.get-name/length', [http.get.name, http.get.length, http.request.name, http.request.length]);

  // keep-alive agent reuse
  const agent = new http.Agent({ keepAlive: true, maxSockets: 1 });
  const socks = new Set();
  for (let i = 0; i < 3; i++) await new Promise((r) => http.get({ host: '127.0.0.1', port: hp, agent, path: '/k' + i }, (res) => { socks.add(res.socket); body(res).then(r); }));
  log('keepalive-reuse', [socks.size, agent.freeSockets ? Object.keys(agent.freeSockets).length : 0]);
  agent.destroy();
  // setEncoding / timeout on socket via http
  log('socket-api', await new Promise((r) => http.get({ host: '127.0.0.1', port: hp }, (res) => { res.socket.setTimeout(5000); res.socket.setNoDelay(true); const sk = res.socket; res.resume(); res.on('end', () => r([typeof sk.remotePort, sk.constructor.name])); })));
  hs.closeAllConnections?.();
  await new Promise((r) => hs.close(r));
  srv.close();
  log('server-sockets', [srvInfo.length > 5, [...new Set(srvInfo.map((x) => JSON.stringify(x)))]]);
  console.log(out.join('\n'));
})();
