// fetch / Request / Response / AbortController against a localhost server.
const http = require('http');
const out = [];
const log = (n, v) => out.push(n + ':' + JSON.stringify(v));
(async () => {
  const srv = http.createServer((req, res) => {
    if (req.url === '/slow') { setTimeout(() => res.end('late'), 3000); return; }
    if (req.url === '/stream') { res.write('a'); setTimeout(() => res.write('b'), 20); setTimeout(() => res.end('c'), 40); return; }
    if (req.url === '/redirect') { res.statusCode = 302; res.setHeader('location', '/final'); res.end(); return; }
    let b = '';
    req.on('data', (d) => (b += d));
    req.on('end', () => { res.setHeader('content-type', 'application/json'); res.setHeader('x-ok', '1'); res.end(JSON.stringify({ m: req.method, u: req.url, b, h: req.headers['x-h'] || null })); });
  });
  await new Promise((r) => srv.listen(0, '127.0.0.1', r));
  const base = 'http://127.0.0.1:' + srv.address().port;
  log('fetch-meta', [typeof fetch, fetch.name, fetch.length, globalThis.fetch === fetch, Object.getOwnPropertyDescriptor(globalThis, 'fetch') && Object.keys(Object.getOwnPropertyDescriptor(globalThis, 'fetch')).sort()]);
  const r1 = await fetch(base + '/a?q=1');
  log('basic', [r1.status, r1.ok, r1.headers.get('x-ok'), r1.url.replace(base, ''), r1.constructor.name, await r1.json()]);
  log('init', await (await fetch(base + '/i', { method: 'POST', body: 'bd', headers: { 'x-h': 'hv' } })).json());
  log('URL-input', await (await fetch(new URL(base + '/u'))).json());
  log('Request-input', await (await fetch(new Request(base + '/r', { method: 'PUT', body: 'rb' }))).json());
  log('Request-input+init-override', await (await fetch(new Request(base + '/r2', { method: 'PUT', body: 'x' }), { method: 'POST' })).json());
  log('Request-reuse-body', await (async () => { const rq = new Request(base + '/rr', { method: 'POST', body: 'b' }); await (await fetch(rq)).text(); return rq.bodyUsed; })());
  log('stream', await (async () => { const res = await fetch(base + '/stream'); const ch = []; const rd = res.body.getReader(); for (;;) { const { done, value } = await rd.read(); if (done) break; ch.push(Buffer.from(value).toString()); } return ch.join(''); })());
  log('stream-async-iter', await (async () => { const res = await fetch(base + '/stream'); let s = ''; for await (const c of res.body) s += Buffer.from(c).toString(); return s; })());
  log('clone', await (async () => { const res = await fetch(base + '/c'); const c = res.clone(); return [(await res.json()).u, (await c.json()).u]; })());
  log('redirect', await (async () => { const res = await fetch(base + '/redirect'); return [res.status, res.redirected, res.url.replace(base, '')]; })());
  log('redirect-manual', await (async () => { const res = await fetch(base + '/redirect', { redirect: 'manual' }); return [res.status, res.headers.get('location')]; })());
  log('abort', await (async () => { const ac = new AbortController(); const p = fetch(base + '/slow', { signal: ac.signal }); setTimeout(() => ac.abort(), 30); try { await p; } catch (e) { return [e.name, e.code, ac.signal.aborted]; } })());
  log('abort-preaborted', await (async () => { try { await fetch(base + '/a', { signal: AbortSignal.abort() }); } catch (e) { return [e.name, e.code]; } })());
  log('abort-timeout', await (async () => { try { await fetch(base + '/slow', { signal: AbortSignal.timeout(30) }); } catch (e) { return [e.name]; } })());
  log('refused', await (async () => { try { await fetch('http://127.0.0.1:1/'); } catch (e) { return [e.name, e.message, e.cause && e.cause.code]; } })());
  log('bad-url', await (async () => { try { await fetch('nope'); } catch (e) { return [e.name, e.message, e.cause && e.cause.code]; } })());
  log('no-args', await (async () => { try { await fetch(); } catch (e) { return [e.name]; } })());
  log('returns-promise', (() => { const p = fetch(base + '/a'); p.then((r) => r.body && r.body.cancel()); return [p instanceof Promise]; })());
  log('this-undefined', await (async () => { const f = fetch; const r = await f.call(undefined, base + '/t'); return r.status; })());
  log('Response-ctor', [new Response('x').constructor === Response, await new Response('hi').text(), Response.json({ a: 1 }).headers.get('content-type')]);
  log('Headers/FormData/URLSearchParams-body', await (await fetch(base + '/f', { method: 'POST', body: new URLSearchParams({ a: '1' }) })).json());
  log('Blob-body', await (await fetch(base + '/blob', { method: 'POST', body: new Blob(['blobby']) })).json());
  log('ReadableStream-body', await (async () => { const body = new ReadableStream({ start(c) { c.enqueue(new TextEncoder().encode('strm')); c.close(); } }); return (await (await fetch(base + '/rs', { method: 'POST', body, duplex: 'half' })).json()).b; })());
  srv.closeAllConnections?.();
  srv.close();
  console.log(out.join('\n'));
})();
