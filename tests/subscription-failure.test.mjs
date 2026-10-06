// Run with: node --test tests/subscription-failure.test.mjs (Node.js >= 18).
import assert from 'node:assert/strict';
import { createHash } from 'node:crypto';
import { readFileSync } from 'node:fs';
import test from 'node:test';
import vm from 'node:vm';

const source = readFileSync(new URL('../明文源吗', import.meta.url), 'utf8');
const uuid = '351c9981-04b6-4103-aa4b-864aa9c91469';
const preferred = 'https://preferred.example/list';
const second = 'https://second.example/list';
const environment = { u: uuid, epd: 'no', epi: 'no', egi: 'yes', ena: 'no',
  yxURL: preferred, ev: 'yes', et: 'yes', ex: 'no', jk: 'yes' };
const targets = ['', 'base64', 'clash', 'clashr', 'stash', 'meta', 'clashmeta',
  'vg', 'jk', 'jiakuan', 'surge', 'surge2', 'surge3', 'surge4',
  'quantumult', 'quanx', 'ss', 'ssr', 'v2ray', 'loon', 'singbox', 'sing-box', 'unknown'];
const residential = new Set(['vg', 'jk', 'jiakuan']);
const base64 = new Set(['', 'base64', 'ss', 'ssr', 'v2ray', 'unknown']);
const vpnConfig = 'client\nproto tcp\nremote 192.0.2.2 443\n' +
  '<ca>fixture-ca</ca>\n<cert>fixture-cert</cert>\n<key>fixture-key</key>\n';
const vpnList = ['fixture-home', '192.0.2.2', '0', '0', '100', 'Test', 'US',
  '0', '0', '0', '0', '0', '0', 'fixture', btoa(vpnConfig)].join(',');

function loadWorker(fetch) {
  const timers = new Map();
  let nextTimer = 0;
  const context = vm.createContext({ Request, Response, URL, URLSearchParams,
    TextEncoder, TextDecoder, Uint8Array, ArrayBuffer, AbortController, atob, btoa,
    // The upstream preferred-IP API uses MD5, which Node WebCrypto does not support.
    crypto: { subtle: { digest: async (algorithm, data) =>
      Uint8Array.from(createHash(algorithm.toLowerCase()).update(data).digest()).buffer } },
    setTimeout(callback) { const id = ++nextTimer; timers.set(id, callback); return id; },
    clearTimeout(id) { timers.delete(id); },
    fetch: (url, options) => fetch(String(url), options, timers)
  });
  // Stub only Cloudflare sockets and expose the original single-file fetch handler.
  vm.runInContext(source.replace("import { connect as 连接 } from 'cloudflare:sockets';",
    'const 连接 = () => { throw new Error("Unexpected socket connection"); };')
    .replace('export default {', 'globalThis.worker = {'), context);
  return {
    request: (target, overrides = {}) => context.worker.fetch(
      new Request(`https://worker.example/${uuid}/sub${target ? `?target=${target}` : ''}`),
      { ...environment, ...overrides }, {}),
    // Verify that requests retain the configured source switches.
    switches: () => vm.runInContext(
      'JSON.stringify([启用原生地址, 启用优选域名, 启用优选地址, 启用仓库优选])', context)
  };
}

function content(body, target) { return base64.has(target) ? atob(body) : body; }

for (const target of targets) {
  test(`${target || 'default'}: all enabled sources fail or provide no usable nodes`, async () => {
    for (const failure of ['http', 'network', 'timeout', 'empty', 'invalid',
      'invalid-ip', 'invalid-port', 'invalid-ipv6', 'tls-filtered']) {
      const calls = [];
      const { request, switches } = loadWorker((url, options, timers) => {
        calls.push(url);
        assert.equal(url, preferred, 'disabled sources must not be fetched');
        if (failure === 'network') throw new Error('Source unavailable');
        if (failure === 'timeout') {
          assert.ok(options.signal);
          return new Promise((_, reject) => {
            options.signal.addEventListener('abort', () => reject(new Error('Source timed out')));
            queueMicrotask(() => [...timers.values()].at(-1)());
          });
        }
        const body = failure === 'http' ? '192.0.2.1:443#must-not-be-used'
          : failure === 'empty' ? ' \n' : failure === 'invalid' ? '<html>source error</html>'
          : failure === 'invalid-ip' ? '999.999.999.999:443'
          : failure === 'invalid-port' ? '192.0.2.1:0\n192.0.2.1:65536'
          : failure === 'invalid-ipv6' ? '[2001:db8:::1]:443'
          : '192.0.2.1:80#non-TLS';
        return new Response(body, { status: failure === 'http' ? 503 : 200 });
      });
      const response = await request(target, { dkby: 'yes' });
      assert.equal(response.status, 503, failure);
      assert.equal(response.headers.get('cache-control'), 'no-store');
      assert.equal(response.headers.get('content-type'), 'text/plain; charset=utf-8');
      const body = await response.text();
      assert.match(body, /有效节点/);
      assert.doesNotMatch(body, /00000000-0000-0000-0000-000000000000|127\.0\.0\.1/);
      assert.ok(calls.length > 0);
      assert.ok(calls.every(url => url === preferred), 'disabled sources must stay disabled');
      assert.equal(switches(), '[false,false,false,true]');
    }
  });

  test(`${target || 'default'}: one failed yxURL preserves nodes from a successful yxURL`, async () => {
    const calls = [];
    const { request, switches } = loadWorker(url => {
      calls.push(url);
      if (url === preferred) return new Response('source error', { status: 503 });
      if (url === second) return new Response('192.0.2.1:443#valid\n999.999.999.999:443\n192.0.2.3:65536');
      assert.ok(residential.has(target) && url === 'https://www.vpngate.net/api/iphone/');
      return new Response(vpnList);
    });
    const response = await request(target, { yxURL: `${preferred},${second}` });
    assert.equal(response.status, 200);
    const body = content(await response.text(), target);
    assert.match(body, /192\.0\.2\.1/);
    assert.doesNotMatch(body, /999\.999\.999\.999|65536/);
    assert.doesNotMatch(body, /00000000-0000-0000-0000-000000000000/);
    assert.ok(calls.includes(preferred) && calls.includes(second));
    assert.equal(switches(), '[false,false,false,true]');
  });

  test(`${target || 'default'}: normal subscriptions retain real nodes`, async () => {
    const calls = [];
    const { request, switches } = loadWorker(url => {
      calls.push(url);
      if (url === preferred) return new Response('192.0.2.1:443#valid');
      assert.ok(residential.has(target) && url === 'https://www.vpngate.net/api/iphone/');
      return new Response(vpnList);
    });
    const response = await request(target);
    assert.equal(response.status, 200);
    assert.match(response.headers.get('cache-control'), /no-store/);
    const body = content(await response.text(), target);
    assert.match(body, /192\.0\.2\.1/);
    assert.doesNotMatch(body, /00000000-0000-0000-0000-000000000000/);
    assert.equal(calls.filter(url => url === preferred).length, 1);
    assert.equal(switches(), '[false,false,false,true]');
  });
}

test('all enabled remote source types fail without enabling native or domain nodes', async () => {
  const calls = [];
  const { request, switches } = loadWorker(url => {
    calls.push(url);
    return new Response('<html>source error</html>', { status: 503 });
  });
  const response = await request('base64', { epi: 'yes', yxURL: '' });
  assert.equal(response.status, 503);
  assert.equal(response.headers.get('cache-control'), 'no-store');
  assert.ok(calls.some(url => url.startsWith('https://api.uouin.com/')));
  assert.equal(switches(), '[false,false,true,true]');
});

test('enabled native nodes still work when the preferred source fails', async () => {
  const { request, switches } = loadWorker(() => new Response('source error', { status: 503 }));
  const response = await request('base64', { ena: 'yes' });
  assert.equal(response.status, 200);
  const nodes = atob(await response.text()).split('\n').map(link => new URL(link));
  assert.ok(nodes.length > 0);
  assert.ok(nodes.every(node => node.hostname === 'worker.example'));
  assert.equal(switches(), '[true,false,false,true]');
});

test('all disabled sources remain disabled and return 503', async () => {
  let calls = 0;
  const { request, switches } = loadWorker(() => { calls++; throw new Error('Unexpected source fetch'); });
  const response = await request('base64', { egi: 'no' });
  assert.equal(response.status, 503);
  assert.equal(calls, 0);
  assert.equal(switches(), '[false,false,false,false]');
});

test('valid custom IPv4, IPv6 and hostnames retain normal share links', async () => {
  for (const host of ['192.0.2.1', '[2001:db8::1]', 'cdn.example',
    'cdn_under.example', 'xn--fsqu00a.xn--0zwm56d', 'edge']) {
    let calls = 0;
    const { request } = loadWorker(() => { calls++; throw new Error('Unexpected source fetch'); });
    const response = await request('base64', { yx: `${host}:8443`, epi: 'yes', epd: 'yes' });
    assert.equal(response.status, 200, host);
    const nodes = atob(await response.text()).split('\n').map(link => new URL(link));
    assert.ok(nodes.length > 0);
    assert.ok(nodes.every(node => node.hostname === host && Number(node.port) > 0));
    assert.ok(nodes.some(node => node.protocol === 'vless:'));
    assert.ok(nodes.some(node => node.protocol === 'trojan:'));
    assert.equal(calls, 0);
  }
});
