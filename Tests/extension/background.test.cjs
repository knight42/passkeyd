const { test } = require('node:test');
const assert = require('node:assert/strict');
const fs = require('node:fs');
const vm = require('node:vm');
const { webcrypto, createHash } = require('node:crypto');
const source = fs.readFileSync(`${__dirname}/../../extension/background.js`, 'utf8');

function bridge(captureCreate = false) {
  let listener;
  const sent = [];
  const chrome = {
    storage: { local: { get: async () => ({ captureCreate }) } },
    runtime: {
      id: 'test-extension',
      onMessage: { addListener: (fn) => { listener = fn; } },
      connectNative() {
        let reply;
        return {
          onMessage: { addListener: (fn) => { reply = fn; } },
          onDisconnect: { addListener() {} },
          disconnect() {},
          postMessage(request) {
            sent.push(request);
            queueMicrotask(() => reply({ ok: true, id: 'credential' }));
          },
        };
      },
    },
  };
  vm.runInNewContext(source, { chrome, URL, TextEncoder, Uint8Array, btoa, atob, crypto: webcrypto });
  return {
    sent,
    call: (payload, overrides = {}) => new Promise((resolve) => listener(
      { type: 'passkeyd', payload },
      { id: chrome.runtime.id, tab: { id: 1 }, frameId: 0,
        origin: 'https://login.example.okta.com', url: 'https://login.example.okta.com/path', ...overrides },
      resolve,
    )),
  };
}
const challenge = Buffer.from('server-issued-challenge').toString('base64url');

test('a matched page cannot claim another RP for has/get/create', async () => {
  for (const op of ['has', 'get', 'create']) {
    const b = bridge(true);
    const result = await b.call({ op, rpId: 'github.com', origin: 'https://github.com', challenge },
      { origin: 'http://localhost:8399', url: 'http://localhost:8399/' });
    assert.equal(result.ok, false);
    assert.match(result.error, /RP ID/);
    assert.equal(b.sent.length, 0);
  }
});

test('get/create bind signed client data to browser metadata, ignoring every page claim', async () => {
  for (const op of ['get', 'create']) {
    const b = bridge(true);
    const result = await b.call({ op, rpId: 'example.okta.com', challenge,
      origin: 'https://example.okta.com', clientDataHash: 'forged-hash',
      clientDataJSON: 'forged-data', crossOrigin: true, type: 'webauthn.wrong',
      user: { id: 'YQ', name: 'user' }, algs: [-7], excludeIds: [] });
    assert.equal(result.ok, true);
    const bytes = Buffer.from(result.clientDataJSON, 'base64url');
    assert.deepEqual(JSON.parse(bytes), { type: `webauthn.${op}`, challenge,
      origin: 'https://login.example.okta.com', crossOrigin: false });
    assert.equal(b.sent[0].origin, 'https://login.example.okta.com');
    assert.equal(b.sent[0].clientDataHash, createHash('sha256').update(bytes).digest('base64url'));
    assert.equal(b.sent[0].clientDataJSON, undefined);
  }
});

test('reject contexts that cannot safely claim a top-level secure origin', async () => {
  for (const context of [
    { id: 'another-extension' }, { tab: undefined }, { frameId: 1 },
    { origin: undefined }, { origin: 'null' },
    { origin: 'http://login.example.okta.com', url: 'http://login.example.okta.com/' },
    { url: 'https://another.okta.com/' },
  ]) {
    const b = bridge();
    assert.equal((await b.call({ op: 'get', rpId: 'example.okta.com', challenge }, context)).ok, false);
    assert.equal(b.sent.length, 0);
  }
});

test('capture setting is enforced outside the page', async () => {
  const b = bridge();
  const result = await b.call({ op: 'create', rpId: 'example.okta.com', challenge });
  assert.equal(result.ok, false);
  assert.match(result.error, /capture is disabled/);
  assert.equal(b.sent.length, 0);
});

test('hash-only legacy requests and malformed challenges never reach the host', async () => {
  for (const bad of [undefined, 'a', '+///', 'YR', 42]) {
    const b = bridge();
    assert.equal((await b.call({ op: 'get', rpId: 'example.okta.com',
      clientDataHash: 'old-hash', challenge: bad })).ok, false);
    assert.equal(b.sent.length, 0);
  }
});

test('localhost and valid has requests remain supported', async () => {
  const b = bridge();
  const result = await b.call({ op: 'has', rpId: 'localhost', allow: ['credential'] },
    { origin: 'http://localhost:8399', url: 'http://localhost:8399/' });
  assert.equal(result.ok, true);
  assert.equal(b.sent[0].origin, 'http://localhost:8399');
  assert.equal(b.sent[0].clientDataHash, undefined);
});
