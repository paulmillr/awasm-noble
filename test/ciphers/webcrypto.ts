import { describe, should } from '@paulmillr/jsbt/test.js';
import { deepStrictEqual as eql, rejects, throws } from 'node:assert';
import * as wasm from '../../src/targets/wasm/index.ts';
import * as stubs from '../../src/targets/stub/index.ts';
import * as web from '../../src/webcrypto.ts';

let freshId = 0;

describe('webcrypto ciphers', () => {
  const ciphers = {
    cbc: { sync: wasm.cbc, web: web.cbc, nonce: 16, aad: false },
    ctr: { sync: wasm.ctr, web: web.ctr, nonce: 16, aad: false },
    gcm: { sync: wasm.gcm, web: web.gcm, nonce: 12, aad: true },
  };
  for (const name in ciphers) {
    const c = ciphers[name];
    should(`${name}: async parity + sync throw`, async () => {
      const key = new Uint8Array(32).fill(7);
      const nonce = new Uint8Array(c.nonce).fill(11);
      const msg = new Uint8Array(64).fill(13);
      const aad = c.aad ? new Uint8Array(33).fill(17) : undefined;
      const sync = c.aad ? c.sync(key, nonce, aad).encrypt(msg) : c.sync(key, nonce).encrypt(msg);
      const asyncEnc = c.aad
        ? await c.web(key, nonce, aad).encrypt.async(msg)
        : await c.web(key, nonce).encrypt.async(msg);
      eql(asyncEnc, sync);
      const asyncDec = c.aad
        ? await c.web(key, nonce, aad).decrypt.async(asyncEnc)
        : await c.web(key, nonce).decrypt.async(asyncEnc);
      eql(asyncDec, msg);
      const i = c.aad ? c.web(key, nonce, aad) : c.web(key, nonce);
      throws(() => i.encrypt(msg));
      throws(() => i.decrypt(asyncEnc));
      throws(() => i.encrypt.create());
      throws(() => i.decrypt.create());
    });
  }

  should('nonce reuse rejects on async path', async () => {
    const key = new Uint8Array(32).fill(5);
    const nonce = new Uint8Array(16).fill(9);
    const msg = new Uint8Array(64).fill(17);
    const c = web.ctr(key, nonce);
    await c.encrypt.async(msg);
    await rejects(() => c.encrypt.async(msg));
  });

  should('gcm rejects falsy non-byte AAD with TypeError', () => {
    const key = new Uint8Array(32).fill(7);
    const nonce = new Uint8Array(12).fill(11);
    for (const bad of [false, 0, '', null])
      throws(() => web.gcm(key, nonce, bad as any), TypeError);
  });

  should('gcm accepts 16-byte nonces like the sync wrapper', async () => {
    const key = new Uint8Array(32).fill(7);
    const nonce = new Uint8Array(16).fill(11);
    const aad = new Uint8Array(33).fill(17);
    const msg = new Uint8Array(64).fill(13);
    const sync = wasm.gcm(key, nonce, aad).encrypt(msg);
    const asyncEnc = await web.gcm(key, nonce, aad).encrypt.async(msg);
    eql(asyncEnc, sync);
    eql(await web.gcm(key, nonce, aad).decrypt.async(asyncEnc), msg);
  });

  should('stub installs work for web ciphers', async () => {
    const cases = [
      { stub: stubs.cbc, web: web.cbc, wasm: wasm.cbc, nonceLen: 16, aad: false },
      { stub: stubs.ctr, web: web.ctr, wasm: wasm.ctr, nonceLen: 16, aad: false },
      { stub: stubs.gcm, web: web.gcm, wasm: wasm.gcm, nonceLen: 12, aad: true },
    ];
    const key = new Uint8Array(32).fill(7);
    const msg = new Uint8Array(64).fill(13);
    const aad = new Uint8Array(33).fill(17);
    for (const c of cases) {
      const nonce = new Uint8Array(c.nonceLen).fill(11);
      c.stub.install(c.web);
      try {
        const st = c.aad ? c.stub(key, nonce, aad) : c.stub(key, nonce);
        throws(() => st.encrypt(msg));
        const enc = await st.encrypt.async(msg);
        const expected = c.aad
          ? c.wasm(key, nonce, aad).encrypt(msg)
          : c.wasm(key, nonce).encrypt(msg);
        eql(enc, expected);
        eql(await st.decrypt.async(enc), msg);
      } finally {
        c.stub.install(c.wasm);
      }
    }
  });

  should('cipher wrapper isSupported methods', async () => {
    eql(await web.cbc.isSupported(), true);
    eql(await web.ctr.isSupported(), true);
    eql(await web.gcm.isSupported(), true);
  });

  should('cipher support probe accepts AES-192-only runtimes', async () => {
    const calls: unknown[] = [];
    const desc = Object.getOwnPropertyDescriptor(globalThis, 'crypto');
    const subtle = {
      importKey: (
        _format: string,
        key: Uint8Array,
        params: { name: string; length: number },
        _extractable: boolean,
        usages: string[]
      ) => {
        calls.push({
          op: 'importKey',
          len: key.byteLength,
          name: params.name,
          length: params.length,
          usages,
        });
        if (params.length !== 192) return Promise.reject(new Error('only AES-192'));
        return Promise.resolve({ params, usages });
      },
      encrypt: (
        params: { name: string },
        key: { params: { length: number } },
        data: Uint8Array
      ) => {
        calls.push({
          op: 'encrypt',
          name: params.name,
          keyLength: key.params.length,
          data: data.byteLength,
        });
        return Promise.resolve(new Uint8Array(data.byteLength).fill(9));
      },
      decrypt: (
        params: { name: string },
        key: { params: { length: number } },
        data: Uint8Array
      ) => {
        calls.push({
          op: 'decrypt',
          name: params.name,
          keyLength: key.params.length,
          data: data.byteLength,
        });
        return Promise.resolve(data);
      },
    };
    Object.defineProperty(globalThis, 'crypto', { configurable: true, value: { subtle } });
    try {
      const fresh = await import(
        new URL(`../../src/webcrypto.ts?aes192=${freshId++}`, import.meta.url).href
      );
      const supported = await fresh.gcm.isSupported();
      const out = await fresh
        .gcm(new Uint8Array(24), new Uint8Array(12))
        .encrypt.async(new Uint8Array(1));
      eql(
        { supported, out: Array.from(out), calls },
        {
          supported: true,
          out: [9],
          calls: [
            {
              op: 'importKey',
              len: 16,
              name: 'AES-GCM',
              length: 128,
              usages: ['encrypt', 'decrypt'],
            },
            {
              op: 'importKey',
              len: 24,
              name: 'AES-GCM',
              length: 192,
              usages: ['encrypt', 'decrypt'],
            },
            { op: 'encrypt', name: 'AES-GCM', keyLength: 192, data: 32 },
            { op: 'decrypt', name: 'AES-GCM', keyLength: 192, data: 32 },
            { op: 'importKey', len: 24, name: 'AES-GCM', length: 192, usages: ['encrypt'] },
            { op: 'encrypt', name: 'AES-GCM', keyLength: 192, data: 1 },
          ],
        }
      );
    } finally {
      if (desc) Object.defineProperty(globalThis, 'crypto', desc);
      else delete (globalThis as any).crypto;
    }
  });

  should('stub install does not check implementation support', () => {
    const stub = stubs.cbc;
    stub.install(web.cbc);
    stub.install(wasm.cbc);
  });
});

should.runWhen(import.meta.url);
