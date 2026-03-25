import { describe, should } from '@paulmillr/jsbt/test.js';
import { deepStrictEqual as eql, rejects, throws } from 'node:assert';
import * as wasm from '../../src/targets/wasm/index.ts';
import * as stubs from '../../src/targets/stub/index.ts';
import * as web from '../../src/webcrypto.ts';

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

  should('stub install does not check implementation support', () => {
    const stub = stubs.cbc;
    stub.install(web.cbc);
    stub.install(wasm.cbc);
  });
});

should.runWhen(import.meta.url);
