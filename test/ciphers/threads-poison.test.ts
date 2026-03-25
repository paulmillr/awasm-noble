import { describe, should } from '@paulmillr/jsbt/test.js';
import { deepStrictEqual as eql } from 'node:assert';
import * as wasm from '../../src/targets/wasm/index.ts';
import * as wasm_threads from '../../src/targets/wasm_threads/index.ts';
import { WP } from '../../src/workers.ts';

const buf = (n: number) => new Uint8Array(n).fill(n % 251);

const checkSame = (
  name: string,
  fn: (lib: any) => {
    encrypt: (m: Uint8Array) => Uint8Array;
    decrypt: (c: Uint8Array) => Uint8Array;
  },
  msgLen = 1024 * 1024
) => {
  should(name, async () => {
    const c0 = fn(wasm);
    const c1 = fn(wasm_threads);
    const msg = buf(msgLen);
    const enc0 = c0.encrypt(msg);
    const enc1 = c1.encrypt(msg);
    eql(enc1, enc0);
    eql(c0.decrypt(enc0), msg);
    eql(c1.decrypt(enc1), msg);
  });
};

describe('threads poison (wasm vs wasm_threads)', () => {
  should('workers online', async () => {
    await WP.waitOnline();
  });

  // These are "poison" operations: they install modules into the pool and exercise batching.
  // Historically, shared-state writes inside batchFn kernels could corrupt later AEAD tags.
  checkSame('aes-ctr (1MB)', (lib) => lib.ctr(buf(32), buf(16)));
  checkSame('aes-cbc (1MB)', (lib) => lib.cbc(buf(32), buf(16)));
  checkSame('aes-ecb (1MB)', (lib) => lib.ecb(buf(32)));
  checkSame('aes-ofb (1MB)', (lib) => lib.ofb(buf(32), buf(16)));
  checkSame('aes-cfb (1MB)', (lib) => lib.cfb(buf(32), buf(16)));
  checkSame('aes-gcm (1MB)', (lib) => lib.gcm(buf(32), buf(12)));
  checkSame('aes-gcm-siv (1MB)', (lib) => lib.gcmsiv(buf(32), buf(12), buf(0)));
  checkSame('aeskw (32B)', (lib) => lib.aeskw(buf(32)), 32);
  checkSame('aeskwp (32B)', (lib) => lib.aeskwp(buf(32)), 32);
  checkSame('xsalsa20 (1MB)', (lib) => lib.xsalsa20(buf(32), buf(24)));
  checkSame('xchacha20 (1MB)', (lib) => lib.xchacha20(buf(32), buf(24)));
  checkSame('xsalsa20poly1305 (1MB)', (lib) => lib.xsalsa20poly1305(buf(32), buf(24)));
  checkSame('xchacha20poly1305 (1MB)', (lib) => lib.xchacha20poly1305(buf(32), buf(24)));
  checkSame('chacha20poly1305 (1MB)', (lib) => lib.chacha20poly1305(buf(32), buf(12)));
});

should.runWhen(import.meta.url);
