import compare from '@paulmillr/jsbt/bench-compare.js';

import { deepStrictEqual } from 'node:assert';
import * as js from '../../src/targets/js/index.ts';
import * as wasm from '../../src/targets/wasm/index.ts';
import * as wasm_threads from '../../src/targets/wasm_threads/index.ts';
import { WP } from '../../src/workers.ts';

const benchBuf = (n: number, seed = 0x9e3779b9) => {
  // Sequential buffers can bias AES table/cache access patterns.
  // Use deterministic pseudo-random data so different backends are compared on the same bytes.
  const out = new Uint8Array(n);
  let x = seed >>> 0;
  for (let i = 0; i < n; i++) {
    x ^= x << 13;
    x ^= x >>> 17;
    x ^= x << 5;
    out[i] = x & 0xff;
  }
  return out;
};

const BUFFERS = {
  '64B': benchBuf(64),
  '1KB': benchBuf(1024),
  '1MB': benchBuf(1024 * 1024),
};

const buf = (n: number) => new Uint8Array(n).fill(n % 251);

const genCtr = (lib: any) => {
  const key = buf(32);
  const iv = buf(16);
  const outs = new Map<number, Uint8Array>();
  for (const v of Object.values(BUFFERS)) outs.set(v.length, new Uint8Array(v.length));
  let nonceCtr = 1;
  const nonceNext = () => {
    // mkCipher forbids encrypt() twice with the same key+nonce per instance.
    // Mutate nonce each run to keep benchmark stable and avoid creating new nonce arrays.
    iv[15] = nonceCtr++ & 0xff;
    iv[14] = (nonceCtr >>> 8) & 0xff;
  };
  return {
    alloc: (b: Uint8Array) => {
      nonceNext();
      return lib.ctr(key, iv).encrypt(b);
    },
    out: (b: Uint8Array) => {
      nonceNext();
      return lib.ctr(key, iv).encrypt(b, outs.get(b.length)!);
    },
  };
};

const CIPHERS = {
  'aes-ctr-256': {
    js: genCtr(js),
    wasm: genCtr(wasm),
    wasm_threads: genCtr(wasm_threads),
  },
};

async function sanityCheck() {
  const b = BUFFERS['64B'];
  const key = buf(32);
  const iv = buf(16);
  iv[15] = 7;
  for (const lib of [js, wasm, wasm_threads]) {
    // Check that output-buffered path matches allocating path (same key+nonce).
    const a = lib.ctr(key, iv.slice()).encrypt(b);
    const out = new Uint8Array(b.length);
    const b2 = lib.ctr(key, iv.slice()).encrypt(b, out);
    deepStrictEqual(a, b2);
  }
}

async function main() {
  await sanityCheck();
  await WP.waitOnline();
  await compare('Ciphers (out buffer vs alloc)', { buffer: BUFFERS }, CIPHERS, {
    libraryDimensions: ['algorithm', 'platform', 'variant'],
    defaults: {
      buffer: '64B',
      algorithm: 'aes-ctr-256',
      platform: 'js',
    },
    iterations: ({ args }) => {
      const buf = args[0];
      if (buf.length <= 64) return 1_000_000;
      if (buf.length <= 1024) return 200_000;
      return 100;
    },
    bytes: ({ args }) => args[0].length,
  });
}

import url from 'node:url';
if (import.meta.url === url.pathToFileURL(process.argv[1]).href) {
  main();
}
