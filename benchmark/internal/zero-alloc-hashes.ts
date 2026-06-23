import compare from '@paulmillr/jsbt/bench-compare.js';

import { deepStrictEqual } from 'node:assert';
import * as js from '../../src/targets/js/index.ts';
import * as wasm from '../../src/targets/wasm/index.ts';
import * as wasm_threads from '../../src/targets/wasm_threads/index.ts';
import { WP } from '../../src/workers.ts';

const benchBuf = (n: number, seed = 0x9e3779b9) => {
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

const genSha256 = (lib: any) => {
  const out = new Uint8Array(32);
  const opts = { out };
  const h = lib.sha256;
  return {
    alloc: (b: Uint8Array) => h(b),
    out: (b: Uint8Array) => h(b, opts),
  };
};

const HASHES = {
  sha256: {
    js: genSha256(js),
    wasm: genSha256(wasm),
    wasm_threads: genSha256(wasm_threads),
  },
};

async function sanityCheck() {
  const b = BUFFERS['64B'];
  for (const algo of Object.values(HASHES)) {
    for (const plat of Object.values(algo)) {
      deepStrictEqual(plat.alloc(b), plat.out(b));
    }
  }
}

async function main() {
  await sanityCheck();
  await WP.waitOnline();
  await compare('Hashes (out buffer vs alloc)', { buffer: BUFFERS }, HASHES, {
    libraryDimensions: ['algorithm', 'platform', 'variant'],
    defaults: {
      buffer: '64B',
      algorithm: 'sha256',
      platform: 'js',
    },
    iterations: ({ args }) => {
      const buf = args[0];
      if (buf.length <= 64) return 2_000_000;
      if (buf.length <= 1024) return 250_000;
      return 250;
    },
    bytes: ({ args }) => args[0].length,
  });
}

import url from 'node:url';
if (import.meta.url === url.pathToFileURL(process.argv[1]).href) {
  main();
}
