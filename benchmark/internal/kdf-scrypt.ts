import compare from '@paulmillr/jsbt/bench-compare.js';
import { deepStrictEqual } from 'node:assert';
import { scrypt, scryptAsync } from '@noble/hashes/scrypt.js';
import { utf8ToBytes } from '@noble/hashes/utils.js';
import * as hashWasm from 'hash-wasm';
import { WP } from '../../src/workers.ts';

import * as js from '../../src/targets/js/index.ts';
import * as wasm from '../../src/targets/wasm/index.ts';
// import * as wasm_threads from '../../src/targets/wasm_threads/index.ts';
import * as wasm_threads from '../../src/targets/wasm_threads/index.ts';

const SCRYPT_VECTORS = [
  { N: 16, r: 1, p: 1 },
  { N: 1024, r: 8, p: 16 },
  { N: 16384, r: 8, p: 1 },
  { N: 2 ** 20, r: 8, p: 1 },
  { N: 2 ** 17, r: 8, p: 8 },
];

const [spassword, ssalt] = [new Uint8Array([1, 2, 3]), new Uint8Array([4, 5, 6])];
const SCRYPT = {
  async: {
    wasm: {
      default: (N, r, p) => wasm.scrypt.async(spassword, ssalt, { N, r, p }),
      threads: (N, r, p) => wasm_threads.scrypt.async(spassword, ssalt, { N, r, p }),
      hashWasm: (N, r, p) =>
        hashWasm.scrypt({
          password: spassword,
          salt: ssalt,
          costFactor: N,
          blockSize: r,
          parallelism: p,
          hashLength: 32,
          outputType: 'binary',
        }),
    },
    js: {
      default: (N, r, p) => js.scrypt.async(spassword, ssalt, { N, r, p }),
      //threads: (N, r, p) => js_threads.scrypt.async(spassword, ssalt, { N, r, p }),
      oldNoble: (N, r, p) => scryptAsync(spassword, ssalt, { N, r, p }),
    },
  },
  sync: {
    wasm: {
      default: (N, r, p) => wasm.scrypt(spassword, ssalt, { N, r, p }),
      threads: (N, r, p) => wasm_threads.scrypt(spassword, ssalt, { N, r, p }),
    },
    js: {
      default: (N, r, p) => js.scrypt(spassword, ssalt, { N, r, p }),
      //threads: (N, r, p) => js_threads.scrypt(spassword, ssalt, { N, r, p }),
      oldNoble: (N, r, p) => scrypt(spassword, ssalt, { N, r, p }),
    },
  },
};

async function main() {
  // We need to process vectors also to make sure threads are online
  await WP.waitOnline();
  for (const opts of SCRYPT_VECTORS) {
    // Sanity
    let exp;
    for (const p in SCRYPT) {
      const sync = SCRYPT[p];
      for (const s in sync) {
        const libs = sync[s];
        for (const l in libs) {
          const lib = libs[l];
          const res = await lib(opts.N, opts.r, opts.p);
          if (!exp) exp = res;
          else deepStrictEqual(res, exp);
        }
      }
    }
  }
  await WP.waitOnline();
  await compare(
    'Scrypt',
    {
      iters: {
        2: 2,
        '2^10': 2 ** 10,
        '2^14': 2 ** 14,
        '2^16': 2 ** 16,
        '2^18': 2 ** 18,
      },
      r: { 8: 8, 4: 4, 1: 1 },
      p: { 1: 1, 2: 2, 4: 4, 8: 8 },
    },
    SCRYPT,
    {
      libraryDimensions: ['sync', 'platform', 'library'],
      defaults: { r: 8, p: 1 },
      iterations: ({ args }) => {
        const iters = args[0];
        if (iters <= 2) return 10_000;
        if (iters <= 2 ** 10) return 1_000;
        if (iters <= 2 ** 14) return 10;
        return 5;
      },
    }
  );
}

import url from 'node:url';
if (import.meta.url === url.pathToFileURL(process.argv[1]).href) {
  main();
}
