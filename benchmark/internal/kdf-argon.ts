import compare from '@paulmillr/jsbt/benchmark-compare.js';
import { deepStrictEqual } from 'node:assert';
import {
  argon2d,
  argon2i,
  argon2id,
  argon2dAsync,
  argon2iAsync,
  argon2idAsync,
} from '@noble/hashes/argon2.js';
import * as hashWasm from 'hash-wasm';
import { WP } from '../../src/workers.ts';
import * as js from '../../src/targets/js/index.ts';
import * as wasm from '../../src/targets/wasm/index.ts';
// import * as wasm_threads from '../../src/targets/wasm_threads/index.ts';
import * as wasm_threads from '../../src/targets/wasm_threads/index.ts';

const password = new Uint8Array([0, 1, 2, 3, 4, 5, 6, 7]);
const salt = new Uint8Array([0, 1, 2, 3, 4, 5, 6, 7, 8, 9, 10, 11, 12, 13, 14, 15]);

const VECTORS = [
  { m: 16, p: 2, t: 2 },
  { m: 32, t: 3, p: 4 },
  { t: 2, m: 256, p: 1 },
  { m: 1024, t: 1, p: 8 },
  { t: 2, m: 65536, p: 1 },
  { t: 2, m: 65536, p: 8 },
  { t: 2, m: 65536, p: 16 },
];

const ARGON = {
  argon2i: {
    async: {
      wasm: {
        default: (t, m, p) => wasm.argon2i.async(password, salt, { t, m, p, dkLen: 32 }),
        threads: (t, m, p) => wasm_threads.argon2i.async(password, salt, { t, m, p, dkLen: 32 }),
        hashWasm: (t, m, p) =>
          hashWasm.argon2i({
            password: password,
            salt: salt,
            parallelism: p,
            iterations: t,
            memorySize: m, // use 512KB memory
            hashLength: 32, // output size = 32 bytes
            outputType: 'binary', // return standard encoded string containing parameters needed to verify the key
          }),
      },
      js: {
        default: (t, m, p) => js.argon2i.async(password, salt, { t, m, p, dkLen: 32 }),
        //threads: (t, m, p) => js_threads.argon2i.async(password, salt, { t, m, p, dkLen: 32 }),
        oldNoble: (t, m, p) => argon2iAsync(password, salt, { t, m, p, dkLen: 32 }),
      },
    },
    sync: {
      wasm: {
        default: (t, m, p) => wasm.argon2i(password, salt, { t, m, p, dkLen: 32 }),
        threads: (t, m, p) => wasm_threads.argon2i(password, salt, { t, m, p, dkLen: 32 }),
      },
      js: {
        default: (t, m, p) => js.argon2i(password, salt, { t, m, p, dkLen: 32 }),
        //threads: (t, m, p) => js_threads.argon2i(password, salt, { t, m, p, dkLen: 32 }),
        oldNoble: (t, m, p) => argon2i(password, salt, { t, m, p, dkLen: 32 }),
      },
    },
  },
  argon2d: {
    async: {
      wasm: {
        default: (t, m, p) => wasm.argon2d.async(password, salt, { t, m, p, dkLen: 32 }),
        threads: (t, m, p) => wasm_threads.argon2d.async(password, salt, { t, m, p, dkLen: 32 }),
        hashWasm: (t, m, p) =>
          hashWasm.argon2d({
            password: password,
            salt: salt,
            parallelism: p,
            iterations: t,
            memorySize: m, // use 512KB memory
            hashLength: 32, // output size = 32 bytes
            outputType: 'binary', // return standard encoded string containing parameters needed to verify the key
          }),
      },
      js: {
        default: (t, m, p) => js.argon2d.async(password, salt, { t, m, p, dkLen: 32 }),
        //threads: (t, m, p) => js_threads.argon2d.async(password, salt, { t, m, p, dkLen: 32 }),
        oldNoble: (t, m, p) => argon2dAsync(password, salt, { t, m, p, dkLen: 32 }),
      },
    },
    sync: {
      wasm: {
        default: (t, m, p) => wasm.argon2d(password, salt, { t, m, p, dkLen: 32 }),
        threads: (t, m, p) => wasm_threads.argon2d(password, salt, { t, m, p, dkLen: 32 }),
      },
      js: {
        default: (t, m, p) => js.argon2d(password, salt, { t, m, p, dkLen: 32 }),
        //threads: (t, m, p) => js_threads.argon2d(password, salt, { t, m, p, dkLen: 32 }),
        oldNoble: (t, m, p) => argon2d(password, salt, { t, m, p, dkLen: 32 }),
      },
    },
  },
  argon2id: {
    async: {
      wasm: {
        default: (t, m, p) => wasm.argon2id.async(password, salt, { t, m, p, dkLen: 32 }),
        threads: (t, m, p) => wasm_threads.argon2id.async(password, salt, { t, m, p, dkLen: 32 }),
        hashWasm: (t, m, p) =>
          hashWasm.argon2id({
            password: password,
            salt: salt,
            parallelism: p,
            iterations: t,
            memorySize: m, // use 512KB memory
            hashLength: 32, // output size = 32 bytes
            outputType: 'binary', // return standard encoded string containing parameters needed to verify the key
          }),
      },
      js: {
        default: (t, m, p) => js.argon2id.async(password, salt, { t, m, p, dkLen: 32 }),
        //threads: (t, m, p) => js_threads.argon2id.async(password, salt, { t, m, p, dkLen: 32 }),
        oldNoble: (t, m, p) => argon2idAsync(password, salt, { t, m, p, dkLen: 32 }),
      },
    },
    sync: {
      wasm: {
        default: (t, m, p) => wasm.argon2id(password, salt, { t, m, p, dkLen: 32 }),
        threads: (t, m, p) => wasm_threads.argon2id(password, salt, { t, m, p, dkLen: 32 }),
      },
      js: {
        default: (t, m, p) => js.argon2id(password, salt, { t, m, p, dkLen: 32 }),
        //threads: (t, m, p) => js_threads.argon2id(password, salt, { t, m, p, dkLen: 32 }),
        oldNoble: (t, m, p) => argon2id(password, salt, { t, m, p, dkLen: 32 }),
      },
    },
  },
};

async function main() {
  await WP.waitOnline();
  // Example: JSBT_BENCHMARK_DIMENSIONS='iters,memory,parallel,algorithm,sync,platform,library' node kdf-argon.ts
  // Sanity
  for (const opts of VECTORS) {
    for (const ver in ARGON) {
      const platforms = ARGON[ver];
      // Sanity
      let exp;
      for (const p in platforms) {
        const sync = platforms[p];
        for (const s in sync) {
          const libs = sync[s];
          for (const l in libs) {
            const lib = libs[l];
            const res = await lib(opts.t, opts.m, opts.p);
            if (!exp) exp = res;
            else deepStrictEqual(res, exp);
          }
        }
      }
    }
  }

  await WP.waitOnline();
  await compare(
    'Argon',
    {
      iters: { 1: 1, 4: 4, 8: 8 },
      memory: { '256KB': 256, '64MB': 64 * 1024, '256MB': 256 * 1024, '1GB': 1 * 1024 * 1024 },
      parallel: { 1: 1, 4: 4, 8: 8, 16: 16 },
    },
    ARGON,
    {
      libraryDimensions: ['algorithm', 'sync', 'platform', 'library'],
      defaults: { memory: '256KB', parallel: 1 },
    }
  );
}

import url from 'node:url';
if (import.meta.url === url.pathToFileURL(process.argv[1]).href) {
  main();
}
