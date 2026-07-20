import compare from '@paulmillr/jsbt/bench-compare.js';
import { deepStrictEqual } from 'node:assert';
import { createRequire } from 'node:module';
import { argon2d, argon2i, argon2id } from '@noble/hashes/argon2.js';
import { WP } from '../../src/workers.ts';
import * as js from '../../src/targets/js/index.ts';
import * as wasm from '../../src/targets/wasm/index.ts';
import * as wasm_threads from '../../src/targets/wasm_threads/index.ts';

const require = createRequire(import.meta.url);
const hashWasm = require('hash-wasm');

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

const hash = (algorithm: string) => (t: number, m: number, p: number) =>
  hashWasm[algorithm]({
    password,
    salt,
    parallelism: p,
    iterations: t,
    memorySize: m,
    hashLength: 32,
    outputType: 'binary',
  });
const def = (algorithm: string, noble: any, _js: any, _wasm: any, threads: any) => ({
  sync: {
    wasm: {
      default: (t: number, m: number, p: number) => _wasm(password, salt, { t, m, p, dkLen: 32 }),
      threads: (t: number, m: number, p: number) => threads(password, salt, { t, m, p, dkLen: 32 }),
      // hash-wasm exposes an async function; bench-compare awaits promise-returning callbacks.
      hashWasm: hash(algorithm),
    },
    js: {
      default: (t: number, m: number, p: number) => _js(password, salt, { t, m, p, dkLen: 32 }),
      oldNoble: (t: number, m: number, p: number) => noble(password, salt, { t, m, p, dkLen: 32 }),
    },
  },
});

const ARGON = {
  argon2i: def('argon2i', argon2i, js.argon2i, wasm.argon2i, wasm_threads.argon2i),
  argon2d: def('argon2d', argon2d, js.argon2d, wasm.argon2d, wasm_threads.argon2d),
  argon2id: def('argon2id', argon2id, js.argon2id, wasm.argon2id, wasm_threads.argon2id),
};

async function main() {
  await WP.waitOnline();
  for (const opts of VECTORS) {
    for (const ver in ARGON) {
      const platforms = ARGON[ver as keyof typeof ARGON];
      let exp;
      for (const p in platforms) {
        const sync = platforms[p as keyof typeof platforms];
        for (const s in sync) {
          const libs = sync[s as keyof typeof sync];
          for (const l in libs) {
            const lib = libs[l as keyof typeof libs];
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
      libDims: ['algorithm', 'sync', 'platform', 'library'],
      defaults: { memory: '256KB', parallel: 1 },
    }
  );
}

import url from 'node:url';
if (import.meta.url === url.pathToFileURL(process.argv[1]).href) main();
