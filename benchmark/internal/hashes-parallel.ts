import compare from '@paulmillr/jsbt/bench-compare.js';

import { deepStrictEqual } from 'node:assert';
import * as stubs from '../../src/targets/stub/index.ts';
import * as wasm from '../../src/targets/wasm/index.ts';
import * as wasm_threads from '../../src/targets/wasm_threads/index.ts';
import { WP } from '../../src/workers.ts';
for (const k in wasm) if (stubs[k]?.install) stubs[k].install(wasm[k]); // check that it doesn't kill performance

const SIZES = [];
for (const [name, sz] of [
  ['32B', 32],
  ['1KB', 1024],
  //    ['8KB', 1024 * 8],
  ['1MB', 1024 * 1024],
] as [string, number][]) {
  for (const chunks of [2, 4, 8, 16, 32, 128, 512, 1024, 10 * 1024]) {
    if (chunks * sz > 100 * 1024 * 1024) continue;
    const res: Uint8Array[] = [];
    for (let i = 0; i < chunks; i++) {
      res.push(new Uint8Array(sz).fill(i));
    }
    SIZES[`${name}/${chunks}`] = res;
  }
}

function plain(hash: any) {
  return (chunks: Uint8Array[]) => {
    const res = [];
    for (const c of chunks) res.push(hash(c));
    return res;
  };
}

const gen = (name) => {
  const wasmVer = wasm[name];
  return {
    wasm: {
      loop: plain(wasmVer),
      simd: wasmVer.parallel,
      threads: wasm_threads[name].parallel,
    },
  };
};

const HASHES = {
  sha256: gen('sha256'),
  sha512: gen('sha512'),
  blake2s: gen('blake2s'),
  blake2b: gen('blake2b'),
  sha3_256: gen('sha3_256'),
  // legacy
  blake256: gen('blake256'),
  blake512: gen('blake512'),
  blake3: gen('blake3'),
  sha1: gen('sha1'),
  md5: gen('md5'),
  ripemd160: gen('ripemd160'),
};

async function main() {
  await WP.waitOnline();

  // Sanity check.
  for (const buf of Object.values(SIZES)) {
    for (const h in HASHES) {
      const H = HASHES[h];
      let res;
      for (const p in H) {
        for (const l in H[p]) {
          const fn = H[p][l];
          let d = await fn(buf);
          if (!res) res = d;
          else {
            deepStrictEqual(res, d);
          }
        }
      }
    }
  }
  await WP.waitOnline();

  await compare(
    'Hashes',
    {
      buffer: SIZES,
    },
    HASHES,
    {
      libraryDimensions: ['algorithm', 'platform', 'library'],
      defaults: {},
      iterations: 10_000_000,
      bytes: ({ args }) => args[0].length * args[0][0].length,
    }
  );
}

import url from 'node:url';
if (import.meta.url === url.pathToFileURL(process.argv[1]).href) {
  main();
}
