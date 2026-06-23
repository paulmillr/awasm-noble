import compare from '@paulmillr/jsbt/bench-compare.js';
import { deepStrictEqual } from 'node:assert';
// noble hashes
import { blake3 } from '@noble/hashes/blake3.js';
import { shake128, shake256 } from '@noble/hashes/sha3.js';
import * as js from '../../src/targets/js/index.ts';
import * as wasm from '../../src/targets/wasm/index.ts';
// hash wasm
import * as hashWasm from 'hash-wasm';

const MSG = new Uint8Array(32).fill(1);

const sanityBuffers = {
  '32B': new Uint8Array(32).fill(1),
  '8KB': new Uint8Array(1024 * 8).fill(3),
  '1MB': new Uint8Array(1024 * 1024).fill(4),
};

const HWASM = {
  // hash-wasm does not expose SHAKE here.
  blake3: (bufLen) => hashWasm.blake3(MSG, bufLen * 8),
};

const wrapNoble = (noble) => (bufLen) => noble(MSG, { dkLen: bufLen });

const HASHES = {
  shake128: {
    wasm: { default: wrapNoble(wasm.shake128) },
    js: { default: wrapNoble(js.shake128), oldNoble: wrapNoble(shake128) },
  },
  shake256: {
    wasm: { default: wrapNoble(wasm.shake256) },
    js: { default: wrapNoble(js.shake256), oldNoble: wrapNoble(shake256) },
  },
  blake3: {
    wasm: { default: wrapNoble(wasm.blake3), hashWasm: HWASM.blake3 },
    js: { default: wrapNoble(js.blake3), oldNoble: wrapNoble(blake3) },
  },
};

async function main() {
  // Sanity check
  for (const buf of Object.values(sanityBuffers)) {
    for (const h in HASHES) {
      const H = HASHES[h];
      let res;
      for (const l in H) {
        for (const alg in H[l]) {
          const fn = H[l][alg];
          // hash-wasm blake3 rejects large XOF output in this setup.
          if (alg === 'hashWasm' && buf.length > 8 * 1024) continue;
          let d = await fn(buf.length);
          if (typeof d === 'string') d = Uint8Array.from(Buffer.from(d, 'hex'));
          if (!Array.isArray(d)) {
            if (!res) res = d;
            else deepStrictEqual(res, d);
          }
        }
      }
    }
  }

  await compare(
    'Hashes',
    {
      buffer: {
        '32B': 32,
        '64B': 64,
        '1KB': 1024,
        '8KB': 8 * 1024,
        '1MB': 1024 * 1024,
      },
    },
    HASHES,
    {
      libraryDimensions: ['algorithm', 'platform', 'library'],
      defaults: {},
      bytes: ({ args }) => args[0],
      filterObj: (o) => o.library !== 'hashWasm' || o.buffer !== '1MB',
    }
  );
}

import url from 'node:url';
if (import.meta.url === url.pathToFileURL(process.argv[1]).href) {
  main();
}
