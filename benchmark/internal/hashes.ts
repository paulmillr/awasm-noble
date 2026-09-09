import compare from '@paulmillr/jsbt/benchmark-compare.js';

import { deepStrictEqual } from 'node:assert';
import * as js from '../../src/targets/js/index.ts';
import * as wasm from '../../src/targets/wasm/index.ts';
import * as webcrypto from '../../src/webcrypto.ts';
// import * as js_threads from '../../src/targets/js_threads/index.ts';
import { hash as b3rs } from 'blake3-wasm-rs';
import * as wasm_threads from '../../src/targets/wasm_threads/index.ts';

import { hexToBytes } from '../../src/utils.ts';
import { NOBLE } from '../../test/noble-all.ts';
// hash wasm
import * as hashWasm from 'hash-wasm';
import { createHash, getHashes } from 'node:crypto';
import * as stubs from '../../src/targets/stub/index.ts';
import { WP } from '../../src/workers.ts';
for (const k in wasm) if (stubs[k]?.install) stubs[k].install(wasm[k]); // check that it doesn't kill performance

const HWASM = {
  sha3_224: (buf) => hashWasm.sha3(buf, 224),
  sha3_256: (buf) => hashWasm.sha3(buf, 256),
  sha3_384: (buf) => hashWasm.sha3(buf, 384),
  sha3_512: (buf) => hashWasm.sha3(buf, 512),

  keccak_224: (buf) => hashWasm.keccak(buf, 224),
  keccak_256: (buf) => hashWasm.keccak(buf, 256),
  keccak_384: (buf) => hashWasm.keccak(buf, 384),
  keccak_512: (buf) => hashWasm.keccak(buf, 512),

  sha224: (buf) => hashWasm.sha224(buf),
  sha256: (buf) => hashWasm.sha256(buf),
  sha384: (buf) => hashWasm.sha384(buf),
  sha512: (buf) => hashWasm.sha512(buf),

  blake2s: (buf) => hashWasm.blake2s(buf),
  blake2b: (buf) => hashWasm.blake2b(buf),
  blake3: (buf) => hashWasm.blake3(buf),
  sha1: (buf) => hashWasm.sha1(buf),
  md5: (buf) => hashWasm.md5(buf),
  ripemd160: (buf) => hashWasm.ripemd160(buf),
};

const NODE_REMAP: Record<string, string> = {
  blake2b512: 'blake2b',
  blake2s256: 'blake2s',
  'sha3-224': 'sha3_224',
  'sha3-256': 'sha3_256',
  'sha3-384': 'sha3_384',
  'sha3-512': 'sha3_512',
};
const NODE_HASHES = Object.fromEntries(
  Array.from(new Set(getHashes())).map((i) => {
    const name = NODE_REMAP[i] || i;
    return [name, (buf: Uint8Array) => Uint8Array.from(createHash(i).update(buf).digest())];
  })
);

const gen = (name) => {
  const jsVer = js[name];
  const wasmVer = wasm[name];
  const wasmB: any = { default: wasmVer };
  if (HWASM[name]) wasmB.hashWasm = HWASM[name];
  if (name === 'blake3') wasmB.b3rs = b3rs;
  //if (name === 'blake3') wasmB.fastest = blakeFastest.hash;
  // wasmB.stream = (buf) => wasmVer.create().update(buf).digest();
  // wasmB.stub = stubs[name];
  if (wasm_threads[name]) wasmB.threads = wasm_threads[name];
  if (NODE_HASHES[name]) wasmB.node = NODE_HASHES[name];
  const jsB: any = { default: jsVer };
  if (NOBLE[name]) jsB.oldNoble = NOBLE[name];
  //jsB.stream = (buf) => jsVer.create().update(buf).digest();
  //if (js_threads[name]) jsB.threads = js_threads[name];
  //jsB.runtime = runtime[name];
  return { wasm: wasmB, js: jsB };
};

const HASHES = {
  // // fix names ordering
  // __tmp__: {
  //   wasm: {
  //     current: () => {},
  //     hashWasm: () => {},
  //     oldNoble: () => {},
  //     fastest: () => {},
  //     stream: () => {},
  //   },
  // },
  // sha224: gen('sha224'),
  // sha256: gen('sha256'),
  // sha384: gen('sha384'),
  // sha512: gen('sha512'),
  // blake2s: gen('blake2s'),
  // blake2b: gen('blake2b'),
  blake3: gen('blake3'),
  // sha3_224: gen('sha3_224'),
  // sha3_256: gen('sha3_256'),
  // sha3_384: gen('sha3_384'),
  // sha3_512: gen('sha3_512'),
  // legacy
  // blake256: gen('blake256'),
  // blake512: gen('blake512'),
  // sha1: gen('sha1'),
  // md5: gen('md5'),
  // ripemd160: gen('ripemd160'),
};

const WEB_HASHES = [
  ['sha1', webcrypto.sha1],
  ['sha224', webcrypto.sha224],
  ['sha256', webcrypto.sha256],
  ['sha384', webcrypto.sha384],
  ['sha512', webcrypto.sha512],
  ['sha3_256', webcrypto.sha3_256],
  ['sha3_384', webcrypto.sha3_384],
  ['sha3_512', webcrypto.sha3_512],
] as const;
async function addWebHashes() {
  for (const [name, hash] of WEB_HASHES) {
    if (!HASHES[name]) continue;
    if (!(await hash.isSupported())) continue;
    HASHES[name].wasm.webcrypto = (buf: Uint8Array) => hash.async(buf);
  }
}

async function sanityCheck() {
  // buffer title, iteration count, data
  const buffers = {
    '32B': [40_000_000, new Uint8Array(32).fill(1)],
    // '64B': [200000, new Uint8Array(64).fill(1)],
    // '1KB': [50000, new Uint8Array(1024).fill(2)],
    '8KB': [10_000, new Uint8Array(1024 * 8).fill(3)],
    // // Slow, but 100 doesn't show difference, probably opt doesn't happen or something
    '1MB': [250, new Uint8Array(1024 * 1024).fill(4)],
  };

  for (const [, [, buf]] of Object.entries(buffers)) {
    for (const h in HASHES) {
      const H = HASHES[h];
      let res;
      for (const l in H) {
        for (const alg in H[l]) {
          const fn = H[l][alg];
          // console.log('X', h, alg, l);
          let d = await fn(buf);
          if (typeof d === 'string') d = hexToBytes(d);
          if (!Array.isArray(d)) {
            if (!res) res = d;
            else deepStrictEqual(res, d);
          }
        }
      }
    }
  }
}

async function main() {
  await addWebHashes();
  await sanityCheck();
  // Need to run sanity check first, so threads installed
  await WP.waitOnline();
  await compare(
    'Hashes',
    {
      buffer: {
        '32B': new Uint8Array(32).fill(1),
        '1KB': new Uint8Array(1024).fill(2),
        '64KB': new Uint8Array(64 * 1024).fill(4),
        '1MB': new Uint8Array(1024 * 1024).fill(4),
        '10MB': new Uint8Array(10 * 1024 * 1024).fill(5),
      },
    },
    HASHES,
    {
      libraryDimensions: ['algorithm', 'platform', 'library'],
      defaults: {},
      bytes: ({ args }) => args[0].length,
    }
  );
}

import url from 'node:url';
if (import.meta.url === url.pathToFileURL(process.argv[1]).href) {
  main();
}
