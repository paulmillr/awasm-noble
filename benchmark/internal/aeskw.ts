import compare from '@paulmillr/jsbt/bench-compare.js';

import * as js from '../../src/targets/js/index.ts';
import * as wasm from '../../src/targets/wasm/index.ts';
import * as wasm_threads from '../../src/targets/wasm_threads/index.ts';
import { WP } from '../../src/workers.ts';
import { NOBLE } from '../../test/noble-all.ts';
import { buf } from './utils-ciphers.ts';

// AES-KW/AES-KWP have atypical length rules (e.g. KW forbids 0-byte and 8-byte messages),
// so we keep a local cross-validator instead of generalizing `utils-ciphers.ts`.
const eql = (a: Uint8Array, b: Uint8Array, msg?: string) => {
  if (a.length !== b.length) throw new Error(`u8a.eql: length ${a.length}!==${b.length} (${msg})`);
  for (let i = 0; i < a.length; i++) {
    if (a[i] !== b[i]) throw new Error(`u8a.eql: a[${i}](${a[i]})!==b[${i}](${b[i]}), ${msg}`);
  }
};
const crossValidateAesKw = async (
  title: string,
  buffers: Record<string, Uint8Array>,
  ciphers: any,
  allowEnc: (len: number) => boolean
) => {
  const bufs = Object.values(buffers).slice();
  const bufMap = new Map(Object.entries(buffers).map(([k, v]) => [v, k]));
  for (let i = 0; i < 2048; i++) {
    if (!allowEnc(i)) continue;
    bufs.push(buf(i));
  }

  const res: Record<string, Uint8Array> = {};
  for (const msg of bufs) {
    const bname = bufMap.get(msg) || `${msg.length}`;
    const orig = msg.slice();
    let encrypted: Uint8Array | undefined;
    const opts = ciphers.options;
    for (const [lib, fn] of Object.entries(ciphers)) {
      if (lib === 'options') continue;
      if (encrypted === undefined) encrypted = await fn.encrypt(msg, opts);
      else
        eql(encrypted, await fn.encrypt(msg, opts), `${title}/${bname}: encrypt verify (${lib})`);
      eql(msg, orig, `${title}/${bname}: encrypt mutates buffer (${lib})`);
      eql(await fn.decrypt(encrypted, opts), msg, `${title}/${bname}: decrypt verify (${lib})`);
    }
    const bufName = bufMap.get(msg);
    if (bufName) res[bufName] = encrypted!;
  }
  return res;
};

const benchBuf = (n: number, seed = 0x9e3779b9) => {
  // Sequential buffers can bias AES table/cache access patterns.
  // Use deterministic pseudo-random data so noble/awasm are compared on less structured input.
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
  '1MB': benchBuf(1024 * 1024),
};

const addAesKw = (algoName: 'aeskw' | 'aeskwp') => {
  const res: Record<string, { encrypt: (b: Uint8Array, o: any) => Uint8Array; decrypt: any }> = {};
  // Keep noble first so diff baselines match "noble-ciphers" by default.
  for (const [name, lib] of Object.entries({ noble: NOBLE, wasm, wasm_threads, js })) {
    const fn = (lib as any)[algoName];
    res[name] = {
      encrypt: (b, opts) => fn(opts.key).encrypt(b),
      decrypt: (b, opts) => fn(opts.key).decrypt(b),
    };
  }
  return res;
};

export const AESKW = {
  Wrap: {
    aeskw: {
      NoPadding: {
        128: {
          options: { key: buf(16), blockSize: 8 },
          ...addAesKw('aeskw'),
        },
        192: {
          options: { key: buf(24), blockSize: 8 },
          ...addAesKw('aeskw'),
        },
        256: {
          options: { key: buf(32), blockSize: 8 },
          ...addAesKw('aeskw'),
        },
      },
    },
    aeskwp: {
      Padding: {
        128: {
          options: { key: buf(16) },
          ...addAesKw('aeskwp'),
        },
        192: {
          options: { key: buf(24) },
          ...addAesKw('aeskwp'),
        },
        256: {
          options: { key: buf(32) },
          ...addAesKw('aeskwp'),
        },
      },
    },
  },
};

export async function main() {
  await WP.waitOnline();
  const crossFilter = process.env.CROSS_FILTER;

  const encrypted: Record<string, Record<string, Uint8Array>> = {};
  for (const [type, algos] of Object.entries(AESKW)) {
    for (const [algo, paddings] of Object.entries(algos as any)) {
      for (const [padding, keySizes] of Object.entries(paddings as any)) {
        for (const [keySize, libraries] of Object.entries(keySizes as any)) {
          const name = `${type}/${algo}/${padding}/${keySize}`;
          if (crossFilter && !name.includes(crossFilter)) continue;
          const allowEnc =
            algo === 'aeskw'
              ? (len: number) => !!len && len !== 8 && len % 8 === 0
              : (len: number) => !!len;
          encrypted[name] = await crossValidateAesKw(name, BUFFERS, libraries as any, allowEnc);
          if (process.env.CROSS_WAIT) await WP.waitOnline();
        }
      }
    }
  }
  await WP.waitOnline();
  console.log('Libraries cross-validated against each other correctly');

  // Example: JSBT_BENCHMARK_FILTER=1MB JSBT_BENCHMARK_DIMENSIONS='buffer,type,algorithm,padding,key size,direction,library' node aeskw.ts
  await compare('AES-KW', { buffer: BUFFERS }, AESKW as any, {
    libraryDimensions: ['type', 'algorithm', 'padding', 'key size', 'library', 'direction'],
    defaults: {
      buffer: '64B',
      type: 'Wrap',
      library: 'noble',
      direction: 'encrypt',
      padding: 'Padding',
      algorithm: 'aeskwp',
      'key size': '256',
    },
    patchArgs: (args, obj) => {
      if (obj.direction === 'decrypt') {
        const buf =
          encrypted[`${obj.type}/${obj.algorithm}/${obj.padding}/${obj['key size']}`][obj.buffer];
        return [buf, args[1]];
      }
      return args;
    },
    bytes: ({ args }) => args[0].length,
  });
}

import url from 'node:url';
if (import.meta.url === url.pathToFileURL(process.argv[1]).href) {
  main();
}
