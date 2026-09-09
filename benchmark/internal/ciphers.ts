import {
  ChaCha20Poly1305 as ChsfChachaPoly,
  newInstance as chainsafe_init_wasm,
} from '@chainsafe/as-chacha20poly1305';
import compare from '@paulmillr/jsbt/benchmark-compare.js';
import { createCipheriv, createDecipheriv } from 'node:crypto';
import * as js from '../../src/targets/js/index.ts';
import * as wasm from '../../src/targets/wasm/index.ts';
import * as wasm_threads from '../../src/targets/wasm_threads/index.ts';
import { concatBytes } from '../../src/utils.ts';
import * as web from '../../src/webcrypto.ts';
import { WP } from '../../src/workers.ts';
import { NOBLE } from '../../test/noble-all.ts';
import { buf, crossValidate } from './utils-ciphers.ts';

const cipherSame = (fn) => ({ encrypt: fn, decrypt: fn });

let chainsafe_chacha_poly;
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
// Works for gcm only?
const nodeGCM = (name) => {
  return {
    encrypt: (buf, opts) => {
      const res = [];
      const c = createCipheriv(name, opts.key, opts.iv);
      if (opts.aad) c.setAAD(opts.aad);
      res.push(c.update(buf));
      res.push(c.final());
      res.push(c.getAuthTag());
      return concatBytes(...res.map((i) => Uint8Array.from(i)));
    },
    decrypt: (buf, opts) => {
      const ciphertext = buf.slice(0, -16);
      const authTag = buf.slice(-16);
      const decipher = createDecipheriv(name, opts.key, opts.iv);
      if (opts.aad) decipher.setAAD(opts.aad);
      decipher.setAuthTag(authTag);
      return concatBytes(
        ...[decipher.update(ciphertext), decipher.final()].map((i) => Uint8Array.from(i))
      );
    },
  };
};

const nodeAES = (name, pcks7 = true) => {
  return {
    encrypt: (buf, opts) => {
      const res = [];
      const c = createCipheriv(name, opts.key, opts.iv);
      c.setAutoPadding(pcks7); // disable  pkcs7Padding
      res.push(c.update(buf));
      res.push(c.final());
      return concatBytes(...res.map((i) => Uint8Array.from(i)));
    },
    decrypt: (buf, opts) => {
      const ciphertext = buf.slice();
      const c = createDecipheriv(name, opts.key, opts.iv);
      c.setAutoPadding(pcks7); // disable  pkcs7Padding
      return concatBytes(...[c.update(ciphertext), c.final()].map((i) => Uint8Array.from(i)));
    },
  };
};

function addNoble(algoName: string, cons: any) {
  const res = {};
  for (const [name, lib] of Object.entries({ wasm, wasm_threads, js, oldNoble: NOBLE })) {
    const fn = lib[algoName];
    res[name] = {
      encrypt: (buf, opts) => cons(fn, opts).encrypt(buf),
      decrypt: (buf, opts) => cons(fn, opts).decrypt(buf),
    };
  }
  return res;
}

function addAwasm(algoName: string, cons: any) {
  const res = {};
  for (const [name, lib] of Object.entries({ wasm, wasm_threads, js })) {
    const fn = lib[algoName];
    res[name] = {
      encrypt: (buf, opts) => cons(fn, opts).encrypt(buf),
      decrypt: (buf, opts) => cons(fn, opts).decrypt(buf),
    };
  }
  return res;
}

// type: 'AES/AEAD', 'Algorithm', Padding, keySize, direction
export const CIPHERS = {
  // Previously AES, changed for easier filtering
  Basic: {
    'aes-ctr': {
      padding: {
        128: {
          options: { key: buf(16), iv: buf(16) },
          ...addNoble('ctr', (fn, opts) => fn(opts.key, opts.iv)),
          node: nodeAES('aes-128-ctr'),
        },
        256: {
          options: { key: buf(32), iv: buf(16) },
          ...addNoble('ctr', (fn, opts) => fn(opts.key, opts.iv)),
          node: nodeAES('aes-256-ctr'),
        },
      },
    },
    'aes-ofb': {
      padding: {
        128: {
          options: { key: buf(16), iv: buf(16) },
          ...addAwasm('ofb', (fn, opts) => fn(opts.key, opts.iv)),
          node: nodeAES('aes-128-ofb', false),
        },
        256: {
          options: { key: buf(32), iv: buf(16) },
          ...addAwasm('ofb', (fn, opts) => fn(opts.key, opts.iv)),
          node: nodeAES('aes-256-ofb', false),
        },
      },
    },
    'aes-cbc': {
      padding: {
        128: {
          options: { key: buf(16), iv: buf(16) },
          ...addNoble('cbc', (fn, opts) => fn(opts.key, opts.iv)),
          node: nodeAES('aes-128-cbc'),
        },
        256: {
          options: { key: buf(32), iv: buf(16) },
          ...addNoble('cbc', (fn, opts) => fn(opts.key, opts.iv)),
          node: nodeAES('aes-256-cbc'),
        },
      },
      NoPadding: {
        128: {
          options: { key: buf(16), iv: buf(16), blockSize: 16 },
          ...addNoble('cbc', (fn, opts) => fn(opts.key, opts.iv, { disablePadding: true })),
          node: nodeAES('aes-128-cbc', false),
        },
        256: {
          options: { key: buf(32), iv: buf(16), blockSize: 16 },
          ...addNoble('cbc', (fn, opts) => fn(opts.key, opts.iv, { disablePadding: true })),
          node: nodeAES('aes-256-cbc', false),
        },
      },
    },
    'aec-ecb': {
      padding: {
        128: {
          options: { key: buf(16), iv: null },
          ...addNoble('ecb', (fn, opts) => fn(opts.key)),
          node: nodeAES('aes-128-ecb'),
        },
        256: {
          options: { key: buf(32), iv: null },
          ...addNoble('ecb', (fn, opts) => fn(opts.key)),
          node: nodeAES('aes-256-ecb'),
        },
      },
      NoPadding: {
        128: {
          options: { key: buf(16), iv: null, blockSize: 16 },
          ...addNoble('ecb', (fn, opts) => fn(opts.key, { disablePadding: true })),
          node: nodeAES('aes-128-ecb', false),
        },
        256: {
          options: { key: buf(32), iv: null, blockSize: 16 },
          ...addNoble('ecb', (fn, opts) => fn(opts.key, { disablePadding: true })),
          node: nodeAES('aes-256-ecb', false),
        },
      },
    },
  },
  Same: {
    salsa: {
      padding: {
        256: {
          options: { key: buf(32), nonce: buf(8) },
          ...addNoble('salsa20', (fn, opts) => fn(opts.key, opts.nonce)),
        },
      },
    },
    chacha: {
      padding: {
        256: {
          options: {
            key: buf(32),
            nonce: buf(12),
            nonce16: concatBytes(new Uint8Array(4), buf(12)),
          },
          ...addNoble('chacha20', (fn, opts) => fn(opts.key, opts.nonce)),
          node: {
            encrypt: (buf, opts) => {
              const c = createCipheriv('chacha20', opts.key, opts.nonce16);
              const res = c.update(buf);
              c.final();
              return Uint8Array.from(res);
            },
            decrypt: (buf, opts) => {
              const decipher = createDecipheriv('chacha20', opts.key, opts.nonce16);
              const res = decipher.update(buf);
              decipher.final();
              return Uint8Array.from(res);
            },
          },
        },
      },
    },
    chacha12: {
      padding: {
        256: {
          options: { key: buf(32), nonce: buf(12) },
          ...addNoble('chacha12', (fn, opts) => fn(opts.key, opts.nonce)),
        },
      },
    },
    chacha8: {
      padding: {
        256: {
          options: { key: buf(32), nonce: buf(12) },
          ...addNoble('chacha8', (fn, opts) => fn(opts.key, opts.nonce)),
        },
      },
    },
    xsalsa: {
      padding: {
        256: {
          options: { key: buf(32), nonce: buf(24) },
          ...addNoble('xsalsa20', (fn, opts) => fn(opts.key, opts.nonce)),
        },
      },
    },
    xchacha: {
      padding: {
        256: {
          options: { key: buf(32), nonce: buf(24) },
          ...addNoble('xchacha20', (fn, opts) => fn(opts.key, opts.nonce)),
        },
      },
    },
  },
  AEAD: {
    xsalsa20poly1305: {
      padding: {
        256: {
          options: { key: buf(32), nonce: buf(24) },
          ...addNoble('xsalsa20poly1305', (fn, opts) => fn(opts.key, opts.nonce)),
        },
      },
    },
    chacha20poly1305: {
      padding: {
        256: {
          options: { key: buf(32), nonce: buf(12) },
          ...addNoble('chacha20poly1305', (fn, opts) => fn(opts.key, opts.nonce)),
          node: {
            encrypt: (buf, opts) => {
              const c = createCipheriv('chacha20-poly1305', opts.key, opts.nonce);
              const res = [];
              res.push(c.update(buf));
              res.push(c.final());
              res.push(c.getAuthTag());
              return concatBytes(...res.map((i) => Uint8Array.from(i)));
            },
            decrypt: (buf, opts) => {
              const ciphertext = buf.slice(0, -16);
              const authTag = buf.slice(-16);
              const decipher = createDecipheriv('chacha20-poly1305', opts.key, opts.nonce);
              decipher.setAuthTag(authTag);
              return concatBytes(
                ...[decipher.update(ciphertext), decipher.final()].map((i) => Uint8Array.from(i))
              );
            },
          },
          chainsafe: {
            encrypt: (buf, opts) => chainsafe_chacha_poly.seal(opts.key, opts.nonce, buf),
            decrypt: (buf, opts) => chainsafe_chacha_poly.open(opts.key, opts.nonce, buf),
          },
        },
      },
    },
    xchacha20poly1305: {
      padding: {
        256: {
          options: { key: buf(32), nonce: buf(24) },
          ...addNoble('xchacha20poly1305', (fn, opts) => fn(opts.key, opts.nonce)),
        },
      },
    },
    'AES-GCM': {
      padding: {
        128: {
          options: { key: buf(16), iv: buf(12) },
          ...addNoble('gcm', (fn, opts) => fn(opts.key, opts.iv)),
          node: nodeGCM('aes-128-gcm'),
        },
        256: {
          options: { key: buf(32), iv: buf(12) },
          ...addNoble('gcm', (fn, opts) => fn(opts.key, opts.iv)),
          node: nodeGCM('aes-256-gcm'),
        },
      },
    },
    // 'AES-GCM-SIV': {
    //   padding: {
    //     128: {
    //       options: { key: buf(16), aad: buf(0), nonce: buf(12) },
    //       ...addNoble('gcmsiv', (fn, opts) => fn(opts.key, opts.nonce, opts.aad)),
    //     },
    //     256: {
    //       options: { key: buf(32), nonce: buf(12), aad: buf(16) },
    //       ...addNoble('gcmsiv', (fn, opts) => fn(opts.key, opts.nonce, opts.aad)),
    //     },
    //   },
    // },
  },
};

const addWebCiphers = async () => {
  if (await web.ctr.isSupported()) {
    CIPHERS.Basic['aes-ctr'].padding[128].webcrypto = {
      encrypt: (buf, opts) => web.ctr(opts.key, opts.iv).encrypt.async(buf),
      decrypt: (buf, opts) => web.ctr(opts.key, opts.iv).decrypt.async(buf),
    };
    CIPHERS.Basic['aes-ctr'].padding[256].webcrypto = {
      encrypt: (buf, opts) => web.ctr(opts.key, opts.iv).encrypt.async(buf),
      decrypt: (buf, opts) => web.ctr(opts.key, opts.iv).decrypt.async(buf),
    };
  }
  if (await web.cbc.isSupported()) {
    CIPHERS.Basic['aes-cbc'].padding[128].webcrypto = {
      encrypt: (buf, opts) => web.cbc(opts.key, opts.iv).encrypt.async(buf),
      decrypt: (buf, opts) => web.cbc(opts.key, opts.iv).decrypt.async(buf),
    };
    CIPHERS.Basic['aes-cbc'].padding[256].webcrypto = {
      encrypt: (buf, opts) => web.cbc(opts.key, opts.iv).encrypt.async(buf),
      decrypt: (buf, opts) => web.cbc(opts.key, opts.iv).decrypt.async(buf),
    };
  }
  if (await web.gcm.isSupported()) {
    CIPHERS.AEAD['AES-GCM'].padding[128].webcrypto = {
      encrypt: (buf, opts) => web.gcm(opts.key, opts.iv).encrypt.async(buf),
      decrypt: (buf, opts) => web.gcm(opts.key, opts.iv).decrypt.async(buf),
    };
    CIPHERS.AEAD['AES-GCM'].padding[256].webcrypto = {
      encrypt: (buf, opts) => web.gcm(opts.key, opts.iv).encrypt.async(buf),
      decrypt: (buf, opts) => web.gcm(opts.key, opts.iv).decrypt.async(buf),
    };
  }
};

const splitLibs = (libs: Record<string, any>) => {
  const out: any = { options: libs.options, wasm: {}, js: {} };
  for (const [name, fn] of Object.entries(libs)) {
    if (name === 'options') continue;
    if (name === 'wasm') out.wasm.default = fn;
    else if (name === 'wasm_threads') out.wasm.threads = fn;
    else if (name === 'node') out.wasm.node = fn;
    else if (name === 'webcrypto') out.wasm.webcrypto = fn;
    else if (name === 'js') out.js.default = fn;
    else if (name === 'oldNoble') out.js.oldNoble = fn;
    else if (name === 'chainsafe') out.js.chainsafe = fn;
    else out.js[name] = fn;
  }
  if (!Object.keys(out.wasm).length) delete out.wasm;
  if (!Object.keys(out.js).length) delete out.js;
  return out;
};
const flattenLibs = (libs: Record<string, any>) => {
  const out: any = { options: libs.options };
  for (const [platform, ls] of Object.entries(libs)) {
    if (platform === 'options') continue;
    for (const [name, fn] of Object.entries(ls as any)) out[`${platform}.${name}`] = fn;
  }
  return out;
};
const splitCipherMatrix = (ciphers: Record<string, any>) => {
  const out: any = {};
  for (const [type, algorithms] of Object.entries(ciphers)) {
    out[type] = {};
    for (const [algo, paddings] of Object.entries(algorithms as any)) {
      out[type][algo] = {};
      for (const [padding, keySizes] of Object.entries(paddings as any)) {
        out[type][algo][padding] = {};
        for (const [keySize, libs] of Object.entries(keySizes as any)) {
          out[type][algo][padding][keySize] = splitLibs(libs as any);
        }
      }
    }
  }
  return out;
};

const BUFFERS = {
  // '16B': benchBuf(16),
  // '32B': benchBuf(32),
  '64B': benchBuf(64),
  '1KB': benchBuf(1024),
  // '8KB': benchBuf(1024 * 8),
  '1MB': benchBuf(1024 * 1024),
  '10MB': benchBuf(10 * 1024 * 1024),
};

export async function main() {
  const ctx = chainsafe_init_wasm();
  chainsafe_chacha_poly = new ChsfChachaPoly(ctx);
  await addWebCiphers();
  const CIPHERS_SPLIT = splitCipherMatrix(CIPHERS);
  await WP.waitOnline();
  const crossFilter = process.env.CROSS_FILTER;

  // Usage:
  //   node ciphers.ts
  //   JSBT_BENCHMARK_DIMENSIONS='buffer,type,padding,key size,algorithm,platform,library,direction' node ciphers.ts
  //   JSBT_BENCHMARK_FILTER=1MB JSBT_BENCHMARK_DIMENSIONS='buffer,type,algorithm,platform,library' node ciphers.ts
  // Iteration counts vary by buffer size; decrypt benchmarks use precomputed ciphertexts.
  const encrypted = {};
  for (const [type, algorithms] of Object.entries(CIPHERS)) {
    for (const [algo, paddings] of Object.entries(algorithms)) {
      for (const [padding, keySizes] of Object.entries(paddings)) {
        for (const [keySize, libraries] of Object.entries(keySizes)) {
          const name = `${type}/${algo}/${padding}/${keySize}`;
          if (crossFilter && !name.includes(crossFilter)) continue;
          encrypted[name] = await crossValidate(
            name,
            BUFFERS,
            flattenLibs((CIPHERS_SPLIT as any)[type][algo][padding][keySize])
          );
          if (process.env.CROSS_WAIT) await WP.waitOnline();
          if (process.env.CROSS_LOG) {
            const wp: any = WP;
            const n = wp.registry ? Object.keys(wp.registry).length : undefined;
            console.log('CROSS_LOG', name, 'wp.pos', wp.pos, 'installed', n);
          }
        }
      }
    }
  }
  await WP.waitOnline();
  console.log('Libraries cross-validated against each other correctly');

  await compare('Ciphers', { buffer: BUFFERS }, CIPHERS_SPLIT, {
    libraryDimensions: ['type', 'algorithm', 'padding', 'key size', 'platform', 'library', 'direction'],
    defaults: {
      direction: 'encrypt',
      'key size': '256',
      padding: 'padding',
    },
    patchArgs: (args, obj) => {
      // Use precomputed ciphertext for decrypt runs.
      if (obj['direction'] === 'decrypt') {
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
