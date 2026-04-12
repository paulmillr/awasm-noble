import * as wasm_threads from '../src/targets/wasm_threads/index.ts';

let SEED = 0x9e3779b9;
function rbuf(n: number) {
  // Sequential buffers can bias AES table/cache access patterns.
  // Use deterministic pseudo-random data for fairer cross-library comparisons.
  const out = new Uint8Array(n);
  let x = SEED >>> 0;
  for (let i = 0; i < n; i++) {
    x ^= x << 13;
    x ^= x >>> 17;
    x ^= x << 5;
    out[i] = x & 0xff;
  }
  SEED = x >>> 0; // guaranteed persisted
  return out;
}

const BUFFERS = {
  '32b': { data: rbuf(32), multiplier: 1/32768 },
  '64b': { data: rbuf(64), multiplier: 1/16384 },
  '1kb': { data: rbuf(1024), multiplier: 1/1024 },
  '64kb': { data: rbuf(1024 * 64), multiplier: 1/16 },
  '1mb': { data: rbuf(1024 * 1024), multiplier: 1 },
  '10mb': { data: rbuf(1024 * 1024 * 10), multiplier: 10 },
  '100mb': { data: rbuf(1024 * 1024 * 100), multiplier: 100 },
};
const CHUNKS_ = [1, 2, 4, 8, 16, 32, 40, 48, 56, 64, 72, 80, 88, 96, 128];
const now = () => process.hrtime.bigint();
async function main_threads() {
  const libs = wasm_threads;
  const hashes = ['sha256', 'sha512', 'sha3_256', 'sha3_512', 'blake2b', 'blake2s', 'blake3', 'sha1', 'ripemd160'];
  let res;
  for (const hashName of hashes) {
    const hash = libs[hashName];
    for (let [bufName, { data, multiplier }] of Object.entries(BUFFERS)) {
      for (let chunk of CHUNKS_) {
        if (bufName === '100mb' && chunk > 16) continue;
        const input = Array(chunk).fill(data);
        const start = now();
        res = hash.parallel(input);
        await Promise.resolve();
        const diff = now() - start;
        const num = Number(diff);
        const SECOND = 10 ** 9;
        const perSec = Math.round((SECOND * (multiplier * chunk)) / num);
        console.log(`${perSec},${hashName},${chunk}x,${bufName}`)
      }
    }
  }

  // console.log(`# ciphers, input: 10mb, +threads`);
  // await bench('chacha20poly1305', () => chacha20poly1305(key, n12).encrypt(cdata), copts);
  // await bench('aes-gcm-256', () => gcm(key, n12).encrypt(cdata), copts);
  // await bench('aes-gcm-siv-256', () => gcmsiv(key, n12).encrypt(cdata), copts);
  // await bench('chacha20', () => chacha20(key, n12).encrypt(cdata), copts);
  // await bench('aes-ecb-256', () => ecb(key).encrypt(cdata), copts);
  // await bench('aes-cbc-256', () => cbc(key, n16).encrypt(cdata), copts);
  // await bench('aes-ctr-256', () => ctr(key, n16).encrypt(cdata), copts);
}

main_threads();
