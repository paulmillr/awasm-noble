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
  SEED = x >>> 0;
  return out;
}

const BUFFERS = {
  '32b': rbuf(32),
  '64b': rbuf(64),
  '1kb': rbuf(1024),
  '64kb': rbuf(1024 * 64),
  '1mb': rbuf(1024 * 1024),
  '10mb': rbuf(1024 * 1024 * 10),
  '100mb': rbuf(1024 * 1024 * 100),
};
const CHUNKS_ = [1, 2, 4, 8, 16, 32, 40, 48, 56, 64, 72, 80, 88, 96, 128];
const now = () => process.hrtime.bigint();
async function main_threads() {
  const libs = wasm_threads;
  const hashes = ['sha256', 'sha512', 'sha3_256', 'sha3_512', 'blake2b', 'blake2s', 'blake3', 'sha1', 'ripemd160'];
  let res;
  for (const hashName of hashes) {
    const hash = libs[hashName];
    for (const [bufName, data] of Object.entries(BUFFERS)) {
      for (let chunk of CHUNKS_) {
        if (bufName === '100mb' && chunk > 16) continue;
        const input = Array(chunk).fill(data);
        const start = now();
        res = hash.parallel(input);
        await Promise.resolve();
        const diff = now() - start;
        const num = Number(diff);
        const SECOND = 10 ** 9;
        const mib = data.byteLength / (1024 * 1024);
        const perSec = Math.round((SECOND * mib * chunk) / num);
        console.log(`${perSec},${hashName},${chunk}x,${bufName}`);
      }
    }
  }
}

main_threads();
