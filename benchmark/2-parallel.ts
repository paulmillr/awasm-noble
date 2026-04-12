import bench from '@paulmillr/jsbt/bench.js';
import * as wasm_threads from '../src/targets/wasm_threads/index.ts';
import { WP } from '../src/workers.ts';

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
  '32b': rbuf(32),
  '1mb': rbuf(1024 * 1024),
  '10mb': rbuf(1024 * 1024 * 10),
  '100mb': rbuf(1024 * 1024 * 100),
  '1gb': rbuf(1024 * 1024 * 1024),
};

async function main_threads() {
  const CHUNKS = 48;
  const data = BUFFERS['1mb'];
  const opts = { unit: 'mb', multiplier: CHUNKS };
  const cdata = BUFFERS['10mb']
  const copts = { unit: 'mb', multiplier: 10 };
  const libs = wasm_threads;

  const chunks = Array(CHUNKS).fill(data);
  await WP.waitOnline();

  // prettier-ignore
  const hashes = ['sha256', 'sha512', 'sha3_256', 'sha3_512', 'blake2b', 'blake2s'];
  const { chacha20poly1305, gcm, gcmsiv, chacha20, ecb, cbc, ctr } = libs;
  // prettier-ignore
  const key = rbuf(32), n12 = rbuf(12), n16 = rbuf(16), n24 = rbuf(24);
  let start = Date.now();
  while (5000 > Date.now() - start) {
    // warm-up
    await libs.sha256.parallel(chunks);
    await chacha20poly1305(key, n12).encrypt(cdata);
  }
  console.log(`# hashes, input: ${CHUNKS}x1mb, +threads`);
  for (const title of hashes) {
    const hash = libs[title];
    await bench(title, () => hash.parallel(chunks), opts);
  }
  await bench(`blake3 ${CHUNKS}x1mb`, () => libs.blake3.parallel(chunks), opts);
  const b3buf = [BUFFERS['1gb']];
  const b3o = { unit: 'mb', multiplier: 1024 }
  await bench('blake3 1x1gb', () => libs.blake3.parallel(b3buf), b3o);
  const hashes2 = ['ripemd160', 'md5', 'sha1'];
  for (const title of hashes2) {
    const hash = libs[title];
    await bench(title, () => hash.parallel(chunks), opts);
  }

  console.log(`# ciphers, input: 10mb, +threads`);
  await bench('chacha20poly1305', () => chacha20poly1305(key, n12).encrypt(cdata), copts);
  await bench('aes-gcm-256', () => gcm(key, n12).encrypt(cdata), copts);
  await bench('aes-gcm-siv-256', () => gcmsiv(key, n12).encrypt(cdata), copts);
  await bench('chacha20', () => chacha20(key, n12).encrypt(cdata), copts);
  await bench('aes-ecb-256', () => ecb(key).encrypt(cdata), copts);
  await bench('aes-cbc-256', () => cbc(key, n16).encrypt(cdata), copts);
  await bench('aes-ctr-256', () => ctr(key, n16).encrypt(cdata), copts);
}

main_threads();
