import bench from '@paulmillr/jsbt/bench.js';
import { pbkdf2 } from '../src/kdf.ts';
import * as wasm from '../src/targets/wasm/index.ts';

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
  '10mb': rbuf(1024 * 1024 * 10)
};

async function main() {
  const data = BUFFERS['1mb'];
  const opts = { unit: 'mb', multiplier: 1 };
  const cdata = BUFFERS['10mb']
  const copts = { unit: 'mb', multiplier: 10 };
  const libs = wasm;

  // prettier-ignore
  const hashes = [
    'sha256', 'sha512', 'sha3_256', 'sha3_512', 'blake2b', 'blake2s', 'blake3', 'ripemd160', 'md5', 'sha1'
  ]
  // prettier-ignore
  const { chacha20poly1305, gcm, gcmsiv, chacha20, ecb, cbc, ctr } = libs;
  // prettier-ignore
  const key = rbuf(32), n12 = rbuf(12), n16 = rbuf(16);
  // warm-up
  for (let i = 0; i < 1000; i++) libs.sha256(data);
  for (let i = 0; i < 1000; i++) chacha20poly1305(key, n12).encrypt(cdata);

  // Benchmarks
  for (const title of hashes) {
    const hash = libs[title];
    await bench(title, () => hash(data), opts);
  }
  await bench('chacha20poly1305', () => chacha20poly1305(key, n12).encrypt(cdata), copts);
  await bench('aes-gcm-256', () => gcm(key, n12).encrypt(cdata), copts);
  await bench('aes-gcm-siv-256', () => gcmsiv(key, n12).encrypt(cdata), copts);
  await bench('chacha20', () => chacha20(key, n12).encrypt(cdata), copts);
  await bench('aes-ecb-256', () => ecb(key).encrypt(cdata), copts);
  await bench('aes-cbc-256', () => cbc(key, n16).encrypt(cdata), copts);
  await bench('aes-ctr-256', () => ctr(key, n16).encrypt(cdata), copts);

  console.log('# KDF');
  const pass = rbuf(12);
  const salt = rbuf(14);
  await bench(
    'pbkdf2(sha256, c: 2 ** 18)',
    () => pbkdf2(libs.sha256)(pass, salt, { c: 2 ** 18, dkLen: 32 })
  );
  await bench(
    'pbkdf2(sha512, c: 2 ** 18)',
    () => pbkdf2(libs.sha512)(pass, salt, { c: 2 ** 18, dkLen: 32 })
  );
  await bench(
    'scrypt(n: 2 ** 19, r: 8, p: 1)',
    () => libs.scrypt(pass, salt, { N: 2 ** 19, r: 8, p: 1, dkLen: 32 })
  );
  await bench(
    'argon2id(t: 1, m: 128MB, p: 1)',
    () => libs.argon2id(pass, salt, { t: 1, m: 128 * 1024, p: 1, dkLen: 32 })
  );
}

main();
