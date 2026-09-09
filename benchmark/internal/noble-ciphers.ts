import mark from '@paulmillr/jsbt/benchmark.js';
import * as js from '../../src/targets/js/index.ts';
import * as wasm from '../../src/targets/wasm/index.ts';

function buf(n: number) {
  return new Uint8Array(n).fill(n % 251);
}

function benchBuf(n: number, seed = 0x9e3779b9) {
  // Sequential buffers can bias AES table/cache access patterns.
  // Use deterministic pseudo-random data for fairer cross-library comparisons.
  const out = new Uint8Array(n);
  let x = seed >>> 0;
  for (let i = 0; i < n; i++) {
    x ^= x << 13;
    x ^= x >>> 17;
    x ^= x << 5;
    out[i] = x & 0xff;
  }
  return out;
}

const buffers = [
  { size: '10MB', data: benchBuf(1024 * 1024 * 10) },
];

async function main() {
  const key = buf(32);
  const key64 = buf(64);
  const nonce = buf(12);
  const nonce8 = buf(8);
  const nonce16 = buf(16);
  const nonce24 = buf(24);
  for (const [platform, libs] of Object.entries({ wasm, js })) {
    console.log('# ' + platform);
    const {
      xsalsa20poly1305,
      chacha20poly1305,
      xchacha20poly1305,
      gcm,
      gcmsiv,
      aessiv,
      salsa20,
      xsalsa20,
      chacha20,
      xchacha20,
      chacha8,
      chacha12,
      ecb,
      cbc,
      ctr,
    } = libs;
    // Warm up constructors and JIT before measuring.
    for (let i = 0; i < 100_000; i++) xsalsa20poly1305(key, nonce24).encrypt(benchBuf(64));
    for (const { size, data: buf } of buffers) {
      const opts = { bytes: buf.byteLength };
      console.log(size);
      // await mark('xsalsa20poly1305', () => xsalsa20poly1305(key, nonce24).encrypt(buf));
      await mark('chacha20poly1305', () => chacha20poly1305(key, nonce).encrypt(buf), opts);
      // await mark('xchacha20poly1305', () => xchacha20poly1305(key, nonce24).encrypt(buf));
      await mark('aes-gcm-256', () => gcm(key, nonce).encrypt(buf), opts);
      await mark('aes-gcm-siv-256', () => gcmsiv(key, nonce).encrypt(buf), opts);
      await mark('aes-siv-256', () => aessiv(key, nonce, nonce16, nonce24).encrypt(buf), opts);
      await mark('aes-siv-512', () => aessiv(key64, nonce, nonce16, nonce24).encrypt(buf), opts);

      console.log('# Unauthenticated encryption');
      await mark('salsa20', () => salsa20(key, nonce8).encrypt(buf), opts);
      await mark('xsalsa20', () => xsalsa20(key, nonce24).encrypt(buf), opts);
      await mark('chacha20', () => chacha20(key, nonce).encrypt(buf), opts);
      await mark('xchacha20', () => xchacha20(key, nonce24).encrypt(buf), opts);
      await mark('chacha8', () => chacha8(key, nonce).encrypt(buf), opts);
      await mark('chacha12', () => chacha12(key, nonce).encrypt(buf), opts);
      await mark('aes-ecb-256', () => ecb(key).encrypt(buf), opts);
      await mark('aes-cbc-256', () => cbc(key, nonce16).encrypt(buf), opts);
      await mark('aes-ctr-256', () => ctr(key, nonce16).encrypt(buf), opts);

      console.log();
    }
  }
}
main();
