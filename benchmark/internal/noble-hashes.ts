import bench from '@paulmillr/jsbt/benchmark.js';
import { pbkdf2 } from '../../src/kdf.ts';
import { hmac } from '../../src/hmac.ts';
import { hkdf } from '../../src/hkdf.ts';
import * as wasm from '../../src/targets/wasm/index.ts';
import * as js from '../../src/targets/js/index.ts';

function buf(size) {
  return new Uint8Array(size).fill(size % 251);
}

const buffers = [
  // { size: '16B', data: buf(16) }, // common block size
  { size: '32B', data: buf(32) },
  // { size: '64B', data: buf(64) },
  // { size: '1KB', data: buf(1024) },
  // { size: '8KB', data: buf(1024 * 8) },
  { size: '1MB', data: buf(1024 * 1024) },
];

async function main() {
  for (const [platform, libs] of Object.entries({ wasm, js })) {
    console.log('# ' + platform);
    const d = buf(32);
    for (let i = 0; i < 1_000_000; i++) libs.sha256(d); // warm-up

    // prettier-ignore
    const hashes = [
      'sha256', 'sha512', 'sha3_256', 'sha3_512', 'blake256', 'blake2b', 'blake2s', 'blake3', 'ripemd160', 'md5', 'sha1'
    ]
    for (const { size, data } of buffers) {
      console.log('# ' + size);
      for (const title of hashes) {
        const hash = libs[title];
        await bench(title, () => hash(data), { bytes: data.byteLength });
      }
      console.log();
    }

    console.log('# MAC');
    const etc = buf(32);
    await bench('hmac(sha256)', () => hmac(libs.sha256, etc, etc));
    await bench('hmac(sha512)', () => hmac(libs.sha512, etc, etc));
    // await bench('kmac256', () => kmac256(etc, etc));
    await bench('blake3(key)', () => libs.blake3(etc, { key: etc }));

    console.log();
    console.log('# KDF');
    const pass = buf(12);
    const salt = buf(14);
    await bench('hkdf(sha256)', () => hkdf(libs.sha256, salt, pass, etc, 32));
    await bench('blake3(context)', () => libs.blake3(etc, { context: etc }));
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
    console.log();
  }
}
main();
