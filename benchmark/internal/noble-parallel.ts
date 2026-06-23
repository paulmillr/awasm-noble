import bench from '@paulmillr/jsbt/bench';
import { pbkdf2 } from '../../src/kdf.ts';
import { hmac } from '../../src/hmac.ts';
import { hkdf } from '../../src/hkdf.ts';
import * as wasm_threads from '../../src/targets/wasm_threads/index.ts';
import { WP } from '../../src/workers.ts';

function buf(size) {
  return new Uint8Array(size).fill(size % 251);
}
const BUFFERS = {
  '1MB': buf(1024 * 1024),
  '10MB': buf(10 * 1024 * 1024),
};

async function main() {
  for (const [platform, libs] of Object.entries({ wasm_threads })) {
    console.log('# ' + platform);

    // prettier-ignore
    const hashes = [
      'sha256', 'sha512', 'sha3_256', 'sha3_512', 'blake256', 'blake2b', 'blake2s', 'blake3', 'ripemd160', 'md5', 'sha1'
    ]
    const data = new Array(10).fill(BUFFERS['1MB']);
    // warmup
    await WP.waitOnline();
    for (const title of hashes) libs[title].parallel(data);
    await WP.waitOnline();

    console.log('# Parallel hashes (1 op = 1MB/s)');
    await bench('blake3 sequential (10MB)', () => libs.blake3(BUFFERS['10MB']));
    console.log();
    console.log('# Sequential hashes (Hint: 10ops = 100MB/s)');
    for (const title of hashes) {
      const hash = libs[title];
      await bench(`${title} (10x1MB)`, () => hash.parallel(data));
    }
    console.log();
  }
}
main();
