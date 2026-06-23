import mark from '@paulmillr/jsbt/bench.js';
import * as wasm from '../../src/targets/wasm/index.ts';
import * as js from '../../src/targets/js/index.ts';

function buf(n: number) {
  return new Uint8Array(n).fill(n % 251);
}

const buffers = [
  // { size: '16B', data: buf(16) }, // common block size
  // { size: '32B', data: buf(32) },
  { size: '64B', data: buf(64) },
  // { size: '1KB', data: buf(1024) },
  // { size: '8KB', data: buf(1024 * 8) },
  { size: '1MB', data: buf(1024 * 1024) },
];

async function main() {
  const key16 = buf(16);
  const key24 = buf(24);
  const key32 = buf(32);
  for (const [platform, libs] of Object.entries({ wasm, js })) {
    console.log('# ' + platform);
    for (let i = 0; i < 100_000; i++) libs.poly1305(key32, key32); // warm-up
    for (const { size, data } of buffers) {
      console.log(size);
      await mark('poly1305', () => libs.poly1305(data, key32));
      await mark('ghash', () => libs.ghash(data, key16));
      await mark('polyval', () => libs.polyval(data, key16));
      await mark('cmac-128', () => libs.cmac(data, key16));
      await mark('cmac-192', () => libs.cmac(data, key24));
      await mark('cmac-256', () => libs.cmac(data, key32));
      console.log();
    }
  }
}
main();
