import { describe, it } from '@paulmillr/jsbt/test.js';
import { getCipherPlatforms, startTests } from '../platforms.ts';
const { test: aes } = await import('./noble-ciphers/test/aes.test.ts');
const { test: arx } = await import('./noble-ciphers/test/arx.test.ts');
const { test: basic } = await import('./noble-ciphers/test/basic.test.ts');
const { test: cmac } = await import('./noble-ciphers/test/cmac.test.ts');
const { test: crosstest } = await import('./noble-ciphers/test/crosstest.test.ts');
const { test: polyval } = await import('./noble-ciphers/test/polyval.test.ts');
const { test: siv } = await import('./noble-ciphers/test/siv.test.ts');
const { test: utils } = await import('./noble-ciphers/test/utils.test.ts');
const { test: webcrypto } = await import('./noble-ciphers/test/webcrypto.test.ts');
const SKIP = new Set([
  // awasm uses fixed module scratch; local validation and zeroization tests cover this.
  'rejects invalid keys before allocation and wipes plaintext copies',
  // awasm copies overlapping input; async.test.ts checks the resulting ciphertext.
  'raw stream ciphers reject output that overlaps unread input',
  // Noble-private fields; the shared public CMAC streaming/output tests still run.
  'keep only one pending block across updates',
  'generate correct subkeys',
  // awasm permits unaligned and forward-overlapping AES output; tested locally.
  ...['cbc', 'ctr', 'ecb'].flatMap((name) =>
    [128, 192, 256].map((bits) => `${name}_${bits} (re-use)`)
  ),
  // awasm rejects asynchronously; webcrypto.ts checks reuse and tampering locally.
  'enforces encrypt-once and rejects tampered GCM ciphertext',
  // This mock uses invalid AES key/nonce lengths; local coverage uses valid inputs.
  'snapshots key and crypt params, but not payload, before awaiting key import',
]);
const BT = {
  describe,
  it: Object.assign((name: string, fn: () => unknown) => {
    if (SKIP.has(name)) return it.skip(name, fn);
    return it(name, fn);
  }, it),
};
const PLATFORMS = getCipherPlatforms();
for (const k in PLATFORMS) {
  aes(k, PLATFORMS[k], BT);
  arx(k, PLATFORMS[k], BT);
  basic(k, PLATFORMS[k], BT);
  cmac(k, PLATFORMS[k], BT);
  crosstest(k, PLATFORMS[k], BT);
  polyval(k, PLATFORMS[k], BT);
  siv(k, PLATFORMS[k], BT);
  webcrypto(k, PLATFORMS[k], BT);
}
utils(BT);
await import('./aeskw.test.ts');
await import('./async.test.ts');
await import('./chunks.test.ts');
await import('./ofb.test.ts');
await import('./threads-poison.test.ts');
await import('./mac.test.ts');
await import('./webcrypto.ts');
await import('./zero.test.ts');

startTests(import.meta.url);
