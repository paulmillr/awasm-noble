import { describe, should } from '@paulmillr/jsbt/test.js';
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
const { test: errors } = await import('./noble-ciphers/test/errors.test.ts');
const BT = { describe, should };
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
  errors(k, PLATFORMS[k], BT);
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
