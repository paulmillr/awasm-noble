import { describe, should } from '@paulmillr/jsbt/test.js';
import { sharePlatforms, startTests } from '../platforms.ts';

sharePlatforms('hashes');
const { PLATFORMS } = await import('./noble-hashes/test/platform.ts');
const { executeKDFTests } = await import('./noble-hashes/test/generator.ts');
const { init } = await import('./noble-hashes/test/hashes.test.ts');
const { avcpTests } = await import('./noble-hashes/test/acvp.test.ts');
const { test: clone } = await import('./noble-hashes/test/clone.test.ts');
const { test: blake } = await import('./noble-hashes/test/blake.test.ts');
const { test: keccak } = await import('./noble-hashes/test/keccak.test.ts');
const { test: hmac } = await import('./noble-hashes/test/hmac.test.ts');
const { test: kdf } = await import('./noble-hashes/test/kdf.test.ts');
const { test: info } = await import('./noble-hashes/test/info.test.ts');
const { test: webcrypto } = await import('./noble-hashes/test/webcrypto.test.ts');
const { test: argon2 } = await import('./noble-hashes/test/argon2.test.ts');
const BT = { describe, should };
for (const k in PLATFORMS) init(k, PLATFORMS[k], BT);
for (const k in PLATFORMS) avcpTests(false, k, PLATFORMS[k], BT);
for (const k in PLATFORMS) clone(k, PLATFORMS[k], BT);
for (const k in PLATFORMS) blake(k, PLATFORMS[k], BT);
for (const k in PLATFORMS) keccak(k, PLATFORMS[k], BT);
for (const k in PLATFORMS) hmac(k, PLATFORMS[k], BT);
for (const k in PLATFORMS) {
  kdf(k, PLATFORMS[k], BT);
  executeKDFTests(k, PLATFORMS[k], true, BT);
}
for (const k in PLATFORMS) info(k, PLATFORMS[k], BT);
for (const k in PLATFORMS) webcrypto(k, PLATFORMS[k], BT);
for (const k in PLATFORMS) argon2(k, PLATFORMS[k], BT);
await import('./blake3.test.ts');
await import('./hash-async.test.ts');
await import('./webcrypto.ts');
await import('./errors.test.ts');
await import('./zero.test.ts');

startTests(import.meta.url);
