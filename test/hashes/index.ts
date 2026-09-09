import { describe, it } from '@paulmillr/jsbt/test.js';
import { throws } from 'node:assert';
import { sharePlatforms, startTests } from '../platforms.ts';

sharePlatforms('hashes');
const { PLATFORMS } = await import('./noble-hashes/test/platform.ts');
const { executeKDFTests } = await import('./noble-hashes/test/generator.ts');
const { getHashes, init } = await import('./noble-hashes/test/hashes.test.ts');
const { TYPE_TEST } = await import('./noble-hashes/test/utils.ts');
const { avcpTests } = await import('./noble-hashes/test/acvp.test.ts');
const { test: clone } = await import('./noble-hashes/test/clone.test.ts');
const { test: blake } = await import('./noble-hashes/test/blake.test.ts');
const { test: keccak } = await import('./noble-hashes/test/keccak.test.ts');
const { test: hmac } = await import('./noble-hashes/test/hmac.test.ts');
const { test: kdf } = await import('./noble-hashes/test/kdf.test.ts');
const { test: info } = await import('./noble-hashes/test/info.test.ts');
const { test: webcrypto } = await import('./noble-hashes/test/webcrypto.test.ts');
const { test: argon2 } = await import('./noble-hashes/test/argon2.test.ts');
const BT = {
  describe,
  it: Object.assign((name: string, fn: () => unknown) => {
    // This mixes message checks with noble's stricter options-object policy.
    // Keep the full message contract below; awasm option handling stays unchanged.
    if (name === 'throw on wrong argument type') return it.skip(name, fn);
    return it(name, fn);
  }, it),
};
const addScryptMaxmem = (variant: string, platform: any) => {
  const { scrypt } = platform;
  const scryptMaxmem =
    platform.scryptMaxmem || ((opts: any) => 128 * opts.r * (opts.N + opts.p + 1));
  const formula = platform.scryptMaxmemFormula || '128*r*(N+p+1)';
  describe(`Scrypt (${variant})`, () => {
    it('Scrypt maxmem', () => {
      const opts = {
        N: 2 ** 10,
        r: 8,
        p: 16,
        dkLen: 64,
        maxmem: scryptMaxmem({ N: 2 ** 10, r: 8, p: 16 }),
      };
      scrypt('pwd', 'salt', opts);
      throws(() => scrypt('pwd', 'salt', { ...opts, maxmem: opts.maxmem - 1 }), {
        message: `Scrypt: "maxmem" limit was hit: memUsed(${formula})=${opts.maxmem}, maxmem=${opts.maxmem - 1}`,
      });
      const maxmem2 = scryptMaxmem({ N: 2 ** 11, r: 8, p: 16 });
      throws(() => scrypt('pwd', 'salt', { ...opts, N: 2 ** 11 }), {
        message: `Scrypt: "maxmem" limit was hit: memUsed(${formula})=${maxmem2}, maxmem=${opts.maxmem}`,
      });
    });
  });
};
const KDF_BT = {
  describe,
  it: (name: string, fn: () => unknown) => {
    // Shared noble-hashes coverage hardcodes noble's scrypt maxmem formula text.
    // awasm replaces that one case below with a formula-aware local assertion.
    if (name === 'Scrypt maxmem') return;
    // KT128/KT256 are not implemented by these platforms.
    if (name === 'PBKDF2-KT128/KT256 reuse workers across a tree-boundary salt')
      return it.skip(name, fn);
    return it(name, fn);
  },
};
for (const k in PLATFORMS) {
  init(k, PLATFORMS[k], BT);
  describe(`message validation (${k})`, () => {
    for (const [name, hash] of Object.entries(getHashes(PLATFORMS[k])))
      it(name, () => {
        for (const message of [undefined, ...TYPE_TEST.bytes]) {
          throws(() => hash.fn(message));
          throws(() => hash.obj().update(message).digest());
        }
      });
  });
}
for (const k in PLATFORMS) avcpTests(false, k, PLATFORMS[k], BT);
for (const k in PLATFORMS) clone(k, PLATFORMS[k], BT);
for (const k in PLATFORMS) blake(k, PLATFORMS[k], BT);
for (const k in PLATFORMS) keccak(k, PLATFORMS[k], BT);
for (const k in PLATFORMS) hmac(k, PLATFORMS[k], BT);
for (const k in PLATFORMS) {
  kdf(k, PLATFORMS[k], KDF_BT);
  addScryptMaxmem(k, PLATFORMS[k]);
  executeKDFTests(k, PLATFORMS[k], true, BT);
}
for (const k in PLATFORMS) info(k, PLATFORMS[k], BT);
for (const k in PLATFORMS) webcrypto(k, PLATFORMS[k], BT);
for (const k in PLATFORMS) argon2(k, PLATFORMS[k], BT);
await import('./blake3.test.ts');
await import('./hash-async.test.ts');
await import('./prefix-state.test.ts');
await import('./webcrypto.ts');
await import('./zero.test.ts');

startTests(import.meta.url);
