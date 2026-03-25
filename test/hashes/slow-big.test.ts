import { describe, should } from '@paulmillr/jsbt/test.js';
import { deepStrictEqual as eql } from 'node:assert';
import { scryptSync as nodeScryptSync } from 'node:crypto';
import { hexToBytes } from '../../src/utils.ts';
import { sharePlatforms, startTests } from '../platforms.ts';

const GB = 1024 * 1024 * 1024;
const ZERO_4GB = new Uint8Array(4 * GB);
const PASSWORD = new Uint8Array([1, 2, 3]);
const SALT = new Uint8Array([4, 5, 6]);
const BT = { describe, should };
function supportsXgb(x: number) {
  try {
    let buf = new Uint8Array(x * GB); // catches u32 overflow in ints
    buf = new Uint8Array(0);
    return true;
  } catch (error) {
    return false;
  }
}

sharePlatforms('hashes');
const { PLATFORMS } = await import('./noble-hashes/test/platform.ts');
const { executeKDFTests } = await import('./noble-hashes/test/generator.ts');
const { getHashes } = await import('./noble-hashes/test/hashes.test.ts');
const { test } = await import('./noble-hashes/test/slow-big.test.ts');
for (const k in PLATFORMS) {
  const platform = PLATFORMS[k];
  test(
    k,
    platform,
    getHashes(platform),
    (name, platform, isFastOnly) => executeKDFTests(name, platform, isFastOnly, BT),
    BT,
    { largeScryptR: false, scrypt25GB: 18 }
  );
  should(`Scrypt (2**24) (${k})`, async () => {
    if (!supportsXgb(18)) return;
    const opts = { N: 2 ** 24, r: 2, p: 2 };
    const exp = Uint8Array.from(nodeScryptSync(PASSWORD, SALT, 32, { ...opts, maxmem: 18 * GB }));
    const nobleOpts = { ...opts, maxmem: 18 * GB };
    eql(platform.scrypt(PASSWORD, SALT, nobleOpts), exp);
    eql(await platform.scryptAsync(PASSWORD, SALT, nobleOpts), exp);
  });
  describe(k, () => {
    should('Hmac 4GB', async () => {
      const exp = hexToBytes('c5c39ec0ad91ddc3010d683b7e077aeedaba92fb7da17e367dbcf08e11aa25d1');
      eql(platform.hmac(platform.sha256, ZERO_4GB, ZERO_4GB), exp);
    });
  });
}

// non parallel: 14h, parallel: ~1h
startTests(import.meta.url);
