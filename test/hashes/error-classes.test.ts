import test from 'node:test';
import { deepStrictEqual, rejects, throws } from 'node:assert';
import { PLATFORMS } from '../platforms.ts';
import { hmac } from '../../src/hmac.ts';
import { utf8ToBytes } from './noble-hashes/src/utils.ts';

const msg = utf8ToBytes('abc');
const key = utf8ToBytes('key');

for (const name in PLATFORMS) {
  const p = PLATFORMS[name];
  test(`${name}: one-shot hash opts use TypeError/RangeError`, async () => {
    const short = p.sha256.outputLen - 1;
    const full = p.sha256(msg);
    throws(() => p.sha256(msg, { dkLen: '32' as any }), TypeError);
    deepStrictEqual(p.sha256(msg, { dkLen: short }), full.subarray(0, short));
    throws(() => p.sha256(msg, { dkLen: p.sha256.outputLen + 1 }), RangeError);
    throws(() => p.sha256(msg, { out: new Uint8Array(p.sha256.outputLen - 1) }), RangeError);
    throws(() => p.sha256(msg, { outPos: '1' as any }), TypeError);
    throws(() => p.sha256(msg, { out: new Uint8Array(p.sha256.outputLen), outPos: 1 }), RangeError);
    await rejects(() => p.sha256.async(msg, { asyncTick: 0, dkLen: '32' as any }), TypeError);
    deepStrictEqual(
      await p.sha256.async(msg, { asyncTick: 0, dkLen: short }),
      full.subarray(0, short)
    );
    await rejects(
      () => p.sha256.async(msg, { asyncTick: 0, dkLen: p.sha256.outputLen + 1 }),
      RangeError
    );
    await rejects(
      () =>
        p.sha256.async(msg, { asyncTick: 0, out: new Uint8Array(p.sha256.outputLen), outPos: 1 }),
      RangeError
    );
  });

  test(`${name}: stream hash opts use TypeError/RangeError`, () => {
    const short = p.sha256.outputLen - 1;
    const full = p.sha256(msg);
    throws(
      () =>
        p.sha256
          .create()
          .update(msg)
          .digest({ dkLen: '32' as any }),
      TypeError
    );
    deepStrictEqual(
      p.sha256.create().update(msg).digest({ dkLen: short }),
      full.subarray(0, short)
    );
    throws(
      () =>
        p.sha256
          .create()
          .update(msg)
          .digest({ dkLen: p.sha256.outputLen + 1 }),
      RangeError
    );
    throws(
      () =>
        p.sha256
          .create()
          .update(msg)
          .digest({ outPos: '1' as any }),
      TypeError
    );
    throws(
      () =>
        p.sha256
          .create()
          .update(msg)
          .digest({ out: new Uint8Array(p.sha256.outputLen), outPos: 1 }),
      RangeError
    );
    throws(
      () =>
        p.shake128
          .create()
          .update(msg)
          .xof('16' as any),
      TypeError
    );
    throws(
      () =>
        p.shake128
          .create()
          .update(msg)
          .xof(16, { out: new Uint8Array(15) }),
      RangeError
    );
  });
}

test('hmac.create rejects non-hash with TypeError', () => {
  throws(() => hmac.create({} as any, key), TypeError);
});
