import { describe, should } from '@paulmillr/jsbt/test.js';
import { deepStrictEqual } from 'node:assert';
import { concatBytes } from '../../src/utils.ts';
import * as js from '../../src/targets/js/index.ts';
import * as wasm from '../../src/targets/wasm/index.ts';
import * as wasm_threads from '../../src/targets/wasm_threads/index.ts';
import { NOBLE } from '../noble-all.ts';
import { WP } from '../../src/workers.ts';

const seqU8 = (n: number): Uint8Array => {
  const a = new Uint8Array(n);
  for (let i = 0; i < n; ) a[i] = ++i & 255;
  return a;
};

const randomBytes = (len: number): Uint8Array => {
  const out = new Uint8Array(len);
  const CHUNK = 0xffff;
  let offset = 0;
  while (offset < len) {
    const size = Math.min(len - offset, CHUNK);
    crypto.getRandomValues(out.subarray(offset, offset + size));
    offset += size;
  }
  return out;
};

const seq = (length: number) => Array.from({ length }, (_, i) => i);
const SIZES = Array.from(
  new Set([
    0,
    ...seq(256),
    ...seq(16).map((i) => 1024 * i),
    ...seq(16).map((i) => 1024 * i + 1),
    ...seq(16).map((i) => 1024 * i - 1),
    ...seq(16).map((i) => 4096 * i),
    ...seq(16).map((i) => 4096 * i + 1),
    ...seq(16).map((i) => 4096 * i - 1),
    10 * 1024 * 1024,
  ])
).map((i) => Math.max(0, i));

const BUFS = [
  ...SIZES.map((i) => seqU8(i)),
  ...SIZES.map((i) => new Uint8Array(i).fill(0xff)),
  ...SIZES.map((i) => new Uint8Array(i).fill(0x01)),
  ...SIZES.map((i) => new Uint8Array(i).fill(0x00)),
  ...SIZES.map((i) => randomBytes(i)),
];

const MACS = {
  poly1305: {
    noble: NOBLE.poly1305,
    keyLens: [32],
    versions: [js.poly1305, wasm.poly1305, wasm_threads.poly1305].filter((i) => !!i),
  },
  ghash: {
    noble: NOBLE.ghash,
    keyLens: [16],
    versions: [js.ghash, wasm.ghash, wasm_threads.ghash].filter((i) => !!i),
  },
  polyval: {
    noble: NOBLE.polyval,
    keyLens: [16],
    versions: [js.polyval, wasm.polyval, wasm_threads.polyval].filter((i) => !!i),
  },
  cmac: {
    noble: NOBLE.cmac,
    keyLens: [16, 24, 32],
    versions: [js.cmac, wasm.cmac, wasm_threads.cmac].filter((i) => !!i),
  },
};

describe('MACs', () => {
  for (const k in MACS) {
    describe(k, () => {
      const { noble, versions, keyLens } = MACS[k];
      should('basic', () => {
        for (const keyLen of keyLens) {
          const key = randomBytes(keyLen);
          for (const b of BUFS) {
            const exp = noble.create(key).update(b).digest();
            for (const ver of versions) deepStrictEqual(ver(b, key), exp);
          }
        }
      });
      should('chunks', () => {
        const buf = randomBytes(16 * 1024);
        for (const keyLen of keyLens) {
          const key = randomBytes(keyLen);
          const exp = noble.create(key).update(buf).digest();
          for (let i = 0; i < buf.length; i++) {
            const b1 = buf.subarray(0, i);
            const b2 = buf.subarray(i);
            for (const ver of versions) deepStrictEqual(ver.chunks([b1, b2], key), exp);
          }
        }
      });
      should('create', () => {
        const buf = randomBytes(16 * 1024);
        for (const keyLen of keyLens) {
          const key = randomBytes(keyLen);
          const exp = noble.create(key).update(buf).digest();
          for (let i = 0; i < buf.length; i++) {
            const b1 = buf.subarray(0, i);
            const b2 = buf.subarray(i);
            for (const ver of versions)
              deepStrictEqual(ver.create(key).update(b1).update(b2).digest(), exp);
          }
        }
      });
      should('clone/mid-stream-equivalence', () => {
        const buf = randomBytes(16 * 1024);
        for (const keyLen of keyLens) {
          const key = randomBytes(keyLen);
          for (let i = 0; i <= buf.length; i += 257) {
            const b1 = buf.subarray(0, i);
            const b2 = buf.subarray(i);
            const exp = noble.create(key).update(buf).digest();
            for (const ver of versions) {
              const h = ver.create(key).update(b1);
              const c = h.clone();
              deepStrictEqual(h.update(b2).digest(), exp);
              deepStrictEqual(c.update(b2).digest(), exp);
            }
          }
        }
      });
      should('clone/independence', () => {
        const a = randomBytes(4096);
        const b = new Uint8Array([1]);
        const c = new Uint8Array([2]);
        for (const keyLen of keyLens) {
          const key = randomBytes(keyLen);
          for (const ver of versions) {
            const h = ver.create(key).update(a);
            const k = h.clone();
            const exp_b = noble.create(key).update(concatBytes(a, b)).digest();
            const exp_c = noble.create(key).update(concatBytes(a, c)).digest();
            deepStrictEqual(h.update(b).digest(), exp_b);
            deepStrictEqual(k.update(c).digest(), exp_c);
          }
        }
      });
      should('clone/into', () => {
        const buf = randomBytes(8 * 1024);
        for (const keyLen of keyLens) {
          const key = randomBytes(keyLen);
          for (let i = 0; i <= buf.length; i += 997) {
            const b1 = buf.subarray(0, i);
            const b2 = buf.subarray(i);
            const exp = noble.create(key).update(buf).digest();
            for (const ver of versions) {
              const src = ver.create(key).update(b1);
              const dst = ver.create(key);
              const got = (src as any)._cloneInto(dst);
              deepStrictEqual(got.update(b2).digest(), exp);
              deepStrictEqual(src.clone().update(b2).digest(), exp);
            }
          }
        }
      });
      should('interleaved-streams-independence', () => {
        const a0 = randomBytes(11 * 1024 + 3);
        const b0 = randomBytes(13 * 1024 + 7);
        for (const keyLen of keyLens) {
          const keyA = randomBytes(keyLen);
          const keyB = randomBytes(keyLen);
          const expA = noble.create(keyA).update(a0).digest();
          const expB = noble.create(keyB).update(b0).digest();
          const cutsA = [0, 17, 257, 1023, 4097, a0.length];
          const cutsB = [0, 31, 503, 2049, 8191, b0.length];
          for (const ver of versions) {
            const a = ver.create(keyA);
            const b = ver.create(keyB);
            for (let i = 1; i < cutsA.length; i++) {
              a.update(a0.subarray(cutsA[i - 1]!, cutsA[i]!));
              b.update(b0.subarray(cutsB[i - 1]!, cutsB[i]!));
            }
            deepStrictEqual(a.digest(), expA);
            deepStrictEqual(b.digest(), expB);
          }
        }
      });
      should('parallelBasic', async () => {
        await WP.waitOnline();
        for (const keyLen of keyLens) {
          const key = randomBytes(keyLen);
          for (const ver of versions) ver.parallel([new Uint8Array(10)], key);
        }
        await WP.waitOnline();
        for (const keyLen of keyLens) {
          const key = randomBytes(keyLen);
          for (const sz of SIZES) {
            const chunks = [];
            const exp = [];
            for (let i = 0; i < 20; i++) {
              const rand = randomBytes(sz);
              chunks.push(rand);
              exp.push(noble.create(key).update(rand).digest());
            }
            for (const parChunks of [1, 2, 4, 8, 16, 17, 18, 19, 20]) {
              for (const ver of versions)
                deepStrictEqual(
                  ver.parallel(chunks.slice(0, parChunks), key),
                  exp.slice(0, parChunks)
                );
            }
          }
        }
      });
    });
  }
});

should.runWhen(import.meta.url);
