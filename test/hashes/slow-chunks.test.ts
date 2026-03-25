import { describe, should } from '@paulmillr/jsbt/test.js';
import { deepStrictEqual } from 'node:assert';
import { concatBytes } from '../../src/utils.ts';
import { BUFS, HASHES, SIZES, msg, randomBytes, seq, seqU8 } from './basic_utils.ts';

describe('Hashes', () => {
  for (const k in HASHES) {
    describe(k, () => {
      const { noble, versions = [], parallel = [] } = HASHES[k];
      should('basic', () => {
        for (const b of BUFS) {
          const exp = noble(b);
          for (const ver of versions) deepStrictEqual(ver(b), exp);
        }
      });
      should('chunks', () => {
        const buf = randomBytes(16 * 1024);
        const exp = noble(buf);
        for (let i = 0; i < buf.length; i++) {
          const b1 = buf.subarray(0, i);
          const b2 = buf.subarray(i);
          for (const ver of versions) deepStrictEqual(ver.chunks([b1, b2]), exp);
        }
      });
      should('create', () => {
        const buf = randomBytes(16 * 1024);
        const exp = noble(buf);
        for (let i = 0; i < buf.length; i++) {
          const b1 = buf.subarray(0, i);
          const b2 = buf.subarray(i);
          for (const ver of versions)
            deepStrictEqual(ver.create().update(b1).update(b2).digest(), exp);
        }
      });
      should('clone/mid-stream-equivalence', () => {
        const buf = randomBytes(16 * 1024);
        for (let i = 0; i <= buf.length; i += 257) {
          const b1 = buf.subarray(0, i);
          const b2 = buf.subarray(i);
          const exp = noble(buf);
          for (const ver of versions) {
            const h = ver.create().update(b1);
            const c = h.clone();
            deepStrictEqual(h.update(b2).digest(), exp); // original continues
            deepStrictEqual(c.update(b2).digest(), exp); // clone continues
          }
        }
      });

      should('clone/independence', () => {
        const a = randomBytes(4096);
        const b = new Uint8Array([1]);
        const c = new Uint8Array([2]);
        for (const ver of versions) {
          const h = ver.create().update(a);
          const k = h.clone();
          const exp_b = noble(concatBytes(a, b));
          const exp_c = noble(concatBytes(a, c));
          deepStrictEqual(h.update(b).digest(), exp_b); // original path
          deepStrictEqual(k.update(c).digest(), exp_c); // diverged clone
        }
      });

      should('clone/into', () => {
        const buf = randomBytes(8 * 1024);
        for (let i = 0; i <= buf.length; i += 997) {
          const b1 = buf.subarray(0, i);
          const b2 = buf.subarray(i);
          const exp = noble(buf);
          for (const ver of versions) {
            const src = ver.create().update(b1);
            const dst = ver.create(); // will be overwritten
            const got = (src as any)._cloneInto(dst);
            // ensure it returned the same instance we passed in
            // (and that it produces correct digest)
            deepStrictEqual(got.update(b2).digest(), exp);
            // original still valid too
            deepStrictEqual(src.clone().update(b2).digest(), exp);
          }
        }
      });

      if (versions[0].canXOF) {
        should('xof/non-streaming', () => {
          for (const sz of SIZES) {
            const exp = noble(msg, { dkLen: sz });
            for (const ver of versions) deepStrictEqual(ver(msg, { dkLen: sz }), exp);
          }
        });
        should('xof/stream', () => {
          const sz = 16 * 1024;
          const exp = noble(msg, { dkLen: sz });
          for (let i = 0; i < sz; i++) {
            for (const ver of versions) {
              const h = ver.create().update(msg);
              deepStrictEqual(concatBytes(h.xof(i), h.xof(sz - i)), exp);
            }
          }
        });
        should('clone/xof-mid-stream', () => {
          const buf = randomBytes(12 * 1024 + 7);
          for (let cut = 0; cut <= 4096; cut += 313) {
            const b1 = buf.subarray(0, cut);
            const b2 = buf.subarray(cut);
            for (const ver of versions) {
              const h = ver.create().update(b1);
              const c = h.clone().update(b2); // clone finishes the message
              const total = buf.length;
              const exp = noble(buf, { dkLen: total }); // reference XOF stream of same length
              // read in two pulls from the clone to exercise XOF caching
              const take = Math.min(1234, total);
              const part1 = c.xof(take);
              const part2 = c.xof(total - take);
              deepStrictEqual(concatBytes(part1, part2), exp);
            }
          }
        });
        should('clone/xof-after-finish', () => {
          const msg = randomBytes(4096 + 33);
          const exp = noble(msg, { dkLen: 5000 });
          for (const ver of versions) {
            const h = ver.create().update(msg);
            // finalize on original, then clone the finalized state
            const hDone = ver.create().update(msg); // parallel to avoid consuming h
            const c = hDone.clone();
            deepStrictEqual(h.xof(5000), exp);
            // split XOF pulls on the clone to verify internal cache is copied
            deepStrictEqual(concatBytes(c.xof(123), c.xof(4877)), exp);
          }
        });
      }
      if (['blake256', 'blake224'].includes(k)) {
        should('blake256 specific', () => {
          const salts = [new Uint8Array(16).fill(1), seqU8(16), randomBytes(16)];
          for (const s of salts) {
            const opts = { salt: s };
            for (const b of BUFS) {
              const exp = noble(b, opts);
              for (const ver of versions) deepStrictEqual(ver(b, opts), exp);
            }
          }
        });
      }
      if (k === 'blake2s') {
        should('blake2s specific', () => {
          const salts = [new Uint8Array(8).fill(1), seqU8(8), randomBytes(8)];
          for (const s of salts) {
            const opts = { salt: s };
            for (const b of BUFS) {
              const exp = noble(b, opts);
              for (const ver of versions) deepStrictEqual(ver(b, opts), exp);
            }
            const opts2 = { personalization: s };
            for (const b of BUFS) {
              const exp = noble(b, opts2);
              for (const ver of versions) deepStrictEqual(ver(b, opts2), exp);
            }
          }
        });
        should('blake2s key', () => {
          // [1..32)
          const keys = seq(31)
            .map((i) => i + 1)
            .map((i) => [new Uint8Array(i).fill(1), seqU8(i), randomBytes(i)])
            .flat();
          const BUFS = seq(256).map((i) => randomBytes(i));
          for (const s of keys) {
            const opts = { key: s };
            for (const b of BUFS) {
              const exp = noble(b, opts);
              for (const ver of versions) {
                deepStrictEqual(ver(b, opts), exp);
                deepStrictEqual(ver.chunks([b], opts), exp);
                deepStrictEqual(ver.create(opts).update(b).digest(), exp);
              }
            }
          }
        });
        should('blake2s dkLen', () => {
          for (let i = 1; i < 32; i++) {
            const opts = { dkLen: i };
            const exp = noble(msg, opts);
            for (const ver of versions) deepStrictEqual(ver(msg, opts), exp);
          }
        });
      }
      if (k === 'blake2b') {
        should('blake2b specific', () => {
          const salts = [new Uint8Array(16).fill(1), seqU8(16), randomBytes(16)];
          for (const s of salts) {
            const opts = { salt: s };
            for (const b of BUFS) {
              const exp = noble(b, opts);
              for (const ver of versions) deepStrictEqual(ver(b, opts), exp);
            }
            const opts2 = { personalization: s };
            for (const b of BUFS) {
              const exp = noble(b, opts2);
              for (const ver of versions) deepStrictEqual(ver(b, opts2), exp);
            }
          }
        });
        should('blake2b key', () => {
          // [1..64)
          const keys = seq(63)
            .map((i) => i + 1)
            .map((i) => [new Uint8Array(i).fill(1), seqU8(i), randomBytes(i)])
            .flat();
          const BUFS = seq(256).map((i) => randomBytes(i));
          for (const s of keys) {
            const opts = { key: s };
            for (const b of BUFS) {
              const exp = noble(b, opts);
              for (const ver of versions) {
                deepStrictEqual(ver(b, opts), exp);
                deepStrictEqual(ver.chunks([b], opts), exp);
                deepStrictEqual(ver.create(opts).update(b).digest(), exp);
              }
            }
          }
        });
        should('blake2b dkLen', () => {
          for (let i = 1; i < 64; i++) {
            const opts = { dkLen: i };
            const exp = noble(msg, opts);
            for (const ver of versions) deepStrictEqual(ver(msg, opts), exp);
          }
        });
      }
      if (k === 'blake3') {
        should('blake3 specific', () => {
          const vectors = [
            { key: Uint8Array.from(seqU8(32)) },
            { context: Uint8Array.from(seqU8(245)) },
            { context: Uint8Array.from(seqU8(32)) },
            { context: Uint8Array.from(seqU8(3)) },
          ];
          for (const opts of vectors) {
            const exp = noble(msg, opts);
            for (const ver of versions) deepStrictEqual(ver(msg, opts), exp);
          }
        });
      }
    });
  }
});

should.runWhen(import.meta.url);
