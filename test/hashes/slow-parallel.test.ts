import { describe, should } from '@paulmillr/jsbt/test.js';
import { deepStrictEqual } from 'node:assert';
import { WP } from '../../src/workers.ts';
import { HASHES, SIZES, randomBytes } from './basic_utils.ts';

describe('Hashes', () => {
  for (const k in HASHES) {
    describe(k, () => {
      const { noble, versions = [] } = HASHES[k];
      should(`parallelBasic`, async () => {
        await WP.waitOnline();
        for (const ver of versions) ver.parallel([new Uint8Array(10)]);
        await WP.waitOnline();
        for (const sz of SIZES) {
          const chunks = [];
          const exp = [];
          for (let i = 0; i < 20; i++) {
            const rand = randomBytes(sz);
            chunks.push(rand);
            exp.push(noble(rand));
          }
          for (const parChunks of [1, 2, 4, 8, 16, 17, 18, 19, 20]) {
            for (const ver of versions)
              deepStrictEqual(ver.parallel(chunks.slice(0, parChunks)), exp.slice(0, parChunks));
          }
        }
      });
    });
  }
});

should.runWhen(import.meta.url);
