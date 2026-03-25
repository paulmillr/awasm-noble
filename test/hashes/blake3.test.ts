import { describe, should } from '@paulmillr/jsbt/test.js';
import { deepStrictEqual as eql } from 'node:assert';
import { PLATFORMS } from '../platforms.ts';

for (const k in PLATFORMS) {
  const { blake3 } = PLATFORMS[k];
  describe(`blake (${k})`, () => {
    describe('blake3', () => {
      should('XOF does not poison parallel', async () => {
        const batch = Array.from({ length: 4 }, (_, i) =>
          Uint8Array.from({ length: 256 * 1024 }, (_, j) => (j + i * 17) & 0xff)
        );
        blake3.create().xof(10);
        eql(await blake3.parallel.async(batch, { asyncTick: 0 }), blake3.parallel(batch));
      });
      should('parallel matches per-message on tail-sensitive batches', () => {
        const key = Uint8Array.from({ length: 32 }, (_, i) => (i + 1) & 0xff);
        const cases = [
          { n: 2, size: 1024 * 1024, opts: {} },
          { n: 3, size: 1024 * 1024, opts: {} },
          { n: 2, size: 1024 * 1024, opts: { key } },
          { n: 3, size: 1024 * 1024, opts: { key } },
        ];
        for (const c of cases) {
          const batch = Array.from({ length: c.n }, (_, i) =>
            Uint8Array.from({ length: c.size }, (_, j) => (j + i * 31) & 0xff)
          );
          const exp = batch.map((m) => blake3(m, c.opts));
          eql(blake3.parallel(batch, c.opts), exp);
        }
      });
    });
  });
}
