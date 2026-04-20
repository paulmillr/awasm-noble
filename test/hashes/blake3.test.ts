import { describe, should } from '@paulmillr/jsbt/test.js';
import { deepStrictEqual as eql } from 'node:assert';
import { blake3 as nobleBlake3 } from '@noble/hashes/blake3.js';
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
      // Regression: inputs with blocks=64 (4 full 1 KiB chunks) and 2..63 trailing zero-pad
      // bytes on the last block previously produced wrong digests on the SIMD WASM target.
      // proccessChunksSequential built its per-lane `V[14] = blockLen - left` mask with
      // `T.and(T.fromN('u32', isLastBlock), T.eq(...))`, which left only the LSB set in
      // lane 3 and (through v128.bitselect) truncated V[14] to `blockLen - (left & 1)`.
      // Covers every `left` in [0, 63] across two 4 KiB boundaries and the streaming
      // create/update/digest path (which takes a different code path and already worked).
      should('single-shot matches streaming across 4 KiB boundaries', () => {
        for (const base of [4096, 8192]) {
          for (let off = -64; off <= 0; off++) {
            const n = base + off;
            const buf = Uint8Array.from({ length: n }, (_, i) => i & 0xff);
            const ref = nobleBlake3(buf);
            eql(blake3(buf), ref, `blake3(${n}) single-shot`);
            eql(blake3.chunks([buf]), ref, `blake3(${n}) chunks`);
            eql(blake3.create().update(buf).digest(), ref, `blake3(${n}) stream`);
          }
        }
      });
    });
  });
}
