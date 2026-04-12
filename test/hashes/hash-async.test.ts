import { describe, should } from '@paulmillr/jsbt/test.js';
import { deepStrictEqual as eql, rejects, strictEqual, throws } from 'node:assert';
import { PLATFORMS } from '../platforms.ts';
import * as webcrypto from '../../src/webcrypto.ts';
import * as wasm from '../../src/targets/wasm/index.ts';
import { mkHash } from '../../src/hashes-abstract.ts';
import { pbkdf2 } from '../../src/kdf.ts';

const msg = Uint8Array.from({ length: 1024 * 1024 }, (_, i) => (i * 13) & 0xff);
const parts = [msg.subarray(0, 300_000), msg.subarray(300_000, 700_000), msg.subarray(700_000)];
const batch = Array.from({ length: 4 }, (_, i) =>
  Uint8Array.from({ length: 256 * 1024 }, (_, j) => (j + i * 17) & 0xff)
);

for (const name in PLATFORMS) {
  const p = PLATFORMS[name];
  describe(`hash async (${name})`, () => {
    should('sha256 sync/async parity', async () => {
      const sync = p.sha256(msg);
      const asyncOut = await p.sha256.async(msg, { asyncTick: 0 });
      eql(asyncOut, sync);
    });

    should('sha256 async uses nextTick', async () => {
      let ticks = 0;
      const out = await p.sha256.async(msg, {
        asyncTick: 0,
        nextTick: async () => {
          ticks++;
        },
      });
      eql(out, p.sha256(msg));
      eql(ticks > 0, true);
    });
    should('pbkdf2 async uses nextTick', async () => {
      const kdf = pbkdf2(p.sha256);
      const sync = kdf('pwd', 'salt', { c: 4, dkLen: 16 });
      let ticks = 0;
      const asyncOut = await kdf.async('pwd', 'salt', {
        c: 4,
        dkLen: 16,
        asyncTick: 0,
        nextTick: async () => {
          ticks++;
        },
      });
      eql(asyncOut, sync);
      eql(ticks > 0, true);
    });
    should('sha256 async onProgress is called', async () => {
      let calls = 0;
      let last = 0;
      const out = await p.sha256.async(msg, {
        asyncTick: 0,
        onProgress: (p) => {
          calls++;
          last = p;
        },
      });
      eql(out, p.sha256(msg));
      eql(calls > 0, true);
      eql(last, 1);
    });
    should('sha256 async reports completed progress for empty input', async () => {
      const progress: number[] = [];
      const empty = new Uint8Array(0);
      const out = await p.sha256.async(empty, {
        onProgress: (per) => {
          progress.push(per);
        },
      });
      eql(out, p.sha256(empty));
      eql(progress, [1]);
    });

    should('sha256 async survives interleaved hash activity', async () => {
      const sync = p.sha256(msg);
      let ticks = 0;
      const asyncOut = await p.sha256.async(msg, {
        asyncTick: 0,
        nextTick: async () => {
          ticks++;
          p.sha512(msg.subarray(0, 4096));
        },
      });
      eql(asyncOut, sync);
      eql(ticks > 0, true);
    });

    should('blake2b chunks sync/async parity', async () => {
      const sync = p.blake2b.chunks(parts);
      let ticks = 0;
      const asyncOut = await p.blake2b.chunks.async(parts, {
        asyncTick: 0,
        nextTick: async () => {
          ticks++;
          p.blake2s(msg.subarray(0, 2048));
        },
      });
      eql(asyncOut, sync);
      eql(ticks > 0, true);
    });

    should('sha256 parallel sync/async parity', async () => {
      const sync = p.sha256.parallel(batch);
      let ticks = 0;
      const asyncOut = await p.sha256.parallel.async(batch, {
        asyncTick: 0,
        nextTick: async () => {
          ticks++;
          p.sha3_256(msg.subarray(0, 1024));
        },
      });
      eql(asyncOut, sync);
      eql(ticks > 0, true);
    });
    should('sha256 parallel honors out/outPos for every lane', async () => {
      const syncExp = p.sha256.parallel(batch);
      const outSync = new Uint8Array(1 + batch.length * syncExp[0].length);
      const resSync = p.sha256.parallel(batch, { out: outSync, outPos: 1 });
      const expSync = new Uint8Array(outSync.length);
      for (let i = 0; i < syncExp.length; i++) expSync.set(syncExp[i], 1 + i * syncExp[i].length);
      eql(outSync, expSync);
      eql(resSync, syncExp);

      const outAsync = new Uint8Array(1 + batch.length * syncExp[0].length);
      const resAsync = await p.sha256.parallel.async(batch, {
        asyncTick: 0,
        out: outAsync,
        outPos: 1,
      });
      eql(outAsync, expSync);
      eql(resAsync, syncExp);
    });
    should('sha256 fixed-digest async wrappers honor shorter dkLen', async () => {
      eql(await p.sha256.async(msg, { asyncTick: 0, dkLen: 3 }), p.sha256(msg).subarray(0, 3));
      eql(
        await p.sha256.chunks.async(parts, { asyncTick: 0, dkLen: 3 }),
        p.sha256.chunks(parts).subarray(0, 3)
      );
      eql(
        await p.sha256.parallel.async(batch, { asyncTick: 0, dkLen: 3 }),
        p.sha256.parallel(batch).map((i) => i.subarray(0, 3))
      );
    });
    should('sha256 async respects out/outPos', async () => {
      const out = new Uint8Array(48);
      const res = await p.sha256.async(msg, { asyncTick: 0, out, outPos: 8 });
      strictEqual(res.buffer, out.buffer);
      strictEqual(res.length, out.length);
      eql(res.subarray(8, 40), p.sha256(msg));
    });
    should('sha256 async invalid output opts does not poison next run', async () => {
      await rejects(() =>
        p.sha256.async(msg, { asyncTick: 0, out: new Uint8Array(16), outPos: 1 })
      );
      eql(await p.sha256.async(msg, { asyncTick: 0 }), p.sha256(msg));
    });
    should('sha256 parallel async invalid output opts does not poison next run', async () => {
      await rejects(() =>
        p.sha256.parallel.async(batch, {
          asyncTick: 0,
          out: Array.from({ length: batch.length }, () => new Uint8Array(16)),
        })
      );
      eql(await p.sha256.parallel.async(batch, { asyncTick: 0 }), p.sha256.parallel(batch));
    });
    should('blake3 parallel size-mismatch throw does not poison next run', async () => {
      if (name !== 'wasm_threads') return;
      const bad = [new Uint8Array(10), new Uint8Array(11)];
      throws(() => p.blake3.parallel(bad));
      await rejects(() => p.blake3.parallel.async(bad, { asyncTick: 0 }));
      eql(await p.blake3.parallel.async(batch, { asyncTick: 0 }), p.blake3.parallel(batch));
    });
    should('blake3 parallel async invalid output opts does not poison next run', async () => {
      if (name !== 'wasm_threads') return;
      await rejects(() =>
        p.blake3.parallel.async(batch, { asyncTick: 0, out: new Uint8Array(1) as any })
      );
      eql(await p.blake3.parallel.async(batch, { asyncTick: 0 }), p.blake3.parallel(batch));
    });
    should('blake3 create digest invalid output opts does not poison parallel', async () => {
      if (name !== 'wasm_threads') return;
      throws(() => p.blake3.create().digest({ out: new Uint8Array(1) as any }));
      eql(await p.blake3.parallel.async(batch, { asyncTick: 0 }), p.blake3.parallel(batch));
    });
  });
}

describe('hash async (webcrypto)', () => {
  should('sha256 fixed-digest async wrappers honor shorter dkLen', async () => {
    eql(await webcrypto.sha256.async(msg, { dkLen: 3 }), wasm.sha256(msg).subarray(0, 3));
    eql(
      await webcrypto.sha256.chunks.async(parts, { dkLen: 3 }),
      wasm.sha256.chunks(parts).subarray(0, 3)
    );
    eql(
      await webcrypto.sha256.parallel.async(batch, { dkLen: 3 }),
      wasm.sha256.parallel(batch).map((i) => i.subarray(0, 3))
    );
  });
});

describe('hash parallel local', () => {
  should('mkHash.parallel honors outPos across multiple groups', () => {
    const lanes = [
      Uint8Array.of(11, 12, 13, 14),
      Uint8Array.of(21, 22, 23, 24),
      Uint8Array.of(31, 32, 33, 34),
    ];
    const hash = mkHash(
      () => {
        const buffer = new Uint8Array(64);
        const state0 = new Uint8Array(4);
        const state1 = new Uint8Array(4);
        return {
          segments: {
            buffer,
            state: state0,
            state_chunks: [state0, state1],
            'state.state_chunks': [state0, state1],
          },
          reset() {},
          padding() {
            return 0;
          },
          processBlocks() {},
          processOutBlocks(
            _batchPos: number,
            batchCnt: number,
            blocks: number,
            maxOutBlocks: number
          ) {
            for (let i = 0; i < batchCnt; i++) {
              // Real modules reuse group-local output slots; the copied input byte marks which
              // logical message this lane currently represents across multi-group runs.
              const lane = buffer[i * 4 * maxOutBlocks] - 1;
              buffer.set(lanes[lane].subarray(0, blocks * 4), i * 4 * maxOutBlocks);
            }
          },
        };
      },
      { blockLen: 4, outputLen: 4, outputBlockLen: 4 } as any
    );
    const batch = [Uint8Array.of(1), Uint8Array.of(2), Uint8Array.of(3)];
    const out = new Uint8Array(1 + batch.length * 4);
    const res = hash.parallel(batch, { out, outPos: 1 });
    eql(Array.from(out), [0, 11, 12, 13, 14, 21, 22, 23, 24, 31, 32, 33, 34]);
    eql(
      res.map((i) => Array.from(i)),
      lanes.map((i) => Array.from(i))
    );
  });
});

should.runWhen(import.meta.url);
