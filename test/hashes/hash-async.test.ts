import { describe, should } from '@paulmillr/jsbt/test.js';
import { deepStrictEqual as eql, rejects, strictEqual, throws } from 'node:assert';
import { PLATFORMS } from '../platforms.ts';

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

should.runWhen(import.meta.url);
