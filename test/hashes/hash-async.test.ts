import { describe, should } from '@paulmillr/jsbt/test.js';
import { deepStrictEqual as eql, rejects, strictEqual, throws } from 'node:assert';
import { PLATFORMS } from '../platforms.ts';
import * as webcrypto from '../../src/webcrypto.ts';
import * as wasm from '../../src/targets/wasm/index.ts';
import { mkHash, type HashState } from '../../src/hashes-abstract.ts';
import { pbkdf2 } from '../../src/kdf.ts';
import { concatBytes } from '../../src/utils.ts';

const msg = Uint8Array.from({ length: 1024 * 1024 }, (_, i) => (i * 13) & 0xff);
const parts = [msg.subarray(0, 300_000), msg.subarray(300_000, 700_000), msg.subarray(700_000)];
const batch = Array.from({ length: 4 }, (_, i) =>
  Uint8Array.from({ length: 256 * 1024 }, (_, j) => (j + i * 17) & 0xff)
);
const smallBatch = Array.from({ length: 3 }, (_, i) =>
  Uint8Array.from({ length: 41 }, (_, j) => (j * 9 + i * 23) & 0xff)
);

for (const name in PLATFORMS) {
  const p = PLATFORMS[name];
  describe(`hash async (${name})`, () => {
    should.serial('digest lengths ignore inherited options', async () => {
      const input = Uint8Array.of(1, 2, 3);
      for (const hash of [p.sha256, p.blake2s, p.blake3, p.shake128, p.shake256]) {
        const expected = hash(input);
        const short = hash(input, { dkLen: 3 });
        const previous = Object.getOwnPropertyDescriptor(Object.prototype, 'dkLen');
        Object.defineProperty(Object.prototype, 'dkLen', {
          configurable: true,
          enumerable: true,
          writable: true,
          value: 0,
        });
        try {
          eql(
            [
              hash(input, {}),
              hash(input, { dkLen: undefined }),
              await hash.async(input),
              hash.chunks([input]),
              hash.parallel([input, input]),
              hash.create().update(input).digest(),
              hash(input, { dkLen: 3 }),
            ],
            [expected, expected, expected, expected, [expected, expected], expected, short]
          );
        } finally {
          if (previous) Object.defineProperty(Object.prototype, 'dkLen', previous);
          else delete (Object.prototype as { dkLen?: number }).dkLen;
        }
      }
    });
    should('multipart finalizes empty input across hash families', async () => {
      const empty = new Uint8Array();
      for (const hash of [
        p.md5,
        p.ripemd160,
        p.sha1,
        p.sha224,
        p.sha256,
        p.sha384,
        p.sha512,
        p.blake2s,
        p.blake2b,
        p.blake3,
        p.keccak_256,
        p.sha3_256,
        p.shake128,
      ]) {
        for (const size of [0, 1, hash.blockLen - 1, hash.blockLen, hash.blockLen + 1]) {
          const input = Uint8Array.from({ length: size }, (_, i) => i % 251);
          const expected = hash(input);
          const parts = [empty, input.subarray(0, 1), empty, input.subarray(1), empty];
          eql(
            [hash.chunks(parts), await hash.chunks.async(parts, { asyncTick: 0 })],
            [expected, expected]
          );
          if (!size) eql(hash.chunks([]), expected);
        }
      }
    });
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

    should('progress callback rejects async hash entry without scheduler options', async () => {
      const message = 'onProgress callback must not start another operation before it returns';
      let nested: Promise<string>[] | undefined;
      await p.sha256.async(smallBatch[0], {
        onProgress: () => {
          if (nested) return;
          nested = [
            p.sha512.async(smallBatch[0]),
            p.sha512.chunks.async([smallBatch[0]], { dkLen: 16 }),
            p.sha512.parallel.async(smallBatch, { dkLen: 16 }),
          ].map(async (call) => {
            try {
              await call;
              return 'resolved';
            } catch (error) {
              return error instanceof Error ? error.message : String(error);
            }
          });
        },
      });
      eql(await Promise.all(nested!), [message, message, message]);
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
    should('parallel accepts exported prefixState', async () => {
      const prefix = Uint8Array.from({ length: p.sha256.blockLen }, (_, i) => (i * 5 + 7) & 255);
      const state = p.sha256.create().update(prefix).exportState();
      const exp = smallBatch.map((i) => p.sha256(concatBytes(prefix, i)));
      eql(p.sha256.parallel(smallBatch, { prefixState: state }), exp);
      eql(await p.sha256.parallel.async(smallBatch, { asyncTick: 0, prefixState: state }), exp);
      p.sha256.cleanState(state);

      const xofPrefix = Uint8Array.from({ length: 19 }, (_, i) => (i * 3 + 1) & 255);
      const xofState = p.shake256.create().update(xofPrefix).exportState();
      eql(
        p.shake256.parallel(smallBatch, { dkLen: 24, prefixState: xofState }),
        smallBatch.map((i) => p.shake256(concatBytes(xofPrefix, i), { dkLen: 24 }))
      );
      p.shake256.cleanState(xofState);
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

  should('parallel rejects prefixState', async () => {
    await rejects(() =>
      webcrypto.sha256.parallel.async(smallBatch, {
        prefixState: new Uint8Array(1) as unknown as HashState,
      })
    );
  });
});

describe('hash parallel local', () => {
  const setup = (slots: number, capacity: number, outputLen: number) => {
    const buffer = new Uint8Array(capacity);
    const state = new Uint8Array(slots);
    const states = Array.from({ length: slots }, (_, i) => state.subarray(i, i + 1));
    const groups: number[] = [];
    const hash = mkHash(
      () => ({
        segments: { buffer, state, state_chunks: states, 'state.state_chunks': states },
        reset() {
          buffer.fill(0);
          state.fill(0);
        },
        padding() {
          return 0;
        },
        processBlocks(
          pos: number,
          count: number,
          blocks: number,
          max: number,
          block: number,
          _last: number,
          left: number
        ) {
          for (let lane = pos; lane < pos + count; lane++) {
            const start = lane * max * block;
            for (const byte of buffer.subarray(start, start + blocks * block - left))
              state[lane] += byte;
            buffer.fill(0, start, start + blocks * block);
          }
        },
        processOutBlocks(pos: number, count: number, blocks: number, max: number, block: number) {
          groups.push(count);
          for (let lane = pos; lane < pos + count; lane++)
            buffer.fill(state[lane], lane * max * block, lane * max * block + blocks * block);
        },
      }),
      { blockLen: 4, outputLen }
    );
    return { hash, buffer, state, groups };
  };
  for (const [slots, capacity, outputLen, limit] of [
    [2, 96, 4, 2], // State limited.
    [4, 24, 4, 2], // Input limited, including padding.
    [4, 32, 16, 2], // Output limited.
    [2, 24, 12, 2], // All limits equal.
    [4, 48, 4, 4], // Input and state limits equal.
  ]) {
    should(
      `mkHash.parallel capacity ${slots}/${capacity}/${outputLen} processes every message`,
      () => {
        const { hash, buffer, state, groups } = setup(slots, capacity, outputLen);
        for (const count of [0, 1, 2, 3, 4, 5, 7, 8, 9]) {
          for (const len of [0, 1, 4, 5, 17]) {
            const input = Array.from({ length: count }, (_, lane) =>
              Uint8Array.from({ length: len }, (_, i) => (lane * 19 + i * 13 + 1) % 251)
            );
            const before = input.map((msg) => msg.slice());
            const expected = input.map((msg) =>
              new Uint8Array(outputLen).fill(msg.reduce((sum, byte) => sum + byte, 0) & 255)
            );
            groups.length = 0;
            const output = hash.parallel(input);
            eql(
              { output, input, buffer, state, groups },
              {
                output: expected,
                input: before,
                buffer: new Uint8Array(capacity),
                state: new Uint8Array(slots),
                groups: Array.from({ length: Math.ceil(count / limit) }, (_, i) =>
                  Math.min(limit, count - i * limit)
                ),
              }
            );
          }
        }
      }
    );
    should(
      `mkHash.parallel capacity ${slots}/${capacity}/${outputLen} validates every message`,
      () => {
        const { hash, buffer, state, groups } = setup(slots, capacity, outputLen);
        hash.parallel([]);
        buffer.fill(165);
        state.fill(165);
        const before = { buffer: buffer.slice(), state: state.slice(), groups: [] };
        for (let i = 0; i < 9; i++) {
          const input = Array.from({ length: 9 }, () => Uint8Array.of(1));
          input[i] = undefined as any;
          throws(() => hash.parallel(input), /expected Uint8Array/);
          eql({ buffer, state, groups }, before);
        }
      }
    );
  }
  should('mkHash.parallel capacity must fit at least one state, input and output', () => {
    for (const [slots, capacity, outputLen] of [
      [0, 24, 4],
      [4, 8, 4],
      [4, 24, 32],
    ]) {
      const { hash } = setup(slots, capacity, outputLen);
      throws(() => hash.parallel([]), /wrong chunks/);
    }
  });
  should('mkHash.parallel copies initialized state and preloaded input once', () => {
    for (const blocks of [0, 1]) {
      const buffer = new Uint8Array(64);
      const state = new Uint8Array(8);
      const states = [state.subarray(0, 4), state.subarray(4)];
      const calls: number[] = [];
      const seen: number[][] = [[], []];
      const hash = mkHash(
        () => ({
          segments: { buffer, state, state_chunks: states, 'state.state_chunks': states },
          reset() {
            buffer.fill(0);
            state.fill(0);
          },
          padding() {
            return 0;
          },
          processBlocks(pos: number, count: number, blocks: number, max: number, block: number) {
            for (let lane = pos; lane < pos + count; lane++) {
              const start = lane * max * block;
              seen[lane].push(...buffer.subarray(start, start + blocks * block));
              buffer.fill(0, start, start + blocks * block);
            }
          },
          processOutBlocks(
            pos: number,
            count: number,
            _blocks: number,
            max: number,
            block: number
          ) {
            for (let lane = pos; lane < pos + count; lane++)
              buffer.set(states[lane], lane * max * block);
          },
        }),
        {
          blockLen: 4,
          outputLen: 4,
          init(pos, max, mod) {
            calls.push(pos);
            // Models initialization that uses nested hashing in slot zero.
            mod.segments.state.fill(0);
            states[pos].set([11, 12, 13, 14]);
            if (blocks) buffer.set([21, 22, 23, 24], pos * max * 4);
            return { blocks };
          },
        }
      );
      const input = [Uint8Array.of(1, 2, 3, 4), Uint8Array.of(5, 6, 7, 8)];
      const output = hash.parallel(input);
      eql(
        { output, seen, calls, buffer, state },
        {
          output: [Uint8Array.of(11, 12, 13, 14), Uint8Array.of(11, 12, 13, 14)],
          seen: input.map((msg) => [...(blocks ? [21, 22, 23, 24] : []), ...msg]),
          calls: [0],
          buffer: new Uint8Array(64),
          state: new Uint8Array(8),
        }
      );
    }
  });
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
