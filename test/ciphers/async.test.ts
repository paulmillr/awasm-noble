import { describe, should } from '@paulmillr/jsbt/test.js';
import { deepStrictEqual, rejects, strictEqual } from 'node:assert';
import { PLATFORMS } from '../platforms.ts';

const msg = Uint8Array.from({ length: 131072 }, (_, i) => i & 0xff);
const msgBig = Uint8Array.from({ length: 1024 * 1024 }, (_, i) => (i * 7) & 0xff);
const key128 = new Uint8Array(16).fill(7);
const key256 = new Uint8Array(32).fill(9);
const nonce16 = new Uint8Array(16).fill(11);
const nonce12 = new Uint8Array(12).fill(13);
const aad = new Uint8Array(33).fill(17);

for (const name in PLATFORMS) {
  const p = PLATFORMS[name];
  describe(`cipher async (${name})`, () => {
    should('borrowed inputs are revalidated before use', async () => {
      const data = new Uint8Array(16);
      for (const algorithm of ['ecb', 'cbc', 'ctr', 'chacha20']) {
        const factory = p[algorithm];
        const args = factory.nonceLength ? [new Uint8Array(factory.nonceLength)] : [];
        for (const detach of [false, true]) {
          for (const mode of ['encrypt', 'decrypt', 'stream', 'async']) {
            const length = algorithm === 'chacha20' ? 32 : 16;
            const buffer = new ArrayBuffer(length, { maxByteLength: length });
            const key = new Uint8Array(buffer);
            const cipher = factory(key, ...args);
            if (detach) structuredClone(buffer, { transfer: [buffer] });
            else buffer.resize(length - 1);
            await rejects(async () => {
              if (mode === 'stream') cipher.encrypt.create().destroy();
              else if (mode === 'async') await cipher.encrypt.async(data);
              else cipher[mode](data);
            }, /key/);
            deepStrictEqual(data, new Uint8Array(16));
          }
        }
      }
    });
    should('ciphers preserve output with overlapping input', () => {
      for (const algorithm of [
        'chacha8',
        'chacha12',
        'chacha20',
        'chacha20orig',
        'xchacha20',
        'salsa20',
        'xsalsa20',
        'cbc',
        'ctr',
        'ecb',
      ]) {
        const factory = p[algorithm];
        const block = factory.blockLen;
        const keys = ['cbc', 'ctr', 'ecb'].includes(algorithm) ? [16, 24, 32] : [32];
        const args = factory.nonceLength ? [new Uint8Array(factory.nonceLength)] : [];
        for (const size of keys) {
          const key = new Uint8Array(size);
          for (const len of [0, 1, block - 1, block, block + 1, 2 * block]) {
            const data = Uint8Array.from({ length: len }, (_, i) => i);
            const encrypted = factory(key, ...args).encrypt(data);
            for (const direction of ['encrypt', 'decrypt']) {
              const message = direction === 'encrypt' ? data : encrypted;
              const expected = direction === 'encrypt' ? encrypted : data;
              const length = Math.max(message.length, expected.length);
              for (const shift of [-length, -block + 1, -4, -1, 0, 1, 4, block - 1, length]) {
                const start = 4 + Math.max(0, -shift);
                const end = 4 + Math.max(0, shift);
                const buffer = new Uint8Array(8 + length + Math.abs(shift));
                const input = buffer.subarray(start, start + message.length);
                const output = buffer.subarray(end, end + length);
                for (const fill of [0, 0xa5]) {
                  buffer.fill(fill);
                  input.set(message);
                  const untouched = buffer.slice();
                  const result = factory(key, ...args)[direction](input, output);
                  strictEqual(result.buffer, buffer.buffer);
                  strictEqual(result.byteOffset, output.byteOffset);
                  deepStrictEqual(
                    [result, output.subarray(0, expected.length)],
                    [expected, expected]
                  );
                  // Padding may use the output suffix as scratch.
                  // Nothing outside output may change.
                  untouched.fill(0, end, end + length);
                  const actual = buffer.slice();
                  actual.fill(0, end, end + length);
                  deepStrictEqual(actual, untouched);
                }
              }
            }
          }
        }
      }
    });
    should('ctr sync/async parity', async () => {
      const sync = p.ctr(key256, nonce16).encrypt(msg);
      const asyncOut = await p.ctr(key256, nonce16).encrypt.async(msg, undefined, { asyncTick: 0 });
      deepStrictEqual(asyncOut, sync);
      const dec = await p.ctr(key256, nonce16).decrypt.async(sync, undefined, { asyncTick: 0 });
      deepStrictEqual(dec, msg);
    });

    should('ecb output parity', async () => {
      const sync = p.ecb(key128, { disablePadding: true }).encrypt(msg, new Uint8Array(msg.length));
      const out = new Uint8Array(msg.length);
      const asyncOut = await p.ecb(key128, { disablePadding: true }).encrypt.async(msg, out, {
        asyncTick: 0,
      });
      deepStrictEqual(asyncOut, sync);
      strictEqual(asyncOut.buffer, out.buffer);
      const dec = await p
        .ecb(key128, { disablePadding: true })
        .decrypt.async(sync, undefined, { asyncTick: 0 });
      deepStrictEqual(dec, msg);
    });

    should('gcm sync/async parity', async () => {
      const sync = p.gcm(key256, nonce12, aad).encrypt(msg);
      const asyncOut = await p.gcm(key256, nonce12, aad).encrypt.async(msg, undefined, {
        asyncTick: 0,
      });
      deepStrictEqual(asyncOut, sync);
      const dec = await p.gcm(key256, nonce12, aad).decrypt.async(sync, undefined, {
        asyncTick: 0,
      });
      deepStrictEqual(dec, msg);
    });

    should('encrypt async rejects on nonce reuse', async () => {
      const c = p.ctr(key256, nonce16);
      await c.encrypt.async(msg, undefined, { asyncTick: 0 });
      await rejects(() => c.encrypt.async(msg, undefined, { asyncTick: 0 }));
    });

    should('async nextTick is used on stream path', async () => {
      let ticks = 0;
      await p.ctr(key256, nonce16).encrypt.async(msg, undefined, {
        asyncTick: 0,
        nextTick: async () => {
          ticks++;
        },
      });
      if (ticks < 1) throw new Error('expected nextTick to be called');
    });
    should('async onProgress is called', async () => {
      let calls = 0;
      let last = 0;
      const out = await p.ctr(key256, nonce16).encrypt.async(msg, undefined, {
        asyncTick: 0,
        onProgress: (p) => {
          calls++;
          last = p;
        },
      });
      deepStrictEqual(out, p.ctr(key256, nonce16).encrypt(msg));
      if (calls < 1) throw new Error('expected onProgress to be called');
      strictEqual(last, 1);
    });

    should('ctr async survives interleaved module activity', async () => {
      const baseline = p.ctr(key256, nonce16).encrypt(msgBig);
      let ticks = 0;
      const out = await p.ctr(key256, nonce16).encrypt.async(msgBig, undefined, {
        asyncTick: 0,
        nextTick: async () => {
          ticks++;
          const k = new Uint8Array(32).fill(23 + (ticks & 15));
          const n = new Uint8Array(16).fill(31 + (ticks & 15));
          p.ctr(k, n).encrypt(msg.subarray(0, 4096));
        },
      });
      if (ticks < 1) throw new Error('expected interleave ticks');
      deepStrictEqual(out, baseline);
    });

    should('gcm async survives interleaved module activity', async () => {
      const baseline = p.gcm(key256, nonce12, aad).encrypt(msgBig);
      let ticks = 0;
      const out = await p.gcm(key256, nonce12, aad).encrypt.async(msgBig, undefined, {
        asyncTick: 0,
        nextTick: async () => {
          ticks++;
          const k = new Uint8Array(32).fill(41 + (ticks & 15));
          const n = new Uint8Array(12).fill(47 + (ticks & 15));
          p.gcm(k, n, aad).encrypt(msg.subarray(0, 2048));
        },
      });
      if (ticks < 1) throw new Error('expected interleave ticks');
      deepStrictEqual(out, baseline);
    });

    should('kwp async parity under async runner', async () => {
      const plain = msgBig;
      const baseline = p.aeskwp(key256).encrypt(plain);
      const out = await p.aeskwp(key256).encrypt.async(plain, undefined, {
        asyncTick: 0,
        nextTick: async () => {
          const k = new Uint8Array(32).fill(59);
          p.aeskwp(k).encrypt(msg.subarray(0, 777));
        },
      });
      deepStrictEqual(out, baseline);
    });
    should('kwp large input progress accounting (work buffer path)', async () => {
      // This exercises the `totalLen > BUFFER.length` path in ciphers.ts for AES-KWP.
      // Keep it robust to buffer size changes by reading module buffer length.
      const modName = name === 'stubs' ? 'wasm' : name;
      const mod = (await import(`../../src/targets/${modName}/aes_kwp.js`)).default();
      const plain = Uint8Array.from(
        { length: mod.segments.buffer.length },
        (_, i) => (i * 11) & 0xff
      );
      let calls = 0;
      let last = 0;
      const enc = await p.aeskwp(key256).encrypt.async(plain, undefined, {
        asyncTick: 0,
        onProgress: (p) => {
          calls++;
          last = p;
        },
      });
      if (calls < 1) throw new Error('expected onProgress to be called');
      strictEqual(last, 1);
      const dec = await p.aeskwp(key256).decrypt.async(enc, undefined, { asyncTick: 0 });
      deepStrictEqual(dec, plain);
    });
    should('gcm async invalid tag does not poison next run', async () => {
      const good = p.gcm(key256, nonce12, aad).encrypt(msg);
      const bad = good.slice();
      bad[bad.length - 1] ^= 1;
      await rejects(() =>
        p.gcm(key256, nonce12, aad).decrypt.async(bad, undefined, { asyncTick: 0 })
      );
      const out = await p
        .gcm(key256, nonce12, aad)
        .decrypt.async(good, undefined, { asyncTick: 0 });
      deepStrictEqual(out, msg);
    });
  });
}

should.runWhen(import.meta.url);
