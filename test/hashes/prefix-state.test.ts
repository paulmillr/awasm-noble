import { describe, should } from '@paulmillr/jsbt/test.js';
import { deepStrictEqual as eql, rejects, strictEqual, throws } from 'node:assert';
import * as noble from '../../src/noble.ts';
import * as webcrypto from '../../src/webcrypto.ts';
import type { HashInstance, HashState } from '../../src/hashes-abstract.ts';
import { concatBytes } from '../../src/utils.ts';
import { PLATFORMS } from '../platforms.ts';

const bytes = (len: number, seed = 1) =>
  Uint8Array.from({ length: len }, (_, i) => (i * 17 + seed) & 255);
const suffix = bytes(37, 91);
const batch = [bytes(37, 31), bytes(37, 32), bytes(37, 33)];
const splitSuffix = [
  [suffix],
  [suffix.subarray(0, 0), suffix],
  [suffix.subarray(0, 11), suffix.subarray(11, 11), suffix.subarray(11)],
  [suffix.subarray(0, suffix.length), suffix.subarray(suffix.length)],
];
const isHash = (hash: unknown): hash is HashInstance<any> =>
  typeof hash === 'function' &&
  typeof (hash as HashInstance<any>).parallel === 'function' &&
  typeof (hash as HashInstance<any>).create === 'function' &&
  typeof (hash as HashInstance<any>).cleanState === 'function';
const canExportPrefix = (hash: HashInstance<any>) => {
  try {
    const state = hash.create().exportState();
    hash.cleanState(state);
    return true;
  } catch {
    return false;
  }
};
const platforms = { ...PLATFORMS, noble } as Record<string, Record<string, HashInstance<any>>>;
const hashNames = Object.keys(platforms.js).filter((name) => {
  for (const platformName in platforms) {
    const hash = platforms[platformName][name];
    if (!isHash(hash) || !canExportPrefix(hash)) return false;
  }
  return true;
});
const opts = (hash: HashInstance<any>) => (hash.canXOF ? { dkLen: 37 } : {});
const outLen = (hash: HashInstance<any>) => opts(hash).dkLen || hash.outputLen;
const keyedCases = [
  {
    name: 'blake2s',
    opts: {
      dkLen: 17,
      key: bytes(17, 5),
      salt: bytes(8, 6),
      personalization: bytes(8, 7),
    },
  },
  {
    name: 'blake2b',
    opts: {
      dkLen: 31,
      key: bytes(31, 8),
      salt: bytes(16, 9),
      personalization: bytes(16, 10),
    },
  },
  { name: 'blake3', opts: { dkLen: 49, key: bytes(32, 11) } },
] as const;

describe('prefixState contract', () => {
  for (const platformName in platforms) {
    const platform = platforms[platformName];
    for (const name of hashNames) {
      should(`${platformName}: ${name} prefixes 1..2*block`, () => {
        const hash = platform[name];
        const o = opts(hash);
        for (let len = 0; len <= hash.blockLen * 2 + 1; len++) {
          const prefix = bytes(len, len);
          const state = hash.create().update(prefix).exportState();
          const exp = hash(concatBytes(prefix, suffix), o);
          for (const parts of splitSuffix)
            eql(hash.chunks(parts, { ...o, prefixState: state }), exp);
          eql(
            hash.parallel(batch, { ...o, prefixState: state }),
            batch.map((msg) => hash(concatBytes(prefix, msg), o))
          );
          hash.cleanState(state);
        }
      });
      should(`${platformName}: ${name} prefix honors output opts`, () => {
        const hash = platform[name];
        const o = opts(hash);
        const len = outLen(hash);
        const prefix = bytes(hash.blockLen + 1, 77);
        const state = hash.create().update(prefix).exportState();
        const exp = hash(concatBytes(prefix, suffix), o);
        const out = new Uint8Array(3 + len + 5);
        const res = hash.chunks([suffix.subarray(0, 17), suffix.subarray(17)], {
          ...o,
          out,
          outPos: 3,
          prefixState: state,
        });
        strictEqual(res.buffer, out.buffer);
        eql(out.subarray(3, 3 + len), exp);
        const expBatch = batch.map((msg) => hash(concatBytes(prefix, msg), o));
        const parOut = new Uint8Array(5 + len * batch.length + 7);
        const par = hash.parallel(batch, { ...o, out: parOut, outPos: 5, prefixState: state });
        for (let i = 0; i < batch.length; i++) {
          strictEqual(par[i].buffer, parOut.buffer);
          eql(par[i], expBatch[i]);
          eql(parOut.subarray(5 + i * len, 5 + (i + 1) * len), expBatch[i]);
        }
        const viewsBase = new Uint8Array(11 + batch.length * (len + 3));
        const views = batch.map((_, i) =>
          viewsBase.subarray(11 + i * (len + 3), 11 + i * (len + 3) + len)
        );
        const parViews = hash.parallel(batch, { ...o, out: views, prefixState: state });
        strictEqual(parViews, views);
        for (let i = 0; i < batch.length; i++) eql(views[i], expBatch[i]);
        hash.cleanState(state);
      });
      should(`${platformName}: ${name} prefix handles long chunk boundaries`, () => {
        const hash = platform[name];
        const o = opts(hash);
        const prefix = bytes(hash.blockLen - 1, 111);
        const parts = [
          bytes(1, 112),
          new Uint8Array(0),
          bytes(hash.blockLen * 3 + 7, 113),
          bytes(hash.blockLen * 5 + 3, 114),
        ];
        const state = hash.create().update(prefix).exportState();
        const exp = hash(concatBytes(prefix, ...parts), o);
        eql(hash.chunks(parts, { ...o, prefixState: state }), exp);
        hash.cleanState(state);
      });
      should(`${platformName}: ${name} prefix handles multi-group parallel output`, () => {
        const hash = platform[name];
        const o = opts(hash);
        const len = outLen(hash);
        const prefix = bytes(hash.blockLen + 3, 121);
        const bigBatch = Array.from({ length: 37 }, (_, i) =>
          bytes(hash.blockLen * 2 + 19, 122 + i)
        );
        const state = hash.create().update(prefix).exportState();
        const exp = bigBatch.map((msg) => hash(concatBytes(prefix, msg), o));
        const out = new Uint8Array(7 + len * bigBatch.length + 5);
        const got = hash.parallel(bigBatch, { ...o, out, outPos: 7, prefixState: state });
        for (let i = 0; i < bigBatch.length; i++) {
          strictEqual(got[i].buffer, out.buffer);
          eql(got[i], exp[i]);
          eql(out.subarray(7 + i * len, 7 + (i + 1) * len), exp[i]);
        }
        hash.cleanState(state);
      });
      should(`${platformName}: ${name} clone can export independent prefix state`, () => {
        const hash = platform[name];
        const o = opts(hash);
        const left = bytes(hash.blockLen + 5, 131);
        const originalRight = bytes(23, 132);
        const cloneRight = bytes(29, 133);
        const src = hash.create().update(left);
        const clone = src.clone();
        const state = clone.exportState();
        eql(src.update(originalRight).digest(o), hash(concatBytes(left, originalRight), o));
        eql(
          hash.chunks([cloneRight], { ...o, prefixState: state }),
          hash(concatBytes(left, cloneRight), o)
        );
        hash.cleanState(state);
      });
      should(`${platformName}: ${name} exported prefix state owns buffered bytes`, () => {
        const hash = platform[name];
        const o = opts(hash);
        const prefix = bytes(hash.blockLen - 3, 141);
        const expPrefix = new Uint8Array(prefix);
        const msg = bytes(41, 142);
        const state = hash.create().update(prefix).exportState();
        prefix.fill(0);
        eql(hash.chunks([msg], { ...o, prefixState: state }), hash(concatBytes(expPrefix, msg), o));
        hash.cleanState(state);
      });
    }
    should(`${platformName}: option-bearing hashes preserve options in prefix state`, () => {
      for (const c of keyedCases) {
        const hash = platform[c.name];
        const prefix = bytes(hash.blockLen + 5, c.name.length);
        const msg = bytes(hash.blockLen + 17, c.name.length + 33);
        const lanes = [bytes(43, 151), bytes(43, 152), bytes(43, 153), bytes(43, 154)];
        const state = hash.create(c.opts).update(prefix).exportState();
        eql(
          hash.chunks([msg], { ...c.opts, prefixState: state }),
          hash(concatBytes(prefix, msg), c.opts)
        );
        eql(
          hash.parallel(lanes, { ...c.opts, prefixState: state }),
          lanes.map((lane) => hash(concatBytes(prefix, lane), c.opts))
        );
        hash.cleanState(state);
      }
    });
    for (const name of hashNames) {
      should(`${platformName}: ${name} async chunks/parallel accept prefix`, async () => {
        const hash = platform[name];
        const o = opts(hash);
        const prefix = bytes(hash.blockLen + 7, 83);
        const state = hash.create().update(prefix).exportState();
        const exp = hash(concatBytes(prefix, suffix), o);
        eql(
          await hash.chunks.async([suffix.subarray(0, 5), suffix.subarray(5)], {
            ...o,
            asyncTick: 0,
            prefixState: state,
          }),
          exp
        );
        eql(
          await hash.parallel.async(batch, { ...o, asyncTick: 0, prefixState: state }),
          batch.map((msg) => hash(concatBytes(prefix, msg), o))
        );
        hash.cleanState(state);
      });
    }
    should(`${platformName}: cleanState destroys and invalidates state`, () => {
      const prefix = bytes(64, 5);
      const state = platform.sha256.create().update(prefix).exportState();
      eql(platform.sha256.parallel([suffix], { prefixState: state }), [
        platform.sha256(concatBytes(prefix, suffix)),
      ]);
      platform.sha256.cleanState(state);
      if (state instanceof Uint8Array) eql([...state.subarray(0, 8)], Array(8).fill(0));
      throws(() => platform.sha256.parallel([suffix], { prefixState: state }));
      throws(() => platform.sha512.parallel([suffix], { prefixState: state }));
      throws(() => platform.sha256.cleanState(state));
    });
    should(`${platformName}: invalid prefix ownership and empty messages throw`, () => {
      const hash = platform.sha256;
      const base = hash.create().exportState();
      throws(() => platform.sha512.parallel([suffix], { prefixState: base }));
      throws(() => platform.sha512.chunks([suffix], { prefixState: base }));
      throws(() => hash.parallel([], { prefixState: base }));
      throws(() => hash.parallel([new Uint8Array(0)], { prefixState: base }));
      throws(() => hash.chunks([], { prefixState: base }));
      throws(() => hash.chunks([new Uint8Array(0)], { prefixState: base }));
      hash.cleanState(base);
    });
    should(`${platformName}: rejected prefix calls do not consume state`, () => {
      const hash = platform.sha256;
      const prefix = bytes(hash.blockLen + 3, 101);
      const state = hash.create().update(prefix).exportState();
      const exp = hash(concatBytes(prefix, suffix));
      throws(() =>
        hash.chunks([suffix], { out: new Uint8Array(hash.outputLen - 1), prefixState: state })
      );
      eql(hash.parallel([suffix], { prefixState: state }), [exp]);
      throws(() =>
        hash.parallel([suffix], { out: new Uint8Array(hash.outputLen - 1), prefixState: state })
      );
      eql(hash.chunks([suffix], { prefixState: state }), exp);
      throws(() => hash.parallel([suffix], { out: [], prefixState: state }));
      throws(() =>
        hash.parallel([suffix], {
          out: [new Uint8Array(hash.outputLen - 1)],
          prefixState: state,
        })
      );
      eql(hash.parallel([suffix], { prefixState: state }), [exp]);
      hash.cleanState(state);
    });
    const probe = platform.sha256.create().exportState();
    const isByteState = probe instanceof Uint8Array;
    platform.sha256.cleanState(probe);
    if (isByteState) {
      should(`${platformName}: byte states flush full blocks and reject byte lookalikes`, () => {
        const hash = platform.sha256;
        const empty = hash.create().exportState();
        const partial = hash
          .create()
          .update(bytes(hash.blockLen - 1, 1))
          .exportState();
        const full = hash.create().update(bytes(hash.blockLen, 2)).exportState();
        if (!(empty instanceof Uint8Array)) throw new Error('expected byte state');
        if (!(partial instanceof Uint8Array)) throw new Error('expected byte state');
        if (!(full instanceof Uint8Array)) throw new Error('expected byte state');
        eql(partial.length, empty.length + hash.blockLen - 1);
        eql(full.length, empty.length);
        const state = hash.create().update(bytes(hash.blockLen, 3)).exportState();
        const copy = new Uint8Array(state as unknown as Uint8Array) as unknown as HashState;
        const len = (state as unknown as Uint8Array).length;
        throws(() => hash.parallel([suffix], { prefixState: copy }));
        throws(() => hash.cleanState(copy));
        throws(() =>
          hash.parallel([suffix], { prefixState: new Uint8Array(len - 1) as unknown as HashState })
        );
        throws(() =>
          hash.chunks([suffix], { prefixState: new Uint8Array(len - 1) as unknown as HashState })
        );
        throws(() =>
          hash.parallel([suffix], {
            prefixState: new Uint8Array(len + hash.blockLen) as unknown as HashState,
          })
        );
        throws(() =>
          hash.chunks([suffix], {
            prefixState: new Uint8Array(len + hash.blockLen) as unknown as HashState,
          })
        );
        hash.cleanState(state);
        throws(() => hash.parallel([suffix], { prefixState: state }));
        hash.cleanState(empty);
        hash.cleanState(partial);
        hash.cleanState(full);
      });
    }
  }

  should('byte states reject same hash from another byte platform', () => {
    const state = PLATFORMS.js.sha256.create().update(bytes(13, 55)).exportState();
    throws(() => PLATFORMS.wasm.sha256.parallel([suffix], { prefixState: state }));
    throws(() => PLATFORMS.wasm.sha256.chunks([suffix], { prefixState: state }));
    PLATFORMS.js.sha256.cleanState(state);
  });

  should('webcrypto: prefixState is rejected by async chunks and parallel', async () => {
    const state = new Uint8Array(1) as unknown as HashState;
    await rejects(() => webcrypto.sha256.chunks.async([suffix], { prefixState: state }));
    await rejects(() => webcrypto.sha256.parallel.async([suffix], { prefixState: state }));
    throws(() => webcrypto.sha256.cleanState(state));
  });

  should('webcrypto: parallel writes into output view arrays', async () => {
    const len = 17;
    const exp = await Promise.all(batch.map((msg) => webcrypto.sha256.async(msg, { dkLen: len })));
    const viewsBase = new Uint8Array(7 + batch.length * (len + 5));
    const views = batch.map((_, i) =>
      viewsBase.subarray(7 + i * (len + 5), 7 + i * (len + 5) + len)
    );
    const got = await webcrypto.sha256.parallel.async(batch, { dkLen: len, out: views });
    strictEqual(got, views);
    for (let i = 0; i < batch.length; i++) eql(views[i], exp[i]);
  });
});

should.runWhen(import.meta.url);
