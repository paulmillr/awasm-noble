import { describe, should } from '@paulmillr/jsbt/test.js';
import { deepStrictEqual as eql, rejects, throws } from 'node:assert';
import { hmac } from '../src/hmac.ts';
import * as u from '../src/utils.ts';

const spoofDataView = () => new (class Uint8Array extends DataView {})(new ArrayBuffer(4));
const spoofU16 = () => new (class Uint8Array extends Uint16Array {})([0x0102, 0x0304]);

describe('utils', () => {
  const staticHexVectors = [
    { bytes: Uint8Array.from([]), hex: '' },
    { bytes: Uint8Array.from([0xbe]), hex: 'be' },
    { bytes: Uint8Array.from([0xca, 0xfe]), hex: 'cafe' },
    { bytes: Uint8Array.from(new Array(1024).fill(0x69)), hex: '69'.repeat(1024) },
  ];
  should('hexToBytes', () => {
    for (let v of staticHexVectors) eql(u.hexToBytes(v.hex), v.bytes);
    for (let v of staticHexVectors) eql(u.hexToBytes(v.hex.toUpperCase()), v.bytes);
    throws(() => u.hexToBytes(1 as any), TypeError);
    throws(() => u.hexToBytes('a'), RangeError);
    throws(() => u.hexToBytes('gg'), RangeError);
  });
  should('bytesToHex', () => {
    for (let v of staticHexVectors) eql(u.bytesToHex(v.bytes), v.hex);
    throws(() => u.bytesToHex(spoofDataView() as any), TypeError);
    throws(() => u.bytesToHex(spoofU16() as any), TypeError);
  });
  should('concatBytes', () => {
    const a = 1;
    const b = 2;
    const c = 0xff;
    const aa = Uint8Array.from([a]);
    const bb = Uint8Array.from([b]);
    const cc = Uint8Array.from([c]);
    eql(u.concatBytes(), Uint8Array.of());
    eql(u.concatBytes(aa, bb), Uint8Array.from([a, b]));
    eql(u.concatBytes(aa, bb, cc), Uint8Array.from([a, b, c]));
    throws(() => u.concatBytes(spoofDataView() as any), TypeError);
    throws(() => u.concatBytes(spoofU16() as any), TypeError);
  });
  should('overlapBytes', () => {
    // Basic
    const buffer = new ArrayBuffer(20);
    const a = new Uint8Array(buffer, 0, 10); // Bytes 0-9
    const b = new Uint8Array(buffer, 5, 10); // Bytes 5-14
    const c = new Uint8Array(buffer, 10, 10); // Bytes 10-19
    const d = new Uint8Array(new ArrayBuffer(20), 0, 10); // Different buffer
    eql(u.overlapBytes(a, b), true);
    eql(u.overlapBytes(a, c), false);
    eql(u.overlapBytes(b, c), true);
    eql(u.overlapBytes(a, d), false);
    // Scan
    const res = [];
    const main = new Uint8Array(8 + 4); // 2byte + first + 2byte
    const first = main.subarray(2).subarray(0, 8);
    for (let i = 0; i < main.length; i++) {
      const second = main.subarray(i).subarray(0, 1); // one byte window
      eql(second, new Uint8Array(1));
      res.push(u.overlapBytes(first, second));
    }
    eql(res, [false, false, true, true, true, true, true, true, true, true, false, false]);
    const main2 = new Uint8Array(buffer, 5, 10); // main
    const inside = new Uint8Array(buffer, 6, 4); // left overlap
    const leftOverlap = new Uint8Array(buffer, 0, 6); // left overlap
    const rightOverlap = new Uint8Array(buffer, 9, 10); // right overlap
    const before = new Uint8Array(buffer, 0, 5); // before
    const after = new Uint8Array(buffer, 15, 5); // after

    eql(u.overlapBytes(before, main2), false);
    eql(u.overlapBytes(after, main2), false);
    eql(u.overlapBytes(leftOverlap, rightOverlap), false);

    eql(u.overlapBytes(main2, leftOverlap), true);
    eql(u.overlapBytes(main2, rightOverlap), true);
    eql(u.overlapBytes(main2, inside), true);

    const emptyInside = new Uint8Array(buffer, 6, 0);
    eql(u.overlapBytes(main2, emptyInside), false);
    eql(u.overlapBytes(emptyInside, main2), false);
  });
  should('utf8ToBytes', () => {
    eql(u.utf8ToBytes('abc'), new Uint8Array([97, 98, 99]));
    throws(() => u.utf8ToBytes(1 as any), TypeError);
  });
  should('getOutput', () => {
    eql(u.getOutput(32), new Uint8Array(32));
    throws(() => u.getOutput(32, new Uint8Array(31)));
    throws(() => u.getOutput(32, new Uint8Array(33)));
    const t = new Uint8Array(33).subarray(1);
    throws(() => u.getOutput(32, t));
    eql(u.getOutput(32, t, false), new Uint8Array(32));
    if (typeof Buffer !== 'undefined') {
      const out = Buffer.alloc(32);
      eql(u.getOutput(32, out as any, false), out);
    }
    throws(() => u.getOutput(32, { length: 32, byteOffset: 0 } as any, false), TypeError);
  });
  should('u64Lengths', () => {
    eql(
      u.bytesToHex(u.u64Lengths(new Uint8Array(10).length, 0, true)),
      '00000000000000000a00000000000000'
    );
    eql(
      u.bytesToHex(u.u64Lengths(new Uint8Array(10).length, new Uint8Array(7).length, true)),
      '07000000000000000a00000000000000'
    );
    throws(() => u.u64Lengths('10' as any, 0, true), TypeError);
    throws(() => u.u64Lengths(10, '7' as any, true), TypeError);
    throws(() => u.u64Lengths(1.5, 0, true), RangeError);
  });
});

describe('assert', () => {
  should('abool', () => {
    eql(u.abool(true), undefined);
    throws(() => u.abool('1' as any), TypeError);
    throws(() => u.abool(1 as any), TypeError);
  });
  should('anumber', () => {
    eql(u.anumber(10), undefined);
    throws(() => u.anumber(1.2), RangeError);
    throws(() => u.anumber('1' as any), TypeError);
    throws(() => u.anumber(true as any), TypeError);
    throws(() => u.anumber(NaN), RangeError);
  });
  should('abytes', () => {
    eql(u.abytes(new Uint8Array(0)), new Uint8Array(0));
    if (typeof Buffer !== 'undefined') eql(u.abytes(Buffer.alloc(10)), Buffer.alloc(10));
    eql(u.abytes(new Uint8Array(10)), new Uint8Array(10));
    u.abytes(new Uint8Array(11), 11, '11');
    u.abytes(new Uint8Array(12), 12, '12');
    throws(() => u.abytes('test' as any), TypeError);
    throws(() => u.abytes(new Uint8Array(10), 11, '11'), RangeError);
    throws(() => u.abytes(new Uint8Array(10), 12, '12'), RangeError);
    throws(() => u.abytes(spoofDataView() as any), TypeError);
    throws(() => u.abytes(spoofU16() as any), TypeError);
  });
  should('aexists', () => {
    eql(u.aexists({}), undefined);
    throws(() => u.aexists({ destroyed: true }));
  });
  should('aoutput', () => {
    eql(u.aoutput(new Uint8Array(10), { outputLen: 5 }), undefined);
    throws(() => u.aoutput(new Uint8Array(1), { outputLen: 5 }), RangeError);
    throws(() => u.aoutput(spoofDataView(), { outputLen: 5 }), TypeError);
    throws(() => u.aoutput(spoofU16(), { outputLen: 5 }), TypeError);
  });
});

describe('utils etc', () => {
  should('checkOpts', () => {
    const defaults = { dkLen: 32, asyncTick: 10 };
    const merged = u.checkOpts(defaults, { dkLen: 64 });
    eql(merged, { dkLen: 64, asyncTick: 10 });
    eql(defaults, { dkLen: 64, asyncTick: 10 });
    eql(merged === defaults, true);
    eql(u.checkOpts({ dkLen: 32 }, undefined), { dkLen: 32 });
    const invalid = [[], null, 'x', 1, new Date(0)];
    for (const value of invalid) throws(() => u.checkOpts({ ok: 1 }, value as any), TypeError);
  });
  should('cleanFast', () => {
    throws(() => u.cleanFast(spoofU16() as any), TypeError);
  });
  should('copyBytes', () => {
    const out = u.copyBytes(Uint8Array.of(1, 2, 3));
    eql(out, Uint8Array.of(1, 2, 3));
    if (typeof Buffer !== 'undefined') {
      const src = Buffer.from([1, 2, 3]);
      const copy = u.copyBytes(src as any);
      eql(copy, Uint8Array.of(1, 2, 3));
      copy[0] = 9;
      eql(src, Buffer.from([1, 2, 3]));
    }
    throws(() => u.copyBytes('ab' as any), TypeError);
    throws(() => u.copyBytes([257, -1, 2.9] as any), TypeError);
    throws(() => u.copyBytes(new Uint16Array([0x0102, 0x0304]) as any), TypeError);
    throws(() => u.copyBytes(new DataView(new ArrayBuffer(4)) as any), TypeError);
  });
  should('randomBytes', () => {
    eql(u.randomBytes(0).length, 0);
    throws(() => u.randomBytes(1.5 as any), RangeError);
    throws(() => u.randomBytes('2' as any), TypeError);
    throws(() => u.randomBytes(true as any), TypeError);
  });
  should('isBytes', () => {
    eql(u.isBytes(new Uint8Array(0)), true);
    if (typeof Buffer !== 'undefined') eql(u.isBytes(Buffer.alloc(10)), true);
    eql(u.isBytes(''), false);
    eql(u.isBytes([1, 2, 3]), false);
    eql(u.isBytes(spoofDataView()), false);
    eql(u.isBytes(spoofU16()), false);
  });
  should('little-endian guard fails closed on big-endian platforms', () => {
    eql(u.isLE, true);
    throws(() => u.__TEST.assertLE(false), { message: 'big-endian platforms are unsupported' });
  });
  should('ahash', () => {
    throws(() => u.ahash({} as any));
    throws(() => u.ahash({ blockLen: 1, outputLen: 1, create: () => {} } as any));
    const hash = Object.assign((_msg: Uint8Array) => new Uint8Array(), {
      outputLen: 0,
      blockLen: 0,
      create() {
        return {
          outputLen: 0,
          blockLen: 0,
          update() {
            return this;
          },
          digestInto() {},
          digest() {
            return new Uint8Array();
          },
          destroy() {},
          _cloneInto() {
            return this;
          },
          clone() {
            return this;
          },
        };
      },
    });
    throws(() => u.ahash(hash as any));
    throws(() => hmac(hash as any, new Uint8Array([1]), new Uint8Array([2])));
  });
  should(
    'mkAsync async setup does not mutate setup options while applying asyncTick default',
    async () => {
      const opts = { total: 1, asyncTick: undefined };
      const run = u.mkAsync(function* (setup) {
        const tick = setup(opts);
        tick();
        return Uint8Array.from([1]);
      });
      eql(await run.async(), Uint8Array.from([1]));
      eql(opts, { total: 1, asyncTick: undefined });
    }
  );
  should('mkAsync async setup rejects non-function nextTick during setup validation', async () => {
    const run = u.mkAsync(function* (setup) {
      const tick = setup({ total: 1, nextTick: true as any });
      tick();
      return Uint8Array.from([1]);
    });
    await rejects(() => run.async(), { message: 'nextTick must be a function' });
  });
  should('mkAsync async runner awaits nextTick before resuming after yield', async () => {
    const order: string[] = [];
    const run = u.mkAsync(function* (setup) {
      eql(setup.isAsync, true);
      const tick = setup({
        total: 1,
        asyncTick: 0,
        nextTick: async () => {
          order.push('nextTick');
        },
      });
      order.push('before-yield');
      if (tick()) yield;
      order.push('after-yield');
      return Uint8Array.from([1]);
    });
    eql(await run.async(), Uint8Array.from([1]));
    eql(order, ['before-yield', 'nextTick', 'after-yield']);
  });
  should('mkAsync sync setup reports completed progress for zero total', () => {
    const progress: number[] = [];
    const run = u.mkAsync(function* (setup) {
      const tick = setup({
        total: 0,
        onProgress: (per) => {
          progress.push(per);
        },
      });
      tick(0);
      return Uint8Array.from([1]);
    });
    eql(run(), Uint8Array.from([1]));
    eql(progress, [1]);
  });
});

should.runWhen(import.meta.url);
