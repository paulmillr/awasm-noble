/**
 * Core MAC logic for Ghash, Polyval, Poly1305.
 * The file is not used in end-user code. Instead, it's used by awasm-compiler
 * to generate different build targets (wasm, wasm_threads, js, runtime).
 * @module
 */
import type {
  ArraySpec,
  FnRegistry,
  GetOps,
  MemorySurface,
  ScalarSpec,
  Scope,
  Segs,
  StructSpec,
  Val,
} from '@awasm/compiler/module.js';
import { array, Module, struct } from '@awasm/compiler/module.js';
import type { TypeName } from '@awasm/compiler/types.js';
import { CHUNKS, getLanes, MIN_PER_THREAD, readMSG } from './utils.ts';

const _0x00ff00ff00ff00ffn = /* @__PURE__ */ BigInt('0x00ff00ff00ff00ff');
const _0x0000ffff0000ffffn = /* @__PURE__ */ BigInt('0x0000ffff0000ffff');

// CMAC is a "mac-like" module, but implemented alongside AES primitives.
// export { genCmac } from './ciphers.ts';

// 8-bit GHASH table windows: each NIST SP 800-38D 128-bit block becomes 16 table lookups.
export const GHASH_U64X2_W = 8;
export const GHASH_U64X2_TABLE_ENTRIES = /* @__PURE__ */ (() =>
  (1 << GHASH_U64X2_W) * (128 / GHASH_U64X2_W))();
export type U32x4Row = ArraySpec<ScalarSpec<'u32', unknown>, readonly [4]>;
export type U32x4RowMem = MemorySurface<{ buf: U32x4Row }>['buf'];
export type U64x2ScalarMem = MemorySurface<{ buf: ScalarSpec<'u64x2', unknown> }>['buf'];
export type U64x2VecTable = ArraySpec<ScalarSpec<'u64x2', unknown>, readonly [number]>;
export type U64x2VecTableMem = MemorySurface<{ buf: U64x2VecTable }>['buf'];

export const ghashState = () =>
  struct({ y: array('u32', {}, 4), y64: 'u64x2', h: array('u32', {}, 4) });
export const bswap64 = (u64: GetOps<'u64'>, u32: GetOps<'u32'>, x: Val<'u64'>) => {
  const c8 = u32.castTo('i32', u32.const(8));
  const c16 = u32.castTo('i32', u32.const(16));
  const c32 = u32.castTo('i32', u32.const(32));
  const m1 = u64.const(_0x00ff00ff00ff00ffn);
  const m2 = u64.const(_0x0000ffff0000ffffn);
  const v1 = u64.or(u64.shl(u64.and(x, m1), c8), u64.and(u64.shr(x, c8), m1));
  const v2 = u64.or(u64.shl(u64.and(v1, m2), c16), u64.and(u64.shr(v1, c16), m2));
  return u64.or(u64.shl(v2, c32), u64.shr(v2, c32));
};
export const ghashInitTableCore64v = <M extends Segs, F extends FnRegistry>(
  f: Scope<M, F>,
  h: U32x4RowMem,
  table: U64x2VecTableMem,
  tmp: U64x2VecTableMem,
  mode: 'ghash' | 'polyval'
) => {
  const { u32, u64, u64x2, i32 } = f.types;
  // GHASH reduction constant, aligned to the top byte for the right-shift step.
  const cPoly = u64.shl(u64.const(0b1110_0001), i32.const(56));
  // NIST SP 800-38D §6.3:
  // advance V with a 128-bit right shift and xor R when the dropped low bit is 1.
  const mul2 = (k0: Val<'u64'>, k1: Val<'u64'>) => {
    const hi = u64.and(k1, u64.const(1));
    const nk1 = u64.or(u64.shl(k0, i32.const(63)), u64.shr(k1, i32.const(1)));
    const mask = u64.sub(u64.const(0), hi);
    const nk0 = u64.xor(u64.shr(k0, i32.const(1)), u64.and(cPoly, mask));
    return [nk0, nk1];
  };
  const [h0, h1, h2, h3] = h.get();
  const k0 = u64.fromN('u32', [h0, h1]);
  const k1 = u64.fromN('u32', [h2, h3]);
  const kb0 = bswap64(u64, u32, k0);
  const kb1 = bswap64(u64, u32, k1);
  const mkVec = (a: Val<'u64'>, b: Val<'u64'>) => u64x2.replaceLane(u64x2.splat(a), 1, b);
  f.doN([kb0, kb1], u32.const(128 / GHASH_U64X2_W), (w, k0v, k1v) => {
    const next = f.doN([k0v, k1v], u32.const(GHASH_U64X2_W), (j, d0, d1) => {
      tmp[j].set(mkVec(bswap64(u64, u32, d0), bswap64(u64, u32, d1)));
      return mul2(d0, d1);
    });
    f.doN([], u32.const(1 << GHASH_U64X2_W), (byte) => {
      const entry = table[u32.add(u32.mul(w, u32.const(1 << GHASH_U64X2_W)), byte)];
      const [o] = f.doN([u64x2.const(0)], u32.const(GHASH_U64X2_W), (j, o) => {
        const shift = i32.sub(i32.const(GHASH_U64X2_W - 1), u32.castTo('i32', j));
        const bit = u32.and(u32.shr(byte, shift), u32.const(1));
        const mask = u64.sub(u64.const(0), u64.fromN('u32', bit));
        return [u64x2.xor(o, u64x2.and(tmp[j].get(), u64x2.splat(mask)))];
      });
      if (mode === 'polyval') {
        // RFC 8452 Appendix A: POLYVAL reuses GHASH via ByteReverse.
        // Reverse table entries back to POLYVAL order here.
        const a0 = u64x2.extractLane(o, 0);
        const a1 = u64x2.extractLane(o, 1);
        return (entry.set(mkVec(bswap64(u64, u32, a1), bswap64(u64, u32, a0))), []);
      }
      return (entry.set(o), []);
    });
    return next;
  });
};
export const ghashBlocksTableCore64v = <M extends Segs, F extends FnRegistry>(
  f: Scope<M, F>,
  blocks: Val<'u32'>,
  buffer: U64x2VecTableMem,
  y: U64x2ScalarMem,
  table: U64x2VecTableMem,
  mode: 'ghash' | 'polyval',
  clear = false
) => {
  const { u32, u64, u64x2, i32 } = f.types;
  const mask = u32.const((1 << GHASH_U64X2_W) - 1);
  const mulTable = (x: Val<'u64x2'>, reverse: boolean) => {
    let o = u64x2.const(0);
    const x0 = u64x2.extractLane(x, 0);
    const x1 = u64x2.extractLane(x, 1);
    // RFC 8452 Appendix A: POLYVAL multiplies ByteReverse(X_i).
    // Reverse lanes and bytes within each lane here.
    const xs = reverse ? [x1, x0] : [x0, x1];
    let w = u32.const(0);
    for (let wi = 0; wi < xs.length; wi++) {
      const from = reverse ? 7 : 0;
      const to = reverse ? -1 : 8;
      const step = reverse ? -1 : 1;
      for (let bytePos = from; bytePos !== to; bytePos += step) {
        const byteU64 = u64.and(u64.shr(xs[wi], i32.const(bytePos * 8)), u64.const(0xff));
        const byte = u32.fromN('u64', byteU64);
        for (let bitPos = 8 / GHASH_U64X2_W - 1; bitPos >= 0; bitPos--) {
          const bit = u32.and(u32.shr(byte, i32.const(GHASH_U64X2_W * bitPos)), mask);
          o = u64x2.xor(o, table[u32.add(u32.mul(w, u32.const(1 << GHASH_U64X2_W)), bit)].get());
          w = u32.add(w, u32.const(1));
        }
      }
    }
    return o;
  };
  // NIST SP 800-38D §6.4 / RFC 8452 §3:
  // fold each block by xoring it into the accumulator before the field multiply.
  const yv = f.doN([y.get()], blocks, (chunkPos, s0) => [
    mulTable(u64x2.xor(s0, readMSG(f, buffer[chunkPos], clear)), mode === 'polyval'),
  ]);
  y.set(yv[0]);
};
const resetBatch = <M extends GhashBatchSegs | PolyBatchSegs, F extends FnRegistry>(
  f: Scope<M, F>,
  pos: Val<'u32'>,
  len: Val<'u32'>,
  written: Val<'u32'>,
  blockLen: Val<'u32'>,
  max: Val<'u32'>
) => {
  const { u32 } = f.types;
  const perBlock = u32.div(blockLen, u32.const(4));
  // Reset clears key material and tables; hash init writes the caller key before each new run.
  f.memory.state.range(pos, len).as8().zero();
  const buffer = f.memory.buffer.reshape(pos, max, perBlock);
  f.doN(
    [],
    len,
    (cnt: Val<'u32'>) => (buffer[u32.add(pos, cnt)].as8().range(0, written).fill(0), [])
  );
};
const ghashBatchState = /* @__PURE__ */ struct({
  // Generic hash-state slot; GHASH/POLYVAL use ghash.y64 as the live accumulator.
  state: /* @__PURE__ */ array('u32', {}, 4),
  ghash: /* @__PURE__ */ ghashState(),
  table64v: /* @__PURE__ */ array('u64x2', {}, GHASH_U64X2_TABLE_ENTRIES),
  tmp64v: /* @__PURE__ */ array('u64x2', {}, GHASH_U64X2_W),
});
const ghashMod = (name: string) =>
  new Module(name)
    .batchMem('state', ghashBatchState)
    .mem('buffer', array('u32', {}, CHUNKS, 4))
    .fn('reset', ['u32', 'u32', 'u32', 'u32', 'u32'], 'void', resetBatch)
    .fn(
      'padding',
      ['u32', 'u32', 'u32', 'u32', 'u32', 'u32'],
      'u32',
      (f, batchPos, take, maxBlocks, left, blockLen) => {
        const { u32 } = f.types;
        const perBlock = u32.div(blockLen, u32.const(4));
        const buffer = f.memory.buffer.reshape(batchPos, maxBlocks, perBlock)[batchPos].as8();
        // Raw GHASH/POLYVAL zero-pad the final partial block.
        f.ifElse(u32.ne(left, u32.const(0)), [], () =>
          f.doN([], left, (i) => (buffer[u32.add(take, i)].set(u32.const(0)), []))
        );
        // Empty input reports a dummy pad block so the block processor absorbs nothing.
        return u32.select(u32.eq(take, u32.const(0)), u32.const(1), u32.const(0));
      }
    );
const ghashOutBlocks = <M extends GhashBatchSegs, F extends FnRegistry>(
  f: Scope<M, F>,
  lanes: number,
  pos: Val<'u32'>,
  b: Val<'u32'>,
  max: Val<'u32'>
) => {
  const { u32 } = f.types;
  f.doN([], u32.const(lanes), (i: Val<'u32'>) => {
    const p = u32.add(pos, i);
    const buffer = f.memory.buffer.reshape(p, max, 4)[p].as('u64x2').reshape(max);
    // ghash.y64 already holds GHASH Y_m or POLYVAL S_s in output byte order.
    const out = f.memory.state[p].ghash.y64.get();
    // Fixed-output wrapper exposes at most one block; loop keeps the generic output interface.
    return (f.doN([], b, (chunkPos: Val<'u32'>) => (buffer[chunkPos].set(out), [])), []);
  });
};
const ghashProcessBlocks = <M extends GhashBatchSegs, F extends FnRegistry>(
  f: Scope<M, F>,
  lanes: number,
  pos: Val<'u32'>,
  b: Val<'u32'>,
  max: Val<'u32'>,
  pad: Val<'u32'>,
  mode: 'ghash' | 'polyval'
) => {
  const { u32 } = f.types;
  // Raw GHASH/POLYVAL uses pad=1 only for an empty final tail; skip that dummy block.
  const run = u32.sub(b, pad);
  f.doN([], u32.const(lanes), (i: Val<'u32'>) => {
    const p = u32.add(pos, i);
    const buffer = f.memory.buffer.reshape(p, max, 4)[p].as('u64x2').reshape(max);
    const table = f.memory.state[p].table64v.reshape(GHASH_U64X2_TABLE_ENTRIES);
    ghashBlocksTableCore64v(f, run, buffer, f.memory.state[p].ghash.y64, table, mode, true);
    return [];
  });
};
const ghashInitBatch = <M extends GhashBatchSegs, F extends FnRegistry>(
  f: Scope<M, F>,
  pos: Val<'u32'>,
  mode: 'ghash' | 'polyval'
) => {
  const { u32, u64x2 } = f.types;
  // NIST SP 800-38D §6.4 / RFC 8452 §3: reset the accumulator before table init.
  f.memory.state[pos].ghash.y.set([u32.const(0), u32.const(0), u32.const(0), u32.const(0)]);
  f.memory.state[pos].ghash.y64.set(u64x2.const(0));
  f.memory.state[pos].state.set([u32.const(0), u32.const(0), u32.const(0), u32.const(0)]);
  const table = f.memory.state[pos].table64v.reshape(GHASH_U64X2_TABLE_ENTRIES);
  const tmp = f.memory.state[pos].tmp64v.reshape(GHASH_U64X2_W);
  ghashInitTableCore64v(f, f.memory.state[pos].ghash.h, table, tmp, mode);
};
export const genGhash = (type: TypeName, _opts: {}) =>
  ghashMod('ghash')
    .fn('macInit', ['u32'], 'void', (f, batchPos) => ghashInitBatch(f, batchPos, 'ghash'))
    .batchFn(
      'processBlocks',
      { lanes: getLanes(type), perThread: MIN_PER_THREAD },
      ['u32', 'u32', 'u32', 'u32', 'u32'],
      (f, l, p, b, m, _bl, _il, _lf, pad) => ghashProcessBlocks(f, l, p, b, m, pad, 'ghash')
    )
    .batchFn(
      'processOutBlocks',
      { lanes: getLanes(type), perThread: MIN_PER_THREAD },
      ['u32', 'u32', 'u32'],
      ghashOutBlocks
    );
export const genPolyval = (type: TypeName, { reverse: _reverse }: { reverse: true }) =>
  ghashMod('polyval')
    .fn('macInit', ['u32'], 'void', (f, batchPos) => {
      const { u32 } = f.types;
      // RFC 8452 Appendix A: convert POLYVAL H to mulX_GHASH(ByteReverse(H)) in module-owned state.
      const k = f.memory.state[batchPos].ghash.h.as8();
      f.doN([], u32.const(8), (i) => {
        const j = u32.sub(u32.const(15), i);
        const a = k[u32.add(u32.const(0), i)].get();
        const b = k[u32.add(u32.const(0), j)].get();
        return (k[u32.add(u32.const(0), i)].set(b), k[u32.add(u32.const(0), j)].set(a), []);
      });
      const mask = u32.sub(u32.const(0), u32.and(k[15].get(), u32.const(1)));
      f.doN1([u32.const(0)], u32.const(16), (i, carry) => {
        const t = k[i].get();
        k[i].set(u32.and(u32.or(u32.shr(t, 1), carry), u32.const(0xff)));
        return [u32.shl(u32.and(t, u32.const(1)), 7)];
      });
      k[0].set(u32.xor(k[0].get(), u32.and(mask, u32.const(0b1110_0001))));
      ghashInitBatch(f, batchPos, 'polyval');
    })
    .batchFn(
      'processBlocks',
      { lanes: getLanes(type), perThread: MIN_PER_THREAD },
      ['u32', 'u32', 'u32', 'u32', 'u32'],
      (f, l, p, b, m, _bl, _il, _lf, pad) => ghashProcessBlocks(f, l, p, b, m, pad, 'polyval')
    )
    .batchFn(
      'processOutBlocks',
      { lanes: getLanes(type), perThread: MIN_PER_THREAD },
      ['u32', 'u32', 'u32'],
      ghashOutBlocks
    );
type U64View = ArrayLike<{ get: () => Val<'u64'>; set: (v: Val<'u64'>) => void }> & {
  as: (type: 'u32') => ArrayLike<{ get: () => Val<'u32'>; set: (v: Val<'u32'>) => void }>;
};
type U32Arr = ArrayLike<Val<'u32'>>;
// RFC 8439 §2.5: Poly1305 is modulo 2^130-5; split 130 bits into 5x26 or 10x13 limbs.
const WIDE_LIMB_COUNT = 5;
type LimbSpec = { bits: number; mask: number; count: number; hibit: number };
const makeSpec = (bits: number, count: number) => {
  const base = 1 << bits;
  // RFC 8439 §2.5: full 16-byte blocks append 2^128, stored as a top-limb bit offset.
  return { bits, mask: base - 1, count, hibit: 128 % bits };
};
const parseWithSpec = (u32: GetOps<'u32'>, W: Val<'u32'>[], hibit: Val<'u32'>, spec: LimbSpec) => {
  const mask = u32.const(spec.mask);
  const parts = new Array<Val<'u32', unknown>>(spec.count);
  // RFC 8439 §2.5.1 uses little-endian numbers; slice the 128-bit words into local limbs.
  for (let i = 0; i < spec.count; i++) {
    const bit = i * spec.bits;
    const lo = Math.floor(bit / 32);
    const shift = bit - lo * 32;
    let v = u32.shr(W[lo], shift);
    if (shift && lo + 1 < W.length) v = u32.or(v, u32.shl(W[lo + 1], 32 - shift));
    if (i === spec.count - 1) v = u32.or(v, hibit);
    parts[i] = u32.and(v, mask);
  }
  return parts;
};
const WIDE_LIMB_SPEC = /* @__PURE__ */ (() =>
  makeSpec((128 + 2) / WIDE_LIMB_COUNT, WIDE_LIMB_COUNT))();
const LIMB_SPEC = /* @__PURE__ */ (() =>
  makeSpec((128 + 2) / (WIDE_LIMB_COUNT * 2), WIDE_LIMB_COUNT * 2))();
const getSpec = (useWide: boolean) => (useWide ? WIDE_LIMB_SPEC : LIMB_SPEC);
type MulOps<T> = {
  add: (a: T, b: T) => T;
  mul: (a: T, b: T) => T;
  shr: (a: T, bits: number) => T;
  and: (a: T, b: T) => T;
  const: (n: number) => T;
  toU32: (a: T) => Val<'u32'>;
  fromU32: (a: Val<'u32'>) => T;
};
// RFC 8439 §2.5 multiply/reduce loop is shared across u32/u64 limb backends.
const makeMulOps = <T>(
  ops:
    | Pick<GetOps<'u32'>, 'add' | 'mul' | 'shr' | 'and' | 'const'>
    | Pick<GetOps<'u64'>, 'add' | 'mul' | 'shr' | 'and' | 'const'>,
  toU32: (a: T) => Val<'u32'>,
  fromU32: (a: Val<'u32'>) => T
): MulOps<T> => ({
  add: ops.add as unknown as MulOps<T>['add'],
  mul: ops.mul as unknown as MulOps<T>['mul'],
  shr: (a, bits) => ops.shr(a as never, bits) as T,
  and: ops.and as unknown as MulOps<T>['and'],
  const: ops.const as unknown as MulOps<T>['const'],
  toU32,
  fromU32,
});
const makeU64Ops = (u64: GetOps<'u64'>) =>
  makeMulOps<Val<'u64'>>(
    u64,
    (a) => u64.toN('u32', a),
    (a) => u64.fromN('u32', a)
  );
const mulReduce = <T>(
  ops: MulOps<T>,
  spec: LimbSpec,
  h: Val<'u32'>[],
  r: Val<'u32'>[],
  r5: Val<'u32'>[]
) => {
  const mask = ops.const(spec.mask);
  const d = new Array<T>(spec.count);
  let c = ops.const(0);
  for (let i = 0; i < spec.count; i++) {
    let sum0 = ops.const(0);
    let sum1 = ops.const(0);
    for (let j = 0; j < spec.count; j++) {
      const idx = i - j;
      // RFC 8439 §2.5: since p=2^130-5, high limbs fold back as r*5.
      const mul = idx >= 0 ? r[idx] : r5[idx + spec.count];
      const add = ops.mul(ops.fromU32(h[j]), ops.fromU32(mul));
      // Narrow u32 limbs split accumulation before carries so five products stay under 2^32.
      if (j < (spec.count === LIMB_SPEC.count ? WIDE_LIMB_COUNT : spec.count))
        sum0 = ops.add(sum0, add);
      else sum1 = ops.add(sum1, add);
    }
    let di = ops.add(c, sum0);
    c = ops.shr(di, spec.bits);
    di = ops.and(di, mask);
    di = ops.add(di, sum1);
    c = ops.add(c, ops.shr(di, spec.bits));
    d[i] = ops.and(di, mask);
  }
  d[0] = ops.add(d[0], ops.mul(c, ops.const(5)));
  c = ops.shr(d[0], spec.bits);
  d[0] = ops.and(d[0], mask);
  d[1] = ops.add(d[1], c);
  const out = new Array<Val<'u32'>>(spec.count);
  for (let i = 0; i < spec.count; i++) out[i] = ops.toU32(d[i]);
  return out;
};
const getU32Arr = (arr: U64View, len: number) => {
  const out = new Array<Val<'u32'>>(len);
  const view = arr.as('u32') as unknown as ArrayLike<{ get: () => Val<'u32'> }>;
  // Poly1305 limbs live in the low u32 half of each u64 slot; the high half is padding here.
  for (let i = 0; i < len; i++) out[i] = view[i * 2].get();
  return out;
};
const setU32Arr = (u32: GetOps<'u32'>, arr: U64View, vals: U32Arr, len: number, clearHi = true) => {
  const view = arr.as('u32') as unknown as ArrayLike<{ set: (v: Val<'u32'>) => void }>;
  for (let i = 0; i < len; i++) {
    const lo = i * 2;
    view[lo].set(vals[i]);
    // Key/pad writes clear padding.
    // Accumulator updates may skip because readers only load low halves.
    if (clearHi) view[lo + 1].set(u32.const(0));
  }
};
const polyFinish = <M extends PolySegs | PolyBatchSegs, F extends FnRegistry>(
  f: Scope<M, F>,
  poly: PolyMem,
  spec: LimbSpec
) => {
  const { u32, u64 } = f.types;
  const limbMask = u32.const(spec.mask);
  const c5 = u32.const(5);
  let H = getU32Arr(poly.h, spec.count);
  let c = u32.const(0);
  for (let i = 1; i < spec.count; i++) {
    const v = u32.add(H[i], c);
    c = u32.shr(v, spec.bits);
    H[i] = u32.and(v, limbMask);
  }
  H[0] = u32.add(H[0], u32.mul(c, c5));
  for (let i = 0; i < (spec.count === LIMB_SPEC.count ? 2 : 1); i++) {
    c = u32.shr(H[i], spec.bits);
    H[i] = u32.and(H[i], limbMask);
    H[i + 1] = u32.add(H[i + 1], c);
  }
  const G = new Array<Val<'u32'>>(spec.count);
  c = u32.const(0);
  for (let i = 0; i < spec.count; i++) {
    const v = u32.add(H[i], i === 0 ? c5 : c);
    c = u32.shr(v, spec.bits);
    // Keep the top limb unmasked so the final subtract can detect carry-out.
    // This fixes p-reduction edge cases.
    G[i] = i === spec.count - 1 ? v : u32.and(v, limbMask);
  }
  G[spec.count - 1] = u32.sub(G[spec.count - 1], u32.shl(u32.const(1), spec.bits));
  const m = u32.sub(u32.shr(G[spec.count - 1], 31), u32.const(1));
  const nm = u32.not(m);
  for (let i = 0; i < spec.count; i++) H[i] = u32.or(u32.and(H[i], nm), u32.and(G[i], m));
  const P = getU32Arr(poly.pad, 4);
  let carry = u64.const(0);
  // RFC 8439 §2.5: add s word-by-word and keep only the low 128-bit tag.
  for (let i = 0; i < 4; i++) {
    let h32 = u32.const(0);
    const wordStart = i * 32;
    for (let j = 0; j < H.length; j++) {
      const limbStart = j * spec.bits;
      if (limbStart + spec.bits <= wordStart || limbStart >= wordStart + 32) continue;
      const shift = limbStart - wordStart;
      const cur = shift === 0 ? H[j] : shift > 0 ? u32.shl(H[j], shift) : u32.shr(H[j], -shift);
      h32 = u32.or(h32, cur);
    }
    const w = u64.add(u64.add(u64.fromN('u32', h32), u64.fromN('u32', P[i])), carry);
    poly.tag[i].set(u64.toN('u32', w));
    carry = u64.shr(w, 32);
  }
};
const polyBlocksMul = <M extends PolySegs | PolyBatchSegs, F extends FnRegistry, T>(
  f: Scope<M, F>,
  poly: PolyMem,
  b: Val<'u32'>,
  last: Val<'u32'>,
  l: Val<'u32'>,
  read: (chunkPos: Val<'u32'>) => Val<'u32'>[],
  spec: LimbSpec,
  r: Val<'u32'>[],
  r5: Val<'u32'>[],
  ops: MulOps<T>,
  set: (H: Val<'u32'>[]) => void
) => {
  const { u32 } = f.types;
  f.ifElse(u32.ne(b, u32.const(0)), [], () => {
    let H = getU32Arr(poly.h, spec.count);
    [H] = f.doN1([H], b, (chunkPos: Val<'u32'>, H: Val<'u32', unknown>[]) => {
      // RFC 8439 §2.5: short final blocks already carry the byte-aligned 0x01 from padding.
      const hibit = u32.select(
        u32.and(last, u32.and(u32.eq(u32.add(chunkPos, u32.const(1)), b), u32.ne(l, u32.const(0)))),
        u32.const(0),
        u32.shl(u32.const(1), spec.hibit)
      );
      const m = parseWithSpec(u32, read(chunkPos), hibit, spec);
      const a = new Array<Val<'u32'>>(spec.count);
      for (let i = 0; i < spec.count; i++) a[i] = u32.add(H[i], m[i]);
      return [mulReduce(ops, spec, a, r, r5)];
    });
    set(H);
  });
};
const polyBlocksMul4 = <M extends PolySegs | PolyBatchSegs, F extends FnRegistry>(
  f: Scope<M, F>,
  poly: PolyMem,
  b: Val<'u32'>,
  last: Val<'u32'>,
  l: Val<'u32'>,
  read: (chunkPos: Val<'u32'>) => Val<'u32'>[],
  spec: LimbSpec,
  r: Val<'u32'>[],
  r5: Val<'u32'>[],
  ops: MulOps<Val<'u64'>>,
  set: (H: Val<'u32'>[]) => void,
  mul4: { rList: ArrayLike<Val<'u32'>[]>; r5List: ArrayLike<Val<'u32'>[]> }
) => {
  const { u32, u64 } = f.types;
  let H = getU32Arr(poly.h, spec.count);
  const hasLeft = u32.ne(l, u32.const(0));
  const runSmall = (chunk: Val<'u32'>, read: (chunkPos: Val<'u32'>) => Val<'u32'>[]) =>
    polyBlocksMul(f, poly, chunk, last, l, read, spec, r, r5, ops, set);
  f.ifElse(u32.or(u32.lt(b, u32.const(4)), u32.and(last, hasLeft)), [], () => {
    runSmall(b, read);
  });
  f.ifElse(
    u32.and(
      u32.ne(u32.shr(b, 2), u32.const(0)),
      u32.or(u32.eq(last, u32.const(0)), u32.eq(l, u32.const(0)))
    ),
    [],
    () => {
      const groups = u32.shr(b, 2);
      [H] = f.doN1([H], groups, (gi: Val<'u32'>, H: Val<'u32', unknown>[]) => {
        const base = u32.mul(gi, u32.const(4));
        const hibit = u32.shl(u32.const(1), spec.hibit);
        const m = new Array<Val<'u32'>[]>(4);
        for (let i = 0; i < 4; i++) {
          const pos = u32.add(base, u32.const(i));
          m[i] = parseWithSpec(u32, read(pos), hibit, spec);
        }
        const a = new Array<Val<'u32'>>(spec.count);
        for (let i = 0; i < spec.count; i++) a[i] = u32.add(H[i], m[0][i]);
        const d = new Array<Val<'u64'>[]>(4);
        // Four full-block updates fold to (H+m0)r^4 + m1r^3 + m2r^2 + m3r.
        for (let i = 0; i < 4; i++) {
          const [h, r, r5] = [i === 0 ? a : m[i], mul4.rList[i], mul4.r5List[i]];
          const hU = new Array<Val<'u64'>>(spec.count);
          const rU = new Array<Val<'u64'>>(spec.count);
          const r5U = new Array<Val<'u64'>>(spec.count);
          for (let j = 0; j < spec.count; j++) {
            hU[j] = u64.fromN('u32', h[j]);
            rU[j] = u64.fromN('u32', r[j]);
            r5U[j] = u64.fromN('u32', r5[j]);
          }
          const di = new Array<Val<'u64'>>(spec.count);
          for (let j = 0; j < spec.count; j++) {
            let acc = u64.const(0);
            for (let k = 0; k < spec.count; k++) {
              const idx = j - k;
              const mul = idx >= 0 ? rU[idx] : r5U[idx + spec.count];
              acc = u64.add(acc, u64.mul(hU[k], mul));
            }
            di[j] = acc;
          }
          d[i] = di;
        }
        const s = new Array<Val<'u64'>>(spec.count);
        for (let i = 0; i < spec.count; i++)
          s[i] = u64.add(u64.add(d[0][i], d[1][i]), u64.add(d[2][i], d[3][i]));
        const mask = u64.const(spec.mask);
        let c = u64.const(0);
        for (let i = 0; i < spec.count; i++) {
          s[i] = u64.add(s[i], c);
          c = u64.shr(s[i], spec.bits);
          s[i] = u64.and(s[i], mask);
        }
        s[0] = u64.add(s[0], u64.mul(c, u64.const(5)));
        c = u64.shr(s[0], spec.bits);
        s[0] = u64.and(s[0], mask);
        s[1] = u64.add(s[1], c);
        const out = new Array<Val<'u32'>>(spec.count);
        for (let i = 0; i < spec.count; i++) out[i] = u64.toN('u32', s[i]);
        return [out];
      });
      set(H);
      const tail = u32.and(b, u32.const(3));
      f.ifElse(u32.ne(tail, u32.const(0)), [], () => {
        const base = u32.shl(groups, 2);
        runSmall(tail, (chunkPos: Val<'u32'>) => read(u32.add(base, chunkPos)));
      });
    }
  );
};
const polyBlocksDual = <M extends PolySegs | PolyBatchSegs, F extends FnRegistry>(
  f: Scope<M, F>,
  poly: PolyMem,
  b: Val<'u32'>,
  last: Val<'u32'>,
  l: Val<'u32'>,
  read: (chunkPos: Val<'u32'>) => Val<'u32'>[]
) => {
  if (f.flags.native64bit) {
    const { u64 } = f.types;
    const [rList, r5List] = [poly.r, poly.r5].map((src) =>
      [src[0], src[1], src[2], src[3]].map((m) => getU32Arr(m, WIDE_LIMB_SPEC.count))
    );
    polyBlocksMul4(
      f,
      poly,
      b,
      last,
      l,
      read,
      WIDE_LIMB_SPEC,
      rList[3],
      r5List[3],
      makeU64Ops(u64),
      (H) => {
        for (let i = 0; i < WIDE_LIMB_SPEC.count; i++) poly.h[i].set(u64.fromN('u32', H[i]));
      },
      { rList, r5List }
    );
    return;
  }
  const { u32 } = f.types;
  polyBlocksMul(
    f,
    poly,
    b,
    last,
    l,
    read,
    LIMB_SPEC,
    getU32Arr(poly.r[3], LIMB_SPEC.count),
    getU32Arr(poly.r5[3], LIMB_SPEC.count),
    makeMulOps<Val<'u32'>>(
      u32,
      (a) => a,
      (a) => a
    ),
    (H) => setU32Arr(u32, poly.h, H, LIMB_SPEC.count, false)
  );
};
const polyInit = <M extends PolySegs | PolyBatchSegs, F extends FnRegistry>(
  f: Scope<M, F>,
  poly: PolyMem
) => {
  const { u32, u64 } = f.types;
  const key = poly.key.as8('u8');
  // RFC 8439 §2.5.1 parses Poly1305 key halves as little-endian numbers.
  const u8to32 = (i: number) => {
    const b0 = u32.fromN('u8', key[i].get());
    const b1 = u32.fromN('u8', key[i + 1].get());
    const b2 = u32.fromN('u8', key[i + 2].get());
    const b3 = u32.fromN('u8', key[i + 3].get());
    return u32.or(b0, u32.or(u32.shl(b1, 8), u32.or(u32.shl(b2, 16), u32.shl(b3, 24))));
  };
  const padU32 = new Array<Val<'u32', unknown>>(4);
  for (let i = 0; i < 4; i++) padU32[i] = u8to32(16 + i * 4);
  const spec = getSpec(!!f.flags.native64bit);
  const rBytes = new Array<Val<'u32', unknown>>(16);
  for (let i = 0; i < 16; i++) rBytes[i] = u32.fromN('u8', key[i].get());
  // RFC 8439 §2.5.1: clamp r &= 0x0ffffffc0ffffffc0ffffffc0fffffff.
  for (const i of [3, 7, 11, 15] as const) rBytes[i] = u32.and(rBytes[i], u32.const(0x0f));
  for (const i of [4, 8, 12] as const) rBytes[i] = u32.and(rBytes[i], u32.const(0xfc));
  const w = new Array<Val<'u32', unknown>>(4);
  for (let i = 0; i < 4; i++) {
    w[i] = u32.or(
      rBytes[i * 4],
      u32.or(u32.shl(rBytes[i * 4 + 1], 8), u32.shl(rBytes[i * 4 + 2], 16))
    );
    w[i] = u32.or(w[i], u32.shl(rBytes[i * 4 + 3], 24));
  }
  const rArr = parseWithSpec(u32, w, u32.const(0), spec);
  const c5 = u32.const(5);
  const r5Arr = rArr.map((v) => u32.mul(v, c5));
  if (f.flags.native64bit) {
    const u64ops = makeU64Ops(u64);
    const pow = [rArr];
    for (let i = 1; i < 4; i++) pow[i] = mulReduce(u64ops, WIDE_LIMB_SPEC, pow[i - 1], rArr, r5Arr);
    // polyBlocksMul4 consumes [r^4, r^3, r^2, r] to fold four RFC 8439 block updates.
    for (let i = 0; i < WIDE_LIMB_COUNT; i++) {
      for (let j = 0; j < 4; j++) poly.r[3 - j][i].set(u64.fromN('u32', pow[j][i]));
      for (let j = 0; j < 4; j++) poly.r5[3 - j][i].set(u64.fromN('u32', u32.mul(pow[j][i], c5)));
    }
    for (let i = WIDE_LIMB_COUNT; i < LIMB_SPEC.count; i++) {
      for (let j = 0; j < 4; j++) poly.r[j][i].set(u64.const(0));
      for (let j = 0; j < 4; j++) poly.r5[j][i].set(u64.const(0));
    }
    const padOut = poly.pad.get();
    for (let i = 0; i < 4; i++) padOut[i] = u64.fromN('u32', padU32[i]);
    for (let i = 4; i < 8; i++) padOut[i] = u64.const(0);
    poly.pad.set(padOut);
  } else {
    setU32Arr(u32, poly.r[3], rArr, LIMB_SPEC.count);
    setU32Arr(u32, poly.r5[3], r5Arr, LIMB_SPEC.count);
    setU32Arr(u32, poly.pad, padU32, 4);
  }
  poly.h.as8().zero();
};
const polyPadAt = <M extends Segs & BufSegs, F extends FnRegistry>(
  f: Scope<M, F>,
  base: Val<'u32'>,
  take: Val<'u32'>,
  left: Val<'u32'>
) => {
  const { u32 } = f.types;
  const buffer = f.memory.buffer.as8();
  // RFC 8439 §2.5: short final Poly1305 blocks append 0x01, then zero-fill to 16 bytes.
  f.ifElse(u32.ne(left, u32.const(0)), [], () => {
    const off = u32.add(base, take);
    buffer[off].set(u32.const(1));
    // Keep the fixed loop value-preserving after the RFC 8439 zero-fill span.
    for (let i = 1; i < 16; i++) {
      const idx = u32.add(off, u32.const(i));
      buffer[idx].set(u32.select(u32.lt(u32.const(i), left), u32.const(0), buffer[idx].get()));
    }
  });
};
export const poly1305Ops =
  // AEAD callers pass false because ciphertext must remain in buffer after MAC reads it.
  (clearBuffer = true) =>
    <M extends Segs & PolySegs, F extends FnRegistry>(mod: Module<M, F>) =>
      mod
        .fn('macInit', [], 'void', (f) => polyInit(f, f.memory.state.poly))
        .fn('macPadAt', ['u32', 'u32', 'u32'], 'void', polyPadAt)
        .fn(
          'macBlocksAt',
          ['u32', 'u32', 'u32', 'u32'],
          'void',
          (f, base, blocks, isLast, left) => {
            const { u32 } = f.types;
            const buffer = f.memory.buffer.reshape(CHUNKS, 4);
            // base is a byte offset; each Poly1305 row is 16 bytes / 4 u32 words.
            const readBlock = (chunkPos: Val<'u32'>) =>
              readMSG(f, buffer[u32.add(u32.shr(base, 4), chunkPos)], clearBuffer);
            polyBlocksDual(f, f.memory.state.poly, blocks, isLast, left, readBlock);
          }
        )
        .fn(
          // Called without args by AEAD modules.
          // Keep the signature empty to avoid awasm arg mismatch.
          'macFinish',
          [],
          'void',
          (f) => polyFinish(f, f.memory.state.poly, getSpec(!!f.flags.native64bit))
        );
// RFC 8439 §2.5 Poly1305 state: key, r powers, accumulator, s pad, and tag.
const polyState = /* @__PURE__ */ struct({
  key: /* @__PURE__ */ array('u64', {}, 4),
  r: /* @__PURE__ */ array('u64', {}, 4, 10),
  r5: /* @__PURE__ */ array('u64', {}, 4, 10),
  h: /* @__PURE__ */ array('u64', {}, 10),
  pad: /* @__PURE__ */ array('u64', {}, 8),
  tag: /* @__PURE__ */ array('u32', {}, 4),
});
const polyBatchState = /* @__PURE__ */ struct({
  // Generic batch scratch/reset slot; Poly1305 arithmetic state lives in the poly field.
  state: /* @__PURE__ */ array('u32', {}, 10),
  poly: polyState,
});
// Raw Poly1305 module; AEAD callers build RFC 8439 §2.8.1 zero-padded MAC input separately.
export const genPoly1305 = (type: TypeName, _opts: {}) =>
  new Module('poly1305')
    .batchMem('state', polyBatchState)
    .mem('buffer', array('u32', {}, CHUNKS, 4))
    .fn('macInit', ['u32'], 'void', (f, batchPos) => polyInit(f, f.memory.state[batchPos].poly))
    .fn('macPadAt', ['u32', 'u32', 'u32'], 'void', polyPadAt)
    .fn(
      'macBlocksAt',
      ['u32', 'u32', 'u32', 'u32', 'u32'],
      'void',
      (f, batch, base, blocks, isLast, left) => {
        const { u32 } = f.types;
        const buffer = f.memory.buffer.reshape(CHUNKS, 4);
        const readBlock = (chunkPos: Val<'u32'>) =>
          readMSG(f, buffer[u32.add(u32.shr(base, 4), chunkPos)], true);
        polyBlocksDual(f, f.memory.state[batch].poly, blocks, isLast, left, readBlock);
      }
    )
    .fn('macFinish', ['u32'], 'void', (f, batchPos) => {
      // Batch mode: finish only the active batch slot to avoid re-finalizing others.
      polyFinish(f, f.memory.state[batchPos].poly, getSpec(!!f.flags.native64bit));
    })
    .fn(
      'padding',
      ['u32', 'u32', 'u32', 'u32', 'u32', 'u32'],
      'u32',
      (f, batchPos, take, maxBlocks, left, blockLen) => {
        const { u32 } = f.types;
        const base = u32.mul(batchPos, u32.mul(maxBlocks, blockLen));
        f.functions.macPadAt.call(base, take, left);
        return u32.select(u32.eq(take, u32.const(0)), u32.const(1), u32.const(0));
      }
    )
    .batchFn(
      'processBlocks',
      { lanes: getLanes(type), perThread: MIN_PER_THREAD },
      ['u32', 'u32', 'u32', 'u32', 'u32'],
      (f, l, p, b, max, len, last, left, pad) => {
        const { u32 } = f.types;
        const run = u32.sub(b, pad);
        f.doN([], u32.const(l), (i) => {
          const pos = u32.add(p, i);
          const base = u32.mul(pos, u32.mul(max, len));
          return (f.functions.macBlocksAt.call(pos, base, run, last, left), []);
        });
      }
    )
    .fn('reset', ['u32', 'u32', 'u32', 'u32', 'u32'], 'void', resetBatch)
    .batchFn(
      'processOutBlocks',
      { lanes: getLanes(type), perThread: MIN_PER_THREAD },
      ['u32', 'u32', 'u32'],
      (f, l, p, b, max) => {
        const { u32 } = f.types;
        f.doN([], u32.const(l), (i) => {
          const pos = u32.add(p, i);
          const buffer = f.memory.buffer.reshape(pos, max, 4)[pos];
          f.functions.macFinish.call(pos);
          const tag = f.memory.state[pos].poly.tag;
          const tagOut = [tag[0].get(), tag[1].get(), tag[2].get(), tag[3].get()];
          f.doN([], b, (chunkPos) => (buffer[chunkPos].set(tagOut), []));
          return [];
        });
      }
    );
type BufSegs = { buffer: ArraySpec<ScalarSpec<'u32', unknown>, readonly [number, 4]> };
type StateSeg<S> = { state: S } & BufSegs;
type GhashBatchSegs = StateSeg<ArraySpec<typeof ghashBatchState, readonly [number]>>;
type PolySegs = StateSeg<StructSpec<{ poly: typeof polyState }>>;
type PolyBatchSegs = StateSeg<ArraySpec<typeof polyBatchState, readonly [number]>>;
type PolyMem = MemorySurface<{ poly: typeof polyState }>['poly'];
