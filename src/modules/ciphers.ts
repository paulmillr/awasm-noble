/**
 * Core AES logic.
 * The file is not used in end-user code. Instead, it's used by awasm-compiler
 * to generate different build targets (wasm, wasm_threads, js, runtime).
 * @module
 */
import type {
  ArraySpec,
  FnDef,
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
import {
  GHASH_U64X2_TABLE_ENTRIES,
  GHASH_U64X2_W,
  ghashBlocksTableCore64v,
  ghashInitTableCore64v,
  ghashState,
  poly1305Ops,
} from './mac.ts';
import { CHUNKS, getLanes, MIN_PER_THREAD, readMSG } from './utils.ts';

// `doN`/`doN1` state accepts arrays/objects; keep this minimal and compatible with any `Val<...>`.
type Shape = symbol | Shape[] | { [k: string]: Shape };

// Salsa / ChaCha
// --------------

// Shared Salsa/ChaCha stream block width: ChaCha20 serializes one 16-word state into 64 bytes,
// and the local Salsa-compatible path keeps the same 512-bit block size for tail/MAC math.
const BLOCK_LEN = 64;
// Shared Poly1305/AEAD MAC granularity:
// RFC 8439 processes data in 16-byte chunks and pads AAD/ciphertext to the
// next 16-byte boundary before final length words, so macUpdate() rounds by 16.
const MAC_BLOCK_LEN = 16;
const ARX_BLOCKS = CHUNKS;
const MAC_BLOCKS = CHUNKS;
// Reindex the same backing store from 4-word MAC rows into 16-word ARX blocks for keystream XOR.
const ARX_MAC_BLOCKS = /* @__PURE__ */ (() => MAC_BLOCKS / 4)();
type ArxState = StructSpec<{
  counter: ScalarSpec<'u64', unknown>;
  sigma: ArraySpec<ScalarSpec<'u32', unknown>, readonly [4]>;
  key: ArraySpec<ScalarSpec<'u32', unknown>, readonly [8]>;
  nonce: ArraySpec<ScalarSpec<'u32', unknown>, readonly [number]>;
}>;
type ArxSegs = {
  state: ArxState;
};
type ArxScope = Scope<ArxSegs>;

type MacSegs = {
  state: StructSpec<{
    aadLen: ScalarSpec<'u64', unknown>;
    dataLen: ScalarSpec<'u64', unknown>;
  }>;
  buffer: ArraySpec<ScalarSpec<'u32', unknown>, readonly [number, number]>;
};
type MacFns = {
  macBlocksAt: FnDef<['u32', 'u32', 'u32', 'u32'], void>;
  macPadAt: FnDef<['u32', 'u32', 'u32'], void>;
};
type MacScope = Scope<MacSegs, MacFns>;

type ArxCfg = {
  name: string;
  nonceWords: number;
  initState: (
    f: ArxScope,
    lanes: number,
    k: Val<'u32', unknown>[],
    n: Val<'u32', unknown>[]
  ) => Val<'u32', unknown>[];
  applyCounter: (cur: Val<'u32', unknown>[], cnt32: Val<'u32', unknown>[]) => void;
  core: (f: ArxScope, lanes: number, state: Val<'u32', unknown>[], rounds: number) => void;
  derive: {
    nonceWords: number;
    initState: (
      f: ArxScope,
      lanes: number,
      k: Val<'u32', unknown>[],
      n: Val<'u32', unknown>[]
    ) => Val<'u32', unknown>[];
    core: (f: ArxScope, lanes: number, state: Val<'u32', unknown>[], rounds: number) => void;
    outIdx: number[];
  };
};

export const chachaCore = (
  f: Scope,
  lanes: number,
  X: Val<'u32', unknown>[],
  rounds: number,
  add: boolean
) => {
  const T = f.getType('u32', lanes);
  const Y = [...X];
  for (let i = 0; i < rounds; i += 2) {
    const qr = (a: number, b: number, c: number, d: number) => {
      Y[a] = T.add(Y[a], Y[b]);
      Y[d] = T.rotl(T.xor(Y[d], Y[a]), 16);
      Y[c] = T.add(Y[c], Y[d]);
      Y[b] = T.rotl(T.xor(Y[b], Y[c]), 12);
      Y[a] = T.add(Y[a], Y[b]);
      Y[d] = T.rotl(T.xor(Y[d], Y[a]), 8);
      Y[c] = T.add(Y[c], Y[d]);
      Y[b] = T.rotl(T.xor(Y[b], Y[c]), 7);
    };
    qr(0, 4, 8, 12);
    qr(1, 5, 9, 13);
    qr(2, 6, 10, 14);
    qr(3, 7, 11, 15);
    qr(0, 5, 10, 15);
    qr(1, 6, 11, 12);
    qr(2, 7, 8, 13);
    qr(3, 4, 9, 14);
  }
  // This core runs ChaCha double rounds; current callers only expose even-round variants.
  // `add=false` reuses the post-round state directly for HChaCha-style derivation.
  for (let i = 0; i < 16; i++) X[i] = add ? T.add(X[i], Y[i]) : Y[i];
};

export const salsaCore = (
  f: Scope,
  lanes: number,
  X: Val<'u32', unknown>[],
  rounds: number,
  add: boolean
) => {
  const T = f.getType('u32', lanes);
  const Y = [...X];
  for (let i = 0; i < rounds; i += 2) {
    const qr = (a: number, b: number, c: number, d: number) => {
      Y[a] = T.xor(Y[a], T.rotl(T.add(Y[d], Y[c]), 7));
      Y[b] = T.xor(Y[b], T.rotl(T.add(Y[a], Y[d]), 9));
      Y[c] = T.xor(Y[c], T.rotl(T.add(Y[b], Y[a]), 13));
      Y[d] = T.xor(Y[d], T.rotl(T.add(Y[c], Y[b]), 18));
    };
    qr(4, 8, 12, 0);
    qr(9, 13, 1, 5);
    qr(14, 2, 6, 10);
    qr(3, 7, 11, 15);
    qr(1, 2, 3, 0);
    qr(6, 7, 4, 5);
    qr(11, 8, 9, 10);
    qr(12, 13, 14, 15);
  }
  // This core runs Salsa double rounds; current callers only expose even-round variants.
  // `add=false` reuses the post-round state directly for HSalsa-style derivation.
  for (let i = 0; i < 16; i++) X[i] = add ? T.add(X[i], Y[i]) : Y[i];
};

const genArx = (type: TypeName, opts: { rounds: number }, cfg: ArxCfg) => {
  const mod = new Module(cfg.name)
    .mem(
      'state',
      struct({
        counter: 'u64',
        sigma: array('u32', {}, 4),
        key: array('u32', {}, 8),
        nonce: array('u32', {}, cfg.nonceWords),
      })
    )
    .mem('buffer', array('u32', {}, ARX_BLOCKS, 16))
    .mem(
      'derive',
      struct({
        nonce: array('u32', {}, cfg.derive.nonceWords),
        out: array('u32', {}, 8),
      })
    )
    .fn('reset', ['u32'], 'void', (f, maxWritten) => {
      f.memory.state.as8().zero();
      f.memory.derive.as8().zero();
      f.memory.buffer.as8().range(0, maxWritten).fill(0);
    })
    .batchFn(
      'processBlocks',
      { lanes: getLanes(type), perThread: MIN_PER_THREAD },
      ['u32', 'u32'],
      (f, lanes, batchPos, blocks, _isLast, _left) => {
        const T = f.getType('u32', lanes);
        const u64T = f.getType('u64', lanes);
        const { u32, u64 } = f.types;
        const { key, nonce, counter } = f.memory.state;
        const buffer = f.memory.buffer.lanes(lanes).reshape(ARX_BLOCKS, 16);
        const k = key.get();
        const n = nonce.get();
        const state = cfg.initState(f, lanes, k, n);
        f.doN1([u64.add(counter.get(), u64.fromN('u32', batchPos))], blocks, (chunkPos, curCnt) => {
          const curState = [...state];
          const cnt64 = u64T.add(u64T.fromN('u64', curCnt), u64T.laneOffsets());
          cfg.applyCounter(curState, T.from(u64T.name, cnt64));
          cfg.core(f, lanes, curState, opts.rounds);
          const block = buffer[u32.add(batchPos, chunkPos)];
          block.set(block.get().map((i, j) => T.xor(i, curState[j])));
          return [u64.add(curCnt, u64.const(lanes))];
        });
      }
    )
    .fn('encryptBlocks', ['u32', 'u32', 'u32'], 'void', (f, blocks, isLast, left) => {
      const { u32, u64 } = f.types;
      f.functions.processBlocks.call(u32.const(0), blocks, u32.const(1), isLast, left);
      f.memory.state.counter.mut.add(u64.fromN('u32', blocks));
    })
    .fn('decryptBlocks', ['u32', 'u32', 'u32'], 'void', (f, blocks, isLast, left) => {
      const { u32, u64 } = f.types;
      f.functions.processBlocks.call(u32.const(0), blocks, u32.const(1), isLast, left);
      f.memory.state.counter.mut.add(u64.fromN('u32', blocks));
    })
    .fn('derive', [], 'void', (f) => {
      const lanes = 1;
      const T = f.getType('u32', lanes);
      const { key } = f.memory.state;
      const { nonce, out } = f.memory.derive;
      const k = key.get();
      const n = nonce.get();
      const state = cfg.derive!.initState(f, lanes, k, n);
      cfg.derive.core(f, lanes, state, opts.rounds);
      out.set(cfg.derive.outIdx.map((i) => T.fromN('u32', state[i])));
    });

  // Stream ARX modes xor the same keystream in both directions; encrypt/decrypt share
  // processBlocks and differ only in the caller-side framing around this module.
  return mod;
};

export const genSalsa = (type: TypeName, opts: { rounds: number }) => {
  return genArx(type, opts, {
    name: 'salsa',
    nonceWords: 2,
    initState: (f, lanes, k, n) => {
      const T = f.getType('u32', lanes);
      const { u32 } = f.types;
      const s = f.memory.state.sigma.get();
      // Initial state of Salsa:
      // "expa" Key     Key     Key
      // Key    "nd 3"  Nonce   Nonce
      // Pos.   Pos.    "2-by"  Key
      // Key    Key     Key     "te k"
      return [
        s[0],
        ...k.slice(0, 4),
        s[1],
        n[0],
        n[1],
        u32.const(0),
        u32.const(0),
        s[2],
        ...k.slice(4, 8),
        s[3],
      ].map((i) => T.fromN('u32', i));
    },
    applyCounter: (cur, cnt32) => {
      for (let i = 0; i < cnt32.length; i++) cur[8 + i] = cnt32[i];
    },
    core: (f, lanes, state, r) => salsaCore(f, lanes, state, r, true),
    derive: {
      nonceWords: 4,
      initState: (f, lanes, k, n) => {
        const T = f.getType('u32', lanes);
        const s = f.memory.state.sigma.get();
        return [s[0], ...k.slice(0, 4), s[1], ...n, s[2], ...k.slice(4, 8), s[3]].map((i) =>
          T.fromN('u32', i)
        );
      },
      core: (f, lanes, state, r) => salsaCore(f, lanes, state, r, false),
      // HSalsa20 derives the XSalsa20 subkey from words 0, 5, 10, 15 and 6..9 after the rounds.
      outIdx: [0, 5, 10, 15, 6, 7, 8, 9],
    },
  });
};

export const genChacha = (type: TypeName, opts: { rounds: number }) => {
  return genArx(type, opts, {
    name: 'chacha',
    nonceWords: 3,
    initState: (f, lanes, k, n) => {
      const T = f.getType('u32', lanes);
      const { u32 } = f.types;
      const s = f.memory.state.sigma.get();
      // Initial state of ChaCha:
      // "expa"   "nd 3"  "2-by"  "te k"
      // Key      Key     Key     Key
      // Key      Key     Key     Key
      // Counter  Counter Nonce   Nonce
      return [...s, ...k, u32.const(0), ...n].map((i) => T.fromN('u32', i));
    },
    applyCounter: (cur, cnt32) => {
      cur[12] = cnt32[0];
    },
    core: (f, lanes, state, r) => chachaCore(f, lanes, state, r, true),
    derive: {
      nonceWords: 4,
      initState: (f, lanes, k, n) => {
        const T = f.getType('u32', lanes);
        const s = f.memory.state.sigma.get();
        return [...s, ...k, ...n].map((i) => T.fromN('u32', i));
      },
      core: (f, lanes, state, r) => chachaCore(f, lanes, state, r, false),
      // HChaCha20 derives the XChaCha20 subkey from words 0..3 and 12..15 after the rounds.
      outIdx: [0, 1, 2, 3, 12, 13, 14, 15],
    },
  });
};

// RFC 8439 §2.8.1 pad16(x): when the last stream block is partial, clear the
// unused keystream tail so later MAC padding sees zero octets instead of stream bytes.
const zeroTail = (
  f: MacScope,
  base: Val<'u32'>,
  bytes: Val<'u32'>,
  isLast: Val<'u32'>,
  left: Val<'u32'>
) => {
  const { u32 } = f.types;
  f.ifElse(u32.and(isLast, u32.ne(left, u32.const(0))), [], () => {
    f.memory.buffer.as8().range(u32.add(base, bytes), left).fill(0);
  });
};

// RFC 8439 AEAD MACs ciphertext || pad16(ciphertext); secretbox-style callers
// instead MAC raw ciphertext and keep Poly1305's short-final-block path.
const macUpdate = (f: MacScope, base: Val<'u32'>, bytes: Val<'u32'>, withLeft: boolean) => {
  const { u32 } = f.types;
  const macBlocks = u32.div(u32.add(bytes, u32.const(15)), u32.const(MAC_BLOCK_LEN));
  const hasBlocks = u32.ne(macBlocks, u32.const(0));
  if (!withLeft) {
    f.functions.macBlocksAt.callIf(hasBlocks, base, macBlocks, u32.const(0), u32.const(0));
    return;
  }
  f.ifElse(hasBlocks, [], () => {
    const macLeft = u32.sub(u32.mul(macBlocks, u32.const(MAC_BLOCK_LEN)), bytes);
    const hasLeft = u32.ne(macLeft, u32.const(0));
    f.functions.macPadAt.callIf(hasLeft, base, bytes, macLeft);
    f.functions.macBlocksAt.call(
      base,
      macBlocks,
      u32.select(hasLeft, u32.const(1), u32.const(0)),
      macLeft
    );
  });
};

// For xsalsa20poly1305
export const genSalsaAead = (type: TypeName, opts: { rounds: number }) => {
  const nonceWords = 2;
  const initState = (
    f: ArxScope,
    lanes: number,
    k: Val<'u32', unknown>[],
    n: Val<'u32', unknown>[]
  ) => {
    const T = f.getType('u32', lanes);
    const { u32 } = f.types;
    const s = f.memory.state.sigma.get();
    // Initial state of Salsa:
    // "expa" Key     Key     Key
    // Key    "nd 3"  Nonce   Nonce
    // Pos.   Pos.    "2-by"  Key
    // Key    Key     Key     "te k"
    return [
      s[0],
      ...k.slice(0, 4),
      s[1],
      n[0],
      n[1],
      u32.const(0),
      u32.const(0),
      s[2],
      ...k.slice(4, 8),
      s[3],
    ].map((i) => T.fromN('u32', i));
  };
  const applyCounter = (
    f: ArxScope,
    lanes: number,
    cnt: Val<'u64', unknown>,
    cur: Val<'u32', unknown>[]
  ) => {
    const u64T = f.getType('u64', lanes);
    const T = f.getType('u32', lanes);
    // Salsa keeps its 64-bit block counter in words 8 and 9; laneOffsets()
    // advances each batched lane to the next counter value before the core runs.
    const cnt64 = u64T.add(u64T.fromN('u64', cnt), u64T.laneOffsets());
    const cnt32 = T.from(u64T.name, cnt64);
    for (let i = 0; i < cnt32.length; i++) cur[8 + i] = cnt32[i];
  };
  const core = (f: ArxScope, lanes: number, state: Val<'u32', unknown>[], r: number) =>
    salsaCore(f, lanes, state, r, true);
  const deriveNonceWords = 4;
  const deriveInitState = (
    f: ArxScope,
    lanes: number,
    k: Val<'u32', unknown>[],
    n: Val<'u32', unknown>[]
  ) => {
    const T = f.getType('u32', lanes);
    const s = f.memory.state.sigma.get();
    // See "initial state of salsa" above
    // HSalsa replaces Salsa20's counter words with the first 16 nonce bytes
    // before deriveCore() selects words 0,5,10,15,6,7,8,9 as the XSalsa subkey.
    return [s[0], ...k.slice(0, 4), s[1], ...n, s[2], ...k.slice(4, 8), s[3]].map((i) =>
      T.fromN('u32', i)
    );
  };
  const deriveCore = (f: ArxScope, lanes: number, state: Val<'u32', unknown>[], r: number) =>
    salsaCore(f, lanes, state, r, false);
  return new Module('arx')
    .mem(
      'state',
      struct({
        counter: 'u64',
        shiftSet: array('u32', {}, 1),
        sigma: array('u32', {}, 4),
        key: array('u32', {}, 8),
        nonce: array('u32', {}, nonceWords),
        aadLen: 'u64',
        dataLen: 'u64',
        poly: struct({
          key: array('u64', {}, 4),
          r: array('u64', {}, 4, 10),
          r5: array('u64', {}, 4, 10),
          h: array('u64', {}, 10),
          pad: array('u64', {}, 8),
          tag: array('u32', {}, 4),
        }),
      })
    )
    .mem('buffer', array('u32', {}, MAC_BLOCKS, 4))
    .mem(
      'derive',
      struct({
        nonce: array('u32', {}, deriveNonceWords),
        out: array('u32', {}, 8),
      })
    )
    .fn('reset', ['u32'], 'void', (f, maxWritten) => {
      f.memory.state.as8().zero();
      f.memory.derive.as8().zero();
      f.memory.buffer.as8().range(0, maxWritten).fill(0);
    })
    .use(poly1305Ops(false))
    .fn('aadInit', [], 'void', (f) => {
      const { u64 } = f.types;
      f.memory.state.aadLen.set(u64.const(0));
      f.memory.state.dataLen.set(u64.const(0));
    })
    .fn('aadBlocks', ['u32', 'u32', 'u32'], 'void', (f, blocks, _isLast, _left) => {
      const { u32 } = f.types;
      // FIXME: XSalsa20-Poly1305 secretbox has no AAD; this extension MACs zero-padded AAD
      // without a length block, so trailing-zero AAD values collide.
      f.functions.macBlocksAt.call(u32.const(0), blocks, u32.const(0), u32.const(0));
    })
    .fn('encryptInit', ['u32', 'u32'], 'void', (f, aadLo, aadHi) => {
      const { u32, u64 } = f.types;
      const buffer = f.memory.buffer.as8('u8');
      f.memory.state.counter.set(u64.const(0));
      buffer.range(0, BLOCK_LEN).zero();
      {
        // Don't call the batchFn from init: wasm_threads may route it through the pool.
        // We only need 1 stream block here (counter=0) to derive Poly1305 key.
        const lanes = 1;
        const { key, nonce, counter } = f.memory.state;
        const k = key.get();
        const n = nonce.get();
        const state = initState(f, lanes, k, n);
        let cnt = counter.get();
        [cnt] = f.doN1([cnt], u32.const(1), (_chunkPos, curCnt) => {
          const curState = [...state];
          applyCounter(f, lanes, curCnt, curState);
          core(f, lanes, curState, opts.rounds);
          f.memory.buffer.as32().range(0, 16).set(curState);
          return [u64.add(curCnt, u64.const(lanes))];
        });
        counter.set(cnt);
      }
      f.memory.state.poly.key.as8('u8').set(buffer.range(0, 32).get());
      f.functions.macInit.call();
      f.memory.state.poly.tag.as8('u8').zero();
      // XSalsa20-Poly1305 keeps block-0 bytes 0..31 as the Poly1305 key, so
      // ciphertext starts at byte 32 until the first chunk clears `shiftSet`.
      f.memory.state.shiftSet[0].set(u32.const(1));
      f.memory.state.counter.set(u64.const(0));
      f.memory.state.aadLen.set(u64.fromN('u32', [aadLo, aadHi]));
      f.memory.state.dataLen.set(u64.const(0));
    })
    .fn('decryptInit', ['u32', 'u32'], 'void', (f, aadLo, aadHi) => {
      f.functions.encryptInit.call(aadLo, aadHi);
    })
    .batchFn(
      'process',
      { lanes: getLanes(type), perThread: MIN_PER_THREAD },
      ['u32', 'u32'],
      (f, lanes, batchPos, blocks, _isLast, _left) => {
        const T = f.getType('u32', lanes);
        const { u32, u64 } = f.types;
        const { key, nonce, counter } = f.memory.state;
        const buffer = f.memory.buffer.lanes(lanes).reshape(ARX_MAC_BLOCKS, 16);
        const k = key.get();
        const n = nonce.get();
        const state = initState(f, lanes, k, n);
        // Thread-safe: derive the counter from (state.counter + batchPos + chunkPos).
        // Do not mutate shared state inside the batchFn.
        // encryptBlocks/decryptBlocks bump state.counter once after.
        const base = u64.add(counter.get(), u64.fromN('u32', batchPos));
        f.doN1([base], blocks, (chunkPos, curCnt) => {
          const idx = u32.add(batchPos, chunkPos);
          const curState = [...state];
          applyCounter(f, lanes, curCnt, curState);
          core(f, lanes, curState, opts.rounds);
          const b = buffer[idx];
          b.set(b.get().map((i, j) => T.xor(i, curState[j])));
          return [u64.add(curCnt, u64.const(lanes))];
        });
      }
    )
    .fn('encryptBlocks', ['u32', 'u32', 'u32'], 'void', (f, blocks, isLast, left) => {
      const { u32, u64 } = f.types;
      const shiftSet = f.memory.state.shiftSet[0];
      const hasOffset = u32.ne(shiftSet.get(), u32.const(0));
      const base = u32.select(hasOffset, u32.const(32), u32.const(0));
      const bytes = u32.sub(u32.mul(blocks, u32.const(BLOCK_LEN)), left);
      f.memory.state.dataLen.mut.add(u64.fromN('u32', bytes));
      f.functions.process.call(u32.const(0), blocks, u32.const(1), isLast, left);
      f.memory.state.counter.mut.add(u64.fromN('u32', blocks));
      // Zero padded tail before MAC so AEAD uses 0x00 pad, not keystream.
      zeroTail(f, base, bytes, isLast, left);
      f.ifElse(hasOffset, [], () => {
        shiftSet.set(u32.const(0));
      });
      macUpdate(f, base, bytes, true);
    })
    .fn('decryptBlocks', ['u32', 'u32', 'u32'], 'void', (f, blocks, isLast, left) => {
      const { u32, u64 } = f.types;
      const shiftSet = f.memory.state.shiftSet[0];
      const hasOffset = u32.ne(shiftSet.get(), u32.const(0));
      const base = u32.select(hasOffset, u32.const(32), u32.const(0));
      const bytes = u32.sub(u32.mul(blocks, u32.const(BLOCK_LEN)), left);
      f.memory.state.dataLen.mut.add(u64.fromN('u32', bytes));
      f.ifElse(hasOffset, [], () => {
        shiftSet.set(u32.const(0));
      });
      zeroTail(f, base, bytes, isLast, left);
      macUpdate(f, base, bytes, true);
      f.functions.process.call(u32.const(0), blocks, u32.const(1), isLast, left);
      f.memory.state.counter.mut.add(u64.fromN('u32', blocks));
    })
    .fn('tagFinish', [], 'void', (f) => {
      f.functions.macFinish.call();
    })
    .fn('derive', [], 'void', (f) => {
      const lanes = 1;
      const T = f.getType('u32', lanes);
      const { key } = f.memory.state;
      const { nonce, out } = f.memory.derive;
      const k = key.get();
      const n = nonce.get();
      const state = deriveInitState(f, lanes, k, n);
      deriveCore(f, lanes, state, opts.rounds);
      out.set([0, 5, 10, 15, 6, 7, 8, 9].map((i) => T.fromN('u32', state[i])));
    });
};

// For chacha20poly1305
export const genChachaAead = (type: TypeName, opts: { rounds: number }) => {
  return new Module('arx')
    .mem(
      'state',
      struct({
        counter: 'u64',
        sigma: array('u32', {}, 4),
        key: array('u32', {}, 8),
        nonce: array('u32', {}, 3),
        aadLen: 'u64',
        dataLen: 'u64',
        poly: struct({
          key: array('u64', {}, 4),
          r: array('u64', {}, 4, 10),
          r5: array('u64', {}, 4, 10),
          msg: array('u32', {}, 4, 5),
          h: array('u64', {}, 10),
          pad: array('u64', {}, 8),
          tag: array('u32', {}, 4),
        }),
      })
    )
    .mem('buffer', array('u32', {}, MAC_BLOCKS, 4))
    .mem('derive', struct({ nonce: array('u32', {}, 4), out: array('u32', {}, 8) }))
    .fn('reset', ['u32'], 'void', (f, maxWritten) => {
      f.memory.state.as8().zero();
      f.memory.derive.as8().zero();
      f.memory.buffer.as8().range(0, maxWritten).fill(0);
    })
    .use(poly1305Ops(false))
    .batchFn(
      'process',
      { lanes: getLanes(type), perThread: MIN_PER_THREAD },
      ['u32', 'u32'],
      (f, lanes, batchPos, blocks, _isLast, _left) => {
        const T = f.getType('u32', lanes);
        const { u32, u64 } = f.types;
        const { key, nonce, counter } = f.memory.state;
        const buffer = f.memory.buffer.lanes(lanes).reshape(ARX_MAC_BLOCKS, 16);
        const k = key.get();
        const n = nonce.get();
        const s = f.memory.state.sigma.get();
        // Initial state of ChaCha:
        // "expa"   "nd 3"  "2-by"  "te k"
        // Key      Key     Key     Key
        // Key      Key     Key     Key
        // Counter  Counter Nonce   Nonce
        const state = [...s, ...k, u32.const(0), ...n].map((i) => T.fromN('u32', i));
        const base = u64.add(counter.get(), u64.fromN('u32', batchPos));
        f.doN([], blocks, (chunkPos) => {
          const idx = u32.add(batchPos, chunkPos);
          const curState = [...state];
          const cntBase = u64.add(base, u64.fromN('u32', chunkPos));
          const cnt32 = T.add(T.fromN('u32', u64.toN('u32', cntBase)), T.laneOffsets());
          curState[12] = cnt32;
          chachaCore(f, lanes, curState, opts.rounds, true);
          const b = buffer[idx];
          const block = b.get();
          for (let i = 0; i < block.length; i++) block[i] = T.xor(block[i], curState[i]);
          b.set(block);
          return [];
        });
      }
    )
    .fn('aadInit', [], 'void', (f) => {
      const { u64 } = f.types;
      f.memory.state.aadLen.set(u64.const(0));
      f.memory.state.dataLen.set(u64.const(0));
    })
    .fn('aadBlocks', ['u32', 'u32', 'u32'], 'void', (f, blocks, _isLast, _left) => {
      const { u32 } = f.types;
      f.functions.macBlocksAt.call(u32.const(0), blocks, u32.const(0), u32.const(0));
    })
    .fn('encryptInit', ['u32', 'u32'], 'void', (f, aadLo, aadHi) => {
      const { u32, u64 } = f.types;
      const buffer = f.memory.buffer.as8('u8');
      const polyKey = f.memory.state.poly.key.as8('u8');
      const tag = f.memory.state.poly.tag.as8('u8');
      f.memory.state.counter.set(u64.const(0));
      buffer.range(0, BLOCK_LEN).zero();
      {
        const lanes = 1;
        const T = f.getType('u32', lanes);
        const { key, nonce, counter } = f.memory.state;
        const k = key.get();
        const n = nonce.get();
        const s = f.memory.state.sigma.get();
        // See "initial state of chacha" above
        const state = [...s, ...k, u32.const(0), ...n].map((i) => T.fromN('u32', i));
        let cnt = counter.get();
        [cnt] = f.doN1([cnt], u32.const(1), (_chunkPos, curCnt) => {
          const curState = [...state];
          curState[12] = T.fromN('u32', u64.toN('u32', curCnt));
          chachaCore(f, lanes, curState, opts.rounds, true);
          f.memory.buffer.as32().range(0, 16).set(curState);
          return [u64.add(curCnt, u64.const(1))];
        });
        counter.set(cnt);
      }
      polyKey.set(buffer.range(0, 32).get());
      f.functions.macInit.call();
      tag.zero();
      // RFC 8439 AEAD uses block 0 only for the Poly1305 one-time key;
      // payload encryption starts at counter 1.
      f.memory.state.counter.set(u64.const(1));
      f.memory.state.aadLen.set(u64.fromN('u32', [aadLo, aadHi]));
      f.memory.state.dataLen.set(u64.const(0));
    })
    .fn('decryptInit', ['u32', 'u32'], 'void', (f, aadLo, aadHi) => {
      f.functions.encryptInit.call(aadLo, aadHi);
    })
    .fn('encryptBlocks', ['u32', 'u32', 'u32'], 'void', (f, blocks, isLast, left) => {
      const { u32, u64 } = f.types;
      const bytes = u32.sub(u32.mul(blocks, u32.const(BLOCK_LEN)), left);
      f.memory.state.dataLen.mut.add(u64.fromN('u32', bytes));
      const cnt = f.memory.state.counter.get();
      f.functions.process.call(u32.const(0), blocks, u32.const(1), isLast, left);
      f.memory.state.counter.set(u64.add(cnt, u64.fromN('u32', blocks)));
      // Zero padded tail before MAC so AEAD uses 0x00 pad, not keystream.
      zeroTail(f, u32.const(0), bytes, isLast, left);
      macUpdate(f, u32.const(0), bytes, false);
    })
    .fn('decryptBlocks', ['u32', 'u32', 'u32'], 'void', (f, blocks, isLast, left) => {
      const { u32, u64 } = f.types;
      const bytes = u32.sub(u32.mul(blocks, u32.const(BLOCK_LEN)), left);
      f.memory.state.dataLen.mut.add(u64.fromN('u32', bytes));
      zeroTail(f, u32.const(0), bytes, isLast, left);
      macUpdate(f, u32.const(0), bytes, false);
      const cnt = f.memory.state.counter.get();
      f.functions.process.call(u32.const(0), blocks, u32.const(1), isLast, left);
      f.memory.state.counter.set(u64.add(cnt, u64.fromN('u32', blocks)));
    })
    .fn('tagFinish', [], 'void', (f) => {
      const { u32 } = f.types;
      // RFC 8439 §2.8.1 appends LE64(aadLen) || LE64(ciphertextLen) as the
      // final Poly1305 block after aad/ciphertext padding.
      f.memory.buffer[0].set([
        ...u32.from('u64', f.memory.state.aadLen.get()),
        ...u32.from('u64', f.memory.state.dataLen.get()),
      ]);
      f.functions.macBlocksAt.call(u32.const(0), u32.const(1), u32.const(0), u32.const(0));
      f.functions.macFinish.call();
    })
    .fn('derive', [], 'void', (f) => {
      const lanes = 1;
      const T = f.getType('u32', lanes);
      const { key } = f.memory.state;
      const { nonce, out } = f.memory.derive;
      const k = key.get();
      const n = nonce.get();
      const s = f.memory.state.sigma.get();
      const state = [...s, ...k, ...n].map((i) => T.fromN('u32', i));
      chachaCore(f, lanes, state, opts.rounds, false);
      out.set([0, 1, 2, 3, 12, 13, 14, 15].map((i) => T.fromN('u32', state[i])));
    });
};

// AES
// ---

type AesDir = 'encrypt' | 'decrypt';

// FIPS 197: AES-128/192/256 all use a fixed 128-bit block size, i.e. 16 bytes.
export const AES_BLOCK_LEN = 16;
// Keep the shared ~10MB CHUNKS budget: one 64-byte chunk maps to four 16-byte AES blocks.
export const AES_BLOCKS = /* @__PURE__ */ (() => CHUNKS * 4)(); // for tree-shaking
// FIPS 197: Nk is 4/6/8 words for AES-128/192/256, so 8 words covers AES-256.
export const KEY_LEN_MAX = 8;
// FIPS 197: Nr is 10/12/14 for AES-128/192/256, so 14 rounds covers AES-256.
const MAX_ROUNDS = 14;
// Max expanded AES key size in u32 words: (rounds + 1) * 4, worst-case AES-256 (14 rounds).
export const EXPANDED_KEY_MAX = /* @__PURE__ */ (() => (MAX_ROUNDS + 1) * 4)();

// These top-level shape descriptors are metadata only;
// mark the builder calls pure so unused cipher modules can drop out.
const aesTable = /* @__PURE__ */ struct({
  // Byte S-box. For `decrypt`, this holds the inverse S-box.
  // Stored in 64 u32 lanes so `.as8('u8')` exposes all 256 byte entries.
  sbox: /* @__PURE__ */ array('u32', {}, 64),
  T0: /* @__PURE__ */ array('u32', {}, 256),
  T1: /* @__PURE__ */ array('u32', {}, 256),
  T2: /* @__PURE__ */ array('u32', {}, 256),
  T3: /* @__PURE__ */ array('u32', {}, 256),
});

// Shared AES constants: encrypt/decrypt S-box + T-table packs, four u32 lanes
// for 16 byte-addressable Rcon powers, and a one-word lazy-init guard.
export const aesConsts = /* @__PURE__ */ struct({
  encrypt: aesTable,
  decrypt: aesTable,
  xPowers: /* @__PURE__ */ array('u32', {}, 4),
  inited: 'u32',
});

// Define an AES block-processing batchFn that follows the batchFn-only calling convention.
//
// - `lanes` is always 1 for t-tables (no SIMD lane plumbing here).
// - `iters` are clamped by kernel from `(blocks - base)` so there are no trailing
//   calls/branches and no duplicated AES call sites inside a single function body.
// - `blocks` is passed as the first runtime input so the kernel can clamp correctly.
export const aesBatchFn =
  <
    Name extends string,
    F extends FnRegistry,
    M extends Segs & {
      state: StructSpec<{
        rounds: ScalarSpec<'u32'>;
        expandedKey: ArraySpec<ScalarSpec<'u32'>, readonly [number]>;
      }>;
      constants: typeof aesConsts;
    },
    Ctx extends Shape,
  >(
    name: Name,
    dir: AesDir,
    init: (f: Scope<M, F>, batchPos: Val<'u32'>, perBatch: Val<'u32'>, blocks: Val<'u32'>) => Ctx,
    cb: (
      f: Scope<M, F>,
      ctx: Ctx,
      processBlock: (in4: Val<'u32'>[]) => Val<'u32'>[],
      pos: Val<'u32'>
    ) => Ctx
  ) =>
  (mod: Module<M, F>) =>
    mod.batchFn(
      name,
      { lanes: 1, perThread: MIN_PER_THREAD },
      ['u32'],
      (f: Scope<M, F>, _lanes, batchPos, perBatch, blocks) => {
        const { u32 } = f.types;
        const base = u32.mul(batchPos, perBatch);
        const rem = u32.sub(blocks, base);
        const iters = u32.select(u32.lt(rem, perBatch), rem, perBatch);
        const roundsVal = f.memory.state.rounds.get();
        const expKey = f.memory.state.expandedKey;
        const ctx0 = init(f, batchPos, perBatch, blocks);
        aesWithBlock(f, dir, roundsVal, expKey, (processBlock) => {
          f.doN1([ctx0], iters, (i: Val<'u32'>, ctx: Ctx) => {
            const pos = u32.add(base, i);
            return [cb(f, ctx, processBlock, pos)];
          });
        });
      }
    );

type AesKeyStateSpec = StructSpec<{
  key: ArraySpec<ScalarSpec<'u32'>, readonly [number]>;
  tmp: ArraySpec<ScalarSpec<'u32'>, readonly [number]>;
  expandedKey: ArraySpec<ScalarSpec<'u32'>, readonly [number]>;
  rounds: ScalarSpec<'u32'>;
}>;

// Common AES key initialization boilerplate (reused by many non-AEAD modes).
//
// mkCipher never calls `mod.init()`, so table init must happen in encryptInit/decryptInit.
// For stream-like modes (CTR/CFB/OFB), decryption uses the encrypt schedule;
// set `withDecrypt=false` to make decryptInit delegate to encryptInit.
export const aesInitKeys =
  (opts: { withDecrypt?: boolean } = {}) =>
  <M extends Segs & { state: AesKeyStateSpec; constants: typeof aesConsts }, F extends FnRegistry>(
    mod: Module<M, F>
  ) =>
    mod
      .fn('initTables', [], 'void', (f) => {
        aesInitTables(f);
      })
      .fn('encryptInit', ['u32'], 'void', (f, len) => {
        f.functions.initTables.call();
        aesKeyInitEnc(
          f,
          len,
          f.memory.state.key,
          f.memory.state.tmp,
          f.memory.state.expandedKey,
          f.memory.state.rounds
        );
      })
      .fn('decryptInit', ['u32'], 'void', (f, len) => {
        if (opts.withDecrypt === false) {
          f.functions.initTables.call();
          aesKeyInitEnc(
            f,
            len,
            f.memory.state.key,
            f.memory.state.tmp,
            f.memory.state.expandedKey,
            f.memory.state.rounds
          );
          return;
        }
        f.functions.initTables.call();
        const { u32 } = f.types;
        const constants = f.memory.constants;
        const dec = constants.decrypt;
        const roundsState = f.memory.state.rounds;
        const expandedKey = f.memory.state.expandedKey;
        const tmp = f.memory.state.tmp;
        // FIPS 197 EQINVCIPHER / KEYEXPANSIONEIC: keep the first/last round keys, reverse the
        // round-key blocks, and apply INVMIXCOLUMNS only to the inner rounds.
        const applyInvMix = (u32: GetOps<'u32'>, x: Val<'u32'>) => {
          const w = applySbox(u32, constants.encrypt.sbox, x, x, x, x);
          const b = new Array<Val<'u32'>>(4);
          for (let i = 0; i < 4; i++) b[i] = u32.and(u32.shr(w, i * 8), u32.const(0xff));
          return u32.xor(
            u32.xor(dec.T0[b[0]].get(), dec.T1[b[1]].get()),
            u32.xor(dec.T2[b[2]].get(), dec.T3[b[3]].get())
          );
        };
        const Nkf = aesExpandKey(
          f,
          len,
          f.memory.state.key,
          tmp,
          expandedKey,
          constants.encrypt.sbox,
          constants.xPowers,
          roundsState
        )[1];
        f.doN([], Nkf, (i: Val<'u32'>) => {
          tmp[i].set(expandedKey[i].get());
          return [];
        });
        const blocks = u32.add(roundsState.get(), u32.const(1));
        f.doN([], blocks, (bi: Val<'u32'>) => {
          const dst = u32.mul(bi, u32.const(4));
          const src = u32.mul(u32.sub(u32.sub(blocks, u32.const(1)), bi), u32.const(4));
          for (let j = 0; j < 4; j++)
            expandedKey[u32.add(dst, u32.const(j))].set(tmp[u32.add(src, u32.const(j))].get());
          return [];
        });
        f.doN([], u32.sub(Nkf, u32.const(8)), (ri: Val<'u32'>) => {
          const i = u32.add(ri, u32.const(4));
          expandedKey[i].set(applyInvMix(u32, expandedKey[i].get()));
          return [];
        });
      });

// PKCS#7 for 16-byte blocks. Exposes module fns used by mkCipher when CipherDef.padding=true.
export const PCKS7 =
  () =>
  <
    M extends Segs & { buffer: ArraySpec<ScalarSpec<'u32'>, readonly [number, ...number[]]> },
    F extends FnRegistry,
  >(
    mod: Module<M, F>
  ) =>
    mod
      .fn('addPadding', ['u32', 'u32', 'u32'], 'u32', (f, take, left, blockLen) => {
        const { u32 } = f.types;
        const buffer = f.memory.buffer.as8('u8');
        const pad = u32.select(u32.eq(left, u32.const(0)), blockLen, left);
        const padBlocks = u32.select(u32.eq(left, u32.const(0)), u32.const(1), u32.const(0));
        for (let i = 0; i < 16; i++) {
          const ok = u32.lt(u32.const(i), pad);
          const idx = u32.add(take, u32.const(i));
          const cur = u32.fromN('u8', buffer[idx].get());
          buffer[idx].set(u32.castTo('u8', u32.select(ok, pad, cur)));
        }
        return padBlocks;
      })
      .fn('verifyPadding', ['u32', 'u32'], 'u32', (f, len, blockLen) => {
        const { u32 } = f.types;
        const buffer = f.memory.buffer.as8('u8');
        let bad = u32.or(u32.eq(len, u32.const(0)), u32.ne(u32.rem(len, blockLen), u32.const(0)));
        const last = u32.fromN('u8', buffer[u32.sub(len, u32.const(1))].get());
        bad = u32.or(bad, u32.or(u32.eq(last, u32.const(0)), u32.gt(last, blockLen)));
        let badBytes = u32.const(0);
        for (let i = 0; i < 16; i++) {
          const ok = u32.lt(u32.const(i), last);
          const idx = u32.sub(len, u32.add(u32.const(i), u32.const(1)));
          const cur = u32.fromN('u8', buffer[idx].get());
          badBytes = u32.or(badBytes, u32.and(ok, u32.ne(cur, last)));
        }
        bad = u32.or(bad, badBytes);
        return u32.select(bad, u32.const(0), last);
      });

export const roundBlocks = <M extends Segs>(
  f: Scope<M, {}>,
  round: Val<'u32'>,
  dir: AesDir,
  doMac: () => void,
  doCtr: () => void
) => {
  const { u32 } = f.types;
  // SIV-family round 0 is asymmetric: encrypt authenticates plaintext before CTR, while decrypt
  // runs CTR first so the candidate plaintext can be re-authenticated against the supplied tag/IV.
  if (dir === 'encrypt') {
    f.ifElse(u32.eq(round, u32.const(0)), [], doMac);
    f.ifElse(u32.ne(round, u32.const(0)), [], doCtr);
    return;
  }
  f.ifElse(u32.eq(round, u32.const(0)), [], doCtr);
  f.ifElse(u32.ne(round, u32.const(0)), [], doMac);
};

export type MemU32 = MemorySurface<{ mem: ArraySpec<ScalarSpec<'u32'>, readonly [number]> }>['mem'];
export type MemU32Scalar = MemorySurface<{ mem: ScalarSpec<'u32'> }>['mem'];

const applySbox = (
  u32: GetOps<'u32'>,
  sbox: MemU32,
  s0: Val<'u32'>,
  s1: Val<'u32'>,
  s2: Val<'u32'>,
  s3: Val<'u32'>
) => {
  // Caller passes words already permuted for ShiftRows/InvShiftRows; rebuild one state word by
  // S-boxing byte 0/1/2/3 from successive source words.
  const sb = sbox.as8('u8');
  const b0 = u32.fromN('u8', sb[u32.and(s0, u32.const(0xff))].get());
  const b1 = u32.shl(u32.fromN('u8', sb[u32.and(u32.shr(s1, 8), u32.const(0xff))].get()), 8);
  const b2 = u32.shl(u32.fromN('u8', sb[u32.and(u32.shr(s2, 16), u32.const(0xff))].get()), 16);
  const b3 = u32.shl(u32.fromN('u8', sb[u32.and(u32.shr(s3, 24), u32.const(0xff))].get()), 24);
  return u32.or(u32.or(b0, b1), u32.or(b2, b3));
};

const subWord = (u32: GetOps<'u32'>, sbox: MemU32, n: Val<'u32'>) => {
  // KEYEXPANSION SUBWORD(): apply the S-box to each byte of one word without the
  // cross-word byte reshuffle used by applySbox(...) in the final AES round.
  const sb = sbox.as8('u8');
  const b0 = u32.fromN('u8', sb[u32.and(n, u32.const(0xff))].get());
  const b1 = u32.shl(u32.fromN('u8', sb[u32.and(u32.shr(n, 8), u32.const(0xff))].get()), 8);
  const b2 = u32.shl(u32.fromN('u8', sb[u32.and(u32.shr(n, 16), u32.const(0xff))].get()), 16);
  const b3 = u32.shl(u32.fromN('u8', sb[u32.and(u32.shr(n, 24), u32.const(0xff))].get()), 24);
  return u32.or(u32.or(b0, b1), u32.or(b2, b3));
};

const aesExpandKey = <M extends Segs>(
  f: Scope<M, {}>,
  len: Val<'u32'>,
  key: MemU32,
  tmp: MemU32,
  expandedKey: MemU32,
  sbox: MemU32,
  xP: MemU32,
  roundsState: MemU32Scalar
) => {
  const { u32 } = f.types;
  const key8 = key.as8('u8');
  const xp8 = xP.as8('u8');
  const is16 = u32.eq(len, u32.const(16));
  const is24 = u32.eq(len, u32.const(24));
  const Nk = u32.select(is16, u32.const(4), u32.select(is24, u32.const(6), u32.const(8)));
  const rounds = u32.select(is16, u32.const(10), u32.select(is24, u32.const(12), u32.const(14)));
  const Nkf = u32.mul(u32.add(rounds, u32.const(1)), u32.const(4));
  roundsState.set(rounds);
  // AES-128/192/256 share one 60-word state buffer; clear the whole schedule so reinit with a
  // shorter key doesn't leave stale tail words from a previous longer expansion.
  for (let i = 0; i < EXPANDED_KEY_MAX; i++) expandedKey[i].set(u32.const(0));
  f.doN([], Nk, (i: Val<'u32'>) => {
    const off = u32.mul(i, u32.const(4));
    const b0 = u32.fromN('u8', key8[off].get());
    const b1 = u32.fromN('u8', key8[u32.add(off, u32.const(1))].get());
    const b2 = u32.fromN('u8', key8[u32.add(off, u32.const(2))].get());
    const b3 = u32.fromN('u8', key8[u32.add(off, u32.const(3))].get());
    const w = u32.or(b0, u32.or(u32.shl(b1, 8), u32.or(u32.shl(b2, 16), u32.shl(b3, 24))));
    tmp[i].set(w);
    return [];
  });
  f.doN([], u32.sub(Nkf, Nk), (ri: Val<'u32'>) => {
    const i = u32.add(ri, Nk);
    let t = tmp[u32.sub(i, u32.const(1))].get();
    const mod = u32.rem(i, Nk);
    const isMod0 = u32.eq(mod, u32.const(0));
    const isNk8 = u32.eq(Nk, u32.const(8));
    const isMod4 = u32.eq(mod, u32.const(4));
    const rot = u32.or(u32.shl(t, 24), u32.shr(t, 8));
    const xp = u32.fromN('u8', xp8[u32.sub(u32.div(i, Nk), u32.const(1))].get());
    const tMod0 = u32.xor(subWord(u32, sbox, rot), xp);
    const tMod4 = subWord(u32, sbox, t);
    t = u32.select(isMod0, tMod0, t);
    t = u32.select(u32.and(isNk8, isMod4), tMod4, t);
    t = u32.xor(t, tmp[u32.sub(i, Nk)].get());
    tmp[i].set(t);
    return [];
  });
  f.doN([], Nkf, (i: Val<'u32'>) => {
    expandedKey[i].set(tmp[i].get());
    return [];
  });
  return [Nk, Nkf];
};

// Forward SHIFTROWS source-column order by output column c: row r comes from input column
// (c + r) mod 4, so each lane lists the four source columns for rows 0..3.
const AES_ORDERS_ENC = [
  [0, 1, 2, 3],
  [1, 2, 3, 0],
  [2, 3, 0, 1],
  [3, 0, 1, 2],
];

// Inverse SHIFTROWS source-column order by output column c: row r comes from input column
// (c - r) mod 4, so each lane lists the four source columns for rows 0..3.
const AES_ORDERS_DEC = [
  [0, 3, 2, 1],
  [1, 0, 3, 2],
  [2, 1, 0, 3],
  [3, 2, 1, 0],
];

export const aesKeyInitEnc = <M extends Segs & { constants: typeof aesConsts }>(
  f: Scope<M, {}>,
  keyLen: Val<'u32'>,
  keyMem: MemU32,
  tmp: MemU32,
  expandedKey: MemU32,
  rounds: MemU32Scalar
) =>
  // Forward KEYEXPANSION always uses the encrypt S-box plus Rcon powers, even when callers later
  // derive decrypt-side data from the resulting schedule.
  aesExpandKey(
    f,
    keyLen,
    keyMem,
    tmp,
    expandedKey,
    f.memory.constants.encrypt.sbox,
    f.memory.constants.xPowers,
    rounds
  );

type RoundFn = (s0: Val<'u32'>, s1: Val<'u32'>, s2: Val<'u32'>, s3: Val<'u32'>) => Val<'u32'>;

export const aesWithBlock = <M extends Segs & { constants: typeof aesConsts }>(
  f: Scope<M, {}>,
  dir: AesDir,
  roundsVal: Val<'u32'>,
  expKey: MemU32,
  cb: (processBlock: (in4: Val<'u32'>[]) => Val<'u32'>[]) => void
) => {
  const { u32 } = f.types;
  const constants = f.memory.constants;
  const enc = constants.encrypt;
  const dec = constants.decrypt;
  const dirc = dir === 'encrypt' ? enc : dec;
  const orders = dir === 'encrypt' ? AES_ORDERS_ENC : AES_ORDERS_DEC;
  const roundFn: RoundFn = (s0, s1, s2, s3) => {
    // Fused main-round transform: laneRound(...) has already picked the row-shifted source words,
    // and T0..T3 supply the combined S-box + MixColumns/InvMixColumns contribution for one lane.
    return u32.xor(
      u32.xor(
        dirc.T0[u32.and(s0, u32.const(0xff))].get(),
        dirc.T1[u32.and(u32.shr(s1, 8), u32.const(0xff))].get()
      ),
      u32.xor(
        dirc.T2[u32.and(u32.shr(s2, 16), u32.const(0xff))].get(),
        dirc.T3[u32.and(u32.shr(s3, 24), u32.const(0xff))].get()
      )
    );
  };
  // Final AES round: laneFinal(...) already applied ShiftRows/InvShiftRows, so only
  // SBOX/INVSBOX remains here and AddRoundKey happens later in processBlock(...).
  const finalFn: RoundFn = (s0, s1, s2, s3) => applySbox(u32, dirc.sbox, s0, s1, s2, s3);
  const LANES = [0, 1, 2, 3] as const;
  const laneRound = (a: Val<'u32'>[], lane: (typeof LANES)[number]) => {
    // Pick the four source columns for one output lane after ShiftRows/InvShiftRows,
    // then hand that row-permuted view to the fused main-round helper.
    const o = orders[lane]!;
    return roundFn(a[o[0]]!, a[o[1]]!, a[o[2]]!, a[o[3]]!);
  };
  const laneFinal = (a: Val<'u32'>[], lane: (typeof LANES)[number]) => {
    // Same lane selection as laneRound(...), but for the last AES round where the
    // row-permuted words go through finalFn(...) instead of the T-table round path.
    const o = orders[lane]!;
    return finalFn(a[o[0]]!, a[o[1]]!, a[o[2]]!, a[o[3]]!);
  };

  // Dynamic rounds: single runtime loop driven by roundsVal.
  // This intentionally avoids compile-time unrolling to measure perf impact.
  const processBlock = (in4: Val<'u32'>[]): Val<'u32'>[] => {
    // Shared AES block skeleton: initial AddRoundKey, Nr-1 table rounds, then the final
    // S-box/row-shift round without MixColumns; `dir` selects the forward or inverse tables/order.
    // `expKey` is pre-arranged for the chosen direction: decryptInit rewrites/reverses the
    // schedule so the same [0..3], [4*r..], [4*Nr..] indexing works for both block flows.
    const s00 = u32.xor(in4[0]!, expKey[0].get());
    const s01 = u32.xor(in4[1]!, expKey[1].get());
    const s02 = u32.xor(in4[2]!, expKey[2].get());
    const s03 = u32.xor(in4[3]!, expKey[3].get());
    const main = u32.sub(roundsVal, u32.const(1));
    const res = f.doN1([s00, s01, s02, s03], main, (i, s0, s1, s2, s3) => {
      const r = u32.add(i, u32.const(1));
      const base = u32.mul(r, u32.const(4));
      const a = [s0, s1, s2, s3];
      return LANES.map((lane) =>
        u32.xor(expKey[u32.add(base, u32.const(lane))].get(), laneRound(a, lane))
      ) as unknown as [Val<'u32'>, Val<'u32'>, Val<'u32'>, Val<'u32'>];
    });
    const baseKey = u32.mul(roundsVal, u32.const(4));
    return LANES.map((lane) =>
      u32.xor(expKey[u32.add(baseKey, u32.const(lane))].get(), laneFinal(res, lane))
    ) as unknown as [Val<'u32'>, Val<'u32'>, Val<'u32'>, Val<'u32'>];
  };
  cb(processBlock);
};

export const aesInitTables = <M extends Segs & { constants: typeof aesConsts }>(
  f: Scope<M, {}>
) => {
  const constants = f.memory.constants;
  const { u32 } = f.types;
  f.ifElse(u32.eq(constants.inited.get(), u32.const(0)), [], () => {
    const sbox = constants.encrypt.sbox.as8('u8');
    const inv = constants.decrypt.sbox.as8('u8');
    const xp = constants.xPowers.as8('u8');
    // Scratch: use bytes over an output table to avoid allocating a dedicated 256-byte array.
    // Important: use runtime loops (f.doN) for 256*256 to avoid codegen blowups.
    const t = constants.encrypt.T0.as8('u8'); // length 1024 bytes, but we use only [0..255]
    // Generate the AES S-box, inverse S-box, Rcon powers, and both T-table families at runtime
    // so all derived constants stay tied to the same field arithmetic and affine-transform logic.

    const mul2 = (x: Val<'u32'>) => {
      const hi = u32.and(u32.shr(x, 7), u32.const(1));
      // AES reduction polynomial 0x11b, stored as the low-byte reduction constant after the shift.
      const red = u32.mul(hi, u32.const(0x1b));
      return u32.and(u32.xor(u32.shl(x, 1), red), u32.const(0xff));
    };
    const mulConst = (x: Val<'u32'>, c: number) => {
      let res = u32.const(0);
      let a = x;
      for (let bit = 0; bit < 8; bit++) {
        if (c & (1 << bit)) res = u32.xor(res, a);
        a = mul2(a);
      }
      return res;
    };
    // Build exp table t[0..255].
    f.doN1([u32.const(1)], u32.const(256), (i: Val<'u32'>, x: Val<'u32'>) => {
      t[i].set(u32.castTo('u8', x));
      return [u32.xor(x, mul2(x))];
    });

    // Build sbox using the parent algorithm.
    // AES affine-transform xor constant.
    sbox[0].set(u32.castTo('u8', u32.const(0x63)));
    f.doN([], u32.const(255), (i: Val<'u32'>) => {
      const ti = u32.fromN('u8', t[i].get());
      let y = u32.fromN('u8', t[u32.sub(u32.const(255), i)].get());
      y = u32.or(y, u32.shl(y, 8));
      const a = u32.xor(
        u32.xor(u32.xor(u32.xor(y, u32.shr(y, 4)), u32.shr(y, 5)), u32.shr(y, 6)),
        u32.shr(y, 7)
      );
      const v = u32.and(u32.xor(a, u32.const(0x63)), u32.const(0xff));
      sbox[ti].set(u32.castTo('u8', v));
      return [];
    });

    // invSbox.
    f.doN([], u32.const(256), (i: Val<'u32'>) => {
      inv[i].set(u32.castTo('u8', u32.const(0)));
      return [];
    });
    f.doN([], u32.const(256), (i: Val<'u32'>) => {
      const b = u32.fromN('u8', sbox[i].get());
      inv[b].set(u32.castTo('u8', i));
      return [];
    });

    // xPowers.
    f.doN1([u32.const(1)], u32.const(16), (i: Val<'u32'>, x: Val<'u32'>) => {
      xp[i].set(u32.castTo('u8', x));
      return [mul2(x)];
    });

    // Small tables (enc/dec).
    f.doN([], u32.const(256), (i: Val<'u32'>) => {
      const se = u32.fromN('u8', sbox[i].get());
      const sd = u32.fromN('u8', inv[i].get());
      const e2 = mulConst(se, 2);
      const e3 = mulConst(se, 3);
      const d9 = mulConst(sd, 9);
      const d11 = mulConst(sd, 11);
      const d13 = mulConst(sd, 13);
      const d14 = mulConst(sd, 14);
      constants.encrypt.T0[i].set(
        u32.or(u32.shl(e3, 24), u32.or(u32.shl(se, 16), u32.or(u32.shl(se, 8), e2)))
      );
      constants.decrypt.T0[i].set(
        u32.or(u32.shl(d11, 24), u32.or(u32.shl(d13, 16), u32.or(u32.shl(d9, 8), d14)))
      );
      return [];
    });
    f.doN([], u32.const(256), (i: Val<'u32'>) => {
      const e0 = constants.encrypt.T0[i].get();
      const e1 = u32.rotl(e0, 8);
      const e2 = u32.rotl(e1, 8);
      constants.encrypt.T1[i].set(e1);
      constants.encrypt.T2[i].set(e2);
      constants.encrypt.T3[i].set(u32.rotl(e2, 8));
      const d0 = constants.decrypt.T0[i].get();
      const d1 = u32.rotl(d0, 8);
      const d2 = u32.rotl(d1, 8);
      constants.decrypt.T1[i].set(d1);
      constants.decrypt.T2[i].set(d2);
      constants.decrypt.T3[i].set(u32.rotl(d2, 8));
      return [];
    });

    constants.inited.set(u32.const(1));
  });
};

// Swap one 32-bit word between local/native word packing and spec-defined big-endian octet order.
export const bswap32 = (u32: GetOps<'u32'>, x: Val<'u32'>) =>
  u32.or(
    u32.or(u32.shl(u32.and(x, u32.const(0xff)), 24), u32.shl(u32.and(x, u32.const(0xff00)), 8)),
    u32.or(u32.shr(u32.and(x, u32.const(0xff0000)), 8), u32.shr(x, 24))
  );

// Generic counter increment helpers.
//
// - Counters are represented as `u32` limbs.
// - Carry propagates across all limbs provided.
// - `isBE` selects which end is least significant:
//   - `true`: least significant limb is last (big-endian limb order).
//   - `false`: least significant limb is first (little-endian limb order).
//
// Intended usage:
// - In threads/batch kernels: derive per-block counters in locals (use `inplace`) and never
//   touch shared state.
// - After batching: update the stored counter once (use `memory`).
export const incCounter = <M extends Segs>(f: Scope<M, {}>, isBE = false) => ({
  inplace: (limbs: Val<'u32'>[], inc: Val<'u32'>): Val<'u32'>[] => {
    const { u32 } = f.types;
    // Hot-path for one-word counters: GCM/GCTR uses a big-endian inc32 word, while
    // AES-GCM-SIV uses a little-endian low word with the same modulo-2^32 wrap.
    // Keep this straight-line to avoid injecting a `block + brIf` structure into every iteration.
    if (limbs.length === 1) {
      const a0 = limbs[0]!;
      if (isBE) {
        const curBE = bswap32(u32, a0);
        const sumBE = u32.add(curBE, inc);
        return [bswap32(u32, sumBE)];
      }
      return [u32.add(a0, inc)];
    }
    if (isBE) {
      // `limbs` are in native/AES word packing.
      // For BE counter semantics, we do arithmetic in the BE-byte
      // domain via bswap, then bswap back.
      return f
        .block([inc, ...limbs], (carry, ...a) => {
          for (let i = 0; i < a.length; i++) {
            const idx = a.length - 1 - i;
            const curLE = a[idx];
            const curBE = bswap32(u32, curLE);
            const sumBE = u32.add(curBE, carry);
            a[idx] = bswap32(u32, sumBE);
            carry = u32.and(u32.lt(sumBE, curBE), u32.const(1));
            f.brIf(0, u32.eq(carry, u32.const(0)), carry, ...a);
          }
          return [carry, ...a];
        })
        .slice(1) as Val<'u32'>[];
    }
    return f
      .block([inc, ...limbs], (carry, ...a) => {
        for (let i = 0; i < a.length; i++) {
          const idx = isBE ? a.length - 1 - i : i;
          const cur = a[idx];
          const sum = u32.add(cur, carry);
          a[idx] = sum;
          carry = u32.and(u32.lt(sum, cur), u32.const(1));
          f.brIf(0, u32.eq(carry, u32.const(0)), carry, ...a);
        }
        return [carry, ...a];
      })
      .slice(1) as Val<'u32'>[];
  },
  memory: (
    limbs: MemorySurface<{ limbs: ArraySpec<ScalarSpec<'u32'>, readonly [number]> }>['limbs'],
    inc: Val<'u32'>
  ) => {
    // Add a 32-bit value into the counter's byte representation.
    // Carry propagation still early-exits when possible.
    //
    // This is used for the single post-batch state update, which is thread-safe,
    // and also for JS per-block updates.
    const { u32 } = f.types;
    const b = limbs.as8('u8');
    const n = limbs.length * 4;
    f.block([inc], (carry) => {
      for (let i = 0; i < n; i++) {
        const idx = isBE ? n - 1 - i : i;
        const bi = u32.fromN('u8', b[u32.const(idx)].get());
        const sum = u32.add(bi, u32.and(carry, u32.const(0xff)));
        b[u32.const(idx)].set(u32.castTo('u8', sum));
        carry = u32.add(u32.shr(carry, 8), u32.shr(sum, 8));
        f.brIf(0, u32.eq(carry, u32.const(0)), carry);
      }
      return [carry];
    });
  },
});

// CMAC subkey doubling in GF(2^128): K1 = dbl(L), K2 = dbl(K1).
export const cmacDbl = <M extends Segs>(f: Scope<M, {}>, src: MemU32) => {
  const { u32 } = f.types;
  const sb = src.as8('u8');
  let carry = u32.const(0);
  [carry] = f.doN1([carry], u32.const(16), (i: Val<'u32'>, carry: Val<'u32'>) => {
    const idx = u32.sub(u32.const(15), i);
    const v = u32.and(u32.fromN('u8', sb[idx].get()), u32.const(0xff));
    const n = u32.and(u32.or(u32.shl(v, 1), carry), u32.const(0xff));
    sb[idx].set(u32.castTo('u8', n));
    return [u32.shr(v, 7)];
  });
  const mask = u32.sub(u32.const(0), carry);
  sb[15].set(
    u32.castTo('u8', u32.xor(u32.fromN('u8', sb[15].get()), u32.and(mask, u32.const(0x87))))
  );
};

export const cmacXor = (
  u32: GetOps<'u32'>,
  bv: Val<'u32'>[],
  iv: Val<'u32'>[],
  k1: Val<'u32'>[],
  k2: Val<'u32'>[],
  useK: Val<'u32'>,
  useK2: Val<'u32'>
) =>
  bv.map((x, i) => {
    // CMAC last-block combiner: optionally xor K1/K2 into the message block first,
    // then xor the chaining value before the single AES block call.
    const kb = u32.select(useK2, k2[i], k1[i]);
    const withK = u32.xor(x, kb);
    const v = u32.select(useK, withK, x);
    return u32.xor(v, iv[i]);
  });

export const cmacSubkeysInit = <M extends Segs & { constants: typeof aesConsts }>(
  f: Scope<M, {}>,
  len: Val<'u32'>,
  st: {
    key: MemU32;
    tmp: MemU32;
    expandedKey: MemU32;
    rounds: MemU32Scalar;
    k1: MemU32;
    k2: MemU32;
    iv: MemU32;
  }
) => {
  const { u32 } = f.types;
  aesInitTables(f);
  aesKeyInitEnc(f, len, st.key, st.tmp, st.expandedKey, st.rounds);
  aesWithBlock(f, 'encrypt', st.rounds.get(), st.expandedKey, (processBlock) => {
    // Reuse k1 as the RFC 4493 `L = AES_K(0^128)` scratch, then clone the derived K1
    // into k2 so the second doubling step can produce K2 without another AES block call.
    st.k1.set(processBlock([u32.const(0), u32.const(0), u32.const(0), u32.const(0)]));
  });
  cmacDbl(f, st.k1);
  st.k2.set(st.k1.get());
  cmacDbl(f, st.k2);
  st.iv.set([u32.const(0), u32.const(0), u32.const(0), u32.const(0)]);
};

export const genCmac = (_type: TypeName, _opts: {}) =>
  new Module('cmac')
    .batchMem(
      'state',
      struct({
        state: array('u32', {}, 4),
        key: array('u32', {}, KEY_LEN_MAX),
        expandedKey: array('u32', {}, EXPANDED_KEY_MAX),
        tmp: array('u32', {}, EXPANDED_KEY_MAX),
        k1: array('u32', {}, 4),
        k2: array('u32', {}, 4),
        iv: array('u32', {}, 4),
        rounds: 'u32',
        tag: array('u32', {}, 4),
      })
    )
    .mem('constants', aesConsts)
    .mem('buffer', array('u32', {}, AES_BLOCKS, 4))
    .fn(
      'reset',
      ['u32', 'u32', 'u32', 'u32', 'u32'],
      'void',
      (f, batchPos, batchLen, maxWritten, blockLen, maxBlocks) => {
        const { u32 } = f.types;
        const perBlock = u32.div(blockLen, u32.const(4));
        f.memory.state.range(batchPos, batchLen).as8('u8').zero();
        const buffer = f.memory.buffer.reshape(batchPos, maxBlocks, perBlock);
        f.doN([], batchLen, (cnt: Val<'u32'>) => {
          buffer[u32.add(batchPos, cnt)].as8('u8').range(0, maxWritten).fill(0);
          return [];
        });
      }
    )
    .fn(
      'padding',
      ['u32', 'u32', 'u32', 'u32', 'u32', 'u32'],
      'u32',
      (f, batchPos, take, maxBlocks, left, _blockLen, _suffix) => {
        const { u32 } = f.types;
        const buffer = f.memory.buffer.reshape(batchPos, maxBlocks, 4)[batchPos].as8('u8');
        const isEmpty = u32.eq(take, u32.const(0));
        const hasLeft = u32.ne(left, u32.const(0));
        f.ifElse(isEmpty, [], () => {
          buffer[0].set(u32.castTo('u8', u32.const(0x80)));
          buffer.range(u32.const(1), u32.const(AES_BLOCK_LEN)).fill(0);
        });
        f.ifElse(hasLeft, [], () => {
          const off = take;
          buffer[off].set(u32.castTo('u8', u32.const(0x80)));
          for (let i = 1; i < AES_BLOCK_LEN; i++) {
            const ok = u32.lt(u32.const(i), left);
            const idx = u32.add(off, u32.const(i));
            const cur = u32.fromN('u8', buffer[idx].get());
            buffer[idx].set(u32.castTo('u8', u32.select(ok, u32.const(0), cur)));
          }
        });
        return u32.select(isEmpty, u32.const(1), u32.const(0));
      }
    )
    .fn('macInit', ['u32', 'u32'], 'void', (f, batchPos, len) => {
      const { u32 } = f.types;
      const st = f.memory.state[batchPos];
      cmacSubkeysInit(f, len, st);
      st.state.set([u32.const(0), u32.const(0), u32.const(0), u32.const(0)]);
    })
    .fn(
      'processBlocks',
      ['u32', 'u32', 'u32', 'u32', 'u32', 'u32', 'u32', 'u32'],
      'void',
      (f, batchPos, batchLen, blocks, maxBlocks, _blockLen, isLast, left, padBlocks) => {
        const { u32 } = f.types;
        f.doN([], batchLen, (cnt: Val<'u32'>) => {
          const cur = u32.add(batchPos, cnt);
          const st = f.memory.state[cur];
          const { k1, k2, iv } = st;
          const buffer = f.memory.buffer.reshape(batchPos, maxBlocks, 4)[cur];
          const lastIdx = u32.sub(blocks, u32.const(1));
          const roundsVal = st.rounds.get();
          const expKey = st.expandedKey;
          aesWithBlock(f, 'encrypt', roundsVal, expKey, (processBlock) => {
            const ivVal = f.doN1(iv.get(), blocks, (chunkPos: Val<'u32'>, ...ivv: Val<'u32'>[]) => {
              const isFinal = u32.and(isLast, u32.eq(chunkPos, lastIdx));
              // Empty-input CMAC still uses K2: `padBlocks != 0` marks the synthetic padded block
              // even when `left == 0`, matching RFC 4493's `n := 1; flag := false` path.
              const hasLeft = u32.or(u32.ne(left, u32.const(0)), u32.ne(padBlocks, u32.const(0)));
              const useK2 = u32.and(isFinal, hasLeft);
              const useK = isFinal;
              const b = buffer[chunkPos];
              const bv = readMSG(f, b);
              return processBlock(cmacXor(u32, bv, ivv, k1.get(), k2.get(), useK, useK2));
            });
            iv.set(ivVal);
            st.state.set(ivVal);
          });
          return [];
        });
      }
    )
    .fn(
      'processOutBlocks',
      ['u32', 'u32', 'u32', 'u32', 'u32', 'u32'],
      'void',
      (f, batchPos, batchLen, blocks, maxBlocks, _outBlockLen, _isLast) => {
        const { u32 } = f.types;
        const buffer = f.memory.buffer.reshape(batchPos, maxBlocks, 4);
        f.doN([], batchLen, (cnt: Val<'u32'>) => {
          const cur = u32.add(batchPos, cnt);
          const iv = f.memory.state[cur].iv;
          const rows = buffer[cur];
          f.doN([], blocks, (chunkPos) => {
            rows[chunkPos].set(iv.get());
            return [];
          });
          return [];
        });
      }
    );

// Shared batchFn calling convention (new core API):
// - If threads are available (`f.flags.threads`), shard:
//   `batchLen=ceil(blocks/perBatch)`, `perBatch=MIN_PER_THREAD`
// - Otherwise (js/wasm without threads), call sequentially:
//   `batchLen=1`, `perBatch=blocks`
// - Kernels must compute `base=batchPos*perBatch` and clamp
//   `iters=min(perBatch, blocks-base)` so there is a single call site
//   without trailing calls/branches that duplicate AES call sites.
export const callBatch = <M extends Segs, F extends FnRegistry>(
  f: Scope<M, F>,
  blocks: Val<'u32'>,
  call: (batchPos: Val<'u32'>, batchLen: Val<'u32'>, perBatch: Val<'u32'>) => void
) => {
  const { u32 } = f.types;
  f.ifElse(u32.ne(blocks, u32.const(0)), [], () => {
    if (!f.flags.threads) return call(u32.const(0), u32.const(1), blocks);
    const perBatch = u32.const(MIN_PER_THREAD);
    call(u32.const(0), u32.div(u32.add(blocks, u32.const(MIN_PER_THREAD - 1)), perBatch), perBatch);
  });
};

export const genAesEcb = (_type: TypeName, _opts: {}) =>
  new Module('aes_ecb')
    .mem(
      'state',
      struct({
        key: array('u32', {}, 8),
        expandedKey: array('u32', {}, EXPANDED_KEY_MAX),
        tmp: array('u32', {}, EXPANDED_KEY_MAX),
        rounds: 'u32',
      })
    )
    .mem('constants', aesConsts)
    .mem('buffer', array('u32', {}, AES_BLOCKS, 4))
    .use(PCKS7())
    .use(aesInitKeys({ withDecrypt: true }))
    .fn('reset', ['u32'], 'void', (f, maxWritten) => {
      f.memory.state.as8('u8').zero();
      f.memory.buffer.as8().range(0, maxWritten).fill(0);
    })
    .use(
      aesBatchFn(
        'processBlocksEnc',
        'encrypt',
        (_f, _batchPos, _perBatch) => [],
        (f, z, processBlock, pos) => {
          const b = f.memory.buffer[pos];
          b.set(processBlock(b.get()));
          return z;
        }
      )
    )
    .use(
      aesBatchFn(
        'processBlocksDec',
        'decrypt',
        (_f, _batchPos, _perBatch) => [],
        (f, z, processBlock, pos) => {
          const b = f.memory.buffer[pos];
          b.set(processBlock(b.get()));
          return z;
        }
      )
    )
    .fn('encryptBlocks', ['u32', 'u32', 'u32'], 'void', (f, blocks, _isLast, _left) => {
      callBatch(f, blocks, (batchPos, batchLen, perBatch) => {
        f.functions.processBlocksEnc.call(batchPos, batchLen, perBatch, blocks);
      });
    })
    .fn('decryptBlocks', ['u32', 'u32', 'u32'], 'void', (f, blocks, _isLast, _left) => {
      callBatch(f, blocks, (batchPos, batchLen, perBatch) => {
        f.functions.processBlocksDec.call(batchPos, batchLen, perBatch, blocks);
      });
    });

export const genAesCbc = (_type: TypeName, _opts: {}) =>
  new Module('aes_cbc')
    .mem(
      'state',
      struct({
        key: array('u32', {}, KEY_LEN_MAX),
        expandedKey: array('u32', {}, EXPANDED_KEY_MAX),
        tmp: array('u32', {}, EXPANDED_KEY_MAX),
        rounds: 'u32',
        iv: array('u32', {}, 4),
      })
    )
    .mem('constants', aesConsts)
    .mem('buffer', array('u32', {}, AES_BLOCKS, 4))
    .use(PCKS7())
    .use(aesInitKeys({ withDecrypt: true }))
    .fn('reset', ['u32'], 'void', (f, maxWritten) => {
      f.memory.state.as8('u8').zero();
      f.memory.buffer.as8().range(0, maxWritten).fill(0);
    })
    .fn('encryptBlocks', ['u32', 'u32', 'u32'], 'void', (f, blocks, _isLast, _left) => {
      const { u32 } = f.types;
      const roundsVal = f.memory.state.rounds.get();
      const expKey = f.memory.state.expandedKey;
      aesWithBlock(f, 'encrypt', roundsVal, expKey, (processBlock) => {
        f.doN([], blocks, (bi: Val<'u32'>) => {
          const b = f.memory.buffer[bi];
          const m = b.get();
          const iv = f.memory.state.iv.get();
          const out = processBlock(m.map((x, j) => u32.xor(x, iv[j])));
          b.set(out);
          f.memory.state.iv.set(out);
          return [];
        });
      });
    })
    .fn('decryptBlocks', ['u32', 'u32', 'u32'], 'void', (f, blocks, _isLast, _left) => {
      const { u32 } = f.types;
      const roundsVal = f.memory.state.rounds.get();
      const expKey = f.memory.state.expandedKey;
      aesWithBlock(f, 'decrypt', roundsVal, expKey, (processBlock) => {
        f.doN([], blocks, (bi: Val<'u32'>) => {
          const b = f.memory.buffer[bi];
          const c = b.get();
          const out = processBlock(c);
          const iv = f.memory.state.iv.get();
          b.set(out.map((x, j) => u32.xor(x, iv[j])));
          f.memory.state.iv.set(c);
          return [];
        });
      });
    });

export const genAesCfb = (_type: TypeName, _opts: {}) =>
  new Module('aes_cfb')
    .mem(
      'state',
      struct({
        key: array('u32', {}, KEY_LEN_MAX),
        expandedKey: array('u32', {}, EXPANDED_KEY_MAX),
        tmp: array('u32', {}, EXPANDED_KEY_MAX),
        rounds: 'u32',
        iv: array('u32', {}, 4),
      })
    )
    .mem('constants', aesConsts)
    .mem('buffer', array('u32', {}, AES_BLOCKS, 4))
    .use(aesInitKeys({ withDecrypt: false }))
    .fn('reset', ['u32'], 'void', (f, maxWritten) => {
      f.memory.state.as8('u8').zero();
      f.memory.buffer.as8().range(0, maxWritten).fill(0);
    })
    .fn('encryptBlocks', ['u32', 'u32', 'u32'], 'void', (f, blocks, _isLast, _left) => {
      const { u32 } = f.types;
      const roundsVal = f.memory.state.rounds.get();
      const expKey = f.memory.state.expandedKey;
      aesWithBlock(f, 'encrypt', roundsVal, expKey, (processBlock) => {
        f.doN([], blocks, (bi: Val<'u32'>) => {
          const b = f.memory.buffer[bi];
          const m = b.get();
          const iv = f.memory.state.iv.get();
          const stream = processBlock(iv);
          const out = m.map((x, j) => u32.xor(x, stream[j]));
          b.set(out);
          f.memory.state.iv.set(out);
          return [];
        });
      });
    })
    .fn('decryptBlocks', ['u32', 'u32', 'u32'], 'void', (f, blocks, _isLast, _left) => {
      const { u32 } = f.types;
      const roundsVal = f.memory.state.rounds.get();
      const expKey = f.memory.state.expandedKey;
      aesWithBlock(f, 'encrypt', roundsVal, expKey, (processBlock) => {
        f.doN([], blocks, (bi: Val<'u32'>) => {
          const b = f.memory.buffer[bi];
          const c = b.get();
          const iv = f.memory.state.iv.get();
          const stream = processBlock(iv);
          b.set(c.map((x, j) => u32.xor(x, stream[j])));
          f.memory.state.iv.set(c);
          return [];
        });
      });
    });

export const genAesOfb = (_type: TypeName, _opts: {}) =>
  new Module('aes_ofb')
    .mem(
      'state',
      struct({
        key: array('u32', {}, KEY_LEN_MAX),
        expandedKey: array('u32', {}, EXPANDED_KEY_MAX),
        tmp: array('u32', {}, EXPANDED_KEY_MAX),
        rounds: 'u32',
        iv: array('u32', {}, 4),
      })
    )
    .mem('constants', aesConsts)
    .mem('buffer', array('u32', {}, AES_BLOCKS, 4))
    .use(aesInitKeys({ withDecrypt: false }))
    .fn('reset', ['u32'], 'void', (f, maxWritten) => {
      f.memory.state.as8('u8').zero();
      f.memory.buffer.as8().range(0, maxWritten).fill(0);
    })
    .fn('encryptBlocks', ['u32', 'u32', 'u32'], 'void', (f, blocks, _isLast, _left) => {
      const { u32 } = f.types;
      const roundsVal = f.memory.state.rounds.get();
      const expKey = f.memory.state.expandedKey;
      aesWithBlock(f, 'encrypt', roundsVal, expKey, (processBlock) => {
        f.doN([], blocks, (bi: Val<'u32'>) => {
          const b = f.memory.buffer[bi];
          const m = b.get();
          const iv = f.memory.state.iv.get();
          const stream = processBlock(iv);
          b.set(m.map((x, j) => u32.xor(x, stream[j])));
          f.memory.state.iv.set(stream);
          return [];
        });
      });
    })
    .fn('decryptBlocks', ['u32', 'u32', 'u32'], 'void', (f, blocks, isLast, left) => {
      f.functions.encryptBlocks.call(blocks, isLast, left);
    });

export const genAesCtr = (_type: TypeName, _opts: {}) => {
  return new Module('aes_ctr')
    .mem(
      'state',
      struct({
        key: array('u32', {}, KEY_LEN_MAX),
        expandedKey: array('u32', {}, EXPANDED_KEY_MAX),
        tmp: array('u32', {}, EXPANDED_KEY_MAX),
        rounds: 'u32',
        nonce: array('u32', {}, 4),
      })
    )
    .mem('constants', aesConsts)
    .mem('buffer', array('u32', {}, AES_BLOCKS, 4))
    .use(aesInitKeys({ withDecrypt: false }))
    .fn('reset', ['u32'], 'void', (f, maxWritten) => {
      f.memory.state.as8('u8').zero();
      f.memory.buffer.as8().range(0, maxWritten).fill(0);
    })
    .use(
      aesBatchFn(
        'processBlocks',
        'encrypt',
        (f, batchPos, perBatch) => {
          const { u32 } = f.types;
          const base = u32.mul(batchPos, perBatch);
          return incCounter(f, true).inplace(f.memory.state.nonce.get(), base);
        },
        (f, ctr, processBlock, pos) => {
          const { u32 } = f.types;
          const ks = processBlock(ctr);
          const b = f.memory.buffer[pos];
          b.set(b.get().map((x, i) => u32.xor(x, ks[i])));
          return incCounter(f, true).inplace(ctr, u32.const(1));
        }
      )
    )
    .fn('encryptBlocks', ['u32', 'u32', 'u32'], 'void', (f, blocks, _isLast, _left) => {
      callBatch(f, blocks, (batchPos, batchLen, perBatch) => {
        f.functions.processBlocks.call(batchPos, batchLen, perBatch, blocks);
      });
      incCounter(f, true).memory(f.memory.state.nonce, blocks);
    })
    .fn('decryptBlocks', ['u32', 'u32', 'u32'], 'void', (f, blocks, isLast, left) => {
      f.functions.encryptBlocks.call(blocks, isLast, left);
    });
};

export const genAesGcm = (_type: TypeName, _opts: {}) => {
  return new Module('aes_gcm')
    .mem(
      'state',
      struct({
        key: array('u32', {}, KEY_LEN_MAX),
        expandedKey: array('u32', {}, EXPANDED_KEY_MAX),
        tmp: array('u32', {}, EXPANDED_KEY_MAX),
        nonce: array('u32', {}, 4),
        rounds: 'u32',
        aadLen: 'u64',
        dataLen: 'u64',
        tagMask: array('u32', {}, 4),
        tag: array('u32', {}, 4),
        ghash: ghashState(),
        table64v: array('u64x2', {}, GHASH_U64X2_TABLE_ENTRIES),
        tmp64v: array('u64x2', {}, GHASH_U64X2_W),
      })
    )
    .mem('constants', aesConsts)
    .mem('buffer', array('u32', {}, AES_BLOCKS, 4))
    .fn('reset', ['u32'], 'void', (f, maxWritten) => {
      f.memory.state.as8('u8').zero();
      f.memory.buffer.as8().range(0, maxWritten).fill(0);
    })
    .fn('padLast', ['u32', 'u32', 'u32'], 'void', (f, blocks, isLast, left) => {
      const { u32 } = f.types;
      f.ifElse(u32.and(isLast, u32.ne(left, u32.const(0))), [], () => {
        const buf8 = f.memory.buffer.as8('u8');
        const start = u32.sub(u32.mul(blocks, u32.const(AES_BLOCK_LEN)), left);
        buf8.range(start, u32.add(start, left)).fill(0);
      });
    })
    .fn('ghashBlocks', ['u32'], 'void', (f, blocks) => {
      const table = f.memory.state.table64v.reshape(GHASH_U64X2_TABLE_ENTRIES);
      const y64 = f.memory.state.ghash.y64;
      const buffer = f.memory.buffer.as('u64x2').reshape(AES_BLOCKS);
      ghashBlocksTableCore64v(f, blocks, buffer, y64, table, 'ghash');
    })
    .fn('gcmInitJ0', [], 'void', (f) => {
      const { u32 } = f.types;
      const roundsVal = f.memory.state.rounds.get();
      const expKey = f.memory.state.expandedKey;
      aesWithBlock(f, 'encrypt', roundsVal, expKey, (processBlock) => {
        f.memory.state.tagMask.set(processBlock(f.memory.state.nonce.get()));
      });
      incCounter(f, true).memory(f.memory.state.nonce.range(3, 1), u32.const(1));
    })
    .use(
      aesBatchFn(
        'processBlocks',
        'encrypt',
        (f, batchPos, perBatch) => {
          const { u32 } = f.types;
          const n = f.memory.state.nonce.get();
          const base = u32.mul(batchPos, perBatch);
          const ctr3 = incCounter(f, true).inplace([n[3]], base)[0];
          return { n0: n[0], n1: n[1], n2: n[2], ctr3 };
        },
        (f, ctr, processBlock, pos) => {
          const { u32 } = f.types;
          const b = f.memory.buffer[pos];
          const ks = processBlock([ctr.n0, ctr.n1, ctr.n2, ctr.ctr3]);
          b.set(b.get().map((x, j) => u32.xor(x, ks[j])));
          return {
            n0: ctr.n0,
            n1: ctr.n1,
            n2: ctr.n2,
            ctr3: incCounter(f, true).inplace([ctr.ctr3], u32.const(1))[0],
          };
        }
      )
    )
    .fn('aadInit', [], 'void', (f) => {
      const { u32, u64x2 } = f.types;
      f.memory.state.ghash.y.set([u32.const(0), u32.const(0), u32.const(0), u32.const(0)]);
      f.memory.state.ghash.y64.set(u64x2.const(0));
    })
    .fn('aadBlocks', ['u32', 'u32', 'u32'], 'void', (f, blocks, _isLast, _left) => {
      f.functions.ghashBlocks.call(blocks);
    })
    .fn(
      'encryptInit',
      ['u32', 'u32', 'u32', 'u32', 'u32', 'u32'],
      'void',
      (f, len, nonceLen, _nonceBitsLo, _nonceBitsHi, aadLo, aadHi) => {
        const { u32, u64 } = f.types;
        // reset() clears module state between public operations, so a key-hash
        // cache here never survives long enough to hit.
        // Keep init direct and exact instead of carrying unreachable cache machinery.
        aesInitTables(f);
        aesKeyInitEnc(
          f,
          len,
          f.memory.state.key,
          f.memory.state.tmp,
          f.memory.state.expandedKey,
          f.memory.state.rounds
        );
        {
          const roundsVal = f.memory.state.rounds.get();
          const expKey = f.memory.state.expandedKey;
          aesWithBlock(f, 'encrypt', roundsVal, expKey, (processBlock) => {
            f.memory.state.ghash.h.set(
              processBlock([u32.const(0), u32.const(0), u32.const(0), u32.const(0)])
            );
          });
        }
        {
          const h = f.memory.state.ghash.h;
          const table = f.memory.state.table64v.reshape(GHASH_U64X2_TABLE_ENTRIES);
          const tmp = f.memory.state.tmp64v.reshape(GHASH_U64X2_W);
          ghashInitTableCore64v(f, h, table, tmp, 'ghash');
        }
        f.memory.state.aadLen.set(u64.fromN('u32', [aadLo, aadHi]));
        f.memory.state.dataLen.set(u64.const(0));
        f.memory.state.tagMask.as8('u8').zero();
        f.memory.state.tag.as8('u8').zero();
        f.ifElse(u32.eq(nonceLen, u32.const(12)), [], () => {
          const nonce = f.memory.state.nonce.as8('u8');
          nonce[15].set(u32.castTo('u8', u32.const(1)));
          f.functions.gcmInitJ0.call();
        });
      }
    )
    .fn('nonceFinish', ['u32', 'u32'], 'void', (f, nonceBitsLo, nonceBitsHi) => {
      const { u32, u64, u64x2 } = f.types;
      const nonceBits = u64.fromN('u32', [nonceBitsLo, nonceBitsHi]);
      {
        const buf8 = f.memory.buffer.as8('u8');
        buf8[0].write('u64', u64.const(0));
        buf8[8].write('u64', u64.swapEndianness(nonceBits));
      }
      f.functions.ghashBlocks.call(u32.const(1));
      const y64 = f.memory.state.ghash.y64;
      const nonce = f.memory.state.nonce;
      const y = y64.get();
      const yv = u64
        .from('u64x2', y)
        .map((w) => u32.from('u64', w))
        .flat();
      nonce.set(yv);
      y64.set(u64x2.const(0));
      f.functions.gcmInitJ0.call();
    })
    .fn(
      'decryptInit',
      ['u32', 'u32', 'u32', 'u32', 'u32', 'u32'],
      'void',
      (f, len, nonceLen, nonceBitsLo, nonceBitsHi, aadLo, aadHi) => {
        f.functions.encryptInit.call(len, nonceLen, nonceBitsLo, nonceBitsHi, aadLo, aadHi);
      }
    )
    .fn('encryptBlocks', ['u32', 'u32', 'u32'], 'void', (f, blocks, isLast, left) => {
      const { u32, u64 } = f.types;
      const bytes = u32.sub(u32.mul(blocks, u32.const(AES_BLOCK_LEN)), left);
      f.memory.state.dataLen.set(u64.add(f.memory.state.dataLen.get(), u64.fromN('u32', bytes)));
      callBatch(f, blocks, (batchPos, batchLen, perBatch) => {
        f.functions.processBlocks.call(batchPos, batchLen, perBatch, blocks);
      });
      incCounter(f, true).memory(f.memory.state.nonce.range(3, 1), blocks);
      f.functions.padLast.call(blocks, isLast, left);
      f.functions.ghashBlocks.call(blocks);
    })
    .fn('decryptBlocks', ['u32', 'u32', 'u32'], 'void', (f, blocks, isLast, left) => {
      const { u32, u64 } = f.types;
      const bytes = u32.sub(u32.mul(blocks, u32.const(AES_BLOCK_LEN)), left);
      f.memory.state.dataLen.set(u64.add(f.memory.state.dataLen.get(), u64.fromN('u32', bytes)));
      f.functions.padLast.call(blocks, isLast, left);
      f.functions.ghashBlocks.call(blocks);
      callBatch(f, blocks, (batchPos, batchLen, perBatch) => {
        f.functions.processBlocks.call(batchPos, batchLen, perBatch, blocks);
      });
      incCounter(f, true).memory(f.memory.state.nonce.range(3, 1), blocks);
    })
    .fn('tagFinish', [], 'void', (f) => {
      const { u32, u64 } = f.types;
      const aadBits = u64.mul(f.memory.state.aadLen.get(), u64.const(8));
      const dataBits = u64.mul(f.memory.state.dataLen.get(), u64.const(8));
      {
        const buf8 = f.memory.buffer.as8('u8');
        buf8[0].write('u64', u64.swapEndianness(aadBits));
        buf8[8].write('u64', u64.swapEndianness(dataBits));
      }
      f.functions.ghashBlocks.call(u32.const(1));
      const y = f.memory.state.ghash.y64.get();
      const yv = u64
        .from('u64x2', y)
        .map((w) => u32.from('u64', w))
        .flat();
      const mask = f.memory.state.tagMask.get();
      f.memory.state.tag.set(yv.map((x, j) => u32.xor(x, mask[j])));
    });
};

export const genAesGcmSiv = (_type: TypeName, _opts: {}) => {
  return new Module('aes_gcmsiv')
    .mem(
      'state',
      struct({
        key: array('u32', {}, KEY_LEN_MAX),
        encKey: array('u32', {}, KEY_LEN_MAX),
        expandedKey: array('u32', {}, EXPANDED_KEY_MAX),
        tmp: array('u32', {}, EXPANDED_KEY_MAX * 2),
        rounds: 'u32',
        nonce: array('u32', {}, 4),
        ctr: array('u32', {}, 4),
        aadLen: 'u64',
        dataLen: 'u64',
        tag: array('u32', {}, 4),
        ctrReady: 'u32',
        ghash: ghashState(),
        table64v: array('u64x2', {}, GHASH_U64X2_TABLE_ENTRIES),
        tmp64v: array('u64x2', {}, GHASH_U64X2_W),
      })
    )
    .mem('constants', aesConsts)
    .mem('buffer', array('u32', {}, AES_BLOCKS, 4))
    .fn('reset', ['u32'], 'void', (f, maxWritten) => {
      f.memory.state.as8('u8').zero();
      f.memory.buffer.as8().range(0, maxWritten).fill(0);
    })
    .fn('polyBlocks', ['u32', 'u32', 'u32'], 'void', (f, blocks, isLast, left) => {
      const { u32 } = f.types;
      f.ifElse(u32.and(isLast, u32.ne(left, u32.const(0))), [], () => {
        const buf8 = f.memory.buffer.as8('u8');
        const start = u32.sub(u32.mul(blocks, u32.const(AES_BLOCK_LEN)), left);
        buf8.range(start, u32.add(start, left)).fill(0);
      });
      const table = f.memory.state.table64v.reshape(GHASH_U64X2_TABLE_ENTRIES);
      const y64 = f.memory.state.ghash.y64;
      const buffer = f.memory.buffer.as('u64x2').reshape(AES_BLOCKS);
      ghashBlocksTableCore64v(f, blocks, buffer, y64, table, 'polyval');
    })
    .fn('encryptInit', ['u32', 'u32', 'u32'], 'void', (f, len, aadLo, aadHi) => {
      const { u32, u64, u64x2 } = f.types;
      const key = f.memory.state.key;
      const encKey = f.memory.state.encKey;
      const roundsState = f.memory.state.rounds;
      const nonce = f.memory.state.nonce.get();

      aesInitTables(f);
      aesKeyInitEnc(f, len, key, f.memory.state.tmp, f.memory.state.expandedKey, roundsState);

      const roundsVal = roundsState.get();
      const expKey = f.memory.state.expandedKey;

      aesWithBlock(f, 'encrypt', roundsVal, expKey, (processBlock) => {
        // RFC 8452 §4 derives the per-nonce auth key first and then the CTR key
        // from consecutive little-endian counters, keeping only the first 8 bytes
        // of each AES block.
        const auth = f.memory.state.ghash.h;
        for (let i = 0; i < KEY_LEN_MAX; i++) encKey[i].set(u32.const(0));
        for (let i = 0; i < 2; i++) {
          const out = processBlock([u32.const(i), nonce[0], nonce[1], nonce[2]]);
          auth[i * 2].set(out[0]);
          auth[i * 2 + 1].set(out[1]);
        }
        const is16 = u32.eq(len, u32.const(16));
        const is24 = u32.eq(len, u32.const(24));
        const Nk = u32.select(is16, u32.const(4), u32.select(is24, u32.const(6), u32.const(8)));
        const pairs = u32.shr(Nk, 1);
        f.doN([], pairs, (i) => {
          const ctr = u32.add(u32.const(2), i);
          const out = processBlock([ctr, nonce[0], nonce[1], nonce[2]]);
          const base = u32.mul(i, u32.const(2));
          encKey[base].set(out[0]);
          encKey[u32.add(base, u32.const(1))].set(out[1]);
          return [];
        });
      });

      f.memory.state.aadLen.set(u64.fromN('u32', [aadLo, aadHi]));
      f.memory.state.dataLen.set(u64.const(0));
      f.memory.state.tag.as8('u8').zero();
      f.memory.state.ctr.as8('u8').zero();
      f.memory.state.ctrReady.set(u32.const(0));
      f.memory.state.ghash.y.set([u32.const(0), u32.const(0), u32.const(0), u32.const(0)]);
      f.memory.state.ghash.y64.set(u64x2.const(0));
      // Transform authKey into POLYVAL key: reverse16, then shift-right-1 with reduction
      // (xor 0b1110_0001 on carry).
      {
        const k = f.memory.state.ghash.h.as8('u8');
        f.doN([], u32.const(8), (i) => {
          const j = u32.sub(u32.const(15), i);
          const a = k[i].get();
          const b = k[j].get();
          k[i].set(b);
          k[j].set(a);
          return [];
        });
        const hiBit = u32.and(u32.fromN('u8', k[15].get()), u32.const(1));
        f.doN1([u32.const(0)], u32.const(16), (i, carry) => {
          const t = u32.fromN('u8', k[i].get());
          const shifted = u32.and(u32.or(u32.shr(t, 1), carry), u32.const(0xff));
          k[i].set(u32.castTo('u8', shifted));
          return [u32.shl(u32.and(t, u32.const(1)), 7)];
        });
        const mask = u32.sub(u32.const(0), hiBit);
        k[0].set(
          u32.castTo(
            'u8',
            u32.xor(u32.fromN('u8', k[0].get()), u32.and(mask, u32.const(0b1110_0001)))
          )
        );
      }
      {
        const h = f.memory.state.ghash.h;
        const table = f.memory.state.table64v.reshape(GHASH_U64X2_TABLE_ENTRIES);
        const tmp = f.memory.state.tmp64v.reshape(GHASH_U64X2_W);
        ghashInitTableCore64v(f, h, table, tmp, 'polyval');
      }

      aesKeyInitEnc(f, len, encKey, f.memory.state.tmp, f.memory.state.expandedKey, roundsState);
    })
    .fn('decryptInit', ['u32', 'u32', 'u32'], 'void', (f, len, aadLo, aadHi) => {
      f.functions.encryptInit.call(len, aadLo, aadHi);
    })
    .use(
      aesBatchFn(
        'processBlocks',
        'encrypt',
        (f, batchPos, perBatch) => {
          const { u32 } = f.types;
          const ctr = f.memory.state.ctr.get();
          const base = u32.mul(batchPos, perBatch);
          const c0 = incCounter(f, false).inplace([ctr[0]], base)[0];
          return [c0, ctr[1], ctr[2], ctr[3]];
        },
        (f, ctr, processBlock, pos) => {
          const { u32 } = f.types;
          const b = f.memory.buffer[pos];
          const ks = processBlock(ctr);
          b.set(b.get().map((x, i) => u32.xor(x, ks[i])));
          const c0 = incCounter(f, false).inplace([ctr[0]], u32.const(1))[0];
          return [c0, ctr[1], ctr[2], ctr[3]];
        }
      )
    )
    .fn('aadBlocks', ['u32', 'u32', 'u32'], 'void', (f, blocks, isLast, left) => {
      f.functions.polyBlocks.call(blocks, isLast, left);
    })
    .fn('macBlocks', ['u32', 'u32', 'u32'], 'void', (f, blocks, isLast, left) => {
      const { u32, u64 } = f.types;
      const bytes = u32.sub(u32.mul(blocks, u32.const(AES_BLOCK_LEN)), left);
      f.memory.state.dataLen.set(u64.add(f.memory.state.dataLen.get(), u64.fromN('u32', bytes)));
      f.functions.polyBlocks.call(blocks, isLast, left);
    })
    .fn('tagInit', [], 'void', (f) => {
      const { u32 } = f.types;
      const ctr = f.memory.state.ctr;
      f.ifElse(u32.eq(f.memory.state.ctrReady.get(), u32.const(0)), [], () => {
        f.memory.state.ctrReady.set(u32.const(1));
        ctr.set(f.memory.state.tag.get());
        const ctr8 = ctr.as8('u8');
        ctr8[15].set(u32.castTo('u8', u32.or(u32.fromN('u8', ctr8[15].get()), u32.const(0x80))));
      });
    })
    .fn('tagFinish', [], 'void', (f) => {
      const { u32, u64 } = f.types;
      const aadBits = u64.mul(f.memory.state.aadLen.get(), u64.const(8));
      const dataBits = u64.mul(f.memory.state.dataLen.get(), u64.const(8));
      const buf8 = f.memory.buffer.as8('u8');
      buf8[0].write('u64', aadBits);
      buf8[8].write('u64', dataBits);
      f.functions.polyBlocks.call(u32.const(1), u32.const(1), u32.const(0));

      const tag32 = f.memory.state.tag;
      const yv = u64
        .from('u64x2', f.memory.state.ghash.y64.get())
        .map((w) => u32.from('u64', w))
        .flat();
      tag32.set(yv);

      const tag8 = tag32.as8('u8');
      const nonce = f.memory.state.nonce.as8('u8');
      f.doN([], u32.const(12), (i) => {
        const n = u32.fromN('u8', nonce[i].get());
        const t = u32.fromN('u8', tag8[i].get());
        tag8[i].set(u32.castTo('u8', u32.xor(t, n)));
        return [];
      });
      tag8[15].set(u32.castTo('u8', u32.and(u32.fromN('u8', tag8[15].get()), u32.const(0x7f))));

      const roundsVal = f.memory.state.rounds.get();
      const expKey = f.memory.state.expandedKey;
      aesWithBlock(f, 'encrypt', roundsVal, expKey, (processBlock) => {
        tag32.set(processBlock(tag32.get()));
      });

      f.memory.state.ghash.y.set([u32.const(0), u32.const(0), u32.const(0), u32.const(0)]);
      f.memory.state.ghash.y64.set(f.types.u64x2.const(0));
    })
    .fn('encryptBlocks', ['u32', 'u32', 'u32', 'u32'], 'void', (f, blocks, isLast, left, round) => {
      const doMac = () => {
        f.functions.macBlocks.call(blocks, isLast, left);
        f.ifElse(isLast, [], () => f.functions.tagFinish.call());
      };
      const doCtr = () => {
        f.functions.tagInit.call();
        callBatch(f, blocks, (batchPos, batchLen, perBatch) => {
          f.functions.processBlocks.call(batchPos, batchLen, perBatch, blocks);
        });
        incCounter(f, false).memory(f.memory.state.ctr.range(0, 1), blocks);
      };
      roundBlocks(f, round, 'encrypt', doMac, doCtr);
    })
    .fn('decryptBlocks', ['u32', 'u32', 'u32', 'u32'], 'void', (f, blocks, isLast, left, round) => {
      const doMac = () => {
        f.functions.macBlocks.call(blocks, isLast, left);
        f.ifElse(isLast, [], () => f.functions.tagFinish.call());
      };
      const doCtr = () => {
        f.functions.tagInit.call();
        callBatch(f, blocks, (batchPos, batchLen, perBatch) => {
          f.functions.processBlocks.call(batchPos, batchLen, perBatch, blocks);
        });
        incCounter(f, false).memory(f.memory.state.ctr.range(0, 1), blocks);
      };
      roundBlocks(f, round, 'decrypt', doMac, doCtr);
    });
};

const sivBlocks = <M extends Segs & { buffer: ArraySpec<ScalarSpec<'u32'>> }>(
  f: Scope<M, {}>,
  blocks: Val<'u32'>,
  isLast: Val<'u32'>,
  left: Val<'u32'>,
  cb: (
    kind: 'pad' | 'body',
    a0: Val<'u32'>,
    a1: Val<'u32'>,
    a2: Val<'u32'>,
    hasLast: Val<'u32'>
  ) => void
) => {
  const { u32 } = f.types;
  const buffer8 = f.memory.buffer.as8('u8');
  // RFC 5297 §2.4 routes an empty final S2V string through `pad(Sn)`, so normalize
  // it to one synthetic 0x80 || 0^... block and let callers reuse the same last-block path.
  const isEmpty = u32.and(isLast, u32.eq(blocks, u32.const(0)));
  const bcount = u32.select(isEmpty, u32.const(1), blocks);
  const l = u32.select(isEmpty, u32.const(AES_BLOCK_LEN), left);
  f.ifElse(isEmpty, [], () => {
    buffer8[0].set(u32.castTo('u8', u32.const(0x80)));
    buffer8.range(u32.const(1), u32.const(16)).fill(0);
  });
  const lastIdx = u32.sub(bcount, u32.const(1));
  const hasLast = u32.and(isLast, u32.ne(bcount, u32.const(0)));
  f.ifElse(u32.and(isLast, u32.ne(l, u32.const(0))), [], () => {
    const start = u32.sub(u32.mul(bcount, u32.const(AES_BLOCK_LEN)), l);
    cb('pad', start, lastIdx, l, hasLast);
  });
  cb('body', bcount, lastIdx, l, hasLast);
};

export const genAesSiv = (_type: TypeName, _opts: {}) => {
  return new Module('aes_siv')
    .mem(
      'state',
      struct({
        key1: array('u32', {}, KEY_LEN_MAX),
        key: array('u32', {}, KEY_LEN_MAX),
        expandedKey: array('u32', {}, EXPANDED_KEY_MAX),
        expandedKeyCmac: array('u32', {}, EXPANDED_KEY_MAX),
        tmp: array('u32', {}, EXPANDED_KEY_MAX * 2),
        rounds: 'u32',
        k1: array('u32', {}, 4),
        k2: array('u32', {}, 4),
        iv: array('u32', {}, 4),
        d: array('u32', {}, 4),
        tag: array('u32', {}, 4),
        ctr: array('u32', {}, 4),
        ctrReady: 'u32',
      })
    )
    .mem('constants', aesConsts)
    .mem('buffer', array('u32', {}, AES_BLOCKS, 4))
    .fn('reset', ['u32'], 'void', (f, maxWritten) => {
      f.memory.state.as8('u8').zero();
      f.memory.buffer.as8().range(0, maxWritten).fill(0);
    })
    .fn('encryptInit', ['u32'], 'void', (f, len) => {
      cmacSubkeysInit(f, len, {
        key: f.memory.state.key1,
        tmp: f.memory.state.tmp,
        expandedKey: f.memory.state.expandedKeyCmac,
        rounds: f.memory.state.rounds,
        k1: f.memory.state.k1,
        k2: f.memory.state.k2,
        iv: f.memory.state.iv,
      });
      {
        const roundsVal = f.memory.state.rounds.get();
        const expKey = f.memory.state.expandedKeyCmac;
        aesWithBlock(f, 'encrypt', roundsVal, expKey, (processBlock) => {
          f.memory.state.d.set(processBlock(f.memory.state.k1.get()));
        });
      }

      aesKeyInitEnc(
        f,
        len,
        f.memory.state.key,
        f.memory.state.tmp,
        f.memory.state.expandedKey,
        f.memory.state.rounds
      );
    })
    .fn('decryptInit', ['u32'], 'void', (f, len) => {
      f.functions.encryptInit.call(len);
    })
    .fn('aadBlocks', ['u32', 'u32', 'u32'], 'void', (f, blocks, isLast, left) => {
      const { u32 } = f.types;
      const k1 = f.memory.state.k1;
      const k2 = f.memory.state.k2;
      const buffer = f.memory.buffer;
      const roundsVal = f.memory.state.rounds.get();
      const expKey = f.memory.state.expandedKeyCmac;
      aesWithBlock(f, 'encrypt', roundsVal, expKey, (processBlock) => {
        sivBlocks(f, blocks, isLast, left, (kind, a0, a1, a2, hasLast) => {
          if (kind === 'pad') {
            const buffer8 = f.memory.buffer.as8('u8');
            buffer8[a0].set(u32.castTo('u8', u32.const(0x80)));
            buffer8.range(u32.add(a0, u32.const(1)), u32.add(a0, a2)).fill(0);
            return;
          }
          const bcount = a0;
          const lastIdx = a1;
          const l = a2;
          f.doN([], bcount, (chunkPos) => {
            const isFinal = u32.and(hasLast, u32.eq(chunkPos, lastIdx));
            const useK2 = u32.and(isFinal, u32.ne(l, u32.const(0)));
            const useK = isFinal;
            const b = buffer[chunkPos];
            const bv = b.get();
            const iv = f.memory.state.iv.get();
            f.memory.state.iv.set(
              processBlock(cmacXor(u32, bv, iv, k1.get(), k2.get(), useK, useK2))
            );
            return [];
          });
          f.ifElse(isLast, [], () => {
            const d = f.memory.state.d;
            const d8 = d.as8('u8');
            const ivb = f.memory.state.iv.as8('u8');
            cmacDbl(f, d);
            const dv = d8.get();
            const ivv = ivb.get();
            d8.set(
              dv.map((v, i) =>
                u32.castTo('u8', u32.xor(u32.fromN('u8', v), u32.fromN('u8', ivv[i])))
              )
            );
            f.memory.state.iv.set([u32.const(0), u32.const(0), u32.const(0), u32.const(0)]);
          });
        });
      });
    })
    .fn('macBlocks', ['u32', 'u32', 'u32'], 'void', (f, blocks, isLast, left) => {
      const { u32 } = f.types;
      const k1 = f.memory.state.k1;
      const k2 = f.memory.state.k2;
      const buffer = f.memory.buffer;
      const roundsVal = f.memory.state.rounds.get();
      const expKey = f.memory.state.expandedKeyCmac;
      aesWithBlock(f, 'encrypt', roundsVal, expKey, (processBlock) => {
        sivBlocks(f, blocks, isLast, left, (kind, a0, a1, a2, hasLast) => {
          if (kind === 'pad') {
            const start = a0;
            const lastIdx = a1;
            const l = a2;
            const blockStart = u32.mul(lastIdx, u32.const(AES_BLOCK_LEN));
            const lastStart = u32.sub(start, u32.const(16));
            const d = f.memory.state.d;
            const d8 = d.as8('u8');
            const tmp = f.memory.state.tmp;
            const tmp8 = tmp.as8('u8');
            const buffer8 = f.memory.buffer.as8('u8');
            const isMulti = u32.ne(u32.add(lastIdx, u32.const(1)), u32.const(1));
            f.ifElse(isMulti, [], () => {
              for (let i = 0; i < 16; i++) {
                const cur = u32.fromN('u8', buffer8[u32.add(lastStart, u32.const(i))].get());
                const dv = u32.fromN('u8', d8[u32.const(i)].get());
                buffer8[u32.add(lastStart, u32.const(i))].set(u32.castTo('u8', u32.xor(cur, dv)));
              }
            });
            buffer8[start].set(u32.castTo('u8', u32.const(0x80)));
            buffer8.range(u32.add(start, u32.const(1)), u32.add(start, l)).fill(0);
            f.ifElse(u32.eq(isMulti, u32.const(0)), [], () => {
              tmp8.range(0, 16).set(d8.get());
              cmacDbl(f, tmp);
              for (let i = 0; i < 16; i++) {
                const cur = u32.fromN('u8', buffer8[u32.add(blockStart, u32.const(i))].get());
                const tv = u32.fromN('u8', tmp8[u32.const(i)].get());
                buffer8[u32.add(blockStart, u32.const(i))].set(u32.castTo('u8', u32.xor(cur, tv)));
              }
            });
            return;
          }
          const bcount = a0;
          const lastIdx = a1;
          const l = a2;
          f.ifElse(u32.and(isLast, u32.eq(l, u32.const(0))), [], () => {
            const dv = f.memory.state.d.get();
            const b = buffer[lastIdx];
            const bv = b.get();
            b.set(bv.map((v, i) => u32.xor(v, dv[i])));
          });
          f.doN([], bcount, (chunkPos) => {
            const isFinal = u32.and(hasLast, u32.eq(chunkPos, lastIdx));
            const useK2 = u32.and(
              isFinal,
              u32.and(u32.ne(l, u32.const(0)), u32.ne(bcount, u32.const(1)))
            );
            const useK = isFinal;
            const b = buffer[chunkPos];
            const bv = b.get();
            const iv = f.memory.state.iv.get();
            f.memory.state.iv.set(
              processBlock(cmacXor(u32, bv, iv, k1.get(), k2.get(), useK, useK2))
            );
            return [];
          });
          f.memory.state.tag.set(f.memory.state.iv.get());
        });
      });
    })
    .use(
      aesBatchFn(
        'processBlocks',
        'encrypt',
        (f, batchPos, perBatch) => {
          const { u32 } = f.types;
          const ctr = f.memory.state.ctr.get();
          const base = u32.mul(batchPos, perBatch);
          return incCounter(f, true).inplace(ctr, base);
        },
        (f, ctr, processBlock, pos) => {
          const { u32 } = f.types;
          const b = f.memory.buffer[pos];
          const ks = processBlock(ctr);
          b.set(b.get().map((x, i) => u32.xor(x, ks[i])));
          return incCounter(f, true).inplace(ctr, u32.const(1));
        }
      )
    )
    .fn('tagInit', [], 'void', (f) => {
      const { u32 } = f.types;
      const ctr = f.memory.state.ctr;
      f.ifElse(u32.eq(f.memory.state.ctrReady.get(), u32.const(0)), [], () => {
        f.memory.state.ctrReady.set(u32.const(1));
        ctr.set(f.memory.state.tag.get());
        const ctr8 = ctr.as8('u8');
        // RFC 5297 §2.6 / §2.7 uses Q = V bitand (1^64 || 0^1 || 1^31 || 0^1 || 1^31),
        // which clears the high bit of bytes 8 and 12 in this byte layout before CTR.
        ctr8[8].set(u32.castTo('u8', u32.and(u32.fromN('u8', ctr8[8].get()), u32.const(0x7f))));
        ctr8[12].set(u32.castTo('u8', u32.and(u32.fromN('u8', ctr8[12].get()), u32.const(0x7f))));
      });
    })
    .fn('encryptBlocks', ['u32', 'u32', 'u32', 'u32'], 'void', (f, blocks, isLast, left, round) => {
      const doMac = () => {
        f.functions.macBlocks.call(blocks, isLast, left);
      };
      const doCtr = () => {
        f.functions.tagInit.call();
        callBatch(f, blocks, (batchPos, batchLen, perBatch) => {
          f.functions.processBlocks.call(batchPos, batchLen, perBatch, blocks);
        });
        incCounter(f, true).memory(f.memory.state.ctr, blocks);
      };
      roundBlocks(f, round, 'encrypt', doMac, doCtr);
    })
    .fn('decryptBlocks', ['u32', 'u32', 'u32', 'u32'], 'void', (f, blocks, isLast, left, round) => {
      const doMac = () => {
        f.functions.macBlocks.call(blocks, isLast, left);
      };
      const doCtr = () => {
        f.functions.tagInit.call();
        callBatch(f, blocks, (batchPos, batchLen, perBatch) => {
          f.functions.processBlocks.call(batchPos, batchLen, perBatch, blocks);
        });
        incCounter(f, true).memory(f.memory.state.ctr, blocks);
      };
      roundBlocks(f, round, 'decrypt', doMac, doCtr);
    });
};

// RFC 3394 default IV split into u32 words.
const AESKW_WORD = 0xa6a6a6a6;
// RFC 5649 alternative initial value high word.
const AESKWP_WORD = 0xa65959a6;

const wrapState = /* @__PURE__ */ struct({
  key: /* @__PURE__ */ array('u32', {}, KEY_LEN_MAX),
  expandedKey: /* @__PURE__ */ array('u32', {}, EXPANDED_KEY_MAX),
  tmp: /* @__PURE__ */ array('u32', {}, EXPANDED_KEY_MAX),
  rounds: 'u32',
});

const kwBuffer = /* @__PURE__ */ array('u32', {}, AES_BLOCKS, 2);

type AesWrapSegs = {
  state: typeof wrapState;
  constants: typeof aesConsts;
  buffer: typeof kwBuffer;
};

const kwBlocks = <M extends Segs & AesWrapSegs>(
  f: Scope<M, {}>,
  blocks: Val<'u32'>,
  iters: Val<'u32'>,
  ctr0: Val<'u32'>,
  step: (
    a0: Val<'u32'>,
    a1: Val<'u32'>,
    ctr: Val<'u32'>,
    pos: Val<'u32'>,
    n: Val<'u32'>
  ) => [Val<'u32'>, Val<'u32'>, Val<'u32'>]
) => {
  const { u32 } = f.types;
  const buffer = f.memory.buffer;
  const n = u32.sub(blocks, u32.const(1));

  // Critical: call AES via an internal module function so codegen doesn't inline the AES block into
  // the KW loop body (which makes `toJs/toWasm` extremely slow for this module).
  const a = buffer[0].get();
  const res = f.doN1(
    [a[0], a[1], ctr0, u32.const(0)],
    iters,
    (_t: Val<'u32'>, a0: Val<'u32'>, a1: Val<'u32'>, ctr: Val<'u32'>, pos: Val<'u32'>) => {
      // `a0/a1` are A (64-bit register) in RFC3394 / RFC5649 represented as 2 u32 words.
      const r = step(a0, a1, ctr, pos, n);
      a0 = r[0];
      a1 = r[1];
      ctr = r[2];
      const pos1 = u32.add(pos, u32.const(1));
      pos = u32.select(u32.eq(pos1, n), u32.const(0), pos1);
      return [a0, a1, ctr, pos];
    }
  );
  buffer[0].set([res[0], res[1]]);
};

const genAesKeyWrap = (_type: TypeName, opts: { kwp: boolean }) =>
  new Module(opts.kwp ? 'aes_kwp' : 'aes_kw')
    .mem('state', wrapState)
    .mem('constants', aesConsts)
    .mem('buffer', kwBuffer)
    .use(aesInitKeys({ withDecrypt: true }))
    .fn(
      'aesBlockEnc',
      ['u32', 'u32', 'u32', 'u32'],
      ['u32', 'u32', 'u32', 'u32'],
      (f, a0, a1, b0, b1) => {
        const roundsVal = f.memory.state.rounds.get();
        const expKey = f.memory.state.expandedKey;
        const tmp = f.memory.state.tmp;
        const tmp4 = tmp.range(0, 4);
        aesWithBlock(f, 'encrypt', roundsVal, expKey, (processBlock) => {
          const out = processBlock([a0, a1, b0, b1]);
          tmp4.set(out);
        });
        return tmp4.get();
      }
    )
    .fn(
      'aesBlockDec',
      ['u32', 'u32', 'u32', 'u32'],
      ['u32', 'u32', 'u32', 'u32'],
      (f, a0, a1, b0, b1) => {
        const roundsVal = f.memory.state.rounds.get();
        const expKey = f.memory.state.expandedKey;
        const tmp = f.memory.state.tmp;
        const tmp4 = tmp.range(0, 4);
        aesWithBlock(f, 'decrypt', roundsVal, expKey, (processBlock) => {
          const out = processBlock([a0, a1, b0, b1]);
          tmp4.set(out);
        });
        return tmp4.get();
      }
    )
    .fn('reset', ['u32'], 'void', (f, maxWritten) => {
      f.memory.state.as8('u8').zero();
      f.memory.buffer.as8().range(0, maxWritten).fill(0);
    })
    .fn('addPadding', ['u32', 'u32', 'u32'], 'u32', (f, take, _left, _blockLen) => {
      const { u32 } = f.types;
      const buf32 = f.memory.buffer.as32();
      buf32[0].set(u32.const(opts.kwp ? AESKWP_WORD : AESKW_WORD));
      buf32[1].set(opts.kwp ? bswap32(u32, take) : u32.const(AESKW_WORD));
      return u32.const(0);
    })
    .fn('verifyPadding', ['u32', 'u32'], 'u32', (f, len, blockLen) => {
      const { u32 } = f.types;
      const buf32 = f.memory.buffer.as32();
      const invalid = u32.add(blockLen, u32.const(1));
      const w0 = buf32[0].get();
      const w1 = buf32[1].get();
      if (!opts.kwp) {
        let bad = u32.ne(w0, u32.const(AESKW_WORD));
        bad = u32.or(bad, u32.ne(w1, u32.const(AESKW_WORD)));
        return u32.select(bad, invalid, u32.const(0));
      }
      let bad = u32.ne(w0, u32.const(AESKWP_WORD));
      const mli = bswap32(u32, w1);
      const padded = u32.sub(len, u32.const(8));
      bad = u32.or(bad, u32.gt(mli, padded));
      let pad = u32.sub(padded, mli);
      bad = u32.or(bad, u32.gt(pad, u32.const(7)));
      pad = u32.select(bad, u32.const(0), pad);
      const buf8 = f.memory.buffer.as8('u8');
      let badBytes = u32.const(0);
      for (let i = 0; i < 7; i++) {
        const ok = u32.lt(u32.const(i), pad);
        const idx = u32.select(ok, u32.add(u32.add(u32.const(8), mli), u32.const(i)), u32.const(0));
        const b = u32.fromN('u8', buf8[idx].get());
        badBytes = u32.or(badBytes, u32.and(ok, u32.ne(b, u32.const(0))));
      }
      bad = u32.or(bad, badBytes);
      return u32.select(bad, invalid, pad);
    })
    .fn(
      'encryptBlocks',
      ['u32', 'u32', 'u32', 'u32'],
      'void',
      (f, blocks, _isLast, _left, round) => {
        const { u32 } = f.types;
        const buffer = f.memory.buffer;
        // mkCipher uses 0xffffffff as an internal sentinel for "run the full wrap pass".
        const all = u32.eq(round, u32.const(0xffffffff));
        const n = u32.sub(blocks, u32.const(1));
        const ctr0 = u32.select(all, u32.const(1), round);
        if (opts.kwp) {
          // RFC5649 N=1: fold into the loop by selecting iters=1 and disabling A^=t via a select.
          const isN1 = u32.and(all, u32.eq(blocks, u32.const(2)));
          const iters = u32.select(
            isN1,
            u32.const(1),
            u32.select(all, u32.mul(u32.const(6), n), n)
          );
          kwBlocks(f, blocks, iters, ctr0, (a0, a1, ctr, pos) => {
            const idx = u32.add(pos, u32.const(1));
            const b = buffer[idx];
            const bv = b.get();
            const out = f.functions.aesBlockEnc.call(a0, a1, bv[0], bv[1]);
            b.set([out[2], out[3]]);
            const tw = u32.select(isN1, u32.const(0), bswap32(u32, ctr));
            const ctr1 = u32.select(isN1, ctr, u32.add(ctr, u32.const(1)));
            return [out[0], u32.xor(out[1], tw), ctr1];
          });
          return;
        }
        const iters = u32.select(all, u32.mul(u32.const(6), n), n);
        kwBlocks(f, blocks, iters, ctr0, (a0, a1, ctr, pos) => {
          const idx = u32.add(pos, u32.const(1));
          const b = buffer[idx];
          const bv = b.get();
          const out = f.functions.aesBlockEnc.call(a0, a1, bv[0], bv[1]);
          b.set([out[2], out[3]]);
          return [out[0], u32.xor(out[1], bswap32(u32, ctr)), u32.add(ctr, u32.const(1))];
        });
      }
    )
    .fn(
      'decryptBlocks',
      ['u32', 'u32', 'u32', 'u32'],
      'void',
      (f, blocks, _isLast, _left, round) => {
        const { u32 } = f.types;
        const buffer = f.memory.buffer;
        // mkCipher uses 0xffffffff as an internal sentinel for "run the full unwrap pass".
        const all = u32.eq(round, u32.const(0xffffffff));
        const n = u32.sub(blocks, u32.const(1));
        const ctr0 = u32.select(all, u32.mul(n, u32.const(6)), round);
        if (opts.kwp) {
          const isN1 = u32.and(all, u32.eq(blocks, u32.const(2)));
          const iters = u32.select(
            isN1,
            u32.const(1),
            u32.select(all, u32.mul(u32.const(6), n), n)
          );
          kwBlocks(f, blocks, iters, ctr0, (a0, a1, ctr, pos, n) => {
            const idx = u32.sub(n, pos);
            const b = buffer[idx];
            const bv = b.get();
            const in1 = u32.select(isN1, a1, u32.xor(a1, bswap32(u32, ctr)));
            const out = f.functions.aesBlockDec.call(a0, in1, bv[0], bv[1]);
            b.set([out[2], out[3]]);
            const ctr1 = u32.select(isN1, ctr, u32.sub(ctr, u32.const(1)));
            return [out[0], out[1], ctr1];
          });
          return;
        }
        const iters = u32.select(all, u32.mul(u32.const(6), n), n);
        kwBlocks(f, blocks, iters, ctr0, (a0, a1, ctr, pos, n) => {
          const idx = u32.sub(n, pos);
          const b = buffer[idx];
          const bv = b.get();
          const out = f.functions.aesBlockDec.call(
            a0,
            u32.xor(a1, bswap32(u32, ctr)),
            bv[0],
            bv[1]
          );
          b.set([out[2], out[3]]);
          return [out[0], out[1], u32.sub(ctr, u32.const(1))];
        });
      }
    );

export const genAesKw = (type: TypeName, _opts: {}) => genAesKeyWrap(type, { kwp: false });
export const genAesKwp = (type: TypeName, _opts: {}) => genAesKeyWrap(type, { kwp: true });
