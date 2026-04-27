/**
 * Core hash functions logic.
 * Contains SHA1, SHA2, SHA3, BLAKE1, BLAKE2, BLAKE3, RIPEMD, MD5.
 * The file is not used in end-user code. Instead, it's used by awasm-compiler
 * to generate different build targets (wasm, wasm_threads, js, runtime).
 * @module
 */
import type {
  ArraySpec,
  FnRegistry,
  GetOps,
  ScalarSpec,
  Scope,
  Segs,
  StructSpec,
  Val,
} from '@awasm/compiler/module.js';
import { array, Module, struct, toGeneric, type Shift } from '@awasm/compiler/module.js';
import {
  type MaskType,
  type OpsFnForType,
  type TypeName,
  type UnsignedType,
} from '@awasm/compiler/types.js';
import * as constants from '../constants.ts';
import { CHUNKS, getLanes, MIN_PER_THREAD, readMSG, type TArg } from './utils.ts';

const _0n = /* @__PURE__ */ BigInt(0);
const _8n = /* @__PURE__ */ BigInt(8);

// Generic Chi and Maj functions
function Chi<V extends Val<UnsignedType, G>, G = unknown>(
  T: GetOps<UnsignedType, G>,
  a: V,
  b: V,
  c: V
): V {
  return T.xor(T.and(a, b), T.andnot(c, a)) as V;
}
function Maj<V extends Val<UnsignedType, G>, G = unknown>(
  T: GetOps<UnsignedType, G>,
  a: V,
  b: V,
  c: V
): V {
  return T.xor(T.and(a, b), T.and(a, c), T.and(b, c)) as V;
}

type PadCounterReq<T extends TypeName> = {
  state: ArraySpec<
    StructSpec<{
      counter: ScalarSpec<'u64'>;
      state: ArraySpec<ScalarSpec<UnsignedType, T>, readonly [number]>;
    }>,
    readonly [number]
  >;
  buffer: ArraySpec<ScalarSpec<UnsignedType, T>>;
};

function padCounter<T extends UnsignedType>(
  type: T,
  counterLen: number,
  perInput: number,
  perOutput: number,
  isLE = false
) {
  return <M extends Segs & PadCounterReq<T>, F extends FnRegistry>(mod: Module<M, F>) =>
    mod
      .batchFn(
        'processOutBlocks',
        { lanes: getLanes(type), perThread: MIN_PER_THREAD },
        ['u32', 'u32', 'u32'],
        (f, lanes, batchPos, _perBatch, maxBlocks, _outBlockLen, _isLast) => {
          const { state } = f.memory.state.lanes(lanes)[batchPos];
          const S = state.get();
          const buffer = f.memory.buffer.reshape(batchPos, maxBlocks, S.length).lanes(lanes)[
            batchPos
          ];
          buffer[0].set(S);
        }
      )
      .fn(
        'resetBuffer',
        ['u32', 'u32', 'u32', 'u32', 'u32'],
        'void',
        (f, batchPos, batchLen, maxWritten, _blockLen, maxBlocks) => {
          const { u32 } = f.types;
          f.doN([], batchLen, (cnt) => {
            f.memory.buffer
              .reshape(batchPos, maxBlocks, perOutput)
              [u32.add(batchPos, cnt)].as8()
              .range(0, maxWritten)
              .fill(0);
            return [];
          });
        }
      )
      .fn(
        'padding',
        ['u32', 'u32', 'u32', 'u32', 'u32', 'u32'],
        'u32',
        (f, batchPos, take, maxBlocks, left, blockLen, suffix) => {
          const { u32, u64 } = f.types;
          const { counter } = f.memory.state[batchPos];
          const buffer = f.memory.buffer.reshape(batchPos, maxBlocks, perInput)[batchPos];
          buffer.as8().range(take, blockLen).fill(0, u32.add(left, blockLen));
          // input[msgLen] ^= 0x80 (either last of current block or next block)
          // NOTE: suffix is const here; only sha3 and blake1 differ.
          // For blake1 the suffix is lengthFlag.
          buffer.as8()[take].mut.xor(u32.const(0x80));
          const fits = u32.ge(left, u32.const(counterLen + 1)); // 1 is suffix here
          const paddingBlocks = u32.select(fits, u32.const(0), u32.const(1)); // fits ? 0 : 1
          const endOfBlock = u32.add(take, left, u32.mul(paddingBlocks, blockLen));
          let total = u64.add(counter.get(), u64.fromN('u32', take)); // what we added here
          let bitLen = u64.mul(total, u64.const(_8n));
          if (!isLE) bitLen = u64.swapEndianness(bitLen);
          buffer.as8()[u32.sub(endOfBlock, u32.const(8))].write('u64', bitLen);
          // optional counter flag
          const counterFlagPos = u32.sub(endOfBlock, u32.const(counterLen + 1));
          buffer.as8()[counterFlagPos].mut.xor(suffix);
          return paddingBlocks;
        }
      );
}

export function genSha1<T extends UnsignedType>(type: T, _opts: undefined) {
  const rounds = 80;
  const counterLen = 8;
  const memType = toGeneric<UnsignedType, T>(type);
  const mod = new Module('sha1')
    .batchMem('state', struct({ counter: 'u64', state: array(memType, {}, 5) }))
    .mem('buffer', array(memType, { swapEndianness: true }, CHUNKS, 16))
    .use(padCounter(type, counterLen, 16, 5))
    .fn(
      'reset',
      ['u32', 'u32', 'u32', 'u32', 'u32'],
      'void',
      (f, batchPos, batchLen, maxWritten, blockLen, maxBlocks) => {
        f.memory.state.range(batchPos, batchLen).as8().zero();
        f.functions.resetBuffer.call(batchPos, batchLen, maxWritten, blockLen, maxBlocks);
      }
    )
    .batchFn(
      'processBlocks',
      { lanes: getLanes(type), perThread: MIN_PER_THREAD },
      ['u32', 'u32', 'u32', 'u32', 'u32'],
      (f, lanes, batchPos, perBatch, maxBlocks, blockLen, _isLast, _left, _padBlocks) => {
        const blocks = perBatch;
        const u64 = f.getType('u64', lanes);
        const { state, counter } = f.memory.state.lanes(lanes)[batchPos];
        const buffer = f.memory.buffer.reshape(batchPos, maxBlocks, 16).lanes(lanes)[batchPos];
        const blockLen64 = u64.fromN('u32', blockLen);
        const T = f.getTypeGeneric<UnsignedType, T>(type, lanes);
        let S = state.get();
        let cnt = counter.get();
        [cnt, S] = f.doN1([cnt, S], blocks, (chunkPos, cnt, S) => {
          let [A, B, C, D, E] = S;
          const prev = [A, B, C, D, E];
          const W = readMSG(f, buffer[chunkPos]);
          for (let i = 16; i < rounds; i++) {
            W[i] = T.rotl(T.xor(W[i - 3], W[i - 8], W[i - 14], W[i - 16]), 1);
          }
          for (let i = 0; i < rounds; i++) {
            let F, K;
            if (i < 20) {
              F = Chi(T, B, C, D);
              K = 0x5a827999;
            } else if (i < 40) {
              F = T.xor(B, C, D);
              K = 0x6ed9eba1;
            } else if (i < 60) {
              F = Maj(T, B, C, D);
              K = 0x8f1bbcdc;
            } else {
              F = T.xor(B, C, D);
              K = 0xca62c1d6;
            }
            const T1 = T.add(T.rotl(A, 5), F, E, T.const(K), W[i]);
            E = D;
            D = C;
            C = T.rotl(B, 30);
            B = A;
            A = T1;
          }
          cnt = u64.add(cnt, blockLen64);
          // Add the compressed chunk to the current hash value
          return [cnt, [A, B, C, D, E].map((v, idx) => T.add(v, prev[idx]))];
        });
        counter.set(cnt);
        state.set(S);
      }
    );
  return mod;
}

export function genSha2<T extends UnsignedType>(
  type: T,
  opts: { K: any; rounds: number; shifts: number[] }
) {
  const { K: K2, rounds, shifts } = opts;
  const counterLen = type.startsWith('u32') ? 8 : 16;
  const memType = toGeneric<UnsignedType, T>(type);
  const mod = new Module('sha2')
    .batchMem('state', struct({ counter: 'u64', state: array(memType, {}, 8) }))
    .mem('buffer', array(memType, { swapEndianness: true }, CHUNKS, 16))
    .use(padCounter(type, counterLen, 16, 8))
    .fn(
      'reset',
      ['u32', 'u32', 'u32', 'u32', 'u32'],
      'void',
      (f, batchPos, batchLen, maxWritten, blockLen, maxBlocks) => {
        f.memory.state.range(batchPos, batchLen).as8().zero();
        f.functions.resetBuffer.call(batchPos, batchLen, maxWritten, blockLen, maxBlocks);
      }
    )
    .batchFn(
      'processBlocks',
      { lanes: getLanes(type), perThread: MIN_PER_THREAD },
      ['u32', 'u32', 'u32', 'u32', 'u32'],
      (f, lanes, batchPos, perBatch, maxBlocks, blockLen, _isLast, _left, _padBlocks) => {
        const blocks = perBatch;
        const { state, counter } = f.memory.state.lanes(lanes)[batchPos];
        const u64T = f.getType('u64', lanes);
        const buffer = f.memory.buffer.reshape(batchPos, maxBlocks, 16).lanes(lanes)[batchPos];
        const blockLen64 = u64T.fromN('u32', blockLen);
        const T = f.getTypeGeneric<UnsignedType, T>(type, lanes);
        let S = state.get();
        const K = Array.from(K2).map((i: any) => T.const(i));
        const SH = shifts.map((i) => i);
        let cnt = counter.get();
        [cnt, S] = f.doN1([cnt, S], blocks, (chunkPos, cnt, S) => {
          let [A, B, C, D, E, F, G, H] = S;
          const prev = [A, B, C, D, E, F, G, H];
          const W = readMSG(f, buffer[chunkPos]);
          for (let i = 16; i < rounds; i++) {
            const W15 = W[i - 15];
            const W2 = W[i - 2];
            // const s0 = rotr(W15, 7) ^ rotr(W15, 18) ^ (W15 >>> 3);
            const s0 = T.xor(T.rotr(W15, SH[0]), T.rotr(W15, SH[1]), T.shr(W15, SH[2]));
            // const s1 = rotr(W2, 17) ^ rotr(W2, 19) ^ (W2 >>> 10);
            const s1 = T.xor(T.rotr(W2, SH[3]), T.rotr(W2, SH[4]), T.shr(W2, SH[5]));
            // SHA256_W[i] = (s1 + SHA256_W[i - 7] + s0 + SHA256_W[i - 16]) | 0;
            W[i] = T.add(s1, W[i - 7], s0, W[i - 16]);
          }
          // Compression function main loop: 64 rounds for SHA-224/256, 80 for SHA-384/512.
          for (let i = 0; i < rounds; i++) {
            // const sigma1 = rotr(E, 6) ^ rotr(E, 11) ^ rotr(E, 25);
            const sigma1 = T.xor(T.rotr(E, SH[6]), T.rotr(E, SH[7]), T.rotr(E, SH[8]));
            // const T1 = (H + sigma1 + Chi(E, F, G) + SHA256_K[i] + SHA256_W[i]) | 0;
            const T1 = T.add(H, sigma1, Chi(T, E, F, G), K[i], W[i]);
            // const sigma0 = rotr(A, 2) ^ rotr(A, 13) ^ rotr(A, 22);
            const sigma0 = T.xor(T.rotr(A, SH[9]), T.rotr(A, SH[10]), T.rotr(A, SH[11]));
            // const T2 = (sigma0 + Maj(A, B, C)) | 0;
            const T2 = T.add(sigma0, Maj(T, A, B, C));
            H = G; // looks like ror(1) on i32x4?
            G = F;
            F = E;
            E = T.add(D, T1);
            D = C; // these are two separate stuff on which we do ror?
            C = B;
            B = A;
            A = T.add(T1, T2);
          }
          cnt = u64T.add(cnt, blockLen64);
          // Add the compressed chunk to the current hash value
          return [cnt, [A, B, C, D, E, F, G, H].map((v, idx) => T.add(v, prev[idx]))];
        });
        counter.set(cnt);
        state.set(S);
      }
    );
  return mod;
}

function keccakFn<T extends UnsignedType>(
  f: Scope<{ rc: ArraySpec<ScalarSpec<'u64'>, readonly [24]> }>,
  type: T,
  S: Val<any, T>[],
  rounds: number,
  lanes: number
) {
  const { u32 } = f.types;
  const T = f.getTypeGeneric<UnsignedType, T>(type, lanes);
  return f.doN1([S], u32.const(rounds), (r, S) => {
    const B = new Array(5).fill(T.const(_0n));
    // Theta
    for (let x = 0; x < 5; x++) {
      for (let y = 0; y < 5; y++) B[x] = T.xor(B[x], S[x + y * 5]);
    }
    for (let x = 0; x < 5; x++) {
      for (let y_count = 0; y_count < 5; y_count++) {
        const y = y_count * 5;
        const i0 = B[(x + 4) % 5];
        const i1 = T.rotl(B[(x + 1) % 5], 1);
        S[y + x] = T.xor(S[y + x], i0, i1);
      }
    }
    // FIPS 202 applies rho then pi; this loop fuses them by walking the 24 non-(0,0) lanes
    // in pi order. Current callers use KECCAK-p[1600,24], so rc[r] already matches ir = 0..23.
    let last = S[1];
    for (let x = 0; x < 24; x++) {
      B[0] = S[constants.SHA3_PI2[x]];
      S[constants.SHA3_PI2[x]] = T.rotl(last, constants.SHA3_ROTL[x]);
      last = B[0];
    }
    // Chi
    for (let y_step = 0; y_step < 5; y_step++) {
      let y = y_step * 5;
      for (let x = 0; x < 5; x++) B[x] = S[y + x];
      for (let x = 0; x < 5; x++) {
        const i0 = B[(x + 1) % 5];
        const i1 = B[(x + 2) % 5];
        S[y + x] = T.xor(B[x], T.and(T.not(i0), i1)); //((!i0) & (i1))
      }
    }
    // Iota
    S[0] = T.xor(S[0], T.fromN('u64', f.memory.rc[r].get()));
    return [S];
  });
}

function keccakBlockLenCb<T>(
  f: Scope,
  S: T[],
  blockLen: Val<'u32'>,
  cb: (S: any, i: number) => void
): T[] {
  const { u32 } = f.types;
  // TODO: just select on whole state? We have 24 rounds of complex stuff later,
  // doesn't matter what we do during the start. Possible blockLens
  // in u32: 72, 104, 136, 144, 168
  // in u64: 9, 13, 17, 18, 21
  // FIPS 202's Keccak[1600] users here only expose rates 72/104/136/144/168 bytes,
  // so this callback ladder touches exactly the first 9/13/17/18/21 u64 lanes.
  return f.block(S, (...S) => {
    for (let i = 0; i < 9; i++) cb(S, i);
    f.brIf(0, u32.eq(blockLen, u32.const(72)), ...S);
    for (let i = 9; i < 13; i++) cb(S, i);
    f.brIf(0, u32.eq(blockLen, u32.const(104)), ...S);
    for (let i = 13; i < 17; i++) cb(S, i);
    f.brIf(0, u32.eq(blockLen, u32.const(136)), ...S);
    for (let i = 17; i < 18; i++) cb(S, i);
    f.brIf(0, u32.eq(blockLen, u32.const(144)), ...S);
    for (let i = 18; i < 21; i++) cb(S, i);
    f.brIf(0, u32.eq(blockLen, u32.const(168)), ...S);
    return S;
  }) as T[];
}

export function genKeccak<T extends UnsignedType>(type: T, opts: { rounds: number }) {
  const { rounds } = opts;
  // separate function for 12 rounds?
  const memType = toGeneric<UnsignedType, T>(type);
  const mod = new Module('keccakF24')
    .mem('rc', array('u64', {}, 24))
    .batchMem(
      'state',
      struct({
        counter: 'u64',
        state: array(memType, {}, 25),
      })
    )
    // NOTE: we cannot use nd-array here, since chunk size depends on blockLen
    .mem('buffer', array(memType, {}, CHUNKS * 25))
    .fn('initKeccak', [], 'void', (f) => {
      const { u64 } = f.types;
      // Not great: it's mutable. Still, it's better than a hidden table / global.
      // This has to be done, to make JS version smaller: 30kb vs 200kb per round.
      // Wasm version isn't affected: it's always 30kb.
      for (let i = 0; i < constants.SHA3_IOTA.length; i++)
        f.memory.rc[i].set(u64.const(constants.SHA3_IOTA[i]));
    })
    .fn(
      'reset',
      ['u32', 'u32', 'u32', 'u32', 'u32'],
      'void',
      (f, batchPos, batchLen, maxWritten, blockLen, maxBlocks) => {
        const { u32 } = f.types;
        f.memory.state.range(batchPos, batchLen).as8().zero();
        const perBlock = u32.div(blockLen, u32.const(8));
        f.doN([], batchLen, (cnt) => {
          f.memory.buffer
            .reshape(batchPos, maxBlocks, perBlock)
            [u32.add(batchPos, cnt)].as8()
            .range(0, maxWritten)
            .fill(0);
          return [];
        });
      }
    )
    .batchFn(
      'processBlocks',
      { lanes: getLanes(type), perThread: MIN_PER_THREAD },
      ['u32', 'u32', 'u32', 'u32', 'u32'],
      (f, lanes, batchPos, perBatch, maxBlocks, blockLen, _isLast, _left, _padBlocks) => {
        const blocks = perBatch;
        const { u32 } = f.types;
        const T = f.getTypeGeneric<UnsignedType, T>(type, lanes);
        const items = u32.div(blockLen, u32.const(8)); // how many u64 items in block?
        const buffer = f.memory.buffer.reshape(batchPos, maxBlocks, items).lanes(lanes)[batchPos];
        const { state, counter } = f.memory.state.lanes(lanes)[batchPos];
        let S = state.get();
        let cnt = counter.get();
        [cnt, S] = f.doN1([cnt, S], blocks, (chunkPos, cnt, S) => {
          S = keccakBlockLenCb(f, S, blockLen, (S, i) => {
            S[i] = T.xor(S[i], readMSG(f, buffer[chunkPos][i]));
          });
          // Slower:
          // f.doN1([], items, (pos) => {
          //   T.set(
          //     'state', pos, T.xor(T.get('state', pos), T.get('input', u32.add(inputPos, pos)))
          //   );
          //   return [];
          // });
          [S] = keccakFn(f, type, S, rounds, lanes);
          return [cnt, S];
        });
        state.set(S);
      }
    )
    .fn(
      'padding',
      ['u32', 'u32', 'u32', 'u32', 'u32', 'u32'],
      'u32',
      (f, batchPos, take, maxBlocks, left, blockLen, suffix) => {
        const { u32 } = f.types;
        const items = u32.div(blockLen, u32.const(8)); // how many u64 items in block?
        const buffer = f.memory.buffer.reshape(batchPos, maxBlocks, items)[batchPos];
        // FIPS 202 Keccak[c] uses pad10*1 after the domain suffix only; unlike the
        // SHA/MD/Blake1 builders, there is no encoded message-length word in the final block here.
        buffer.as8().range(take, blockLen).fill(0, u32.add(left, blockLen)); // left + blockLen?
        // input[msgLen] ^= 0x80 (either last of current block or next block)
        // NOTE: suffix is const here, only sha3 and blake1 have different suffix.
        // For blake1 suffix is lengthFlag!
        // xorByte(T, 'buffer', take, suffix);
        buffer.as8()[take].mut.xor(suffix);
        // if msb + left==1 -> add padding block
        const noMSB = u32.eqz(u32.and(suffix, u32.const(0x80)));
        // if MSB need 2 bytes, otherwise 1
        const fits = u32.ge(left, u32.select(noMSB, u32.const(1), u32.const(2)));
        const paddingBlocks = u32.select(fits, u32.const(0), u32.const(1)); // fits ? 0 : 1
        const endOfBlock = u32.sub(
          u32.add(take, left, u32.mul(paddingBlocks, blockLen)),
          u32.const(1)
        );
        // input[blockLen-1] ^= 0x80
        buffer.as8()[endOfBlock].mut.xor(u32.const(0x80));
        return paddingBlocks;
      }
    )
    .batchFn(
      'processOutBlocks',
      { lanes: getLanes(type), perThread: MIN_PER_THREAD },
      ['u32', 'u32', 'u32'],
      (f, lanes, batchPos, perBatch, maxBlocks, outBlockLen, isLast) => {
        const blocks = perBatch;
        const { u32 } = f.types;
        const { state } = f.memory.state.lanes(lanes)[batchPos];
        let S = state.get();
        // Number of u64 lanes to output per squeeze block
        const itemsOut = u32.div(outBlockLen, u32.const(8));
        const buffer = f.memory.buffer.reshape(batchPos, maxBlocks, itemsOut).lanes(lanes)[
          batchPos
        ];
        [S] = f.doN1([S], blocks, (cnt, S) => {
          keccakBlockLenCb(f, S, outBlockLen, (_S, i) => {
            buffer[cnt][i].set(S[i]);
          });
          const moreInCall = u32.lt(u32.add(cnt, u32.const(1)), blocks);
          const doPermAfter = u32.or(u32.eq(isLast, u32.const(0)), moreInCall);
          S = f.block(S, (...S) => {
            f.brIf(0, u32.eqz(doPermAfter), ...S); // skip only for final block of final call
            [S] = keccakFn(f, type, S, rounds, lanes);
            return S;
          });
          return [S];
        });
        state.set(S);
      }
    );
  return mod;
}

export function genRipemd<T extends UnsignedType>(type: T, _opts: undefined) {
  const counterLen = 8;
  const memType = toGeneric<UnsignedType, T>(type);
  const mod = new Module('ripemd')
    .batchMem('state', struct({ counter: 'u64', state: array(memType, {}, 5) }))
    .mem('buffer', array(memType, {}, CHUNKS, 16))
    .use(padCounter(type, counterLen, 16, 5, true))
    .fn(
      'reset',
      ['u32', 'u32', 'u32', 'u32', 'u32'],
      'void',
      (f, batchPos, batchLen, maxWritten, blockLen, maxBlocks) => {
        f.memory.state.range(batchPos, batchLen).as8().zero();
        f.functions.resetBuffer.call(batchPos, batchLen, maxWritten, blockLen, maxBlocks);
      }
    )
    .batchFn(
      'processBlocks',
      { lanes: getLanes(type), perThread: MIN_PER_THREAD },
      ['u32', 'u32', 'u32', 'u32', 'u32'],
      (f, lanes, batchPos, perBatch, maxBlocks, blockLen, _isLast, _left, _padBlocks) => {
        const blocks = perBatch;
        const u64 = f.getType('u64', lanes);
        const T = f.getTypeGeneric<UnsignedType, T>(type, lanes);
        const { state, counter } = f.memory.state.lanes(lanes)[batchPos];
        const buffer = f.memory.buffer.reshape(batchPos, maxBlocks, 16).lanes(lanes)[batchPos];
        const blockLen64 = u64.fromN('u32', blockLen);
        type TVal = Val<UnsignedType, T>;
        let S = state.get();
        let cnt = counter.get();
        [cnt, S] = f.doN1([cnt, S], blocks, (chunkPos, cnt, S) => {
          const prev = S;
          const W = readMSG(f, buffer[chunkPos]);
          let [al, bl, cl, dl, el] = S;
          let [ar, br, cr, dr, er] = S;

          // Instead of iterating 0 to 80, we split it into 5 groups
          // And use the groups in constants, functions, etc. Much simpler
          function ripemd_f(group: number, x: TVal, y: TVal, z: TVal) {
            if (group === 0) return T.xor(x, y, z);
            if (group === 1) return T.or(T.and(x, y), T.andnot(z, x));
            if (group === 2) return T.xor(T.or(x, T.not(y)), z);
            if (group === 3) return T.or(T.and(x, z), T.andnot(y, z));
            return T.xor(x, T.or(y, T.not(z)));
          }
          for (let group = 0; group < 5; group++) {
            const rGroup = 4 - group;
            const hbl = constants.RIPEMD160_Kl160[group];
            const hbr = constants.RIPEMD160_Kr160[group];
            const rl = constants.RIPEMD160_idxL[group];
            const rr = constants.RIPEMD160_idxR[group];
            const sl = constants.RIPEMD160_shiftsL160[group];
            const sr = constants.RIPEMD160_shiftsR160[group];
            for (let i = 0; i < 16; i++) {
              const tl = T.add(
                T.rotl(T.add(al, ripemd_f(group, bl, cl, dl), W[rl[i]], T.const(hbl)), sl[i]),
                el
              );
              al = el;
              el = dl;
              dl = T.rotl(cl, 10);
              cl = bl;
              bl = tl;
            }
            // 2 loops are 10% faster
            for (let i = 0; i < 16; i++) {
              const tr = T.add(
                T.rotl(T.add(ar, ripemd_f(rGroup, br, cr, dr), W[rr[i]], T.const(hbr)), sr[i]),
                er
              );
              ar = er;
              er = dr;
              dr = T.rotl(cr, 10);
              cr = br;
              br = tr;
            }
          }
          cnt = u64.add(cnt, blockLen64);
          // RIPEMD-160 recombines the left and right lines with this fixed word permutation,
          // not by adding the two lanes back in place.
          return [
            cnt,
            [
              T.add(prev[1], cl, dr),
              T.add(prev[2], dl, er),
              T.add(prev[3], el, ar),
              T.add(prev[4], al, br),
              T.add(prev[0], bl, cr),
            ],
          ];
        });
        counter.set(cnt);
        state.set(S);
      }
    );
  return mod;
}

export function genMd5<T extends UnsignedType>(type: T, _opts: undefined) {
  const rounds = 64;
  const counterLen = 8;
  const memType = toGeneric<UnsignedType, T>(type);
  const mod = new Module('md5')
    .batchMem('state', struct({ counter: 'u64', state: array(memType, {}, 4) }))
    .mem('buffer', array(memType, {}, CHUNKS, 16))
    .use(padCounter(type, counterLen, 16, 4, true))
    .fn(
      'reset',
      ['u32', 'u32', 'u32', 'u32', 'u32'],
      'void',
      (f, batchPos, batchLen, maxWritten, blockLen, maxBlocks) => {
        f.memory.state.range(batchPos, batchLen).as8().zero();
        f.functions.resetBuffer.call(batchPos, batchLen, maxWritten, blockLen, maxBlocks);
      }
    )
    .batchFn(
      'processBlocks',
      { lanes: getLanes(type), perThread: MIN_PER_THREAD },
      ['u32', 'u32', 'u32', 'u32', 'u32'],
      (f, lanes, batchPos, perBatch, maxBlocks, blockLen, _isLast, _left, _padBlocks) => {
        const blocks = perBatch;
        const u64 = f.getType('u64', lanes);
        const T = f.getTypeGeneric<UnsignedType, T>(type, lanes);

        const { state, counter } = f.memory.state.lanes(lanes)[batchPos];
        const buffer = f.memory.buffer.reshape(batchPos, maxBlocks, 16).lanes(lanes)[batchPos];
        const blockLen64 = u64.fromN('u32', blockLen);
        let S = state.get();
        let cnt = counter.get();
        [cnt, S] = f.doN1([cnt, S], blocks, (chunkPos, cnt, S) => {
          const prev = S;
          const W = readMSG(f, buffer[chunkPos]);
          let [A, B, C, D] = S;
          for (let i = 0; i < rounds; i++) {
            let F, g, s;
            if (i < 16) {
              F = Chi(T, B, C, D);
              g = i;
              s = [7, 12, 17, 22];
            } else if (i < 32) {
              // MD5 round 2 `G(X,Y,Z) = XZ v Y not(Z)` is the same choice primitive
              // as round 1 after rotating the arguments to `(D, B, C)`.
              F = Chi(T, D, B, C);
              g = (5 * i + 1) % 16;
              s = [5, 9, 14, 20];
            } else if (i < 48) {
              F = T.xor(B, C, D);
              g = (3 * i + 5) % 16;
              s = [4, 11, 16, 23];
            } else {
              F = T.xor(C, T.or(B, T.not(D))); // F = C ^ (B | ~D);
              g = (7 * i) % 16;
              s = [6, 10, 15, 21];
            }
            F = T.add(F, A, T.const(constants.MD5_K[i]), W[g]);
            A = D;
            D = C;
            C = B;
            B = T.add(B, T.rotl(F, s[i % 4]));
          }
          cnt = u64.add(cnt, blockLen64);
          // Add the compressed chunk to the current hash value
          return [cnt, [A, B, C, D].map((v, idx) => T.add(v, prev[idx]))];
        });
        counter.set(cnt);
        state.set(S);
      }
    );
  return mod;
}

function blakeFn<N extends UnsignedType, G = unknown>(
  T: GetOps<N, G> & OpsFnForType<UnsignedType, Val<N, G>, Shift, Val<MaskType<N>, G>>,
  rounds: number,
  shifts: number[],
  sigma: TArg<Uint8Array>,
  V: Val<N, G>[],
  MSG: Val<N, G>[],
  TBL?: Val<N, G>[]
) {
  function G(aN: number, bN: number, cN: number, dN: number, x0N: number, x1N: number) {
    let x = MSG[sigma[x0N]];
    // blake1 only, but we cannot do this before this function, since same indice in sigma will
    // happen multiple times (we cannot prexor MSG with TBL)
    // Blake1 precomputes the companion constants in flattened G1/G2 order, so `TBL` stays
    // indexed by the call position (`x0N` / `x1N`) rather than by the permuted message word.
    if (TBL) x = T.xor(x, TBL[x0N]);
    let x2 = MSG[sigma[x1N]];
    if (TBL) x2 = T.xor(x2, TBL[x1N]);

    // prettier-ignore
    let a = V[aN], b = V[bN], c = V[cN], d = V[dN];
    // G1
    a = T.add(a, b, x);
    d = T.rotr(T.xor(d, a), shifts[0]);
    c = T.add(c, d);
    b = T.rotr(T.xor(b, c), shifts[1]);
    // G2
    a = T.add(a, b, x2);
    d = T.rotr(T.xor(d, a), shifts[2]);
    c = T.add(c, d);
    b = T.rotr(T.xor(b, c), shifts[3]);
    ((V[aN] = a), (V[bN] = b), (V[cN] = c), (V[dN] = d));
  }
  // `sigma` is flattened as 16 consecutive word indices per round, so `j` walks one round in
  // spec order: four column G calls followed by four diagonal G calls.
  for (let i = 0, j = 0; i < rounds; i++) {
    // columns
    G(0, 4, 8, 12, j++, j++);
    G(1, 5, 9, 13, j++, j++);
    G(2, 6, 10, 14, j++, j++);
    G(3, 7, 11, 15, j++, j++);
    // diagonals
    G(0, 5, 10, 15, j++, j++);
    G(1, 6, 11, 12, j++, j++);
    G(2, 7, 8, 13, j++, j++);
    G(3, 4, 9, 14, j++, j++);
  }
  return V;
}

export function genBlake1<T extends UnsignedType>(
  type: T,
  opts: { rounds: number; shifts: number[]; tbl: any[]; constants: any[] }
) {
  const { rounds, shifts, tbl, constants: ccc } = opts;
  const counterLen = type.startsWith('u32') ? 8 : 16;
  const memType = toGeneric<UnsignedType, T>(type);
  const mod = new Module('blake1')
    .batchMem(
      'state',
      struct({
        counter: 'u64',
        state: array(memType, {}, 8),
        salt: array(memType, { swapEndianness: true }, 4),
      })
    )
    .mem('buffer', array(memType, { swapEndianness: true }, CHUNKS, 16))
    .use(padCounter(type, counterLen, 16, 8, false))
    .fn(
      'reset',
      ['u32', 'u32', 'u32', 'u32', 'u32'],
      'void',
      (f, batchPos, batchLen, maxWritten, blockLen, maxBlocks) => {
        f.memory.state.range(batchPos, batchLen).as8().zero();
        f.functions.resetBuffer.call(batchPos, batchLen, maxWritten, blockLen, maxBlocks);
      }
    )
    .batchFn(
      'processBlocks',
      { lanes: getLanes(type), perThread: MIN_PER_THREAD },
      ['u32', 'u32', 'u32', 'u32', 'u32'],
      (f, lanes, batchPos, perBatch, maxBlocks, blockLen, isLast, left, padBlocks) => {
        const blocks = perBatch;
        const { u32 } = f.types;
        const u64 = f.getType('u64', lanes);
        const T = f.getTypeGeneric<UnsignedType, T>(type, lanes);
        const { state, counter, salt: saltMem } = f.memory.state.lanes(lanes)[batchPos];
        const buffer = f.memory.buffer.reshape(batchPos, maxBlocks, 16).lanes(lanes)[batchPos];
        let V = state.get();
        const salt = saltMem.get();
        let cnt = counter.get();
        [cnt, V] = f.doN1([cnt, V], blocks, (chunkPos, cnt, V) => {
          const chunkIsLast = u32.and(
            isLast,
            u32.eq(chunkPos, u32.sub(blocks, u32.add(u32.const(1), padBlocks)))
          ); // isLast & chunkPos==N-1-padBlocks
          const chunkIsPad = u32.and(
            isLast,
            u32.ne(padBlocks, u32.const(0)),
            u32.eq(chunkPos, u32.sub(blocks, u32.const(1)))
          );
          // isLast & chunkPos=-1
          // last nonPad = blockLen-left
          // all others: blockLen
          // padding = 0
          // isLast ? padBlocks ? 0 : blockLen-left : blockLen
          const curLen = u32.select(chunkIsLast, u32.sub(blockLen, left), blockLen);
          const x = u64.fromN('u32', curLen);
          cnt = u64.add(cnt, x);
          const MSG = readMSG(f, buffer[chunkPos]);

          for (let i = 0; i < 8; i++) V[8 + i] = T.const(ccc[i]);
          // SHA-3 proposal BLAKE v1.2 §2.1.3 / §2.2.3:
          // if the final emitted block contains only padding bits,
          // the compression counter for that block is zero instead of repeating the prior length.
          const internalLength = u64.select(chunkIsPad, u64.const(0), u64.mul(cnt, u64.const(8)));
          const L = T.from(u64.name, internalLength);
          V[12] = T.xor(V[12], L[0]);
          V[13] = T.xor(V[13], L[0]);
          if (L.length === 2) {
            V[14] = T.xor(V[14], L[1]);
            V[15] = T.xor(V[15], L[1]);
          }
          for (let i = 0; i < salt.length; i++) V[8 + i] = T.xor(V[8 + i], salt[i]);
          const prev = [...V];
          const TBL = tbl.map((i) => T.const(i));
          V = blakeFn(T, rounds, shifts, constants.BSIGMA, V, MSG, TBL);
          for (let i = 0; i < 8; i++) V[i] = T.xor(prev[i], V[i], V[8 + i]);
          for (let i = 0; i < 8; i++) V[i] = T.xor(V[i], salt[i % salt.length]);

          return [cnt, V.slice(0, 8)];
        });
        counter.set(cnt);
        state.set(V);
      }
    );
  return mod;
}

export function genBlake2<T extends UnsignedType>(
  type: T,
  opts: { rounds: number; shifts: number[]; IV: any }
) {
  const { rounds, shifts, IV } = opts;
  const S = constants.BSIGMA;
  const memType = toGeneric<UnsignedType, T>(type);
  const mod = new Module('blake2')
    .batchMem(
      'init',
      struct({ salt: array(memType, {}, 2), personalization: array(memType, {}, 2) })
    )
    .batchMem('state', struct({ counter: 'u64', state: array(memType, {}, 8) }))
    .mem('buffer', array(memType, {}, CHUNKS, 16))
    .fn(
      'reset',
      ['u32', 'u32', 'u32', 'u32', 'u32'],
      'void',
      (f, batchPos, batchLen, maxWritten, _blockLen, maxBlocks) => {
        f.memory.init.range(batchPos, batchLen).as8().zero();
        f.memory.state.range(batchPos, batchLen).as8().zero();
        const { u32 } = f.types;
        f.doN([], batchLen, (cnt) => {
          f.memory.buffer
            .reshape(batchPos, maxBlocks, 8)
            [u32.add(batchPos, cnt)].as8()
            .range(0, maxWritten)
            .fill(0);
          return [];
        });
      }
    )
    .batchFn(
      'initBlake2',
      { lanes: getLanes(type), perThread: MIN_PER_THREAD },
      ['u32', 'u32'],
      (f, lanes, batchPos, _perBatch, dkLen, keyLen) => {
        const { u32 } = f.types;
        const { salt, personalization } = f.memory.init.lanes(lanes)[batchPos];
        const { state } = f.memory.state.lanes(lanes)[batchPos];
        const T = f.getTypeGeneric<UnsignedType, T>(type, lanes);
        // src/hashes.ts preloads state[0..7] with the family IV; initBlake2 only xors p[0]
        // and the optional salt/personalization words on top of that RFC 7693 base state.
        // 2) param word (low 32 bits): dkLen | (keyLen<<8) | (1<<16) | (1<<24)
        let p = u32.or(dkLen, u32.shl(keyLen, 8));
        p = u32.or(p, u32.shl(u32.const(1), 16));
        p = u32.or(p, u32.shl(u32.const(1), 24));
        state[0].mut.xor(T.fromN('u32', p)); // xor into h0
        // 3) xor salt / personalization (assumed present)
        for (let i = 0; i < 2; i++) {
          state[4 + i].mut.xor(salt[i].get());
          state[6 + i].mut.xor(personalization[i].get());
        }
      }
    )
    .batchFn(
      'processOutBlocks',
      { lanes: getLanes(type), perThread: MIN_PER_THREAD },
      ['u32', 'u32', 'u32'],
      (f, lanes, batchPos, _perBatch, maxBlocks, _outBlockLen, _isLast) => {
        const { state } = f.memory.state.lanes(lanes)[batchPos];
        const S = state.get();
        const buffer = f.memory.buffer.reshape(batchPos, maxBlocks, S.length).lanes(lanes)[
          batchPos
        ];
        buffer[0].set(S);
      }
    )
    .fn(
      'padding',
      ['u32', 'u32', 'u32', 'u32', 'u32', 'u32'],
      'u32',
      (f, batchPos, take, maxBlocks, left, blockLen, _suffix) => {
        const { u32 } = f.types;
        const isEmpty = u32.eqz(take);
        f.memory.buffer
          .reshape(batchPos, maxBlocks, 16)
          [batchPos].as8()
          .range(take, blockLen)
          .fill(0, u32.select(isEmpty, blockLen, left));
        // We padding only if message is empty. Take=0 will never happen otherwise
        return u32.select(isEmpty, u32.const(1), u32.const(0));
      }
    )
    .batchFn(
      'processBlocks',
      { lanes: getLanes(type), perThread: MIN_PER_THREAD },
      ['u32', 'u32', 'u32', 'u32', 'u32'],
      (f, lanes, batchPos, perBatch, maxBlocks, blockLen, isLast, left, padBlocks) => {
        const N = perBatch;
        const { u32 } = f.types;
        const u64 = f.getType('u64', lanes);
        const T = f.getTypeGeneric<UnsignedType, T>(type, lanes);
        const { state, counter } = f.memory.state.lanes(lanes)[batchPos];
        const buffer = f.memory.buffer.reshape(batchPos, maxBlocks, 16).lanes(lanes)[batchPos];
        let V = state.get();
        let cnt = counter.get();
        [cnt, V] = f.doN1([cnt, V], N, (chunkPos, cnt, V) => {
          // isLast & chunkPos == N - 1
          const chunkIsLast = u32.and(u32.eq(chunkPos, u32.sub(N, u32.const(1))), isLast);
          // last nonPad = blockLen-left
          // all others: blockLen
          // padding = 0
          // isLast ? padBlocks ? 0 : blockLen-left : blockLen
          const curLen = u32.select(
            chunkIsLast,
            u32.select(u32.ne(padBlocks, u32.const(0)), u32.const(0), u32.sub(blockLen, left)),
            blockLen
          );
          cnt = u64.add(cnt, u64.fromN('u32', curLen));
          const prev = [...V];
          for (let i = 0; i < 8; i++) V.push(T.const(IV![i]));
          // Flags
          const L = T.from(u64.name, cnt);
          for (let i = 0; i < L.length; i++) V[12 + i] = T.xor(V[12 + i], L[i]);

          V[14] = T.select(chunkIsLast, T.not(V[14]), V[14]);
          V = blakeFn(T, rounds, shifts, S, V, readMSG(f, buffer[chunkPos]));
          for (let i = 0; i < 8; i++) V[i] = T.xor(prev[i], V[i], V[8 + i]);
          return [cnt, V.slice(0, 8)];
        });
        counter.set(cnt);
        state.set(V);
      }
    );
  return mod;
}

export function genBlake3(_type: TypeName, _opts = {}) {
  // Blake3 is actually 3 hashes:
  // - block hash: we have generic hash for up to 1kb blocks which just processes them
  //     - basically faster blake2s
  // - tree hash: we have some tree like hash that merges two children (output of block hash)
  // - output hash: different hash, which produces output
  //     - it hashes (last block from block hash) OR tree root - NOT result!
  const rounds = 7;
  const shifts = [16, 12, 8, 7];
  const blockLen = 64;
  const sigma = constants.B3_SIGMA;
  const IV = constants.B3_IV;
  const type = 'u32' as const;
  const tailSeqBlocks = MIN_PER_THREAD * getLanes(type);
  // NOTE: x10 (100MB) doesn't improve performance of 100MB benchmark.
  const mod = new Module('blake3')
    .batchMem(
      'state',
      struct({
        chunksDone: 'u64',
        chunkOut: 'u64',
        //
        flags: 'u32',
        chunkPos: 'u32',
        stackPos: 'u32',
        lastBlockRem: 'u32',
        iv: array('u32', {}, 8), // personalized iv, can be different from B3_IV
        state: array('u32', {}, 8),
        // max stack for u64 is actually 55, but we're extra-cautious
        stack: array('u32', {}, 64, 8),
      })
    )
    .mem('buffer', array('u32', {}, CHUNKS / 16, 16, 16)) // 16 * 16 * 4 = 1024 (1kb)
    // If everything is parallel and there is 1 block per parallel message,
    // each block produces 1 stack entry.
    .mem('stackBuffer', array('u32', {}, CHUNKS, 8)) // up to 16 stack elm per 1kb of buffer
    .fn('compressParents', ['u32', 'u32', 'u32'], 'void', (f, batchPos, stackPos, stackPosOut) => {
      const { u32 } = f.types;
      const { iv, stack, flags } = f.memory.state[batchPos];
      const T = f.types[type];
      let V = iv.get();
      // take two items from stack and merge
      const MSG = [
        ...readMSG(f, stack[stackPos]),
        ...readMSG(f, stack[u32.add(stackPos, u32.const(1))]),
      ];
      for (let i = 0; i < 4; i++) V[8 + i] = T.const(IV[i]);
      V[13] = u32.const(0);
      V[12] = u32.const(0);
      V[14] = u32.const(blockLen);
      V[15] = u32.or(flags.get(), u32.const(constants.B3_Flags.PARENT));
      V = blakeFn(T, rounds, shifts, sigma, V, MSG);
      for (let i = 0; i < 8; i++) V[i] = T.xor(V[i], V[8 + i]);
      stack[stackPosOut].set(V.slice(0, 8));
    })
    .fn('compressParentsFull', ['u32', 'u32'], 'void', (f, batchPos, isLast) => {
      const { u32, u64 } = f.types;
      const { chunksDone, stackPos } = f.memory.state[batchPos];
      // Important notes:
      // - `isLast` leaves us with two elements on stack (compressOut will do last merge each time)
      // - we can't merge N new leaves, since they are tree. We can't merge [a,b,c,d] in a loop;
      //   for new leaves we have to do: [ab, cd], [abcd].
      // If not the last one, compress only when there are trailing zeros in chunk counter
      // chunks used as binary tree where current stack is path.
      // Zero means current leaf is finished and can be compressed.
      // 1 (001) - leaf not finished (just push current chunk to stack)
      // 2 (010) - leaf finished at depth=1 (merge with last elm on stack and push back)
      // 3 (011) - last leaf not finished
      // 4 (100) - leafs finished at depth=1 and depth=2
      let [_chunks, curStackPos] = f.forLoop(
        [u64.add(chunksDone.get(), u64.const(1)), stackPos.get()], // let chunks = chunksDone + 1
        (chunks, curStackPos) =>
          u32.and(
            u32.ne(curStackPos, u32.const(0)),
            u32.or(isLast, u64.eqz(u64.and(chunks, u64.const(1))))
          ), // stackPos && (isLast || !(chunks & 1))
        (chunks, curStackPos) => [u64.shr(chunks, 1), curStackPos], // chunks >>= 1
        (chunks, curStackPos) => {
          curStackPos = u32.sub(curStackPos, u32.const(1)); // stackPos--;
          // skip last merge on before root
          f.breakIf(
            u32.and(isLast, u32.eq(curStackPos, u32.const(0))),
            undefined,
            chunks,
            curStackPos
          );
          // mod.compressParents(gFlags, stackPos, stackPos);
          f.functions.compressParents.call(batchPos, curStackPos, curStackPos);
          return [chunks, curStackPos];
        }
      );
      chunksDone.mut.add(u64.const(1));
      stackPos.set(u32.add(curStackPos, u32.const(1))); // stackPos++;
    })
    // processes single hash in parallel: only full chunks
    .batchFn(
      'proccessChunksSequential',
      { lanes: getLanes(type), perThread: MIN_PER_THREAD },
      ['u32', 'u32', 'u32', 'u32', 'u32', 'u32'],
      (
        f,
        lanes,
        batchPos,
        _perBatch,
        blockPos,
        blockLen,
        lastChunkPos,
        left,
        maxBlocks,
        parallelPos
      ) => {
        // f.print(`process sequential lanes=${lanes} batchPos`, batchPos, 'perBatch', perBatch);
        const { u32, u64 } = f.types;
        const u64T = f.getType('u64', lanes);
        const T = f.getType('u32', lanes);
        const { iv, chunksDone, flags: flagsMem } = f.memory.state[parallelPos];
        const chunksPerMsg = u32.div(maxBlocks, u32.const(16));
        const msgBlocks = f.memory.buffer.reshape(batchPos, maxBlocks, 16)[parallelPos];
        const block4 = msgBlocks.reshape(chunksPerMsg, 16, 16).lanes(lanes)[batchPos];
        let chunkCounter = u64.add(chunksDone.get(), u64.fromN('u32', batchPos));
        let flags = flagsMem.get();
        const flagsStart = u32.or(flags, u32.const(constants.B3_Flags.CHUNK_START));
        const flagsEnd = u32.or(flags, u32.const(constants.B3_Flags.CHUNK_END));
        let V = iv.get().map((i) => T.fromN(type, i));
        [V] = f.doN([V], 16, (cnt, V) => {
          const isLastBlock = u32.and(u32.eq(cnt, u32.const(16 - 1)));
          // const currFlags = b === 0 ? flagsStart : b === 15 ? flagsEnd : flags;
          const currFlags = u32.select(
            u32.eqz(cnt),
            flagsStart,
            u32.select(u32.eq(cnt, u32.const(15)), flagsEnd, flags)
          );
          // pos, currFlags, chunkCounter, blockPos
          const laneCounter = u64T.add(u64T.fromN('u64', chunkCounter), u64T.laneOffsets());
          for (let i = 0; i < 4; i++) V[8 + i] = T.const(IV[i]);
          const L = T.from(u64T.name, laneCounter);
          V[12] = L[0];
          V[13] = L[1];
          // V[14] = u32.select(chunkIsLast, u32.sub(blockLen, left), blockLen);
          // The isLastBlock + lastChunkPos mask was previously built as
          //   T.and(T.fromN('u32', isLastBlock), T.eq(vBatchPos, ...))
          // but T.fromN('u32', isLastBlock) splats the scalar 1 to [1,1,1,1] — a bit
          // value, not an all-ones lane mask. AND with T.eq's proper [-1,...] mask gave
          // [0,0,0,1], and since T.select lowers to v128.bitselect (bitwise, not
          // element-wise) only the LSB of `left` survived. That truncated V[14] to
          // blockLen - (left & 1) on the last block of the last chunk, so inputs whose
          // length falls in [4096k-63, 4096k-2] produced wrong digests.
          // Do the isLastBlock pick in scalar u32 (same across lanes), then gate by
          // the per-lane T.eq mask — matches the pattern in proccessChunksParallel below.
          const vBatchPos = T.add(T.laneOffsets(), T.fromN('u32', batchPos));
          V[14] = T.sub(
            T.fromN('u32', blockLen),
            T.select(
              T.eq(vBatchPos, T.fromN('u32', lastChunkPos)),
              T.fromN('u32', u32.select(isLastBlock, left, u32.const(0))),
              T.const(0)
            )
          );
          // flags?
          V[15] = T.fromN('u32', currFlags); // splats
          const MSG = readMSG(f, block4[u32.add(cnt, blockPos)]); // 16 x 16 x u32x4
          V = blakeFn(T, rounds, shifts, sigma, V, MSG);
          for (let i = 0; i < 8; i++) V[i] = T.xor(V[i], V[8 + i]);
          return [V.slice(0, 8)];
        });
        f.memory.stackBuffer.lanes(lanes)[batchPos].set(V);
      }
    )
    // processes multiple hashes in parallel
    .batchFn(
      'proccessChunksParallel',
      { lanes: getLanes(type), perThread: MIN_PER_THREAD },
      ['u32', 'u32', 'u32', 'u32', 'u32'],
      (f, lanes, batchPos, perBatch, blockPos, maxBlocks, blockLen, isLast, left) => {
        // f.print(`process parallel lanes=${lanes} batchPos`, batchPos, 'perBatch', perBatch);
        const blocks = perBatch;
        const { u32 } = f.types;
        const T = f.getType('u32', lanes);
        const u64T = f.getType('u64', lanes);
        const { iv, chunkPos, flags, state, stack, stackPos, chunksDone } =
          f.memory.state.lanes(lanes)[batchPos];
        const curIV = iv.get();
        // buffer is: (M(0...batchPos), perBatch, blockLen)
        // NOTE: we don't know full batch size, so we use batchPos, it is not used in indexing
        const buffer = f.memory.buffer.reshape(batchPos, maxBlocks, 16).lanes(lanes)[batchPos];
        // NOTE: we assume chunkPos is same across messages here
        const chunkPos32 = u32.fromN(chunkPos.type, chunkPos.get());
        // TODO: fix, conversion breaks if load!
        const curChunksDone = u64T.add(chunksDone.get(), u64T.const(0));
        const flagsMiddle = flags.get();
        const flagsStart = T.const(constants.B3_Flags.CHUNK_START);
        const flagsEnd = T.const(constants.B3_Flags.CHUNK_END);
        // Total: blocks we've processed so far
        // chunkCtr: chunks we've processed so far
        // blockCtr: blocks we've processed inside of the current chunk
        const [_total, _chunkCtr, V, lastChunkPos] = f.forLoop(
          [u32.const(0), u32.const(0), state.get(), chunkPos32],
          (total, _chunkCtr, _V, _chunkPos) => u32.lt(total, blocks), // cnt <blocks
          (total, chunkCtr, V, chunkPos) => [total, chunkCtr, V, chunkPos],
          (total, chunkCtr, V, chunkPos) => {
            // do 1..16
            const blocksLeft = u32.sub(blocks, total);
            const N = u32.min(blocksLeft, u32.sub(u32.const(16), chunkPos));
            // if chunkPos==0: use iv
            V = f.ifElse(u32.eqz(chunkPos), V, (...V) => {
              return curIV.slice(0, V.length);
            });
            [total, V, chunkPos] = f.doN1(
              [total, V, chunkPos],
              N,
              (blockCtr, total, V, chunkPos) => {
                const chunkIsLast = u32.and(
                  u32.eq(blocksLeft, N),
                  u32.eq(blockCtr, u32.sub(N, u32.const(1))),
                  isLast
                );
                const chunkStatePos = chunkPos;
                // const currFlags = b === 0 ? flagsStart : b === 15 ? flagsEnd : flags;
                const leafStart = u32.eqz(chunkStatePos);
                const leafEnd = u32.or(u32.eq(chunkStatePos, u32.const(15)), chunkIsLast);
                const currFlags = T.or(
                  flagsMiddle,
                  T.select(leafStart, flagsStart, T.const(0)),
                  T.select(leafEnd, flagsEnd, T.const(0))
                );
                // TODO: what actually should we read?
                const MSG = readMSG(f, buffer[u32.add(blockPos, total)]);
                for (let i = 0; i < 4; i++) V[8 + i] = T.const(IV[i]);
                const L = T.from(u64T.name, u64T.add(curChunksDone, u64T.fromN('u32', chunkCtr)));
                V[12] = L[0];
                V[13] = L[1];
                // TODO: per lane?
                V[14] = T.fromN('u32', u32.select(chunkIsLast, u32.sub(blockLen, left), blockLen));
                V[15] = currFlags;
                V = blakeFn(T, rounds, shifts, sigma, V, MSG);
                for (let i = 0; i < 8; i++) V[i] = T.xor(V[i], V[8 + i]);
                chunkPos = u32.select(leafEnd, u32.const(0), u32.add(chunkPos, u32.const(1)));
                return [u32.add(total, u32.const(1)), V.slice(0, 8), chunkPos];
              }
            );
            // if ended at 15 -> write to stack buf
            f.ifElse(u32.eqz(chunkPos), [], () => {
              // stackBuffer[chunkCtr].set(V);
              let currStackPos = u32.fromN(T.name, stackPos.get());
              // let isLastChunk = u32.and(isLast, u32.eq(total, u32.sub(blocks, u32.const(1))));
              let isLastChunk = u32.and(isLast, u32.eq(total, blocks));
              stack[currStackPos].set(V);
              for (let i = 0; i < lanes; i++) {
                f.functions.compressParentsFull.call(u32.add(batchPos, u32.const(i)), isLastChunk);
              }
            });
            // write to stackBuf?
            return [total, u32.add(chunkCtr, u32.const(1)), V, chunkPos];
          }
        );
        chunkPos.set(T.fromN('u32', lastChunkPos));
        f.ifElse(
          u32.ne(lastChunkPos, u32.const(0)),
          [],
          () => {
            state.set(V);
          },
          () => {
            state.as8().copyFrom(iv, 32);
          }
        );
      }
    )
    .fn(
      'processBlocks',
      ['u32', 'u32', 'u32', 'u32', 'u32', 'u32', 'u32', 'u32'],
      'void',
      (f, batchPos, batchLen, blocks, maxBlocks, blockLen, isLast, left, _padBlocks) => {
        /*
        Parallel vs Sequential:
        we got M hashes over N blocks, what to use?
        - if we have leftovers (lastBlockPos): finish in parallel
        - last non full chunk (blocks % 16): finish in parallel
        - Other cases? There should be some "configurable metric M/N ratio" that used to choose?
          - any reasonable defaults?
        - parallelSize = 1: always use sequential, but we still need parallel
          for leftovers / the last non-full chunk.
        */
        const { u32 } = f.types;
        const inBlocks = blocks;
        // Should be same for all batch elements
        const curPos = f.memory.state[batchPos].chunkPos.get();
        const curStackPos = f.memory.state[batchPos].stackPos.get();
        // Weird case: super broken optimization in blake3:
        const skipLast = u32.and(
          isLast, // last chunk
          u32.ne(blocks, u32.const(0)), // at least one block
          u32.eqz(curStackPos), // empty stack
          u32.le(u32.add(blocks, curPos), u32.const(16)) // <=16 blocks with already processed
        );
        const skipIdx = u32.sub(blocks, u32.const(1));
        const tailSeq = u32.and(
          u32.or(u32.eq(batchLen, u32.const(2)), u32.eq(batchLen, u32.const(3))),
          u32.ge(inBlocks, u32.const(tailSeqBlocks))
        );
        blocks = u32.select(skipLast, u32.sub(blocks, u32.const(1)), blocks);
        f.ifElse(
          tailSeq,
          [],
          () => {
            f.doN([], batchLen, (cnt) => {
              f.functions.processBlocks.call(
                u32.add(batchPos, cnt),
                u32.const(1),
                inBlocks,
                maxBlocks,
                blockLen,
                isLast,
                left,
                _padBlocks
              );
              return [];
            });
          },
          () =>
            f.ifElse(
              u32.gt(batchLen, u32.const(1)),
              [],
              () => {
                f.brIf(0, u32.eqz(blocks));
                // Process inside single call, no sequential
                f.functions.proccessChunksParallel.call(
                  batchPos, // batchPos
                  batchLen, // batchLen
                  blocks, // ->per Batch
                  u32.const(0), // blockPos?
                  maxBlocks,
                  blockLen,
                  u32.and(isLast, u32.eqz(skipLast)),
                  left
                );
              },
              () => {
                const STATE = f.memory.state[batchPos];
                const { stackPos, stack } = STATE;
                const prefix = u32.min(blocks, u32.sub(u32.const(16), curPos));
                const processPrefix = u32.and(
                  u32.ne(curPos, u32.const(0)),
                  u32.ne(prefix, u32.const(0))
                );
                let blocksProcessed = u32.const(0);
                f.ifElse(processPrefix, [], () => {
                  f.functions.proccessChunksParallel.call(
                    batchPos, // batchPos
                    batchLen, // batchLen
                    prefix, // ->per Batch
                    blocksProcessed, // blockPos?
                    maxBlocks,
                    blockLen,
                    u32.and(isLast, u32.eq(prefix, blocks), u32.eqz(skipLast)),
                    left
                  );
                });
                blocks = u32.select(processPrefix, u32.sub(blocks, prefix), blocks);
                blocksProcessed = u32.select(
                  processPrefix,
                  u32.add(blocksProcessed, prefix),
                  blocksProcessed
                );
                const blockChunks = u32.div(blocks, u32.const(16));
                // const blockChunks = ceilDiv(blocks, u32.const(16));
                const blocksLeft = u32.sub(blocks, u32.mul(blockChunks, u32.const(16)));
                [blocksProcessed] = f.ifElse(
                  u32.ne(blocks, u32.const(0)),
                  [blocksProcessed],
                  (blocksProcessed) => {
                    const lastChunkPos = u32.select(
                      u32.and(isLast, u32.eqz(blocksLeft)),
                      u32.sub(blockChunks, u32.const(1)),
                      blockChunks
                    );
                    [blocksProcessed] = f.ifElse(
                      u32.ne(blockChunks, u32.const(0)),
                      [blocksProcessed],
                      (blocksProcessed) => {
                        f.functions.proccessChunksSequential.call(
                          u32.const(0),
                          blockChunks,
                          u32.const(16),
                          blocksProcessed,
                          blockLen,
                          lastChunkPos,
                          left,
                          maxBlocks,
                          batchPos
                        );
                        return [u32.add(blocksProcessed, u32.mul(blockChunks, u32.const(16)))];
                      }
                    );
                    // at this point we have blockChunks inside stackBuf
                    const stackBuffer = f.memory.stackBuffer;
                    f.doN([], blockChunks, (i) => {
                      const curBuf = readMSG(f, stackBuffer[i]);
                      stack[stackPos.get()].set(curBuf);
                      const isLast2 = u32.and(isLast, u32.eq(i, lastChunkPos));
                      f.functions.compressParentsFull.call(batchPos, isLast2);
                      return [];
                    });
                    return [blocksProcessed];
                  }
                );
                // isLast && !stackPos && blocksLeft nonEmpty
                f.ifElse(u32.ne(blocksLeft, u32.const(0)), [], () => {
                  f.functions.proccessChunksParallel.call(
                    batchPos, // batchPos
                    batchLen, // batchLen
                    blocksLeft, // -> per Batch
                    blocksProcessed, // blockPos?
                    maxBlocks,
                    blockLen,
                    u32.and(isLast, u32.eqz(skipLast)),
                    left
                  );
                });
              }
            )
        );
        f.ifElse(u32.eqz(tailSeq), [], () => {
          f.doN([], batchLen, (cnt) => {
            const STATE = f.memory.state[u32.add(batchPos, cnt)];
            const { stack, lastBlockRem, state, iv } = STATE;
            f.ifElse(u32.eqz(STATE.chunkPos.get()), [], () => {
              state.as8().copyFrom(iv, 32);
            });
            // If there we have nothing on stack: copy last chunk as input for output function
            f.ifElse(skipLast, [], () => {
              const buffer = f.memory.buffer.reshape(batchPos, maxBlocks, 16)[
                u32.add(batchPos, cnt)
              ];
              const chunk = readMSG(f, buffer[skipIdx]);
              stack[0].set(chunk.slice(0, 8));
              stack[1].set(chunk.slice(8));
              lastBlockRem.set(u32.sub(blockLen, left));
            });
            return [];
          });
        });
      }
    )
    .batchFn(
      'processOutBlocks',
      { lanes: getLanes(type), perThread: MIN_PER_THREAD },
      ['u32', 'u32', 'u32'],
      (f, lanes, batchPos, perBatch, maxBlocks, outBlockLen, _isLast) => {
        // f.print(
        //   `processOutBlocks lanes=${lanes} batchPos=`,
        //   batchPos,
        //   'perBatch',
        //   perBatch,
        //   'maxBlocks',
        //   maxBlocks,
        //   'outBlockLen',
        //   outBlockLen
        // );
        const blocks = perBatch;
        const T = f.getType('u32', lanes);
        const u64T = f.getType('u64', lanes);
        const buffer = f.memory.buffer.reshape(batchPos, maxBlocks, 16).lanes(lanes)[batchPos];
        const { state, flags, stack, chunkOut, stackPos, lastBlockRem, chunkPos } =
          f.memory.state.lanes(lanes)[batchPos];
        // restore flags of last compressed message
        // const lastFlags =
        //   CTL_gFlags[0] |
        //   (CTL_stackPos[0]
        //     ? B3_Flags.PARENT
        //     : (!CTL_chunkPos[0] ? B3_Flags.CHUNK_START : 0) | B3_Flags.CHUNK_END);
        const curFlags = T.or(
          flags.get(),
          T.select(
            T.eqz(stackPos.get()),
            T.or(
              T.select(T.eqz(chunkPos.get()), T.const(constants.B3_Flags.CHUNK_START), T.const(0)),
              T.const(constants.B3_Flags.CHUNK_END)
            ),
            T.const(constants.B3_Flags.PARENT)
          ),
          T.const(constants.B3_Flags.ROOT)
        );
        // XOF output replays the exact final ROOT compression with incrementing `t`, so stack[0..1]
        // hold that call's 64-byte message: either the last chunk block or the two child CVs.
        const MSG = [...stack[0].get(), ...stack[1].get()];
        // doN1 == doWhile, will do at least once. don't call on empty inputs!
        let [curChunkOut] = f.doN1([chunkOut.get()], blocks, (cnt, curChunkOut) => {
          let V = state.get();
          const prev = [...V];
          for (let i = 0; i < 4; i++) V[8 + i] = T.const(IV[i]);
          const L = T.from(u64T.name, u64T.add(curChunkOut, u64T.const(0)));
          V[12] = L[0];
          V[13] = L[1];
          V[14] = T.select(T.eqz(stackPos.get()), lastBlockRem.get(), T.fromN('u32', outBlockLen));
          V[15] = curFlags;
          V = blakeFn(T, rounds, shifts, sigma, V, MSG);
          const out = [];
          for (let i = 0; i < 8; i++) out.push(T.xor(V[i], V[8 + i]));
          for (let i = 0; i < 8; i++) out.push(T.xor(prev[i], V[8 + i]));
          buffer[cnt].set(out);
          return [u64T.add(curChunkOut, u64T.const(1))];
        });
        chunkOut.set(curChunkOut);
      }
    )
    .fn(
      'padding',
      ['u32', 'u32', 'u32', 'u32', 'u32', 'u32'],
      'u32',
      (f, batchPos, take, maxBlocks, left, blockLen, _suffix) => {
        const { u32 } = f.types;
        const buffer = f.memory.buffer.reshape(batchPos, maxBlocks, 16)[batchPos];
        const isEmpty = u32.eqz(take);
        buffer
          .as8()
          .range(take, u32.select(isEmpty, blockLen, left))
          .zero();
        return u32.const(0);
      }
    )
    .fn(
      'reset',
      ['u32', 'u32', 'u32', 'u32', 'u32'],
      'void',
      (f, batchPos, batchLen, maxWritten, _blockLen, maxBlocks) => {
        f.memory.state.range(batchPos, batchLen).as8().zero();
        const { u32 } = f.types;
        f.doN([], batchLen, (cnt) => {
          f.memory.buffer
            .reshape(batchPos, maxBlocks, 16)
            [u32.add(batchPos, cnt)].as8()
            .range(0, maxWritten)
            .fill(0);
          return [];
        });
      }
    );
  return mod;
}
