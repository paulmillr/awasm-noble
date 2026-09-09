/**
 * Core KDF logic for Scrypt and Argon2.
 * The file is not used in end-user code. Instead, it's used by awasm-compiler
 * to generate different build targets (wasm, wasm_threads, js, runtime).
 * @module
 */
import type { Scope, Val } from '@awasm/compiler/module.js';
import { Module, array } from '@awasm/compiler/module.js';
import { type TypeName } from '@awasm/compiler/types.js';
import { ARGON2_SYNC_POINTS, ARGON_MAX_BLOCKS, SCRYPT_BATCH } from '../kdf.ts';
import { salsaCore } from './ciphers.ts';

const _0xffffffffn = /* @__PURE__ */ BigInt(0xffffffff);
const _1n = /* @__PURE__ */ BigInt(1);
// Compiler backend flags are sparse; an absent capability is false.
const nativeArgon = (flags: { native64bit?: boolean; threads?: boolean }, lanes: number) =>
  !!flags.native64bit && !flags.threads && lanes === 1;

export const __TEST = { nativeArgon };

export function genScrypt(_type: TypeName, _opts = {}) {
  // Deno publish hits TS2589 on the internal 16-word state here; keep this generator-only helper
  // on widened types so the emitted target code stays unchanged.
  type Word = Val<'u32', unknown>;
  type State = Word[] & { __state__?: never };
  const salsa20_8 = (f: Pick<Scope, 'getType'>, lanes: number, X: State): void =>
    salsaCore(f, lanes, X as Word[], 8, true);
  return new Module('scrypt')
    .mem('xorInput', array('u32', {}, SCRYPT_BATCH, 16))
    .mem('output', array('u32', {}, 2 * SCRYPT_BATCH, 16)) // at least two blocks (state + current)
    .batchFn(
      'blockMix',
      { lanes: 4, perThread: 1024 },
      ['u32', 'u32', 'u32', 'u32'],
      (f, lanes, batchPos, _perBatch, blocks, r, p, needXor) => {
        const { u32 } = f.types;
        const T = f.getType('u32', lanes);
        const lastChunkIndex = u32.sub(u32.mul(r, u32.const(2)), u32.const(1));
        const perBlock = u32.mul(r, u32.const(2)); // 2 items per block
        const perBlockBytes = u32.mul(r, u32.const(128)); // 128 bytes per block

        const mem = f.memory.output.reshape(u32.add(blocks, u32.const(1)), p, perBlock, 16);
        const xorInput = f.memory.xorInput.reshape(p, perBlock, 16);

        // RFC 7914 §5 step 3: phase 2 applies BlockMix to X xor V[j], not to X directly.
        f.ifElse(needXor, [], () => {
          for (let l = 0; l < lanes; l++) {
            f.doN([], u32.mul(r, u32.const(2)), (i) => {
              const curBatchPos = u32.add(batchPos, u32.const(l));
              const av = mem[0][curBatchPos][i].as('u32x4');
              const bv = xorInput[curBatchPos][i].as('u32x4');
              f.doN([], 16 / 4, (i) => void av[i].mut.xor(bv[i].get()));
            });
          }
        });

        f.doN([], blocks, (c) => {
          const input = mem[c].lanes(lanes)[batchPos];
          const out = mem[u32.add(c, u32.const(1))].lanes(lanes)[batchPos];
          (
            f.doN as (
              state: readonly Word[],
              cnt: typeof r,
              body: (cnt: typeof r, ...s: Word[]) => Word[]
            ) => Word[]
          )(input[lastChunkIndex].get() as Word[], r, (i: typeof r, ...X: Word[]) => {
            const idx = u32.mul(i, u32.const(2));
            let inp = input[idx].get();
            for (let k = 0; k < 16; k++) X[k] = T.xor(X[k], inp[k]); // X = X ^ Input[2*i]
            salsa20_8(f, lanes, X as State);
            out[i].set(X);
            inp = input[u32.add(idx, u32.const(1))].get();
            for (let k = 0; k < 16; k++) X[k] = T.xor(X[k], inp[k]); // X = X ^ Input[2*i+1]
            salsa20_8(f, lanes, X as State);
            out[u32.add(r, i)].set(X); // Write to Output[r + i] (The "Tail")
            return X;
          });
        });
        // NOTE: blocks instead blocks-1, because starting block is not included in blocks
        //mem[0].as8().copyFrom(mem[u32.sub(blocks, u32.const(0))].as8(), u32.mul(perBlockBytes, p));
        mem[0]
          .lanes(lanes)
          [batchPos].as8()
          .copyFrom(mem[blocks].lanes(lanes)[batchPos].as8(), perBlockBytes);
      }
    );
}

export function genArgon2(_type: TypeName, _opts: {}) {
  /*
    refBlocks: [zero,                  zero,         zero, scratchpad, refBlock(1), ...]
    inputBlocks: [addressParams, addressTmp, addressResult,  input(0),    input(1), ...]
  */
  return new Module('argon')
    .mem('refBlocks', array('u64', {}, ARGON_MAX_BLOCKS, 128))
    .mem('inputBlocks', array('u64', {}, ARGON_MAX_BLOCKS, 128))
    .mem('indices', array('u32', {}, ARGON_MAX_BLOCKS))
    .mem('refIndices', array('u32', {}, ARGON_MAX_BLOCKS))
    .batchFn(
      'compress',
      { lanes: 4, perThread: 1024 },
      ['u32', 'u32', 'u32'],
      (f, lanes, batchPos, perBatch, prevPos, needXor, MAX_PARALLEL) => {
        const { u32 } = f.types;
        const T = f.getType('u64', lanes);
        const MASK32 = T.const(_0xffffffffn);
        const firstDim = u32.div(u32.const(ARGON_MAX_BLOCKS), MAX_PARALLEL);
        const blamka = (U: any, mask: any, A: any, B: any) => {
          const loProd = U.mul(U.and(A, mask), U.and(B, mask)); // 32×32 → low 64 mod 2^64
          return U.add(A, B, U.shl(loProd, 1)); // + 2 * loProd
        };
        const G = (U: any, mask: any, S: any[], ...chains: [number, number, number, number][]) => {
          const parts = [
            [0, 1, 3, 32],
            [2, 3, 1, 24],
            [0, 1, 3, 16],
            [2, 3, 1, 63],
          ];
          // Multiple chains are quarter-interleaved to expose independent native vector work.
          for (const [v0, v1, v2, shift] of parts) {
            for (const chain of chains) {
              const a = chain[v0];
              const b = chain[v1];
              const c = chain[v2];
              S[a] = blamka(U, mask, S[a], S[b]);
              S[c] = U.rotr(U.xor(S[c], S[a]), shift);
            }
          }
        };
        const P = (S: any[]) => {
          G(T, MASK32, S, [0, 4, 8, 12]);
          G(T, MASK32, S, [1, 5, 9, 13]);
          G(T, MASK32, S, [2, 6, 10, 14]);
          G(T, MASK32, S, [3, 7, 11, 15]);

          G(T, MASK32, S, [0, 5, 10, 15]);
          G(T, MASK32, S, [1, 6, 11, 12]);
          G(T, MASK32, S, [2, 7, 8, 13]);
          G(T, MASK32, S, [3, 4, 9, 14]);
        };
        const REF_BLOCKS = f.memory.refBlocks.reshape(firstDim, MAX_PARALLEL, 128);
        const REF_INDICES = f.memory.refIndices.reshape(firstDim, MAX_PARALLEL);
        const INPUT_BLOCKS = f.memory.inputBlocks.reshape(
          MAX_PARALLEL,
          u32.div(u32.const(ARGON_MAX_BLOCKS), MAX_PARALLEL),
          128
        );

        // A scalar batch tail has one Argon block, so native u64x2 lanes can work across that
        // block instead of emulating parallel lanes. JS and threaded memory keep the compact
        // reference kernel; this path uses the same fixed scratch window and ABI.
        if (nativeArgon(f.flags, lanes)) {
          const V = f.types.u64x2;
          const mask = V.const(_0xffffffffn);
          const G2 = (S: any[]) => {
            G(V, mask, S, [0, 1, 2, 3], [4, 5, 6, 7]);
            return S;
          };
          const P2 = (S: any[]) => {
            let [v0, v2, v4, v6, v1, v3, v5, v7] = G2([
              S[0],
              S[2],
              S[4],
              S[6],
              S[1],
              S[3],
              S[5],
              S[7],
            ]);
            let b45 = V.shuffleLanes(v2, v3, [1, 2]);
            let b67 = V.shuffleLanes(v3, v2, [1, 2]);
            let d45 = V.shuffleLanes(v7, v6, [1, 2]);
            let d67 = V.shuffleLanes(v6, v7, [1, 2]);
            [v0, b45, v5, d45, v1, b67, v4, d67] = G2([v0, b45, v5, d45, v1, b67, v4, d67]);
            v2 = V.shuffleLanes(b67, b45, [1, 2]);
            v3 = V.shuffleLanes(b45, b67, [1, 2]);
            v6 = V.shuffleLanes(d45, d67, [1, 2]);
            v7 = V.shuffleLanes(d67, d45, [1, 2]);
            return [v0, v1, v2, v3, v4, v5, v6, v7];
          };

          f.doN([], perBatch, (i) => {
            const curPrev = u32.add(i, prevPos);
            const outPos = u32.add(curPrev, u32.const(1));
            const refPos = REF_INDICES[outPos][batchPos].get();
            const prev = INPUT_BLOCKS[batchPos][curPrev].as('u64x2');
            const localRef = INPUT_BLOCKS[batchPos][refPos].as('u64x2');
            const externalRef = REF_BLOCKS[outPos][batchPos].as('u64x2');
            const output = INPUT_BLOCKS[batchPos][outPos].as('u64x2');
            const rows = REF_BLOCKS[3][batchPos].as('u64x2');
            const isLocal = u32.ne(outPos, refPos);
            f.doN([], 8, (c) => {
              const offset = u32.mul(c, u32.const(8));
              const state = Array.from({ length: 8 }, (_, j) => {
                const pos = u32.add(offset, u32.const(j));
                // Pin the carried vector tuple: the generic batch scope otherwise infers its
                // empty-state overload here, despite both branches returning one u64x2 value.
                const [ref] = f.ifElse<[Val<'u64x2'>]>(
                  isLocal,
                  [V.const(BigInt(0))],
                  () => [localRef[pos].get()],
                  () => [externalRef[pos].get()]
                );
                return V.xor(prev[pos].get(), ref);
              });
              f.ifElse(
                needXor,
                [],
                () =>
                  state.forEach((value, j) => output[u32.add(offset, u32.const(j))].mut.xor(value)),
                () => state.forEach((value, j) => output[u32.add(offset, u32.const(j))].set(value))
              );
              P2(state).forEach((value, j) => rows[u32.add(offset, u32.const(j))].set(value));
            });
            f.doN([], 8, (c) => {
              const state = P2(
                Array.from({ length: 8 }, (_, j) => rows[u32.add(c, u32.const(j * 8))].get())
              );
              state.forEach((value, j) => output[u32.add(c, u32.const(j * 8))].mut.xor(value));
            });
          });
          return;
        }

        f.doN([], perBatch, (i) => {
          const curPrev = u32.add(i, prevPos);
          const refPos = u32.add(curPrev, u32.const(1));
          const refPosScalar = REF_INDICES[refPos].range(batchPos, lanes).get();
          // Instead of interleaved read/write, we do sequential SIMD loop here
          for (let l = 0; l < lanes; l++) {
            const curBatchPos = u32.add(batchPos, u32.const(l));
            const T2 = f.types['u64x4'];
            const rb = REF_BLOCKS[refPos][curBatchPos].as('u64x4');
            const ib = INPUT_BLOCKS[curBatchPos][curPrev].as('u64x4');
            const ob = INPUT_BLOCKS[curBatchPos][refPos].as('u64x4');
            const refPosBlock = INPUT_BLOCKS[curBatchPos][refPosScalar[l]].as('u64x4');
            f.doN([], 128 / 4, (i: any) => {
              const [rbVal] = f.ifElse(
                u32.ne(refPos, refPosScalar[l]),
                [T2.const(0)],
                (..._s) => [refPosBlock[i].get()],
                (..._s) => [rb[i].get()]
              );
              const val = T2.xor(rbVal, ib[i].get());
              rb[i].set(val);
              f.ifElse(
                needXor,
                [],
                () => void ob[i].mut.xor(val),
                () => void ob[i].set(val)
              );
            });
          }
          const outBlock = INPUT_BLOCKS.lanes(lanes)[batchPos][refPos];
          const colIdx = [0, 1, 2, 3, 4, 5, 6, 7, 8, 9, 10, 11, 12, 13, 14, 15];
          const rowIdx = [0, 1, 16, 17, 32, 33, 48, 49, 64, 65, 80, 81, 96, 97, 112, 113];
          // RFC 9106 §3.5 applies P rowwise then columnwise; rc=0 transposes rows into
          // scratchpad so rc=1 can read columns contiguously.
          // Full unroll: 0.5mb, slightly faster (~10-15%)
          f.doN([], 2, (rc) => {
            const inputIdx = u32.select(u32.eqz(rc), refPos, u32.const(3));
            const outputIdx = u32.select(u32.eqz(rc), u32.const(3), refPos);
            f.doN([], 8, (c) => {
              const idx = colIdx.map((j) => u32.add(u32.mul(c, u32.const(16)), u32.const(j)));
              let state = idx.map((i) => REF_BLOCKS[inputIdx].lanes(lanes)[batchPos][i].get());
              P(state);
              const writeIdx = rowIdx.map((j) => u32.add(u32.mul(c, u32.const(2)), u32.const(j)));
              f.ifElse(
                u32.eqz(rc),
                [],
                // rc=0: rows -> scratchpad
                () =>
                  writeIdx.forEach((i, j) =>
                    REF_BLOCKS[outputIdx].lanes(lanes)[batchPos][i].set(state[j])
                  ),
                // rc=1: columns -> outBlock
                () => writeIdx.forEach((i, j) => outBlock[i].mut.xor(state[j]))
              );
            });
          });
        });
      }
    )
    .fn(
      'getAddresses',
      ['u32', 'u32', 'u32', 'u32', 'u32', 'u32', 'u32', 'u32', 'u32', 'u32'],
      'void',
      (
        f,
        batchPos,
        batchLen,
        perBatch,
        laneLen,
        segmentLen,
        index,
        lanes,
        prevBlockPos,
        flushStartRel,
        MAX_PARALLEL
      ) => {
        const { u32, u64 } = f.types;
        const firstDim = u32.div(u32.const(ARGON_MAX_BLOCKS), MAX_PARALLEL);
        // first dimension is dummy
        const INDICES = f.memory.indices.reshape(firstDim, MAX_PARALLEL);
        const REF_INDICES = f.memory.refIndices.reshape(firstDim, MAX_PARALLEL);
        const REF_BLOCKS = f.memory.refBlocks.reshape(firstDim, MAX_PARALLEL, 128);
        const INPUT_BLOCKS = f.memory.inputBlocks.reshape(
          MAX_PARALLEL,
          u32.div(u32.const(ARGON_MAX_BLOCKS), MAX_PARALLEL),
          128
        );

        const addrState = INPUT_BLOCKS[0][0].get().map((i) => u32.fromN('u64', i));
        const r = addrState[0];
        const l = addrState[1];
        const s = addrState[2];
        // const mP = addrState[3];
        // const t = addrState[4];
        const type = addrState[5];
        // const cur128block? = addrState[6];
        const dataIndependent = u32.or(
          u32.eq(type, u32.const(1)),
          u32.and(u32.eq(type, u32.const(2)), u32.and(u32.eqz(r), u32.lt(s, u32.const(2))))
        );
        // r == 0 ? s * segmentLen : laneLen - segmentLen
        const area1 = u32.select(u32.eqz(r), u32.mul(s, segmentLen), u32.sub(laneLen, segmentLen));
        const isStart = u32.and(u32.eqz(r), u32.eqz(s));
        const startPos = u32.select(
          //r !== 0 && s !== ARGON2_SYNC_POINTS - 1
          u32.and(u32.ne(r, u32.const(0)), u32.ne(s, u32.const(ARGON2_SYNC_POINTS - 1))),
          u32.mul(segmentLen, u32.add(s, u32.const(1))), // (s + 1) * segmentLen
          u32.const(0)
        );

        f.doN([], perBatch, (j) => {
          const curIndex = u32.add(index, j);
          const curIndices = INDICES[j];
          const idx1 = u32.sub(curIndex, u32.const(1)); // index-1
          const curPrevBlockPos = u32.add(prevBlockPos, j);
          const addrBlock = u32.select(u32.eqz(dataIndependent), curPrevBlockPos, u32.const(2));
          const addrIdx = u32.select(
            u32.eqz(dataIndependent),
            u32.const(0),
            u32.rem(curIndex, u32.const(128))
          );
          const shouldUpdate = u32.and(
            u32.eq(dataIndependent, u32.const(1)),
            u32.or(u32.eqz(addrIdx), u32.and(isStart, u32.eq(curIndex, u32.const(2))))
          );
          f.ifElse(shouldUpdate, [], () => {
            f.doN([], batchLen, (cnt) => {
              const curBatch = u32.add(batchPos, cnt);
              INPUT_BLOCKS[curBatch][0][6].mut.add(u64.const(_1n));
              REF_INDICES[1][curBatch].set(u32.const(1));
              REF_INDICES[2][curBatch].set(u32.const(2));
              REF_BLOCKS[1][u32.add(batchPos, cnt)].as8().fill(0);
              REF_BLOCKS[2][u32.add(batchPos, cnt)].as8().fill(0);
            });
            f.functions.compress.call(
              batchPos,
              batchLen,
              u32.const(2),
              u32.const(0),
              u32.const(0),
              MAX_PARALLEL
            );
          });
          const currentSliceStart = u32.mul(s, segmentLen);
          // absFlushStart = currentSliceStart + flushStartRel
          const absFlushStart = u32.add(currentSliceStart, flushStartRel);
          // absBatchStart = currentSliceStart + index (index is batchStart)
          const absBatchStart = u32.add(currentSliceStart, index);
          f.doN([], batchLen, (i) => {
            const curBatchPos = u32.add(batchPos, i);
            const curL = u32.add(l, i);
            const addr = INPUT_BLOCKS[curBatchPos][addrBlock][addrIdx].get();
            const [randL, randH] = u32.from('u64', addr);
            // const refLane = r === 0 && s === 0 ? l : randH % lanes;
            const refLane = u32.select(
              u32.and(u32.eqz(r), u32.eqz(s)),
              curL,
              u32.rem(randH, lanes)
            );
            const sameLane = u32.eq(refLane, curL); // const sameLane = refLane == l ? 1 : 0;
            // !index ? area1-1 : area1
            const area2 = u32.select(u32.eqz(curIndex), u32.sub(area1, u32.const(1)), area1);
            // !sameLane ? area2 : area1-idx1;
            const area3 = u32.select(u32.eqz(sameLane), area2, u32.add(area1, idx1));
            // r=0 && s=0 ? index - 1 : area1
            const area = u32.select(u32.and(u32.eqz(r), u32.eqz(s)), idx1, area3);
            const randL64 = u64.fromN('u32', randL);
            const randL64Sqr = u64.mul(randL64, randL64);
            const randLSqr = u32.from('u64', randL64Sqr)[1];
            const mulHi64 = u64.mul(u64.fromN('u32', area), u64.fromN('u32', randLSqr));
            const mulHi = u32.from('u64', mulHi64)[1];
            const rel = u32.sub(u32.sub(area, u32.const(1)), mulHi);
            const refPos = u32.rem(u32.add(startPos, rel), laneLen);
            const res = u32.add(u32.mul(laneLen, refLane), refPos);
            curIndices[curBatchPos].set(res);
            const currentPos = u32.add(u32.add(prevBlockPos, u32.const(1)), j);
            // 1. Check for Local Dependency (in current batch)
            const delta = u32.add(u32.sub(u32.sub(refPos, currentSliceStart), index), u32.const(1));
            const isLocal = u32.and(u32.eq(refLane, curL), u32.lt(delta, u32.add(j, u32.const(1))));
            // 2. Check for Dirty Buffer Dependency (previous batches in this segment)
            // Range: [absFlushStart ... absBatchStart)
            const isInBuffer = u32.and(
              u32.eq(refLane, curL),
              u32.and(u32.ge(refPos, absFlushStart), u32.lt(refPos, absBatchStart))
            );
            // Calculate index in ring buffer if hit
            // Buffer start (idx 4) corresponds to absFlushStart
            const bufferIdx = u32.add(u32.const(4), u32.sub(refPos, absFlushStart));
            // Priority: Local > Buffer > External (currentPos)
            const finalIdx = u32.select(
              isLocal,
              u32.add(prevBlockPos, delta),
              u32.select(isInBuffer, bufferIdx, currentPos)
            );
            REF_INDICES[currentPos][curBatchPos].set(finalIdx);
          });
        });
      }
    )
    .fn(
      'compressAndGetAddress',
      ['u32', 'u32', 'u32', 'u32', 'u32', 'u32', 'u32', 'u32', 'u32', 'u32', 'u32'],
      'void',
      (
        f,
        batchPos,
        batchLen,
        laneLen,
        segmentLen,
        index,
        lanes,
        prevBlockPos,
        flushStartRel,
        MAX_PARALLEL,
        needXor,
        hasNext
      ) => {
        const { u32 } = f.types;
        f.functions.compress.call(
          batchPos,
          batchLen,
          u32.const(1),
          prevBlockPos,
          needXor,
          MAX_PARALLEL
        );
        f.ifElse(hasNext, [], () => {
          f.functions.getAddresses.call(
            batchPos,
            batchLen,
            u32.const(1),
            laneLen,
            segmentLen,
            u32.add(index, u32.const(1)),
            lanes,
            u32.add(prevBlockPos, u32.const(1)),
            flushStartRel,
            MAX_PARALLEL
          );
        });
      }
    );
}
