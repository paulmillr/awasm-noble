/**
 * Reusable utils.
 * The file is not used in end-user code. Instead, it's used by awasm-compiler
 * to generate different build targets (wasm, wasm_threads, js, runtime).
 * @module
 */
import type { GetOps, Scope, Val } from '@awasm/compiler/module.js';
import { type TypeName } from '@awasm/compiler/types.js';

/**
 * Bytes API type helpers for old + new TypeScript.
 *
 * TS 5.6 has `Uint8Array`, while TS 5.9+ made it generic `Uint8Array<ArrayBuffer>`.
 * We can't use specific return type, because TS 5.6 will error.
 * We can't use generic return type, because most TS 5.9 software will expect specific type.
 *
 * Maps typed-array input leaves to broad forms.
 * These are compatibility adapters, not ownership guarantees.
 *
 * - `TArg` keeps byte inputs broad.
 * - `TRet` marks byte outputs for TS 5.6 and TS 5.9+ compatibility.
 */
export type TypedArg<T> = T extends BigInt64Array
  ? BigInt64Array
  : T extends BigUint64Array
    ? BigUint64Array
    : T extends Float32Array
      ? Float32Array
      : T extends Float64Array
        ? Float64Array
        : T extends Int16Array
          ? Int16Array
          : T extends Int32Array
            ? Int32Array
            : T extends Int8Array
              ? Int8Array
              : T extends Uint16Array
                ? Uint16Array
                : T extends Uint32Array
                  ? Uint32Array
                  : T extends Uint8ClampedArray
                    ? Uint8ClampedArray
                    : T extends Uint8Array
                      ? Uint8Array
                      : never;
/** Maps typed-array output leaves to narrow TS-compatible forms. */
export type TypedRet<T> = T extends BigInt64Array
  ? ReturnType<typeof BigInt64Array.of>
  : T extends BigUint64Array
    ? ReturnType<typeof BigUint64Array.of>
    : T extends Float32Array
      ? ReturnType<typeof Float32Array.of>
      : T extends Float64Array
        ? ReturnType<typeof Float64Array.of>
        : T extends Int16Array
          ? ReturnType<typeof Int16Array.of>
          : T extends Int32Array
            ? ReturnType<typeof Int32Array.of>
            : T extends Int8Array
              ? ReturnType<typeof Int8Array.of>
              : T extends Uint16Array
                ? ReturnType<typeof Uint16Array.of>
                : T extends Uint32Array
                  ? ReturnType<typeof Uint32Array.of>
                  : T extends Uint8ClampedArray
                    ? ReturnType<typeof Uint8ClampedArray.of>
                    : T extends Uint8Array
                      ? ReturnType<typeof Uint8Array.of>
                      : never;
/** Recursively adapts byte-carrying API input types. See {@link TypedArg}. */
export type TArg<T> =
  | T
  | ([TypedArg<T>] extends [never]
      ? T extends (...args: infer A) => infer R
        ? ((...args: { [K in keyof A]: TRet<A[K]> }) => TArg<R>) & {
            [K in keyof T]: T[K] extends (...args: any) => any ? T[K] : TArg<T[K]>;
          }
        : T extends [infer A, ...infer R]
          ? [TArg<A>, ...{ [K in keyof R]: TArg<R[K]> }]
          : T extends readonly [infer A, ...infer R]
            ? readonly [TArg<A>, ...{ [K in keyof R]: TArg<R[K]> }]
            : T extends (infer A)[]
              ? TArg<A>[]
              : T extends readonly (infer A)[]
                ? readonly TArg<A>[]
                : T extends Promise<infer A>
                  ? Promise<TArg<A>>
                  : T extends object
                    ? { [K in keyof T]: TArg<T[K]> }
                    : T
      : TypedArg<T>);
/** Recursively adapts byte-carrying API output types. See {@link TypedArg}. */
export type TRet<T> = T extends unknown
  ? T &
      ([TypedRet<T>] extends [never]
        ? T extends (...args: infer A) => infer R
          ? ((...args: { [K in keyof A]: TArg<A[K]> }) => TRet<R>) & {
              [K in keyof T]: T[K] extends (...args: any) => any ? T[K] : TRet<T[K]>;
            }
          : T extends [infer A, ...infer R]
            ? [TRet<A>, ...{ [K in keyof R]: TRet<R[K]> }]
            : T extends readonly [infer A, ...infer R]
              ? readonly [TRet<A>, ...{ [K in keyof R]: TRet<R[K]> }]
              : T extends (infer A)[]
                ? TRet<A>[]
                : T extends readonly (infer A)[]
                  ? readonly TRet<A>[]
                  : T extends Promise<infer A>
                    ? Promise<TRet<A>>
                    : T extends object
                      ? { [K in keyof T]: TRet<T[K]> }
                      : T
        : TypedRet<T>)
  : never;

export function getLanes(_type: TypeName) {
  // Even for u64 it is better to use virtual u64x4 than real u64x2.
  // Lane count is scheduling-only.
  // Batch functions still address logical messages by batch position.
  return 4;
}

export function readMSG(f: Scope, region: any, clear = true) {
  // `BUFFER.fill(0)` is slow garbage: even BUFFER.set() is faster,
  // but requires pre-allocated array of exact size.
  // So, instead of doing `fill` to zeroize data, we zeroize on read.
  // This should be slower in theory: for 100MB we would
  // wipe buffer on every 10MB chunk, instead of just once.
  //
  // The trick why it's faster: cache / memory locality,
  // we are wiping region which we've just touched.
  const T = f.getTypeGeneric(region.type);
  // Keep the block values live for the caller before zeroizing module-owned scratch.
  const res = region.get();
  if (clear) region.set(Array.isArray(res) ? res.map((_i) => T.const(0)) : T.const(0));
  return res;
}

// Shared workspace budget; callers reshape this count to each algorithm's block width.
export const CHUNKS = 10 * 1024 * 16; // ~10MB, 160K blocks
// Thread scheduling threshold; kernels still clamp actual work from their block counts.
export const MIN_PER_THREAD = 1024; // 1k blocks

// Shared u32 byteswap. Placed here so `mac.ts` doesn't need to import from AES modules
// (avoids circular deps).
export const bswap = (u32: GetOps<'u32'>, x: Val<'u32'>) =>
  u32.or(
    u32.or(u32.shl(u32.and(x, u32.const(0xff)), 24), u32.shl(u32.and(x, u32.const(0xff00)), 8)),
    u32.or(u32.shr(u32.and(x, u32.const(0xff0000)), 8), u32.shr(x, 24))
  );
