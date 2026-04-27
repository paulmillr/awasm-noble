/**
 * Utilities: assertions, conversions.
 * @module
 */
import type { HashInstance } from './hashes-abstract.ts';

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

/** Whether the current platform is little-endian. */
export const isLE: boolean = /* @__PURE__ */ (() =>
  new Uint8Array(new Uint32Array([0x11223344]).buffer)[0] === 0x44)();

const assertLE = (littleEndian = isLE) => {
  if (littleEndian) return;
  // Fail closed on BE for now: qemu-smoke checks still showed broken wasm outputs, and the JS
  // target would need a dedicated BE compilation path that is not currently generated.
  throw new Error('big-endian platforms are unsupported');
};

assertLE();

/** Checks if something is Uint8Array. Be careful: nodejs Buffer will return true. */
/**
 * Checks whether a value is a byte-oriented Uint8Array view.
 * @param a - value to inspect.
 * @returns True when the value is a Uint8Array-compatible byte view.
 * @example
 * ```ts
 * import { isBytes } from '@awasm/noble/utils.js';
 * isBytes(new Uint8Array([1, 2, 3]));
 * ```
 */
export function isBytes(a: unknown): a is Uint8Array {
  // Plain `instanceof Uint8Array` is too strict for some Buffer / proxy / cross-realm cases.
  // The fallback still requires a real ArrayBuffer view, so plain
  // JSON-deserialized `{ constructor: ... }` spoofing is rejected, and
  // `BYTES_PER_ELEMENT === 1` keeps the fallback on byte-oriented views.
  return (
    a instanceof Uint8Array ||
    (ArrayBuffer.isView(a) &&
      a.constructor.name === 'Uint8Array' &&
      'BYTES_PER_ELEMENT' in a &&
      a.BYTES_PER_ELEMENT === 1)
  );
}

/**
 * Asserts something is boolean.
 * @param b - value to validate.
 * @throws On wrong argument types. {@link TypeError}
 * @example
 * ```ts
 * import { abool } from '@awasm/noble/utils.js';
 * abool(true);
 * ```
 */
export function abool(b: boolean): void {
  if (typeof b !== 'boolean') throw new TypeError(`boolean expected, not ${b}`);
}

/**
 * Asserts something is a non-negative safe integer.
 * @param n - value to validate.
 * @param title - optional field name for error messages.
 * @throws On wrong argument types. {@link TypeError}
 * @throws On wrong argument ranges or values. {@link RangeError}
 * @example
 * ```ts
 * import { anumber } from '@awasm/noble/utils.js';
 * anumber(7, 'count');
 * ```
 */
export function anumber(n: number, title: string = ''): void {
  const prefix = title && `"${title}" `;
  if (typeof n !== 'number') throw new TypeError(`${prefix}expected number, got ${typeof n}`);
  if (!Number.isSafeInteger(n) || n < 0) {
    throw new RangeError(`${prefix}expected integer >= 0, got ${n}`);
  }
}

/**
 * Asserts something is Uint8Array.
 * @param value - byte array candidate.
 * @param length - optional exact length requirement.
 * @param title - optional field name for error messages.
 * @returns The validated byte array.
 * @throws On wrong argument types. {@link TypeError}
 * @throws On wrong argument ranges or values. {@link RangeError}
 * @example
 * ```ts
 * import { abytes } from '@awasm/noble/utils.js';
 * abytes(new Uint8Array([1, 2, 3]), 3, 'msg');
 * ```
 */
export function abytes(
  value: TArg<Uint8Array>,
  length?: number,
  title: string = ''
): TRet<Uint8Array> {
  const bytes = isBytes(value);
  const len = value?.length;
  const needsLen = length !== undefined;
  const prefix = title && `"${title}" `;
  if (!bytes) throw new TypeError(prefix + 'expected Uint8Array, got type=' + typeof value);
  if (needsLen && len !== length)
    throw new RangeError(
      prefix + 'expected Uint8Array of length ' + length + ', got length=' + len
    );
  return value as TRet<Uint8Array>;
}

/**
 * Asserts a hash-like instance has not been destroyed or finished.
 * @param instance - instance to validate.
 * @param checkFinished - whether to reject already-finished instances.
 * @throws If the documented runtime validation or state check fails. {@link Error}
 * @example
 * ```ts
 * import { aexists } from '@awasm/noble/utils.js';
 * aexists({ destroyed: false, finished: false });
 * ```
 */
export function aexists(instance: any, checkFinished = true): void {
  if (instance.destroyed) throw new Error('Hash instance has been destroyed');
  if (checkFinished && instance.finished) throw new Error('Hash#digest() has already been called');
}

/**
 * Asserts an output buffer is a byte array with sufficient capacity.
 * @param out - destination buffer.
 * @param instance - object exposing `outputLen`.
 * @throws On wrong argument types. {@link TypeError}
 * @throws On wrong argument ranges or values. {@link RangeError}
 * @example
 * ```ts
 * import { aoutput } from '@awasm/noble/utils.js';
 * aoutput(new Uint8Array(32), { outputLen: 32 });
 * ```
 */
export function aoutput(out: any, instance: any): void {
  abytes(out, undefined, 'output');
  const min = instance.outputLen;
  if (out.length < min) {
    // Shared digestInto() contracts treat undersized destinations as a range problem, not a
    // generic runtime failure, so callers can distinguish "wrong type" from "too short".
    throw new RangeError('digestInto() expects output buffer of length at least ' + min);
  }
}

/**
 * Asserts a hash surface looks like one produced by the hash factory.
 * @param h - hash surface to validate.
 * @throws On wrong argument types. {@link TypeError}
 * @throws On wrong argument ranges or values. {@link RangeError}
 * @throws If a documented runtime validation or state check fails. {@link Error}
 * @example
 * ```ts
 * import { sha256 } from '@awasm/noble';
 * import { ahash } from '@awasm/noble/utils.js';
 * ahash(sha256);
 * ```
 */
export function ahash<Opts>(h: TArg<HashInstance<Opts>>): void {
  if (typeof h !== 'function' || typeof h.create !== 'function')
    throw new TypeError('Hash must created by hashes.mkHash');
  anumber(h.outputLen);
  anumber(h.blockLen);
  // HMAC and KDF callers treat these as real byte lengths; allowing zero lets fake wrappers pass
  // validation and can produce empty outputs instead of failing fast.
  if (h.outputLen < 1) throw new Error('"outputLen" must be >= 1');
  if (h.blockLen < 1) throw new Error('"blockLen" must be >= 1');
}

/** Compatibility alias matching noble-hashes `CHash<Instance, Opts>` consumers. */
export type CHash<_T = any, Opts = undefined> = HashInstance<Opts>;
/** Compatibility alias matching noble-hashes `CHashXOF<Instance, Opts>` consumers. */
export type CHashXOF<_T = any, Opts = undefined> = HashInstance<Opts>;

/** Generic type encompassing 8/16/32-byte arrays - but not 64-byte. */
// prettier-ignore
export type TypedArray = Int8Array | Uint8ClampedArray | Uint8Array |
  Uint16Array | Int16Array | Uint32Array | Int32Array;

/**
 * Casts a typed-array view to bytes over the same memory region.
 * Shared buffer view in native memory order; used for internal state init, not endian-normalized serialization.
 * @param arr - source typed-array view.
 * @returns Byte view over the same buffer region.
 * @example
 * ```ts
 * import { u8 } from '@awasm/noble/utils.js';
 * u8(new Uint32Array([1]));
 * ```
 */
export function u8(arr: TArg<TypedArray>): TRet<Uint8Array> {
  return new Uint8Array(arr.buffer, arr.byteOffset, arr.byteLength) as TRet<Uint8Array>;
}

/**
 * Casts a typed-array view to 32-bit words over the same memory region.
 * Shared native-order word view; byteOffset must be 4-byte aligned and trailing 1..3 bytes are ignored.
 * @param arr - source typed-array view.
 * @returns Uint32Array view over the same buffer region.
 * @example
 * ```ts
 * import { u32 } from '@awasm/noble/utils.js';
 * u32(new Uint8Array([1, 2, 3, 4]));
 * ```
 */
export function u32(arr: TArg<TypedArray>): TRet<Uint32Array> {
  return new Uint32Array(
    arr.buffer,
    arr.byteOffset,
    Math.floor(arr.byteLength / 4)
  ) as TRet<Uint32Array>;
}

/**
 * Byte-swaps each 32-bit word on big-endian platforms.
 * @param arr - word array to normalize in place.
 * @returns The input array after any required byte swaps.
 * @example
 * ```ts
 * import { swap32IfBE } from '@awasm/noble/utils.js';
 * const words = new Uint32Array([0x11223344]);
 * swap32IfBE(words);
 * ```
 */
export function swap32IfBE(arr: TArg<Uint32Array>): TRet<Uint32Array> {
  if (isLE) return arr as TRet<Uint32Array>;
  for (let i = 0; i < arr.length; i++) {
    const x = arr[i];
    arr[i] = ((x << 24) | ((x & 0xff00) << 8) | ((x >>> 8) & 0xff00) | (x >>> 24)) >>> 0;
  }
  return arr as TRet<Uint32Array>;
}

/**
 * Zeroize typed arrays in place. Warning: JS provides no guarantees.
 * @param arrays - arrays to overwrite with zeros.
 * @example
 * ```ts
 * import { clean } from '@awasm/noble/utils.js';
 * const buf = new Uint8Array([1, 2, 3]);
 * clean(buf);
 * ```
 */
export function clean(...arrays: TArg<TypedArray[]>): void {
  for (let i = 0; i < arrays.length; i++) {
    arrays[i].fill(0);
  }
}

// JS `.fill(0)` can be surprisingly slow on large buffers; chunked `.set` tends to be faster.
// This is used by ciphers to clear large staging buffers without making perf unusable.
/**
 * Fast zeroization for large byte buffers.
 * @param dst - destination buffer.
 * @param len - prefix length to clear.
 * @example
 * ```ts
 * import { cleanFast } from '@awasm/noble/utils.js';
 * cleanFast(new Uint8Array(16), 8);
 * ```
 */
export const cleanFast: (dst: TArg<Uint8Array>, len?: number) => void = (() => {
  let zero: Uint8Array | undefined;
  return (dst: TArg<Uint8Array>, len: number = dst.length): void => {
    abytes(dst);
    anumber(len, 'len');
    if (len > dst.length)
      throw new Error(`"len" expected <= dst.length, got len=${len} dst.length=${dst.length}`);
    if (!len) return;
    // Keep the zero chunk inside the export so bundles that don't use cleanFast can drop it too.
    const chunk = zero || (zero = /* @__PURE__ */ new Uint8Array(1024 * 1024));
    let off = 0;
    for (; off + chunk.length <= len; off += chunk.length) dst.set(chunk, off);
    if (off < len) dst.fill(0, off, len);
  };
})();

/**
 * Create a DataView over the same buffer region; writes through it mutate the original array.
 * @param arr - source typed-array view.
 * @returns DataView over the same buffer region.
 * @example
 * ```ts
 * import { createView } from '@awasm/noble/utils.js';
 * createView(new Uint8Array(8));
 * ```
 */
export function createView(arr: TArg<TypedArray>): DataView {
  return new DataView(arr.buffer, arr.byteOffset, arr.byteLength);
}

/**
 * Checks if two byte arrays overlap in the same underlying buffer.
 * This is invalid and can corrupt data.
 * @param a - first byte view.
 * @param b - second byte view.
 * @returns True when the byte ranges overlap.
 * @example
 * ```ts
 * import { overlapBytes } from '@awasm/noble/utils.js';
 * const buf = new Uint8Array(8);
 * overlapBytes(buf.subarray(0, 4), buf.subarray(2, 6));
 * ```
 */
export function overlapBytes(a: TArg<Uint8Array>, b: TArg<Uint8Array>): boolean {
  // Zero-length views cannot overwrite anything, even if their offset sits inside another range.
  if (!a.byteLength || !b.byteLength) return false;
  return (
    a.buffer === b.buffer &&
    a.byteOffset < b.byteOffset + b.byteLength &&
    b.byteOffset < a.byteOffset + a.byteLength
  );
}

export const __TEST: Readonly<{ assertLE: typeof assertLE }> = /* @__PURE__ */ Object.freeze({
  assertLE,
});

// Built-in hex conversion https://caniuse.com/mdn-javascript_builtins_uint8array_fromhex
const hasHexBuiltin: boolean = /* @__PURE__ */ (() =>
  // @ts-ignore
  typeof Uint8Array.from([]).toHex === 'function' && typeof Uint8Array.fromHex === 'function')();

// Array where index 0xf0 (240) is mapped to string 'f0'
const hexes = /* @__PURE__ */ Array.from({ length: 256 }, (_, i) =>
  i.toString(16).padStart(2, '0')
);

/**
 * Convert byte array to hex string. Uses built-in function, when available.
 * @param bytes - bytes to encode.
 * @returns Lowercase hex string.
 * @throws On wrong argument types. {@link TypeError}
 * @example
 * ```ts
 * import { bytesToHex } from '@awasm/noble/utils.js';
 * bytesToHex(Uint8Array.from([0xca, 0xfe, 0x01, 0x23]));
 * ```
 */
export function bytesToHex(bytes: TArg<Uint8Array>): string {
  abytes(bytes);
  // @ts-ignore
  if (hasHexBuiltin) return bytes.toHex();
  // pre-caching improves the speed 6x
  let hex = '';
  for (let i = 0; i < bytes.length; i++) {
    hex += hexes[bytes[i]];
  }
  return hex;
}

// We use optimized technique to convert hex string to byte array
const asciis = { _0: 48, _9: 57, A: 65, F: 70, a: 97, f: 102 } as const;
function asciiToBase16(ch: number): number | undefined {
  if (ch >= asciis._0 && ch <= asciis._9) return ch - asciis._0; // '2' => 50-48
  if (ch >= asciis.A && ch <= asciis.F) return ch - (asciis.A - 10); // 'B' => 66-(65-10)
  if (ch >= asciis.a && ch <= asciis.f) return ch - (asciis.a - 10); // 'b' => 98-(97-10)
  return;
}

/**
 * Convert hex string to byte array. Uses built-in function, when available.
 * @param hex - hex string to decode.
 * @returns Decoded bytes.
 * @throws On wrong argument types. {@link TypeError}
 * @throws On wrong argument ranges or values. {@link RangeError}
 * @example
 * ```ts
 * import { hexToBytes } from '@awasm/noble/utils.js';
 * hexToBytes('cafe0123');
 * ```
 */
export function hexToBytes(hex: string): TRet<Uint8Array> {
  if (typeof hex !== 'string') throw new TypeError('hex string expected, got ' + typeof hex);
  if (hasHexBuiltin) {
    try {
      // @ts-ignore
      return Uint8Array.fromHex(hex) as TRet<Uint8Array>;
    } catch (error) {
      if (error instanceof SyntaxError) throw new RangeError(error.message);
      throw error;
    }
  }
  const hl = hex.length;
  const al = hl / 2;
  if (hl % 2) throw new RangeError('hex string expected, got unpadded hex of length ' + hl);
  const array = new Uint8Array(al);
  for (let ai = 0, hi = 0; ai < al; ai++, hi += 2) {
    const n1 = asciiToBase16(hex.charCodeAt(hi));
    const n2 = asciiToBase16(hex.charCodeAt(hi + 1));
    if (n1 === undefined || n2 === undefined) {
      const char = hex[hi] + hex[hi + 1];
      throw new RangeError(
        'hex string expected, got non-hex character "' + char + '" at index ' + hi
      );
    }
    array[ai] = n1 * 16 + n2; // multiply first octet, e.g. 'a3' => 10*16+3 => 160 + 3 => 163
  }
  return array as TRet<Uint8Array>;
}

/**
 * There is no setImmediate in browser and setTimeout is slow.
 * Call of async fn will return Promise, which will be fullfiled only on
 * next scheduler queue processing step and this is exactly what we need.
 * This yields to the Promise/microtask scheduler queue, not to timers or the full macrotask event loop.
 * @example
 * ```ts
 * import { nextTick } from '@awasm/noble/utils.js';
 * await nextTick();
 * ```
 */
export const nextTick = async (): Promise<void> => {};

/**
 * Returns control to the Promise/microtask scheduler every `tick` ms to avoid blocking long loops.
 * @param iters - number of loop iterations.
 * @param tick - maximum milliseconds to spend before yielding.
 * @param cb - callback invoked for each iteration index.
 */
export async function asyncLoop(
  iters: number,
  tick: number,
  cb: (i: number) => void
): Promise<void> {
  let ts = Date.now();
  for (let i = 0; i < iters; i++) {
    cb(i);
    // Date.now() is not monotonic, so in case if clock goes backwards we return return control too
    const diff = Date.now() - ts;
    if (diff >= 0 && diff < tick) continue;
    await nextTick();
    ts += diff;
  }
}

// Global symbols, but ts doesn't see them: https://github.com/microsoft/TypeScript/issues/31535
declare const TextEncoder: any;
declare const TextDecoder: any;

/**
 * Converts string to bytes using UTF8 encoding.
 * Built-in doesn't validate input to be string: we do the check.
 * Non-ASCII details are delegated to the platform TextEncoder.
 * @param str - string to encode.
 * @returns UTF-8 bytes.
 * @throws On wrong argument types. {@link TypeError}
 * @example
 * ```ts
 * import { utf8ToBytes } from '@awasm/noble/utils.js';
 * utf8ToBytes('abc');
 * ```
 */
export function utf8ToBytes(str: string): TRet<Uint8Array> {
  if (typeof str !== 'string') throw new TypeError('string expected');
  return new Uint8Array(new TextEncoder().encode(str)) as TRet<Uint8Array>; // https://bugzil.la/1681809
}

/**
 * Convert byte array to string, assuming UTF8 encoding.
 * Input validation and malformed-sequence handling are delegated to TextDecoder:
 * invalid UTF-8 is replacement-decoded, not rejected.
 * @param bytes - bytes to decode.
 * @returns UTF-8 string.
 * @example
 * ```ts
 * import { bytesToUtf8 } from '@awasm/noble/utils.js';
 * bytesToUtf8(new Uint8Array([97, 98, 99]));
 * ```
 */
export function bytesToUtf8(bytes: TArg<Uint8Array>): string {
  return new TextDecoder().decode(bytes);
}

/**
 * Checks whether a byte array is aligned to a 4-byte offset.
 * @param bytes - byte view to inspect.
 * @returns True when the view is 32-bit aligned.
 * @example
 * ```ts
 * import { isAligned32 } from '@awasm/noble/utils.js';
 * isAligned32(new Uint8Array(8));
 * ```
 */
export function isAligned32(bytes: TArg<Uint8Array>): boolean {
  return bytes.byteOffset % 4 === 0;
}

/**
 * By default, returns u8a of expected length.
 * When `out` is specified, it checks it for validity and uses it.
 * @param expectedLength - expected output length in bytes.
 * @param out - optional caller-provided destination buffer.
 * @param onlyAligned - whether to require 32-bit alignment for `out`.
 * @returns Output buffer with the expected length.
 * @throws On wrong argument types. {@link TypeError}
 * @throws If a documented runtime validation or state check fails. {@link Error}
 * @example
 * ```ts
 * import { getOutput } from '@awasm/noble/utils.js';
 * getOutput(16);
 * ```
 */
export function getOutput(
  expectedLength: number,
  out?: TArg<Uint8Array>,
  onlyAligned = true
): TRet<Uint8Array> {
  if (out === undefined) return new Uint8Array(expectedLength) as TRet<Uint8Array>;
  // Keep Buffer/cross-realm Uint8Array support here instead of trusting a shape-compatible object.
  abytes(out, undefined, 'output');
  if (out.length !== expectedLength)
    throw new Error(
      '"output" expected Uint8Array of length ' + expectedLength + ', got: ' + out.length
    );
  if (onlyAligned && !isAligned32(out)) throw new Error('invalid output, must be aligned');
  return out as TRet<Uint8Array>;
}

/**
 * Encodes the AEAD length block as aadLength || dataLength.
 * Callers pass lengths already scaled to the mode's unit:
 * octets for ChaCha20-Poly1305, bits for GCM/GCM-SIV.
 * @param dataLength - encoded data length.
 * @param aadLength - encoded AAD length.
 * @param isLE - whether to write values in little-endian order.
 * @returns Encoded 16-byte length block.
 * @throws On wrong argument types. {@link TypeError}
 * @throws On wrong argument ranges or values. {@link RangeError}
 * @example
 * ```ts
 * import { u64Lengths } from '@awasm/noble/utils.js';
 * u64Lengths(16, 8, true);
 * ```
 */
export function u64Lengths(dataLength: number, aadLength: number, isLE: boolean): TRet<Uint8Array> {
  // Reject coercible non-number lengths like '10' and true before BigInt(...) accepts them.
  anumber(dataLength);
  anumber(aadLength);
  abool(isLE);
  const num = new Uint8Array(16);
  const view = createView(num);
  view.setBigUint64(0, BigInt(aadLength), isLE);
  view.setBigUint64(8, BigInt(dataLength), isLE);
  return num as TRet<Uint8Array>;
}

/** KDFs can accept string or Uint8Array for user convenience. */
export type KDFInput = string | Uint8Array;

/**
 * Helper for KDFs: consumes Uint8Array or string.
 * String inputs are UTF-8 encoded; byte-array inputs stay aliased to the caller buffer.
 * @param data - string or bytes input.
 * @param errorTitle - optional field name for byte validation.
 * @returns Byte representation of the input.
 * @throws On wrong argument types. {@link TypeError}
 * @example
 * ```ts
 * import { kdfInputToBytes } from '@awasm/noble/utils.js';
 * kdfInputToBytes('password');
 * ```
 */
export function kdfInputToBytes(data: TArg<KDFInput>, errorTitle = ''): TRet<Uint8Array> {
  if (typeof data === 'string') return utf8ToBytes(data);
  return abytes(data, undefined, errorTitle);
}

/**
 * Copies several Uint8Arrays into one.
 * @param arrays - arrays to concatenate.
 * @returns Concatenated bytes.
 * @throws On wrong argument types. {@link TypeError}
 * @example
 * ```ts
 * import { concatBytes } from '@awasm/noble/utils.js';
 * concatBytes(new Uint8Array([1]), new Uint8Array([2, 3]));
 * ```
 */
export function concatBytes(...arrays: TArg<Uint8Array[]>): TRet<Uint8Array> {
  let sum = 0;
  for (let i = 0; i < arrays.length; i++) {
    const a = arrays[i];
    abytes(a);
    sum += a.length;
  }
  const res = new Uint8Array(sum);
  for (let i = 0, pad = 0; i < arrays.length; i++) {
    const a = arrays[i];
    res.set(a, pad);
    pad += a.length;
  }
  return res as TRet<Uint8Array>;
}

/**
 * Fast copy for validated, in-bounds byte ranges.
 * Overlap is intentionally unsupported here for speed: hot callers only pass disjoint ranges,
 * and same-buffer moves must use copyWithin()/set() at the call site instead.
 * @param dst - destination byte array.
 * @param dstPos - write offset in destination.
 * @param src - source byte array.
 * @param srcPos - read offset in source.
 * @param len - number of bytes to copy.
 * @example
 * ```ts
 * import { copyFast } from '@awasm/noble/utils.js';
 * const dst = new Uint8Array(4);
 * copyFast(dst, 1, new Uint8Array([7, 8]), 0, 2);
 * ```
 */
export function copyFast(
  dst: TArg<Uint8Array>,
  dstPos: number,
  src: TArg<Uint8Array>,
  srcPos: number,
  len: number
): void {
  if (len <= 0) return;
  if (len <= 64) for (let i = 0; i < len; i++) dst[dstPos + i] = src[srcPos + i];
  else dst.set(src.subarray(srcPos, srcPos + len), dstPos);
}

/**
 * Fast copy for validated, in-bounds 32-bit word ranges.
 * Overlap is intentionally unsupported here for speed: hot callers only pass disjoint ranges,
 * and same-buffer moves must use copyWithin()/set() at the call site instead.
 * @param dst - destination word array.
 * @param dstPos - write offset in destination.
 * @param src - source word array.
 * @param srcPos - read offset in source.
 * @param len - number of words to copy.
 * @example
 * ```ts
 * import { copyFast32 } from '@awasm/noble/utils.js';
 * const dst = new Uint32Array(4);
 * copyFast32(dst, 1, new Uint32Array([7, 8]), 0, 2);
 * ```
 */
export function copyFast32(
  dst: TArg<Uint32Array>,
  dstPos: number,
  src: TArg<Uint32Array>,
  srcPos: number,
  len: number
): void {
  if (len <= 0) return;
  if (len <= 64) for (let i = 0; i < len; i++) dst[dstPos + i] = src[srcPos + i];
  else dst.set(src.subarray(srcPos, srcPos + len), dstPos);
}

/**
 * Callers must pass a validated byte array; Uint8Array.from() would otherwise coerce arbitrary iterables.
 * Copies into a detached Uint8Array instead of using slice(), because Buffer.slice() aliases memory.
 * @param bytes - bytes to copy.
 * @returns Detached copy of the input bytes.
 * @throws On wrong argument types. {@link TypeError}
 * @example
 * ```ts
 * import { copyBytes } from '@awasm/noble/utils.js';
 * copyBytes(new Uint8Array([1, 2, 3]));
 * ```
 */
export function copyBytes(bytes: TArg<Uint8Array>): TRet<Uint8Array> {
  // `Uint8Array.from(...)` would also accept arrays / other typed arrays. Keep this helper strict
  // because callers use it at byte-validation boundaries before mutating the detached copy.
  return Uint8Array.from(abytes(bytes)) as TRet<Uint8Array>;
}

/**
 * Creates OID opts for NIST hashes, with prefix 06 09 60 86 48 01 65 03 04 02.
 * Current callers pass one-byte hashAlgs suffixes for 2.16.840.1.101.3.4.2.<suffix>,
 * so the DER length byte stays 0x09.
 * @param suffix - final OID suffix byte.
 * @returns DER-encoded OID bytes.
 * @example
 * ```ts
 * import { oidNist } from '@awasm/noble/utils.js';
 * oidNist(1);
 * ```
 */
export const oidNist = (suffix: number) =>
  Uint8Array.from([
    0x06,
    0x09,
    0x60,
    0x86,
    0x48,
    0x01,
    0x65,
    0x03,
    0x04,
    0x02,
    suffix,
  ]) as TRet<Uint8Array>;

type EmptyObj = {};
/**
 * Merges default options and passed options.
 * This mutates `defaults`, so callers pass fresh defaults when they need reuse.
 * @param defaults - default option object.
 * @param opts - caller-provided overrides.
 * @returns Merged options object.
 * @throws On wrong argument types. {@link TypeError}
 * @example
 * ```ts
 * import { checkOpts } from '@awasm/noble/utils.js';
 * checkOpts({ a: 1 }, { b: 2 });
 * ```
 */
export function checkOpts<T1 extends EmptyObj, T2 extends EmptyObj>(
  defaults: T1,
  opts?: T2
): T1 & T2 {
  if (opts !== undefined && {}.toString.call(opts) !== '[object Object]')
    throw new TypeError('options must be object or undefined');
  const merged = Object.assign(defaults, opts);
  return merged as T1 & T2;
}

/*
Make sync/async versions from the same generator body.
Used by KDFs, hash async wrappers, and cipher async wrappers.
*/
/** Async execution options shared by generator-backed wrappers. */
export type AsyncOpts = {
  /** Total number of progress units for the run. */
  total: number;
  /** Maximum time in ms before yielding control in async mode. */
  asyncTick?: number;
  /**
   * Optional progress callback receiving values in the `[0, 1]` range.
   * @param progress - normalized progress value in the `[0, 1]` range.
   */
  onProgress?: (progress: number) => void;
  /** Optional serialized-state size in bytes for resumable async work. */
  stateBytes?: number;
  /**
   * Save callback for resumable async work.
   * @param state - serialized algorithm state bytes.
   */
  save?: (state: Uint8Array) => void;
  /**
   * Restore callback for resumable async work.
   * @param state - serialized algorithm state bytes.
   */
  restore?: (state: Uint8Array) => void;
  /** Optional scheduler override used instead of the default microtask tick. */
  nextTick?: () => Promise<void>;
};

/** Common async-call options for APIs that expose `.async(...)`. */
export type AsyncRunOpts = Pick<AsyncOpts, 'asyncTick' | 'onProgress' | 'nextTick'>;

/** Factory that turns per-call async options into a progress/yield callback. */
export type AsyncSetup = (opts: AsyncOpts) => (inc?: number) => boolean;
type AsyncSetupMode = AsyncSetup & { isAsync?: boolean };
/** Function with a matching `.async(...)` variant. */
export type AsyncFn<T extends any[], R> = ((...args: T) => R) & {
  async: (...args: T) => Promise<R>;
};
/** Converts a sync function shape into a sync + async callable shape. */
export type Asyncify<F extends (...args: any[]) => any> = AsyncFn<Parameters<F>, ReturnType<F>>;
/**
 * Build sync and async wrappers from the same generator body.
 * @param cb_ - generator callback shared by sync and async variants.
 * @returns Function exposing both sync and `.async(...)` entrypoints.
 * @example
 * ```ts
 * import { mkAsync } from '@awasm/noble/utils.js';
 * const twice = mkAsync(function* (_setup, value: number) {
 *   return value * 2;
 * });
 * await twice.async(2);
 * ```
 */
export function mkAsync<T extends any[], R>(
  cb_: TArg<(setup: AsyncSetup, ...args: T) => Generator<unknown, R, unknown>>
): AsyncFn<T, R> {
  const cb = cb_ as (setup: AsyncSetup, ...args: T) => Generator<unknown, R, unknown>;
  const genSetup = (canReturn: boolean) => {
    let setupDone = false;
    let progressTotal = -1;
    let done = 0;
    let stateBytes = 0;
    let state: Uint8Array | undefined;
    let onSave = (_state: TArg<Uint8Array>) => {};
    let onRestore = (_state: TArg<Uint8Array>) => {};
    /**
     * Default scheduler yields to the Promise microtask queue.
     * Callers can pass `nextTick` when they need a custom scheduler.
     */
    let onNextTick = async () => {};
    return {
      save: () => {
        if (!canReturn || !stateBytes) return;
        if (!state) state = new Uint8Array(stateBytes);
        onSave(state);
      },
      restore: () => {
        if (!canReturn || !state) return;
        onRestore(state);
      },
      nextTick: () => onNextTick(),
      onEnd: () => {
        // setup() can be skipped on explicit sync fast-paths.
        if (progressTotal < 0) return;
        if (done !== progressTotal)
          throw new Error(`done (${done}) < progressTotal(${progressTotal})`);
      },
      setup: (_opts: TArg<AsyncOpts>) => {
        const rawOpts = _opts as AsyncOpts;
        if (setupDone) throw new Error('setup already called');
        setupDone = true;
        if (!canReturn) {
          anumber(rawOpts.total, 'total');
          progressTotal = rawOpts.total;
          const onProgress = rawOpts.onProgress;
          if (onProgress !== undefined && typeof onProgress !== 'function')
            throw new Error('onProgress must be a function');
          if (!onProgress) {
            return (inc: number = 1) => {
              done += inc;
              return false;
            };
          }
          const callbackPer = Math.max(Math.floor(progressTotal / 10000), 1);
          return (inc: number = 1) => {
            done += inc;
            if (!(done % callbackPer) || done === progressTotal)
              onProgress(progressTotal ? done / progressTotal : 1);
            return false;
          };
        }
        const opts = { ...rawOpts };
        if (opts.asyncTick === undefined) delete opts.asyncTick; // will override defaults otherwise
        const {
          asyncTick,
          onProgress,
          stateBytes: _stateBytes,
          save,
          restore,
          nextTick,
          total,
        } = checkOpts({ asyncTick: 10 }, opts);
        anumber(asyncTick, 'asyncTick');
        anumber(total, 'total');
        progressTotal = total;
        for (const [k, v] of Object.entries({ onProgress, save, restore, nextTick })) {
          if (v !== undefined && typeof v !== 'function')
            throw new Error(`${k} must be a function`);
        }
        if (_stateBytes !== undefined) anumber(_stateBytes, 'stateBytes');
        if (_stateBytes !== undefined) stateBytes = _stateBytes;
        if ((save !== undefined || restore !== undefined) && !stateBytes)
          throw new Error('stateBytes must be a positive integer when save/restore is used');
        if (save !== undefined) onSave = save;
        if (restore !== undefined) onRestore = restore;
        if (nextTick !== undefined) onNextTick = nextTick;
        let needReturn = () => false;
        if (canReturn) {
          let ts = Date.now();
          needReturn = () => {
            // Date.now() is not monotonic, so in case if clock goes backwards we return return control too
            const diff = Date.now() - ts;
            if (diff >= 0 && diff < asyncTick) return false;
            ts += diff;
            return true;
          };
        }
        // Invoke callback if progress changes from 10.01 to 10.02
        // Allows to draw smooth progress bar on up to 8K screen
        const callbackPer = Math.max(Math.floor(progressTotal / 10000), 1);
        let progress = (inc: number = 1) => {
          done += inc;
          return needReturn();
        };
        if (onProgress) {
          progress = (inc: number = 1) => {
            done += inc;
            if (onProgress && (!(done % callbackPer) || done === total))
              onProgress(total ? done / total : 1);
            return needReturn();
          };
        }
        return progress;
      },
    };
  };
  const res = (...args: T) => {
    let setupDone = false;
    let progressTotal = -1;
    let done = 0;
    const setup = ((opts: TArg<AsyncOpts>) => {
      const rawOpts = opts as AsyncOpts;
      if (setupDone) throw new Error('setup already called');
      setupDone = true;
      anumber(rawOpts.total, 'total');
      progressTotal = rawOpts.total;
      const onProgress = rawOpts.onProgress;
      if (onProgress !== undefined && typeof onProgress !== 'function')
        throw new Error('onProgress must be a function');
      if (!onProgress) {
        return (inc: number = 1) => {
          done += inc;
          return false;
        };
      }
      const callbackPer = Math.max(Math.floor(progressTotal / 10000), 1);
      return (inc: number = 1) => {
        done += inc;
        // Keep zero-total sync progress aligned with the async path for empty-input callers.
        if (!(done % callbackPer) || done === progressTotal)
          onProgress(progressTotal ? done / progressTotal : 1);
        return false;
      };
    }) as AsyncSetupMode;
    setup.isAsync = false;
    const g = cb(setup, ...args);
    let r = g.next();
    while (!r.done) r = g.next();
    if (progressTotal >= 0 && done !== progressTotal)
      throw new Error(`done (${done}) < progressTotal(${progressTotal})`);
    return r.value;
  };
  res.async = async (...args: T) => {
    const { setup, save, restore, onEnd, nextTick } = genSetup(true);
    const setupMode = setup as AsyncSetupMode;
    setupMode.isAsync = true;
    const g = cb(setupMode, ...args);
    let r = g.next();
    while (!r.done) {
      save();
      await nextTick();
      restore();
      r = g.next();
    }
    onEnd();
    return r.value;
  };
  return res;
}

/**
 * Compares two byte arrays in kinda constant time once lengths already match.
 * Different lengths return false immediately.
 * @param a - first byte array.
 * @param b - second byte array.
 * @returns True when the byte arrays are equal.
 * @example
 * ```ts
 * import { equalBytes } from '@awasm/noble/utils.js';
 * equalBytes(new Uint8Array([1, 2]), new Uint8Array([1, 2]));
 * ```
 */
export function equalBytes(a: TArg<Uint8Array>, b: TArg<Uint8Array>): boolean {
  if (a.length !== b.length) return false;
  let diff = 0;
  for (let i = 0; i < a.length; i++) diff |= a[i] ^ b[i];
  return diff === 0;
}

/**
 * Cryptographically secure PRNG. Uses internal OS-level `crypto.getRandomValues`.
 * @param bytesLength - number of random bytes to generate.
 * @returns Random bytes.
 * @throws On wrong argument types. {@link TypeError}
 * @throws On wrong argument ranges or values. {@link RangeError}
 * @throws If a documented runtime validation or state check fails. {@link Error}
 * @example
 * ```ts
 * import { randomBytes } from '@awasm/noble/utils.js';
 * randomBytes(16);
 * ```
 */
export function randomBytes(bytesLength = 32): TRet<Uint8Array> {
  // Validate upfront so fractional / coercible lengths do not silently
  // truncate through Uint8Array().
  anumber(bytesLength);
  const cr = typeof globalThis === 'object' ? (globalThis as any).crypto : null;
  if (typeof cr?.getRandomValues !== 'function')
    throw new Error('crypto.getRandomValues must be defined');
  return cr.getRandomValues(new Uint8Array(bytesLength)) as TRet<Uint8Array>;
}

/** Sync cipher: takes byte array and returns byte array. */
export type Cipher = {
  /**
   * Encrypt plaintext bytes.
   * @param plaintext - plaintext bytes to encrypt.
   * @returns Ciphertext bytes.
   */
  encrypt(plaintext: TArg<Uint8Array>): TRet<Uint8Array>;
  /**
   * Decrypt ciphertext bytes.
   * @param ciphertext - ciphertext bytes to decrypt.
   * @returns Plaintext bytes.
   */
  decrypt(ciphertext: TArg<Uint8Array>): TRet<Uint8Array>;
};

/** Async cipher e.g. from built-in WebCrypto. */
export type AsyncCipher = {
  /**
   * Encrypt plaintext bytes asynchronously.
   * @param plaintext - plaintext bytes to encrypt.
   * @returns Promise resolving to ciphertext bytes.
   */
  encrypt(plaintext: TArg<Uint8Array>): Promise<TRet<Uint8Array>>;
  /**
   * Decrypt ciphertext bytes asynchronously.
   * @param ciphertext - ciphertext bytes to decrypt.
   * @returns Promise resolving to plaintext bytes.
   */
  decrypt(ciphertext: TArg<Uint8Array>): Promise<TRet<Uint8Array>>;
};

/** Cipher with `output` argument which can optimize by doing 1 less allocation. */
export type CipherWithOutput = Cipher & {
  encrypt(plaintext: TArg<Uint8Array>, output?: TArg<Uint8Array>): TRet<Uint8Array>;
  decrypt(ciphertext: TArg<Uint8Array>, output?: TArg<Uint8Array>): TRet<Uint8Array>;
};

type RemoveNonceInner<T extends any[], Ret> = ((...args: T) => Ret) extends (
  arg0: any,
  arg1: any,
  ...rest: infer R
) => any
  ? (key: Uint8Array, ...args: R) => Ret
  : never;

/** Removes the nonce parameter from a nonce-taking cipher factory type. */
export type RemoveNonce<T extends (...args: any) => any> = RemoveNonceInner<
  Parameters<T>,
  ReturnType<T>
>;
/** Cipher factory shape that accepts `(key, nonce, ...args)`. */
export type CipherWithNonce = ((
  key: TArg<Uint8Array>,
  nonce: TArg<Uint8Array>,
  ...args: any[]
) => TRet<Cipher | AsyncCipher>) & {
  nonceLength?: number;
};

/**
 * Uses CSPRNG for nonce and injects it into ciphertext.
 * For `encrypt`, a `nonceLength`-byte nonce is fetched from CSPRNG and
 * prepended to encrypted ciphertext. For `decrypt`, the first `nonceLength`
 * bytes of ciphertext are treated as nonce.
 *
 * The wrapper always allocates a fresh `nonce || ciphertext` buffer on encrypt
 * and intentionally does not support caller-provided destination buffers.
 * Too-short decrypt inputs are split into short/empty nonce views and then
 * delegated to the wrapped cipher instead of being rejected here first.
 *
 * NOTE: Under the same key, using random nonces (e.g. `managedNonce`) with AES-GCM and ChaCha
 * should be limited to `2**23` (8M) messages to get a collision chance of
 * `2**-50`. Stretching to `2**32` (4B) messages would raise that chance to
 * `2**-33`, still negligible but creeping up.
 * @param fn - nonce-taking cipher factory.
 * @param randomBytes_ - CSPRNG used to generate nonces.
 * @returns Cipher factory that prepends managed nonces to ciphertext.
 * @throws On wrong argument types. {@link TypeError}
 * @throws On wrong argument ranges or values. {@link RangeError}
 * @example
 * ```ts
 * import { managedNonce } from '@awasm/noble/utils.js';
 * import { xchacha20poly1305 } from '@awasm/noble';
 * const cipher = managedNonce(xchacha20poly1305)(new Uint8Array(32));
 * const sealed = cipher.encrypt(new Uint8Array([1, 2, 3]));
 * cipher.decrypt(sealed);
 * ```
 */
export function managedNonce<T extends CipherWithNonce>(
  fn: T,
  randomBytes_: typeof randomBytes = randomBytes
): TRet<RemoveNonce<T>> {
  const { nonceLength } = fn;
  const nonceLen = nonceLength as number;
  anumber(nonceLen);
  const addNonce = (
    nonce: TArg<Uint8Array>,
    ciphertext: TArg<Uint8Array>,
    plaintext: TArg<Uint8Array>
  ) => {
    const out = concatBytes(nonce, ciphertext);
    // Wrapped ciphers may alias caller plaintext on encrypt(); don't wipe caller-owned bytes here.
    if (!overlapBytes(plaintext, ciphertext)) ciphertext.fill(0);
    return out;
  };
  // NOTE: we cannot support DST here, it would be a mistake:
  // - we don't know how much dst length cipher requires
  // - nonce may unalign dst and break everything
  // - we create new u8a anyway (concatBytes)
  // - previously all args were passed-through to a cipher, but that was a mistake
  const res = ((key: TArg<Uint8Array>, ...args: any[]): any => ({
    encrypt(plaintext: TArg<Uint8Array>) {
      abytes(plaintext);
      const nonce = randomBytes_(nonceLen);
      const encrypted = fn(key, nonce, ...args).encrypt(plaintext);
      // @ts-ignore
      if (encrypted instanceof Promise)
        return encrypted.then((ct) => addNonce(nonce, ct, plaintext));
      return addNonce(nonce, encrypted, plaintext);
    },
    decrypt(ciphertext: TArg<Uint8Array>) {
      abytes(ciphertext);
      const nonce = ciphertext.subarray(0, nonceLen);
      const decrypted = ciphertext.subarray(nonceLen);
      return fn(key, nonce, ...args).decrypt(decrypted);
    },
  })) as RemoveNonce<T> & { blockSize?: number; nonceLength: number; tagLength?: number };
  // awasm tests and callers still treat managed wrappers as cipher factories, so preserve metadata.
  if ('blockSize' in fn) res.blockSize = (fn as any).blockSize;
  res.nonceLength = nonceLen;
  if ('tagLength' in fn) res.tagLength = (fn as any).tagLength;
  return res as unknown as TRet<RemoveNonce<T>>;
}
