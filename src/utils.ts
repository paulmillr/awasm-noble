/**
 * Utilities: assertions, conversions.
 * @module
 */
import type { HashInstance } from './hashes-abstract.ts';

/** Checks if something is Uint8Array. Be careful: nodejs Buffer will return true. */
export function isBytes(a: unknown): a is Uint8Array {
  return a instanceof Uint8Array || (ArrayBuffer.isView(a) && a.constructor.name === 'Uint8Array');
}

/** Asserts something is boolean. */
export function abool(b: boolean): void {
  if (typeof b !== 'boolean') throw new Error(`boolean expected, not ${b}`);
}

/** Asserts something is positive integer. */
export function anumber(n: number, title: string = ''): void {
  if (!Number.isSafeInteger(n) || n < 0) {
    const prefix = title && `"${title}" `;
    throw new Error(`${prefix}expected integer >= 0, got ${n}`);
  }
}

/** Asserts something is Uint8Array. */
export function abytes(value: Uint8Array, length?: number, title: string = ''): Uint8Array {
  const bytes = isBytes(value);
  const len = value?.length;
  const needsLen = length !== undefined;
  if (!bytes || (needsLen && len !== length)) {
    const prefix = title && `"${title}" `;
    const ofLen = needsLen ? ` of length ${length}` : '';
    const got = bytes ? `length=${len}` : `type=${typeof value}`;
    throw new Error(prefix + 'expected Uint8Array' + ofLen + ', got ' + got);
  }
  return value;
}

/** Asserts a hash instance has not been destroyed / finished */
export function aexists(instance: any, checkFinished = true): void {
  if (instance.destroyed) throw new Error('Hash instance has been destroyed');
  if (checkFinished && instance.finished) throw new Error('Hash#digest() has already been called');
}

/** Asserts output is properly-sized byte array */
export function aoutput(out: any, instance: any): void {
  abytes(out, undefined, 'output');
  const min = instance.outputLen;
  if (out.length < min) {
    throw new Error('digestInto() expects output buffer of length at least ' + min);
  }
}

export function ahash(h: HashInstance<any>): void {
  if (typeof h !== 'function' || typeof h.create !== 'function')
    throw new Error('Hash must created by hashes.mkHash');
  anumber(h.outputLen);
  anumber(h.blockLen);
}

/** Generic type encompassing 8/16/32-byte arrays - but not 64-byte. */
// prettier-ignore
export type TypedArray = Int8Array | Uint8ClampedArray | Uint8Array |
  Uint16Array | Int16Array | Uint32Array | Int32Array;

/** Cast u8 / u16 / u32 to u8. */
export function u8(arr: TypedArray): Uint8Array {
  return new Uint8Array(arr.buffer, arr.byteOffset, arr.byteLength);
}

/** Cast u8 / u16 / u32 to u32. */
export function u32(arr: TypedArray): Uint32Array {
  return new Uint32Array(arr.buffer, arr.byteOffset, Math.floor(arr.byteLength / 4));
}

/** Zeroize a byte array. Warning: JS provides no guarantees. */
export function clean(...arrays: TypedArray[]): void {
  for (let i = 0; i < arrays.length; i++) {
    arrays[i].fill(0);
  }
}

// JS `.fill(0)` can be surprisingly slow on large buffers; chunked `.set` tends to be faster.
// This is used by ciphers to clear large staging buffers without making perf unusable.
export const cleanFast = (() => {
  let zero: Uint8Array | undefined;
  return (dst: Uint8Array, len: number = dst.length): void => {
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

/** Create DataView of an array for easy byte-level manipulation. */
export function createView(arr: TypedArray): DataView {
  return new DataView(arr.buffer, arr.byteOffset, arr.byteLength);
}

/**
 * Checks if two U8A use same underlying buffer and overlaps.
 * This is invalid and can corrupt data.
 */
export function overlapBytes(a: Uint8Array, b: Uint8Array): boolean {
  return (
    a.buffer === b.buffer &&
    a.byteOffset < b.byteOffset + b.byteLength &&
    b.byteOffset < a.byteOffset + a.byteLength
  );
}

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
 * @example bytesToHex(Uint8Array.from([0xca, 0xfe, 0x01, 0x23])) // 'cafe0123'
 */
export function bytesToHex(bytes: Uint8Array): string {
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
 * @example hexToBytes('cafe0123') // Uint8Array.from([0xca, 0xfe, 0x01, 0x23])
 */
export function hexToBytes(hex: string): Uint8Array {
  if (typeof hex !== 'string') throw new Error('hex string expected, got ' + typeof hex);
  // @ts-ignore
  if (hasHexBuiltin) return Uint8Array.fromHex(hex);
  const hl = hex.length;
  const al = hl / 2;
  if (hl % 2) throw new Error('hex string expected, got unpadded hex of length ' + hl);
  const array = new Uint8Array(al);
  for (let ai = 0, hi = 0; ai < al; ai++, hi += 2) {
    const n1 = asciiToBase16(hex.charCodeAt(hi));
    const n2 = asciiToBase16(hex.charCodeAt(hi + 1));
    if (n1 === undefined || n2 === undefined) {
      const char = hex[hi] + hex[hi + 1];
      throw new Error('hex string expected, got non-hex character "' + char + '" at index ' + hi);
    }
    array[ai] = n1 * 16 + n2; // multiply first octet, e.g. 'a3' => 10*16+3 => 160 + 3 => 163
  }
  return array;
}

/**
 * There is no setImmediate in browser and setTimeout is slow.
 * Call of async fn will return Promise, which will be fullfiled only on
 * next scheduler queue processing step and this is exactly what we need.
 */
export const nextTick = async (): Promise<void> => {};

/** Returns control to thread each 'tick' ms to avoid blocking. */
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
 * @example utf8ToBytes('abc') // Uint8Array.from([97, 98, 99])
 */
export function utf8ToBytes(str: string): Uint8Array {
  if (typeof str !== 'string') throw new Error('string expected');
  return new Uint8Array(new TextEncoder().encode(str)); // https://bugzil.la/1681809
}

/**
 * Convert byte array to string, assuming UTF8 encoding.
 * @example bytesToUtf8(new Uint8Array([97, 98, 99])) // 'abc'
 */
export function bytesToUtf8(bytes: Uint8Array): string {
  return new TextDecoder().decode(bytes);
}

// Is byte array aligned to 4 byte offset (u32)?
export function isAligned32(bytes: Uint8Array): boolean {
  return bytes.byteOffset % 4 === 0;
}

/**
 * By default, returns u8a of expected length.
 * When `out` is specified, it checks it for validity and uses it.
 */
export function getOutput(
  expectedLength: number,
  out?: Uint8Array,
  onlyAligned = true
): Uint8Array {
  if (out === undefined) return new Uint8Array(expectedLength);
  if (out.length !== expectedLength)
    throw new Error(
      '"output" expected Uint8Array of length ' + expectedLength + ', got: ' + out.length
    );
  if (onlyAligned && !isAligned32(out)) throw new Error('invalid output, must be aligned');
  return out;
}

export function u64Lengths(dataLength: number, aadLength: number, isLE: boolean): Uint8Array {
  abool(isLE);
  const num = new Uint8Array(16);
  const view = createView(num);
  view.setBigUint64(0, BigInt(aadLength), isLE);
  view.setBigUint64(8, BigInt(dataLength), isLE);
  return num;
}

/** KDFs can accept string or Uint8Array for user convenience. */
export type KDFInput = string | Uint8Array;

/**
 * Helper for KDFs: consumes uint8array or string.
 * When string is passed, does utf8 decoding, using TextDecoder.
 */
export function kdfInputToBytes(data: KDFInput, errorTitle = ''): Uint8Array {
  if (typeof data === 'string') return utf8ToBytes(data);
  return abytes(data, undefined, errorTitle);
}

/** Copies several Uint8Arrays into one. */
export function concatBytes(...arrays: Uint8Array[]): Uint8Array {
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
  return res;
}

export function copyFast(
  dst: Uint8Array,
  dstPos: number,
  src: Uint8Array,
  srcPos: number,
  len: number
): void {
  if (len <= 0) return;
  if (len <= 64) for (let i = 0; i < len; i++) dst[dstPos + i] = src[srcPos + i];
  else dst.set(src.subarray(srcPos, srcPos + len), dstPos);
}

export function copyFast32(
  dst: Uint32Array,
  dstPos: number,
  src: Uint32Array,
  srcPos: number,
  len: number
): void {
  if (len <= 0) return;
  if (len <= 64) for (let i = 0; i < len; i++) dst[dstPos + i] = src[srcPos + i];
  else dst.set(src.subarray(srcPos, srcPos + len), dstPos);
}

export function copyBytes(src: Uint8Array) {
  return Uint8Array.from(src); // because Buffer.slice doesn't copy!
}

/** Creates OID opts for NIST hashes, with prefix 06 09 60 86 48 01 65 03 04 02. */
export const oidNist = (suffix: number) =>
  Uint8Array.from([0x06, 0x09, 0x60, 0x86, 0x48, 0x01, 0x65, 0x03, 0x04, 0x02, suffix]);

type EmptyObj = {};
/** Merges default options and passed options. */
export function checkOpts<T1 extends EmptyObj, T2 extends EmptyObj>(
  defaults: T1,
  opts?: T2
): T1 & T2 {
  if (opts !== undefined && {}.toString.call(opts) !== '[object Object]')
    throw new Error('options must be object or undefined');
  const merged = Object.assign(defaults, opts);
  return merged as T1 & T2;
}

/*
Make sync/async version from same code. Currently used only in KDF, but very generic.
TODO: worth using in hashes too? if message is too big?
*/
export type AsyncOpts = {
  total: number;
  asyncTick?: number; // block execution max time
  onProgress?: (progress: number) => void;
  // state management
  stateBytes?: number;
  save?: (state: Uint8Array) => void;
  restore?: (state: Uint8Array) => void;
  // allow overriding if more complex scheduling needed
  nextTick?: () => Promise<void>;
};

// Common async-call options for APIs that expose `.async(...)`.
export type AsyncRunOpts = Pick<AsyncOpts, 'asyncTick' | 'onProgress' | 'nextTick'>;

export type AsyncSetup = (opts: AsyncOpts) => (inc?: number) => boolean;
type AsyncSetupMode = AsyncSetup & { isAsync?: boolean };
export type AsyncFn<T extends any[], R> = ((...args: T) => R) & {
  async: (...args: T) => Promise<R>;
};
export type Asyncify<F extends (...args: any[]) => any> = AsyncFn<Parameters<F>, ReturnType<F>>;
export function mkAsync<T extends any[], R>(
  cb: (setup: AsyncSetup, ...args: T) => Generator<unknown, R, unknown>
): AsyncFn<T, R> {
  const genSetup = (canReturn: boolean) => {
    let setupDone = false;
    let progressTotal = -1;
    let done = 0;
    let stateBytes = 0;
    let state: Uint8Array | undefined;
    let onSave = (_state: Uint8Array) => {};
    let onRestore = (_state: Uint8Array) => {};
    /**
     * There is no setImmediate in browser and setTimeout is slow.
     * Call of async fn will return Promise, which will be fullfiled only on
     * next scheduler queue processing step and this is exactly what we need.
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
      setup: (_opts: AsyncOpts) => {
        if (setupDone) throw new Error('setup already called');
        setupDone = true;
        if (!canReturn) {
          anumber(_opts.total, 'total');
          progressTotal = _opts.total;
          const onProgress = _opts.onProgress;
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
            if (!(done % callbackPer) || done === progressTotal) onProgress(done / progressTotal);
            return false;
          };
        }
        if (_opts.asyncTick === undefined) delete _opts.asyncTick; // will override defaults otherwise
        const {
          asyncTick,
          onProgress,
          stateBytes: _stateBytes,
          save,
          restore,
          nextTick,
          total,
        } = checkOpts({ asyncTick: 10 }, _opts);
        anumber(asyncTick, 'asyncTick');
        anumber(total, 'total');
        progressTotal = total;
        for (const [k, v] of Object.entries({ onProgress, save, restore })) {
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
            if (onProgress && (!(done % callbackPer) || done === total)) onProgress(done / total);
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
    const setup = ((opts: AsyncOpts) => {
      if (setupDone) throw new Error('setup already called');
      setupDone = true;
      anumber(opts.total, 'total');
      progressTotal = opts.total;
      const onProgress = opts.onProgress;
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
        if (!(done % callbackPer) || done === progressTotal) onProgress(done / progressTotal);
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
      r = g.next();
      save();
      await nextTick();
      restore();
    }
    onEnd();
    return r.value;
  };
  return res;
}

/** Compares 2 uint8array-s in kinda constant time. */
export function equalBytes(a: Uint8Array, b: Uint8Array): boolean {
  if (a.length !== b.length) return false;
  let diff = 0;
  for (let i = 0; i < a.length; i++) diff |= a[i] ^ b[i];
  return diff === 0;
}

/** Cryptographically secure PRNG. Uses internal OS-level `crypto.getRandomValues`. */
export function randomBytes(bytesLength = 32): Uint8Array {
  const cr = typeof globalThis === 'object' ? (globalThis as any).crypto : null;
  if (typeof cr?.getRandomValues !== 'function')
    throw new Error('crypto.getRandomValues must be defined');
  return cr.getRandomValues(new Uint8Array(bytesLength));
}

/** Sync cipher: takes byte array and returns byte array. */
export type Cipher = {
  encrypt(plaintext: Uint8Array): Uint8Array;
  decrypt(ciphertext: Uint8Array): Uint8Array;
};

/** Async cipher e.g. from built-in WebCrypto. */
export type AsyncCipher = {
  encrypt(plaintext: Uint8Array): Promise<Uint8Array>;
  decrypt(ciphertext: Uint8Array): Promise<Uint8Array>;
};

/** Cipher with `output` argument which can optimize by doing 1 less allocation. */
export type CipherWithOutput = Cipher & {
  encrypt(plaintext: Uint8Array, output?: Uint8Array): Uint8Array;
  decrypt(ciphertext: Uint8Array, output?: Uint8Array): Uint8Array;
};

type RemoveNonceInner<T extends any[], Ret> = ((...args: T) => Ret) extends (
  arg0: any,
  arg1: any,
  ...rest: infer R
) => any
  ? (key: Uint8Array, ...args: R) => Ret
  : never;

export type RemoveNonce<T extends (...args: any) => any> = RemoveNonceInner<
  Parameters<T>,
  ReturnType<T>
>;
export type CipherWithNonce = ((
  key: Uint8Array,
  nonce: Uint8Array,
  ...args: any[]
) => Cipher | AsyncCipher) & {
  nonceLength: number;
};

/**
 * Uses CSPRG for nonce, nonce injected in ciphertext.
 * For `encrypt`, a `nonceBytes`-length buffer is fetched from CSPRNG and
 * prepended to encrypted ciphertext. For `decrypt`, first `nonceBytes` of ciphertext
 * are treated as nonce.
 *
 * NOTE: Under the same key, using random nonces (e.g. `managedNonce`) with AES-GCM and ChaCha
 * should be limited to `2**23` (8M) messages to get a collision chance of `2**-50`. Stretching to  * `2**32` (4B) messages, chance would become `2**-33` - still negligible, but creeping up.
 * @example
 * const gcm = managedNonce(aes.gcm);
 * const ciphr = gcm(key).encrypt(data);
 * const plain = gcm(key).decrypt(ciph);
 */
export function managedNonce<T extends CipherWithNonce>(
  fn: T,
  randomBytes_: typeof randomBytes = randomBytes
): RemoveNonce<T> {
  const { nonceLength } = fn;
  anumber(nonceLength);
  const addNonce = (nonce: Uint8Array, ciphertext: Uint8Array) => {
    const out = concatBytes(nonce, ciphertext);
    ciphertext.fill(0);
    return out;
  };
  // NOTE: we cannot support DST here, it would be a mistake:
  // - we don't know how much dst length cipher requires
  // - nonce may unalign dst and break everything
  // - we create new u8a anyway (concatBytes)
  // - previously all args were passed-through to a cipher, but that was a mistake
  return ((key: Uint8Array, ...args: any[]): any => ({
    encrypt(plaintext: Uint8Array) {
      abytes(plaintext);
      const nonce = randomBytes_(nonceLength);
      const encrypted = fn(key, nonce, ...args).encrypt(plaintext);
      // @ts-ignore
      if (encrypted instanceof Promise) return encrypted.then((ct) => addNonce(nonce, ct));
      return addNonce(nonce, encrypted);
    },
    decrypt(ciphertext: Uint8Array) {
      abytes(ciphertext);
      const nonce = ciphertext.subarray(0, nonceLength);
      const decrypted = ciphertext.subarray(nonceLength);
      return fn(key, nonce, ...args).decrypt(decrypted);
    },
  })) as RemoveNonce<T>;
}
