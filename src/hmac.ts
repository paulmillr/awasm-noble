/**
 * HMAC copied from noble-hashes.
 * @module
 */
import type { HashInstance, HashStream } from './hashes-abstract.ts';
import { abytes, ahash, aoutput, clean, type TArg, type TRet } from './utils.ts';

/** Streaming HMAC helper returned by `hmac.create(...)`. */
export interface HMACStream {
  /** Whether the underlying hash supports extendable output. */
  canXOF: boolean;
  /** Absorb another message chunk into the MAC state. */
  update(msg: TArg<Uint8Array>): HMACStream;
  /**
   * Finalize and return the authentication tag.
   * @returns Authentication tag bytes.
   */
  digest(): TRet<Uint8Array>;
  /** Wipe internal state and make the instance unusable. */
  destroy(): void;
  /** Clone the current state into a new or provided stream instance. */
  _cloneInto(to?: HMACStream): HMACStream;
  /** Clone the current stream state. */
  clone(): HMACStream;
  /**
   * Finalize directly into the provided output buffer.
   * @param buf - output buffer for the authentication tag.
   */
  digestInto(buf: TArg<Uint8Array>): void;
  /** Underlying hash block length in bytes. */
  blockLen: number;
  /** Authentication tag length in bytes. */
  outputLen: number;
}

/**
 * Internal class for HMAC.
 * Accepts any byte key, although RFC 2104 §3 recommends keys at least
 * `HashLen` bytes long.
 */
class HMAC<T extends HashStream<any>> {
  oHash: any;
  iHash: any;
  blockLen: number;
  outputLen: number;
  canXOF = false;
  private finished = false;
  private destroyed = false;

  constructor(hash: HashInstance<any>, key: Uint8Array) {
    ahash(hash);
    abytes(key, undefined, 'key');
    this.iHash = hash.create() as T;
    if (typeof this.iHash.update !== 'function')
      throw new Error('Expected instance of class which extends utils.Hash');
    this.blockLen = this.iHash.blockLen;
    this.outputLen = this.iHash.outputLen;
    const blockLen = this.blockLen;
    const pad = new Uint8Array(blockLen);
    // blockLen can be bigger than outputLen
    pad.set(key.length > blockLen ? hash.create().update(key).digest() : key);
    for (let i = 0; i < pad.length; i++) pad[i] ^= 0x36;
    this.iHash.update(pad);
    // Process the first outer block here so clone() can reuse the prepared state
    // across multiple calls.
    this.oHash = hash.create() as T;
    // Undo internal XOR && apply outer XOR
    for (let i = 0; i < pad.length; i++) pad[i] ^= 0x36 ^ 0x5c;
    this.oHash.update(pad);
    clean(pad);
  }
  update(buf: Uint8Array): this {
    //    aexists(this);
    this.iHash.update(buf);
    return this;
  }
  digestInto(out: Uint8Array): void {
    //aexists(this);
    aoutput(out, this);
    this.finished = true;
    const buf = out.subarray(0, this.outputLen);
    // Reuse the first outputLen bytes for the inner digest; the outer hash consumes them before
    // overwriting that same prefix with the final tag, leaving any oversized tail untouched.
    this.iHash.digestInto(buf);
    this.oHash.update(buf);
    this.oHash.digestInto(buf);
    this.destroy();
  }
  digest(): Uint8Array {
    const out = new Uint8Array(this.oHash.outputLen);
    this.digestInto(out);
    return out;
  }
  _cloneInto(to?: HMAC<T>): HMAC<T> {
    // Create a new instance without calling the constructor.
    // The key is already in state and is not available here.
    to ||= Object.create(Object.getPrototypeOf(this), {});
    const { oHash, iHash, finished, destroyed, blockLen, outputLen } = this;
    to = to as this;
    to.finished = finished;
    to.destroyed = destroyed;
    to.blockLen = blockLen;
    to.outputLen = outputLen;
    to.oHash = oHash._cloneInto(to.oHash);
    to.iHash = iHash._cloneInto(to.iHash);
    return to;
  }
  clone(): HMAC<T> {
    return this._cloneInto();
  }
  destroy(): void {
    this.destroyed = true;
    this.oHash.destroy();
    this.iHash.destroy();
  }
}

type HmacFn = {
  (
    hash: TArg<HashInstance<any>>,
    key: TArg<Uint8Array>,
    message: TArg<Uint8Array>
  ): TRet<Uint8Array>;
  create(hash: TArg<HashInstance<any>>, key: TArg<Uint8Array>): HMACStream;
};

/**
 * HMAC: RFC 2104 message authentication code.
 * @param hash - hash function that would be used e.g. sha256
 * @param key - authentication key bytes
 * @param message - message bytes to authenticate
 * @returns Authentication tag bytes.
 * @example
 * Compute an RFC 2104 HMAC.
 * ```ts
 * import { hmac } from '@awasm/noble/hmac.js';
 * import { sha256 } from '@awasm/noble';
 * const mac = hmac(sha256, new Uint8Array([1, 2, 3]), new Uint8Array([4, 5, 6]));
 * ```
 */
export const hmac: TRet<HmacFn> = /* @__PURE__ */ (() => {
  const fn = ((
    hash: TArg<HashInstance<any>>,
    key: TArg<Uint8Array>,
    message: TArg<Uint8Array>
  ): TRet<Uint8Array> =>
    new HMAC<any>(hash as HashInstance<any>, key)
      .update(message)
      .digest() as TRet<Uint8Array>) as TRet<HmacFn>;
  fn.create = (hash: TArg<HashInstance<any>>, key: TArg<Uint8Array>) =>
    new HMAC<any>(hash as HashInstance<any>, key) as HMACStream;
  return fn;
})();
