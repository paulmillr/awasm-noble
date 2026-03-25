/**
 * HMAC copied from noble-hashes.
 * @module
 */
import type { HashInstance, HashStream } from './hashes-abstract.ts';
import { abytes, clean } from './utils.ts';

export interface HMACStream {
  update(msg: Uint8Array): HMACStream;
  digest(): Uint8Array;
  destroy(): void;
  _cloneInto(to?: HMACStream): HMACStream;
  clone(): HMACStream;
  digestInto(buf: Uint8Array): void;
  blockLen: number;
  outputLen: number;
}

class HMAC<T extends HashStream<any>> {
  oHash: any;
  iHash: any;
  blockLen: number;
  outputLen: number;
  private finished = false;
  private destroyed = false;

  constructor(hash: HashInstance<any>, key: Uint8Array) {
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
    // By doing update (processing of first block) of outer hash here we can re-use it between multiple calls via clone
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
    abytes(out, this.outputLen, 'output');
    this.finished = true;
    this.iHash.digestInto(out);
    this.oHash.update(out);
    this.oHash.digestInto(out);
    this.destroy();
  }
  digest(): Uint8Array {
    const out = new Uint8Array(this.oHash.outputLen);
    this.digestInto(out);
    return out;
  }
  _cloneInto(to?: HMAC<T>): HMAC<T> {
    // Create new instance without calling constructor since key already in state and we don't know it.
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

export const hmac: {
  (hash: HashInstance<any>, key: Uint8Array, message: Uint8Array): Uint8Array;
  create(hash: HashInstance<any>, key: Uint8Array): HMACStream;
} = /* @__PURE__ */ (() => {
  const fn = ((hash: HashInstance<any>, key: Uint8Array, message: Uint8Array): Uint8Array =>
    new HMAC<any>(hash, key).update(message).digest()) as typeof hmac;
  fn.create = (hash: HashInstance<any>, key: Uint8Array) => new HMAC<any>(hash, key);
  return fn;
})();
