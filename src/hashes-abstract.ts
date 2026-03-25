/**
 * Abstract logic for hashes.
 * @module
 */
import {
  abytes,
  anumber,
  clean,
  concatBytes,
  copyBytes,
  copyFast,
  isBytes,
  mkAsync,
  type AsyncRunOpts,
  type AsyncSetup,
  type Asyncify,
} from './utils.ts';

export type HashMod = {
  readonly segments: {
    readonly buffer: Uint8Array; // no need to copy on streaming mode
    readonly 'state.state_chunks': ReadonlyArray<Uint8Array>; // actual state for iv
    readonly state: Uint8Array; // should contain everything to import/export and restart of streaming hash
    readonly state_chunks: ReadonlyArray<Uint8Array>; // chunks == batch
  };
  reset(
    batchPos: number,
    batchCnt: number,
    maxWritten: number,
    blockLen: number,
    maxBlocks: number
  ): void; // resets all internal buffers
  // - pad remainder of block
  // - returns amount of "padding" blocks to process
  // - left = how much empty space in last block
  // NOTE: cannot batch here (returns value)
  padding(
    batchPos: number,
    take: number,
    maxBlocks: number,
    left: number,
    blockLen: number,
    suffix: number
  ): number;
  // proceesses N blocks of size blockLen
  // left = how much empty space in last block (blockLen-lastBlockSize)
  // - reads to buffer
  // - blocks can be less than chunks! (streaming mode).
  // - only last block can be non-full by construction
  // - no blocks can be processed after call with isLast
  processBlocks(
    batchPos: number,
    batchCnt: number,
    blocks: number,
    maxBlocks: number,
    blockLen: number,
    isLast: number,
    left: number,
    padBlocks: number
  ): void;
  // NOTE: outBlockLen is not neccesarily same as blockLen!
  // - writes to buffer
  // - if not isLast we can expect user to ask for more blocks later.
  processOutBlocks(
    batchPos: number,
    batchCnt: number,
    blocks: number,
    maxBlocks: number,
    outBlockLen: number,
    isLast: number
  ): void;
};

export type HashDef<Mod extends HashMod, Opts = undefined> = {
  suffix?: number;
  chunks?: number; // = 16
  blockLen: number;
  outputBlockLen?: number;
  outputLen: number;
  canXOF?: boolean;
  oid?: Uint8Array;
  init?: (
    batchPos: number,
    maxBlocks: number,
    mod: Mod,
    hash: HashInstance<Opts>,
    opts: MergeOpts<Opts, OutputOpts>
  ) => void | { blocks: number }; // we can use HashOpts via 'this.'
};
/*
Since we finally can do zero-alloc hashes, we should expose nice zero-alloc API for them:
- we write to user provided buffer at user provided position
- user provided buffer can be bigger than required length, but not less
- user may ask for less output from non-xof hashes (if hash used for consistency check instead of cryptography)
- out.length >= outPos+dkLen?
*/
export type OutputOpts = {
  out?: Uint8Array;
  outPos?: number;
  dkLen?: number; // outLen, but compat with old API.
};

export type HashStream<Opts> = {
  // streaming mode
  update(msg: Uint8Array): HashStream<Opts>; // this, but without weird recursive types
  // finish(): void;
  digest(opts?: Opts & OutputOpts): Uint8Array;
  destroy(): void;
  xof(bytes: number, opts?: Opts & OutputOpts): Uint8Array;
  // clone
  _cloneInto(to?: HashStream<Opts>): HashStream<Opts>;
  clone(): HashStream<Opts>;
  // old
  digestInto(buf: Uint8Array): void;
  xofInto(buf: Uint8Array): Uint8Array;
};

type MergeOpts<Opts, Out> = [Opts] extends [undefined] ? Out : Opts & Out;

export type HashInstance<Opts> = Asyncify<
  (msg: Uint8Array, opts?: MergeOpts<Opts, OutputOpts>) => Uint8Array
> & {
  // process multiple messages without concatBytes
  chunks: Asyncify<(chunks: Uint8Array[], opts?: MergeOpts<Opts, OutputOpts>) => Uint8Array>;
  parallel: Asyncify<(chunks: Uint8Array[], opts?: MergeOpts<Opts, OutputOpts>) => Uint8Array[]>;
  create: (opts?: Opts) => HashStream<Opts>;
  getPlatform: () => string | undefined;
  getDefinition: () => HashDef<any, Opts>;
  isSupported?: () => boolean | Promise<boolean>;
  blockLen: number;
  outputLen: number;
  canXOF?: boolean;
  oid?: Uint8Array;
};

const BRAND = /* @__PURE__ */ Symbol('hash_impl_brand');
const brandSet = /* @__PURE__ */ new WeakSet<object>();
function isBranded(x: unknown): x is object {
  return typeof x === 'function' || (typeof x === 'object' && x !== null)
    ? brandSet.has(x as object)
    : false;
}

// Universal generic wrapper
export function mkHash<Mod extends HashMod, Opts>(
  modFn: () => Mod,
  def: HashDef<Mod, Opts>,
  platform?: string
): HashInstance<Opts> {
  const { outputLen, blockLen, suffix = 0, init, canXOF, oid } = def;
  const outBlockLen = def.outputBlockLen ? def.outputBlockLen : def.outputLen;
  let hashImpl: (msg: Uint8Array, opts?: MergeOpts<Opts, OutputOpts>) => Uint8Array;
  let hashAsyncImpl: (
    msg: Uint8Array,
    opts?: MergeOpts<Opts, OutputOpts> & AsyncRunOpts
  ) => Promise<Uint8Array>;
  let chunksImpl: (parts: Uint8Array[], opts?: Opts & OutputOpts) => Uint8Array;
  let chunksAsyncImpl: (
    parts: Uint8Array[],
    opts?: Opts & OutputOpts & AsyncRunOpts
  ) => Promise<Uint8Array>;
  let parallelImpl: (chunks: Uint8Array[], opts?: Opts & OutputOpts) => Uint8Array[];
  let parallelAsyncImpl: (
    chunks: Uint8Array[],
    opts?: Opts & OutputOpts & AsyncRunOpts
  ) => Promise<Uint8Array[]>;
  let createImpl: (opts?: Opts & OutputOpts) => HashStream<Opts>;
  let inited = false;
  function lazyInit() {
    if (inited) throw new Error('second lazyInit call');
    const mod = modFn();
    inited = true;
    const { processBlocks, processOutBlocks, padding, reset } = mod;
    const BUFFER: Uint8Array = mod.segments.buffer;
    const STATE: Uint8Array = mod.segments.state_chunks[0];
    const parallelChunks = mod.segments.state_chunks.length;
    const maxBlocks = Math.floor(BUFFER.length / blockLen);
    const chunks = maxBlocks - 2; // 2 for padding
    if (chunks < 1) throw new Error('wrong chunks');
    const maxOutBlocks = Math.floor(BUFFER.length / outBlockLen);

    function initHash(opts: MergeOpts<Opts, OutputOpts>, batchPos = 0) {
      reset(batchPos, 1, 0, outBlockLen, maxOutBlocks);
      let blocks = 0;
      if (init) {
        const i = init(batchPos, maxBlocks, mod, hash, opts);
        if (i && i.blocks !== undefined) blocks = i.blocks;
      }
      return { blocks };
    }
    //  reset(0, 1);
    function processMessage(msg: Uint8Array, blocks: number) {
      // Preloaded blocks from init(): e.g., keyed BLAKE2 writes key||zeros into BUFFER
      // Invariant: these are full blocks, already in BUFFER, and must *not* be treated as 'last'.
      if (blocks > 0) {
        if (msg.length === 0) {
          const padBlocks = padding(0, blocks * blockLen, maxBlocks, 0, blockLen, suffix);
          processBlocks(0, 1, blocks + padBlocks, maxBlocks, blockLen, 1, 0, padBlocks);
          return;
        }
        processBlocks(0, 1, blocks, maxBlocks, blockLen, 0, 0, 0);
      }
      let pos = 0;
      do {
        const take = Math.min(msg.length - pos, chunks * blockLen);
        copyFast(BUFFER, 0, msg, pos, take);
        const isLast = pos + take == msg.length;
        let blocks = Math.ceil(take / blockLen); // how many blocks do we have here? full/partial. can be zero
        // now, we need position where we add padding? take?
        const left = blocks * blockLen - take; // how much space we have. blockLen-rem except when rem=0
        let padBlocks = 0;
        if (isLast) {
          padBlocks = padding(0, take, maxBlocks, left, blockLen, suffix); // suffix for sha3 and length for blake1, nothing for others
          blocks += padBlocks;
        }
        processBlocks(0, 1, blocks, maxBlocks, blockLen, isLast ? 1 : 0, left, padBlocks);
        pos += take;
      } while (pos < msg.length); // no extra final take=0 pass
    }
    function processMessages(parts: Uint8Array[], blocks: number) {
      // TODO: cleanup, garbage.
      const cap = (chunks * blockLen) | 0; // max bytes per batch
      // total length to keep isLast identical to single-buffer path
      let totalLen = 0;
      for (let k = 0; k < parts.length; k++) totalLen += parts[k].length;
      // Preloaded blocks from init():
      // those are full blocks, already in BUFFER, and must NOT be treated as 'last'.
      if (blocks > 0) {
        if (totalLen === 0) {
          const padBlocks = padding(0, blocks * blockLen, maxBlocks, 0, blockLen, suffix);
          processBlocks(0, 1, blocks + padBlocks, maxBlocks, blockLen, 1, 0, padBlocks);
          return;
        }
        processBlocks(0, 1, blocks, maxBlocks, blockLen, 0, 0, 0);
      }
      let pos = 0; // global position in virtual concatenation
      let idx = 0; // which part
      let off = 0; // offset within current part
      while (pos < totalLen) {
        const take = Math.min(totalLen - pos, cap) | 0;
        // fill BUFFER[0..take) from parts[idx..] without concat
        let written = 0;
        while (written < take) {
          const cur = parts[idx];
          const rem = (cur.length - off) | 0;
          const n = (take - written < rem ? take - written : rem) | 0;
          copyFast(BUFFER, written, cur, off, n);
          written += n;
          off += n;
          if (off === cur.length) {
            idx++;
            off = 0;
          }
        }

        const isLast = pos + take === totalLen;
        let blocks = Math.ceil(take / blockLen) | 0;
        const left = (blocks * blockLen - take) | 0;
        let padBlocks = 0;
        if (isLast) {
          padBlocks = padding(0, take, maxBlocks, left, blockLen, suffix) | 0;
          blocks = (blocks + padBlocks) | 0;
        }
        processBlocks(0, 1, blocks, maxBlocks, blockLen, isLast ? 1 : 0, left, padBlocks);
        pos += take;
      }
      return;
    }
    // same as processMessage but with chunkPos.
    function processMessageParallel(
      msg: Uint8Array[],
      chunkPos: number,
      chunkLen: number,
      blocks: number,
      maxBlocks: number
    ) {
      const chunks = maxBlocks - 2;
      if (chunks < 1) throw new Error('wrong chunks');
      // Caller validates per-group size equality before touching module state.
      if (blocks > 0) {
        if (msg[chunkPos].length === 0) {
          // No more message input: do a normal finalization over an empty tail.
          // Keep 'left' consistent with the wrapper contract for take=0: left=0.
          const padBlocks = padding(0, blocks * blockLen, maxBlocks, 0, blockLen, suffix);
          for (let j = 0; j < chunkLen; j++) {
            const pb2 = padding(j, blocks * blockLen, maxBlocks, 0, blockLen, suffix);
            if (pb2 !== padBlocks) throw new Error('different padding across batch');
          }
          processBlocks(0, chunkLen, blocks + padBlocks, maxBlocks, blockLen, 1, 0, padBlocks);
          return;
        }
        processBlocks(0, chunkLen, blocks, maxBlocks, blockLen, 0, 0, 0);
      }
      let pos = 0;
      do {
        const take = Math.min(msg[chunkPos].length - pos, chunks * blockLen);
        for (let i = 0; i < chunkLen; i++) {
          copyFast(BUFFER, i * maxBlocks * blockLen, msg[chunkPos + i], pos, take);
        }
        const isLast = pos + take == msg[chunkPos].length;
        let blocks = Math.ceil(take / blockLen); // how many blocks do we have here? full/partial. can be zero
        const left = blocks * blockLen - take; // how much space we have. blockLen-rem except when rem=0
        let padBlocks = 0;
        if (isLast) {
          padBlocks = padding(0, take, maxBlocks, left, blockLen, suffix); // suffix for sha3 and length for blake1, nothing for others
          for (let j = 1; j < chunkLen; j++) {
            const pb2 = padding(j, take, maxBlocks, left, blockLen, suffix);
            if (pb2 !== padBlocks) throw new Error('parallel batch: different padding');
          }
          blocks += padBlocks;
        }
        processBlocks(0, chunkLen, blocks, maxBlocks, blockLen, isLast ? 1 : 0, left, padBlocks);
        pos += take;
      } while (pos < msg[chunkPos].length); // no extra final take=0 pass
      return;
    }

    function checkOutputOpts(o = {} as OutputOpts, bytes?: number) {
      if (o.dkLen !== undefined) anumber(o.dkLen, 'opts.dkLen');
      if (o.outPos !== undefined) anumber(o.outPos, 'opts.outPos');
      if (o.out !== undefined) abytes(o.out, o.dkLen, 'output');
      if (bytes !== undefined) anumber(bytes, 'xof.bytes');
      const dkLen = bytes !== undefined ? bytes : (o.dkLen === undefined ? outputLen : o.dkLen) | 0;
      const out = o.out || new Uint8Array(dkLen);
      const outPos = (o.outPos === undefined ? 0 : o.outPos) | 0;
      if (outPos < 0 || outPos + dkLen > out.length) throw new Error('out/outPos too small');
      return { dkLen, out, outPos };
    }
    function processOutput(
      o = {} as OutputOpts,
      checked: ReturnType<typeof checkOutputOpts> = checkOutputOpts(o)
    ) {
      const { dkLen, out, outPos } = checked;
      const batch = chunks | 0;
      const blocksTotal = ((dkLen + outBlockLen - 1) / outBlockLen) | 0; // ceil div
      let produced = 0,
        blocksLeft = blocksTotal;
      let maxWritten = 0;
      while (blocksLeft > 0) {
        const takeBlocks = blocksLeft > batch ? batch : blocksLeft;
        const isLast = blocksLeft === takeBlocks ? 1 : 0;
        processOutBlocks(0, 1, takeBlocks, maxOutBlocks, outBlockLen, isLast);
        const emitted = takeBlocks * outBlockLen;
        const need = dkLen - produced;
        const takeBytes = need < emitted ? need : emitted;
        copyFast(out, outPos + produced, BUFFER, 0, takeBytes);
        maxWritten = Math.max(maxWritten, takeBytes, takeBlocks * outBlockLen);
        produced += takeBytes;
        blocksLeft -= takeBlocks;
      }
      // NOTE: it would be nice to return slices subarray here, but it is not free!
      return { maxWritten, out };
    }
    function checkOutputOptsParallel(opts = {} as Opts & OutputOpts, chunkLen: number) {
      if (opts.dkLen !== undefined) anumber(opts.dkLen, 'opts.dkLen');
      if (opts.outPos !== undefined) anumber(opts.outPos, 'opts.outPos');
      if (opts.out !== undefined) abytes(opts.out, undefined, 'output');
      const dkLen = (opts.dkLen === undefined ? outputLen : opts.dkLen) | 0;
      const out = opts.out || new Uint8Array(dkLen * chunkLen);
      const outPos = (opts.outPos === undefined ? 0 : opts.outPos) | 0;
      if (outPos < 0 || outPos + dkLen * chunkLen > out.length)
        throw new Error('out/outPos too small');
      const slices = [];
      for (let i = 0; i < chunkLen; i++) slices.push(out.subarray(i * dkLen, (i + 1) * dkLen));
      return { dkLen, outPos, out: slices };
    }
    function processOutputParallel(
      opts = {} as Opts & OutputOpts,
      _chunkPos: number,
      chunkLen: number,
      maxOutBlocks: number,
      checked: ReturnType<typeof checkOutputOptsParallel> = checkOutputOptsParallel(opts, chunkLen)
    ) {
      const chunks = maxOutBlocks;
      const { dkLen, outPos, out } = checked;
      let maxWritten = 0;
      const batch = chunks | 0;
      const blocksTotal = ((dkLen + outBlockLen - 1) / outBlockLen) | 0; // ceil div
      let produced = 0,
        blocksLeft = blocksTotal;
      while (blocksLeft > 0) {
        const takeBlocks = blocksLeft > batch ? batch : blocksLeft;
        const isLast = blocksLeft === takeBlocks ? 1 : 0;
        processOutBlocks(0, chunkLen, takeBlocks, maxOutBlocks, outBlockLen, isLast);
        const emitted = takeBlocks * outBlockLen;
        const need = dkLen - produced;
        const takeBytes = need < emitted ? need : emitted;
        for (let i = 0; i < chunkLen; i++) {
          copyFast(out[i], outPos + produced, BUFFER, i * outBlockLen * maxOutBlocks, takeBytes);
          // Some modules (e.g. blake3) may write full output blocks even when only part is copied out.
          // Track emitted block span for reset() so unread bytes are also zeroized.
          maxWritten = Math.max(maxWritten, takeBytes, emitted);
        }
        produced += takeBytes;
        blocksLeft -= takeBlocks;
      }
      // NOTE: it would be nice to return slices subarray here, but it is not free!
      return { out, maxWritten };
    }
    class StreamHash {
      private buf: Uint8Array;
      private pos: number;
      private state: Uint8Array;
      private finished: boolean;
      private destroyed: boolean;
      constructor(opts: any) {
        if (opts.streamBufLen % blockLen || opts.streamBufLen < blockLen)
          throw new Error('wrong streamBufLen');
        this.finished = false;
        this.destroyed = false;
        //   this.reserve = blockLen; // TODO: change when sha2
        this.buf = new Uint8Array(opts.streamBufLen);
        this.pos = 0;
        if (opts.blocks !== undefined) {
          if (opts.blocks * blockLen > this.buf.length) throw new Error('too much blocks');
          copyFast(this.buf, 0, BUFFER, 0, opts.blocks * blockLen);
          this.pos = opts.blocks * blockLen;
        }
        Object.assign(this, { blockLen, outputLen });
        this.state = copyBytes(STATE);
        reset(0, 1, 0, outBlockLen, maxOutBlocks); // cleanup
      }
      private restoreState() {
        copyFast(STATE, 0, this.state, 0, STATE.length);
      }
      private saveState() {
        this.state = copyBytes(STATE);
      }
      update(msg: Uint8Array): this {
        abytes(msg);
        if (this.destroyed) throw new Error('Hash instance has been destroyed');
        if (this.finished) throw new Error('Hash#digest() has already been called');
        let msgPos = 0;
        let blocks = Math.ceil((this.pos + msg.length) / blockLen) - 1; // never process last block here!
        if (blocks > 0) {
          this.restoreState();
          let takeBlocks = Math.min(chunks, blocks);
          // first can be unaligned!
          const msgFirstLen = takeBlocks * blockLen - this.pos;
          copyFast(BUFFER, 0, this.buf, 0, this.pos);
          copyFast(BUFFER, this.pos, msg, msgPos, msgFirstLen);
          this.pos = 0;
          msgPos += msgFirstLen;
          processBlocks(0, 1, takeBlocks, maxBlocks, blockLen, 0, 0, 0);
          blocks -= takeBlocks;
          for (; msgPos < msg.length && blocks; ) {
            const takeBlocks = Math.min(chunks, blocks);
            copyFast(BUFFER, 0, msg, msgPos, takeBlocks * blockLen);
            processBlocks(0, 1, takeBlocks, maxBlocks, blockLen, 0, 0, 0);
            blocks -= takeBlocks;
            msgPos += takeBlocks * blockLen;
          }
          this.saveState();
          reset(0, 1, 0, outBlockLen, maxOutBlocks);
        }
        // save leftovers
        const leftover = msg.length - msgPos;
        if (leftover) {
          copyFast(this.buf, this.pos, msg, msgPos, leftover);
          this.pos += leftover;
        }
        return this;
      }
      private finish() {
        if (this.finished) throw new Error('Hash#digest() has already been called');
        this.restoreState();
        this.finished = true;
        const isLast = true;
        let take = this.pos;
        let blocks = Math.ceil(take / blockLen);
        copyFast(BUFFER, 0, this.buf, 0, this.pos);
        const left = blocks * blockLen - take; // how much space we have. blockLen-rem except when rem=0
        let padBlocks = 0;
        if (isLast) {
          padBlocks = padding(0, take, maxBlocks, left, blockLen, suffix); // suffix for sha3 and length for blake1, nothing for others
          blocks += padBlocks;
        }
        processBlocks(0, 1, blocks, maxBlocks, blockLen, 1, left, padBlocks);
        this.pos = outBlockLen;
        return blocks * blockLen;
      }
      digest(opts = {} as Opts & OutputOpts) {
        if (this.destroyed) throw new Error('Hash instance has been destroyed');
        const outChecked = checkOutputOpts(opts);
        this.finish();
        const { out: res, maxWritten } = processOutput(opts, outChecked);
        this.destroy();
        reset(0, 1, maxWritten, outBlockLen, maxOutBlocks);
        return res;
      }
      /**
       * Resets internal state. Makes Hash instance unusable.
       * Reset is impossible for keyed hashes if key is consumed into state. If digest is not consumed
       * by user, they will need to manually call `destroy()` when zeroing is necessary.
       */
      destroy(): void {
        this.destroyed = true;
        this.state.fill(0);
        this.buf.fill(0);
      }
      xof(bytes: number, opts: OutputOpts = {}): Uint8Array {
        if (!canXOF) throw new Error('XOF is not possible for this instance');
        if (this.destroyed) throw new Error('Hash instance has been destroyed');
        const outChecked = checkOutputOpts(opts, bytes);
        if (!this.finished) {
          this.finish();
          this.saveState();
        }
        // XOF mutates module state via processOutBlocks(). Snapshot/restore around calls so
        // stream instances don't leak squeeze state into global hash wrappers.
        this.restoreState();
        const { out, outPos } = outChecked;
        for (let pos = 0; pos < bytes; ) {
          if (this.pos >= outBlockLen) {
            // get next squeeze block
            processOutBlocks(0, 1, 1, maxOutBlocks, outBlockLen, 0); // never 'last' in XOF
            copyFast(this.buf, 0, BUFFER, 0, outBlockLen);
            this.pos = 0;
          }
          const take =
            (outBlockLen - this.pos < bytes - pos ? outBlockLen - this.pos : bytes - pos) | 0;
          copyFast(out, (outPos + pos) | 0, this.buf, this.pos, take);
          this.pos = (this.pos + take) | 0;
          pos = (pos + take) | 0;
        }
        this.saveState();
        reset(0, 1, 0, outBlockLen, maxOutBlocks);
        return out;
      }
      // old api
      digestInto(buf: Uint8Array): void {
        this.digest({ out: buf, dkLen: buf.length } as Opts & OutputOpts);
      }
      xofInto(buf: Uint8Array): Uint8Array {
        return this.xof(buf.length, { out: buf });
      }
      /**
       * Clones hash instance. Unsafe: doesn't check whether `to` is valid. Can be used as `clone()`
       * when no options are passed.
       * Reasons to use `_cloneInto` instead of clone: 1) performance 2) reuse instance => all internal
       * buffers are overwritten => causes buffer overwrite which is used for digest in some cases.
       * There are no guarantees for clean-up because it's impossible in JS.
       */
      _cloneInto(to?: this): this {
        if (this.destroyed) throw new Error('Hash instance has been destroyed');
        // Allocate target if needed (ensure same stream buffer capacity).
        const dst =
          to || (new (this as any).constructor({ streamBufLen: this.buf.length }) as this);
        if (!(dst instanceof StreamHash)) throw new Error('wrong instance');
        if (dst.buf.length !== this.buf.length) throw new Error('wrong buffer length');
        // Copy tail / XOF cache content up to bufPos.
        if (this.pos) copyFast(dst.buf, 0, this.buf, 0, this.pos);
        dst.pos = this.pos | 0;
        // Snapshot of full engine state used by restoreState().
        dst.state = copyBytes(this.state);
        // Flags
        dst.finished = !!this.finished;
        dst.destroyed = !!this.destroyed;
        return dst;
      }
      // Safe version that clones internal state
      clone(): this {
        return this._cloneInto();
      }
    }
    const hashSync = (msg: Uint8Array, opts = {} as MergeOpts<Opts, OutputOpts>) => {
      abytes(msg);
      const outChecked = checkOutputOpts(opts);
      const { blocks } = initHash(opts);
      processMessage(msg, blocks);
      const { out: res, maxWritten } = processOutput(opts, outChecked);
      reset(0, 1, maxWritten, outBlockLen, maxOutBlocks);
      return res;
    };
    const chunksSync = (parts: Uint8Array[], opts = {} as Opts & OutputOpts) => {
      if (!Array.isArray(parts)) throw new Error('expected array of messages');
      for (const p of parts) abytes(p);
      const outChecked = checkOutputOpts(opts);
      const { blocks } = initHash(opts);
      processMessages(parts, blocks);
      const { out: res, maxWritten } = processOutput(opts, outChecked);
      reset(0, 1, maxWritten, outBlockLen, maxOutBlocks);
      return res;
    };
    const parallelSync = (chunks: Uint8Array[], opts = {} as Opts & OutputOpts) => {
      const out = [];
      const outChecked = [];
      // At least 3 blocks (for padding).
      const maxGroups = Math.floor(BUFFER.length / (blockLen * 3));
      const maxOutGroups = Math.floor(BUFFER.length / outBlockLen);
      // Validate user input first. Wrong input must throw before touching module state/memory.
      for (let i = 0; i < chunks.length; i += parallelChunks) {
        const groupLen = Math.min(parallelChunks, chunks.length - i, maxGroups, maxOutGroups);
        outChecked.push(checkOutputOptsParallel(opts, groupLen));
        for (let j = 0; j < groupLen; j++)
          if (!isBytes(chunks[i + j]))
            throw new Error(`expected Uint8Array, got type=${typeof chunks[i + j]}`);
        for (let j = 1; j < groupLen; j++) {
          if (chunks[i + j].length !== chunks[i].length)
            throw new Error('different sizes inside chunk');
        }
      }
      for (let i = 0; i < chunks.length; i += parallelChunks) {
        const groupLen = Math.min(parallelChunks, chunks.length - i, maxGroups, maxOutGroups);
        const maxBlocks = Math.floor(BUFFER.length / (blockLen * groupLen));
        const maxOutBlocks = Math.floor(BUFFER.length / (outBlockLen * groupLen));
        let blocks = 0;
        if (init) {
          const i = init(0, maxBlocks, mod, hash, opts);
          if (i && i.blocks !== undefined) blocks = i.blocks;
          for (let j = 0; j < groupLen; j++) {
            const t = init(j, maxBlocks, mod, hash, opts);
            if ((t && t.blocks) !== (i && i.blocks))
              throw new Error('inconsistent init blocks inside parallel group');
          }
        }
        processMessageParallel(chunks, i, groupLen, blocks, maxBlocks);
        const { out: res, maxWritten } = processOutputParallel(
          opts,
          i,
          groupLen,
          maxOutBlocks,
          outChecked[(i / parallelChunks) | 0]
        );
        out.push(...res);
        reset(0, groupLen, maxWritten, outBlockLen, maxOutBlocks);
      }
      return out;
    };
    const setupTick = (
      setup: AsyncSetup & { isAsync?: boolean },
      total: number,
      opts?: AsyncRunOpts
    ) =>
      !setup.isAsync
        ? !opts?.onProgress
          ? (setup({ total: 0 }), (_inc?: number) => false)
          : setup({ total, onProgress: opts.onProgress })
        : setup({
            total,
            asyncTick: opts?.asyncTick,
            onProgress: opts?.onProgress,
            nextTick: opts?.nextTick,
          });
    const hashRun = mkAsync(function* (
      setup,
      msg: Uint8Array,
      opts = {} as MergeOpts<Opts, OutputOpts> & AsyncRunOpts
    ) {
      const setupMode = setup as AsyncSetup & { isAsync?: boolean };
      if (!setupMode.isAsync && !opts?.onProgress) return hashSync(msg, opts);
      const tick = setupTick(setupMode, msg.length, opts);
      const out = hashSync(msg, opts);
      if ((setupMode.isAsync || !!opts?.onProgress) && tick(msg.length)) yield;
      return out;
    });
    const chunksRun = mkAsync(function* (
      setup,
      parts: Uint8Array[],
      opts = {} as Opts & OutputOpts & AsyncRunOpts
    ) {
      const setupMode = setup as AsyncSetup & { isAsync?: boolean };
      if (!setupMode.isAsync && !opts?.onProgress) return chunksSync(parts, opts);
      let total = 0;
      for (const p of parts) total += p.length;
      const tick = setupTick(setupMode, total, opts);
      const out = chunksSync(parts, opts);
      if ((setupMode.isAsync || !!opts?.onProgress) && tick(total)) yield;
      return out;
    });
    const parallelRun = mkAsync(function* (
      setup,
      parts: Uint8Array[],
      opts = {} as Opts & OutputOpts & AsyncRunOpts
    ) {
      const setupMode = setup as AsyncSetup & { isAsync?: boolean };
      if (!setupMode.isAsync && !opts?.onProgress) return parallelSync(parts, opts);
      let total = 0;
      for (const p of parts) total += p.length;
      const tick = setupTick(setupMode, total, opts);
      const out = parallelSync(parts, opts);
      if ((setupMode.isAsync || !!opts?.onProgress) && tick(total)) yield;
      return out;
    });
    hashImpl = (msg, opts = {} as MergeOpts<Opts, OutputOpts>) => hashSync(msg, opts);
    hashAsyncImpl = async (msg, opts?: MergeOpts<Opts, OutputOpts> & AsyncRunOpts) => {
      if (!opts) return hashSync(msg, {} as MergeOpts<Opts, OutputOpts>);
      return opts.asyncTick !== undefined ||
        opts.onProgress !== undefined ||
        opts.nextTick !== undefined
        ? hashRun.async(msg, opts)
        : hashSync(msg, opts);
    };
    chunksImpl = (parts: Uint8Array[], opts = {} as Opts & OutputOpts) => chunksSync(parts, opts);
    chunksAsyncImpl = async (parts: Uint8Array[], opts?: Opts & OutputOpts & AsyncRunOpts) => {
      if (!opts) return chunksSync(parts, {} as Opts & OutputOpts);
      return opts.asyncTick !== undefined ||
        opts.onProgress !== undefined ||
        opts.nextTick !== undefined
        ? chunksRun.async(parts, opts)
        : chunksSync(parts, opts);
    };
    parallelImpl = (parts: Uint8Array[], opts = {} as Opts & OutputOpts) =>
      parallelSync(parts, opts);
    parallelAsyncImpl = async (parts: Uint8Array[], opts?: Opts & OutputOpts & AsyncRunOpts) => {
      if (!opts) return parallelSync(parts, {} as Opts & OutputOpts);
      return opts.asyncTick !== undefined ||
        opts.onProgress !== undefined ||
        opts.nextTick !== undefined
        ? parallelRun.async(parts, opts)
        : parallelSync(parts, opts);
    };
    createImpl = (opts = {} as Opts & OutputOpts) => {
      reset(0, 1, 0, outBlockLen, maxOutBlocks);
      const { blocks } = initHash(opts);
      return new StreamHash({ ...opts, streamBufLen: blockLen, blocks });
    };
  }
  // Trampoline: init only on first usage
  hashImpl = (msg, opts) => {
    lazyInit();
    return hashImpl(msg, opts);
  };
  hashAsyncImpl = (msg, opts) => {
    lazyInit();
    return hashAsyncImpl(msg, opts);
  };
  chunksImpl = (parts, opts) => {
    lazyInit();
    return chunksImpl(parts, opts);
  };
  chunksAsyncImpl = (parts, opts) => {
    lazyInit();
    return chunksAsyncImpl(parts, opts);
  };
  parallelImpl = (chunks, opts) => {
    lazyInit();
    return parallelImpl(chunks, opts);
  };
  parallelAsyncImpl = (chunks, opts) => {
    lazyInit();
    return parallelAsyncImpl(chunks, opts);
  };
  createImpl = (opts) => {
    lazyInit();
    return createImpl(opts);
  };
  const hash = ((msg, opts = {} as MergeOpts<Opts, OutputOpts>) =>
    hashImpl(msg, opts)) as HashInstance<Opts>;
  const chunksFn = (parts: Uint8Array[], opts = {} as Opts & OutputOpts) => chunksImpl(parts, opts);
  Object.assign(chunksFn, {
    async: (parts: Uint8Array[], opts?: Opts & OutputOpts & AsyncRunOpts) =>
      chunksAsyncImpl(parts, opts),
  });
  const parallel = (chunks: Uint8Array[], opts = {} as Opts & OutputOpts) =>
    parallelImpl(chunks, opts);
  Object.assign(parallel, {
    async: (chunks: Uint8Array[], opts?: Opts & OutputOpts & AsyncRunOpts) =>
      parallelAsyncImpl(chunks, opts),
  });
  Object.assign(hash, {
    async: (msg: Uint8Array, opts?: Opts & OutputOpts & AsyncRunOpts) => hashAsyncImpl(msg, opts),
    chunks: chunksFn,
    parallel,
    create: (opts = {} as Opts & OutputOpts) => createImpl(opts),
    getPlatform: () => platform,
    getDefinition: () => def,
    canXOF,
    outputLen,
    blockLen,
    oid,
  });
  Object.defineProperty(hash, BRAND, { value: true, enumerable: false });
  brandSet.add(hash);
  return Object.freeze(hash);
}

type AsyncHashImpl<Opts> = {
  hash: (msg: Uint8Array, opts?: MergeOpts<Opts, OutputOpts>) => Promise<Uint8Array>;
  chunks?: (parts: Uint8Array[], opts?: MergeOpts<Opts, OutputOpts>) => Promise<Uint8Array>;
  parallel?: (parts: Uint8Array[], opts?: MergeOpts<Opts, OutputOpts>) => Promise<Uint8Array[]>;
};

const copyOutput = (
  out: Uint8Array,
  opts: OutputOpts | undefined,
  outputLen: number,
  canXOF?: boolean
) => {
  const dkLen = opts?.dkLen || outputLen;
  anumber(dkLen, 'dkLen');
  if (!canXOF && dkLen > outputLen) throw new Error(`expected dkLen <= outputLen, got ${dkLen}`);
  if (out.length < dkLen) throw new Error(`expected output length >= dkLen, got ${out.length}`);
  const msg = out.subarray(0, dkLen);
  if (!opts?.out) {
    const res = copyBytes(msg);
    clean(out);
    return res;
  }
  const outPos = opts.outPos || 0;
  anumber(outPos, 'outPos');
  if (opts.out.length < outPos + dkLen) throw new Error('output is too small');
  opts.out.set(msg, outPos);
  clean(out);
  return opts.out;
};

const hashSyncError = () => {
  throw new Error('sync is not supported');
};

export function mkHashAsync<Opts>(
  def: HashDef<any, Opts>,
  impl: AsyncHashImpl<Opts>,
  platform = 'webcrypto',
  isSupported?: () => boolean | Promise<boolean>
): HashInstance<Opts> {
  const { outputLen, blockLen, canXOF, oid } = def;
  const hash = ((_msg: Uint8Array) => hashSyncError()) as unknown as HashInstance<Opts>;
  const hashAsync = async (msg: Uint8Array, opts = {} as Opts & OutputOpts) => {
    abytes(msg);
    const out = await impl.hash(msg, opts);
    return copyOutput(out, opts, outputLen, canXOF);
  };
  const chunks = ((_parts: Uint8Array[]) =>
    hashSyncError()) as unknown as HashInstance<Opts>['chunks'];
  const chunksAsync = async (parts: Uint8Array[], opts = {} as Opts & OutputOpts) => {
    for (let i = 0; i < parts.length; i++) abytes(parts[i]);
    if (impl.chunks) {
      const out = await impl.chunks(parts, opts);
      return copyOutput(out, opts, outputLen, canXOF);
    }
    const joined = concatBytes(...parts);
    try {
      const out = await impl.hash(joined, opts);
      return copyOutput(out, opts, outputLen, canXOF);
    } finally {
      clean(joined);
    }
  };
  Object.assign(chunks, { async: chunksAsync });
  const parallel = ((_parts: Uint8Array[]) =>
    hashSyncError()) as unknown as HashInstance<Opts>['parallel'];
  const parallelAsync = async (parts: Uint8Array[], opts = {} as Opts & OutputOpts) => {
    if (opts.out || opts.outPos) throw new Error('parallel output opts are not supported');
    for (let i = 0; i < parts.length; i++) abytes(parts[i]);
    const out = impl.parallel
      ? await impl.parallel(parts, opts)
      : await Promise.all(parts.map((i) => impl.hash(i, opts)));
    return out.map((i) => copyOutput(i, opts, outputLen, canXOF));
  };
  Object.assign(parallel, { async: parallelAsync });
  Object.assign(hash, {
    async: hashAsync,
    chunks,
    parallel,
    create: () => {
      throw new Error('streaming is not supported');
    },
    getPlatform: () => platform,
    getDefinition: () => def,
    canXOF,
    outputLen,
    blockLen,
    oid,
  });
  if (isSupported) (hash as any).isSupported = isSupported;
  Object.defineProperty(hash, BRAND, { value: true, enumerable: false });
  brandSet.add(hash as object);
  return Object.freeze(hash);
}

/*
stubbing allows to install specific implementation of hash later.

- Some apps (React Native; also ones wish wasm-unsafe-eval) can't use wasm
- Some apps (no CORS; broken bundling) can't use wasm_threads
- So they use js

Risks such as:

- Installing an implementation from previous version of the library
- Installing a malware

Are mitigated by:

- Checking for unique Symbol on install()
- Test result is preserved in inaccessible WeakSet

Multiple installations are allowed, the last one wins.
*/
type Stub<Opts> = { install: (impl: HashInstance<Opts>) => void };
export function mkHashStub<Mod extends HashMod, Opts>(
  def: HashDef<Mod, Opts>
): HashInstance<Opts> & Stub<Opts> {
  const { outputLen, blockLen, canXOF, oid } = def;
  let inner: HashInstance<Opts> | undefined;
  function checkInner(inner: HashInstance<Opts> | undefined): asserts inner is HashInstance<Opts> {
    if (inner === undefined) throw new Error('implementation not installed');
  }
  const hash = ((msg, opts = {} as Opts & OutputOpts) => {
    checkInner(inner);
    return inner(msg, opts);
  }) as HashInstance<Opts> & Stub<Opts>;

  const chunks = (parts: Uint8Array[], opts = {} as Opts & OutputOpts) => {
    checkInner(inner);
    return inner.chunks(parts, opts);
  };
  Object.assign(chunks, {
    async: async (parts: Uint8Array[], opts = {} as Opts & OutputOpts) => {
      checkInner(inner);
      return inner.chunks.async(parts, opts);
    },
  });
  const parallel = (chunks: Uint8Array[], opts = {} as Opts & OutputOpts) => {
    checkInner(inner);
    return inner.parallel(chunks, opts);
  };
  Object.assign(parallel, {
    async(chunks: Uint8Array[], opts = {} as Opts & OutputOpts) {
      checkInner(inner);
      return inner.parallel.async(chunks, opts);
    },
  });

  Object.assign(hash, {
    async: async (msg: Uint8Array, opts = {} as Opts & OutputOpts) => {
      checkInner(inner);
      return inner.async(msg, opts);
    },
    chunks,
    parallel,
    create(opts = {} as Opts & OutputOpts) {
      checkInner(inner);
      return inner.create(opts);
    },
    getPlatform: () => {
      checkInner(inner);
      return inner.getPlatform();
    },
    getDefinition: () => {
      checkInner(inner);
      return inner.getDefinition();
    },
    install: (impl: HashInstance<Opts>) => {
      if (!isBranded(impl)) throw new Error('install: non-branded implementation');
      // NOTE: this strict check works because all implementations will use exact same frozen definition
      // which means it is impossible to use same blockLen/outputLen hash from different definition
      if (impl.getDefinition() !== def) throw new Error('wrong implementation definition');
      inner = impl;
    },
    canXOF,
    outputLen,
    blockLen,
    oid,
  });
  return Object.freeze(hash);
}
