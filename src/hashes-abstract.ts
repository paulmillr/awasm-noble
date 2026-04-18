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
  type TArg,
  type TRet,
} from './utils.ts';

export type HashMod = {
  readonly segments: {
    readonly buffer: Uint8Array; // no need to copy on streaming mode
    readonly 'state.state_chunks': ReadonlyArray<Uint8Array>; // actual state for iv
    // Should contain everything needed to export/import and restart a streaming hash.
    readonly state: Uint8Array;
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

/** Hash algorithm definition shared by all runtime/target wrappers. */
export type HashDef<Mod extends HashMod, Opts = undefined> = {
  /** Optional domain-separation suffix byte applied before the shared padding path. */
  suffix?: number;
  /** Preferred chunk count for batch helpers. */
  chunks?: number; // = 16
  /** Compression/input block size in bytes. */
  blockLen: number;
  /** Output block size in bytes when it differs from {@link blockLen}. */
  outputBlockLen?: number;
  /** Default digest length in bytes. */
  outputLen: number;
  /** Whether the hash supports variable-length XOF output. */
  canXOF?: boolean;
  /** Optional ASN.1 object identifier for fixed-output hash variants. */
  oid?: TRet<Uint8Array>;
  /**
   * Initialize state and optionally override block count or effective output length.
   * @param batchPos - batch slot being initialized.
   * @param maxBlocks - maximum number of blocks available in the shared buffers.
   * @param mod - backend hash module implementation for this batch slot.
   * @param hash - public hash helper being configured.
   * @param opts - merged hash and output options for this initialization; see {@link MergeOpts}.
   * @returns Optional overrides for preloaded block count or effective digest length.
   */
  init?: (
    batchPos: number,
    maxBlocks: number,
    mod: Mod,
    hash: HashInstance<Opts>,
    opts: MergeOpts<Opts, OutputOpts>
    // We can use HashOpts via `this`.
  ) => void | { blocks?: number; outputLen?: number };
};
/*
Since we finally can do zero-alloc hashes, we should expose nice zero-alloc API for them:
- we write to user provided buffer at user provided position
- user provided buffer can be bigger than required length, but not less
- user may ask for less output from non-xof hashes
  (if hash is used for consistency checks instead of cryptography)
- out.length >= outPos+dkLen?
*/
/** Shared output-buffer options for one-shot and streaming hash APIs. */
export type OutputOpts = {
  /** Optional destination buffer to write the digest or XOF output into. */
  out?: TArg<Uint8Array>;
  /** Starting offset inside {@link out}. */
  outPos?: number;
  /** Requested digest length in bytes. */
  dkLen?: number; // outLen, but compat with old API.
};

/** Streaming hash instance returned by {@link HashInstance.create}. */
export type HashStream<Opts> = {
  // streaming mode
  /** Whether this stream supports variable-length XOF output via xof()/xofInto(). */
  canXOF: boolean;
  /** Absorb more message bytes into the stream and return the same stream. */
  update(msg: TArg<Uint8Array>): HashStream<Opts>; // this, but without weird recursive types
  // finish(): void;
  /** Finalize the stream and return the digest bytes. */
  digest(opts?: Opts & OutputOpts): TRet<Uint8Array>;
  /** Wipe internal state and make the stream unusable. */
  destroy(): void;
  /** Finalize the stream and return variable-length XOF output. */
  xof(bytes: number, opts?: Opts & OutputOpts): TRet<Uint8Array>;
  // clone
  /** Copy the current stream state into another stream or a freshly created clone target. */
  _cloneInto(to?: HashStream<Opts>): HashStream<Opts>;
  /** Clone the current stream state. */
  clone(): HashStream<Opts>;
  // Fixed-size in-place digest: writes only the digest prefix and returns nothing.
  /**
   * Finalize the stream and write the fixed-size digest into `buf`.
   * @param buf - destination buffer for the digest bytes.
   */
  digestInto(buf: TArg<Uint8Array>): void;
  // Variable-size XOF output: fills the whole destination buffer and returns it back.
  /** Finalize the stream and fill `buf` with XOF output. */
  xofInto(buf: TArg<Uint8Array>): TRet<Uint8Array>;
};

type MergeOpts<Opts, Out> = [Opts] extends [undefined] ? Out : Opts & Out;

/** One-shot hash helper plus streaming constructor and metadata. */
export type HashInstance<Opts> = Asyncify<
  (msg: TArg<Uint8Array>, opts?: MergeOpts<Opts, OutputOpts>) => TRet<Uint8Array>
> & {
  // process multiple messages without concatBytes
  chunks: Asyncify<
    (chunks: TArg<Uint8Array[]>, opts?: MergeOpts<Opts, OutputOpts>) => TRet<Uint8Array>
  >;
  parallel: Asyncify<
    (chunks: TArg<Uint8Array[]>, opts?: MergeOpts<Opts, OutputOpts>) => TRet<Uint8Array[]>
  >;
  create: (opts?: Opts) => HashStream<Opts>;
  getPlatform: () => string | undefined;
  getDefinition: () => HashDef<any, Opts>;
  isSupported?: () => boolean | Promise<boolean>;
  blockLen: number;
  outputLen: number;
  // Whether this hash surface supports variable-length XOF output.
  canXOF: boolean;
  oid?: TRet<Uint8Array>;
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
  def_: TArg<HashDef<Mod, Opts>>,
  platform?: string
): TRet<HashInstance<Opts>> {
  const def = def_ as HashDef<Mod, Opts>;
  const { outputLen, blockLen, suffix = 0, init, canXOF, oid } = def;
  const outBlockLen = def.outputBlockLen ? def.outputBlockLen : def.outputLen;
  let hashImpl: (
    msg: TArg<Uint8Array>,
    opts?: TArg<MergeOpts<Opts, OutputOpts>>
  ) => TRet<Uint8Array>;
  let hashAsyncImpl: (
    msg: TArg<Uint8Array>,
    opts?: TArg<MergeOpts<Opts, OutputOpts> & AsyncRunOpts>
  ) => Promise<TRet<Uint8Array>>;
  let chunksImpl: (parts: TArg<Uint8Array[]>, opts?: TArg<Opts & OutputOpts>) => TRet<Uint8Array>;
  let chunksAsyncImpl: (
    parts: TArg<Uint8Array[]>,
    opts?: TArg<Opts & OutputOpts & AsyncRunOpts>
  ) => Promise<TRet<Uint8Array>>;
  let parallelImpl: (
    chunks: TArg<Uint8Array[]>,
    opts?: TArg<Opts & OutputOpts>
  ) => TRet<Uint8Array[]>;
  let parallelAsyncImpl: (
    chunks: TArg<Uint8Array[]>,
    opts?: TArg<Opts & OutputOpts & AsyncRunOpts>
  ) => Promise<TRet<Uint8Array[]>>;
  let createImpl: (opts?: TArg<Opts & OutputOpts>) => TRet<HashStream<Opts>>;
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

    function initHash(opts: TArg<MergeOpts<Opts, OutputOpts>>, batchPos = 0) {
      const rawOpts = opts as MergeOpts<Opts, OutputOpts>;
      reset(batchPos, 1, 0, outBlockLen, maxOutBlocks);
      let blocks = 0;
      let streamOutputLen = outputLen;
      if (init) {
        const i = init(batchPos, maxBlocks, mod, hash as HashInstance<Opts>, rawOpts);
        if (i && i.blocks !== undefined) blocks = i.blocks;
        if (i && i.outputLen !== undefined) streamOutputLen = i.outputLen;
      }
      return { blocks, outputLen: streamOutputLen };
    }
    //  reset(0, 1);
    function processMessage(msg: TArg<Uint8Array>, blocks: number) {
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
        // How many full/partial blocks do we have here? Can be zero.
        let blocks = Math.ceil(take / blockLen);
        // now, we need position where we add padding? take?
        // How much space remains? blockLen-rem, except rem=0.
        const left = blocks * blockLen - take;
        let padBlocks = 0;
        if (isLast) {
          // suffix for sha3 and length for blake1, nothing for others
          padBlocks = padding(0, take, maxBlocks, left, blockLen, suffix);
          blocks += padBlocks;
        }
        processBlocks(0, 1, blocks, maxBlocks, blockLen, isLast ? 1 : 0, left, padBlocks);
        pos += take;
      } while (pos < msg.length); // no extra final take=0 pass
    }
    function processMessages(parts: TArg<Uint8Array[]>, blocks: number) {
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
      msg: TArg<Uint8Array[]>,
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
        // How many full/partial blocks do we have here? Can be zero.
        let blocks = Math.ceil(take / blockLen);
        // How much space remains? blockLen-rem, except rem=0.
        const left = blocks * blockLen - take;
        let padBlocks = 0;
        if (isLast) {
          // suffix for sha3 and length for blake1, nothing for others
          padBlocks = padding(0, take, maxBlocks, left, blockLen, suffix);
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

    function checkOutputOpts(
      o = {} as TArg<OutputOpts>,
      bytes?: number
    ): TRet<{ dkLen: number; out: TRet<Uint8Array>; outPos: number }> {
      const raw = o as OutputOpts;
      if (raw.dkLen !== undefined) anumber(raw.dkLen, 'opts.dkLen');
      if (raw.outPos !== undefined) anumber(raw.outPos, 'opts.outPos');
      if (raw.out !== undefined) abytes(raw.out, undefined, 'output');
      if (bytes !== undefined) anumber(bytes, 'xof.bytes');
      let dkLen =
        bytes !== undefined ? bytes : (raw.dkLen === undefined ? outputLen : raw.dkLen) | 0;
      // Old awasm hash output opts intentionally allow requesting a shorter fixed digest, but
      // must reject oversize lengths instead of silently clamping or zero-extending the tail.
      if (!canXOF && dkLen > outputLen)
        throw new RangeError(`"opts.dkLen" expected <= ${outputLen}, got ${dkLen}`);
      const out = raw.out || new Uint8Array(dkLen);
      const outPos = (raw.outPos === undefined ? 0 : raw.outPos) | 0;
      if (outPos < 0 || outPos + dkLen > out.length) throw new RangeError('out/outPos too small');
      return { dkLen, out: out as TRet<Uint8Array>, outPos } as TRet<{
        dkLen: number;
        out: TRet<Uint8Array>;
        outPos: number;
      }>;
    }
    function processOutput(
      o = {} as TArg<OutputOpts>,
      checked: TArg<ReturnType<typeof checkOutputOpts>> = checkOutputOpts(o)
    ): TRet<{ maxWritten: number; out: TRet<Uint8Array> }> {
      const { dkLen, out, outPos } = checked as ReturnType<typeof checkOutputOpts>;
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
      return { maxWritten, out } as TRet<{ maxWritten: number; out: TRet<Uint8Array> }>;
    }
    function checkOutputOptsParallel(
      opts = {} as TArg<Opts & OutputOpts>,
      chunkPos: number,
      chunkLen: number
    ): TRet<{ dkLen: number; out: TRet<Uint8Array>[] }> {
      const raw = opts as Opts & OutputOpts;
      if (raw.dkLen !== undefined) anumber(raw.dkLen, 'opts.dkLen');
      if (raw.outPos !== undefined) anumber(raw.outPos, 'opts.outPos');
      if (raw.out !== undefined) abytes(raw.out, undefined, 'output');
      const dkLen = (raw.dkLen === undefined ? outputLen : raw.dkLen) | 0;
      if (!canXOF && dkLen > outputLen)
        throw new RangeError(`"opts.dkLen" expected <= ${outputLen}, got ${dkLen}`);
      const out = raw.out || new Uint8Array(dkLen * chunkLen);
      const outPos = (raw.outPos === undefined ? 0 : raw.outPos) | 0;
      const base = raw.out ? outPos + chunkPos * dkLen : outPos;
      if (outPos < 0 || base + dkLen * chunkLen > out.length)
        throw new RangeError('out/outPos too small');
      const slices: TRet<Uint8Array>[] = [];
      for (let i = 0; i < chunkLen; i++)
        slices.push(out.subarray(base + i * dkLen, base + (i + 1) * dkLen) as TRet<Uint8Array>);
      return { dkLen, out: slices } as TRet<{ dkLen: number; out: TRet<Uint8Array>[] }>;
    }
    function processOutputParallel(
      opts = {} as TArg<Opts & OutputOpts>,
      _chunkPos: number,
      chunkLen: number,
      maxOutBlocks: number,
      checked: TArg<ReturnType<typeof checkOutputOptsParallel>> = checkOutputOptsParallel(
        opts,
        _chunkPos,
        chunkLen
      )
    ): TRet<{ out: TRet<Uint8Array>[]; maxWritten: number }> {
      const chunks = maxOutBlocks;
      const { dkLen, out } = checked as ReturnType<typeof checkOutputOptsParallel>;
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
          copyFast(out[i], produced, BUFFER, i * outBlockLen * maxOutBlocks, takeBytes);
          // Some modules (e.g. blake3) may write full output blocks even when only part is copied out.
          // Track emitted block span for reset() so unread bytes are also zeroized.
          maxWritten = Math.max(maxWritten, takeBytes, emitted);
        }
        produced += takeBytes;
        blocksLeft -= takeBlocks;
      }
      // NOTE: it would be nice to return slices subarray here, but it is not free!
      return { out, maxWritten } as TRet<{ out: TRet<Uint8Array>[]; maxWritten: number }>;
    }
    class StreamHash {
      canXOF: boolean;
      blockLen: number;
      outputLen: number;
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
        this.canXOF = !!canXOF;
        this.blockLen = blockLen;
        this.outputLen = opts.outputLen;
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
      digest(opts = {} as Opts & OutputOpts): TRet<Uint8Array> {
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
      xof(bytes: number, opts: OutputOpts = {}): TRet<Uint8Array> {
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
        // digestInto is the fixed-size surface even for XOF hashes, but callers may provide a
        // larger workspace buffer and expect the tail to stay untouched.
        abytes(buf, undefined, 'output');
        if (buf.length < this.outputLen)
          // Keep short digest destinations aligned with the shared noble-hashes contract:
          // wrong output type -> TypeError, too-short output -> RangeError.
          throw new RangeError(
            'digestInto() expects output buffer of length at least ' + this.outputLen
          );
        this.digest({ out: buf.subarray(0, this.outputLen), dkLen: this.outputLen } as Opts &
          OutputOpts);
      }
      xofInto(buf: Uint8Array): TRet<Uint8Array> {
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
        // Clones must preserve the public stream metadata too. digest()/digestInto() allocate and
        // validate against outputLen, xof()/xofInto() gate on canXOF, and callers may read blockLen.
        dst.blockLen = this.blockLen;
        dst.outputLen = this.outputLen;
        dst.canXOF = this.canXOF;
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
    const hashSync = (msg: TArg<Uint8Array>, opts = {} as MergeOpts<Opts, OutputOpts>) => {
      abytes(msg);
      const outChecked = checkOutputOpts(opts);
      const { blocks } = initHash(opts);
      processMessage(msg, blocks);
      const { out: res, maxWritten } = processOutput(opts, outChecked);
      reset(0, 1, maxWritten, outBlockLen, maxOutBlocks);
      return res;
    };
    const chunksSync = (parts: TArg<Uint8Array[]>, opts = {} as Opts & OutputOpts) => {
      if (!Array.isArray(parts)) throw new Error('expected array of messages');
      for (const p of parts) abytes(p);
      const outChecked = checkOutputOpts(opts);
      const { blocks } = initHash(opts);
      processMessages(parts, blocks);
      const { out: res, maxWritten } = processOutput(opts, outChecked);
      reset(0, 1, maxWritten, outBlockLen, maxOutBlocks);
      return res;
    };
    const parallelSync = (chunks: TArg<Uint8Array[]>, opts = {} as Opts & OutputOpts) => {
      const out = [];
      const outChecked = [];
      // At least 3 blocks (for padding).
      const maxGroups = Math.floor(BUFFER.length / (blockLen * 3));
      const maxOutGroups = Math.floor(BUFFER.length / outBlockLen);
      // Validate user input first. Wrong input must throw before touching module state/memory.
      for (let i = 0; i < chunks.length; i += parallelChunks) {
        const groupLen = Math.min(parallelChunks, chunks.length - i, maxGroups, maxOutGroups);
        outChecked.push(checkOutputOptsParallel(opts, i, groupLen));
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
      setup: TArg<AsyncSetup & { isAsync?: boolean }>,
      total: number,
      opts?: TArg<AsyncRunOpts>
    ) => {
      const rawSetup = setup as AsyncSetup & { isAsync?: boolean };
      const rawOpts = opts as AsyncRunOpts | undefined;
      return !rawSetup.isAsync
        ? !rawOpts?.onProgress
          ? (rawSetup({ total: 0 }), (_inc?: number) => false)
          : rawSetup({ total, onProgress: rawOpts.onProgress })
        : rawSetup({
            total,
            asyncTick: rawOpts?.asyncTick,
            onProgress: rawOpts?.onProgress,
            nextTick: rawOpts?.nextTick,
          });
    };
    const hashRun = mkAsync(function* (
      setup: TArg<AsyncSetup>,
      msg: TArg<Uint8Array>,
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
      setup: TArg<AsyncSetup>,
      parts: TArg<Uint8Array[]>,
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
      setup: TArg<AsyncSetup>,
      parts: TArg<Uint8Array[]>,
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
    hashImpl = (msg, opts = {} as TArg<MergeOpts<Opts, OutputOpts>>) =>
      hashSync(msg, opts as MergeOpts<Opts, OutputOpts>);
    hashAsyncImpl = async (msg, opts?: TArg<MergeOpts<Opts, OutputOpts> & AsyncRunOpts>) => {
      const rawOpts = opts as (MergeOpts<Opts, OutputOpts> & AsyncRunOpts) | undefined;
      if (!rawOpts) return hashSync(msg, {} as MergeOpts<Opts, OutputOpts>);
      return rawOpts.asyncTick !== undefined ||
        rawOpts.onProgress !== undefined ||
        rawOpts.nextTick !== undefined
        ? hashRun.async(msg, rawOpts)
        : hashSync(msg, rawOpts);
    };
    chunksImpl = (parts: TArg<Uint8Array[]>, opts = {} as TArg<Opts & OutputOpts>) =>
      chunksSync(parts, opts as Opts & OutputOpts);
    chunksAsyncImpl = async (
      parts: TArg<Uint8Array[]>,
      opts?: TArg<Opts & OutputOpts & AsyncRunOpts>
    ) => {
      const rawOpts = opts as (Opts & OutputOpts & AsyncRunOpts) | undefined;
      if (!rawOpts) return chunksSync(parts, {} as Opts & OutputOpts);
      return rawOpts.asyncTick !== undefined ||
        rawOpts.onProgress !== undefined ||
        rawOpts.nextTick !== undefined
        ? chunksRun.async(parts, rawOpts)
        : chunksSync(parts, rawOpts);
    };
    parallelImpl = (parts: TArg<Uint8Array[]>, opts = {} as TArg<Opts & OutputOpts>) =>
      parallelSync(parts, opts as Opts & OutputOpts);
    parallelAsyncImpl = async (
      parts: TArg<Uint8Array[]>,
      opts?: TArg<Opts & OutputOpts & AsyncRunOpts>
    ) => {
      const rawOpts = opts as (Opts & OutputOpts & AsyncRunOpts) | undefined;
      if (!rawOpts) return parallelSync(parts, {} as Opts & OutputOpts);
      return rawOpts.asyncTick !== undefined ||
        rawOpts.onProgress !== undefined ||
        rawOpts.nextTick !== undefined
        ? parallelRun.async(parts, rawOpts)
        : parallelSync(parts, rawOpts);
    };
    createImpl = (opts = {} as TArg<Opts & OutputOpts>) => {
      const rawOpts = opts as Opts & OutputOpts;
      reset(0, 1, 0, outBlockLen, maxOutBlocks);
      const { blocks, outputLen } = initHash(rawOpts);
      return new StreamHash({ ...rawOpts, streamBufLen: blockLen, blocks, outputLen }) as TRet<
        HashStream<Opts>
      >;
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
  const hash = ((msg, opts = {} as TArg<MergeOpts<Opts, OutputOpts>>) =>
    hashImpl(msg, opts as TArg<MergeOpts<Opts, OutputOpts>>)) as TRet<HashInstance<Opts>>;
  const chunksFn = (parts: TArg<Uint8Array[]>, opts = {} as TArg<Opts & OutputOpts>) =>
    chunksImpl(parts, opts);
  Object.assign(chunksFn, {
    async: (parts: TArg<Uint8Array[]>, opts?: TArg<Opts & OutputOpts & AsyncRunOpts>) =>
      chunksAsyncImpl(parts, opts),
  });
  const parallel = (chunks: TArg<Uint8Array[]>, opts = {} as TArg<Opts & OutputOpts>) =>
    parallelImpl(chunks, opts);
  Object.assign(parallel, {
    async: (chunks: TArg<Uint8Array[]>, opts?: TArg<Opts & OutputOpts & AsyncRunOpts>) =>
      parallelAsyncImpl(chunks, opts),
  });
  Object.assign(hash, {
    async: (msg: TArg<Uint8Array>, opts?: TArg<Opts & OutputOpts & AsyncRunOpts>) =>
      hashAsyncImpl(msg, opts as TArg<MergeOpts<Opts, OutputOpts> & AsyncRunOpts> | undefined),
    chunks: chunksFn,
    parallel,
    create: (opts = {} as Opts & OutputOpts) => createImpl(opts),
    getPlatform: () => platform,
    getDefinition: () => def,
    canXOF: !!canXOF,
    outputLen,
    blockLen,
    oid,
  });
  Object.defineProperty(hash, BRAND, { value: true, enumerable: false });
  brandSet.add(hash);
  return Object.freeze(hash) as TRet<HashInstance<Opts>>;
}

type AsyncHashImpl<Opts> = {
  hash: (msg: TArg<Uint8Array>, opts?: MergeOpts<Opts, OutputOpts>) => Promise<TRet<Uint8Array>>;
  chunks?: (
    parts: TArg<Uint8Array[]>,
    opts?: MergeOpts<Opts, OutputOpts>
  ) => Promise<TRet<Uint8Array>>;
  parallel?: (
    parts: TArg<Uint8Array[]>,
    opts?: MergeOpts<Opts, OutputOpts>
  ) => Promise<TRet<Uint8Array[]>>;
};

const copyOutput = (
  out: TArg<Uint8Array>,
  opts: TArg<OutputOpts | undefined>,
  outputLen: number,
  canXOF?: boolean
): TRet<Uint8Array> => {
  const rawLen = opts?.dkLen;
  if (rawLen !== undefined) anumber(rawLen, 'dkLen');
  const dkLen = rawLen === undefined ? outputLen : rawLen;
  anumber(dkLen, 'dkLen');
  // Old awasm hash output opts intentionally allow requesting a shorter fixed digest, but
  // must reject oversize lengths instead of silently clamping or zero-extending the tail.
  if (!canXOF && dkLen > outputLen)
    throw new RangeError(`"dkLen" expected <= ${outputLen}, got ${dkLen}`);
  if (out.length < dkLen)
    throw new RangeError(`expected output length >= dkLen, got ${out.length}`);
  const msg = out.subarray(0, dkLen);
  if (!opts?.out) {
    const res = copyBytes(msg);
    clean(out);
    return res as TRet<Uint8Array>;
  }
  const outPos = opts.outPos || 0;
  anumber(outPos, 'outPos');
  if (opts.out.length < outPos + dkLen) throw new RangeError('output is too small');
  opts.out.set(msg, outPos);
  clean(out);
  return opts.out as TRet<Uint8Array>;
};

const hashSyncError = () => {
  throw new Error('sync is not supported');
};

export function mkHashAsync<Opts>(
  def_: TArg<HashDef<any, Opts>>,
  impl_: TArg<AsyncHashImpl<Opts>>,
  platform = 'webcrypto',
  isSupported?: () => boolean | Promise<boolean>,
  meta?: Record<string, unknown>
): TRet<HashInstance<Opts>> {
  const def = def_ as HashDef<any, Opts>;
  const impl = impl_ as AsyncHashImpl<Opts>;
  const { outputLen, blockLen, canXOF, oid } = def;
  const hash = ((_msg: TArg<Uint8Array>) => hashSyncError()) as unknown as HashInstance<Opts>;
  const hashAsync = async (msg: TArg<Uint8Array>, opts = {} as Opts & OutputOpts) => {
    abytes(msg);
    const out = await impl.hash(msg, opts);
    return copyOutput(out, opts, outputLen, canXOF);
  };
  const chunks = ((_parts: TArg<Uint8Array[]>) =>
    hashSyncError()) as unknown as HashInstance<Opts>['chunks'];
  const chunksAsync = async (parts: TArg<Uint8Array[]>, opts = {} as Opts & OutputOpts) => {
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
  const parallel = ((_parts: TArg<Uint8Array[]>) =>
    hashSyncError()) as unknown as HashInstance<Opts>['parallel'];
  const parallelAsync = async (parts: TArg<Uint8Array[]>, opts = {} as Opts & OutputOpts) => {
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
    canXOF: !!canXOF,
    outputLen,
    blockLen,
    oid,
  });
  if (meta) Object.assign(hash, meta);
  if (isSupported) (hash as any).isSupported = isSupported;
  Object.defineProperty(hash, BRAND, { value: true, enumerable: false });
  brandSet.add(hash as object);
  return Object.freeze(hash) as TRet<HashInstance<Opts>>;
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
  def_: TArg<HashDef<Mod, Opts>>
): TRet<HashInstance<Opts> & Stub<Opts>> {
  const def = def_ as HashDef<Mod, Opts>;
  const { outputLen, blockLen, canXOF, oid } = def;
  let inner: HashInstance<Opts> | undefined;
  function checkInner(
    inner: TArg<HashInstance<Opts> | undefined>
  ): asserts inner is HashInstance<Opts> {
    if (inner === undefined) throw new Error('implementation not installed');
  }
  const hash = ((msg, opts = {} as Opts & OutputOpts) => {
    checkInner(inner);
    return inner(msg, opts);
  }) as HashInstance<Opts> & Stub<Opts>;

  const chunks = (parts: TArg<Uint8Array[]>, opts = {} as Opts & OutputOpts) => {
    checkInner(inner);
    return inner.chunks(parts, opts);
  };
  Object.assign(chunks, {
    async: async (parts: TArg<Uint8Array[]>, opts = {} as Opts & OutputOpts) => {
      checkInner(inner);
      return inner.chunks.async(parts, opts);
    },
  });
  const parallel = (chunks: TArg<Uint8Array[]>, opts = {} as Opts & OutputOpts) => {
    checkInner(inner);
    return inner.parallel(chunks, opts);
  };
  Object.assign(parallel, {
    async(chunks: TArg<Uint8Array[]>, opts = {} as Opts & OutputOpts) {
      checkInner(inner);
      return inner.parallel.async(chunks, opts);
    },
  });

  Object.assign(hash, {
    async: async (msg: TArg<Uint8Array>, opts = {} as Opts & OutputOpts) => {
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
    install: (impl: TArg<HashInstance<Opts>>) => {
      // install() accepts only constructor-created hashes: WeakSet branding rejects copied fields,
      // and exact definition identity rejects same-shaped but different hash families.
      if (!isBranded(impl)) throw new Error('install: non-branded implementation');
      // NOTE: this strict check works because all implementations will use exact same frozen definition
      // which means it is impossible to use same blockLen/outputLen hash from different definition
      if (impl.getDefinition() !== def) throw new Error('wrong implementation definition');
      inner = impl as HashInstance<Opts>;
    },
    canXOF,
    outputLen,
    blockLen,
    oid,
  });
  return Object.freeze(hash) as TRet<HashInstance<Opts> & Stub<Opts>>;
}
