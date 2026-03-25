/**
 * Abstract logic for ciphers.
 * @module
 */
import {
  abytes,
  clean,
  cleanFast,
  copyBytes,
  copyFast,
  mkAsync,
  type AsyncRunOpts,
  type AsyncSetup,
} from './utils.ts';

export type Cipher = {
  encrypt(plaintext: Uint8Array, output?: Uint8Array): Uint8Array;
  decrypt(ciphertext: Uint8Array, output?: Uint8Array): Uint8Array;
};
export type CipherFactory = ((key: Uint8Array, ...args: unknown[]) => Cipher) & {
  blockSize: number;
  blockLen: number;
  nonceLength?: number;
  tagLength?: number;
  varSizeNonce?: boolean;
  getPlatform: () => string | undefined;
  getDefinition: () => CipherDef<any>;
  isSupported?: () => boolean | Promise<boolean>;
};
type CipherStub = { install: (impl: CipherFactory) => void };
const brandSet = new WeakSet<object>();
const isBranded = (x: unknown): x is object =>
  typeof x === 'function' || (typeof x === 'object' && x !== null)
    ? brandSet.has(x as object)
    : false;

export type CipherParams = {
  blockSize?: number;
  blockLen: number;
  nonceLength?: number;
  tagLength?: number;
  varSizeNonce?: boolean;
};

export type CipherOpts = {
  disablePadding?: boolean;
};

export type CipherStream = {
  update(data: Uint8Array, output?: Uint8Array): Uint8Array;
  finish(tag?: Uint8Array): { data: Uint8Array; tag?: Uint8Array };
  destroy(): void;
  _cloneInto(to?: CipherStream): CipherStream;
  clone(): CipherStream;
  saveState(): Uint8Array;
  restoreState(state: Uint8Array): void;
};

type Dir = 'encrypt' | 'decrypt';

type CipherMod = {
  readonly segments: {
    readonly buffer: Uint8Array;
    readonly state: Uint8Array;
  };
  reset(maxWritten: number): void;
  encryptBlocks(blocks: number, isLast: number, left: number, round?: number): void;
  decryptBlocks(blocks: number, isLast: number, left: number, round?: number): void;
  aadBlocks?(blocks: number, isLast: number, left: number): void;
  macBlocks?(blocks: number, isLast: number, left: number): void;
  tagInit?(): void;
  addPadding?(take: number, left: number, blockLen: number): number;
  verifyPadding?(take: number, blockLen: number): number;
};

export type CipherDef<Mod> = CipherParams & {
  tagLeft?: boolean;
  dataOffset?: number;
  paddingLeft?: number;
  padding?: boolean;
  padFull?: boolean;
  multiPass?: number;
  multiPassResult?: boolean | { encrypt?: boolean; decrypt?: boolean };
  multiPassOut?: { encrypt?: number; decrypt?: number };
  tagError?: string;
  lengthError?: string;
  lengthErrorEnc?: string;
  lengthErrorDec?: string;
  lengthLimitEnc?: (len: number) => void;
  lengthLimitDec?: (len: number) => void;
  padError?: string;
  emptyError?: string;
  noOverlap?: boolean;
  noOutput?: boolean;
  noStream?: boolean;
  twoPass?: boolean;
  validate?: (key: Uint8Array, ...args: unknown[]) => void;
  init: (
    mod: Mod,
    dir: Dir,
    key: Uint8Array,
    ...args: unknown[]
  ) => void | {
    disablePadding?: boolean;
  };
  getTag?: (mod: Mod) => Uint8Array;
};

const getOutput = (len: number, out?: Uint8Array) => {
  if (!out) return new Uint8Array(len);
  if (out.length < len) throw new Error('output is too small');
  return out;
};

const equalBytes = (a: Uint8Array, b: Uint8Array) => {
  if (a.length !== b.length) return false;
  let diff = 0;
  for (let i = 0; i < a.length; i++) diff |= a[i] ^ b[i];
  return diff === 0;
};

export const mkCipher = <Mod extends CipherMod>(
  modFn: () => Mod,
  def: CipherDef<Mod>,
  platform?: string
) => {
  let mod: Mod | undefined;
  let BUFFER: Uint8Array;
  let STATE: Uint8Array;
  let maxBlocks = 0;
  const { blockLen, tagLength, tagLeft, padding, noStream, twoPass } = def;
  const multiPass = def.multiPass || 0;
  const multiPassResult = def.multiPassResult;
  const multiPassOut = def.multiPassOut;
  const hasTag = !!tagLength;
  const paddingLeft = def.paddingLeft || 0;
  const padFull = def.padFull !== undefined ? def.padFull : true;
  const padZeroOk = !!paddingLeft || !padFull;
  const lengthError = (dir: Dir) =>
    def.lengthError || (dir === 'encrypt' ? def.lengthErrorEnc : def.lengthErrorDec);
  const padError = () => def.padError || def.lengthError || 'invalid padding';
  const emptyError = () => def.emptyError || def.padError || def.lengthError || 'invalid padding';
  const passResult = (dir: Dir) => {
    if (multiPassResult && typeof multiPassResult === 'object')
      return !!(multiPassResult as { encrypt?: boolean; decrypt?: boolean })[dir];
    return !!multiPassResult;
  };
  const lazyInit = () => {
    if (mod) return;
    mod = modFn();
    const bufAny = mod.segments.buffer as Uint8Array | Uint32Array;
    BUFFER =
      bufAny instanceof Uint8Array
        ? bufAny
        : new Uint8Array(bufAny.buffer, bufAny.byteOffset, bufAny.byteLength);
    STATE = mod.segments.state;
    maxBlocks = Math.floor(BUFFER.length / blockLen);
    if (maxBlocks < 1) throw new Error('blockLen is too large for buffer');
  };
  const reset = (maxWritten: number) => {
    if (!mod) throw new Error('missing module');
    if (platform === 'js') {
      // JS `.fill(0)` is slow on large buffers. Clear the written prefix via `cleanFast`,
      // and ask the module to reset only its state/small scratch.
      if (maxWritten) cleanFast(BUFFER, maxWritten);
      cleanFast(STATE);
      mod.reset(0);
      return;
    }
    mod.reset(maxWritten);
  };
  const runBlocks = (dir: Dir, blocks: number, isLast: number, left: number, round?: number) => {
    if (!mod) throw new Error('missing module');
    if (dir === 'encrypt') mod.encryptBlocks(blocks, isLast, left, round);
    else mod.decryptBlocks(blocks, isLast, left, round);
  };
  const getTag = () => {
    if (!def.getTag) throw new Error('missing getTag');
    return def.getTag(mod as Mod);
  };
  const initCipher = (dir: Dir, key: Uint8Array, args: unknown[]) => {
    if (!mod) throw new Error('missing module');
    const res = def.init(mod, dir, key, ...args);
    if (!padding || !res || typeof res !== 'object') return false;
    return !!(res as { disablePadding?: boolean }).disablePadding;
  };
  const process = (
    dir: Dir,
    data: Uint8Array,
    output: Uint8Array | undefined,
    key: Uint8Array,
    args: unknown[]
  ) => {
    if (dir === 'encrypt' && def.lengthLimitEnc) def.lengthLimitEnc(data.length);
    if (dir === 'decrypt' && def.lengthLimitDec) def.lengthLimitDec(data.length);
    let overlapCopy: Uint8Array | undefined;
    const cleanInput = () => {
      if (!overlapCopy) return;
      cleanFast(overlapCopy);
      overlapCopy = undefined;
    };
    // Avoid overlapping input/output corrupting tags or ciphertext in-place.
    if (output && output.buffer === data.buffer) {
      const aStart = data.byteOffset;
      const aEnd = aStart + data.byteLength;
      const bStart = output.byteOffset;
      const bEnd = bStart + output.byteLength;
      if (aStart < bEnd && bStart < aEnd) {
        if (def.noOverlap) throw new Error('input and output cannot overlap');
        overlapCopy = copyBytes(data);
        data = overlapCopy;
      }
    }
    // initCipher writes key material into module memory; any validation error after this point
    // must still trigger a reset, otherwise zero-check will catch the leaked state.
    const disablePadding = initCipher(dir, key, args);
    try {
      if (padding && hasTag) throw new Error('padding with tag is not supported');
      const tagLen = tagLength || 0;
      let msg = data;
      let passedTag: Uint8Array | undefined;
      if (hasTag && dir === 'decrypt') {
        if (data.length < tagLen) throw new Error(lengthError('decrypt') || 'invalid data length');
        if (tagLeft) {
          passedTag = data.subarray(0, tagLen);
          msg = data.subarray(tagLen);
        } else {
          passedTag = data.subarray(data.length - tagLen);
          msg = data.subarray(0, data.length - tagLen);
        }
      }
      if (!mod) throw new Error('missing module');
      const m = mod;
      if (multiPass && def.dataOffset)
        throw new Error('multiPass with dataOffset is not supported');
      if (multiPass && paddingLeft) {
        if (!m.addPadding || !m.verifyPadding) throw new Error('missing padding');
        const rem = msg.length % blockLen;
        const pad =
          padding && dir === 'encrypt' && !disablePadding
            ? rem === 0
              ? padFull
                ? blockLen
                : 0
              : blockLen - rem
            : 0;
        const totalLen = dir === 'encrypt' ? paddingLeft + msg.length + pad : msg.length;
        if (totalLen > BUFFER.length) {
          // Use a work buffer to support KWP large inputs with padding.
          const work = new Uint8Array(totalLen);
          if (dir === 'encrypt') {
            if (msg.length) copyFast(work, paddingLeft, msg, 0, msg.length);
            if (pad) work.fill(0, paddingLeft + msg.length, paddingLeft + msg.length + pad);
            m.addPadding(msg.length, pad, blockLen);
            copyFast(work, 0, BUFFER, 0, paddingLeft);
          } else {
            copyFast(work, 0, msg, 0, msg.length);
          }
          const totalBlocks = totalLen / blockLen;
          const rBlocks = totalBlocks - 1;
          const maxR = maxBlocks - 1;
          if (maxR < 1) throw new Error('blockLen is too large for buffer');
          const a = new Uint8Array(paddingLeft);
          copyFast(a, 0, work, 0, paddingLeft);
          let maxWritten = 0;
          try {
            for (let round = 0; round < multiPass; round++) {
              if (dir === 'encrypt') {
                let pos = 0;
                while (pos < rBlocks) {
                  const chunkR = Math.min(maxR, rBlocks - pos);
                  const start = paddingLeft + pos * blockLen;
                  const bytes = chunkR * blockLen;
                  copyFast(BUFFER, 0, a, 0, paddingLeft);
                  copyFast(BUFFER, paddingLeft, work, start, bytes);
                  const roundBase = round * rBlocks + pos + 1;
                  // `runBlocks` may throw (e.g. padding/integrity on decrypt); mark touched prefix first
                  // so reset scrubs buffer even on exceptional exits.
                  maxWritten = Math.max(maxWritten, paddingLeft + bytes);
                  runBlocks(dir, chunkR + 1, 1, 0, roundBase);
                  copyFast(a, 0, BUFFER, 0, paddingLeft);
                  copyFast(work, start, BUFFER, paddingLeft, bytes);
                  pos += chunkR;
                }
              } else {
                let pos = rBlocks;
                while (pos > 0) {
                  const chunkR = Math.min(maxR, pos);
                  const start = paddingLeft + (pos - chunkR) * blockLen;
                  const bytes = chunkR * blockLen;
                  copyFast(BUFFER, 0, a, 0, paddingLeft);
                  copyFast(BUFFER, paddingLeft, work, start, bytes);
                  const roundBase = (multiPass - 1 - round) * rBlocks + pos;
                  // `runBlocks` may throw (e.g. padding/integrity on decrypt); mark touched prefix first
                  // so reset scrubs buffer even on exceptional exits.
                  maxWritten = Math.max(maxWritten, paddingLeft + bytes);
                  runBlocks(dir, chunkR + 1, 1, 0, roundBase);
                  copyFast(a, 0, BUFFER, 0, paddingLeft);
                  copyFast(work, start, BUFFER, paddingLeft, bytes);
                  pos -= chunkR;
                }
              }
              copyFast(work, 0, a, 0, paddingLeft);
            }
            if (dir === 'decrypt') {
              copyFast(BUFFER, 0, a, 0, paddingLeft);
              const gotPad = m.verifyPadding(totalLen, blockLen);
              if (gotPad > blockLen || (!padZeroOk && gotPad === 0)) throw new Error(padError());
              const outLen = totalLen - paddingLeft - gotPad;
              const out = getOutput(totalLen - paddingLeft, output);
              copyFast(out, 0, work, paddingLeft, outLen);
              cleanInput();
              return out.subarray(0, outLen);
            }
            const out = getOutput(totalLen, output);
            copyFast(out, 0, work, 0, totalLen);
            cleanInput();
            return out;
          } finally {
            cleanFast(work);
            cleanFast(a);
            reset(maxWritten);
          }
        }
        const blocks = Math.ceil(totalLen / blockLen);
        if (blocks * blockLen !== totalLen)
          throw new Error(lengthError(dir) || 'invalid data length');
        let maxWritten = 0;
        try {
          // This branch writes/reads [0..totalLen) in module buffer; if decrypt integrity checks throw,
          // scrub the full touched prefix instead of leaving ciphertext/plaintext in buffer.
          maxWritten = totalLen;
          if (dir === 'encrypt') {
            if (msg.length) copyFast(BUFFER, paddingLeft, msg, 0, msg.length);
            if (pad) BUFFER.fill(0, paddingLeft + msg.length, paddingLeft + msg.length + pad);
            m.addPadding(msg.length, pad, blockLen);
            // Run all rounds inside the module when paddingLeft is used.
            runBlocks(dir, blocks, 1, 0, 0xffffffff);
            const out = getOutput(totalLen, output);
            copyFast(out, 0, BUFFER, 0, totalLen);
            cleanInput();
            return out;
          }
          if (msg.length) copyFast(BUFFER, 0, msg, 0, msg.length);
          // Run all rounds inside the module when paddingLeft is used.
          runBlocks(dir, blocks, 1, 0, 0xffffffff);
          const gotPad = m.verifyPadding(totalLen, blockLen);
          if (gotPad > blockLen || (!padZeroOk && gotPad === 0)) throw new Error(padError());
          const outLen = totalLen - paddingLeft - gotPad;
          const out = getOutput(outLen, output);
          copyFast(out, 0, BUFFER, paddingLeft, outLen);
          cleanInput();
          return out;
        } finally {
          reset(maxWritten);
        }
      }
      if (multiPass) {
        if (padding && dir === 'decrypt' && !disablePadding && msg.length % blockLen !== 0)
          throw new Error(lengthError('decrypt') || 'invalid data length');
        if (padding && dir === 'decrypt' && !disablePadding && msg.length === 0)
          throw new Error(emptyError());
        if (padding && disablePadding && msg.length % blockLen !== 0)
          throw new Error(lengthError(dir) || 'invalid data length');
        const rem = msg.length % blockLen;
        const pad =
          padding && dir === 'encrypt' && !disablePadding
            ? rem === 0
              ? padFull
                ? blockLen
                : 0
              : blockLen - rem
            : 0;
        const cipherOutLen = msg.length + pad;
        const tagPrefix = dir === 'encrypt' && tagLeft ? tagLen : 0;
        const tagSuffix = dir === 'encrypt' && hasTag && !tagLeft ? tagLen : 0;
        const outLen = tagPrefix + cipherOutLen + tagSuffix;
        const out = getOutput(outLen || 0, output);
        if (hasTag && dir === 'decrypt') {
          if (!passedTag) throw new Error(def.tagError || 'invalid tag');
          const tagSeg = (m as any).segments?.['state.tag'] as Uint8Array | undefined;
          if (tagSeg) tagSeg.set(passedTag);
        }
        const useResult = passResult(dir);
        const outRound =
          multiPassOut && typeof multiPassOut === 'object' && multiPassOut[dir] !== undefined
            ? (multiPassOut[dir] as number)
            : multiPass - 1;
        const workOwned = useResult && multiPass > 1;
        const work = workOwned
          ? new Uint8Array(cipherOutLen)
          : out.subarray(tagPrefix, tagPrefix + cipherOutLen);
        const work2Owned = useResult ? multiPass > 2 : true;
        const work2 = work2Owned
          ? new Uint8Array(cipherOutLen)
          : useResult && multiPass > 1
            ? work
            : new Uint8Array(cipherOutLen);
        const runPass = (
          input: Uint8Array,
          output: Uint8Array,
          round: number,
          applyPadding: boolean,
          applyVerify: boolean
        ) => {
          let pos = 0;
          let outPos = 0;
          let maxWritten = 0;
          let lastBytes = 0;
          let processed = false;
          while (pos < input.length) {
            const remaining = input.length - pos;
            const isLast = remaining <= maxBlocks * blockLen ? 1 : 0;
            const blocks = isLast ? Math.ceil(remaining / blockLen) : maxBlocks;
            const take = remaining < blocks * blockLen ? remaining : blocks * blockLen;
            const left = blocks * blockLen - take;
            if (take) copyFast(BUFFER, 0, input, pos, take);
            if (left) BUFFER.fill(0, take, take + left);
            let padBlocks = 0;
            if (isLast && applyPadding) {
              if (!m.addPadding) throw new Error('missing padding');
              padBlocks = m.addPadding(take, left, blockLen);
            }
            const padApplied = applyPadding;
            const totalBlocks = blocks + padBlocks;
            runBlocks(dir, totalBlocks, isLast, padApplied ? 0 : left, round);
            const bytes = padApplied
              ? totalBlocks * blockLen
              : padBlocks
                ? totalBlocks * blockLen
                : take;
            if (bytes) {
              copyFast(output, outPos, BUFFER, 0, bytes);
              maxWritten = Math.max(maxWritten, totalBlocks * blockLen);
              outPos += bytes;
            }
            if (isLast) lastBytes = bytes;
            pos += take;
            processed = processed || totalBlocks > 0 || isLast === 1;
            if (isLast) break;
          }
          if (!processed) runBlocks(dir, 0, 1, 0, round);
          if (applyVerify) {
            if (!m.verifyPadding) throw new Error('missing padding');
            const pad = m.verifyPadding(lastBytes, blockLen);
            if (pad > blockLen || (!padZeroOk && pad === 0)) throw new Error(padError());
            return [outPos - pad, maxWritten] as const;
          }
          return [outPos, maxWritten] as const;
        };
        let cur = msg;
        let outPos = 0;
        let maxWritten = 0;
        try {
          for (let round = 0; round < multiPass; round++) {
            const hasPadding = !!padding;
            const applyPadding = hasPadding && dir === 'encrypt' && !disablePadding && round === 0;
            const applyVerify =
              hasPadding && dir === 'decrypt' && !disablePadding && round === multiPass - 1;
            const writeOut = round === outRound;
            const target = writeOut
              ? out.subarray(tagPrefix)
              : useResult
                ? round % 2 === 0
                  ? work
                  : work2
                : work2;
            const res = runPass(cur, target, round, applyPadding, applyVerify);
            outPos = res[0];
            maxWritten = Math.max(maxWritten, res[1]);
            if (round !== multiPass - 1 && useResult) cur = target;
          }
          if (hasTag) {
            const tag = getTag();
            if (dir === 'encrypt') {
              if (tagLeft) copyFast(out, 0, tag, 0, tagLen);
              else copyFast(out, tagPrefix + cipherOutLen, tag, 0, tagLen);
            } else if (!equalBytes(tag, passedTag as Uint8Array)) {
              throw new Error(def.tagError || 'invalid tag');
            }
          }
          cleanInput();
          return out.subarray(0, tagPrefix + outPos + tagSuffix);
        } finally {
          if (work2Owned && work2 !== work) cleanFast(work2);
          if (workOwned) cleanFast(work);
          reset(maxWritten);
        }
      }
      if (twoPass) {
        if (!hasTag) throw new Error('missing tag length');
        if (padding) throw new Error('padding with tag is not supported');
        const macBlocks = m.macBlocks;
        const tagInit = m.tagInit;
        if (!macBlocks) throw new Error('missing macBlocks');
        if (!tagInit) throw new Error('missing tagInit');
        if (dir === 'decrypt' && !passedTag) throw new Error(def.tagError || 'invalid tag');
        const tagPrefix = dir === 'encrypt' && tagLeft ? tagLen : 0;
        const tagSuffix = dir === 'encrypt' && hasTag && !tagLeft ? tagLen : 0;
        const outLen = tagPrefix + msg.length + tagSuffix;
        const out = getOutput(outLen || 0, output);
        let pos = 0;
        let outPos = 0;
        let maxWritten = 0;
        let processed = false;
        const runMac = (input: Uint8Array) => {
          pos = 0;
          processed = false;
          while (pos < input.length) {
            const remaining = input.length - pos;
            const isLast = remaining <= maxBlocks * blockLen ? 1 : 0;
            const blocks = isLast ? Math.ceil(remaining / blockLen) : maxBlocks;
            const take = remaining < blocks * blockLen ? remaining : blocks * blockLen;
            const left = blocks * blockLen - take;
            if (take) copyFast(BUFFER, 0, input, pos, take);
            if (left) BUFFER.fill(0, take, take + left);
            macBlocks(blocks, isLast, left);
            maxWritten = Math.max(maxWritten, blocks * blockLen);
            pos += take;
            processed = processed || blocks > 0 || isLast === 1;
            if (isLast) break;
          }
          if (!processed) macBlocks(0, 1, 0);
        };
        const runCipher = (dir: Dir, input: Uint8Array, outBase: number) => {
          pos = 0;
          processed = false;
          while (pos < input.length) {
            const remaining = input.length - pos;
            const isLast = remaining <= maxBlocks * blockLen ? 1 : 0;
            const blocks = isLast ? Math.ceil(remaining / blockLen) : maxBlocks;
            const take = remaining < blocks * blockLen ? remaining : blocks * blockLen;
            const left = blocks * blockLen - take;
            if (take) copyFast(BUFFER, 0, input, pos, take);
            if (left) BUFFER.fill(0, take, take + left);
            runBlocks(dir, blocks, isLast, left, -1);
            if (take) {
              copyFast(out, outBase + outPos, BUFFER, 0, take);
              maxWritten = Math.max(maxWritten, blocks * blockLen);
              outPos += take;
            }
            pos += take;
            processed = processed || blocks > 0 || isLast === 1;
            if (isLast) break;
          }
          if (!processed) runBlocks(dir, 0, 1, 0, -1);
        };
        try {
          if (dir === 'encrypt') {
            runMac(msg);
            const tag = getTag();
            tagInit();
            outPos = 0;
            runCipher('encrypt', msg, tagPrefix);
            if (tagLeft) copyFast(out, 0, tag, 0, tagLen);
            else copyFast(out, tagPrefix + msg.length, tag, 0, tagLen);
            cleanInput();
            return out;
          }
          const tagSeg = (m as any).segments['state.tag'] as Uint8Array;
          tagSeg.set(passedTag as Uint8Array);
          tagInit();
          outPos = 0;
          runCipher('decrypt', msg, 0);
          runMac(out.subarray(0, msg.length));
          const computed = getTag();
          if (!equalBytes(computed, passedTag as Uint8Array))
            throw new Error(def.tagError || 'invalid tag');
          cleanInput();
          return out.subarray(0, msg.length);
        } finally {
          reset(maxWritten);
        }
      }
      if (paddingLeft) {
        if (!m.addPadding || !m.verifyPadding) throw new Error('missing padding');
        const rem = msg.length % blockLen;
        const pad =
          padding && dir === 'encrypt' && !disablePadding
            ? rem === 0
              ? padFull
                ? blockLen
                : 0
              : blockLen - rem
            : 0;
        const totalLen = dir === 'encrypt' ? paddingLeft + msg.length + pad : msg.length;
        if (totalLen > BUFFER.length) throw new Error('input is too large');
        const blocks = Math.ceil(totalLen / blockLen);
        if (blocks * blockLen !== totalLen)
          throw new Error(lengthError(dir) || 'invalid data length');
        let maxWritten = 0;
        try {
          if (dir === 'encrypt') {
            if (msg.length) copyFast(BUFFER, paddingLeft, msg, 0, msg.length);
            if (pad) BUFFER.fill(0, paddingLeft + msg.length, paddingLeft + msg.length + pad);
            m.addPadding(msg.length, pad, blockLen);
            runBlocks(dir, blocks, 1, 0, -1);
            const out = getOutput(totalLen, output);
            copyFast(out, 0, BUFFER, 0, totalLen);
            maxWritten = Math.max(maxWritten, totalLen);
            cleanInput();
            return out;
          }
          if (msg.length) copyFast(BUFFER, 0, msg, 0, msg.length);
          runBlocks(dir, blocks, 1, 0, -1);
          const gotPad = m.verifyPadding(totalLen, blockLen);
          if (gotPad > blockLen || (!padZeroOk && gotPad === 0)) throw new Error(padError());
          const outLen = totalLen - paddingLeft - gotPad;
          const out = getOutput(outLen, output);
          copyFast(out, 0, BUFFER, paddingLeft, outLen);
          maxWritten = Math.max(maxWritten, totalLen);
          cleanInput();
          return out;
        } finally {
          reset(maxWritten);
        }
      }
      if (padding && dir === 'decrypt' && !disablePadding && msg.length % blockLen !== 0)
        throw new Error(lengthError('decrypt') || 'invalid data length');
      if (padding && dir === 'decrypt' && !disablePadding && msg.length === 0)
        throw new Error(emptyError());
      if (padding && disablePadding && msg.length % blockLen !== 0)
        throw new Error(lengthError(dir) || 'invalid data length');
      const rem = msg.length % blockLen;
      const pad =
        padding && dir === 'encrypt' && !disablePadding
          ? rem === 0
            ? padFull
              ? blockLen
              : 0
            : blockLen - rem
          : 0;
      const cipherOutLen = msg.length + pad;
      const tagPrefix = dir === 'encrypt' && tagLeft ? tagLen : 0;
      const tagSuffix = dir === 'encrypt' && hasTag && !tagLeft ? tagLen : 0;
      const outLen = tagPrefix + cipherOutLen + tagSuffix;
      const out = getOutput(outLen || 0, output);
      let pos = 0;
      let outPos = 0;
      let maxWritten = 0;
      let lastBytes = 0;
      let processed = false;
      const dataOffset = def.dataOffset || 0;
      let offsetUsed = false;
      const nextOffset = () => {
        if (!offsetUsed && dataOffset) {
          offsetUsed = true;
          return dataOffset;
        }
        return 0;
      };
      try {
        while (pos < msg.length) {
          const remaining = msg.length - pos;
          const off = nextOffset();
          let maxHere = off ? 1 : maxBlocks;
          let capacity = off ? blockLen - off : maxHere * blockLen;
          if (
            !off &&
            padding &&
            dir === 'encrypt' &&
            !disablePadding &&
            maxHere === maxBlocks &&
            maxBlocks > 1 &&
            remaining === capacity
          ) {
            // Leave room for a full padding block when the input fills the buffer exactly.
            maxHere -= 1;
            capacity = maxHere * blockLen;
          }
          const isLast = remaining <= capacity ? 1 : 0;
          const blocks = isLast ? Math.ceil(remaining / blockLen) : maxHere;
          const blockBytes = off ? blockLen - off : blocks * blockLen;
          const take = remaining < blockBytes ? remaining : blockBytes;
          const leftPad = off ? blockLen - off - take : 0;
          const left = off ? blockLen - take : blocks * blockLen - take;
          if (off) BUFFER.fill(0, 0, off);
          if (take) copyFast(BUFFER, off, msg, pos, take);
          if (leftPad) BUFFER.fill(0, off + take, off + take + leftPad);
          let padBlocks = 0;
          if (isLast && padding && dir === 'encrypt' && !disablePadding) {
            if (!m.addPadding) throw new Error('missing padding');
            padBlocks = m.addPadding(take, left, blockLen);
          }
          // Ensure PKCS#7 bytes are encrypted/emitted as full blocks.
          const padApplied = padding && dir === 'encrypt' && !disablePadding;
          const totalBlocks = blocks + padBlocks;
          runBlocks(dir, totalBlocks, isLast, padApplied ? 0 : left, -1);
          const bytes = padApplied
            ? totalBlocks * blockLen
            : padBlocks
              ? totalBlocks * blockLen
              : take;
          if (bytes) {
            copyFast(out, tagPrefix + outPos, BUFFER, off, bytes);
            maxWritten = Math.max(maxWritten, off + totalBlocks * blockLen);
            outPos += bytes;
          }
          if (isLast) lastBytes = bytes;
          pos += take;
          processed = processed || totalBlocks > 0 || isLast === 1;
          if (isLast) break;
        }
        if (!processed) {
          if (padding && dir === 'encrypt' && !disablePadding) {
            // Empty plaintext still emits a full padding block.
            if (!m.addPadding) throw new Error('missing padding');
            const padBlocks = m.addPadding(0, 0, blockLen);
            runBlocks(dir, padBlocks, 1, 0, -1);
            const bytes = padBlocks * blockLen;
            if (bytes) {
              copyFast(out, tagPrefix + outPos, BUFFER, 0, bytes);
              maxWritten = Math.max(maxWritten, bytes);
              outPos += bytes;
            }
          } else {
            runBlocks(dir, 0, 1, 0, -1);
          }
        }
        if (padding && dir === 'decrypt' && !disablePadding) {
          if (!m.verifyPadding) throw new Error('missing padding');
          const pad = m.verifyPadding(lastBytes, blockLen);
          if (pad > blockLen || (!padZeroOk && pad === 0)) throw new Error(padError());
          outPos -= pad;
        }
        if (hasTag) {
          const tag = getTag();
          if (dir === 'encrypt') {
            if (tagLeft) copyFast(out, 0, tag, 0, tagLen);
            else copyFast(out, tagPrefix + cipherOutLen, tag, 0, tagLen);
          } else if (!equalBytes(tag, passedTag as Uint8Array)) {
            throw new Error(def.tagError || 'invalid tag');
          }
        }
        cleanInput();
        return out.subarray(0, tagPrefix + outPos + tagSuffix);
      } finally {
        reset(maxWritten);
      }
    } catch (e) {
      cleanInput();
      reset(0);
      throw e;
    }
  };
  class StreamCipher implements CipherStream {
    private buf: Uint8Array;
    private pos: number;
    private state: Uint8Array;
    private finished: boolean;
    private destroyed: boolean;
    private dir: Dir;
    private key: Uint8Array;
    private args: unknown[];
    private disablePadding: boolean;
    private offsetUsed: boolean;
    constructor(dir: Dir, key: Uint8Array, args: unknown[], from?: StreamCipher) {
      this.dir = dir;
      this.key = key;
      this.args = args;
      this.finished = false;
      this.destroyed = false;
      this.offsetUsed = false;
      this.buf = new Uint8Array(blockLen * maxBlocks);
      this.pos = 0;
      if (!mod) throw new Error('missing module');
      if (from) {
        // clone() can reuse the captured stream state directly; re-running initCipher here only does
        // setup work that clone immediately overwrites.
        this.disablePadding = from.disablePadding;
        this.state = copyBytes(from.state);
        return;
      }
      this.disablePadding = initCipher(dir, key, args);
      this.state = copyBytes(STATE);
      mod.reset(0);
    }
    private _restoreState() {
      copyFast(STATE, 0, this.state, 0, STATE.length);
    }
    private _saveState() {
      copyFast(this.state, 0, STATE, 0, STATE.length);
    }
    saveState(): Uint8Array {
      return copyBytes(this.state);
    }
    restoreState(state: Uint8Array): void {
      if (state.length !== this.state.length) throw new Error('invalid state');
      copyFast(this.state, 0, state, 0, state.length);
    }
    update(data: Uint8Array, output?: Uint8Array): Uint8Array {
      abytes(data);
      if (this.destroyed) throw new Error('Cipher instance has been destroyed');
      if (this.finished) throw new Error('Cipher#finish() has already been called');
      if (padding && this.disablePadding && data.length % blockLen !== 0)
        throw new Error(lengthError(this.dir) || 'invalid data length');
      const holdLast = padding && !this.disablePadding && this.dir === 'decrypt' ? blockLen : 0;
      const bufferPartial = hasTag;
      const prevPos = this.pos;
      const total = data.length + prevPos;
      const dataOffset = def.dataOffset || 0;
      const offPending = bufferPartial && dataOffset && !this.offsetUsed;
      // dataOffset makes the first block shorter; compute output length accordingly.
      const outLen = (() => {
        if (offPending) {
          const cap = blockLen - dataOffset;
          if (total < cap) return 0;
          const rest = total - cap;
          return cap + Math.floor(rest / blockLen) * blockLen;
        }
        const totalRem = total % blockLen;
        return bufferPartial && totalRem ? total - totalRem : total;
      })();
      const out = getOutput(outLen, output);
      let outPos = 0;
      let msgPos = 0;
      let maxWritten = 0;
      const nextOffset = () => {
        if (!this.offsetUsed && dataOffset) {
          this.offsetUsed = true;
          return dataOffset;
        }
        return 0;
      };
      this._restoreState();
      if (!mod) throw new Error('missing module');
      try {
        if (!this.offsetUsed && dataOffset && this.pos > blockLen - dataOffset) {
          // Drain the first dataOffset block from the buffer before appending new data.
          const off = dataOffset;
          const cap = blockLen - off;
          BUFFER.fill(0, 0, off);
          copyFast(BUFFER, off, this.buf, 0, cap);
          runBlocks(this.dir, 1, 0, off, -1);
          copyFast(out, outPos, BUFFER, off, cap);
          maxWritten = Math.max(maxWritten, off + blockLen);
          outPos += cap;
          this.buf.copyWithin(0, cap, this.pos);
          this.pos -= cap;
          this.offsetUsed = true;
        }
        if (holdLast) {
          copyFast(this.buf, this.pos, data, 0, data.length);
          this.pos += data.length;
          while (this.pos >= blockLen * 2) {
            const blocks = Math.min(maxBlocks, Math.floor((this.pos - blockLen) / blockLen));
            const bytes = blocks * blockLen;
            const off = nextOffset();
            if (off) BUFFER.fill(0, 0, off);
            copyFast(BUFFER, off, this.buf, 0, bytes);
            runBlocks(this.dir, blocks, 0, 0, -1);
            copyFast(out, outPos, BUFFER, off, bytes);
            maxWritten = Math.max(maxWritten, off + bytes);
            outPos += bytes;
            this.buf.copyWithin(0, bytes, this.pos);
            this.pos -= bytes;
          }
          this._saveState();
          return out.subarray(0, outPos);
        }
        if (this.pos) {
          // dataOffset reduces first-block capacity; honor it for buffered updates.
          const off = !this.offsetUsed && dataOffset ? dataOffset : 0;
          const cap = off ? blockLen - off : blockLen;
          const need = cap - this.pos;
          const take = Math.min(need, data.length);
          copyFast(this.buf, this.pos, data, 0, take);
          this.pos += take;
          msgPos += take;
          if (this.pos === cap && (!holdLast || data.length - msgPos + cap > holdLast)) {
            if (off) this.offsetUsed = true;
            if (off) BUFFER.fill(0, 0, off);
            copyFast(BUFFER, off, this.buf, 0, cap);
            runBlocks(this.dir, 1, 0, off, -1);
            copyFast(out, outPos, BUFFER, off, cap);
            maxWritten = Math.max(maxWritten, off + blockLen);
            outPos += cap;
            this.pos = 0;
          }
        }
        for (; msgPos + blockLen <= data.length - holdLast; ) {
          const remaining = data.length - msgPos - holdLast;
          const off = nextOffset();
          const maxHere = off ? 1 : maxBlocks;
          const blocks = Math.min(maxHere, Math.floor(remaining / blockLen));
          if (!blocks) break;
          const take = off ? Math.min(remaining, blockLen - off) : blocks * blockLen;
          const left = off ? blockLen - take : 0;
          if (off) BUFFER.fill(0, 0, off);
          copyFast(BUFFER, off, data, msgPos, take);
          runBlocks(this.dir, blocks, 0, left, -1);
          copyFast(out, outPos, BUFFER, off, take);
          maxWritten = Math.max(maxWritten, off + blocks * blockLen);
          outPos += take;
          msgPos += take;
        }
        const leftover = data.length - msgPos;
        if (leftover) {
          // Buffer tail so chunked updates don't advance the block counter early (CTR/stream correctness).
          copyFast(this.buf, this.pos, data, msgPos, leftover);
          this.pos += leftover;
        }
        this._saveState();
      } finally {
        reset(maxWritten);
      }
      return out.subarray(0, outPos);
    }
    finish(tag?: Uint8Array): { data: Uint8Array; tag?: Uint8Array } {
      if (this.destroyed) throw new Error('Cipher instance has been destroyed');
      if (this.finished) throw new Error('Cipher#finish() has already been called');
      this.finished = true;
      if (padding && this.disablePadding && this.pos !== 0)
        throw new Error(lengthError(this.dir) || 'invalid data length');
      this._restoreState();
      if (!mod) throw new Error('missing module');
      const m = mod;
      let maxWritten = 0;
      let data = new Uint8Array(0);
      let tagOut: Uint8Array | undefined = undefined;
      const dataOffset = def.dataOffset || 0;
      let off = 0;
      try {
        if (this.pos && !this.offsetUsed && dataOffset && this.pos > blockLen - dataOffset) {
          // Split the buffered data to match dataOffset streaming semantics.
          this.offsetUsed = true;
          off = dataOffset;
          const firstTake = blockLen - off;
          const rest = this.pos - firstTake;
          const out = new Uint8Array(this.pos);
          if (off) BUFFER.fill(0, 0, off);
          copyFast(BUFFER, off, this.buf, 0, firstTake);
          runBlocks(this.dir, 1, 0, off, -1);
          copyFast(out, 0, BUFFER, off, firstTake);
          maxWritten = Math.max(maxWritten, off + blockLen);
          if (rest) {
            copyFast(BUFFER, 0, this.buf, firstTake, rest);
            if (rest < blockLen) BUFFER.fill(0, rest, rest + (blockLen - rest));
            runBlocks(this.dir, 1, 1, blockLen - rest, -1);
            copyFast(out, firstTake, BUFFER, 0, rest);
            maxWritten = Math.max(maxWritten, blockLen);
          }
          data = out;
        } else {
          let padBlocks = 0;
          let left = 0;
          let blocks = 0;
          if (this.pos) {
            if (!this.offsetUsed && dataOffset) {
              this.offsetUsed = true;
              off = dataOffset;
            }
            if (off) {
              // dataOffset shifts data into block; match single-shot left/zeroing semantics.
              blocks = 1;
              left = blockLen - this.pos;
              BUFFER.fill(0, 0, off);
              copyFast(BUFFER, off, this.buf, 0, this.pos);
              const leftPad = blockLen - off - this.pos;
              if (leftPad) BUFFER.fill(0, off + this.pos, off + this.pos + leftPad);
            } else {
              const used = this.pos;
              blocks = Math.ceil(used / blockLen);
              left = blocks * blockLen - used;
              copyFast(BUFFER, 0, this.buf, 0, this.pos);
              if (left) BUFFER.fill(0, this.pos, this.pos + left);
            }
          }
          if (padding && this.dir === 'encrypt' && !this.disablePadding) {
            if (!m.addPadding) throw new Error('missing padding');
            padBlocks = m.addPadding(this.pos, left, blockLen);
          }
          const padApplied = padding && this.dir === 'encrypt' && !this.disablePadding;
          const totalBlocks = blocks + padBlocks;
          const outLeft = padApplied ? 0 : left;
          runBlocks(this.dir, totalBlocks, 1, outLeft, -1);
          maxWritten = Math.max(maxWritten, off + totalBlocks * blockLen);
          if (padding && this.dir === 'decrypt' && !this.disablePadding) {
            if (!m.verifyPadding) throw new Error('missing padding');
            if (blocks * blockLen === 0) throw new Error(emptyError());
            const pad = m.verifyPadding(blocks * blockLen, blockLen);
            if (pad < 1 || pad > blockLen) throw new Error(padError());
            const outLen = blocks * blockLen - pad;
            // m.reset() clears BUFFER/state; copy out before returning.
            data = copyBytes(BUFFER.subarray(off, off + outLen));
            if (hasTag && this.dir === 'decrypt') {
              const computed = getTag();
              if (!tag) throw new Error(def.tagError || 'invalid tag');
              if (!equalBytes(computed, tag)) throw new Error(def.tagError || 'invalid tag');
            }
            return { data, tag: tagOut };
          }
          // Include padding block(s) in output length for encrypt+padding.
          const outBlocks = padApplied ? totalBlocks : blocks;
          const rawLen = outBlocks * blockLen - outLeft;
          const outLen = rawLen;
          if (!outLen) data = new Uint8Array(0);
          else data = copyBytes(BUFFER.subarray(off, off + outLen));
        }
        if (hasTag) {
          // tagFinish writes length block into BUFFER; copy data before computing tag.
          const computed = getTag();
          if (this.dir === 'encrypt')
            // m.reset() clears state; return a copy.
            tagOut = copyBytes(computed.slice(0, tagLength as number));
          else {
            if (!tag) throw new Error(def.tagError || 'invalid tag');
            if (!equalBytes(computed, tag)) throw new Error(def.tagError || 'invalid tag');
          }
        }
        return { data, tag: tagOut };
      } finally {
        reset(maxWritten);
      }
    }
    destroy(): void {
      this.destroyed = true;
      cleanFast(this.state);
      cleanFast(this.buf);
    }
    _cloneInto(to?: CipherStream): CipherStream {
      if (this.destroyed) throw new Error('Cipher instance has been destroyed');
      const dst = to || new StreamCipher(this.dir, this.key, this.args, this);
      if (!(dst instanceof StreamCipher)) throw new Error('wrong instance');
      if (dst.buf.length !== this.buf.length) throw new Error('wrong buffer length');
      if (this.pos) copyFast(dst.buf, 0, this.buf, 0, this.pos);
      dst.pos = this.pos;
      if (to) {
        if (dst.state.length !== this.state.length) throw new Error('wrong state length');
        copyFast(dst.state, 0, this.state, 0, this.state.length);
        dst.disablePadding = this.disablePadding;
      }
      dst.finished = !!this.finished;
      dst.destroyed = !!this.destroyed;
      return dst;
    }
    clone(): CipherStream {
      return this._cloneInto();
    }
  }
  const cipherFactory = (key: Uint8Array, ...args: unknown[]) => {
    lazyInit();
    abytes(key);
    if (def.nonceLength !== undefined) {
      const nonce = args[0] as Uint8Array;
      abytes(nonce, def.varSizeNonce ? undefined : def.nonceLength, 'nonce');
    }
    if (def.tagLength && args[1] !== undefined) abytes(args[1] as Uint8Array, undefined, 'AAD');
    if (def.validate) def.validate(key, ...args);
    let used = false;
    const make = (dir: Dir) => {
      const fn = (data: Uint8Array, output?: Uint8Array) => {
        abytes(data);
        if (output !== undefined && def.noOutput) throw new Error('cipher output not supported');
        if (dir === 'encrypt') {
          if (used) throw new Error('cannot encrypt() twice with same key + nonce');
          used = true;
        }
        return process(dir, data, output, key, args);
      };
      let run:
        | ReturnType<
            typeof mkAsync<
              [Uint8Array, Uint8Array | undefined, AsyncRunOpts | undefined],
              Uint8Array
            >
          >
        | undefined;
      Object.assign(fn, {
        async: (data: Uint8Array, output?: Uint8Array, opts?: AsyncRunOpts) =>
          (
            run ||
            (run = mkAsync(function* (
              setup,
              data: Uint8Array,
              output?: Uint8Array,
              opts?: AsyncRunOpts
            ) {
              const setupMode = setup as AsyncSetup & { isAsync?: boolean };
              if (!setupMode.isAsync && !opts?.onProgress) return fn(data, output);
              const tick = !setupMode.isAsync
                ? !opts?.onProgress
                  ? (setupMode({ total: 0 }), (_inc?: number) => false)
                  : setupMode({ total: data.length, onProgress: opts.onProgress })
                : setupMode({
                    total: data.length,
                    asyncTick: opts?.asyncTick,
                    onProgress: opts?.onProgress,
                    nextTick: opts?.nextTick,
                    stateBytes: STATE.length,
                    save: (state) => state.set(STATE),
                    restore: (state) => STATE.set(state),
                  });
              const out = fn(data, output);
              if ((setupMode.isAsync || !!opts?.onProgress) && tick(data.length)) yield;
              return out;
            }))
          ).async(data, output, opts),
        create: () => {
          if (noStream) throw new Error('streaming is not supported');
          return new StreamCipher(dir, key, args);
        },
      });
      return fn;
    };
    return { encrypt: make('encrypt'), decrypt: make('decrypt') } as Cipher;
  };
  Object.assign(cipherFactory, {
    blockSize: def.blockLen,
    blockLen: def.blockLen,
    nonceLength: def.nonceLength,
    tagLength: def.tagLength,
    varSizeNonce: def.varSizeNonce,
    getPlatform: () => platform,
    getDefinition: () => def,
  });
  brandSet.add(cipherFactory);
  return Object.freeze(cipherFactory);
};

type AsyncCipherImpl = {
  encrypt: (data: Uint8Array) => Promise<Uint8Array>;
  decrypt: (data: Uint8Array) => Promise<Uint8Array>;
};

const cipherSyncError = () => {
  throw new Error('sync is not supported');
};

const copyCipherOutput = (res: Uint8Array, out?: Uint8Array) => {
  if (!out) return res;
  if (out.length < res.length) throw new Error('output is too small');
  out.set(res.subarray(0, res.length), 0);
  clean(res);
  return out;
};

export const mkCipherAsync = <Mod extends CipherMod>(
  def: CipherDef<Mod>,
  init: (key: Uint8Array, ...args: unknown[]) => AsyncCipherImpl,
  platform = 'webcrypto',
  isSupported?: () => boolean | Promise<boolean>
) => {
  const factory = ((key: Uint8Array, ...args: unknown[]) => {
    abytes(key, undefined, 'key');
    if (def.validate) def.validate(key, ...args);
    const impl = init(key, ...args);
    const mk = (run: (data: Uint8Array) => Promise<Uint8Array>) => {
      const fn = ((_: Uint8Array, _out?: Uint8Array) =>
        cipherSyncError()) as unknown as Cipher['encrypt'] & {
        async: (data: Uint8Array, out?: Uint8Array, opts?: AsyncRunOpts) => Promise<Uint8Array>;
        create: () => never;
      };
      fn.async = async (data: Uint8Array, out?: Uint8Array, _opts?: AsyncRunOpts) => {
        abytes(data, undefined, 'data');
        const res = await run(data);
        return copyCipherOutput(res, out);
      };
      fn.create = () => {
        throw new Error('streaming is not supported');
      };
      return fn;
    };
    return { encrypt: mk(impl.encrypt), decrypt: mk(impl.decrypt) } as Cipher;
  }) as CipherFactory;
  Object.assign(factory, {
    blockSize: def.blockLen,
    blockLen: def.blockLen,
    nonceLength: def.nonceLength,
    tagLength: def.tagLength,
    varSizeNonce: def.varSizeNonce,
    getPlatform: () => platform,
    getDefinition: () => def,
  });
  if (isSupported) (factory as any).isSupported = isSupported;
  brandSet.add(factory as object);
  return Object.freeze(factory);
};

export function mkCipherStub<Mod extends CipherMod>(
  def: CipherDef<Mod>
): CipherFactory & CipherStub {
  let inner: CipherFactory | undefined;
  const checkInner = () => {
    if (inner === undefined) throw new Error('implementation not installed');
  };
  const stub = ((key: Uint8Array, ...args: unknown[]) => {
    checkInner();
    const impl = inner as CipherFactory;
    return impl(key, ...args);
  }) as CipherFactory & CipherStub;
  Object.assign(stub, {
    getPlatform: () => {
      checkInner();
      const impl = inner as CipherFactory;
      return impl.getPlatform();
    },
    getDefinition: () => {
      checkInner();
      const impl = inner as CipherFactory;
      return impl.getDefinition();
    },
    install: (impl: CipherFactory) => {
      if (!isBranded(impl)) throw new Error('install: non-branded implementation');
      if (impl.getDefinition() !== def) throw new Error('wrong implementation definition');
      inner = impl;
    },
    blockSize: def.blockLen,
    blockLen: def.blockLen,
    nonceLength: def.nonceLength,
    tagLength: def.tagLength,
    varSizeNonce: def.varSizeNonce,
  });
  return Object.freeze(stub);
}
