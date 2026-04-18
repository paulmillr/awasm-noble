/**
 * Generic KDF methods. Common logic for all targets.
 * Doesn't contain WASM-specific/JS-specific code.
 * @module
 */
import type { HashInstance } from './hashes-abstract.ts';
import { hmac } from './hmac.ts';
import type { ARGON2, SCRYPT } from './targets/types.ts';
import {
  abytes,
  anumber,
  checkOpts,
  clean,
  copyFast32,
  createView,
  mkAsync,
  u32,
  u8,
  utf8ToBytes,
  type AsyncOpts,
  type AsyncSetup,
  type KDFInput,
  type TArg,
  type TRet,
} from './utils.ts';

// Generic KDF stuff
type KDFOpts = {
  dkLen?: number; // key length
  asyncTick?: number; // block execution max time
  maxmem?: number;
  onProgress?: (progress: number) => void;
  nextTick?: () => Promise<void>;
};
/** Generic installed KDF surface with sync/async entrypoints and backend metadata. */
export type KDF<Opts extends KDFOpts> = ((
  password: TArg<KDFInput>,
  salt: TArg<KDFInput>,
  opts: TArg<Opts>
) => TRet<Uint8Array>) & {
  async: (
    password: TArg<KDFInput>,
    salt: TArg<KDFInput>,
    opts: TArg<Opts>
  ) => Promise<TRet<Uint8Array>>;
  getPlatform: () => string | undefined;
  getDefinition: () => TRet<any>;
};

/**
 * Helper for KDFs: consumes uint8array or string.
 * When string is passed, encodes it as UTF-8 bytes; Uint8Array inputs
 * are only type-checked and returned without cloning.
 */
function kdfInputToBytes(data: TArg<KDFInput>, errorTitle = ''): TRet<Uint8Array> {
  if (typeof data === 'string') return utf8ToBytes(data);
  return abytes(data, undefined, errorTitle);
}

const BRAND = /* @__PURE__ */ Symbol('kdf_impl_brand');
const brandSet = /* @__PURE__ */ new WeakSet<object>();
function isBranded(x: unknown): x is object {
  return typeof x === 'function' || (typeof x === 'object' && x !== null)
    ? brandSet.has(x as object)
    : false;
}

function mkKDF<O extends KDFOpts>(
  defOpts: Partial<O> & { dkLen: number; maxmem: number },
  cb_: TArg<
    (
      setup: AsyncSetup,
      password: Uint8Array,
      salt: Uint8Array,
      opts: O & { dkLen: number; maxmem: number }
    ) => Generator<unknown, TRet<Uint8Array>, unknown>
  >,
  definition?: any,
  platform?: string
) {
  const cb = cb_ as (
    setup: AsyncSetup,
    password: Uint8Array,
    salt: Uint8Array,
    opts: O & { dkLen: number; maxmem: number }
  ) => Generator<unknown, TRet<Uint8Array>, unknown>;
  const res = mkAsync(
    (setup: TArg<AsyncSetup>, password: TArg<KDFInput>, salt: TArg<KDFInput>, opts: TArg<O>) => {
      password = kdfInputToBytes(password, 'password');
      salt = kdfInputToBytes(salt, 'salt');
      abytes(password);
      abytes(salt);
      const _opts = checkOpts({ ...defOpts }, opts);
      const { dkLen, asyncTick, maxmem, onProgress, nextTick } = _opts;
      anumber(dkLen, 'dkLen');
      anumber(maxmem, 'maxmem');
      const _setup = (opts: TArg<AsyncOpts>) =>
        setup({ asyncTick, onProgress, nextTick, ...(opts as AsyncOpts) });
      return cb(_setup, password, salt, _opts as O & { dkLen: number; maxmem: number });
    }
  );
  Object.assign(res, {
    getPlatform: () => platform,
    getDefinition: () => definition,
  });
  Object.defineProperty(res, BRAND, { value: true, enumerable: false });
  brandSet.add(res);
  return Object.freeze(res) as KDF<O>;
}

type Stub<Opts extends KDFOpts> = { install: (impl: KDF<Opts>) => void };
/**
 * Create an installable KDF stub for targets that attach the real implementation later.
 * @param _def_ - definition factory that installed implementations must report via
 *   `getDefinition()`.
 * @returns Frozen stub KDF that forwards to the installed implementation once available.
 */
export function mkKDFStub<Opts extends KDFOpts>(
  _def_: TArg<(mod: any, deps: any, platform: string) => KDF<Opts>>
): TRet<KDF<Opts> & Stub<Opts>> {
  const _def = _def_ as (mod: any, deps: any, platform: string) => KDF<Opts>;
  let inner: KDF<Opts> | undefined;
  function checkInner(inner: TArg<KDF<Opts> | undefined>): asserts inner is KDF<Opts> {
    if (inner === undefined) throw new Error('implementation not installed');
  }
  const kdf = ((password: TArg<KDFInput>, salt: TArg<KDFInput>, opts = {} as Opts) => {
    checkInner(inner);
    return inner(password, salt, opts);
  }) as KDF<Opts> & Stub<Opts>;
  Object.assign(kdf, {
    async: async (password: TArg<KDFInput>, salt: TArg<KDFInput>, opts = {} as Opts) => {
      checkInner(inner);
      return inner.async(password, salt, opts);
    },
    getPlatform: () => {
      checkInner(inner);
      return inner.getPlatform();
    },
    getDefinition: () => {
      checkInner(inner);
      return inner.getDefinition();
    },
    install: (impl: TArg<KDF<Opts>>) => {
      if (!isBranded(impl)) throw new Error('install: non-branded implementation');
      // NOTE: this strict check works because all implementations use the same
      // exported KDF factory function, so a same-shaped different KDF family
      // cannot be installed here.
      if (impl.getDefinition() !== _def) throw new Error('wrong implementation definition');
      inner = impl as KDF<Opts>;
    },
  });
  return Object.freeze(kdf) as TRet<KDF<Opts> & Stub<Opts>>;
}

/**
 * Argon2
 * --------------------------------------------------------
 */
const AT = { Argon2d: 0, Argon2i: 1, Argon2id: 2 } as const;
type Types = (typeof AT)[keyof typeof AT];

// RFC 9106 Figure 1 preserves LE32(length(K/X)) even when the optional
// payload is absent, so undefined maps to an empty byte string here.
const abytesOrZero = (buf?: TArg<KDFInput>) => {
  if (buf === undefined) return Uint8Array.of();
  return kdfInputToBytes(buf);
};

/**
 * Argon2 options.
 * * t: time cost, m: mem cost in kb, p: parallelization.
 * * key: optional key. personalization: arbitrary extra data.
 * * dkLen: desired number of output bytes.
 */
export type ArgonOpts = KDFOpts & {
  t: number; // Time cost, iterations count
  m: number; // Memory cost (in KB)
  p: number; // Parallelization parameter
  version?: number; // Default: 0x13 (19)
  key?: KDFInput; // Optional key
  personalization?: KDFInput; // Optional arbitrary extra data
};

// Exclusive `2^32` sentinel used by `isU32(...)`, not the inclusive maximum u32 value.
const maxUint32 = /* @__PURE__ */ Math.pow(2, 32);
// Validate safe JS integers in `[0, 2^32 - 1]`.
function isU32(num: number) {
  return Number.isSafeInteger(num) && num >= 0 && num < maxUint32;
}

function argon2Opts(opts: TArg<ArgonOpts>) {
  const merged: any = {
    version: 0x13,
    dkLen: 32,
    maxmem: maxUint32 - 1,
    asyncTick: 10,
  };
  for (let [k, v] of Object.entries(opts)) if (v !== undefined) merged[k] = v;

  const { dkLen, p, m, t, version, onProgress } = merged;
  // RFC 9106 §3.1: tag length `T` MUST be an integer number of bytes from 4 to 2^32-1.
  if (!isU32(dkLen) || dkLen < 4) throw new Error('dkLen should be at least 4 bytes');
  if (!isU32(p) || p < 1 || p >= Math.pow(2, 24)) throw new Error('p should be 1 <= p < 2^24');
  if (!isU32(m)) throw new Error('m should be 0 <= m < 2^32');
  if (!isU32(t) || t < 1) throw new Error('t (iterations) should be 1 <= t < 2^32');
  if (onProgress !== undefined && typeof onProgress !== 'function')
    throw new Error('progressCb should be function');
  /*
  Memory size m MUST be an integer number of kibibytes from 8*p to 2^(32)-1.
  The actual number of blocks is m', which is m rounded down to the nearest
  multiple of 4*p.
  */
  if (!isU32(m) || m < 8 * p) throw new Error('memory should be at least 8*p bytes');
  // Accept legacy `0x10` for compatibility even though RFC 9106 profiles standardize `0x13`.
  if (version !== 0x10 && version !== 0x13) throw new Error('unknown version=' + version);
  return merged;
}

/**
 * Local Argon2 backend block cap used to bound the resident working matrix per batch.
 * Kept as a pure exported constant so unrelated bundles can tree-shake it away.
 */
export const ARGON_MAX_BLOCKS = /* @__PURE__ */ (() => 10 * 1024)();
/** RFC 9106 sync-points constant `SL = 4`, fixed by the Argon2 design. */
export const ARGON2_SYNC_POINTS = 4;

function mkArgon2(
  type: Types,
  modFn: TArg<() => ARGON2>,
  deps: TArg<{ blake2b: HashInstance<any> }>,
  platform: string,
  definition?: any
) {
  const { blake2b } = deps;
  let mod: ARGON2;
  // Instantiate the backend lazily once so importing Argon2 surfaces does not build it eagerly.
  const initMod = () => {
    if (mod === undefined) mod = modFn();
  };
  function Hp(A: TArg<Uint32Array>, dkLen: number) {
    const A8 = u8(A);
    const T = new Uint32Array(1);
    const T8 = u8(T);
    // RFC 9106 Figure 8 prefixes `T` as `LE32(T)`, so this direct word view relies on the
    // surrounding Uint32Array byte order already being little-endian.
    T[0] = dkLen;
    // Fast path
    if (dkLen <= 64) return blake2b.chunks([T8, A8], { dkLen });
    const out = new Uint8Array(dkLen);
    let V = blake2b.chunks([T8, A8]);
    let pos = 0;
    // First block
    out.set(V.subarray(0, 32));
    pos += 32;
    // Rest blocks
    for (; dkLen - pos > 64; pos += 32) {
      blake2b(V, { out: V });
      out.set(V.subarray(0, 32), pos);
    }
    // Last block
    out.set(blake2b(V, { dkLen: dkLen - pos }), pos);
    clean(V, T);
    // H' is byte-oriented; returning `u32(out)` would silently drop dkLen % 4 tail bytes.
    return out;
  }
  return mkKDF<ArgonOpts>(
    // Local safety cap: default `maxmem` stays near 1 GiB so callers must opt in before allocating
    // larger Argon2 matrices.
    { dkLen: 32, maxmem: 1024 ** 3 + 1024 },
    function* (
      setup: TArg<AsyncSetup>,
      password: TArg<Uint8Array>,
      salt: TArg<Uint8Array>,
      opts: TArg<ArgonOpts & { dkLen: number; maxmem: number }>
    ) {
      initMod();
      const INDICES = u32(mod.segments.indices);
      const REF_INDICES = u32(mod.segments.refIndices);
      const REF_BLOCKS = u32(mod.segments.refBlocks);
      const INPUT_BLOCKS = u32(mod.segments.inputBlocks);

      // ... (Opts, H0, B allocation - Same as previous stable version) ...
      if (!isU32(password.length)) throw new Error('password should be less than 4 GB');
      if (!isU32(salt.length) || salt.length < 8)
        throw new Error('salt should be at least 8 bytes and less than 4 GB');
      if (!Object.values(AT).includes(type)) throw new Error('invalid type');
      let { p, dkLen, m, t, version, key, personalization, maxmem } = argon2Opts(opts);

      key = abytesOrZero(key);
      personalization = abytesOrZero(personalization);

      const h = blake2b.create({});
      const BUF = new Uint32Array(1);
      const BUF8 = u8(BUF);
      for (let item of [p, dkLen, m, t, version, type]) {
        BUF[0] = item;
        h.update(BUF8);
      }
      for (let i of [password, salt, key, personalization]) {
        BUF[0] = i.length;
        h.update(BUF8).update(i);
      }
      const H0 = new Uint32Array(18);
      const H0_8 = u8(H0);
      h.digestInto(H0_8);

      const lanes = p;
      const mP = 4 * p * Math.floor(m / (ARGON2_SYNC_POINTS * p));
      const laneLen = Math.floor(mP / p);
      const segmentLen = Math.floor(laneLen / ARGON2_SYNC_POINTS);
      const perBlock = 256;
      // `maxmem` is documented in bytes; compare against the actual 1024-byte block allocation.
      const memUsed = mP * 1024;
      if (!isU32(maxmem)) throw new Error('"maxmem" expected <2**32, got ' + maxmem);
      if (memUsed > maxmem)
        throw new Error(
          '"maxmem" limit was hit: memUsed(mP*1024)=' + memUsed + ', maxmem=' + maxmem
        );
      const B = new Uint32Array(memUsed / 4);
      for (let l = 0; l < p; l++) {
        const i = perBlock * laneLen * l;
        H0[17] = l;
        H0[16] = 0;
        B.set(u32(Hp(H0, 1024)), i);
        H0[16] = 1;
        B.set(u32(Hp(H0, 1024)), i + perBlock);
      }
      clean(BUF, H0);

      const MIN_BLOCKS = 8; // actually 5, but just in case
      const MAX_PARALLEL = Math.min(p, Math.floor(ARGON_MAX_BLOCKS / MIN_BLOCKS), 8);
      const inputBlocksChunks = [];
      const MAX_BLOCKS = Math.floor(ARGON_MAX_BLOCKS / MAX_PARALLEL);
      // console.log('MAX_BLOCKS', { MAX_BLOCKS, MAX_PARALLEL });
      const stride = MAX_BLOCKS * 256;
      const usedInputSize = MAX_PARALLEL * stride;
      const currentState = INPUT_BLOCKS.subarray(0, usedInputSize);
      let savedInput32: Uint32Array | undefined;
      const progress = setup({
        total: t * ARGON2_SYNC_POINTS * p * segmentLen - 2 * p,
        stateBytes: currentState.byteLength,
        save: (state: TArg<Uint8Array>) => {
          if (!savedInput32) savedInput32 = u32(state);
          savedInput32.set(currentState);
          // We can probably skip this, but this is neccessary to verify save/restore
          // NOTE: this impacts perf, but otherwise somebody can read sensitive data between pauses.
          INDICES.fill(0);
          REF_INDICES.fill(0);
          REF_BLOCKS.fill(0);
          INPUT_BLOCKS.fill(0);
        },
        restore: (state: TArg<Uint8Array>) => {
          if (!savedInput32) savedInput32 = u32(state);
          currentState.set(savedInput32);
        },
      });

      for (let i = 0; i < MAX_PARALLEL; i++) {
        const stride = MAX_BLOCKS * 256;
        inputBlocksChunks.push(INPUT_BLOCKS.subarray(i * stride, (i + 1) * stride));
      }

      const address_chunks = inputBlocksChunks.map((i: TArg<Uint32Array>) => i.subarray(0, 256));

      for (let chunk = 0; chunk < MAX_PARALLEL; chunk++) {
        address_chunks[chunk][6] = mP;
        address_chunks[chunk][8] = t;
        address_chunks[chunk][10] = type;
      }

      for (let r = 0; r < t; r++) {
        const needXor = r !== 0 && version === 0x13;
        for (let chunk = 0; chunk < MAX_PARALLEL; chunk++) address_chunks[chunk][0] = r;

        for (let s = 0; s < ARGON2_SYNC_POINTS; s++) {
          for (let chunk = 0; chunk < MAX_PARALLEL; chunk++) address_chunks[chunk][4] = s;
          const dataIndependent = type == AT.Argon2i || (type == AT.Argon2id && r === 0 && s < 2);
          const startPos = r === 0 && s === 0 ? 2 : 0;

          for (let l = 0; l < p; l += MAX_PARALLEL) {
            const LANES_LEFT = Math.min(p - l, MAX_PARALLEL);

            for (let chunk = 0; chunk < LANES_LEFT; chunk++) {
              const lane = l + chunk;
              address_chunks[chunk][2] = lane;
              address_chunks[chunk][12] = 0;
            }

            // Init Copy: Load initial 'prev' block
            for (let chunk = 0; chunk < LANES_LEFT; chunk++) {
              const lane = l + chunk;
              const offset = lane * laneLen + s * segmentLen + startPos;
              const prev = offset % laneLen === 0 ? offset + laneLen - 1 : offset - 1;
              inputBlocksChunks[chunk].set(
                B.subarray(perBlock * prev, perBlock * (prev + 1)),
                perBlock * 3
              );
            }
            // TODO: Very fragile part here, should be MAX_BLOCKS, but breaks in that case
            const MAX_BUFFER_SIZE = 1024;
            let cursor = 3;
            let flushStartRel = startPos;
            for (let batchStart = startPos; batchStart < segmentLen; ) {
              let wasmStart = cursor + 1;
              let slots = MAX_BUFFER_SIZE - wasmStart;
              const minNeeded = dataIndependent ? 1 : 1;

              if (slots < minNeeded) {
                // Buffer Full: Batch Flush
                const flushLen = (cursor + 1 - 4) * perBlock;
                if (flushLen > 0) {
                  for (let chunk = 0; chunk < LANES_LEFT; chunk++) {
                    const segOffset = (l + chunk) * laneLen + s * segmentLen;
                    B.set(
                      inputBlocksChunks[chunk].subarray(4 * perBlock, (cursor + 1) * perBlock),
                      (segOffset + flushStartRel) * perBlock
                    );
                  }
                }
                // Reset Window
                for (let chunk = 0; chunk < LANES_LEFT; chunk++) {
                  inputBlocksChunks[chunk].copyWithin(
                    3 * perBlock,
                    cursor * perBlock,
                    (cursor + 1) * perBlock
                  );
                }
                cursor = 3;
                wasmStart = 4;
                flushStartRel = batchStart;
                slots = MAX_BUFFER_SIZE - 4;
              }

              const remaining = segmentLen - batchStart;
              const batchSize = Math.min(remaining, dataIndependent ? slots : 1);
              const batchLen = batchSize * perBlock;

              // A. Batch Load XOR Data
              if (needXor) {
                for (let chunk = 0; chunk < LANES_LEFT; chunk++) {
                  const offset = (l + chunk) * laneLen + s * segmentLen + batchStart;
                  inputBlocksChunks[chunk].set(
                    B.subarray(offset * perBlock, offset * perBlock + batchLen),
                    wasmStart * perBlock
                  );
                }
              }
              // B. Generate Addresses
              // Pass flushStartRel to WASM
              mod.getAddresses(
                0,
                LANES_LEFT,
                batchSize,
                laneLen,
                segmentLen,
                batchStart,
                lanes,
                cursor,
                flushStartRel,
                MAX_PARALLEL
              );
              // C. Cache Miss Loading
              // Optimized: WASM handles dirty buffer, JS only does true misses
              for (let chunk = 0; chunk < LANES_LEFT; chunk++) {
                for (let k = 0; k < batchSize; k++) {
                  const currentPos = wasmStart + k;
                  if (REF_INDICES[currentPos * MAX_PARALLEL + chunk] !== currentPos) continue;
                  const val = INDICES[MAX_PARALLEL * k + chunk];
                  REF_BLOCKS.set(
                    B.subarray(perBlock * val, perBlock * (val + 1)),
                    (currentPos * MAX_PARALLEL + chunk) * perBlock
                  );
                }
              }
              // D. Run WASM Kernel
              mod.compress(0, LANES_LEFT, batchSize, cursor, needXor ? 1 : 0, MAX_PARALLEL);
              if (progress(LANES_LEFT * batchSize)) yield;
              batchStart += batchSize;
              cursor += batchSize;
            }
            // Final Flush
            const finalFlushLen = (cursor + 1 - 4) * perBlock;
            if (finalFlushLen > 0) {
              for (let chunk = 0; chunk < LANES_LEFT; chunk++) {
                const segOffset = (l + chunk) * laneLen + s * segmentLen;
                B.set(
                  inputBlocksChunks[chunk].subarray(4 * perBlock, (cursor + 1) * perBlock),
                  (segOffset + flushStartRel) * perBlock
                );
              }
            }
          }
        }
      }
      const B_final = new Uint32Array(perBlock);
      for (let l = 0; l < p; l++)
        for (let j = 0; j < perBlock; j++)
          B_final[j] ^= B[perBlock * (laneLen * l + laneLen - 1) + j];
      const res = Hp(B_final, dkLen);
      clean(...address_chunks, B_final, B, INDICES, REF_INDICES, REF_BLOCKS, INPUT_BLOCKS);
      return res;
    },
    definition,
    platform
  ) satisfies KDF<ArgonOpts>;
}
/** argon2d GPU-resistant version. */
/**
 * Build the argon2d KDF for a concrete backend.
 * @param modFn - backend module factory.
 * @param deps - required hash dependencies.
 * @param platform - backend platform label.
 * @param definition - definition object exposed through `getDefinition()`.
 * @returns Installed argon2d KDF surface.
 */
export const mkArgon2d = /* @__PURE__ */ mkArgon2.bind(null, /* @__PURE__ */ (() => AT.Argon2d)());
/** argon2i side-channel-resistant version. */
/**
 * Build the argon2i KDF for a concrete backend.
 * @param modFn - backend module factory.
 * @param deps - required hash dependencies.
 * @param platform - backend platform label.
 * @param definition - definition object exposed through `getDefinition()`.
 * @returns Installed argon2i KDF surface.
 */
export const mkArgon2i = /* @__PURE__ */ mkArgon2.bind(null, /* @__PURE__ */ (() => AT.Argon2i)());
/** argon2id combining i+d, the most popular version from RFC 9106 */
/**
 * Build the argon2id KDF for a concrete backend.
 * @param modFn - backend module factory.
 * @param deps - required hash dependencies.
 * @param platform - backend platform label.
 * @param definition - definition object exposed through `getDefinition()`.
 * @returns Installed argon2id KDF surface.
 */
export const mkArgon2id = /* @__PURE__ */ mkArgon2.bind(
  null,
  /* @__PURE__ */ (() => AT.Argon2id)()
);

// PBKDF2 copied from noble-hashes
// TODO: real target-specific implementation

/**
 * PBKDF2 options:
 * * c: iterations, should probably be higher than 100_000
 * * dkLen: desired length of derived key in bytes
 * * asyncTick: max time in ms for which async function can block execution
 */
export type Pbkdf2Opts = KDFOpts & { c: number };

/**
 * Build a PBKDF2-HMAC KDF around the provided hash function.
 * @param hash - hash function used as the PBKDF2 PRF.
 * @returns Installed PBKDF2 surface with sync and async entrypoints.
 */
export function pbkdf2(hash: TArg<HashInstance<any>>) {
  return mkKDF<Pbkdf2Opts>(
    { dkLen: 32, maxmem: 1024 },
    function* (
      setup: TArg<AsyncSetup>,
      password: TArg<Uint8Array>,
      salt: TArg<Uint8Array>,
      _opts: TArg<Pbkdf2Opts & { dkLen: number; maxmem: number }>
    ) {
      const opts = checkOpts({ dkLen: 32, asyncTick: 10 }, _opts);
      const { c, dkLen } = opts;
      anumber(c, 'c');
      if (c < 1) throw new Error('iterations (c) must be >= 1');
      // RFC 8018 §5.2 defines dkLen as a positive integer.
      if (dkLen < 1) throw new Error('"dkLen" must be >= 1');
      // RFC 8018 §5.2 step 1 requires rejecting oversize dkLen before allocating the destination
      // buffer or constructing any PRF state, otherwise absurd requests fail with host allocation
      // errors instead of the PBKDF2 contract error.
      if (dkLen > (2 ** 32 - 1) * hash.outputLen) throw new Error('derived key too long');
      const blocks = Math.ceil(dkLen / hash.outputLen);
      const progress = setup({ total: (c - 1) * blocks });
      // DK = PBKDF2(PRF, Password, Salt, c, dkLen);
      const DK = new Uint8Array(dkLen);
      // U1 = PRF(Password, Salt + INT_32_BE(i))
      const PRF = hmac.create(hash as any, password);
      const PRFSalt = PRF._cloneInto().update(salt);
      let prfW: any; // Working copy
      const arr = new Uint8Array(4);
      const view = createView(arr);
      const u = new Uint8Array(hash.outputLen);
      // DK = T1 + T2 + ⋯ + Tdklen/hlen
      for (let ti = 1, pos = 0; pos < dkLen; ti++, pos += hash.outputLen) {
        // Ti = F(Password, Salt, c, i)
        // The last Ti view can be shorter than hLen, which applies
        // RFC 8018 §5.2 step 4's T_l<0..r-1> truncation without extra copies.
        const Ti = DK.subarray(pos, pos + hash.outputLen);
        view.setInt32(0, ti, false);
        // F(Password, Salt, c, i) = U1 ^ U2 ^ ⋯ ^ Uc
        // U1 = PRF(Password, Salt + INT_32_BE(i))
        (prfW = PRFSalt._cloneInto(prfW)).update(arr).digestInto(u);
        Ti.set(u.subarray(0, Ti.length));
        for (let ui = 1; ui < c; ui++) {
          // Uc = PRF(Password, Uc−1)
          PRF._cloneInto(prfW).update(u).digestInto(u);
          for (let i = 0; i < Ti.length; i++) Ti[i] ^= u[i];
          if (progress()) yield;
        }
      }
      PRF.destroy();
      PRFSalt.destroy();
      if (prfW) prfW.destroy();
      clean(u);
      return DK;
    }
  ) satisfies KDF<Pbkdf2Opts>;
}

// Scrypt

/**
 * Internal scrypt lane batch cap in 64-byte chunks.
 * Controls resident workspace size without changing RFC-visible output.
 */
export const SCRYPT_BATCH = /* @__PURE__ */ (() => 10 * 1024)(); // ~2mb

/** Scrypt options: cost factor `N`, block size `r`, and parallelization `p`. */
export type ScryptOpts = KDFOpts & {
  N: number; // cost factor
  r: number; // block size
  p: number; // parallelization
};

/**
 * Build the scrypt KDF for a concrete backend.
 * @param modFn - backend module factory.
 * @param deps - required hash dependencies.
 * @param platform - backend platform label.
 * @param definition - definition object exposed through `getDefinition()`.
 * @returns Installed scrypt KDF surface.
 */
export function mkScrypt(
  modFn: TArg<() => SCRYPT>,
  deps: TArg<{ sha256: HashInstance<any> }>,
  platform: string,
  definition?: any
) {
  const { sha256 } = deps;
  let mod: SCRYPT;
  // Instantiate the backend lazily once so importing scrypt surfaces does not build it eagerly.
  const initMod = () => {
    if (mod === undefined) mod = modFn();
  };
  const _pbkdf2 = pbkdf2(sha256);
  return mkKDF<ScryptOpts>(
    // Maxmem - 1GB+1KB by default
    { dkLen: 32, maxmem: 1024 ** 3 + 1024 },
    function* (
      setup: TArg<AsyncSetup>,
      password: TArg<Uint8Array>,
      salt: TArg<Uint8Array>,
      opts: TArg<ScryptOpts & { dkLen: number; maxmem: number }>
    ) {
      initMod();
      const _opts = checkOpts({}, opts);
      const { N, r, p, dkLen, maxmem } = _opts;
      anumber(N);
      anumber(r);
      anumber(p);
      const blockSize = 128 * r;
      const blockSize32 = blockSize / 4;
      // Max N is 2^32 because Integrify is 32-bit.
      // Real limit is 2^22 because JS engines capped Uint8Array near 4 GB in 2024.
      // Spec check `N >= 2^(blockSize / 8)` is not done for compat with popular libs,
      // which used incorrect r: 1, p: 8. Also, the check seems to be a spec error:
      // https://www.rfc-editor.org/errata_search.php?rfc=7914
      const pow32 = Math.pow(2, 32);
      if (N <= 1 || (N & (N - 1)) !== 0 || N > pow32) {
        throw new Error('Scrypt: N must be larger than 1, a power of 2, and less than 2^32');
      }
      if (p < 1 || p > ((pow32 - 1) * 32) / blockSize) {
        throw new Error('"p" expected integer 1..((2^32 - 1) * 32) / (128 * r)');
      }
      // RFC 7914 §2 defines dkLen as a positive integer.
      if (dkLen < 1 || dkLen > (pow32 - 1) * 32) {
        throw new Error(
          'Scrypt: dkLen should be positive integer less than or equal to (2^32 - 1) * 32'
        );
      }
      const maxP = Math.min(p, Math.floor(SCRYPT_BATCH / (2 * r)));
      if (maxP < 1) throw new Error('Scrypt: r is too large');
      // Resident memory tracks only the current lane window; larger `p` values are processed
      // across later windows and copied back into the global `B` buffer before the final PBKDF2.
      const memUsed = blockSize * (N * maxP);
      if (memUsed > maxmem) {
        throw new Error(
          'Scrypt: "maxmem" limit was hit: memUsed(128*r*N*maxP)=' + memUsed + ', maxmem=' + maxmem
        );
      }
      // [B0...Bp−1] ← PBKDF2HMAC-SHA256(Passphrase, Salt, 1, blockSize*ParallelizationFactor)
      // Since it has only one iteration there is no reason to use async variant
      const B = _pbkdf2(password, salt, { c: 1, dkLen: blockSize * p });
      const B32 = u32(B);

      // Dimensions: P, r, 2*64
      const V = u32(new Uint8Array(blockSize * N * maxP));
      const output = u32(mod.segments.output);
      const x32 = u32(mod.segments.xorInput);
      const curState = output.subarray(0, maxP * blockSize32);
      let savedState32: Uint32Array | undefined;
      const progress = setup({
        total: 2 * N * p,
        stateBytes: curState.byteLength,
        save: (state: TArg<Uint8Array>) => {
          if (!savedState32) savedState32 = u32(state);
          savedState32.set(curState);
          mod.segments.output.fill(0);
          mod.segments.xorInput.fill(0);
        },
        restore: (state: TArg<Uint8Array>) => {
          if (!savedState32) savedState32 = u32(state);
          curState.set(savedState32);
        },
      });
      for (let pIdx = 0; pIdx < p; pIdx += maxP) {
        const takeP = Math.min(maxP, p - pIdx);
        const parBlockSize = blockSize32 * takeP;
        const MAX_BATCH = Math.floor((2 * SCRYPT_BATCH) / (2 * r * takeP)) - 1;
        if (!MAX_BATCH) throw new Error('scrypt empty batch');
        const i32 = output.subarray(0, parBlockSize);
        const o32 = output.subarray(parBlockSize);
        // Fill starting block
        const curB = B32.subarray(pIdx * blockSize32, pIdx * blockSize32 + parBlockSize);
        V.set(curB);
        i32.set(curB);
        // Phase 1: SMix Fill
        for (let i = 0; i < N - 1; ) {
          const count = Math.min(MAX_BATCH, N - 1 - i);
          mod.blockMix(0, takeP, r * count, count, r, takeP, 0);
          copyFast32(V, (i + 1) * parBlockSize, o32, 0, count * parBlockSize);
          i += count;
          if (progress(takeP * count)) yield;
        }
        // Phase 2: SMix Mix
        mod.blockMix(0, takeP, r, 1, r, takeP, 0);
        copyFast32(i32, 0, o32, 0, parBlockSize);
        if (progress(takeP)) yield;
        for (let i = 0; i < N; i++) {
          for (let k = 0; k < takeP; k++) {
            const laneOffset = k * blockSize32;
            const j = i32[laneOffset + blockSize32 - 16] & (N - 1);
            const vIdx = (j * takeP + k) * blockSize32;
            copyFast32(x32, laneOffset, V, vIdx, blockSize32);
          }
          mod.blockMix(0, takeP, r, 1, r, takeP, 1);
          if (progress(takeP)) yield;
        }
        // C. Final Result: Copy i32 (containing B final) back to B32
        copyFast32(B32, pIdx * blockSize32, i32, 0, parBlockSize);
      }
      const res = _pbkdf2(password, B, { c: 1, dkLen });
      clean(B, V, output, x32);
      return res;
    },
    definition,
    platform
  ) satisfies KDF<ScryptOpts>;
}
