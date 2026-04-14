/**
 * Hash definitions. Common logic for all targets.
 * Doesn't contain WASM-specific/JS-specific code.
 * @module
 */
import * as constants from './constants.ts';
import { type HashDef } from './hashes-abstract.ts';
import { mkArgon2d, mkArgon2i, mkArgon2id, mkScrypt } from './kdf.ts';
import type { Modules } from './modules/index.ts';
import type * as TYPES from './targets/types.ts';
import { abytes, anumber, isBytes, oidNist, u32, type TArg, type TRet } from './utils.ts';

// FIPS 202 §6.1 appends SHA-3 suffix bits `01`; this byte-level wrapper uses `0x06`
// so the shared Keccak padding path applies those domain bits before pad10*1.
export const sha3_224: TRet<HashDef<TYPES.KECCAK24>> = /* @__PURE__ */ Object.freeze({
  suffix: 0x06,
  blockLen: 144,
  outputLen: 28,
  outputBlockLen: 144,
  oid: /* @__PURE__ */ oidNist(0x07),
  init: (_batchPos, _maxBlocks, mod) => mod.initKeccak(),
});
export const sha3_256: TRet<HashDef<TYPES.KECCAK24>> = /* @__PURE__ */ Object.freeze({
  suffix: 0x06,
  blockLen: 136,
  outputLen: 32,
  outputBlockLen: 136,
  oid: /* @__PURE__ */ oidNist(0x08),
  init: (_batchPos, _maxBlocks, mod) => mod.initKeccak(),
});
export const sha3_384: TRet<HashDef<TYPES.KECCAK24>> = /* @__PURE__ */ Object.freeze({
  suffix: 0x06,
  blockLen: 104,
  outputLen: 48,
  outputBlockLen: 104,
  oid: /* @__PURE__ */ oidNist(0x09),
  init: (_batchPos, _maxBlocks, mod) => mod.initKeccak(),
});
export const sha3_512: TRet<HashDef<TYPES.KECCAK24>> = /* @__PURE__ */ Object.freeze({
  suffix: 0x06,
  blockLen: 72,
  outputLen: 64,
  outputBlockLen: 72,
  oid: /* @__PURE__ */ oidNist(0x0a),
  init: (_batchPos, _maxBlocks, mod) => mod.initKeccak(),
});
// Legacy Keccak keeps the original 0x01 domain suffix on Keccak-f[1600].
// Unlike FIPS 202 SHA3-*, it does not use the SHA-3 0x06 suffix or expose
// NIST hash OIDs here.
export const keccak_224: TRet<HashDef<TYPES.KECCAK24>> = /* @__PURE__ */ Object.freeze({
  suffix: 0x01,
  blockLen: 144,
  outputLen: 28,
  outputBlockLen: 144,
  init: (_batchPos, _maxBlocks, mod) => mod.initKeccak(),
});
export const keccak_256: TRet<HashDef<TYPES.KECCAK24>> = /* @__PURE__ */ Object.freeze({
  suffix: 0x01,
  blockLen: 136,
  outputLen: 32,
  outputBlockLen: 136,
  init: (_batchPos, _maxBlocks, mod) => mod.initKeccak(),
});
export const keccak_384: TRet<HashDef<TYPES.KECCAK24>> = /* @__PURE__ */ Object.freeze({
  suffix: 0x01,
  blockLen: 104,
  outputLen: 48,
  outputBlockLen: 104,
  init: (_batchPos, _maxBlocks, mod) => mod.initKeccak(),
});
export const keccak_512: TRet<HashDef<TYPES.KECCAK24>> = /* @__PURE__ */ Object.freeze({
  suffix: 0x01,
  blockLen: 72,
  outputLen: 64,
  outputBlockLen: 72,
  init: (_batchPos, _maxBlocks, mod) => mod.initKeccak(),
});
// FIPS 202 §6.2: SHAKE128 uses the 1111 domain suffix.
// It is `0x1f` in this byte-oriented padding path and stays XOF-capable; this
// wrapper keeps a 16-byte library default while callers can request any dkLen.
export const shake128: TRet<HashDef<TYPES.KECCAK24>> = /* @__PURE__ */ Object.freeze({
  suffix: 0x1f,
  blockLen: 168,
  outputLen: 16,
  outputBlockLen: 168,
  canXOF: true,
  oid: /* @__PURE__ */ oidNist(0x0b),
  init: (_batchPos, _maxBlocks, mod) => mod.initKeccak(),
});
// FIPS 202 §6.2: SHAKE256 uses the same 1111 domain suffix (`0x1f` here).
// It stays XOF-capable; this wrapper keeps a 32-byte library default while
// callers can request any dkLen.
export const shake256: TRet<HashDef<TYPES.KECCAK24>> = /* @__PURE__ */ Object.freeze({
  suffix: 0x1f,
  blockLen: 136,
  outputLen: 32,
  outputBlockLen: 136,
  canXOF: true,
  oid: /* @__PURE__ */ oidNist(0x0c),
  init: (_batchPos, _maxBlocks, mod) => mod.initKeccak(),
});
// This keeps the SHAKE128 algorithm and OID from FIPS 202 Appendix C.
// It chooses the 32-byte "NIST version" default while staying XOF-capable for
// any requested dkLen.
export const shake128_32: TRet<HashDef<TYPES.KECCAK24>> = /* @__PURE__ */ Object.freeze({
  suffix: 0x1f,
  blockLen: 168,
  outputLen: 32,
  outputBlockLen: 168,
  canXOF: true,
  oid: /* @__PURE__ */ oidNist(0x0b),
  init: (_batchPos, _maxBlocks, mod) => mod.initKeccak(),
});
// This keeps the SHAKE256 algorithm and OID from FIPS 202 Appendix C.
// It chooses the 64-byte "NIST version" default while staying XOF-capable for
// any requested dkLen.
export const shake256_64: TRet<HashDef<TYPES.KECCAK24>> = /* @__PURE__ */ Object.freeze({
  suffix: 0x1f,
  blockLen: 136,
  outputLen: 64,
  outputBlockLen: 136,
  canXOF: true,
  oid: /* @__PURE__ */ oidNist(0x0c),
  init: (_batchPos, _maxBlocks, mod) => mod.initKeccak(),
});
export const sha256: TRet<HashDef<TYPES.SHA256>> = /* @__PURE__ */ Object.freeze({
  blockLen: 64,
  outputLen: 32,
  oid: /* @__PURE__ */ oidNist(0x01),
  init: (batchPos, _maxBlocks, mod) => {
    mod.segments['state.state_chunks'][batchPos].set(constants.SHA256_IV_U8);
  },
});
// RFC 6234 §6.2: SHA-224 shares the SHA-256 compression core and eight-word state, but
// exposes only the leftmost 224 bits, so this wrapper keeps 32-byte backend output blocks
// while truncating the public digest to 28 bytes.
export const sha224: TRet<HashDef<TYPES.SHA256>> = /* @__PURE__ */ Object.freeze({
  blockLen: 64,
  outputLen: 28,
  outputBlockLen: 32,
  oid: /* @__PURE__ */ oidNist(0x04),
  init: (batchPos, _maxBlocks, mod) => {
    mod.segments['state.state_chunks'][batchPos].set(constants.SHA224_IV_U8);
  },
});

export const sha512: TRet<HashDef<TYPES.SHA512>> = /* @__PURE__ */ Object.freeze({
  blockLen: 128,
  outputLen: 64,
  outputBlockLen: 64,
  oid: /* @__PURE__ */ oidNist(0x03),
  init: (batchPos, _maxBlocks, mod) => {
    mod.segments['state.state_chunks'][batchPos].set(constants.SHA512_IV_U8);
  },
});
// RFC 4634 §6.4: SHA-384 shares the SHA-512 compression core and eight-word state, but
// exposes only H(N)0..H(N)5, so this wrapper keeps 64-byte backend output blocks while
// truncating the public digest to 48 bytes.
export const sha384: TRet<HashDef<TYPES.SHA512>> = /* @__PURE__ */ Object.freeze({
  blockLen: 128,
  outputLen: 48,
  outputBlockLen: 64,
  oid: /* @__PURE__ */ oidNist(0x02),
  init: (batchPos, _maxBlocks, mod) => {
    mod.segments['state.state_chunks'][batchPos].set(constants.SHA384_IV_U8);
  },
});
// This variant uses the shared SHA-512 backend with the derived SHA-512/224 IV, so backend
// output blocks stay 64 bytes while the public digest truncates to 28 bytes.
export const sha512_224: TRet<HashDef<TYPES.SHA512>> = /* @__PURE__ */ Object.freeze({
  blockLen: 128,
  outputLen: 28,
  outputBlockLen: 64,
  oid: /* @__PURE__ */ oidNist(0x05),
  init: (batchPos, _maxBlocks, mod) => {
    mod.segments['state.state_chunks'][batchPos].set(constants.SHA512_224_IV_U8);
  },
});
// This variant uses the shared SHA-512 backend with the derived SHA-512/256 IV, so backend
// output blocks stay 64 bytes while the public digest truncates to 32 bytes.
export const sha512_256: TRet<HashDef<TYPES.SHA512>> = /* @__PURE__ */ Object.freeze({
  blockLen: 128,
  outputLen: 32,
  outputBlockLen: 64,
  oid: /* @__PURE__ */ oidNist(0x06),
  init: (batchPos, _maxBlocks, mod) => {
    mod.segments['state.state_chunks'][batchPos].set(constants.SHA512_256_IV_U8);
  },
});
export const sha1: TRet<HashDef<TYPES.SHA1>> = /* @__PURE__ */ Object.freeze({
  blockLen: 64,
  outputLen: 20,
  init: (batchPos, _maxBlocks, mod) => {
    mod.segments['state.state_chunks'][batchPos].set(constants.SHA1_IV_U8);
  },
});
export const ripemd160: TRet<HashDef<TYPES.RIPEMD160>> = /* @__PURE__ */ Object.freeze({
  blockLen: 64,
  outputLen: 20,
  init: (batchPos, _maxBlocks, mod) => {
    mod.segments['state.state_chunks'][batchPos].set(constants.RIPEMD160_IV_U8);
  },
});
export const md5: TRet<HashDef<TYPES.MD5>> = /* @__PURE__ */ Object.freeze({
  blockLen: 64,
  outputLen: 16,
  init: (batchPos, _maxBlocks, mod) => {
    mod.segments['state.state_chunks'][batchPos].set(constants.MD5_IV_U8);
  },
});

/** Blake1 options. Basically just "salt" */
export type BlakeOpts = {
  salt?: TArg<Uint8Array>;
};

function blake1Salt(batchPos: number, mod: TArg<TYPES.BLAKE256>, opts: TArg<BlakeOpts>) {
  if (opts.salt !== undefined) {
    const slt = opts.salt;
    const salt_chunks = mod.segments['state.salt_chunks'];
    abytes(slt, salt_chunks[batchPos].length, 'salt');
    salt_chunks[batchPos].set(slt);
  }
}

export const blake256: TRet<HashDef<TYPES.BLAKE256, BlakeOpts>> = /* @__PURE__ */ Object.freeze({
  blockLen: 64,
  outputLen: 32,
  // SHA-3 proposal BLAKE v1.2 §2.1.1 / §2.1.3:
  // BLAKE-32 starts from the SHA-256 IV, and the 256-bit variant
  // keeps the pre-length padding bit set to 1, so this wrapper uses suffix 0x01.
  suffix: 0b0000_0001,
  init: (batchPos, _maxBlocks, mod, _, opts = {}) => {
    mod.segments['state.state_chunks'][batchPos].set(constants.SHA256_IV_U8);
    blake1Salt(batchPos, mod, opts);
  },
});
export const blake224: TRet<HashDef<TYPES.BLAKE256, BlakeOpts>> = /* @__PURE__ */ Object.freeze({
  blockLen: 64,
  outputLen: 28,
  // SHA-3 proposal BLAKE v1.2 §2.3:
  // BLAKE-28 reuses the BLAKE-32 core with the SHA-224 IV, replaces the
  // pre-length padding bit with 0, and truncates the public digest to 224 bits, so this
  // wrapper keeps 32-byte backend output blocks and leaves suffix at the default 0.
  outputBlockLen: 32,
  init: (batchPos, _maxBlocks, mod, _, opts = {}) => {
    mod.segments['state.state_chunks'][batchPos].set(constants.SHA224_IV_U8);
    blake1Salt(batchPos, mod, opts);
  },
});
export const blake384: TRet<HashDef<TYPES.BLAKE512, BlakeOpts>> = /* @__PURE__ */ Object.freeze({
  blockLen: 128,
  outputLen: 48,
  // SHA-3 proposal BLAKE v1.2 §2.4:
  // BLAKE-48 reuses the BLAKE-64 core with the SHA-384 IV, replaces the
  // pre-length padding bit with 0, and truncates the public digest to 384 bits, so this
  // wrapper keeps 64-byte backend output blocks and leaves suffix at the default 0.
  outputBlockLen: 64,
  init: (batchPos, _maxBlocks, mod, _, opts = {}) => {
    mod.segments['state.state_chunks'][batchPos].set(constants.SHA384_IV_U8);
    blake1Salt(batchPos, mod, opts);
  },
});
export const blake512: TRet<HashDef<TYPES.BLAKE512, BlakeOpts>> = /* @__PURE__ */ Object.freeze({
  blockLen: 128,
  outputLen: 64,
  // SHA-3 proposal BLAKE v1.2 §2.2.1 / §2.2.3:
  // BLAKE-64 starts from the SHA-512 IV, and the 512-bit variant
  // keeps the pre-length padding bit set to 1, so this wrapper uses suffix 0x01 and falls
  // back to 64-byte output blocks.
  suffix: 0b0000_0001,
  init: (batchPos, _maxBlocks, mod, _, opts = {}) => {
    mod.segments['state.state_chunks'][batchPos].set(constants.SHA512_IV_U8);
    blake1Salt(batchPos, mod, opts);
  },
});

/**
 * Blake2 hash options.
 * dkLen is output length. key is used in MAC mode. salt is used in KDF mode.
 */
export type Blake2Opts = {
  dkLen?: number;
  key?: TArg<Uint8Array>;
  salt?: TArg<Uint8Array>;
  personalization?: TArg<Uint8Array>;
};

function blake2Init(
  batchPos: number,
  outputLen: number,
  maxBlocks: number,
  blockLen: number,
  mod: TArg<TYPES.BLAKE2S>,
  opts: TArg<Blake2Opts>
) {
  if (opts.dkLen !== undefined) anumber(opts.dkLen, 'opts.dkLen');
  const dkLen = opts.dkLen === undefined ? outputLen : opts.dkLen;
  let keyLength = 0;
  let blocks = 0;
  // RFC 7693 uses digest length nn in 1..outputLen, so zero-length output is invalid here.
  if (dkLen <= 0 || dkLen > outputLen) throw new Error('outputLen bigger than keyLen');
  const { key, salt, personalization } = opts;
  if (key !== undefined) {
    if (key.length < 1 || key.length > outputLen)
      throw new Error('"key" expected to be undefined or of length=1..' + outputLen);
    abytes(key);
    const keyPos = batchPos * maxBlocks * blockLen;
    // RFC 7693 §3.3: keyed BLAKE2 pads the key with zeros and prepends it as d[0],
    // so preload one full block here and report blocks=1 to the shared absorber.
    mod.segments.buffer.fill(0, keyPos, keyPos + blockLen);
    mod.segments.buffer.set(key, keyPos);
    keyLength = key.length;
    blocks = 1;
  }
  const salt_chunk = mod.segments['init.salt_chunks'][batchPos];
  const pers_chunk = mod.segments['init.personalization_chunks'][batchPos];
  if (salt !== undefined) {
    abytes(salt, salt_chunk.length, 'salt');
    salt_chunk.set(salt);
  }
  if (personalization !== undefined) {
    abytes(personalization, pers_chunk.length, 'personalization');
    pers_chunk.set(personalization);
  }
  mod.initBlake2(batchPos, 1, 1, dkLen, keyLength);
  // Streaming BLAKE2 instances keep dkLen as their fixed digest size, so create({ dkLen })
  // must carry that value into digest() / digestInto() instead of falling back to the family max.
  return { blocks, outputLen: dkLen };
}

export const blake2s: TRet<HashDef<TYPES.BLAKE2S, Blake2Opts>> = /* @__PURE__ */ Object.freeze({
  blockLen: 64,
  // RFC 7693 §4: the default named surface here is BLAKE2s-256 (nn = 32);
  // shorter digests come from opts.dkLen, and OID support is optional so oid stays unset.
  outputLen: 32,
  init: (batchPos, maxBlocks, mod, _, opts = {}) => {
    mod.segments['state.state_chunks'][batchPos].set(constants.B2S_IV_U8);
    return blake2Init(batchPos, 32, maxBlocks, 64, mod, opts);
  },
});

export const blake2b: TRet<HashDef<TYPES.BLAKE2B, Blake2Opts>> = /* @__PURE__ */ Object.freeze({
  blockLen: 128,
  // RFC 7693 §4: the default named surface here is BLAKE2b-512 (nn = 64);
  // shorter digests come from opts.dkLen, and OID support is optional so oid stays unset.
  outputLen: 64,
  suffix: 0,
  init: (batchPos, maxBlocks, mod, _, opts = {}) => {
    mod.segments['state.state_chunks'][batchPos].set(constants.B2B_IV_U8);
    return blake2Init(batchPos, 64, maxBlocks, 128, mod, opts);
  },
});
/**
 * Ensure to use EITHER `key` OR `context`, not both.
 *
 * * `key`: 32-byte MAC key.
 * * `context`: string for KDF. Should be hardcoded, globally unique, and application - specific.
 *   A good default format for the context string is "[application] [commit timestamp] [purpose]".
 */
export type Blake3Opts = {
  dkLen?: number;
  key?: Uint8Array;
  context?: Uint8Array;
  _keyContext?: boolean;
};
export const blake3: TRet<HashDef<TYPES.BLAKE3, Blake3Opts>> = /* @__PURE__ */ Object.freeze({
  blockLen: 64,
  // BLAKE3's default hash is the 32-byte root chaining value, but XOF output repeats
  // the full 64-byte ROOT compression blocks, so outputBlockLen stays 64 while outputLen is 32.
  outputBlockLen: 64,
  outputLen: 32,
  chunks: /* @__PURE__ */ (() => 10 * 1024 * 16)(),
  canXOF: true,
  init(batchPos, _maxBlocks, mod, hash, opts = {}) {
    const { key, context, _keyContext } = opts;
    if (opts.dkLen !== undefined) anumber(opts.dkLen, 'opts.dkLen');
    let flags = 0 >>> 0;
    let IV: Uint8Array = constants.B3_IV_U8;
    if (key !== undefined) {
      abytes(key, 32, 'key');
      if (context !== undefined || _keyContext !== undefined)
        throw new Error('Only "key" or "context" can be specified at same time');
      // PRF/HMAC/MAC
      IV = key;
      flags = constants.B3_Flags.KEYED_HASH;
    } else if (_keyContext !== undefined) {
      if (context !== undefined || key !== undefined)
        throw new Error('Only "key" or "context" can be specified at same time');
      flags = constants.B3_Flags.DERIVE_KEY_CONTEXT;
    } else if (context !== undefined) {
      abytes(context, undefined, 'context');
      if (_keyContext !== undefined || key !== undefined)
        throw new Error('Only "key" or "context" can be specified at same time');
      if (_keyContext !== undefined && typeof _keyContext !== 'boolean')
        throw new Error('wrong type for _keyContext');
      // BLAKE3 derive_key is two-stage: first hash the context under
      // DERIVE_KEY_CONTEXT, then use that 32-byte output as the key words for key material.
      const derive = hash as (msg: Uint8Array, opts?: Blake3Opts) => TRet<Uint8Array>;
      IV = derive(context as Uint8Array, { dkLen: 32, _keyContext: true });
      flags = constants.B3_Flags.DERIVE_KEY_MATERIAL;
    }
    mod.segments['state.iv_chunks'][batchPos].set(IV);
    mod.segments['state.state_chunks'][batchPos].set(IV);
    u32(mod.segments['state.flags_chunks'][batchPos])[0] = flags;
  },
});

// MAC
// Old API was key as second argument, so we just support that
type MACOpts = { key: TArg<Uint8Array> } | TArg<Uint8Array>;
// Normalize both legacy mac(msg, key) and newer mac(msg, { key }) call shapes without cloning.
const getMacKey = (opts: TArg<MACOpts>): TRet<Uint8Array> =>
  (isBytes(opts) ? opts : opts.key) as TRet<Uint8Array>;

// RFC 8439 §2.5: Poly1305 consumes a fresh 32-byte one-time key per message.
// It emits a 16-byte tag over 16-byte blocks.
export const poly1305: TRet<HashDef<TYPES.POLY1305, MACOpts>> = /* @__PURE__ */ Object.freeze({
  blockLen: 16,
  outputLen: 16,
  init(_batchPos, _maxBlocks, mod, _hash, opts) {
    const key = getMacKey(opts);
    if (key === undefined)
      throw new Error('"key" expected Uint8Array of length 32, got type=undefined');
    abytes(key, 32, 'key');
    mod.segments['state.poly.key_chunks'][_batchPos].set(key);
    mod.macInit(_batchPos);
  },
});

// RFC 4493 §2.4 / FIPS 197-upd1 §3.1:
// AES-CMAC uses AES's 16-byte block size and fixed 16-byte tag, while this
// wrapper accepts AES-128/192/256 keys.
export const cmac: TRet<HashDef<TYPES.CMAC, MACOpts>> = /* @__PURE__ */ Object.freeze({
  blockLen: 16,
  outputLen: 16,
  init(_batchPos, _maxBlocks, mod, _hash, opts) {
    const key = getMacKey(opts);
    if (key === undefined)
      throw new Error('"cmac key" expected Uint8Array of length 16/24/32, got length=undefined');
    abytes(key, undefined, 'cmac key');
    if (key.length !== 16 && key.length !== 24 && key.length !== 32)
      throw new Error(
        '"cmac key" expected Uint8Array of length 16/24/32, got length=' + key.length
      );
    mod.segments['state.key_chunks'][_batchPos].set(key);
    mod.macInit(_batchPos, key.length);
  },
});

// NIST SP 800-38D §6.4 / §7.1:
// raw GHASH takes the 16-byte hash subkey H = CIPH_K(0^128), not the AES key K.
export const ghash: TRet<HashDef<TYPES.GHASH, MACOpts>> = /* @__PURE__ */ Object.freeze({
  blockLen: 16,
  outputLen: 16,
  init(_batchPos, _maxBlocks, mod, _hash, opts) {
    const key = getMacKey(opts);
    if (key === undefined)
      throw new Error('"key" expected Uint8Array of length 16, got type=undefined');
    abytes(key, 16, 'key');
    mod.segments['state.ghash.h_chunks'][_batchPos].set(key);
    mod.macInit(_batchPos);
  },
});
// RFC 8452 §3 / Appendix A:
// raw POLYVAL takes a 16-byte field element H and shares the GHASH core via
// the reversed byte/bit convention.
export const polyval: TRet<HashDef<TYPES.POLYVAL, MACOpts>> = /* @__PURE__ */ Object.freeze({
  blockLen: 16,
  outputLen: 16,
  init(_batchPos, _maxBlocks, mod, _hash, opts) {
    const key = getMacKey(opts);
    if (key === undefined)
      throw new Error('"key" expected Uint8Array of length 16, got type=undefined');
    abytes(key, 16, 'key');
    mod.segments['state.ghash.h_chunks'][_batchPos].set(key);
    mod.macInit(_batchPos);
  },
});

// NOTE: safe for tree-shaking since used only in building process
// prettier-ignore
const defs = {
  sha3_224, sha3_256, sha3_384, sha3_512, // sha3
  keccak_224, keccak_256, keccak_384, keccak_512, // keccak
  shake128, shake256, shake128_32, shake256_64, // shake
  sha224, sha256, sha384, sha512, sha512_224, sha512_256, // sha2
  sha1, ripemd160, md5, // legacy
  blake224, blake256, blake384, blake512, blake2s, blake2b, blake3, // blake
  poly1305, ghash, polyval, cmac, // MAC
} as const;

// Map each name to module
const MOD_OF = {
  // sha3
  sha3_224: 'keccak24',
  sha3_256: 'keccak24',
  sha3_384: 'keccak24',
  sha3_512: 'keccak24',
  // keccak
  keccak_224: 'keccak24',
  keccak_256: 'keccak24',
  keccak_384: 'keccak24',
  keccak_512: 'keccak24',
  // shake
  shake128: 'keccak24',
  shake256: 'keccak24',
  shake128_32: 'keccak24',
  shake256_64: 'keccak24',
  // sha2
  sha224: 'sha256',
  sha256: 'sha256',
  sha384: 'sha512',
  sha512: 'sha512',
  sha512_224: 'sha512',
  sha512_256: 'sha512',
  // legacy
  sha1: 'sha1',
  ripemd160: 'ripemd160',
  md5: 'md5',
  // blake1/2/3
  blake224: 'blake256',
  blake256: 'blake256',
  blake384: 'blake512',
  blake512: 'blake512',
  blake2s: 'blake2s',
  blake2b: 'blake2b',
  blake3: 'blake3',
  // Mac
  poly1305: 'poly1305',
  ghash: 'ghash',
  polyval: 'polyval',
  cmac: 'cmac',
} as const satisfies { [K in keyof typeof defs & string]: Modules };
// Verifies that definition actually can be used with module
function buildDefinitions<D extends Record<string, unknown>, M extends { [K in keyof D]: Modules }>(
  defs: D,
  modOf: M
) {
  type Pair<K extends keyof D> = { mod: M[K]; def: D[K] };
  const out = {} as { [K in keyof D]: Pair<K> };
  for (const k in defs) out[k] = { mod: modOf[k], def: defs[k] } as Pair<typeof k>;
  return out;
}
export const Definitions = /* @__PURE__ */ buildDefinitions(defs, MOD_OF);
// Generic definitions can be used for non-hash/cipher surfaces that still need
// a specific wrapper function.
// KDF stubs compare factory identity, so installed implementations carry the public wrapper here.
export const scrypt = ((mod, deps, platform) =>
  mkScrypt(mod, deps, platform, scrypt)) as typeof mkScrypt;
export const argon2d = ((mod, deps, platform) =>
  mkArgon2d(mod, deps, platform, argon2d)) as typeof mkArgon2d;
export const argon2i = ((mod, deps, platform) =>
  mkArgon2i(mod, deps, platform, argon2i)) as typeof mkArgon2i;
export const argon2id = ((mod, deps, platform) =>
  mkArgon2id(mod, deps, platform, argon2id)) as typeof mkArgon2id;

// type GenericDefinition<T, DEPS extends Record<string, any>, RET> = (
//   mod: T,
//   deps: DEPS,
//   platform: string
// ) => RET;

// const genDefs = { scrypt, argon2d, argon2i, argon2id } satisfies Record<
//   string,
//   GenericDefinition<any, any, any>
// >;
const KDFStub = { path: 'kdf.ts', fn: 'mkKDFStub' };
export const GenericDefinitions = {
  scrypt: { mod: 'scrypt', deps: ['sha256'], stub: KDFStub },
  argon2d: { mod: 'argon2', deps: ['blake2b'], stub: KDFStub },
  argon2i: { mod: 'argon2', deps: ['blake2b'], stub: KDFStub },
  argon2id: { mod: 'argon2', deps: ['blake2b'], stub: KDFStub },
};
