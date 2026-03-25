/**
 * Hash definitions. Common logic for all targets.
 * Doesn't contain WASM-specific/JS-specific code.
 * @module
 */
import * as constants from './constants.ts';
import { type HashDef } from './hashes-abstract.ts';
import { mkArgon2d, mkArgon2i, mkArgon2id, mkScrypt } from './kdf.ts';
import { type Modules } from './modules/index.ts'; // we can import only types here!
import type * as TYPES from './targets/types.ts';
import { abytes, anumber, isBytes, oidNist, u32 } from './utils.ts';

export const sha3_224: HashDef<TYPES.KECCAK24> = /* @__PURE__ */ Object.freeze({
  suffix: 0x06,
  blockLen: 144,
  outputLen: 28,
  outputBlockLen: 144,
  oid: /* @__PURE__ */ oidNist(0x07),
  init: (_batchPos, _maxBlocks, mod) => mod.initKeccak(),
});
export const sha3_256: HashDef<TYPES.KECCAK24> = /* @__PURE__ */ Object.freeze({
  suffix: 0x06,
  blockLen: 136,
  outputLen: 32,
  outputBlockLen: 136,
  oid: /* @__PURE__ */ oidNist(0x08),
  init: (_batchPos, _maxBlocks, mod) => mod.initKeccak(),
});
export const sha3_384: HashDef<TYPES.KECCAK24> = /* @__PURE__ */ Object.freeze({
  suffix: 0x06,
  blockLen: 104,
  outputLen: 48,
  outputBlockLen: 104,
  oid: /* @__PURE__ */ oidNist(0x09),
  init: (_batchPos, _maxBlocks, mod) => mod.initKeccak(),
});
export const sha3_512: HashDef<TYPES.KECCAK24> = /* @__PURE__ */ Object.freeze({
  suffix: 0x06,
  blockLen: 72,
  outputLen: 64,
  outputBlockLen: 72,
  oid: /* @__PURE__ */ oidNist(0x0a),
  init: (_batchPos, _maxBlocks, mod) => mod.initKeccak(),
});
export const keccak_224: HashDef<TYPES.KECCAK24> = /* @__PURE__ */ Object.freeze({
  suffix: 0x01,
  blockLen: 144,
  outputLen: 28,
  outputBlockLen: 144,
  init: (_batchPos, _maxBlocks, mod) => mod.initKeccak(),
});
export const keccak_256: HashDef<TYPES.KECCAK24> = /* @__PURE__ */ Object.freeze({
  suffix: 0x01,
  blockLen: 136,
  outputLen: 32,
  outputBlockLen: 136,
  init: (_batchPos, _maxBlocks, mod) => mod.initKeccak(),
});
export const keccak_384: HashDef<TYPES.KECCAK24> = /* @__PURE__ */ Object.freeze({
  suffix: 0x01,
  blockLen: 104,
  outputLen: 48,
  outputBlockLen: 104,
  init: (_batchPos, _maxBlocks, mod) => mod.initKeccak(),
});
export const keccak_512: HashDef<TYPES.KECCAK24> = /* @__PURE__ */ Object.freeze({
  suffix: 0x01,
  blockLen: 72,
  outputLen: 64,
  outputBlockLen: 72,
  init: (_batchPos, _maxBlocks, mod) => mod.initKeccak(),
});
export const shake128: HashDef<TYPES.KECCAK24> = /* @__PURE__ */ Object.freeze({
  suffix: 0x1f,
  blockLen: 168,
  outputLen: 16,
  outputBlockLen: 168,
  canXOF: true,
  init: (_batchPos, _maxBlocks, mod) => mod.initKeccak(),
});
export const shake256: HashDef<TYPES.KECCAK24> = /* @__PURE__ */ Object.freeze({
  suffix: 0x1f,
  blockLen: 136,
  outputLen: 32,
  outputBlockLen: 136,
  canXOF: true,
  init: (_batchPos, _maxBlocks, mod) => mod.initKeccak(),
});
export const shake128_32: HashDef<TYPES.KECCAK24> = /* @__PURE__ */ Object.freeze({
  suffix: 0x1f,
  blockLen: 168,
  outputLen: 32,
  outputBlockLen: 168,
  canXOF: true,
  init: (_batchPos, _maxBlocks, mod) => mod.initKeccak(),
});
export const shake256_64: HashDef<TYPES.KECCAK24> = /* @__PURE__ */ Object.freeze({
  suffix: 0x1f,
  blockLen: 136,
  outputLen: 64,
  outputBlockLen: 136,
  canXOF: true,
  init: (_batchPos, _maxBlocks, mod) => mod.initKeccak(),
});
export const sha256: HashDef<TYPES.SHA256> = /* @__PURE__ */ Object.freeze({
  blockLen: 64,
  outputLen: 32,
  oid: /* @__PURE__ */ oidNist(0x01),
  init: (batchPos, _maxBlocks, mod) => {
    mod.segments['state.state_chunks'][batchPos].set(constants.SHA256_IV_U8);
  },
});
export const sha224: HashDef<TYPES.SHA256> = /* @__PURE__ */ Object.freeze({
  blockLen: 64,
  outputLen: 28,
  outputBlockLen: 32,
  oid: /* @__PURE__ */ oidNist(0x04),
  init: (batchPos, _maxBlocks, mod) => {
    mod.segments['state.state_chunks'][batchPos].set(constants.SHA224_IV_U8);
  },
});

export const sha512: HashDef<TYPES.SHA512> = /* @__PURE__ */ Object.freeze({
  blockLen: 128,
  outputLen: 64,
  outputBlockLen: 64,
  oid: /* @__PURE__ */ oidNist(0x03),
  init: (batchPos, _maxBlocks, mod) => {
    mod.segments['state.state_chunks'][batchPos].set(constants.SHA512_IV_U8);
  },
});
export const sha384: HashDef<TYPES.SHA512> = /* @__PURE__ */ Object.freeze({
  blockLen: 128,
  outputLen: 48,
  outputBlockLen: 64,
  oid: /* @__PURE__ */ oidNist(0x02),
  init: (batchPos, _maxBlocks, mod) => {
    mod.segments['state.state_chunks'][batchPos].set(constants.SHA384_IV_U8);
  },
});
export const sha512_224: HashDef<TYPES.SHA512> = /* @__PURE__ */ Object.freeze({
  blockLen: 128,
  outputLen: 28,
  outputBlockLen: 64,
  oid: /* @__PURE__ */ oidNist(0x05),
  init: (batchPos, _maxBlocks, mod) => {
    mod.segments['state.state_chunks'][batchPos].set(constants.SHA512_224_IV_U8);
  },
});
export const sha512_256: HashDef<TYPES.SHA512> = /* @__PURE__ */ Object.freeze({
  blockLen: 128,
  outputLen: 32,
  outputBlockLen: 64,
  oid: /* @__PURE__ */ oidNist(0x06),
  init: (batchPos, _maxBlocks, mod) => {
    mod.segments['state.state_chunks'][batchPos].set(constants.SHA512_256_IV_U8);
  },
});
export const sha1: HashDef<TYPES.SHA1> = /* @__PURE__ */ Object.freeze({
  blockLen: 64,
  outputLen: 20,
  init: (batchPos, _maxBlocks, mod) => {
    mod.segments['state.state_chunks'][batchPos].set(constants.SHA1_IV_U8);
  },
});
export const ripemd160: HashDef<TYPES.RIPEMD160> = /* @__PURE__ */ Object.freeze({
  blockLen: 64,
  outputLen: 20,
  init: (batchPos, _maxBlocks, mod) => {
    mod.segments['state.state_chunks'][batchPos].set(constants.RIPEMD160_IV_U8);
  },
});
export const md5: HashDef<TYPES.MD5> = /* @__PURE__ */ Object.freeze({
  blockLen: 64,
  outputLen: 16,
  init: (batchPos, _maxBlocks, mod) => {
    mod.segments['state.state_chunks'][batchPos].set(constants.MD5_IV_U8);
  },
});

/** Blake1 options. Basically just "salt" */
export type BlakeOpts = {
  salt?: Uint8Array;
};

function blake1Salt(batchPos: number, mod: TYPES.BLAKE256, opts: BlakeOpts) {
  if (opts.salt !== undefined) {
    const slt = opts.salt;
    const salt_chunks = mod.segments['state.salt_chunks'];
    abytes(slt, salt_chunks[batchPos].length, 'salt');
    salt_chunks[batchPos].set(slt);
  }
}

export const blake256: HashDef<TYPES.BLAKE256, BlakeOpts> = /* @__PURE__ */ Object.freeze({
  blockLen: 64,
  outputLen: 32,
  suffix: 0b0000_0001,
  init: (batchPos, _maxBlocks, mod, _, opts = {}) => {
    mod.segments['state.state_chunks'][batchPos].set(constants.SHA256_IV_U8);
    blake1Salt(batchPos, mod, opts);
  },
});
export const blake224: HashDef<TYPES.BLAKE256, BlakeOpts> = /* @__PURE__ */ Object.freeze({
  blockLen: 64,
  outputLen: 28,
  outputBlockLen: 32,
  init: (batchPos, _maxBlocks, mod, _, opts = {}) => {
    mod.segments['state.state_chunks'][batchPos].set(constants.SHA224_IV_U8);
    blake1Salt(batchPos, mod, opts);
  },
});
export const blake384: HashDef<TYPES.BLAKE512, BlakeOpts> = /* @__PURE__ */ Object.freeze({
  blockLen: 128,
  outputLen: 48,
  outputBlockLen: 64,
  init: (batchPos, _maxBlocks, mod, _, opts = {}) => {
    mod.segments['state.state_chunks'][batchPos].set(constants.SHA384_IV_U8);
    blake1Salt(batchPos, mod, opts);
  },
});
export const blake512: HashDef<TYPES.BLAKE512, BlakeOpts> = /* @__PURE__ */ Object.freeze({
  blockLen: 128,
  outputLen: 64,
  suffix: 0b0000_0001,
  init: (batchPos, _maxBlocks, mod, _, opts = {}) => {
    mod.segments['state.state_chunks'][batchPos].set(constants.SHA512_IV_U8);
    blake1Salt(batchPos, mod, opts);
  },
});

/** Blake2 hash options. dkLen is output length. key is used in MAC mode. salt is used in KDF mode. */
export type Blake2Opts = {
  dkLen?: number;
  key?: Uint8Array;
  salt?: Uint8Array;
  personalization?: Uint8Array;
};

function blake2Init(
  batchPos: number,
  outputLen: number,
  maxBlocks: number,
  blockLen: number,
  mod: TYPES.BLAKE2S,
  opts: Blake2Opts
) {
  if (opts.dkLen !== undefined) anumber(opts.dkLen, 'opts.dkLen');
  const dkLen = opts.dkLen || outputLen;
  let keyLength = 0;
  let blocks = 0;
  if (dkLen < 0 || dkLen > outputLen) throw new Error('outputLen bigger than keyLen');
  const { key, salt, personalization } = opts;
  if (key !== undefined) {
    if (key.length < 1 || key.length > outputLen)
      throw new Error('"key" expected to be undefined or of length=1..' + outputLen);
    abytes(key);
    const keyPos = batchPos * maxBlocks * blockLen;
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
  return { blocks };
}

export const blake2s: HashDef<TYPES.BLAKE2S, Blake2Opts> = /* @__PURE__ */ Object.freeze({
  blockLen: 64,
  outputLen: 32,
  init: (batchPos, maxBlocks, mod, _, opts = {}) => {
    mod.segments['state.state_chunks'][batchPos].set(constants.B2S_IV_U8);
    return blake2Init(batchPos, 32, maxBlocks, 64, mod, opts);
  },
});

export const blake2b: HashDef<TYPES.BLAKE2B, Blake2Opts> = /* @__PURE__ */ Object.freeze({
  blockLen: 128,
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
export const blake3: HashDef<TYPES.BLAKE3, Blake3Opts> = /* @__PURE__ */ Object.freeze({
  blockLen: 64,
  outputBlockLen: 64,
  outputLen: 32,
  chunks: /* @__PURE__ */ (() => 10 * 1024 * 16)(),
  canXOF: true,
  init(batchPos, _maxBlocks, mod, hash, opts = {}) {
    const { key, context, _keyContext } = opts;
    if (opts.dkLen !== undefined) anumber(opts.dkLen, 'opts.dkLen');
    let flags = 0 >>> 0;
    let IV = constants.B3_IV_U8;
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
      // KDF/HKDF
      IV = hash(context, { dkLen: 32, _keyContext: true });
      flags = constants.B3_Flags.DERIVE_KEY_MATERIAL;
    }
    mod.segments['state.iv_chunks'][batchPos].set(IV);
    mod.segments['state.state_chunks'][batchPos].set(IV);
    u32(mod.segments['state.flags_chunks'][batchPos])[0] = flags;
  },
});

// MAC
// Old API was key as second argument, so we just support that
type MACOpts = { key: Uint8Array } | Uint8Array;
const getMacKey = (opts: MACOpts): Uint8Array => (isBytes(opts) ? opts : opts.key);

export const poly1305: HashDef<TYPES.POLY1305, MACOpts> = /* @__PURE__ */ Object.freeze({
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

export const cmac: HashDef<TYPES.CMAC, MACOpts> = /* @__PURE__ */ Object.freeze({
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

export const ghash: HashDef<TYPES.GHASH, MACOpts> = /* @__PURE__ */ Object.freeze({
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
export const polyval: HashDef<TYPES.POLYVAL, MACOpts> = /* @__PURE__ */ Object.freeze({
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
} as const satisfies Record<string, HashDef<any, any>>;

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
function buildDefinitions<
  D extends Record<string, HashDef<any, any>>,
  M extends { [K in keyof D]: Modules },
>(defs: D, modOf: M) {
  type Pair<K extends keyof D> = { mod: M[K]; def: D[K] };
  const out = {} as { [K in keyof D]: Pair<K> };
  for (const k in defs) out[k] = { mod: modOf[k], def: defs[k] } as Pair<typeof k>;
  return out;
}
export const Definitions = /* @__PURE__ */ buildDefinitions(defs, MOD_OF);
// Generic definitions, those can be used for anything non-hash/ciphers related that has specific wrapper function
export const scrypt = mkScrypt;
export const argon2d = mkArgon2d;
export const argon2i = mkArgon2i;
export const argon2id = mkArgon2id;

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
