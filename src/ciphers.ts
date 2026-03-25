/**
 * Cipher definitions. Common logic for all targets.
 * Doesn't contain WASM-specific/JS-specific code.
 * @module
 */
import type { CipherDef, CipherOpts } from './ciphers-abstract.ts';
import { ARX_SIGMA16, ARX_SIGMA32 } from './constants.ts';
import { type Modules } from './modules/index.ts'; // we can import only types here!
import type * as TYPES from './targets/types.ts';
import { abytes, anumber, u32 } from './utils.ts';

export const limit = (name: string, min: number, max: number) => (value: number) => {
  if (!Number.isSafeInteger(value) || min > value || value > max) {
    const minmax = '[' + min + '..' + max + ']';
    throw new Error('' + name + ': expected value in range ' + minmax + ', got ' + value);
  }
};

const setCounter = (counterSeg: Uint32Array, counter: number) => {
  counterSeg[0] = counter >>> 0;
  counterSeg[1] = 0;
};

export type ArxOpts = {
  counter?: number;
};

export type ArxInit = {
  allowShortKeys: boolean;
  extendNonce?: boolean;
  counterLength: number;
  counterRight: boolean;
};

// Validations live in validate() because init() is lazy; tests expect errors at factory creation.
export const initArx = (
  mod: any,
  key: Uint8Array,
  nonce: Uint8Array,
  opts: ArxOpts | undefined,
  cfg: ArxInit
) => {
  const { allowShortKeys, extendNonce, counterLength, counterRight } = cfg;
  const counter = opts?.counter === undefined ? 0 : opts.counter;
  let k = key;
  let sigma = key.length === 16 ? ARX_SIGMA16 : ARX_SIGMA32;
  if (key.length === 16 && allowShortKeys) {
    const kk = new Uint8Array(32);
    kk.set(key);
    kk.set(key, 16);
    k = kk;
    sigma = ARX_SIGMA16;
  }
  let n = nonce;
  if (extendNonce) {
    if (!mod.derive) throw new Error('arx: extendNonce requires derive');
    mod.segments['state.sigma'].set(sigma);
    mod.segments['state.key'].set(k);
    mod.segments['derive.nonce'].set(nonce.subarray(0, 16));
    mod.derive();
    k = mod.segments['derive.out'];
    n = nonce.subarray(16);
  }
  const nonceNcLen = 16 - counterLength;
  if (nonceNcLen !== 12) {
    const nc = new Uint8Array(12);
    const off = counterRight ? 0 : 12 - n.length;
    nc.set(n, off);
    n = nc;
  }
  mod.segments['state.sigma'].set(sigma);
  mod.segments['state.key'].set(k);
  const nonceBytes = mod.segments['state.nonce'].length;
  mod.segments['state.nonce'].set(n.length === nonceBytes ? n : n.subarray(0, nonceBytes));
  setCounter(u32(mod.segments['state.counter']), counter);
};
// Factory-time validation: mkCipher init is lazy.
const validateArx = (
  key: Uint8Array,
  nonce: Uint8Array,
  opts: ArxOpts | undefined,
  cfg: ArxInit
) => {
  const { allowShortKeys, extendNonce, counterLength } = cfg;
  abytes(key, undefined, 'key');
  abytes(nonce, undefined, 'nonce');
  const counter = opts?.counter === undefined ? 0 : opts.counter;
  anumber(counter, 'counter');
  if (counter < 0 || counter >= 2 ** 32 - 1) throw new Error('arx: counter overflow');
  if (key.length === 32) {
    // ok
  } else if (key.length === 16 && allowShortKeys) {
    // ok
  } else {
    abytes(key, 32, 'arx key');
    throw new Error('invalid key size');
  }
  let n = nonce;
  if (extendNonce) {
    if (nonce.length !== 24) throw new Error('arx: extended nonce must be 24 bytes');
    n = nonce.subarray(16);
  }
  const nonceNcLen = 16 - counterLength;
  if (nonceNcLen !== n.length) throw new Error(`arx: nonce must be ${nonceNcLen} or 16 bytes`);
};

const arxBase = (cfg: ArxInit): CipherDef<any> => ({
  blockLen: 64,
  validate: (key, nonce, opts) => {
    validateArx(key, nonce as Uint8Array, opts as ArxOpts | undefined, cfg);
  },
  init: (mod, _dir, key, nonce, opts) => {
    const iv = nonce as Uint8Array;
    initArx(mod, key, iv, opts as ArxOpts | undefined, cfg);
  },
});

export const salsa20: CipherDef<TYPES.SALSA20> = /* @__PURE__ */ (() =>
  Object.freeze({
    .../* @__PURE__ */ arxBase({ allowShortKeys: true, counterLength: 8, counterRight: true }),
    nonceLength: 8,
  }))();

export const xsalsa20: CipherDef<TYPES.SALSA20> = /* @__PURE__ */ (() =>
  Object.freeze({
    .../* @__PURE__ */ arxBase({
      allowShortKeys: true,
      counterLength: 8,
      counterRight: true,
      extendNonce: true,
    }),
    nonceLength: 24,
  }))();

export const chacha20orig: CipherDef<TYPES.CHACHA20> = /* @__PURE__ */ (() =>
  Object.freeze({
    .../* @__PURE__ */ arxBase({ allowShortKeys: true, counterLength: 8, counterRight: false }),
    nonceLength: 8,
  }))();

export const chacha20: CipherDef<TYPES.CHACHA20> = /* @__PURE__ */ (() =>
  Object.freeze({
    .../* @__PURE__ */ arxBase({ allowShortKeys: false, counterLength: 4, counterRight: false }),
    nonceLength: 12,
  }))();

export const xchacha20: CipherDef<TYPES.CHACHA20> = /* @__PURE__ */ (() =>
  Object.freeze({
    .../* @__PURE__ */ arxBase({
      allowShortKeys: false,
      counterLength: 8,
      counterRight: false,
      extendNonce: true,
    }),
    nonceLength: 24,
  }))();

export const chacha8: CipherDef<TYPES.CHACHA8> = /* @__PURE__ */ (() =>
  Object.freeze({
    .../* @__PURE__ */ arxBase({ allowShortKeys: false, counterLength: 4, counterRight: false }),
    nonceLength: 12,
  }))();

export const chacha12: CipherDef<TYPES.CHACHA12> = /* @__PURE__ */ (() =>
  Object.freeze({
    .../* @__PURE__ */ arxBase({ allowShortKeys: false, counterLength: 4, counterRight: false }),
    nonceLength: 12,
  }))();

const arxAeadBase = (cfg: ArxInit, tagLeft = false): CipherDef<any> => ({
  blockLen: 64,
  tagLength: 16,
  tagLeft,
  tagError: 'invalid tag',
  validate: (key, nonce, aad) => {
    validateArx(key, nonce as Uint8Array, undefined, cfg);
    if (aad !== undefined) abytes(aad as Uint8Array, undefined, 'AAD');
  },
  init: (mod, dir, key, nonce, aad) => {
    const iv = nonce as Uint8Array;
    const aadBytes = aad as Uint8Array | undefined;
    initArx(mod, key, iv, undefined, cfg);
    const [aadLo, aadHi] = splitLen(aadBytes ? aadBytes.length : 0);
    if (dir === 'encrypt') mod.encryptInit(aadLo, aadHi);
    else mod.decryptInit(aadLo, aadHi);
    if (aadBytes && aadBytes.length) aadBlocks(mod, aadBytes);
  },
  getTag: (mod) => {
    mod.tagFinish();
    return mod.segments['state.poly.tag'].subarray(0, 16);
  },
});

export const chacha20poly1305: CipherDef<any> = /* @__PURE__ */ (() =>
  Object.freeze({
    .../* @__PURE__ */ arxAeadBase({
      allowShortKeys: false,
      counterLength: 4,
      counterRight: false,
    }),
    nonceLength: 12,
  }))();

export const xchacha20poly1305: CipherDef<any> = /* @__PURE__ */ (() =>
  Object.freeze({
    .../* @__PURE__ */ arxAeadBase({
      allowShortKeys: false,
      counterLength: 8,
      counterRight: false,
      extendNonce: true,
    }),
    nonceLength: 24,
  }))();

export const xsalsa20poly1305: CipherDef<any> = /* @__PURE__ */ (() =>
  Object.freeze({
    .../* @__PURE__ */ arxAeadBase(
      { allowShortKeys: true, counterLength: 8, counterRight: true, extendNonce: true },
      true
    ),
    dataOffset: 32,
    nonceLength: 24,
  }))();

const AES_LEN_ENC = 'aec/(cbc-ecb): unpadded plaintext with disabled padding';
const AES_LEN_DEC = 'aes-(cbc/ecb).decrypt ciphertext should consist of blocks with size 16';
const AES_PAD_EMPTY = 'aes/pcks5: empty ciphertext not allowed';
const AES_PAD_BAD = 'aes/pcks5: wrong padding';

const aesKey = (key: Uint8Array) => {
  abytes(key, undefined, 'aes key');
  if (key.length !== 16 && key.length !== 24 && key.length !== 32) {
    throw new Error('"aes key" expected Uint8Array of length 16/24/32, got length=' + key.length);
  }
};

const aesInit = (
  mod: any,
  key: Uint8Array,
  iv: Uint8Array | undefined,
  dir: 'encrypt' | 'decrypt',
  useDec: boolean
) => {
  const keySeg = mod.segments['state.key'];
  keySeg.set(key);
  if (iv !== undefined) mod.segments['state.iv'].set(iv);
  if (dir === 'encrypt' || !useDec) mod.encryptInit(key.length);
  else mod.decryptInit(key.length);
};

const aesInitCtr = (
  mod: any,
  key: Uint8Array,
  nonce: Uint8Array | undefined,
  dir: 'encrypt' | 'decrypt'
) => {
  const keySeg = mod.segments['state.key'];
  keySeg.set(key);
  if (nonce !== undefined) mod.segments['state.nonce'].set(nonce);
  if (dir === 'encrypt') mod.encryptInit(key.length);
  else mod.decryptInit(key.length);
};

export const ecb: CipherDef<TYPES.AES_ECB> = {
  blockLen: 16,
  padding: true,
  lengthErrorEnc: AES_LEN_ENC,
  lengthErrorDec: AES_LEN_DEC,
  padError: AES_PAD_BAD,
  emptyError: AES_PAD_EMPTY,
  validate: (key) => {
    aesKey(key);
  },
  init: (mod, dir, key, opts) => {
    aesInit(mod, key, undefined, dir, true);
    const o = opts as CipherOpts | undefined;
    return { disablePadding: !!o?.disablePadding };
  },
};

export const cbc: CipherDef<TYPES.AES_CBC> = {
  blockLen: 16,
  nonceLength: 16,
  padding: true,
  lengthErrorEnc: AES_LEN_ENC,
  lengthErrorDec: AES_LEN_DEC,
  padError: AES_PAD_BAD,
  emptyError: AES_PAD_EMPTY,
  validate: (key, iv) => {
    aesKey(key);
    if (iv !== undefined) abytes(iv as Uint8Array, 16, 'iv');
  },
  init: (mod, dir, key, iv, opts) => {
    aesInit(mod, key, iv as Uint8Array, dir, true);
    const o = opts as CipherOpts | undefined;
    return { disablePadding: !!o?.disablePadding };
  },
};

export const cfb: CipherDef<TYPES.AES_CFB> = {
  blockLen: 16,
  nonceLength: 16,
  noOverlap: true,
  validate: (key, iv) => {
    aesKey(key);
    if (iv !== undefined) abytes(iv as Uint8Array, 16, 'iv');
  },
  init: (mod, dir, key, iv) => {
    aesInit(mod, key, iv as Uint8Array, dir, false);
  },
};

export const ofb: CipherDef<TYPES.AES_OFB> = {
  blockLen: 16,
  nonceLength: 16,
  validate: (key, iv) => {
    aesKey(key);
    if (iv !== undefined) abytes(iv as Uint8Array, 16, 'iv');
  },
  init: (mod, dir, key, iv) => {
    aesInit(mod, key, iv as Uint8Array, dir, false);
  },
};

export const ctr: CipherDef<TYPES.AES_CTR> = {
  blockLen: 16,
  nonceLength: 16,
  validate: (key, nonce) => {
    aesKey(key);
    if (nonce !== undefined) abytes(nonce as Uint8Array, 16, 'nonce');
  },
  init: (mod, dir, key, nonce) => {
    aesInitCtr(mod, key, nonce as Uint8Array, dir);
  },
};

const splitLen = (len: number) => {
  const v = BigInt(len);
  return [Number(v & 0xffffffffn), Number((v >> 32n) & 0xffffffffn)];
};

const streamBlocks = (
  mod: any,
  data: Uint8Array,
  blockLen: number,
  run: (blocks: number, isLast: number, left: number) => void
) => {
  const buffer = mod.segments.buffer as Uint8Array;
  const maxBlocks = Math.floor(buffer.length / blockLen);
  let pos = 0;
  while (pos < data.length) {
    const remaining = data.length - pos;
    const blocks = Math.min(maxBlocks, Math.ceil(remaining / blockLen));
    const take = Math.min(remaining, blocks * blockLen);
    const left = blocks * blockLen - take;
    if (take) buffer.set(data.subarray(pos, pos + take), 0);
    if (left) buffer.fill(0, take, take + left);
    run(blocks, remaining <= maxBlocks * blockLen ? 1 : 0, left);
    buffer.fill(0, 0, blocks * blockLen);
    pos += take;
  }
};
const aadBlocks = (mod: any, data: Uint8Array) => {
  streamBlocks(mod, data, 16, (blocks, isLast, left) => {
    mod.aadBlocks(blocks, isLast, left);
  });
};
export const gcm: CipherDef<TYPES.AES_GCM> = {
  blockLen: 16,
  nonceLength: 12,
  tagLength: 16,
  varSizeNonce: true,
  noOutput: true,
  validate: (key, nonce, aad) => {
    const iv = nonce as Uint8Array;
    abytes(iv, undefined, 'nonce');
    if (iv.length < 8) throw new Error('aes/gcm: invalid nonce length');
    aesKey(key);
    if (aad !== undefined) abytes(aad as Uint8Array, undefined, 'AAD');
  },
  init: (mod, dir, key, nonce, aad) => {
    const iv = nonce as Uint8Array;
    const aadBytes = aad as Uint8Array | undefined;
    mod.segments['state.key'].set(key);
    if (iv.length === 12) {
      mod.segments['state.nonce'].set(iv);
    }
    const [aadLo, aadHi] = splitLen(aadBytes ? aadBytes.length : 0);
    const nonceBits = iv.length === 12 ? [0, 0] : splitLen(iv.length * 8);
    if (dir === 'encrypt')
      mod.encryptInit(key.length, iv.length, nonceBits[0], nonceBits[1], aadLo, aadHi);
    else mod.decryptInit(key.length, iv.length, nonceBits[0], nonceBits[1], aadLo, aadHi);
    mod.aadInit();
    if (iv.length !== 12) {
      aadBlocks(mod, iv);
      mod.nonceFinish(nonceBits[0], nonceBits[1]);
    }
    if (aadBytes && aadBytes.length) {
      aadBlocks(mod, aadBytes);
    }
  },
  getTag: (mod) => {
    mod.tagFinish();
    return mod.segments['state.tag'].subarray(0, 16);
  },
};

export const gcmsiv: CipherDef<TYPES.AES_GCMSIV> = /* @__PURE__ */ (() => {
  const GCMSIV_AAD = /* @__PURE__ */ limit('AAD', 0, 2 ** 36);
  const GCMSIV_PLAIN = /* @__PURE__ */ limit('plaintext', 0, 2 ** 36);
  const GCMSIV_CIPHER = /* @__PURE__ */ limit('ciphertext', 16, 2 ** 36 + 16);
  const GCMSIV_NONCE = /* @__PURE__ */ limit('nonce', 12, 12);
  return {
    blockLen: 16,
    nonceLength: 12,
    tagLength: 16,
    varSizeNonce: true,
    noOutput: true,
    noStream: true,
    multiPass: 2,
    multiPassResult: { encrypt: false, decrypt: true },
    multiPassOut: { decrypt: 0 },
    lengthLimitEnc: (len) => GCMSIV_PLAIN(len),
    lengthLimitDec: (len) => GCMSIV_CIPHER(len),
    validate: (key, nonce, aad) => {
      const iv = nonce as Uint8Array;
      const aadBytes = aad as Uint8Array | undefined;
      abytes(iv, undefined, 'nonce');
      aesKey(key);
      GCMSIV_NONCE(iv.length);
      if (aadBytes) {
        abytes(aadBytes, undefined, 'AAD');
        GCMSIV_AAD(aadBytes.length);
      }
    },
    init: (mod, dir, key, nonce, aad) => {
      const iv = nonce as Uint8Array;
      const aadBytes = aad as Uint8Array | undefined;
      mod.segments['state.key'].set(key);
      mod.segments['state.nonce'].set(iv);
      const [aadLo, aadHi] = splitLen(aadBytes ? aadBytes.length : 0);
      if (dir === 'encrypt') mod.encryptInit(key.length, aadLo, aadHi);
      else mod.decryptInit(key.length, aadLo, aadHi);
      if (aadBytes && aadBytes.length) aadBlocks(mod, aadBytes);
    },
    getTag: (mod) => mod.segments['state.tag'].subarray(0, 16),
  };
})();

export const aessiv: CipherDef<TYPES.AES_SIV> = {
  blockLen: 16,
  tagLength: 16,
  tagLeft: true,
  noStream: true,
  multiPass: 2,
  multiPassResult: { encrypt: false, decrypt: true },
  multiPassOut: { decrypt: 0 },
  validate: (_key, ...aadList) => {
    const aad = aadList as Uint8Array[];
    if (aad.length > 126)
      throw new Error('"AAD" number of elements must be less than or equal to 126');
    const key = _key as Uint8Array;
    abytes(key, undefined, 'aes key');
    if (key.length !== 32 && key.length !== 48 && key.length !== 64) {
      throw new Error('"aes key" expected Uint8Array of length 32/48/64, got length=' + key.length);
    }
    for (const a of aad) abytes(a);
  },
  init: (mod, dir, key, ...aadList) => {
    const aad = aadList as Uint8Array[];
    const half = key.length / 2;
    mod.segments['state.key1'].set(key.subarray(0, half));
    mod.segments['state.key'].set(key.subarray(half));
    if (dir === 'encrypt') mod.encryptInit(half);
    else mod.decryptInit(half);
    for (const a of aad) {
      if (a.length) aadBlocks(mod, a);
      else mod.aadBlocks(0, 1, 0);
    }
  },
  getTag: (mod) => mod.segments['state.tag'].subarray(0, 16),
};

const AESKW_PLAIN = 'invalid plaintext length';
const AESKW_CIPHER = 'invalid ciphertext length';
const AESKW_SHORT = '8-byte keys not allowed in AESKW, use AESKWP instead';
const AESKW_PLAIN_4G = 'plaintext should be less than 4gb';
const AESKW_CIPHER_4G = 'ciphertext should be less than 4gb';
const aeskwInit = (mod: any, dir: 'encrypt' | 'decrypt', key: Uint8Array) => {
  mod.segments['state.key'].set(key);
  if (dir === 'encrypt') mod.encryptInit(key.length);
  else mod.decryptInit(key.length);
};
const kwPlainLimit = (len: number) => {
  if (len >= 2 ** 32) throw new Error(AESKW_PLAIN_4G);
  if (len === 8) throw new Error(AESKW_SHORT);
  if (!len || len % 8 !== 0) throw new Error(AESKW_PLAIN);
};
const kwCipherLimit = (len: number) => {
  if (len - 8 >= 2 ** 32) throw new Error(AESKW_CIPHER_4G);
  if (len % 8 !== 0 || len < 24) throw new Error(AESKW_CIPHER);
};
const kwpPlainLimit = (len: number) => {
  if (len >= 2 ** 32) throw new Error(AESKW_PLAIN_4G);
  if (!len) throw new Error(AESKW_PLAIN);
};
const kwpCipherLimit = (len: number) => {
  if (len - 8 >= 2 ** 32) throw new Error(AESKW_CIPHER_4G);
  if (len < 16) throw new Error(AESKW_CIPHER);
};

export const aeskw: CipherDef<TYPES.AES_KW> = {
  blockLen: 8,
  paddingLeft: 8,
  noStream: true,
  noOutput: true,
  padError: 'integrity check failed',
  multiPass: 6,
  multiPassResult: true,
  validate: (key) => {
    aesKey(key);
  },
  lengthLimitEnc: kwPlainLimit,
  lengthLimitDec: kwCipherLimit,
  init: (mod, dir, key) => {
    aeskwInit(mod, dir, key);
  },
};

export const aeskwp: CipherDef<TYPES.AES_KWP> = {
  blockLen: 8,
  paddingLeft: 8,
  padding: true,
  padFull: false,
  noStream: true,
  noOutput: true,
  padError: 'integrity check failed',
  multiPass: 6,
  multiPassResult: true,
  validate: (key) => {
    aesKey(key);
  },
  lengthLimitEnc: kwpPlainLimit,
  lengthLimitDec: kwpCipherLimit,
  init: (mod, dir, key) => {
    aeskwInit(mod, dir, key);
  },
};

// NOTE: safe for tree-shaking since used only in building process
// prettier-ignore
const defs = {
  ctr, cbc, ofb, cfb, ecb, gcm, gcmsiv, aessiv, aeskw, aeskwp, // AES
  salsa20, xsalsa20, chacha8, chacha12, chacha20, chacha20orig, xchacha20, // ARX
  chacha20poly1305, xchacha20poly1305, xsalsa20poly1305 // ARX AED
} as const satisfies Record<string, CipherDef<any>>;

// Map each name to module
const MOD_OF = {
  salsa20: 'salsa20',
  xsalsa20: 'salsa20',
  chacha8: 'chacha8',
  chacha12: 'chacha12',
  chacha20: 'chacha20',
  chacha20orig: 'chacha20',
  xchacha20: 'chacha20',
  chacha20poly1305: 'chacha_poly1305',
  xchacha20poly1305: 'chacha_poly1305',
  xsalsa20poly1305: 'salsa_poly1305',
  ctr: 'aes_ctr',
  cbc: 'aes_cbc',
  cfb: 'aes_cfb',
  ecb: 'aes_ecb',
  gcm: 'aes_gcm',
  gcmsiv: 'aes_gcmsiv',
  aessiv: 'aes_siv',
  aeskw: 'aes_kw',
  aeskwp: 'aes_kwp',
  ofb: 'aes_ofb',
} as const satisfies { [K in keyof typeof defs & string]: Modules };
// Verifies that definition actually can be used with module
function buildDefinitions<
  D extends Record<string, CipherDef<any>>,
  M extends { [K in keyof D]: Modules },
>(defs: D, modOf: M) {
  type Pair<K extends keyof D> = { mod: M[K]; def: D[K] };
  const out = {} as { [K in keyof D]: Pair<K> };
  for (const k in defs) out[k] = { mod: modOf[k], def: defs[k] } as Pair<typeof k>;
  return out;
}
export const Definitions = /* @__PURE__ */ buildDefinitions(defs, MOD_OF);
