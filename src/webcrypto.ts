/**
 * Small wrappers over native WebCrypto.
 * @module
 */
import { mkCipherAsync, type CipherFactory } from './ciphers-abstract.ts';
import { cbc as def_cbc, ctr as def_ctr, gcm as def_gcm } from './ciphers.ts';
import { mkHashAsync, type HashInstance } from './hashes-abstract.ts';
import {
  sha1 as def_sha1,
  sha224 as def_sha224,
  sha256 as def_sha256,
  sha384 as def_sha384,
  sha3_256 as def_sha3_256,
  sha3_384 as def_sha3_384,
  sha3_512 as def_sha3_512,
  sha512 as def_sha512,
} from './hashes.ts';
import type { Pbkdf2Opts } from './kdf.ts';
import {
  abytes,
  ahash,
  anumber,
  checkOpts,
  clean,
  kdfInputToBytes,
  type KDFInput,
} from './utils.ts';
type WebHash<Opts = any> = HashInstance<Opts> & { isSupported: () => Promise<boolean> };
type WebCipher = CipherFactory & { isSupported: () => Promise<boolean> };

const subtleMaybe = () => {
  const cr = typeof globalThis === 'object' ? (globalThis as any).crypto : undefined;
  return typeof cr?.subtle === 'object' && cr.subtle ? cr.subtle : undefined;
};
const subtle = () => {
  const sb = subtleMaybe();
  if (sb) return sb;
  throw new Error('crypto.subtle must be defined');
};

const probeCache = new Map<string, Promise<boolean>>();
const probe = (name: string, fn: () => Promise<boolean>) => {
  let p = probeCache.get(name);
  if (!p) {
    p = fn().catch(() => false);
    probeCache.set(name, p);
  }
  return p;
};
const probeDigest = (name: string) =>
  probe(`digest:${name}`, async () => {
    const sb = subtleMaybe();
    if (!sb) return false;
    const data = new Uint8Array(1);
    try {
      await sb.digest(name, data);
      return true;
    } finally {
      clean(data);
    }
  });

const mode = {
  CBC: 'AES-CBC',
  CTR: 'AES-CTR',
  GCM: 'AES-GCM',
} as const;
type BlockMode = (typeof mode)[keyof typeof mode];
const getCryptParams = (algo: BlockMode, nonce: Uint8Array, aad?: Uint8Array) => {
  if (algo === mode.CBC) return { name: algo, iv: nonce };
  if (algo === mode.CTR) return { name: mode.CTR, counter: nonce, length: 64 };
  if (algo === mode.GCM) {
    return aad ? { name: algo, iv: nonce, additionalData: aad } : { name: algo, iv: nonce };
  }
  throw new Error('unknown block mode');
};
const getKeyParams = (algo: BlockMode, key: Uint8Array) =>
  algo.startsWith('AES-') ? { name: algo, length: key.length * 8 } : { name: algo };
const probeCipher = (algo: BlockMode, keyLens: number[], nonceLen: number) =>
  probe(`cipher:${algo}`, async () => {
    const sb = subtleMaybe();
    if (!sb) return false;
    const nonce = new Uint8Array(nonceLen);
    const data = new Uint8Array(32);
    try {
      const params = getCryptParams(algo, nonce);
      for (const keyLen of keyLens) {
        const key = new Uint8Array(keyLen);
        try {
          const iKey = await sb.importKey(
            'raw',
            key as BufferSource,
            getKeyParams(algo, key),
            false,
            ['encrypt', 'decrypt']
          );
          const enc = await sb.encrypt(params, iKey, data as BufferSource);
          await sb.decrypt(params, iKey, enc);
          return true;
        } catch {
        } finally {
          clean(key);
        }
      }
      return false;
    } finally {
      clean(nonce, data);
    }
  });

const toKdfInput = (data: KDFInput, label: string) => {
  const buf = kdfInputToBytes(data, label);
  return { buf, borrowed: typeof data !== 'string' };
};
const ZERO = /* @__PURE__ */ Uint8Array.of();

const hkdfSalt = (salt: Uint8Array | undefined) => salt || ZERO;
const hkdfInfo = (info: Uint8Array | undefined) => info || ZERO;

const keepIfBorrowed = (buf: Uint8Array, borrowed: boolean) => {
  if (!borrowed) clean(buf);
};
const restoreKdf = (...items: Array<{ buf: Uint8Array; borrowed: boolean }>) => {
  for (const i of items) keepIfBorrowed(i.buf, i.borrowed);
};

const hkdfDerive = async (
  webHash: string,
  ikm: Uint8Array,
  salt: Uint8Array | undefined,
  info: Uint8Array | undefined,
  length: number
) => {
  const wkey = await subtle().importKey('raw', ikm as BufferSource, 'HKDF', false, ['deriveBits']);
  const opts = { name: 'HKDF', hash: webHash, salt: hkdfSalt(salt), info: hkdfInfo(info) };
  return new Uint8Array(await subtle().deriveBits(opts, wkey, 8 * length));
};
const pbkdf2Derive = async (
  webHash: string,
  password: Uint8Array,
  salt: Uint8Array,
  c: number,
  dkLen: number
) => {
  const key = await subtle().importKey('raw', password as BufferSource, 'PBKDF2', false, [
    'deriveBits',
  ]);
  const deriveOpts = { name: 'PBKDF2', salt, iterations: c, hash: webHash };
  return new Uint8Array(await subtle().deriveBits(deriveOpts, key, 8 * dkLen));
};
const webHashNames = new WeakMap<object, string>();
const webHashNamesByDef = new Map<object, string>([
  [def_sha1 as object, 'SHA-1'],
  [def_sha224 as object, 'SHA-224'],
  [def_sha256 as object, 'SHA-256'],
  [def_sha384 as object, 'SHA-384'],
  [def_sha512 as object, 'SHA-512'],
  [def_sha3_256 as object, 'SHA3-256'],
  [def_sha3_384 as object, 'SHA3-384'],
  [def_sha3_512 as object, 'SHA3-512'],
]);
const getWebHashName = (hash: HashInstance<any>) => {
  ahash(hash);
  const name = webHashNames.get(hash as object);
  if (name) return name;
  if (hash.getPlatform() !== 'webcrypto') throw new Error('non-web hash');
  const byDef = webHashNamesByDef.get(hash.getDefinition() as object);
  if (byDef) return byDef;
  throw new Error('non-web hash');
};

const createWebHash = (name: string, def: any): WebHash => {
  const supported = () => probeDigest(name);
  const hash = mkHashAsync(
    def,
    {
      hash: async (msg: Uint8Array) => {
        abytes(msg);
        return new Uint8Array(await subtle().digest(name, msg as BufferSource));
      },
    },
    'webcrypto',
    supported
  ) as WebHash;
  webHashNames.set(hash as object, name);
  return hash;
};

/** WebCrypto SHA1 (RFC 3174) legacy hash function. */
export const sha1 = /* @__PURE__ */ createWebHash('SHA-1', def_sha1);
/** WebCrypto SHA2-224 hash function. */
export const sha224 = /* @__PURE__ */ createWebHash('SHA-224', def_sha224);
/** WebCrypto SHA2-256 hash function from RFC 4634. */
export const sha256 = /* @__PURE__ */ createWebHash('SHA-256', def_sha256);
/** WebCrypto SHA2-384 hash function from RFC 4634. */
export const sha384 = /* @__PURE__ */ createWebHash('SHA-384', def_sha384);
/** WebCrypto SHA2-512 hash function from RFC 4634. */
export const sha512 = /* @__PURE__ */ createWebHash('SHA-512', def_sha512);
/** WebCrypto SHA3-256 hash function (runtime-dependent / experimental). */
export const sha3_256 = /* @__PURE__ */ createWebHash('SHA3-256', def_sha3_256);
/** WebCrypto SHA3-384 hash function (runtime-dependent / experimental). */
export const sha3_384 = /* @__PURE__ */ createWebHash('SHA3-384', def_sha3_384);
/** WebCrypto SHA3-512 hash function (runtime-dependent / experimental). */
export const sha3_512 = /* @__PURE__ */ createWebHash('SHA3-512', def_sha3_512);

export const hmac: {
  (hash: HashInstance<any>, key: Uint8Array, message: Uint8Array): Promise<Uint8Array>;
  create(hash: HashInstance<any>, key: Uint8Array): never;
} = /* @__PURE__ */ (() => {
  const fn = (async (
    hash: HashInstance<any>,
    key: Uint8Array,
    message: Uint8Array
  ): Promise<Uint8Array> => {
    const webHash = getWebHashName(hash);
    abytes(key, undefined, 'key');
    abytes(message, undefined, 'message');
    const wkey = await subtle().importKey(
      'raw',
      key as BufferSource,
      { name: 'HMAC', hash: webHash },
      false,
      ['sign']
    );
    return new Uint8Array(await subtle().sign('HMAC', wkey, message as BufferSource));
  }) as typeof hmac;
  fn.create = (_hash: HashInstance<any>, _key: Uint8Array) => {
    throw new Error('streaming is not supported');
  };
  return fn;
})();

export const hkdf = async (
  hash: HashInstance<any>,
  ikm: Uint8Array,
  salt: Uint8Array | undefined,
  info: Uint8Array | undefined,
  length: number
) => {
  const webHash = getWebHashName(hash);
  abytes(ikm, undefined, 'ikm');
  anumber(length, 'length');
  if (salt !== undefined) abytes(salt, undefined, 'salt');
  if (info !== undefined) abytes(info, undefined, 'info');
  return hkdfDerive(webHash, ikm, salt, info, length);
};

const pbkdf2Async = async (
  hash: HashInstance<any>,
  password: KDFInput,
  salt: KDFInput,
  opts: Pbkdf2Opts
) => {
  const webHash = getWebHashName(hash);
  const _opts = checkOpts({ dkLen: 32 }, opts);
  const { c, dkLen } = _opts;
  anumber(c, 'c');
  anumber(dkLen, 'dkLen');
  const _password = toKdfInput(password, 'password');
  const _salt = toKdfInput(salt, 'salt');
  try {
    return await pbkdf2Derive(webHash, _password.buf, _salt.buf, c, dkLen);
  } finally {
    restoreKdf(_password, _salt);
  }
};
type WebPbkdf2 = (hash: HashInstance<any>) => {
  (password: KDFInput, salt: KDFInput, opts: Pbkdf2Opts): never;
  async: (password: KDFInput, salt: KDFInput, opts: Pbkdf2Opts) => Promise<Uint8Array>;
};
export const pbkdf2: WebPbkdf2 = ((hash: HashInstance<any>) => {
  const fn = ((_password: KDFInput, _salt: KDFInput, _opts: Pbkdf2Opts) => {
    throw new Error('sync is not supported');
  }) as ReturnType<WebPbkdf2>;
  fn.async = (password: KDFInput, salt: KDFInput, opts: Pbkdf2Opts) =>
    pbkdf2Async(hash, password, salt, opts);
  return fn;
}) as WebPbkdf2;

export const utils = {
  encrypt: async (key: Uint8Array, keyParams: any, cryptParams: any, plaintext: Uint8Array) => {
    const iKey = await subtle().importKey('raw', key as BufferSource, keyParams, true, ['encrypt']);
    return new Uint8Array(await subtle().encrypt(cryptParams, iKey, plaintext as BufferSource));
  },
  decrypt: async (key: Uint8Array, keyParams: any, cryptParams: any, ciphertext: Uint8Array) => {
    const iKey = await subtle().importKey('raw', key as BufferSource, keyParams, true, ['decrypt']);
    return new Uint8Array(await subtle().decrypt(cryptParams, iKey, ciphertext as BufferSource));
  },
};

const gen = (algo: BlockMode, nonceLength: number, def: any): WebCipher =>
  mkCipherAsync(
    def,
    (key: Uint8Array, ...args: unknown[]) => {
      const nonce = args[0] as Uint8Array;
      const aad = args[1] as Uint8Array | undefined;
      abytes(key, undefined, 'key');
      abytes(nonce, nonceLength, 'nonce');
      if (aad !== undefined) abytes(aad, undefined, 'aad');
      const keyParams = getKeyParams(algo, key);
      const cryptParams = getCryptParams(algo, nonce, aad);
      let consumed = false;
      return {
        encrypt: async (plaintext: Uint8Array) => {
          abytes(plaintext, undefined, 'plaintext');
          if (consumed) throw new Error('Cannot encrypt() twice with same key / nonce');
          consumed = true;
          return utils.encrypt(key, keyParams, cryptParams, plaintext);
        },
        decrypt: async (ciphertext: Uint8Array) => {
          abytes(ciphertext, undefined, 'ciphertext');
          return utils.decrypt(key, keyParams, cryptParams, ciphertext);
        },
      };
    },
    'webcrypto',
    () => probeCipher(algo, [16, 32], nonceLength)
  ) as WebCipher;

export const cbc = /* @__PURE__ */ gen(/* @__PURE__ */ (() => mode.CBC)(), 16, def_cbc);
export const ctr = /* @__PURE__ */ gen(/* @__PURE__ */ (() => mode.CTR)(), 16, def_ctr);
export const gcm = /* @__PURE__ */ gen(/* @__PURE__ */ (() => mode.GCM)(), 12, def_gcm);
