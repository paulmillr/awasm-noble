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
  type TArg,
  type TRet,
} from './utils.ts';
type WebHash<Opts = any> = TRet<HashInstance<Opts>> & {
  isSupported: () => Promise<boolean>;
  webCryptoName: string;
};
type WebCipher = TRet<CipherFactory> & { isSupported: () => Promise<boolean> };

const subtleMaybe = () => {
  const cr = typeof globalThis === 'object' ? (globalThis as any).crypto : undefined;
  return typeof cr?.subtle === 'object' && cr.subtle ? cr.subtle : undefined;
};
const subtle = () => {
  const sb = subtleMaybe();
  if (sb) return sb;
  throw new Error('crypto.subtle must be defined');
};

// Cache WebCrypto support probes per process; runtime crypto availability is treated as stable.
const probeCache = new Map<string, Promise<boolean>>();
const probe = (name: string, fn: () => Promise<boolean>) => {
  let p = probeCache.get(name);
  if (!p) {
    // isSupported() is a boolean gate, so backend probe failures are treated as unsupported.
    p = fn().catch(() => false);
    probeCache.set(name, p);
  }
  return p;
};
const probeDigest = (name: string) =>
  probe(`digest:${name}`, async () => {
    const sb = subtleMaybe();
    if (!sb) return false;
    // One byte is valid for supported SHA digests; this checks availability, not known-answer output.
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
const getCryptParams = (algo: BlockMode, nonce: TArg<Uint8Array>, aad?: TArg<Uint8Array>) => {
  if (algo === mode.CBC) return { name: algo, iv: nonce };
  // Use the full AES counter block so WebCrypto CTR matches the sync ctr() wrapper on low-64 carry.
  if (algo === mode.CTR) return { name: mode.CTR, counter: nonce, length: 128 };
  if (algo === mode.GCM) {
    // WebCrypto defaults AES-GCM tags to 128 bits; the factory exposes def.tagLength separately.
    return aad ? { name: algo, iv: nonce, additionalData: aad } : { name: algo, iv: nonce };
  }
  throw new Error('unknown block mode');
};
const getKeyParams = (algo: BlockMode, key: TArg<Uint8Array>) =>
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

const toKdfInput = (data: TArg<KDFInput>, label: string) => {
  const buf = kdfInputToBytes(data, label);
  // Track ownership so UTF-8 temporaries can be wiped without clearing caller-owned byte arrays.
  return { buf, borrowed: typeof data !== 'string' };
};
const ZERO = /* @__PURE__ */ Uint8Array.of();

// RFC 5869 absent salt is HashLen zeros; HMAC pads empty and all-zero short keys identically.
const hkdfSalt = (salt: TArg<Uint8Array | undefined>) => salt || ZERO;
// RFC 5869 permits omitted info as the zero-length context string.
const hkdfInfo = (info: TArg<Uint8Array | undefined>) => info || ZERO;

const keepIfBorrowed = (buf: TArg<Uint8Array>, borrowed: boolean) => {
  if (!borrowed) clean(buf);
};
const restoreKdf = (...items: TArg<Array<{ buf: Uint8Array; borrowed: boolean }>>) => {
  for (const i of items) keepIfBorrowed(i.buf, i.borrowed);
};

const hkdfDerive = async (
  webHash: string,
  ikm: TArg<Uint8Array>,
  salt: TArg<Uint8Array | undefined>,
  info: TArg<Uint8Array | undefined>,
  length: number
): Promise<TRet<Uint8Array>> => {
  const wkey = await subtle().importKey('raw', ikm as BufferSource, 'HKDF', false, ['deriveBits']);
  const opts = { name: 'HKDF', hash: webHash, salt: hkdfSalt(salt), info: hkdfInfo(info) };
  // RFC 5869 caps L at 255*HashLen; rely on WebCrypto deriveBits() to enforce it.
  return new Uint8Array(await subtle().deriveBits(opts, wkey, 8 * length)) as TRet<Uint8Array>;
};
const pbkdf2Derive = async (
  webHash: string,
  password: TArg<Uint8Array>,
  salt: TArg<Uint8Array>,
  c: number,
  dkLen: number
): Promise<TRet<Uint8Array>> => {
  const key = await subtle().importKey('raw', password as BufferSource, 'PBKDF2', false, [
    'deriveBits',
  ]);
  const deriveOpts = { name: 'PBKDF2', salt, iterations: c, hash: webHash };
  // RFC 8018 derives dkLen octets; WebCrypto deriveBits() takes bits and rejects invalid c.
  return new Uint8Array(await subtle().deriveBits(deriveOpts, key, 8 * dkLen)) as TRet<Uint8Array>;
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
const getWebHashName = (hash: TArg<HashInstance<any>>) => {
  ahash(hash);
  if (typeof (hash as any).webCryptoName === 'string') return (hash as any).webCryptoName;
  const name = webHashNames.get(hash as object);
  if (name) return name;
  if (hash.getPlatform() !== 'webcrypto') throw new Error('non-web hash');
  const byDef = webHashNamesByDef.get(hash.getDefinition() as object);
  if (byDef) return byDef;
  throw new Error('non-web hash');
};

const createWebHash = (name: string, def: any): TRet<WebHash> => {
  const supported = () => probeDigest(name);
  const hash = mkHashAsync(
    def,
    {
      hash: async (msg: TArg<Uint8Array>) => {
        abytes(msg);
        return new Uint8Array(await subtle().digest(name, msg as BufferSource)) as TRet<Uint8Array>;
      },
    },
    'webcrypto',
    supported,
    { webCryptoName: name }
  ) as WebHash;
  // HMAC/HKDF/PBKDF2 and shared tests read the public descriptor metadata directly, so the wrapper
  // must expose the same immutable surface as noble-hashes instead of hiding the digest name in maps.
  webHashNames.set(hash as object, name);
  return hash;
};

/** WebCrypto SHA1 (RFC 3174) legacy hash function. */
export const sha1 = /* @__PURE__ */ createWebHash('SHA-1', def_sha1);
/** WebCrypto SHA2-224 hash function from RFC 6234; support is runtime-dependent. */
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

/** WebCrypto HMAC message authentication code from RFC 2104; this wrapper supports one-shot tags only. */
export const hmac: TRet<{
  (
    hash: TArg<HashInstance<any>>,
    key: TArg<Uint8Array>,
    message: TArg<Uint8Array>
  ): Promise<TRet<Uint8Array>>;
  create(hash: TArg<HashInstance<any>>, key: TArg<Uint8Array>): never;
}> = /* @__PURE__ */ (() => {
  const fn = (async (
    hash: TArg<HashInstance<any>>,
    key: TArg<Uint8Array>,
    message: TArg<Uint8Array>
  ): Promise<TRet<Uint8Array>> => {
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
    return new Uint8Array(
      await subtle().sign('HMAC', wkey, message as BufferSource)
    ) as TRet<Uint8Array>;
  }) as typeof hmac;
  fn.create = (_hash: TArg<HashInstance<any>>, _key: TArg<Uint8Array>) => {
    throw new Error('streaming is not supported');
  };
  return fn;
})();

/** WebCrypto HKDF extract-and-expand key derivation from RFC 5869; returns one-shot output bytes. */
export const hkdf = async (
  hash: TArg<HashInstance<any>>,
  ikm: TArg<Uint8Array>,
  salt: TArg<Uint8Array | undefined>,
  info: TArg<Uint8Array | undefined>,
  length: number
): Promise<TRet<Uint8Array>> => {
  const webHash = getWebHashName(hash);
  abytes(ikm, undefined, 'ikm');
  anumber(length, 'length');
  if (salt !== undefined) abytes(salt, undefined, 'salt');
  if (info !== undefined) abytes(info, undefined, 'info');
  return hkdfDerive(webHash, ikm, salt, info, length);
};

const pbkdf2Async = async (
  hash: TArg<HashInstance<any>>,
  password: TArg<KDFInput>,
  salt: TArg<KDFInput>,
  opts: TArg<Pbkdf2Opts>
) => {
  const webHash = getWebHashName(hash);
  const _opts = checkOpts({ dkLen: 32 }, opts);
  const { c, dkLen } = _opts;
  anumber(c, 'c');
  anumber(dkLen, 'dkLen');
  // RFC 8018 §5.2 defines dkLen as a positive integer.
  if (dkLen < 1) throw new Error('"dkLen" must be >= 1');
  const _password = toKdfInput(password, 'password');
  const _salt = toKdfInput(salt, 'salt');
  try {
    return await pbkdf2Derive(webHash, _password.buf, _salt.buf, c, dkLen);
  } finally {
    restoreKdf(_password, _salt);
  }
};
type WebPbkdf2 = (hash: TArg<HashInstance<any>>) => {
  (password: TArg<KDFInput>, salt: TArg<KDFInput>, opts: TArg<Pbkdf2Opts>): never;
  async: (
    password: TArg<KDFInput>,
    salt: TArg<KDFInput>,
    opts: TArg<Pbkdf2Opts>
  ) => Promise<TRet<Uint8Array>>;
};
/** WebCrypto PBKDF2-HMAC key-derivation factory from RFC 8018; sync mode is unsupported. */
export const pbkdf2: TRet<WebPbkdf2> = ((hash: TArg<HashInstance<any>>) => {
  const fn = ((_password: TArg<KDFInput>, _salt: TArg<KDFInput>, _opts: TArg<Pbkdf2Opts>) => {
    throw new Error('sync is not supported');
  }) as ReturnType<WebPbkdf2>;
  fn.async = (password: TArg<KDFInput>, salt: TArg<KDFInput>, opts: TArg<Pbkdf2Opts>) =>
    pbkdf2Async(hash, password, salt, opts);
  return fn;
}) as WebPbkdf2;

/** Internal WebCrypto AES hooks; properties stay mutable so runtimes can replace encrypt/decrypt. */
export const utils = {
  encrypt: async (
    key: TArg<Uint8Array>,
    keyParams: any,
    cryptParams: any,
    plaintext: TArg<Uint8Array>
  ): Promise<TRet<Uint8Array>> => {
    const iKey = await subtle().importKey('raw', key as BufferSource, keyParams, true, ['encrypt']);
    return new Uint8Array(
      await subtle().encrypt(cryptParams, iKey, plaintext as BufferSource)
    ) as TRet<Uint8Array>;
  },
  decrypt: async (
    key: TArg<Uint8Array>,
    keyParams: any,
    cryptParams: any,
    ciphertext: TArg<Uint8Array>
  ): Promise<TRet<Uint8Array>> => {
    const iKey = await subtle().importKey('raw', key as BufferSource, keyParams, true, ['decrypt']);
    return new Uint8Array(
      await subtle().decrypt(cryptParams, iKey, ciphertext as BufferSource)
    ) as TRet<Uint8Array>;
  },
};

const gen = (algo: BlockMode, nonceLength: number, def: any): TRet<WebCipher> =>
  mkCipherAsync(
    def,
    (key: TArg<Uint8Array>, ...args: unknown[]) => {
      const nonce = args[0] as TArg<Uint8Array>;
      const aad = args[1] as TArg<Uint8Array> | undefined;
      abytes(key, undefined, 'key');
      // WebCrypto AES-GCM accepts 12-byte IVs and, in some runtimes, longer non-12-byte IVs.
      // Local validation follows def.varSizeNonce, so shorter sync-GCM IVs may still be rejected by backend.
      abytes(nonce, def.varSizeNonce ? undefined : nonceLength, 'nonce');
      if (aad !== undefined) abytes(aad, undefined, 'aad');
      const keyParams = getKeyParams(algo, key);
      const cryptParams = getCryptParams(algo, nonce, aad);
      let consumed = false;
      return {
        encrypt: async (plaintext: TArg<Uint8Array>) => {
          abytes(plaintext, undefined, 'plaintext');
          if (consumed) throw new Error('Cannot encrypt() twice with same key / nonce');
          consumed = true;
          return utils.encrypt(key, keyParams, cryptParams, plaintext);
        },
        decrypt: async (ciphertext: TArg<Uint8Array>) => {
          abytes(ciphertext, undefined, 'ciphertext');
          return utils.decrypt(key, keyParams, cryptParams, ciphertext);
        },
      };
    },
    'webcrypto',
    // Real AES wrappers derive `{length: key.length * 8}` and accept AES-192, so the support
    // probe must try 24-byte keys too instead of treating AES-192-only runtimes as unsupported.
    () => probeCipher(algo, [16, 24, 32], nonceLength)
  ) as WebCipher;

/** WebCrypto AES-CBC cipher from NIST SP 800-38A; callers must supply an unpredictable 16-byte IV. */
export const cbc = /* @__PURE__ */ gen(/* @__PURE__ */ (() => mode.CBC)(), 16, def_cbc);
/** WebCrypto AES-CTR mode from NIST SP 800-38A; callers must supply a unique 16-byte initial counter block per key. */
export const ctr = /* @__PURE__ */ gen(/* @__PURE__ */ (() => mode.CTR)(), 16, def_ctr);
/**
 * WebCrypto AES-GCM authenticated cipher from NIST SP 800-38D.
 * Returns ciphertext with a 16-byte tag, requires unique IVs per key, and leaves
 * nonce-shape enforcement beyond raw bytes to the backend.
 */
export const gcm = /* @__PURE__ */ gen(/* @__PURE__ */ (() => mode.GCM)(), 12, def_gcm);
