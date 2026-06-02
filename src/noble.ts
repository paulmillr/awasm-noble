/**
 * Static wrappers over noble-hashes and noble-ciphers.
 * @module
 */
import * as nobleBlake1 from '@noble/hashes/blake1.js';
import * as nobleBlake2 from '@noble/hashes/blake2.js';
import * as nobleBlake3 from '@noble/hashes/blake3.js';
import * as nobleLegacy from '@noble/hashes/legacy.js';
import * as nobleSha2 from '@noble/hashes/sha2.js';
import * as nobleSha3 from '@noble/hashes/sha3.js';
import * as nobleArgon2 from '@noble/hashes/argon2.js';
import * as nobleScrypt from '@noble/hashes/scrypt.js';
import * as nobleAes from '@noble/ciphers/aes.js';
import * as nobleChacha from '@noble/ciphers/chacha.js';
import * as noblePoly from '@noble/ciphers/_poly1305.js';
import * as noblePolyval from '@noble/ciphers/_polyval.js';
import * as nobleSalsa from '@noble/ciphers/salsa.js';
import {
  mkCipherNoble,
  type Cipher,
  type CipherDef,
  type CipherFactory,
} from './ciphers-abstract.ts';
import {
  aeskw as def_aeskw,
  aeskwp as def_aeskwp,
  aessiv as def_aessiv,
  cbc as def_cbc,
  cfb as def_cfb,
  chacha8 as def_chacha8,
  chacha12 as def_chacha12,
  chacha20 as def_chacha20,
  chacha20orig as def_chacha20orig,
  chacha20poly1305 as def_chacha20poly1305,
  ctr as def_ctr,
  ecb as def_ecb,
  gcm as def_gcm,
  gcmsiv as def_gcmsiv,
  ofb as def_ofb,
  salsa20 as def_salsa20,
  xchacha20 as def_xchacha20,
  xchacha20poly1305 as def_xchacha20poly1305,
  xsalsa20 as def_xsalsa20,
  xsalsa20poly1305 as def_xsalsa20poly1305,
} from './ciphers.ts';
import {
  mkHashNoble,
  type HashDef,
  type HashInstance,
  type HashState,
  type HashStream,
  type OutputOpts,
  type HashBatchOpts,
} from './hashes-abstract.ts';
import {
  argon2d as def_argon2d,
  argon2i as def_argon2i,
  argon2id as def_argon2id,
  blake224 as def_blake224,
  blake256 as def_blake256,
  blake384 as def_blake384,
  blake512 as def_blake512,
  blake2b as def_blake2b,
  blake2s as def_blake2s,
  blake3 as def_blake3,
  cmac as def_cmac,
  ghash as def_ghash,
  keccak_224 as def_keccak_224,
  keccak_256 as def_keccak_256,
  keccak_384 as def_keccak_384,
  keccak_512 as def_keccak_512,
  md5 as def_md5,
  poly1305 as def_poly1305,
  polyval as def_polyval,
  ripemd160 as def_ripemd160,
  scrypt as def_scrypt,
  sha1 as def_sha1,
  sha224 as def_sha224,
  sha256 as def_sha256,
  sha384 as def_sha384,
  sha512 as def_sha512,
  sha512_224 as def_sha512_224,
  sha512_256 as def_sha512_256,
  sha3_224 as def_sha3_224,
  sha3_256 as def_sha3_256,
  sha3_384 as def_sha3_384,
  sha3_512 as def_sha3_512,
  shake128 as def_shake128,
  shake128_32 as def_shake128_32,
  shake256 as def_shake256,
  shake256_64 as def_shake256_64,
  type Blake2Opts,
  type Blake3Opts,
  type BlakeOpts,
} from './hashes.ts';
import { mkKDFNoble, type ArgonOpts, type KDF, type ScryptOpts } from './kdf.ts';
import {
  abytes,
  copyBytes,
  isBytes,
  type Asyncify,
  type KDFInput,
  type TArg,
  type TRet,
} from './utils.ts';
export type {
  OutputOpts,
  HashBatchOpts,
  HashState,
  HashStream,
  HashDef,
  HashInstance,
  Cipher,
  CipherDef,
  CipherFactory,
  KDF,
  BlakeOpts,
  Blake2Opts,
  Blake3Opts,
  ScryptOpts,
  ArgonOpts,
  TArg,
  TRet,
  Asyncify,
  KDFInput,
};

type MACOpts = { key: Uint8Array } | Uint8Array;
type SecretBox = (
  key: TArg<Uint8Array>,
  nonce: TArg<Uint8Array>
) => {
  seal: Cipher['encrypt'];
  open: Cipher['decrypt'];
};
const PLATFORM = 'noble';
const hash = <Opts>(def: TArg<HashDef<any, Opts>>, impl: any): TRet<HashInstance<Opts>> =>
  mkHashNoble(def, { hash: impl, create: impl.create }, PLATFORM);
const cipher = (def: TArg<CipherDef<any>>, impl: any): TRet<CipherFactory> =>
  mkCipherNoble(def, impl, PLATFORM);
const key = (opts: TArg<MACOpts | undefined>) =>
  (isBytes(opts) ? opts : opts?.key) as TArg<Uint8Array>;
const mac = <Opts>(
  def: TArg<HashDef<any, Opts>>,
  impl: any,
  stream = true
): TRet<HashInstance<Opts>> =>
  mkHashNoble(
    def as any,
    {
      hash: (msg: TArg<Uint8Array>, opts?: TArg<Opts>) =>
        impl(msg, key(opts as TArg<MACOpts | undefined>)),
      create: stream
        ? (opts?: TArg<Opts>) => impl.create(key(opts as TArg<MACOpts | undefined>))
        : undefined,
    } as any,
    PLATFORM
  ) as TRet<HashInstance<Opts>>;
const xor = (fn: any) => (key: TArg<Uint8Array>, nonce: TArg<Uint8Array>, opts?: any) => {
  const counter = opts?.counter;
  return {
    encrypt: (data: TArg<Uint8Array>, output?: TArg<Uint8Array>) =>
      fn(key, nonce, data, output, counter),
    decrypt: (data: TArg<Uint8Array>, output?: TArg<Uint8Array>) =>
      fn(key, nonce, data, output, counter),
  };
};
const ofbNative = (key: TArg<Uint8Array>, iv: TArg<Uint8Array>) => {
  const xk = nobleAes.unsafe.expandKeyLE(key);
  const init = copyBytes(iv);
  const run = (data: TArg<Uint8Array>) => {
    abytes(data);
    const next = copyBytes(init);
    const out = new Uint8Array(data.length);
    for (let pos = 0; pos < data.length; pos += 16) {
      nobleAes.unsafe.encryptBlock(xk, next);
      const take = Math.min(16, data.length - pos);
      for (let i = 0; i < take; i++) out[pos + i] = data[pos + i] ^ next[i];
    }
    return out as TRet<Uint8Array>;
  };
  return { encrypt: run, decrypt: run };
};

/**
 * Noble BLAKE-224 hash.
 * @param msg - message to hash.
 * @param opts - optional {@link OutputOpts} hash configuration.
 * @returns Hash output bytes.
 * @example
 * ```ts
 * import { blake224 } from '@awasm/noble/noble.js';
 * blake224(new Uint8Array([1, 2, 3]));
 * ```
 */
export const blake224: TRet<HashInstance<BlakeOpts>> = /* @__PURE__ */ hash(
  def_blake224,
  nobleBlake1.blake224
);
/**
 * Noble BLAKE-256 hash.
 * @param msg - message to hash.
 * @param opts - optional {@link OutputOpts} hash configuration.
 * @returns Hash output bytes.
 * @example
 * ```ts
 * import { blake256 } from '@awasm/noble/noble.js';
 * blake256(new Uint8Array([1, 2, 3]));
 * ```
 */
export const blake256: TRet<HashInstance<BlakeOpts>> = /* @__PURE__ */ hash(
  def_blake256,
  nobleBlake1.blake256
);
/**
 * Noble BLAKE-384 hash.
 * @param msg - message to hash.
 * @param opts - optional {@link OutputOpts} hash configuration.
 * @returns Hash output bytes.
 * @example
 * ```ts
 * import { blake384 } from '@awasm/noble/noble.js';
 * blake384(new Uint8Array([1, 2, 3]));
 * ```
 */
export const blake384: TRet<HashInstance<BlakeOpts>> = /* @__PURE__ */ hash(
  def_blake384,
  nobleBlake1.blake384
);
/**
 * Noble BLAKE-512 hash.
 * @param msg - message to hash.
 * @param opts - optional {@link OutputOpts} hash configuration.
 * @returns Hash output bytes.
 * @example
 * ```ts
 * import { blake512 } from '@awasm/noble/noble.js';
 * blake512(new Uint8Array([1, 2, 3]));
 * ```
 */
export const blake512: TRet<HashInstance<BlakeOpts>> = /* @__PURE__ */ hash(
  def_blake512,
  nobleBlake1.blake512
);
/**
 * Noble BLAKE2s hash.
 * @param msg - message to hash.
 * @param opts - optional {@link OutputOpts} hash configuration.
 * @returns Hash output bytes.
 * @example
 * ```ts
 * import { blake2s } from '@awasm/noble/noble.js';
 * blake2s(new Uint8Array([1, 2, 3]));
 * ```
 */
export const blake2s: TRet<HashInstance<Blake2Opts>> = /* @__PURE__ */ hash(
  def_blake2s,
  nobleBlake2.blake2s
);
/**
 * Noble BLAKE2b hash.
 * @param msg - message to hash.
 * @param opts - optional {@link OutputOpts} hash configuration.
 * @returns Hash output bytes.
 * @example
 * ```ts
 * import { blake2b } from '@awasm/noble/noble.js';
 * blake2b(new Uint8Array([1, 2, 3]));
 * ```
 */
export const blake2b: TRet<HashInstance<Blake2Opts>> = /* @__PURE__ */ hash(
  def_blake2b,
  nobleBlake2.blake2b
);
/**
 * Noble BLAKE3 hash.
 * @param msg - message to hash.
 * @param opts - optional {@link OutputOpts} hash configuration.
 * @returns Hash output bytes.
 * @example
 * ```ts
 * import { blake3 } from '@awasm/noble/noble.js';
 * blake3(new Uint8Array([1, 2, 3]));
 * ```
 */
export const blake3: TRet<HashInstance<Blake3Opts>> = /* @__PURE__ */ hash(
  def_blake3,
  nobleBlake3.blake3
);
/**
 * Noble MD5 hash.
 * @param msg - message to hash.
 * @param opts - optional {@link OutputOpts} hash configuration.
 * @returns Hash output bytes.
 * @example
 * ```ts
 * import { md5 } from '@awasm/noble/noble.js';
 * md5(new Uint8Array([1, 2, 3]));
 * ```
 */
export const md5: TRet<HashInstance<undefined>> = /* @__PURE__ */ hash(def_md5, nobleLegacy.md5);
/**
 * Noble RIPEMD-160 hash.
 * @param msg - message to hash.
 * @param opts - optional {@link OutputOpts} hash configuration.
 * @returns Hash output bytes.
 * @example
 * ```ts
 * import { ripemd160 } from '@awasm/noble/noble.js';
 * ripemd160(new Uint8Array([1, 2, 3]));
 * ```
 */
export const ripemd160: TRet<HashInstance<undefined>> = /* @__PURE__ */ hash(
  def_ripemd160,
  nobleLegacy.ripemd160
);
/**
 * Noble SHA1 hash.
 * @param msg - message to hash.
 * @param opts - optional {@link OutputOpts} hash configuration.
 * @returns Hash output bytes.
 * @example
 * ```ts
 * import { sha1 } from '@awasm/noble/noble.js';
 * sha1(new Uint8Array([1, 2, 3]));
 * ```
 */
export const sha1: TRet<HashInstance<undefined>> = /* @__PURE__ */ hash(def_sha1, nobleLegacy.sha1);
/**
 * Noble SHA2-224 hash.
 * @param msg - message to hash.
 * @param opts - optional {@link OutputOpts} hash configuration.
 * @returns Hash output bytes.
 * @example
 * ```ts
 * import { sha224 } from '@awasm/noble/noble.js';
 * sha224(new Uint8Array([1, 2, 3]));
 * ```
 */
export const sha224: TRet<HashInstance<undefined>> = /* @__PURE__ */ hash(
  def_sha224,
  nobleSha2.sha224
);
/**
 * Noble SHA2-256 hash.
 * @param msg - message to hash.
 * @param opts - optional {@link OutputOpts} hash configuration.
 * @returns Hash output bytes.
 * @example
 * ```ts
 * import { sha256 } from '@awasm/noble/noble.js';
 * sha256(new Uint8Array([1, 2, 3]));
 * ```
 */
export const sha256: TRet<HashInstance<undefined>> = /* @__PURE__ */ hash(
  def_sha256,
  nobleSha2.sha256
);
/**
 * Noble SHA2-384 hash.
 * @param msg - message to hash.
 * @param opts - optional {@link OutputOpts} hash configuration.
 * @returns Hash output bytes.
 * @example
 * ```ts
 * import { sha384 } from '@awasm/noble/noble.js';
 * sha384(new Uint8Array([1, 2, 3]));
 * ```
 */
export const sha384: TRet<HashInstance<undefined>> = /* @__PURE__ */ hash(
  def_sha384,
  nobleSha2.sha384
);
/**
 * Noble SHA2-512/224 hash.
 * @param msg - message to hash.
 * @param opts - optional {@link OutputOpts} hash configuration.
 * @returns Hash output bytes.
 * @example
 * ```ts
 * import { sha512_224 } from '@awasm/noble/noble.js';
 * sha512_224(new Uint8Array([1, 2, 3]));
 * ```
 */
export const sha512_224: TRet<HashInstance<undefined>> = /* @__PURE__ */ hash(
  def_sha512_224,
  nobleSha2.sha512_224
);
/**
 * Noble SHA2-512/256 hash.
 * @param msg - message to hash.
 * @param opts - optional {@link OutputOpts} hash configuration.
 * @returns Hash output bytes.
 * @example
 * ```ts
 * import { sha512_256 } from '@awasm/noble/noble.js';
 * sha512_256(new Uint8Array([1, 2, 3]));
 * ```
 */
export const sha512_256: TRet<HashInstance<undefined>> = /* @__PURE__ */ hash(
  def_sha512_256,
  nobleSha2.sha512_256
);
/**
 * Noble SHA2-512 hash.
 * @param msg - message to hash.
 * @param opts - optional {@link OutputOpts} hash configuration.
 * @returns Hash output bytes.
 * @example
 * ```ts
 * import { sha512 } from '@awasm/noble/noble.js';
 * sha512(new Uint8Array([1, 2, 3]));
 * ```
 */
export const sha512: TRet<HashInstance<undefined>> = /* @__PURE__ */ hash(
  def_sha512,
  nobleSha2.sha512
);
/**
 * Noble SHA3-224 hash.
 * @param msg - message to hash.
 * @param opts - optional {@link OutputOpts} hash configuration.
 * @returns Hash output bytes.
 * @example
 * ```ts
 * import { sha3_224 } from '@awasm/noble/noble.js';
 * sha3_224(new Uint8Array([1, 2, 3]));
 * ```
 */
export const sha3_224: TRet<HashInstance<undefined>> = /* @__PURE__ */ hash(
  def_sha3_224,
  nobleSha3.sha3_224
);
/**
 * Noble SHA3-256 hash.
 * @param msg - message to hash.
 * @param opts - optional {@link OutputOpts} hash configuration.
 * @returns Hash output bytes.
 * @example
 * ```ts
 * import { sha3_256 } from '@awasm/noble/noble.js';
 * sha3_256(new Uint8Array([1, 2, 3]));
 * ```
 */
export const sha3_256: TRet<HashInstance<undefined>> = /* @__PURE__ */ hash(
  def_sha3_256,
  nobleSha3.sha3_256
);
/**
 * Noble SHA3-384 hash.
 * @param msg - message to hash.
 * @param opts - optional {@link OutputOpts} hash configuration.
 * @returns Hash output bytes.
 * @example
 * ```ts
 * import { sha3_384 } from '@awasm/noble/noble.js';
 * sha3_384(new Uint8Array([1, 2, 3]));
 * ```
 */
export const sha3_384: TRet<HashInstance<undefined>> = /* @__PURE__ */ hash(
  def_sha3_384,
  nobleSha3.sha3_384
);
/**
 * Noble SHA3-512 hash.
 * @param msg - message to hash.
 * @param opts - optional {@link OutputOpts} hash configuration.
 * @returns Hash output bytes.
 * @example
 * ```ts
 * import { sha3_512 } from '@awasm/noble/noble.js';
 * sha3_512(new Uint8Array([1, 2, 3]));
 * ```
 */
export const sha3_512: TRet<HashInstance<undefined>> = /* @__PURE__ */ hash(
  def_sha3_512,
  nobleSha3.sha3_512
);
/**
 * Noble Keccak-224 hash.
 * @param msg - message to hash.
 * @param opts - optional {@link OutputOpts} hash configuration.
 * @returns Hash output bytes.
 * @example
 * ```ts
 * import { keccak_224 } from '@awasm/noble/noble.js';
 * keccak_224(new Uint8Array([1, 2, 3]));
 * ```
 */
export const keccak_224: TRet<HashInstance<undefined>> = /* @__PURE__ */ hash(
  def_keccak_224,
  nobleSha3.keccak_224
);
/**
 * Noble Keccak-256 hash.
 * @param msg - message to hash.
 * @param opts - optional {@link OutputOpts} hash configuration.
 * @returns Hash output bytes.
 * @example
 * ```ts
 * import { keccak_256 } from '@awasm/noble/noble.js';
 * keccak_256(new Uint8Array([1, 2, 3]));
 * ```
 */
export const keccak_256: TRet<HashInstance<undefined>> = /* @__PURE__ */ hash(
  def_keccak_256,
  nobleSha3.keccak_256
);
/**
 * Noble Keccak-384 hash.
 * @param msg - message to hash.
 * @param opts - optional {@link OutputOpts} hash configuration.
 * @returns Hash output bytes.
 * @example
 * ```ts
 * import { keccak_384 } from '@awasm/noble/noble.js';
 * keccak_384(new Uint8Array([1, 2, 3]));
 * ```
 */
export const keccak_384: TRet<HashInstance<undefined>> = /* @__PURE__ */ hash(
  def_keccak_384,
  nobleSha3.keccak_384
);
/**
 * Noble Keccak-512 hash.
 * @param msg - message to hash.
 * @param opts - optional {@link OutputOpts} hash configuration.
 * @returns Hash output bytes.
 * @example
 * ```ts
 * import { keccak_512 } from '@awasm/noble/noble.js';
 * keccak_512(new Uint8Array([1, 2, 3]));
 * ```
 */
export const keccak_512: TRet<HashInstance<undefined>> = /* @__PURE__ */ hash(
  def_keccak_512,
  nobleSha3.keccak_512
);
/**
 * Noble SHAKE128 XOF hash.
 * @param msg - message to hash.
 * @param opts - optional {@link OutputOpts} hash configuration.
 * @returns Hash output bytes.
 * @example
 * ```ts
 * import { shake128 } from '@awasm/noble/noble.js';
 * shake128(new Uint8Array([1, 2, 3]), { dkLen: 32 });
 * ```
 */
export const shake128: TRet<HashInstance<undefined>> = /* @__PURE__ */ hash(
  def_shake128,
  nobleSha3.shake128
);
/**
 * Noble SHAKE256 XOF hash.
 * @param msg - message to hash.
 * @param opts - optional {@link OutputOpts} hash configuration.
 * @returns Hash output bytes.
 * @example
 * ```ts
 * import { shake256 } from '@awasm/noble/noble.js';
 * shake256(new Uint8Array([1, 2, 3]), { dkLen: 32 });
 * ```
 */
export const shake256: TRet<HashInstance<undefined>> = /* @__PURE__ */ hash(
  def_shake256,
  nobleSha3.shake256
);
/**
 * Noble SHAKE128/32 XOF hash.
 * @param msg - message to hash.
 * @param opts - optional {@link OutputOpts} hash configuration.
 * @returns Hash output bytes.
 * @example
 * ```ts
 * import { shake128_32 } from '@awasm/noble/noble.js';
 * shake128_32(new Uint8Array([1, 2, 3]), { dkLen: 32 });
 * ```
 */
export const shake128_32: TRet<HashInstance<undefined>> = /* @__PURE__ */ hash(
  def_shake128_32,
  nobleSha3.shake128_32
);
/**
 * Noble SHAKE256/64 XOF hash.
 * @param msg - message to hash.
 * @param opts - optional {@link OutputOpts} hash configuration.
 * @returns Hash output bytes.
 * @example
 * ```ts
 * import { shake256_64 } from '@awasm/noble/noble.js';
 * shake256_64(new Uint8Array([1, 2, 3]), { dkLen: 64 });
 * ```
 */
export const shake256_64: TRet<HashInstance<undefined>> = /* @__PURE__ */ hash(
  def_shake256_64,
  nobleSha3.shake256_64
);
// noble-ciphers MAC streams do not expose `_cloneInto`, so keep them on the one-shot path.
/**
 * Noble Poly1305 MAC.
 * @param msg - message to authenticate.
 * @param opts - optional {@link OutputOpts} hash configuration and MAC key options.
 * @returns Authentication tag bytes.
 * @example
 * ```ts
 * import { poly1305 } from '@awasm/noble/noble.js';
 * poly1305(new Uint8Array([1, 2, 3]), { key: new Uint8Array(32) });
 * ```
 */
export const poly1305: TRet<HashInstance<MACOpts>> = /* @__PURE__ */ mac(
  def_poly1305,
  noblePoly.poly1305,
  false
);
/**
 * Noble AES-CMAC.
 * @param msg - message to authenticate.
 * @param opts - optional {@link OutputOpts} hash configuration and MAC key options.
 * @returns Authentication tag bytes.
 * @example
 * ```ts
 * import { cmac } from '@awasm/noble/noble.js';
 * cmac(new Uint8Array([1, 2, 3]), { key: new Uint8Array(16) });
 * ```
 */
export const cmac: TRet<HashInstance<MACOpts>> = /* @__PURE__ */ mac(
  def_cmac,
  nobleAes.cmac,
  false
);
/**
 * Noble GHASH MAC.
 * @param msg - message to authenticate.
 * @param opts - optional {@link OutputOpts} hash configuration and MAC key options.
 * @returns Authentication tag bytes.
 * @example
 * ```ts
 * import { ghash } from '@awasm/noble/noble.js';
 * ghash(new Uint8Array([1, 2, 3]), { key: new Uint8Array(16) });
 * ```
 */
export const ghash: TRet<HashInstance<MACOpts>> = /* @__PURE__ */ mac(
  def_ghash,
  noblePolyval.ghash,
  false
);
/**
 * Noble Polyval MAC.
 * @param msg - message to authenticate.
 * @param opts - optional {@link OutputOpts} hash configuration and MAC key options.
 * @returns Authentication tag bytes.
 * @example
 * ```ts
 * import { polyval } from '@awasm/noble/noble.js';
 * polyval(new Uint8Array([1, 2, 3]), { key: new Uint8Array(16) });
 * ```
 */
export const polyval: TRet<HashInstance<MACOpts>> = /* @__PURE__ */ mac(
  def_polyval,
  noblePolyval.polyval,
  false
);

/**
 * Noble AES-CTR cipher factory.
 * @param key - secret key bytes.
 * @param args - algorithm-specific extra arguments such as nonce bytes.
 * @returns Configured cipher instance.
 * @example
 * ```ts
 * import { ctr } from '@awasm/noble/noble.js';
 * ctr(new Uint8Array(16), new Uint8Array(16));
 * ```
 */
export const ctr: TRet<CipherFactory> = /* @__PURE__ */ cipher(def_ctr, nobleAes.ctr);
/**
 * Noble AES-CBC cipher factory.
 * @param key - secret key bytes.
 * @param args - algorithm-specific extra arguments such as IV bytes.
 * @returns Configured cipher instance.
 * @example
 * ```ts
 * import { cbc } from '@awasm/noble/noble.js';
 * cbc(new Uint8Array(16), new Uint8Array(16));
 * ```
 */
export const cbc: TRet<CipherFactory> = /* @__PURE__ */ cipher(def_cbc, nobleAes.cbc);
/**
 * Noble AES-OFB cipher factory.
 * @param key - secret key bytes.
 * @param args - algorithm-specific extra arguments such as IV bytes.
 * @returns Configured cipher instance.
 * @example
 * ```ts
 * import { ofb } from '@awasm/noble/noble.js';
 * ofb(new Uint8Array(16), new Uint8Array(16));
 * ```
 */
export const ofb: TRet<CipherFactory> = /* @__PURE__ */ cipher(def_ofb, ofbNative);
/**
 * Noble AES-CFB cipher factory.
 * @param key - secret key bytes.
 * @param args - algorithm-specific extra arguments such as IV bytes.
 * @returns Configured cipher instance.
 * @example
 * ```ts
 * import { cfb } from '@awasm/noble/noble.js';
 * cfb(new Uint8Array(16), new Uint8Array(16));
 * ```
 */
export const cfb: TRet<CipherFactory> = /* @__PURE__ */ cipher(def_cfb, nobleAes.cfb);
/**
 * Noble AES-ECB cipher factory.
 * @param key - secret key bytes.
 * @param args - algorithm-specific extra arguments.
 * @returns Configured cipher instance.
 * @example
 * ```ts
 * import { ecb } from '@awasm/noble/noble.js';
 * ecb(new Uint8Array(16));
 * ```
 */
export const ecb: TRet<CipherFactory> = /* @__PURE__ */ cipher(def_ecb, nobleAes.ecb);
/**
 * Noble AES-GCM cipher factory.
 * @param key - secret key bytes.
 * @param args - algorithm-specific extra arguments such as nonce and AAD bytes.
 * @returns Configured cipher instance.
 * @example
 * ```ts
 * import { gcm } from '@awasm/noble/noble.js';
 * gcm(new Uint8Array(16), new Uint8Array(12));
 * ```
 */
export const gcm: TRet<CipherFactory> = /* @__PURE__ */ cipher(def_gcm, nobleAes.gcm);
/**
 * Noble AES-GCM-SIV cipher factory.
 * @param key - secret key bytes.
 * @param args - algorithm-specific extra arguments such as nonce and AAD bytes.
 * @returns Configured cipher instance.
 * @example
 * ```ts
 * import { gcmsiv } from '@awasm/noble/noble.js';
 * gcmsiv(new Uint8Array(16), new Uint8Array(12));
 * ```
 */
export const gcmsiv: TRet<CipherFactory> = /* @__PURE__ */ cipher(def_gcmsiv, nobleAes.gcmsiv);
/**
 * Noble AES-SIV cipher factory.
 * @param key - secret key bytes.
 * @param args - algorithm-specific extra arguments such as AAD components.
 * @returns Configured cipher instance.
 * @example
 * ```ts
 * import { aessiv } from '@awasm/noble/noble.js';
 * aessiv(new Uint8Array(32));
 * ```
 */
export const aessiv: TRet<CipherFactory> = /* @__PURE__ */ cipher(def_aessiv, nobleAes.aessiv);
/**
 * Noble AES-KW cipher factory.
 * @param key - secret key bytes.
 * @param args - algorithm-specific extra arguments.
 * @returns Configured cipher instance.
 * @example
 * ```ts
 * import { aeskw } from '@awasm/noble/noble.js';
 * aeskw(new Uint8Array(16));
 * ```
 */
export const aeskw: TRet<CipherFactory> = /* @__PURE__ */ cipher(def_aeskw, nobleAes.aeskw);
/**
 * Noble AES-KWP cipher factory.
 * @param key - secret key bytes.
 * @param args - algorithm-specific extra arguments.
 * @returns Configured cipher instance.
 * @example
 * ```ts
 * import { aeskwp } from '@awasm/noble/noble.js';
 * aeskwp(new Uint8Array(16));
 * ```
 */
export const aeskwp: TRet<CipherFactory> = /* @__PURE__ */ cipher(def_aeskwp, nobleAes.aeskwp);
/**
 * Noble Salsa20 stream cipher factory.
 * @param key - secret key bytes.
 * @param args - algorithm-specific extra arguments such as nonce bytes.
 * @returns Configured cipher instance.
 * @example
 * ```ts
 * import { salsa20 } from '@awasm/noble/noble.js';
 * salsa20(new Uint8Array(32), new Uint8Array(8));
 * ```
 */
export const salsa20: TRet<CipherFactory> = /* @__PURE__ */ cipher(
  def_salsa20,
  /* @__PURE__ */ xor(nobleSalsa.salsa20)
);
/**
 * Noble XSalsa20 stream cipher factory.
 * @param key - secret key bytes.
 * @param args - algorithm-specific extra arguments such as nonce bytes.
 * @returns Configured cipher instance.
 * @example
 * ```ts
 * import { xsalsa20 } from '@awasm/noble/noble.js';
 * xsalsa20(new Uint8Array(32), new Uint8Array(24));
 * ```
 */
export const xsalsa20: TRet<CipherFactory> = /* @__PURE__ */ cipher(
  def_xsalsa20,
  /* @__PURE__ */ xor(nobleSalsa.xsalsa20)
);
/**
 * Noble ChaCha8 stream cipher factory.
 * @param key - secret key bytes.
 * @param args - algorithm-specific extra arguments such as nonce bytes.
 * @returns Configured cipher instance.
 * @example
 * ```ts
 * import { chacha8 } from '@awasm/noble/noble.js';
 * chacha8(new Uint8Array(32), new Uint8Array(12));
 * ```
 */
export const chacha8: TRet<CipherFactory> = /* @__PURE__ */ cipher(
  def_chacha8,
  /* @__PURE__ */ xor(nobleChacha.chacha8)
);
/**
 * Noble ChaCha12 stream cipher factory.
 * @param key - secret key bytes.
 * @param args - algorithm-specific extra arguments such as nonce bytes.
 * @returns Configured cipher instance.
 * @example
 * ```ts
 * import { chacha12 } from '@awasm/noble/noble.js';
 * chacha12(new Uint8Array(32), new Uint8Array(12));
 * ```
 */
export const chacha12: TRet<CipherFactory> = /* @__PURE__ */ cipher(
  def_chacha12,
  /* @__PURE__ */ xor(nobleChacha.chacha12)
);
/**
 * Noble ChaCha20 stream cipher factory.
 * @param key - secret key bytes.
 * @param args - algorithm-specific extra arguments such as nonce bytes.
 * @returns Configured cipher instance.
 * @example
 * ```ts
 * import { chacha20 } from '@awasm/noble/noble.js';
 * chacha20(new Uint8Array(32), new Uint8Array(12));
 * ```
 */
export const chacha20: TRet<CipherFactory> = /* @__PURE__ */ cipher(
  def_chacha20,
  /* @__PURE__ */ xor(nobleChacha.chacha20)
);
/**
 * Noble original ChaCha20 stream cipher factory.
 * @param key - secret key bytes.
 * @param args - algorithm-specific extra arguments such as nonce bytes.
 * @returns Configured cipher instance.
 * @example
 * ```ts
 * import { chacha20orig } from '@awasm/noble/noble.js';
 * chacha20orig(new Uint8Array(32), new Uint8Array(8));
 * ```
 */
export const chacha20orig: TRet<CipherFactory> = /* @__PURE__ */ cipher(
  def_chacha20orig,
  /* @__PURE__ */ xor(nobleChacha.chacha20orig)
);
/**
 * Noble XChaCha20 stream cipher factory.
 * @param key - secret key bytes.
 * @param args - algorithm-specific extra arguments such as nonce bytes.
 * @returns Configured cipher instance.
 * @example
 * ```ts
 * import { xchacha20 } from '@awasm/noble/noble.js';
 * xchacha20(new Uint8Array(32), new Uint8Array(24));
 * ```
 */
export const xchacha20: TRet<CipherFactory> = /* @__PURE__ */ cipher(
  def_xchacha20,
  /* @__PURE__ */ xor(nobleChacha.xchacha20)
);
/**
 * Noble ChaCha20-Poly1305 AEAD cipher factory.
 * @param key - secret key bytes.
 * @param args - algorithm-specific extra arguments such as nonce and AAD bytes.
 * @returns Configured cipher instance.
 * @example
 * ```ts
 * import { chacha20poly1305 } from '@awasm/noble/noble.js';
 * chacha20poly1305(new Uint8Array(32), new Uint8Array(12));
 * ```
 */
export const chacha20poly1305: TRet<CipherFactory> = /* @__PURE__ */ cipher(
  def_chacha20poly1305,
  nobleChacha.chacha20poly1305
);
/**
 * Noble XChaCha20-Poly1305 AEAD cipher factory.
 * @param key - secret key bytes.
 * @param args - algorithm-specific extra arguments such as nonce and AAD bytes.
 * @returns Configured cipher instance.
 * @example
 * ```ts
 * import { xchacha20poly1305 } from '@awasm/noble/noble.js';
 * xchacha20poly1305(new Uint8Array(32), new Uint8Array(24));
 * ```
 */
export const xchacha20poly1305: TRet<CipherFactory> = /* @__PURE__ */ cipher(
  def_xchacha20poly1305,
  nobleChacha.xchacha20poly1305
);
/**
 * Noble XSalsa20-Poly1305 AEAD cipher factory.
 * @param key - secret key bytes.
 * @param args - algorithm-specific extra arguments such as nonce bytes.
 * @returns Configured cipher instance.
 * @example
 * ```ts
 * import { xsalsa20poly1305 } from '@awasm/noble/noble.js';
 * xsalsa20poly1305(new Uint8Array(32), new Uint8Array(24));
 * ```
 */
export const xsalsa20poly1305: TRet<CipherFactory> = /* @__PURE__ */ cipher(
  def_xsalsa20poly1305,
  nobleSalsa.xsalsa20poly1305
);
/**
 * Noble XSalsa20-Poly1305 secretbox helper.
 * @param key - secret key bytes.
 * @param nonce - nonce bytes.
 * @returns Configured secretbox helper.
 * @example
 * ```ts
 * import { secretbox } from '@awasm/noble/noble.js';
 * secretbox(new Uint8Array(32), new Uint8Array(24));
 * ```
 */
export const secretbox: TRet<SecretBox> = (key: TArg<Uint8Array>, nonce: TArg<Uint8Array>) => {
  const xs = xsalsa20poly1305(key, nonce);
  return { seal: xs.encrypt, open: xs.decrypt };
};

/**
 * Noble scrypt KDF.
 * @param password - password or key material bytes.
 * @param salt - salt bytes.
 * @param opts - algorithm configuration options.
 * @returns Derived output bytes.
 * @example
 * ```ts
 * import { scrypt } from '@awasm/noble/noble.js';
 * scrypt('password', 'salt', { N: 16, r: 1, p: 1, dkLen: 32 });
 * ```
 */
export const scrypt: ReturnType<typeof def_scrypt> = /* @__PURE__ */ mkKDFNoble(
  def_scrypt,
  nobleScrypt.scrypt,
  nobleScrypt.scryptAsync,
  PLATFORM
);
/**
 * Noble Argon2d KDF.
 * @param password - password or key material bytes.
 * @param salt - salt bytes.
 * @param opts - algorithm configuration options.
 * @returns Derived output bytes.
 * @example
 * ```ts
 * import { argon2d } from '@awasm/noble/noble.js';
 * argon2d('password', 'saltsalt', { t: 1, m: 8, p: 1, dkLen: 32 });
 * ```
 */
export const argon2d: ReturnType<typeof def_argon2d> = /* @__PURE__ */ mkKDFNoble(
  def_argon2d,
  nobleArgon2.argon2d,
  nobleArgon2.argon2dAsync,
  PLATFORM
);
/**
 * Noble Argon2i KDF.
 * @param password - password or key material bytes.
 * @param salt - salt bytes.
 * @param opts - algorithm configuration options.
 * @returns Derived output bytes.
 * @example
 * ```ts
 * import { argon2i } from '@awasm/noble/noble.js';
 * argon2i('password', 'saltsalt', { t: 1, m: 8, p: 1, dkLen: 32 });
 * ```
 */
export const argon2i: ReturnType<typeof def_argon2i> = /* @__PURE__ */ mkKDFNoble(
  def_argon2i,
  nobleArgon2.argon2i,
  nobleArgon2.argon2iAsync,
  PLATFORM
);
/**
 * Noble Argon2id KDF.
 * @param password - password or key material bytes.
 * @param salt - salt bytes.
 * @param opts - algorithm configuration options.
 * @returns Derived output bytes.
 * @example
 * ```ts
 * import { argon2id } from '@awasm/noble/noble.js';
 * argon2id('password', 'saltsalt', { t: 1, m: 8, p: 1, dkLen: 32 });
 * ```
 */
export const argon2id: ReturnType<typeof def_argon2id> = /* @__PURE__ */ mkKDFNoble(
  def_argon2id,
  nobleArgon2.argon2id,
  nobleArgon2.argon2idAsync,
  PLATFORM
);
