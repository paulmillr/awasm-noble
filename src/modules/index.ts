/**
 * Re-exports of all methods.
 * The file is not used in end-user code. Instead, it's used by awasm-compiler
 * to generate different build targets (wasm, wasm_threads, js, runtime).
 * @module
 */
import type { CompilerOpts } from '@awasm/compiler/codegen.js';
import * as constants from '../constants.ts';
import {
  genAesCbc,
  genAesCfb,
  genAesCtr,
  genAesEcb,
  genAesGcm,
  genAesGcmSiv,
  genAesKw,
  genAesKwp,
  genAesOfb,
  genAesSiv,
  genChacha,
  genChachaAead,
  genCmac,
  genSalsa,
  genSalsaAead,
} from './ciphers.ts';
import {
  genBlake1,
  genBlake2,
  genBlake3,
  genKeccak,
  genMd5,
  genRipemd,
  genSha1,
  genSha2,
} from './hashes.ts';
import { genArgon2, genScrypt } from './kdf.ts';
import { genGhash, genPoly1305, genPolyval } from './mac.ts';

// Keep the generator registry obviously pure.
// That lets runtime tree-shaking drop unrelated module builders.
export const GENERATORS = /* @__PURE__ */ Object.freeze({
  genKeccak,
  genSha1,
  genSha2,
  genRipemd,
  genMd5,
  genBlake1,
  genBlake2,
  genBlake3,
  genScrypt,
  genArgon2,
  genSalsa,
  genSalsaAead,
  genChacha,
  genChachaAead,
  genAesEcb,
  genAesCbc,
  genAesCfb,
  genAesOfb,
  genAesCtr,
  genAesGcm,
  genAesGcmSiv,
  genAesSiv,
  genAesKw,
  genAesKwp,
  genCmac,
  genGhash,
  genPolyval,
  genPoly1305,
} as const);
export {
  genAesCbc,
  genAesCfb,
  genAesCtr,
  genAesEcb,
  genAesGcm,
  genAesGcmSiv,
  genAesKw,
  genAesKwp,
  genAesOfb,
  genAesSiv,
  genArgon2,
  genBlake1,
  genBlake2,
  genBlake3,
  genChacha,
  genChachaAead,
  genCmac,
  genGhash,
  genKeccak,
  genMd5,
  genPoly1305,
  genPolyval,
  genRipemd,
  genSalsa,
  genSalsaAead,
  genScrypt,
  genSha1,
  genSha2,
};

type ModuleSpec<K extends keyof typeof GENERATORS> = {
  fn: K;
  type: Parameters<(typeof GENERATORS)[K]>[0];
  opts: Parameters<(typeof GENERATORS)[K]>[1];
  compilerOpts: CompilerOpts;
};
type AnyModuleSpec = { [K in keyof typeof GENERATORS]: ModuleSpec<K> }[keyof typeof GENERATORS];

// Runtime builds import only a few module specs.
// Keep each spec on its own export so unused ones can disappear.
export const keccak24 = {
  fn: 'genKeccak',
  type: 'u64',
  opts: { rounds: 24 },
  compilerOpts: {},
} satisfies ModuleSpec<'genKeccak'>;
export const sha256 = {
  fn: 'genSha2',
  type: 'u32',
  opts: {
    K: constants.SHA256_K,
    rounds: 64,
    shifts: [7, 18, 3, 17, 19, 10, 6, 11, 25, 2, 13, 22],
  },
  compilerOpts: { threadLimit: 2 },
} satisfies ModuleSpec<'genSha2'>;
export const sha512 = {
  fn: 'genSha2',
  type: 'u64',
  opts: {
    K: constants.SHA512_K,
    rounds: 80,
    shifts: [1, 8, 7, 19, 61, 6, 14, 18, 41, 28, 34, 39],
  },
  compilerOpts: { wasmTee: true },
} satisfies ModuleSpec<'genSha2'>;
export const sha1 = {
  fn: 'genSha1',
  type: 'u32',
  opts: undefined,
  compilerOpts: { wasmTeeSimd: true },
} satisfies ModuleSpec<'genSha1'>;
export const ripemd160 = {
  fn: 'genRipemd',
  type: 'u32',
  opts: undefined,
  compilerOpts: { wasmTee: false },
} satisfies ModuleSpec<'genRipemd'>;
export const md5 = {
  fn: 'genMd5',
  type: 'u32',
  opts: undefined,
  compilerOpts: {},
} satisfies ModuleSpec<'genMd5'>;
// Blake1 legacy round counts differ from Blake2: blake256 uses 14 vs blake2s 10,
// and blake512 uses 16 vs blake2b 12.
export const blake256 = {
  fn: 'genBlake1',
  type: 'u32',
  opts: {
    rounds: 14,
    shifts: [16, 12, 8, 7],
    tbl: constants.TBL256,
    constants: constants.B32C as any as number[],
  },
  compilerOpts: {},
} satisfies ModuleSpec<'genBlake1'>;
export const blake512 = {
  fn: 'genBlake1',
  type: 'u64',
  opts: {
    rounds: 16,
    shifts: [32, 25, 16, 11],
    tbl: constants.TBL512,
    constants: constants.B64C_U64,
  },
  compilerOpts: {},
} satisfies ModuleSpec<'genBlake1'>;
export const blake2s = {
  fn: 'genBlake2',
  type: 'u32',
  opts: {
    rounds: 10,
    shifts: [16, 12, 8, 7],
    IV: constants.B2S_IV,
  },
  compilerOpts: {},
} satisfies ModuleSpec<'genBlake2'>;
export const blake2b = {
  fn: 'genBlake2',
  type: 'u64',
  opts: {
    rounds: 12,
    shifts: [32, 24, 16, 63],
    IV: constants.B2B_IV_U64,
  },
  compilerOpts: { jsOpsPerFn: 80_000 },
} satisfies ModuleSpec<'genBlake2'>;
export const blake3 = {
  fn: 'genBlake3',
  type: 'u32',
  opts: {},
  compilerOpts: {},
} satisfies ModuleSpec<'genBlake3'>;
export const scrypt = {
  fn: 'genScrypt',
  type: 'u32',
  opts: {},
  compilerOpts: {},
} satisfies ModuleSpec<'genScrypt'>;
export const argon2 = {
  fn: 'genArgon2',
  type: 'u32',
  opts: {},
  compilerOpts: {},
} satisfies ModuleSpec<'genArgon2'>;
export const salsa20 = {
  fn: 'genSalsa',
  type: 'u32',
  opts: { rounds: 20 },
  compilerOpts: {},
} satisfies ModuleSpec<'genSalsa'>;
export const chacha20 = {
  fn: 'genChacha',
  type: 'u32',
  opts: { rounds: 20 },
  compilerOpts: {},
} satisfies ModuleSpec<'genChacha'>;
export const chacha12 = {
  fn: 'genChacha',
  type: 'u32',
  opts: { rounds: 12 },
  compilerOpts: {},
} satisfies ModuleSpec<'genChacha'>;
export const chacha8 = {
  fn: 'genChacha',
  type: 'u32',
  opts: { rounds: 8 },
  compilerOpts: {},
} satisfies ModuleSpec<'genChacha'>;
export const salsa_poly1305 = {
  fn: 'genSalsaAead',
  type: 'u32',
  opts: { rounds: 20 },
  compilerOpts: {},
} satisfies ModuleSpec<'genSalsaAead'>;
export const chacha_poly1305 = {
  fn: 'genChachaAead',
  type: 'u32',
  opts: { rounds: 20 },
  compilerOpts: {},
} satisfies ModuleSpec<'genChachaAead'>;
export const aes_ecb = {
  fn: 'genAesEcb',
  type: 'u32',
  opts: {},
  compilerOpts: {},
} satisfies ModuleSpec<'genAesEcb'>;
export const aes_cbc = {
  fn: 'genAesCbc',
  type: 'u32',
  opts: {},
  compilerOpts: {},
} satisfies ModuleSpec<'genAesCbc'>;
export const aes_cfb = {
  fn: 'genAesCfb',
  type: 'u32',
  opts: {},
  compilerOpts: {},
} satisfies ModuleSpec<'genAesCfb'>;
export const aes_ofb = {
  fn: 'genAesOfb',
  type: 'u32',
  opts: {},
  compilerOpts: {},
} satisfies ModuleSpec<'genAesOfb'>;
export const aes_ctr = {
  fn: 'genAesCtr',
  type: 'u32',
  opts: {},
  compilerOpts: {},
} satisfies ModuleSpec<'genAesCtr'>;
export const aes_gcm = {
  fn: 'genAesGcm',
  type: 'u32',
  opts: {},
  compilerOpts: {},
} satisfies ModuleSpec<'genAesGcm'>;
export const aes_gcmsiv = {
  fn: 'genAesGcmSiv',
  type: 'u32',
  opts: {},
  compilerOpts: {},
} satisfies ModuleSpec<'genAesGcmSiv'>;
export const aes_siv = {
  fn: 'genAesSiv',
  type: 'u32',
  opts: {},
  compilerOpts: {},
} satisfies ModuleSpec<'genAesSiv'>;
export const aes_kw = {
  fn: 'genAesKw',
  type: 'u32',
  opts: {},
  compilerOpts: {},
} satisfies ModuleSpec<'genAesKw'>;
export const aes_kwp = {
  fn: 'genAesKwp',
  type: 'u32',
  opts: {},
  compilerOpts: {},
} satisfies ModuleSpec<'genAesKwp'>;
export const cmac = {
  fn: 'genCmac',
  type: 'u32',
  opts: {},
  compilerOpts: {},
} satisfies ModuleSpec<'genCmac'>;
export const ghash = {
  fn: 'genGhash',
  type: 'u32',
  opts: {},
  compilerOpts: {},
} satisfies ModuleSpec<'genGhash'>;
export const poly1305 = {
  fn: 'genPoly1305',
  type: 'u32',
  opts: {},
  compilerOpts: {},
} satisfies ModuleSpec<'genPoly1305'>;
export const polyval = {
  fn: 'genPolyval',
  type: 'u32',
  opts: { reverse: true },
  compilerOpts: {},
} satisfies ModuleSpec<'genPolyval'>;
export const MODULES = /* @__PURE__ */ Object.freeze({
  keccak24,
  sha256,
  sha512,
  sha1,
  ripemd160,
  md5,
  blake256,
  blake512,
  blake2s,
  blake2b,
  blake3,
  scrypt,
  argon2,
  salsa20,
  chacha20,
  chacha12,
  chacha8,
  salsa_poly1305,
  chacha_poly1305,
  aes_ecb,
  aes_cbc,
  aes_cfb,
  aes_ofb,
  aes_ctr,
  aes_gcm,
  aes_gcmsiv,
  aes_siv,
  aes_kw,
  aes_kwp,
  cmac,
  ghash,
  poly1305,
  polyval,
} satisfies Record<string, AnyModuleSpec>);

export type Modules = keyof typeof MODULES;
