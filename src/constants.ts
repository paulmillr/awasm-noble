/**
 * Constants for hashes and ciphers. Mostly initial state.
 * @module
 */
import { u8, type TRet } from './utils.ts';

/**
 * Round constants:
 * First 32 bits of fractional parts of the cube roots of the first 64 primes 2..311)
 */
export const SHA256_K = [
  0x428a2f98, 0x71374491, 0xb5c0fbcf, 0xe9b5dba5, 0x3956c25b, 0x59f111f1, 0x923f82a4, 0xab1c5ed5,
  0xd807aa98, 0x12835b01, 0x243185be, 0x550c7dc3, 0x72be5d74, 0x80deb1fe, 0x9bdc06a7, 0xc19bf174,
  0xe49b69c1, 0xefbe4786, 0x0fc19dc6, 0x240ca1cc, 0x2de92c6f, 0x4a7484aa, 0x5cb0a9dc, 0x76f988da,
  0x983e5152, 0xa831c66d, 0xb00327c8, 0xbf597fc7, 0xc6e00bf3, 0xd5a79147, 0x06ca6351, 0x14292967,
  0x27b70a85, 0x2e1b2138, 0x4d2c6dfc, 0x53380d13, 0x650a7354, 0x766a0abb, 0x81c2c92e, 0x92722c85,
  0xa2bfe8a1, 0xa81a664b, 0xc24b8b70, 0xc76c51a3, 0xd192e819, 0xd6990624, 0xf40e3585, 0x106aa070,
  0x19a4c116, 0x1e376c08, 0x2748774c, 0x34b0bcb5, 0x391c0cb3, 0x4ed8aa4a, 0x5b9cca4f, 0x682e6ff3,
  0x748f82ee, 0x78a5636f, 0x84c87814, 0x8cc70208, 0x90befffa, 0xa4506ceb, 0xbef9a3f7, 0xc67178f2,
];

/** Initial SHA256 state. Bits 0..32 of frac part of sqrt of primes 2..19 */
export const SHA256_IV = /* @__PURE__ */ new Uint32Array([
  0x6a09e667, 0xbb67ae85, 0x3c6ef372, 0xa54ff53a, 0x510e527f, 0x9b05688c, 0x1f83d9ab, 0x5be0cd19,
]);
export const SHA256_IV_U8 = /* @__PURE__ */ u8(SHA256_IV);

/** Initial SHA224 state. Bits 32..64 of frac part of sqrt of primes 23..53 */
export const SHA224_IV: TRet<Uint32Array> = /* @__PURE__ */ Uint32Array.from([
  0xc1059ed8, 0x367cd507, 0x3070dd17, 0xf70e5939, 0xffc00b31, 0x68581511, 0x64f98fa7, 0xbefa4fa4,
]);
export const SHA224_IV_U8 = /* @__PURE__ */ u8(SHA224_IV);

// Round constants
// RFC 6234 §5.2:
// first 64 bits of the fractional parts of the cube roots of the first 80 primes.
// prettier-ignore
export const SHA512_K = /* @__PURE__ */ [
  '0x428a2f98d728ae22', '0x7137449123ef65cd', '0xb5c0fbcfec4d3b2f', '0xe9b5dba58189dbbc',
  '0x3956c25bf348b538', '0x59f111f1b605d019', '0x923f82a4af194f9b', '0xab1c5ed5da6d8118',
  '0xd807aa98a3030242', '0x12835b0145706fbe', '0x243185be4ee4b28c', '0x550c7dc3d5ffb4e2',
  '0x72be5d74f27b896f', '0x80deb1fe3b1696b1', '0x9bdc06a725c71235', '0xc19bf174cf692694',
  '0xe49b69c19ef14ad2', '0xefbe4786384f25e3', '0x0fc19dc68b8cd5b5', '0x240ca1cc77ac9c65',
  '0x2de92c6f592b0275', '0x4a7484aa6ea6e483', '0x5cb0a9dcbd41fbd4', '0x76f988da831153b5',
  '0x983e5152ee66dfab', '0xa831c66d2db43210', '0xb00327c898fb213f', '0xbf597fc7beef0ee4',
  '0xc6e00bf33da88fc2', '0xd5a79147930aa725', '0x06ca6351e003826f', '0x142929670a0e6e70',
  '0x27b70a8546d22ffc', '0x2e1b21385c26c926', '0x4d2c6dfc5ac42aed', '0x53380d139d95b3df',
  '0x650a73548baf63de', '0x766a0abb3c77b2a8', '0x81c2c92e47edaee6', '0x92722c851482353b',  '0xa2bfe8a14cf10364', '0xa81a664bbc423001', '0xc24b8b70d0f89791', '0xc76c51a30654be30',
  '0xd192e819d6ef5218', '0xd69906245565a910', '0xf40e35855771202a', '0x106aa07032bbd1b8',
  '0x19a4c116b8d2d0c8', '0x1e376c085141ab53', '0x2748774cdf8eeb99', '0x34b0bcb5e19b48a8',
  '0x391c0cb3c5c95a63', '0x4ed8aa4ae3418acb', '0x5b9cca4f7763e373', '0x682e6ff3d6b2b8a3',
  '0x748f82ee5defb2fc', '0x78a5636f43172f60', '0x84c87814a1f0ab72', '0x8cc702081a6439ec',
  '0x90befffa23631e28', '0xa4506cebde82bde9', '0xbef9a3f7b2c67915', '0xc67178f2e372532b',
  '0xca273eceea26619c', '0xd186b8c721c0c207', '0xeada7dd6cde0eb1e', '0xf57d4f7fee6ed178',
  '0x06f067aa72176fba', '0x0a637dc5a2c898a6', '0x113f9804bef90dae', '0x1b710b35131c471b',
  '0x28db77f523047d84', '0x32caab7b40c72493', '0x3c9ebe0a15c9bebc', '0x431d67c49c100d4c',
  '0x4cc5d4becb3e42b6', '0x597f299cfc657e2a', '0x5fcb6fab3ad6faec', '0x6c44198c4a475817',
].map((n) => BigInt(n));

// 64-bit SHA-2 IV words are stored as [lo, hi] u32 pairs.
// This lets u8(...) seed native module state directly.
/** Initial SHA512 state. Bits 0..64 of frac part of sqrt of primes 2..19 */
export const SHA512_IV: TRet<Uint32Array> = /* @__PURE__ */ Uint32Array.from([
  0xf3bcc908, 0x6a09e667, 0x84caa73b, 0xbb67ae85, 0xfe94f82b, 0x3c6ef372, 0x5f1d36f1, 0xa54ff53a,
  0xade682d1, 0x510e527f, 0x2b3e6c1f, 0x9b05688c, 0xfb41bd6b, 0x1f83d9ab, 0x137e2179, 0x5be0cd19,
]);
export const SHA512_IV_U8 = /* @__PURE__ */ u8(SHA512_IV);

/** Initial SHA384 state. Bits 0..64 of frac part of sqrt of primes 23..53 */
export const SHA384_IV: TRet<Uint32Array> = /* @__PURE__ */ Uint32Array.from([
  0xc1059ed8, 0xcbbb9d5d, 0x367cd507, 0x629a292a, 0x3070dd17, 0x9159015a, 0xf70e5939, 0x152fecd8,
  0xffc00b31, 0x67332667, 0x68581511, 0x8eb44a87, 0x64f98fa7, 0xdb0c2e0d, 0xbefa4fa4, 0x47b5481d,
]);
export const SHA384_IV_U8 = /* @__PURE__ */ u8(SHA384_IV);

/**
 * Truncated SHA512/256 and SHA512/224.
 * SHA512_IV is XORed with 0xa5a5a5a5a5a5a5a5, then used as "intermediary" IV of SHA512/t.
 * Then t hashes string to produce result IV.
 */
// Derived SHA-512/t IVs also use [lo, hi] u32 pairs here.
// That lets hashes.ts seed the shared SHA-512 state layout directly.

/** SHA512/224 IV */
const SHA512_224_IV = /* @__PURE__ */ Uint32Array.from([
  0x19544da2, 0x8c3d37c8, 0x89dcd4d6, 0x73e19966, 0x32ff9c82, 0x1dfab7ae, 0x582f9fcf, 0x679dd514,
  0x7bd44da8, 0x0f6d2b69, 0x04c48942, 0x77e36f73, 0x6a1d36c8, 0x3f9d85a8, 0x91d692a1, 0x1112e6ad,
]);
export const SHA512_224_IV_U8 = /* @__PURE__ */ u8(SHA512_224_IV);
/** SHA512/256 IV */
const SHA512_256_IV = /* @__PURE__ */ Uint32Array.from([
  0xfc2bf72c, 0x22312194, 0xc84c64c2, 0x9f555fa3, 0x6f53b151, 0x2393b86b, 0x5940eabd, 0x96387719,
  0xa88effe3, 0x96283ee2, 0x53863992, 0xbe5e1e25, 0x2c85b8aa, 0x2b0199fc, 0x81c52ca2, 0x0eb72ddc,
]);
export const SHA512_256_IV_U8 = /* @__PURE__ */ u8(SHA512_256_IV);

// RFC 7693 §2.6 / Appendix C: BLAKE2b reuses the SHA-512 IV words.
// This file keeps them as LE [lo, hi] u32 halves for the BLAKE2b helpers.
// Same as SHA512_IV, but swapped endianness: LE instead of BE. iv[1] is iv[0], etc.
export const B2B_IV = /* @__PURE__ */ Uint32Array.from([
  0xf3bcc908, 0x6a09e667, 0x84caa73b, 0xbb67ae85, 0xfe94f82b, 0x3c6ef372, 0x5f1d36f1, 0xa54ff53a,
  0xade682d1, 0x510e527f, 0x2b3e6c1f, 0x9b05688c, 0xfb41bd6b, 0x1f83d9ab, 0x137e2179, 0x5be0cd19,
]);
export const B2B_IV_U8 = /* @__PURE__ */ u8(B2B_IV);

const _32n = /* @__PURE__ */ BigInt(32);
export const B2B_IV_U64 = /* @__PURE__ */ [
  '0x6a09e667f3bcc908',
  '0xbb67ae8584caa73b',
  '0x3c6ef372fe94f82b',
  '0xa54ff53a5f1d36f1',
  '0x510e527fade682d1',
  '0x9b05688c2b3e6c1f',
  '0x1f83d9abfb41bd6b',
  '0x5be0cd19137e2179',
].map((n) => BigInt(n));

// RFC 7693 §2.6 / Appendix D: BLAKE2s reuses the SHA-256 IV words as-is.
export const B2S_IV = /* @__PURE__ */ Uint32Array.from([
  0x6a09e667, 0xbb67ae85, 0x3c6ef372, 0xa54ff53a, 0x510e527f, 0x9b05688c, 0x1f83d9ab, 0x5be0cd19,
]);
export const B2S_IV_U8 = /* @__PURE__ */ u8(B2S_IV);

// SHA-3 proposal BLAKE v1.2 §2.1.1 Table 2.1 / RFC 7693 §2.7:
// rows 0..9 are the published SIGMA table; rows 10..11 repeat 0..1 for BLAKE2b;
// rows 10..13 satisfy SHA-3 proposal BLAKE v1.2 §2.2.2's sigma[r mod 10] reuse for 14-round
// BLAKE-64; rows 14..15 extend that modulo-10 reuse for the legacy 16-round
// Blake1 path.
// prettier-ignore
export const BSIGMA: TRet<Uint8Array> = /* @__PURE__ */ Uint8Array.from([
  0, 1, 2, 3, 4, 5, 6, 7, 8, 9, 10, 11, 12, 13, 14, 15,
  14, 10, 4, 8, 9, 15, 13, 6, 1, 12, 0, 2, 11, 7, 5, 3,
  11, 8, 12, 0, 5, 2, 15, 13, 10, 14, 3, 6, 7, 1, 9, 4,
  7, 9, 3, 1, 13, 12, 11, 14, 2, 6, 5, 10, 4, 0, 15, 8,
  9, 0, 5, 7, 2, 4, 10, 15, 14, 1, 11, 12, 6, 8, 3, 13,
  2, 12, 6, 10, 0, 11, 8, 3, 4, 13, 7, 5, 15, 14, 1, 9,
  12, 5, 1, 15, 14, 13, 4, 10, 0, 7, 6, 3, 9, 2, 8, 11,
  13, 11, 7, 14, 12, 1, 3, 9, 5, 0, 15, 4, 8, 6, 2, 10,
  6, 15, 14, 9, 11, 3, 0, 8, 12, 2, 13, 7, 1, 4, 10, 5,
  10, 2, 8, 4, 7, 6, 1, 5, 15, 11, 9, 14, 3, 12, 13, 0,
  0, 1, 2, 3, 4, 5, 6, 7, 8, 9, 10, 11, 12, 13, 14, 15,
  14, 10, 4, 8, 9, 15, 13, 6, 1, 12, 0, 2, 11, 7, 5, 3,
  // Blake1, unused in others
  11, 8, 12, 0, 5, 2, 15, 13, 10, 14, 3, 6, 7, 1, 9, 4,
  7, 9, 3, 1, 13, 12, 11, 14, 2, 6, 5, 10, 4, 0, 15, 8,
  9, 0, 5, 7, 2, 4, 10, 15, 14, 1, 11, 12, 6, 8, 3, 13,
  2, 12, 6, 10, 0, 11, 8, 3, 4, 13, 7, 5, 15, 14, 1, 9,
]);

// blake1

// first half of C512
// SHA-3 proposal BLAKE v1.2 §2.1.1: BLAKE-32 uses c0..c15,
// starting at 0x243f6a88 and ending at 0xb5470917.
export const B32C = /* @__PURE__ */ Uint32Array.from([
  0x243f6a88, 0x85a308d3, 0x13198a2e, 0x03707344, 0xa4093822, 0x299f31d0, 0x082efa98, 0xec4e6c89,
  0x452821e6, 0x38d01377, 0xbe5466cf, 0x34e90c6c, 0xc0ac29b7, 0xc97c50dd, 0x3f84d5b5, 0xb5470917,
]);
// prettier-ignore
// SHA-3 proposal BLAKE v1.2 §2.2.1 c0..c15 are stored as [lo32, hi32] halves.
// generateTBL512_new rebuilds each 64-bit constant with (hi << 32n) | lo.
export const B64C = /* @__PURE__ */ (() =>
  Uint32Array.from([
  B32C[1], B32C[0], B32C[3], B32C[2], B32C[5], B32C[4], B32C[7], B32C[6], // le<->be
  B32C[9], B32C[8], B32C[11], B32C[10], B32C[13], B32C[12], B32C[15], B32C[14],
  0x8979fb1b, 0x9216d5d9, 0x98dfb5ac, 0xd1310ba6, 0xd01adfb7, 0x2ffd72db, 0x6a267e96, 0xb8e1afed,
  0xf12c7f99, 0xba7c9045, 0xb3916cf7, 0x24a19947, 0x858efc16, 0x0801f2e2, 0x71574e69, 0x636920d8,
]))();

export const B64C_U64 = /* @__PURE__ */ [
  // first half
  '0x243f6a8885a308d3',
  '0x13198a2e03707344',
  '0xa4093822299f31d0',
  '0x082efa98ec4e6c89',
  '0x452821e638d01377',
  '0xbe5466cf34e90c6c',
  '0xc0ac29b7c97c50dd',
  '0x3f84d5b5b5470917',
  // second half
  '0x9216d5d98979fb1b',
  '0xd1310ba698dfb5ac',
  '0x2ffd72dbd01adfb7',
  '0xb8e1afed6a267e96',
  '0xba7c9045f12c7f99',
  '0x24a19947b3916cf7',
  '0x0801f2e2858efc16',
  '0x636920d871574e69',
].map((n) => BigInt(n));

export const B256_IV = /* @__PURE__ */ SHA256_IV.slice();
// SHA-3 proposal BLAKE v1.2 §2.2.1: legacy Blake1-64 keeps the SHA-512 IV in canonical
// [hi32, lo32] order, unlike SHA512_IV above, which is laid out as [lo, hi]
// for module-state seeding.
export const B512_IV = /* @__PURE__ */ Uint32Array.from([
  0x6a09e667, 0xf3bcc908, 0xbb67ae85, 0x84caa73b, 0x3c6ef372, 0xfe94f82b, 0xa54ff53a, 0x5f1d36f1,
  0x510e527f, 0xade682d1, 0x9b05688c, 0x2b3e6c1f, 0x1f83d9ab, 0xfb41bd6b, 0x5be0cd19, 0x137e2179,
]);
function generateTBL256(): number[] {
  const TBL = [];
  for (let i = 0, j = 0; i < 14; i++, j += 16) {
    for (let offset = 1; offset < 16; offset += 2) {
      TBL.push(B32C[BSIGMA[j + offset]]);
      TBL.push(B32C[BSIGMA[j + offset - 1]]);
    }
  }
  return TBL;
}
export const TBL256 = /* @__PURE__ */ generateTBL256(); // C256[SIGMA[X]] precompute

function generateTBL512_new(): bigint[] {
  const TBL = [];
  for (let r = 0, k = 0; r < 16; r++, k += 16) {
    for (let offset = 1; offset < 16; offset += 2) {
      const l0 = B64C[BSIGMA[k + offset] * 2 + 1];
      const h0 = B64C[BSIGMA[k + offset] * 2 + 0];
      const l1 = B64C[BSIGMA[k + offset - 1] * 2 + 1];
      const h1 = B64C[BSIGMA[k + offset - 1] * 2 + 0];
      TBL.push((BigInt(l0) << _32n) | BigInt(h0));
      TBL.push((BigInt(l1) << _32n) | BigInt(h1));
    }
  }
  return TBL;
}
export const TBL512 = /* @__PURE__ */ generateTBL512_new();

/** Initial SHA-1 state from RFC 3174 §6.1. */
export const SHA1_IV = /* @__PURE__ */ Uint32Array.from([
  0x67452301, 0xefcdab89, 0x98badcfe, 0x10325476, 0xc3d2e1f0,
]);
export const SHA1_IV_U8 = /* @__PURE__ */ u8(SHA1_IV);

const p32 = /* @__PURE__ */ Math.pow(2, 32);
/** RFC 1321 §3.4 / Appendix A.3 `T[1..64]` table. */
export const MD5_K = /* @__PURE__ */ Array.from({ length: 64 }, (_, i) =>
  Math.floor(p32 * Math.abs(Math.sin(i + 1)))
);
/**
 * RFC 1321 §3.3 / Appendix A.3 MD5 initial state.
 * It matches the first four SHA-1 words, so slice() copies them without
 * aliasing SHA1_IV.
 */
export const MD5_IV = /* @__PURE__ */ SHA1_IV.slice(0, 4);
export const MD5_IV_U8 = /* @__PURE__ */ u8(MD5_IV);

/** RIPEMD-160 initial state; same five 32-bit words as SHA-1. */
export const RIPEMD160_IV = /* @__PURE__ */ new Uint32Array([
  0x67452301, 0xefcdab89, 0x98badcfe, 0x10325476, 0xc3d2e1f0,
]);
export const RIPEMD160_IV_U8 = /* @__PURE__ */ u8(RIPEMD160_IV);

const Rho160 = /* @__PURE__ */ Uint8Array.from([
  7, 4, 13, 1, 10, 6, 15, 3, 12, 0, 9, 5, 2, 14, 11, 8,
]);
const Id160 = /* @__PURE__ */ (() => Uint8Array.from(new Array(16).fill(0).map((_, i) => i)))();
const Pi160 = /* @__PURE__ */ (() => Id160.map((i) => (9 * i + 5) % 16))();
// Five left/right message-word orderings for the RIPEMD-160 dual-lane rounds.
const idxLR = /* @__PURE__ */ (() => {
  const L = [Id160];
  const R = [Pi160];
  const res = [L, R];
  for (let i = 0; i < 4; i++) for (let j of res) j.push(j[i].map((k) => Rho160[k]));
  return res;
})();
export const RIPEMD160_idxL = /* @__PURE__ */ (() => idxLR[0])();
export const RIPEMD160_idxR = /* @__PURE__ */ (() => idxLR[1])();
// const [idxL, idxR] = idxLR;

// Base per-group shift table before the left/right message-order permutations are applied.
const shifts160 = /* @__PURE__ */ [
  [11, 14, 15, 12, 5, 8, 7, 9, 11, 13, 14, 15, 6, 7, 9, 8],
  [12, 13, 11, 15, 6, 9, 9, 7, 12, 15, 11, 13, 7, 8, 7, 7],
  [13, 15, 14, 11, 7, 7, 6, 8, 13, 14, 13, 12, 5, 5, 6, 9],
  [14, 11, 12, 14, 8, 6, 5, 5, 15, 12, 15, 14, 9, 9, 8, 6],
  [15, 12, 13, 13, 9, 5, 8, 6, 14, 11, 12, 11, 8, 6, 5, 5],
].map((i) => Uint8Array.from(i));
export const RIPEMD160_shiftsL160 = /* @__PURE__ */ RIPEMD160_idxL.map((idx, i) =>
  idx.map((j) => shifts160[i][j])
);
export const RIPEMD160_shiftsR160 = /* @__PURE__ */ RIPEMD160_idxR.map((idx, i) =>
  idx.map((j) => shifts160[i][j])
);
// Five left-lane additive constants for RIPEMD-160.
export const RIPEMD160_Kl160 = /* @__PURE__ */ Uint32Array.from([
  0x00000000, 0x5a827999, 0x6ed9eba1, 0x8f1bbcdc, 0xa953fd4e,
]);
// Five right-lane additive constants for RIPEMD-160.
export const RIPEMD160_Kr160 = /* @__PURE__ */ Uint32Array.from([
  0x50a28be6, 0x5c4dd124, 0x6d703ef3, 0x7a6d76e9, 0x00000000,
]);

const _0n = /* @__PURE__ */ BigInt(0);
const _1n = /* @__PURE__ */ BigInt(1);
const _2n = /* @__PURE__ */ BigInt(2);
const _7n = /* @__PURE__ */ BigInt(7);
const _256n = /* @__PURE__ */ BigInt(256);
// FIPS 202 Algorithm 5 rc():
// when the outgoing bit is 1, the 8-bit LFSR xors taps 0, 4, 5, and 6.
// That compresses to the feedback mask `0x71`.
const _0x71n = /* @__PURE__ */ BigInt(0x71);
// Grouped export destructuring sticks in bundles even when SHA3 is unused, so generate
// each table in its own pure IIFE instead of exporting all three from one object.
// FIPS 202 §3.2.2 / §3.2.3 walk the 24 non-(0,0) lanes.
// This table stores each lane as 5*y + x for the u64 state layout.
export const SHA3_PI2 = /* @__PURE__ */ (() => {
  const SHA3_PI2: number[] = [];
  for (let round = 0, x = 1, y = 0; round < 24; round++) {
    [x, y] = [y, (2 * x + 3 * y) % 5];
    SHA3_PI2.push(5 * y + x);
  }
  return SHA3_PI2;
})();
export const SHA3_ROTL = /* @__PURE__ */ (() => {
  const SHA3_ROTL: number[] = [];
  for (let round = 0, x = 1, y = 0; round < 24; round++) {
    [x, y] = [y, (2 * x + 3 * y) % 5];
    SHA3_ROTL.push((((round + 1) * (round + 2)) / 2) % 64);
  }
  return SHA3_ROTL;
})();
export const SHA3_IOTA = /* @__PURE__ */ (() => {
  const SHA3_IOTA: bigint[] = [];
  for (let round = 0, R = _1n; round < 24; round++) {
    let t = _0n;
    for (let j = 0; j < 7; j++) {
      R = ((R << _1n) ^ ((R >> _7n) * _0x71n)) % _256n;
      if (R & _2n) t ^= _1n << ((_1n << /* @__PURE__ */ BigInt(j)) - _1n);
    }
    SHA3_IOTA.push(t);
  }
  return SHA3_IOTA;
})();

// Flag bitset
// BLAKE3 compression-domain flags from Table~\ref{tab:flags}.
export const B3_Flags = {
  CHUNK_START: 0b1,
  CHUNK_END: 0b10,
  PARENT: 0b100,
  ROOT: 0b1000,
  KEYED_HASH: 0b10000,
  DERIVE_KEY_CONTEXT: 0b100000,
  DERIVE_KEY_MATERIAL: 0b1000000,
} as const;

// Default BLAKE3 IV, cloned from the shared BLAKE2s / SHA-256 IV basis.
export const B3_IV = /* @__PURE__ */ SHA256_IV.slice();
export const B3_IV_U8 = /* @__PURE__ */ u8(B3_IV);

// Seven 16-word rounds of the BLAKE3 message schedule.
// Generated by repeatedly applying the adopted single permutation.
export const B3_SIGMA: TRet<Uint8Array> = /* @__PURE__ */ (() => {
  const Id = Array.from({ length: 16 }, (_, i) => i);
  const permute = (arr: number[]) =>
    [2, 6, 3, 10, 7, 0, 4, 13, 1, 11, 12, 5, 9, 14, 15, 8].map((i) => arr[i]);
  const res: number[] = [];
  for (let i = 0, v = Id; i < 7; i++, v = permute(v)) res.push(...v);
  return Uint8Array.from(res) as TRet<Uint8Array>;
})();

// Replaces `TextEncoder` for ASCII literals, which is enough for sigma constants.
// Non-ASCII input would not match UTF-8 `TextEncoder` output.
const encodeStr = (str: string) => Uint8Array.from(str.split(''), (c) => c.charCodeAt(0));
// RFC 8439 §2.3 / RFC 7539 §2.3 only define the 256-bit-key constants; this 16-byte sigma is
// kept for legacy allowShortKeys Salsa/ChaCha variants.
export const ARX_SIGMA16 = /* @__PURE__ */ encodeStr('expand 16-byte k');
// RFC 8439 §2.3 / RFC 7539 §2.3 define words 0-3 as
// `0x61707865 0x3320646e 0x79622d32 0x6b206574`, i.e. `expand 32-byte k`.
export const ARX_SIGMA32 = /* @__PURE__ */ encodeStr('expand 32-byte k');
