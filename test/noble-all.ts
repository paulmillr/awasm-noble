// Hashes
import * as nobleBlake1 from '@noble/hashes/blake1.js';
import * as nobleBlake2 from '@noble/hashes/blake2.js';
import * as nobleBlake3 from '@noble/hashes/blake3.js';
import * as nobleLegacy from '@noble/hashes/legacy.js';
import * as nobleSha2 from '@noble/hashes/sha2.js';
import * as nobleSha3 from '@noble/hashes/sha3.js';
// Ciphers
import * as noblePoly from '@noble/ciphers/_poly1305.js';
import * as noblePolyval from '@noble/ciphers/_polyval.js';
import * as nobleAes from '@noble/ciphers/aes.js';
import * as nobleChacha from '@noble/ciphers/chacha.js';
import * as nobleSalsa from '@noble/ciphers/salsa.js';

export type XorStream = (
  key: Uint8Array,
  nonce: Uint8Array,
  data: Uint8Array,
  output?: Uint8Array,
  counter?: number
) => Uint8Array;

const xorCipher = (fn) => (key: Uint8Array, nonce: Uint8Array, counter?: number) => ({
  encrypt: (data: Uint8Array, output?: Uint8Array) => fn(key, nonce, data, output, counter),
  decrypt: (data: Uint8Array, output?: Uint8Array) => fn(key, nonce, data, output, counter),
});

export const NOBLE = {
  // Hashes
  blake224: nobleBlake1.blake224,
  blake256: nobleBlake1.blake256,
  blake384: nobleBlake1.blake384,
  blake512: nobleBlake1.blake512,
  blake2s: nobleBlake2.blake2s,
  blake2b: nobleBlake2.blake2b,
  blake3: nobleBlake3.blake3,
  md5: nobleLegacy.md5,
  ripemd160: nobleLegacy.ripemd160,
  sha1: nobleLegacy.sha1,
  sha224: nobleSha2.sha224,
  sha256: nobleSha2.sha256,
  sha384: nobleSha2.sha384,
  sha512_224: nobleSha2.sha512_224,
  sha512_256: nobleSha2.sha512_256,
  sha512: nobleSha2.sha512,
  sha3_224: nobleSha3.sha3_224,
  sha3_256: nobleSha3.sha3_256,
  sha3_384: nobleSha3.sha3_384,
  sha3_512: nobleSha3.sha3_512,
  keccak_224: nobleSha3.keccak_224,
  keccak_256: nobleSha3.keccak_256,
  keccak_384: nobleSha3.keccak_384,
  keccak_512: nobleSha3.keccak_512,
  shake128: nobleSha3.shake128,
  shake256: nobleSha3.shake256,
  shake128_32: nobleSha3.shake128_32,
  shake256_64: nobleSha3.shake256_64,
  // Ciphers/ARX
  salsa20: xorCipher(nobleSalsa.salsa20),
  xsalsa20: xorCipher(nobleSalsa.xsalsa20),
  xsalsa20poly1305: nobleSalsa.xsalsa20poly1305,
  chacha8: xorCipher(nobleChacha.chacha8),
  chacha12: xorCipher(nobleChacha.chacha12),
  chacha20orig: xorCipher(nobleChacha.chacha20orig),
  chacha20: xorCipher(nobleChacha.chacha20),
  xchacha20: xorCipher(nobleChacha.xchacha20),
  chacha20poly1305: nobleChacha.chacha20poly1305,
  xchacha20poly1305: nobleChacha.xchacha20poly1305,
  poly1305: noblePoly.poly1305,
  // Ciphers/AES
  ctr: nobleAes.ctr,
  ecb: nobleAes.ecb,
  cbc: nobleAes.cbc,
  cfb: nobleAes.cfb,
  gcm: nobleAes.gcm,
  gcmsiv: nobleAes.gcmsiv,
  aessiv: nobleAes.aessiv,
  aeskw: nobleAes.aeskw,
  aeskwp: nobleAes.aeskwp,
  // MAC
  cmac: nobleAes.cmac,
  polyval: noblePolyval.polyval,
  ghash: noblePolyval.ghash,
};
