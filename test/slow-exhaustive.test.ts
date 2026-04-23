import { describe, should } from '@paulmillr/jsbt/test.js';
import { deepStrictEqual } from 'node:assert';
import * as js from '../src/targets/js/index.ts';
import * as wasm from '../src/targets/wasm/index.ts';
import * as wasm_threads from '../src/targets/wasm_threads/index.ts';
import { WP } from '../src/workers.ts';
import { NOBLE } from './noble-all.ts';
import { startTests } from './platforms.ts';

const EMPTY = new Uint8Array(0);
const MAX = 16 * 1024 + 1;
const SIZES = Array.from({ length: MAX }, (_, i) => i + 1);
const ASYNC_OPTS = { asyncTick: 0 };
const PLATFORMS = { wasm, wasm_threads, js } as const;
const HASH_NAMES = [
  'blake224',
  'blake256',
  'blake384',
  'blake512',
  'blake2s',
  'blake2b',
  'blake3',
  'md5',
  'ripemd160',
  'sha1',
  'sha224',
  'sha256',
  'sha384',
  'sha512_224',
  'sha512_256',
  'sha512',
  'sha3_224',
  'sha3_256',
  'sha3_384',
  'sha3_512',
  'keccak_224',
  'keccak_256',
  'keccak_384',
  'keccak_512',
  'shake128',
  'shake256',
  'shake128_32',
  'shake256_64',
] as const;
const HASH_DK = {
  blake2s: 32,
  blake2b: 64,
  blake3: MAX,
  shake128: MAX,
  shake256: MAX,
  shake128_32: MAX,
  shake256_64: MAX,
} as const;
const MACS = [
  { name: 'poly1305', keyLen: 32 },
  { name: 'ghash', keyLen: 16 },
  { name: 'polyval', keyLen: 16 },
  { name: 'cmac', keyLen: 32 },
] as const;
const CIPHERS = [
  { name: 'ctr', keyLen: 32, nonceLen: 16 },
  { name: 'cbc', keyLen: 32, nonceLen: 16 },
  { name: 'cfb', keyLen: 32, nonceLen: 16 },
  { name: 'ecb', keyLen: 32 },
  { name: 'gcm', keyLen: 32, nonceLen: 12, aadLens: [5] },
  { name: 'gcmsiv', keyLen: 32, nonceLen: 12, aadLens: [5] },
  { name: 'aessiv', keyLen: 32, aadLens: [5, 9] },
  { name: 'aeskw', keyLen: 32, valid: (size: number) => size >= 16 && size % 8 === 0 },
  { name: 'aeskwp', keyLen: 32 },
  { name: 'salsa20', keyLen: 32, nonceLen: 8 },
  { name: 'xsalsa20', keyLen: 32, nonceLen: 24 },
  { name: 'chacha20', keyLen: 32, nonceLen: 12 },
  { name: 'xchacha20', keyLen: 32, nonceLen: 24 },
  { name: 'chacha20poly1305', keyLen: 32, nonceLen: 12, aadLens: [5] },
  { name: 'xchacha20poly1305', keyLen: 32, nonceLen: 24, aadLens: [5] },
  { name: 'xsalsa20poly1305', keyLen: 32, nonceLen: 24 },
] as const;

const eq = (label: string, actual: unknown, expected: unknown) =>
  deepStrictEqual(actual, expected, label);

const bytes = (len: number, seed = 0) => {
  const out = new Uint8Array(len);
  for (let i = 0; i < len; i++) out[i] = (len * 17 + seed * 29 + i * 131 + (i >>> 1)) & 255;
  return out;
};

const join = (parts: Uint8Array[]) => {
  let len = 0;
  for (const part of parts) len += part.length;
  const out = new Uint8Array(len);
  let pos = 0;
  for (const part of parts) {
    out.set(part, pos);
    pos += part.length;
  }
  return out;
};

const split = (buf: Uint8Array) => {
  const len = buf.length;
  const a = len ? Math.max(1, Math.floor(len / 3)) : 0;
  const b = len > a ? Math.floor((len - a) / 2) : 0;
  return [buf.subarray(0, a), buf.subarray(a, a + b), buf.subarray(a + b)];
};

const batch = (len: number, seed = 0) => [
  bytes(len, seed),
  bytes(len, seed + 1),
  bytes(len, seed + 2),
];

const splitTag = (factory: any, data: Uint8Array) => {
  const def = factory.getDefinition();
  if (!def.tagLength) return { ct: data, tag: undefined };
  if (def.tagLeft) {
    const tag = data.subarray(0, def.tagLength);
    return { ct: data.subarray(def.tagLength), tag };
  }
  const tag = data.subarray(data.length - def.tagLength);
  return { ct: data.subarray(0, data.length - def.tagLength), tag };
};

const streamEncrypt = (cipher: any, parts: Uint8Array[], tagLeft = false) => {
  const stream = cipher.encrypt.create();
  const out: Uint8Array[] = [];
  for (const part of parts) out.push(stream.update(part));
  const { data, tag } = stream.finish();
  if (data.length) out.push(data);
  if (!tag) return join(out);
  return tagLeft ? join([tag, ...out]) : join([...out, tag]);
};

const streamDecrypt = (factory: any, parts: Uint8Array[], tag?: Uint8Array) => {
  const stream = factory.decrypt.create();
  const out: Uint8Array[] = [];
  for (const part of parts) out.push(stream.update(part));
  const { data } = tag ? stream.finish(tag) : stream.finish();
  if (data.length) out.push(data);
  return join(out);
};

const cipherArgs = (spec: (typeof CIPHERS)[number], size: number, seed: number): Uint8Array[] => {
  const args: Uint8Array[] = [];
  if (spec.nonceLen) args.push(bytes(spec.nonceLen, seed));
  if (spec.aadLens) {
    for (let i = 0; i < spec.aadLens.length; i++) {
      const len = spec.aadLens[i] + (size % (i + 5));
      args.push(len ? bytes(len, seed + 10 + i) : EMPTY);
    }
  }
  return args;
};

const hashInput = bytes(257, 91);
const hashInputParts = split(hashInput);
const hashBatch = batch(hashInput.length, 111);

for (const [platform, mod] of Object.entries(PLATFORMS) as [keyof typeof PLATFORMS, any][]) {
  describe(String(platform), () => {
    describe('hashes', () => {
      for (const name of HASH_NAMES) {
        const ver = mod[name];
        if (!ver) continue;
        should(name, async () => {
          const ref = NOBLE[name];
          await WP.waitOnline();
          for (const size of SIZES) {
            const msg = bytes(size, 1);
            const parts = split(msg);
            const msgs = batch(size, 11);
            const exp = ref(msg);
            const expParallel = msgs.map((item) => ref(item));
            eq(`${name} ${platform} sync size=${size}`, ver(msg), exp);
            eq(`${name} ${platform} chunks size=${size}`, ver.chunks(parts), exp);
            eq(
              `${name} ${platform} create size=${size}`,
              ver.create().update(parts[0]).update(parts[1]).update(parts[2]).digest(),
              exp
            );
            eq(`${name} ${platform} parallel size=${size}`, ver.parallel(msgs), expParallel);
            eq(`${name} ${platform} async size=${size}`, await ver.async(msg, ASYNC_OPTS), exp);
            eq(
              `${name} ${platform} chunks.async size=${size}`,
              await ver.chunks.async(parts, ASYNC_OPTS),
              exp
            );
            eq(
              `${name} ${platform} parallel.async size=${size}`,
              await ver.parallel.async(msgs, ASYNC_OPTS),
              expParallel
            );
          }
        });
      }
      for (const [name, maxDkLen] of Object.entries(HASH_DK)) {
        const ver = mod[name];
        if (!ver) continue;
        should(`${name} dkLen`, async () => {
          const ref = NOBLE[name as keyof typeof NOBLE];
          await WP.waitOnline();
          for (let dkLen = 1; dkLen <= maxDkLen; dkLen++) {
            const opts = { dkLen };
            const exp = ref(hashInput, opts);
            const expParallel = hashBatch.map((item) => ref(item, opts));
            eq(`${name} ${platform} dkLen sync=${dkLen}`, ver(hashInput, opts), exp);
            eq(`${name} ${platform} dkLen chunks=${dkLen}`, ver.chunks(hashInputParts, opts), exp);
            eq(
              `${name} ${platform} dkLen create=${dkLen}`,
              ver
                .create(opts)
                .update(hashInputParts[0])
                .update(hashInputParts[1])
                .update(hashInputParts[2])
                .digest(),
              exp
            );
            eq(
              `${name} ${platform} dkLen parallel=${dkLen}`,
              ver.parallel(hashBatch, opts),
              expParallel
            );
            eq(
              `${name} ${platform} dkLen async=${dkLen}`,
              await ver.async(hashInput, { ...ASYNC_OPTS, dkLen }),
              exp
            );
            eq(
              `${name} ${platform} dkLen chunks.async=${dkLen}`,
              await ver.chunks.async(hashInputParts, { ...ASYNC_OPTS, dkLen }),
              exp
            );
            eq(
              `${name} ${platform} dkLen parallel.async=${dkLen}`,
              await ver.parallel.async(hashBatch, { ...ASYNC_OPTS, dkLen }),
              expParallel
            );
          }
        });
      }
    });

    describe('macs', () => {
      for (const { name, keyLen } of MACS) {
        const ver = mod[name];
        if (!ver) continue;
        should(name, async () => {
          const ref = NOBLE[name];
          const key = bytes(keyLen, 201);
          await WP.waitOnline();
          for (const size of SIZES) {
            const msg = bytes(size, 3);
            const parts = split(msg);
            const msgs = batch(size, 21);
            const exp = ref(msg, key);
            const expParallel = msgs.map((item) => ref(item, key));
            eq(`${name} ${platform} sync size=${size}`, ver(msg, key), exp);
            eq(`${name} ${platform} chunks size=${size}`, ver.chunks(parts, key), exp);
            eq(
              `${name} ${platform} create size=${size}`,
              ver.create(key).update(parts[0]).update(parts[1]).update(parts[2]).digest(),
              exp
            );
            eq(`${name} ${platform} parallel size=${size}`, ver.parallel(msgs, key), expParallel);
            eq(
              `${name} ${platform} async size=${size}`,
              await ver.async(msg, key, ASYNC_OPTS),
              exp
            );
            eq(
              `${name} ${platform} chunks.async size=${size}`,
              await ver.chunks.async(parts, key, ASYNC_OPTS),
              exp
            );
            eq(
              `${name} ${platform} parallel.async size=${size}`,
              await ver.parallel.async(msgs, key, ASYNC_OPTS),
              expParallel
            );
          }
        });
      }
    });

    describe('ciphers', () => {
      for (const spec of CIPHERS) {
        const ver = mod[spec.name];
        if (!ver) continue;
        should(spec.name, async () => {
          const refFactory = NOBLE[spec.name];
          const key = bytes(spec.keyLen, 251);
          const def = ver.getDefinition();
          const noStream = def.noStream;
          const tagLeft = !!def.tagLeft;
          for (const size of SIZES) {
            if (spec.valid && !spec.valid(size)) continue;
            const msg = bytes(size, 7);
            const parts = split(msg);
            const args = cipherArgs(spec, size, 31);
            const expEnc = refFactory(key, ...args).encrypt(msg);
            const expDec = refFactory(key, ...args).decrypt(expEnc);
            const syncEnc = ver(key, ...args).encrypt(msg);
            eq(`${spec.name} ${platform} encrypt size=${size}`, syncEnc, expEnc);
            eq(
              `${spec.name} ${platform} decrypt size=${size}`,
              ver(key, ...args).decrypt(expEnc),
              expDec
            );
            const asyncEnc = await ver(key, ...args).encrypt.async(msg, undefined, ASYNC_OPTS);
            eq(`${spec.name} ${platform} encrypt.async size=${size}`, asyncEnc, expEnc);
            eq(
              `${spec.name} ${platform} decrypt.async size=${size}`,
              await ver(key, ...args).decrypt.async(expEnc, undefined, ASYNC_OPTS),
              expDec
            );
            if (noStream) continue;
            eq(
              `${spec.name} ${platform} stream.encrypt size=${size}`,
              streamEncrypt(ver(key, ...args), parts, tagLeft),
              expEnc
            );
            const { ct, tag } = splitTag(ver, expEnc);
            eq(
              `${spec.name} ${platform} stream.decrypt size=${size}`,
              streamDecrypt(ver(key, ...args), split(ct), tag),
              expDec
            );
          }
        });
      }
    });
  });
}

startTests(import.meta.url);
