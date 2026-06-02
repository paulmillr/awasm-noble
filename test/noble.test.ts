import { describe, should } from '@paulmillr/jsbt/test.js';
import { deepStrictEqual as eql, rejects, strictEqual, throws } from 'node:assert';
import { createCipheriv } from 'node:crypto';
import * as nobleAes from '@noble/ciphers/aes.js';
import * as nobleChacha from '@noble/ciphers/chacha.js';
import * as noblePoly from '@noble/ciphers/_poly1305.js';
import * as nobleSha2 from '@noble/hashes/sha2.js';
import * as nobleSha3 from '@noble/hashes/sha3.js';
import * as nobleScrypt from '@noble/hashes/scrypt.js';
import * as noble from '../src/noble.ts';
import * as js from '../src/targets/js/index.ts';
import * as wasm from '../src/targets/wasm/index.ts';
import * as wasm_threads from '../src/targets/wasm_threads/index.ts';
import { mkCipherStub } from '../src/ciphers-abstract.ts';
import { ctr as def_ctr } from '../src/ciphers.ts';
import { mkHashStub } from '../src/hashes-abstract.ts';
import { scrypt as def_scrypt, sha256 as def_sha256 } from '../src/hashes.ts';
import { mkKDFStub } from '../src/kdf.ts';
import { concatBytes } from '../src/utils.ts';

const bytes = (len: number, seed = 1) =>
  Uint8Array.from({ length: len }, (_, i) => (i * 17 + seed) & 255);
const msg = bytes(333, 9);
const msg2 = bytes(333, 19);
const compiled = { js, wasm, wasm_threads };
const macKeys = {
  poly1305: bytes(32, 21),
  cmac: bytes(16, 22),
  ghash: bytes(16, 23),
  polyval: bytes(16, 24),
};
const hashArg = (name: string, out?: Uint8Array, outPos?: number) => {
  const key = macKeys[name];
  if (!out) return key;
  return key ? { key, out, outPos } : { out, outPos };
};
const hashCall = (fn: any, name: string, data: Uint8Array, out?: Uint8Array, outPos?: number) => {
  const opts = hashArg(name, out, outPos);
  return opts ? fn(data, opts) : fn(data);
};
const chunksCall = (
  fn: any,
  name: string,
  parts: Uint8Array[],
  out?: Uint8Array,
  outPos?: number
) => {
  const opts = hashArg(name, out, outPos);
  return opts ? fn.chunks(parts, opts) : fn.chunks(parts);
};
const parallelCall = (
  fn: any,
  name: string,
  parts: Uint8Array[],
  out?: Uint8Array,
  outPos?: number
) => {
  const opts = hashArg(name, out, outPos);
  return opts ? fn.parallel(parts, opts) : fn.parallel(parts);
};

describe('noble platform', () => {
  should('hashes: one-shot, create, chunks, parallel, async, out/outPos', async () => {
    const exp = nobleSha2.sha256(msg);
    eql(noble.sha256(msg), exp);
    eql(noble.sha256.chunks([msg.subarray(0, 111), msg.subarray(111)]), exp);
    eql(noble.sha256.create().update(msg.subarray(0, 70)).update(msg.subarray(70)).digest(), exp);

    const out = new Uint8Array(40);
    const res = noble.sha256(msg, { out, outPos: 4 });
    strictEqual(res.buffer, out.buffer);
    eql(out.subarray(4, 36), exp);

    const exp2 = nobleSha2.sha256(msg2);
    const parOut = new Uint8Array(1 + 2 * exp.length);
    const par = noble.sha256.parallel([msg, msg2], { out: parOut, outPos: 1 });
    eql(parOut.subarray(1, 33), exp);
    eql(parOut.subarray(33, 65), exp2);
    eql(par, [parOut.subarray(1, 33), parOut.subarray(33, 65)]);

    let ticks = 0;
    const asyncOut = await noble.sha256.async(msg, {
      asyncTick: 0,
      nextTick: async () => {
        ticks++;
      },
    });
    eql(asyncOut, exp);
    eql(ticks > 0, true);
  });

  should('hashes: prefixState seeds parallel lanes', () => {
    const prefix = bytes(64, 29);
    const suffix = [bytes(37, 30), bytes(37, 31)];
    const state = noble.sha256.create().update(prefix).exportState();
    eql(
      noble.sha256.parallel(suffix, { prefixState: state }),
      suffix.map((i) => nobleSha2.sha256(concatBytes(prefix, i)))
    );
    noble.sha256.cleanState(state);
  });

  should('fixed hashes honor short stream dkLen', () => {
    eql(
      noble.sha512.create({ dkLen: 24 }).update(msg).digest(),
      nobleSha2.sha512(msg).subarray(0, 24)
    );
  });

  should('xof hashes honor dkLen and xof output', () => {
    eql(noble.shake256(msg, { dkLen: 48 }), nobleSha3.shake256(msg, { dkLen: 48 }));
    eql(
      noble.shake256.create({ dkLen: 16 }).update(msg).digest(),
      nobleSha3.shake256(msg, { dkLen: 16 })
    );
    const xof = noble.shake256.create().update(msg).xof(40);
    eql(xof, nobleSha3.shake256.create().update(msg).xof(40));
  });

  should('hashes match compiled platforms for shared APIs', () => {
    const parts = [msg.subarray(0, 111), msg.subarray(111)];
    const batch = [msg, msg2];
    for (const name in noble) {
      const nfn = noble[name];
      if (typeof nfn?.parallel !== 'function') continue;
      if (macKeys[name]) continue;
      for (const platformName in compiled) {
        const pfn = compiled[platformName][name];
        if (typeof pfn?.parallel !== 'function') continue;
        const exp = hashCall(pfn, name, msg);
        eql(hashCall(nfn, name, msg), exp, `${name}: direct matches ${platformName}`);
        eql(chunksCall(nfn, name, parts), chunksCall(pfn, name, parts), `${name}: chunks`);
        eql(parallelCall(nfn, name, batch), parallelCall(pfn, name, batch), `${name}: parallel`);
        const out = new Uint8Array(3 + nfn.outputLen);
        const res = hashCall(nfn, name, msg, out, 3);
        strictEqual(res.buffer, out.buffer);
        eql(out.subarray(3, 3 + nfn.outputLen), exp, `${name}: out/outPos`);
        eql(nfn.create().update(parts[0]).update(parts[1]).digest(), exp, `${name}: create`);
      }
    }
  });

  should('MACs support direct wrappers and refuse unsupported streaming', () => {
    const key32 = macKeys.poly1305;
    const key16 = macKeys.ghash;
    eql(noble.poly1305(msg, key32), noblePoly.poly1305(msg, key32));
    eql(
      noble.poly1305.chunks([msg.subarray(0, 19), msg.subarray(19)], key32),
      noblePoly.poly1305(msg, key32)
    );
    throws(() => noble.poly1305.create(key32));
    throws(() => noble.cmac.create(key32));
    throws(() => noble.ghash.create(key16));
  });

  should('ciphers wrap noble-ciphers and throw on streaming create', () => {
    const key16 = bytes(16, 1);
    const key32 = bytes(32, 2);
    const nonce16 = bytes(16, 3);
    const nonce12 = bytes(12, 4);
    const ctr = noble.ctr(key16, nonce16).encrypt(msg);
    eql(ctr, nobleAes.ctr(key16, nonce16).encrypt(msg));
    eql(noble.ctr(key16, nonce16).decrypt(ctr), msg);
    const out = new Uint8Array(msg.length + 2);
    const outRes = noble.ctr(key16, nonce16).encrypt(msg, out);
    strictEqual(outRes.buffer, out.buffer);
    eql(out.subarray(0, msg.length), ctr);
    throws(() => (noble.ctr(key16, nonce16).encrypt as any).create());

    eql(
      noble.chacha20(key32, nonce12, { counter: 7 }).encrypt(msg),
      nobleChacha.chacha20(key32, nonce12, msg, undefined, 7)
    );
    const gcm = noble.gcm(key16, nonce12, msg2.subarray(0, 9)).encrypt(msg);
    eql(gcm, nobleAes.gcm(key16, nonce12, msg2.subarray(0, 9)).encrypt(msg));
  });

  should('ciphers match compiled platforms for one-shot APIs', async () => {
    const key16 = bytes(16, 1);
    const key24 = bytes(24, 2);
    const key32 = bytes(32, 3);
    const key64 = bytes(64, 4);
    const nonce8 = bytes(8, 5);
    const nonce12 = bytes(12, 6);
    const nonce16 = bytes(16, 7);
    const nonce24 = bytes(24, 8);
    const aad = bytes(13, 9);
    const blockData = bytes(320, 10);
    const kwData = bytes(32, 11);
    const kwpData = bytes(23, 12);
    const cases = [
      { name: 'ctr', args: [key16, nonce16], data: msg },
      { name: 'cbc', args: [key24, nonce16], data: msg },
      { name: 'ofb', args: [key32, nonce16], data: msg },
      { name: 'cfb', args: [key16, nonce16], data: msg },
      { name: 'ecb', args: [key32], data: msg },
      { name: 'gcm', args: [key16, nonce12, aad], data: msg },
      { name: 'gcmsiv', args: [key32, nonce12, aad], data: msg },
      { name: 'aessiv', args: [key64, aad, nonce16, nonce24], data: msg },
      { name: 'aeskw', args: [key32], data: kwData },
      { name: 'aeskwp', args: [key32], data: kwpData },
      { name: 'salsa20', args: [key32, nonce8, { counter: 7 }], data: msg },
      { name: 'xsalsa20', args: [key32, nonce24, { counter: 7 }], data: msg },
      { name: 'chacha8', args: [key32, nonce12, { counter: 7 }], data: msg },
      { name: 'chacha12', args: [key32, nonce12, { counter: 7 }], data: msg },
      { name: 'chacha20', args: [key32, nonce12, { counter: 7 }], data: msg },
      { name: 'chacha20orig', args: [key32, nonce8, { counter: 7 }], data: msg },
      { name: 'xchacha20', args: [key32, nonce24, { counter: 7 }], data: msg },
      { name: 'chacha20poly1305', args: [key32, nonce12, aad], data: msg },
      { name: 'xchacha20poly1305', args: [key32, nonce24, aad], data: msg },
      { name: 'xsalsa20poly1305', args: [key32, nonce24], data: blockData },
    ];
    for (const c of cases) {
      const nfn = noble[c.name];
      const noOutput = !!nfn.getDefinition().noOutput;
      for (const platformName in compiled) {
        const pfn = compiled[platformName][c.name];
        const exp = pfn(...c.args).encrypt(c.data);
        const enc = nfn(...c.args).encrypt(c.data);
        eql(enc, exp, `${c.name}: noble encrypt matches ${platformName}`);
        eql(nfn(...c.args).decrypt(exp), c.data, `${c.name}: noble decrypts ${platformName}`);
        eql(pfn(...c.args).decrypt(enc), c.data, `${c.name}: ${platformName} decrypts noble`);
        eql(
          await nfn(...c.args).encrypt.async(c.data, undefined, { asyncTick: 0 }),
          exp,
          `${c.name}: noble async encrypt matches ${platformName}`
        );
        eql(
          await nfn(...c.args).decrypt.async(exp, undefined, { asyncTick: 0 }),
          c.data,
          `${c.name}: noble async decrypt matches ${platformName}`
        );
        if (!noOutput) {
          const out = new Uint8Array(exp.length);
          const res = nfn(...c.args).encrypt(c.data, out);
          strictEqual(res.buffer, out.buffer);
          eql(out, exp, `${c.name}: noble encrypt output matches ${platformName}`);
        }
        throws(() => nfn(...c.args).encrypt.create());
      }
    }
  });

  should('MACs match compiled platforms for direct, chunks, and parallel', async () => {
    const cases = [
      { name: 'poly1305', key: bytes(32, 21) },
      { name: 'cmac', key: bytes(16, 22) },
      { name: 'ghash', key: bytes(16, 23) },
      { name: 'polyval', key: bytes(16, 24) },
    ];
    const batch = [msg, msg2];
    for (const c of cases) {
      const nfn = noble[c.name];
      for (const platformName in compiled) {
        const pfn = compiled[platformName][c.name];
        const exp = pfn(msg, c.key);
        eql(nfn(msg, c.key), exp, `${c.name}: noble direct matches ${platformName}`);
        eql(
          nfn.chunks([msg.subarray(0, 111), msg.subarray(111)], c.key),
          pfn.chunks([msg.subarray(0, 111), msg.subarray(111)], c.key),
          `${c.name}: noble chunks matches ${platformName}`
        );
        eql(
          nfn.parallel(batch, c.key),
          pfn.parallel(batch, c.key),
          `${c.name}: noble parallel matches ${platformName}`
        );
        const out = new Uint8Array(3 + nfn.outputLen * batch.length);
        const res = nfn.parallel(batch, { key: c.key, out, outPos: 3 });
        strictEqual(res[0].buffer, out.buffer);
        eql(out.subarray(3, 3 + nfn.outputLen), exp);
        eql(
          await nfn.parallel.async(batch, { key: c.key, asyncTick: 0 }),
          pfn.parallel(batch, c.key),
          `${c.name}: noble async parallel matches ${platformName}`
        );
      }
    }
  });

  should('KDFs match compiled platforms', async () => {
    const argonOpts = { t: 1, m: 256, p: 1, dkLen: 16 };
    const cases = [
      { name: 'scrypt', args: ['password', 'salt', { N: 16, r: 1, p: 1, dkLen: 16 }] },
      { name: 'argon2d', args: ['password', 'salt-salt', argonOpts] },
      { name: 'argon2i', args: ['password', 'salt-salt', argonOpts] },
      { name: 'argon2id', args: ['password', 'salt-salt', argonOpts] },
    ];
    for (const c of cases) {
      const nfn = noble[c.name];
      for (const platformName in compiled) {
        const pfn = compiled[platformName][c.name];
        const exp = pfn(...c.args);
        eql(nfn(...c.args), exp, `${c.name}: noble matches ${platformName}`);
        eql(await nfn.async(...c.args), exp, `${c.name}: noble async matches ${platformName}`);
      }
      const badOpts = { ...(c.args[2] as object), nextTick: async () => {} };
      throws(() => nfn(c.args[0], c.args[1], badOpts), {
        message: '"nextTick" is not supported',
      });
      await rejects(() => nfn.async(c.args[0], c.args[1], badOpts), {
        message: '"nextTick" is not supported',
      });
    }
  });

  should('ofb uses noble AES unsafe API compatibly with node crypto', () => {
    const key = bytes(16, 11);
    const iv = bytes(16, 12);
    const cipher = createCipheriv('aes-128-ofb', key, iv);
    const exp = new Uint8Array([...cipher.update(msg), ...cipher.final()]);
    const ct = noble.ofb(key, iv).encrypt(msg);
    eql(ct, exp);
    eql(noble.ofb(key, iv).decrypt(ct), msg);
  });

  should('installs into hash, cipher, and KDF stubs', () => {
    const h = mkHashStub(def_sha256);
    throws(() => h.getPlatform());
    h.install(noble.sha256, { onlyMissing: true });
    eql(h.getPlatform(), 'noble');
    h.install(noble.sha512 as any, { onlyMissing: true });
    eql(h(msg), nobleSha2.sha256(msg));
    h.install(noble.sha256);
    eql(h.getPlatform(), 'noble');
    eql(h(msg), nobleSha2.sha256(msg));
    throws(() => mkHashStub(def_sha256).install(noble.sha512 as any, { onlyMissing: true }));

    const c = mkCipherStub(def_ctr);
    c.install(noble.ctr, { onlyMissing: true });
    c.install(noble.cbc as any, { onlyMissing: true });
    eql(c.getPlatform(), 'noble');
    eql(c(bytes(16), bytes(16)).encrypt(msg), noble.ctr(bytes(16), bytes(16)).encrypt(msg));
    throws(() => mkCipherStub(def_ctr).install(noble.cbc as any, { onlyMissing: true }));

    const k = mkKDFStub(def_scrypt);
    k.install(noble.scrypt, { onlyMissing: true });
    k.install(noble.argon2d as any, { onlyMissing: true });
    eql(k.getPlatform(), 'noble');
    eql(
      k('password', 'salt', { N: 16, r: 1, p: 1, dkLen: 16 }),
      nobleScrypt.scrypt('password', 'salt', { N: 16, r: 1, p: 1, dkLen: 16 })
    );
    throws(() => mkKDFStub(def_scrypt).install(noble.argon2d as any, { onlyMissing: true }));
  });
});

should.runWhen(import.meta.url);
