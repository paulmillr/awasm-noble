import { describe, should } from '@paulmillr/jsbt/test.js';
import { deepStrictEqual as eql, throws } from 'node:assert';
import { createCipheriv, createDecipheriv, getCiphers } from 'node:crypto';
import { concatBytes, managedNonce } from '../../src/utils.ts';
import { TYPE_TEST, unalign } from './utils.ts';
import { randomBytes } from '@noble/hashes/utils.js';
import { PLATFORMS } from '../platforms.ts';

const KB = 1024;
const MB = 1024 * KB;
const GB = 1024 * MB;
const SLOW = process.argv.includes('slow');
const SMALL_KEYS = false;
const isDeno = 'deno' in process.versions;
const empty = new Uint8Array(0);
const nodeCiphers = new Set(getCiphers());
const buf = (n: number) => new Uint8Array(n).fill(n % 251);
const chunks = (array: Uint8Array, length: number) => {
  const out = [];
  const total = Math.ceil(array.length / length);
  for (let i = 0; i < total; i++) {
    const start = i * length;
    const end = Math.min(start + length, array.length);
    out.push(array.subarray(start, end));
  }
  return out;
};
const nodeCipher = (name: string, pcks7 = true) => ({
  encrypt: (buf: Uint8Array, opts: any) => {
    const res = [];
    const c = createCipheriv(name, opts.key, opts.iv || empty);
    c.setAutoPadding(pcks7);
    for (const b of chunks(buf, 1 * GB)) res.push(c.update(b));
    res.push(c.final());
    return concatBytes(...res.map((i) => Uint8Array.from(i)));
  },
  decrypt: (buf: Uint8Array, opts: any) => {
    const ciphertext = buf.slice();
    const res = [];
    const c = createDecipheriv(name, opts.key, opts.iv || empty);
    c.setAutoPadding(pcks7);
    for (const b of chunks(ciphertext, 1 * GB)) res.push(c.update(b));
    res.push(c.final());
    return concatBytes(...res.map((i) => Uint8Array.from(i)));
  },
});

function test(name: string, { ofb }: any) {
  if (typeof ofb !== 'function') return;

  const CIPHERS: Record<string, any> = {};
  for (const keyLen of [16, 24, 32])
    CIPHERS[`ofb_${keyLen * 8}`] = { fn: ofb, keyLen, withNonce: true };
  for (const k in CIPHERS) {
    const opts = CIPHERS[k];
    CIPHERS[`${k}_managedNonce`] = { ...opts, fn: managedNonce(opts.fn), withNonce: false };
  }

  const checkBlockSize = (opts: any, len: number) => {
    if (opts.minLength && len < opts.minLength) return false;
    if (!len && opts.disableEmptyBlock) return false;
    if (!opts.blockSize) return true;
    if (len % opts.blockSize === 0) return true;
    return false;
  };
  const initCipher = (opts: any) => {
    const { fn, keyLen, withNonce } = opts;
    const args = opts.args || [];
    const key = randomBytes(keyLen);
    const nonce = randomBytes(fn.nonceLength);
    const c = withNonce ? fn(key, nonce, ...args) : fn(key, ...args);
    return { c, key, nonce, copy: { key: key.slice(), nonce: nonce.slice() } };
  };
  const overlapTest = (a: Uint8Array, b: Uint8Array, cb: any) => {
    const buffer = new Uint8Array(a.length + b.length);
    let inputPos = 0;
    let outputPos = a.length;
    const t = () => {
      const aBuf = buffer.subarray(inputPos, inputPos + a.length);
      const bBuf = buffer.subarray(outputPos, outputPos + b.length);
      cb(aBuf, bBuf, buffer);
    };
    for (; outputPos > 0; outputPos--) t();
    for (; inputPos <= b.length; inputPos++) t();
  };

  describe(`Basic (${name})`, () => {
    for (const k in CIPHERS) {
      const opts = CIPHERS[k];
      should(`${k}: blockSize`, () => {
        const { c, key, nonce, copy } = initCipher(opts);
        const msg = new Uint8Array(opts.blockSize).fill(12);
        const msgCopy = msg.slice();
        if (checkBlockSize(opts, msgCopy.length)) {
          eql(c.decrypt(c.encrypt(msgCopy)), msg);
          eql(msg, msgCopy);
          eql(key, copy.key);
          eql(nonce, copy.nonce);
        }
      });
      if (opts.blockSize) {
        should(`${k}: wrong blockSize`, () => {
          const { c } = initCipher(opts);
          const msg = new Uint8Array(opts.blockSize - 1).fill(12);
          throws(() => c.encrypt(msg));
          throws(() => c.decrypt(msg));
        });
      }
      should(`${k}: round-trip`, () => {
        const msg = new Uint8Array(2).fill(12);
        const msgCopy = msg.slice();
        if (checkBlockSize(opts, msgCopy.length)) {
          const { c } = initCipher(opts);
          eql(c.decrypt(c.encrypt(msgCopy)), msg);
          eql(msg, msgCopy);
        }

        const msg2 = new Uint8Array(2048).fill(255);
        const msg2Copy = msg2.slice();
        if (checkBlockSize(opts, msg2Copy.length)) {
          const { c } = initCipher(opts);
          eql(c.decrypt(c.encrypt(msg2)), msg2);
          eql(msg2, msg2Copy);
        }

        const { c, key, nonce, copy } = initCipher(opts);
        const msg3 = new Uint8Array(256).fill(3);
        const msg3Copy = msg3.slice();
        if (!checkBlockSize(opts, msg3Copy.length)) {
          eql(c.decrypt(c.encrypt(msg3Copy)), msg3);
          eql(msg3, msg3Copy);
        }
        eql(key, copy.key);
        eql(nonce, copy.nonce);
      });
      should(`${k}: different sizes`, () => {
        for (let i = 0; i < 2048; i++) {
          const msg = new Uint8Array(i).fill(i);
          const msgCopy = msg.slice();
          if (checkBlockSize(opts, msgCopy.length)) {
            const { c, key, nonce, copy } = initCipher(opts);
            eql(c.decrypt(c.encrypt(msg)), msg);
            eql(msg, msgCopy);
            eql(key, copy.key);
            eql(nonce, copy.nonce);
          }
        }
      });
      for (let i = 0; i < 8; i++) {
        should(`${k} (unalign ${i})`, () => {
          const { fn, keyLen } = opts;
          const key = unalign(randomBytes(keyLen), i);
          const nonce = unalign(randomBytes(fn.nonceLength), i);
          const AAD = unalign(randomBytes(64), i);
          const msg = unalign(new Uint8Array(2048).fill(255), i);
          if (checkBlockSize(opts, msg.length)) {
            const cipher = fn(key, nonce, AAD);
            const encrypted = unalign(cipher.encrypt(msg), i);
            const decrypted = cipher.decrypt(encrypted);
            eql(decrypted, msg);
          }
        });
      }
      should(`${k} (re-use)`, () => {
        const { fn, keyLen } = opts;
        const key = randomBytes(keyLen);
        const nonce = randomBytes(fn.nonceLength);
        const AAD = randomBytes(64);
        let cipher = fn(key, nonce, AAD);
        const pcksOutput = (len: number) => {
          const remaining = len % fn.blockSize;
          let left = fn.blockSize - remaining;
          if (!left) left = fn.blockSize;
          return left;
        };
        const messageLengths = [
          4,
          8,
          fn.blockSize,
          2 * fn.blockSize,
          5 * fn.blockSize,
          10 * fn.blockSize,
        ];
        messageLengths.push((1.5 * fn.blockSize) | 0);
        messageLengths.push((1.75 * fn.blockSize) | 0);
        const stats = { e_ok: 0, e_fail: 0, d_ok: 0, d_fail: 0 };
        for (const msgLen of messageLengths) {
          const msg = randomBytes(msgLen);
          const key = randomBytes(keyLen);
          const nonce = randomBytes(fn.nonceLength);
          const AAD = randomBytes(64);
          let cipher = fn(key, nonce, AAD);
          const mayThrow = ['cbc', 'ctr', 'ecb'].map((i) => k.includes(i)).includes(true);
          const pkcs5 = ['cbc', 'ecb'].map((i) => k.includes(i)).includes(true);
          for (let fillByte = 0; fillByte < 256; fillByte++) {
            if (cipher.encrypt.length === 2) {
              let outLen = msg.length;
              if (fn.tagLength) outLen += fn.tagLength;
              if (k === 'xsalsa20poly1305') outLen += 16;
              if (pkcs5) outLen += pcksOutput(msg.length);
              cipher = fn(key, nonce, AAD);
              const exp = cipher.encrypt(msg);
              const out = new Uint8Array(outLen);
              cipher = fn(key, nonce, AAD);
              const res = cipher.encrypt(msg, out);
              eql(res, exp);
              eql(res, out.subarray(res.byteOffset, res.byteOffset + res.length));
              eql(res.buffer, out.buffer);
              out.fill(fillByte);
              cipher = fn(key, nonce, AAD);
              const res2 = cipher.encrypt(msg, out);
              eql(res2, exp);
              eql(res2, out.subarray(res2.byteOffset, res2.byteOffset + res2.length));
              eql(res2.buffer, out.buffer);
              cipher = fn(key, nonce, AAD);
              out.fill(fillByte);
              out.set(msg);
              const msg2 = out.subarray(0, msg.length);
              eql(cipher.encrypt(msg2, out), exp);

              overlapTest(msg2, out, (msg2: Uint8Array, out2: Uint8Array, all: Uint8Array) => {
                all.fill(fillByte);
                msg2.set(msg);
                cipher = fn(key, nonce, AAD);
                let newOut;
                try {
                  newOut = cipher.encrypt(msg2, out2);
                  stats.e_ok++;
                } catch (e) {
                  stats.e_fail++;
                  if (mayThrow) return;
                  throw e;
                }
                eql(newOut.buffer, all.buffer);
                eql(newOut.buffer, out2.buffer);
                eql(newOut, exp);
              });
            }
            if (cipher.decrypt.length === 2) {
              cipher = fn(key, nonce, AAD);
              const input = cipher.encrypt(msg);
              let outLen = msg.length;
              if (k.endsWith('xsalsa20poly1305')) outLen += 32 + 16;
              if (pkcs5) outLen += pcksOutput(msg.length);
              const out = new Uint8Array(outLen);
              const res = cipher.decrypt(input, out);
              eql(res, msg);
              eql(res, out.subarray(res.byteOffset, res.byteOffset + res.length));
              eql(res.buffer, out.buffer);
              out.fill(fillByte);
              const res2 = cipher.decrypt(input, out);
              eql(res2, msg);
              eql(res2, out.subarray(res2.byteOffset, res2.byteOffset + res2.length));
              eql(res2.buffer, out.buffer);
              const tmp = new Uint8Array(Math.max(out.length, input.length));
              tmp.fill(fillByte);
              tmp.set(input);
              const out2 = tmp.subarray(0, out.length);
              const input2 = tmp.subarray(0, input.length);
              eql(cipher.decrypt(input2, out2), msg);

              overlapTest(input2, out2, (input2: Uint8Array, out2: Uint8Array, all: Uint8Array) => {
                all.fill(fillByte);
                input2.set(input);
                let newOut;
                try {
                  newOut = cipher.decrypt(input2, out2);
                  stats.d_ok++;
                } catch (e) {
                  stats.d_fail++;
                  if (mayThrow) return;
                  throw e;
                }
                eql(newOut.buffer, all.buffer);
                eql(newOut.buffer, out2.buffer);
                eql(newOut, msg);
              });
            }
          }
        }
      });
      should('unaligned', () => {
        if (!['xsalsa20poly1305', 'xchacha20poly1305', 'chacha20poly1305'].includes(k)) return;
        if (k.includes('managedNonce')) return;
      });
      should('be able to reuse input and output arrays', () => {
        if (!['xsalsa20poly1305', 'xchacha20poly1305', 'chacha20poly1305'].includes(k)) return;
        if (k.includes('managedNonce')) return;
      });
      const msg_10 = new Uint8Array(10);
      if (checkBlockSize(opts, msg_10.length) && !k.endsWith('_managedNonce')) {
        should(`${k}: prohibit encrypting twice`, () => {
          const { c } = initCipher(opts);
          c.encrypt(msg_10);
          throws(() => {
            c.encrypt(msg_10);
          });
        });
      }
    }
  });

  describe('input validation', () => {
    const INVALID_BYTE_ARRAYS = TYPE_TEST.bytes;
    for (const k in CIPHERS) {
      const opts = CIPHERS[k];
      const { fn, keyLen } = opts;
      if (k.includes('managed')) continue;
      describe(k, () => {
        should('reject invalid key', () => {
          const nonce = new Uint8Array(fn.nonceLength);
          for (const invalid of INVALID_BYTE_ARRAYS) throws(() => fn(invalid, nonce), 'non-u8a');
          const msg = new Uint8Array(1);
          throws(() => fn(new Uint8Array(keyLen + 1), nonce).encrypt(msg), 'key length + 1');
          throws(() => fn(new Uint8Array(keyLen - 1), nonce).encrypt(msg), 'key length - 1');
        });
        should('reject invalid nonce', () => {
          const key = new Uint8Array(keyLen);
          for (const invalid of INVALID_BYTE_ARRAYS) throws(() => fn(key, invalid));
          if (fn.varSizeNonce) return;
          const msg = new Uint8Array(1);
          throws(() => fn(key, new Uint8Array(fn.nonceLength + 1)).encrypt(msg));
          throws(() => fn(key, new Uint8Array(fn.nonceLength - 1)).encrypt(msg));
        });
        should('reject invalid encrypt input', () => {
          const key = new Uint8Array(keyLen);
          const nonce = fn.nonceLength ? new Uint8Array(fn.nonceLength) : undefined;
          const cipher = nonce ? fn(key, nonce) : fn(key);
          for (const invalid of INVALID_BYTE_ARRAYS) throws(() => cipher.encrypt(invalid));
        });
        should('reject invalid decrypt input', () => {
          const key = new Uint8Array(keyLen);
          const nonce = fn.nonceLength ? new Uint8Array(fn.nonceLength) : undefined;
          const cipher = nonce ? fn(key, nonce) : fn(key);
          for (const invalid of INVALID_BYTE_ARRAYS) throws(() => cipher.decrypt(invalid));
        });
      });
    }
  });

  const CROSSTEST = {
    aes_ofb128: {
      opts: { key: buf(16), iv: buf(16) },
      node: nodeCipher('aes-128-ofb', false),
      noble: {
        encrypt: (buf: Uint8Array, opts: any) => ofb(opts.key, opts.iv).encrypt(buf),
        decrypt: (buf: Uint8Array, opts: any) => ofb(opts.key, opts.iv).decrypt(buf),
      },
    },
    aes_ofb192: !SMALL_KEYS && {
      opts: { key: buf(24), iv: buf(16) },
      node: nodeCipher('aes-192-ofb', false),
      noble: {
        encrypt: (buf: Uint8Array, opts: any) => ofb(opts.key, opts.iv).encrypt(buf),
        decrypt: (buf: Uint8Array, opts: any) => ofb(opts.key, opts.iv).decrypt(buf),
      },
    },
    aes_ofb256: !SMALL_KEYS && {
      opts: { key: buf(32), iv: buf(16) },
      node: nodeCipher('aes-256-ofb', false),
      noble: {
        encrypt: (buf: Uint8Array, opts: any) => ofb(opts.key, opts.iv).encrypt(buf),
        decrypt: (buf: Uint8Array, opts: any) => ofb(opts.key, opts.iv).decrypt(buf),
      },
    },
  };
  const ALGO_4GB_LIMIT = ['aes128_wrap', 'aes192_wrap', 'aes256_wrap', 'chacha20'];
  let supports5GB = false;
  try {
    let ZERO_5GB = new Uint8Array(5 * GB);
    ZERO_5GB = null as any;
    supports5GB = true;
  } catch (error) {}

  describe(`Cross-test (node, ${name})`, () => {
    for (const k in CROSSTEST) {
      const v = CROSSTEST[k];
      if (isDeno || !v) continue;
      describe(k, () => {
        should('basic round-trip', () => {
          const BUF = buf(32);
          const enc = v.noble.encrypt(BUF, v.opts);
          eql(v.noble.decrypt(enc, v.opts), BUF);
        });
        if (v.node) {
          describe('node', () => {
            should('basic', () => {
              const BUF = buf(32);
              const enc = v.node.encrypt(BUF, v.opts);
              eql(v.noble.encrypt(BUF, v.opts), enc);
              eql(v.noble.decrypt(enc, v.opts), BUF);
            });
            should('1 MB', () => {
              const BUF = new Uint8Array(1 * MB);
              const enc = v.node.encrypt(BUF, v.opts);
              eql(v.noble.encrypt(BUF, v.opts), enc);
              eql(v.noble.decrypt(enc, v.opts), BUF);
            });
            if (SLOW) {
              if (supports5GB && !ALGO_4GB_LIMIT.includes(k)) {
                should('5 GB', () => {
                  const BUF = new Uint8Array(5 * GB);
                  const enc = v.node.encrypt(BUF, v.opts);
                  eql(v.noble.encrypt(BUF, v.opts), enc);
                  eql(v.noble.decrypt(enc, v.opts), BUF);
                });
              }
            }
          });
        }
      });
    }
  });
}

for (const k in PLATFORMS) test(k, PLATFORMS[k]);
should.runWhen(import.meta.url);
