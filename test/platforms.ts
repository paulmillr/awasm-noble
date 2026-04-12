import { should } from '@paulmillr/jsbt/test.js';
import * as js from '../src/targets/js/index.ts';
import * as stubs from '../src/targets/stub/index.ts';
import * as wasm from '../src/targets/wasm/index.ts';
// import * as js_threads from '../src/targets/js_threads/index.ts';
import { expand, extract, hkdf } from '../src/hkdf.ts';
import { hmac } from '../src/hmac.ts';
import { pbkdf2, SCRYPT_BATCH } from '../src/kdf.ts';
import * as wasm_threads from '../src/targets/wasm_threads/index.ts';
import * as web from '../src/webcrypto.ts';
import { watchMemory } from './zero-check.ts';
for (const k in wasm) {
  // Some exports (e.g. secretbox wrappers) don't expose install(); only install when supported.
  if (typeof stubs[k]?.install === 'function') stubs[k].install(wasm[k]);
}

export const PLATFORMS = {
  js,
  // js_threads,
  wasm_threads,
  wasm,
  stubs,
};

const SLOT = '__NOBLE_TEST_PLATFORMS__';
const wrapCipher = (platform: Record<string, any>) => {
  const copy = (fn: any, run: (...args: any[]) => any) => Object.assign(run, fn);
  const stream = (fn: any) =>
    fn &&
    copy(fn, (key: any, nonce: any, data: any, out?: any, counter?: any) =>
      (counter === undefined ? fn(key, nonce) : fn(key, nonce, { counter })).encrypt(data, out)
    );
  const webCipher = (fn: any) =>
    fn &&
    copy(fn, (key: any, nonce: any, aad?: any) => {
      const i = aad === undefined ? fn(key, nonce) : fn(key, nonce, aad);
      return {
        encrypt: (data: any) => i.encrypt.async(data),
        decrypt: (data: any) => i.decrypt.async(data),
      };
    });
  const webGcm = copy(web.gcm, (key: any, nonce: any, aad?: any) => {
    const i = aad === undefined ? web.gcm(key, nonce) : web.gcm(key, nonce, aad);
    return {
      encrypt: (data: any) => i.encrypt.async(data),
      decrypt: (data: any) => i.decrypt.async(data),
    };
  });
  return {
    ...platform,
    cmac: platform.cmac && copy(platform.cmac, (msg: any, key: any) => platform.cmac(msg, key)),
    poly1305:
      platform.poly1305 &&
      copy(platform.poly1305, (msg: any, key: any) => platform.poly1305(msg, { key })),
    chacha8: stream(platform.chacha8),
    chacha12: stream(platform.chacha12),
    chacha20: stream(platform.chacha20),
    chacha20orig: stream(platform.chacha20orig),
    xchacha20: stream(platform.xchacha20),
    salsa20: stream(platform.salsa20),
    xsalsa20: stream(platform.xsalsa20),
    web: { ...web, cbc: webCipher(web.cbc), ctr: webCipher(web.ctr), gcm: webGcm },
  };
};
// slow-runtime rewrites PLATFORMS after module load, so compute wrapped ciphers lazily.
export const getCipherPlatforms = () =>
  Object.fromEntries(
    Object.entries(PLATFORMS).map(([name, platform]) => [name, wrapCipher(platform)])
  );
const wrapHash = (platform: Record<string, any>) => {
  const webHash = (fn: any) => {
    if (!fn) return fn;
    const hash = Object.assign((msg: any) => fn.async(msg), fn, { raw: fn });
    // Keep the wrapped WebCrypto hash surface frozen so callers can't retarget metadata like
    // `webCryptoName` after construction; the shared tests only verify that contract.
    return Object.freeze(hash);
  };
  const rawHash = (fn: any) => fn?.raw || fn;
  const shared = {
    ...platform,
    hmac,
    hkdf,
    extract,
    expand,
    // Shared noble-hashes tests need the resident scrypt batch size here, not the old N+p estimate.
    scryptMaxmemFormula: '128*r*N*maxP',
    scryptMaxmem: ({ N, r, p }: any) =>
      128 * r * N * Math.min(p, Math.floor(SCRYPT_BATCH / (2 * r))),
    pbkdf2: (hash: any, password: any, salt: any, opts: any) => pbkdf2(hash)(password, salt, opts),
    pbkdf2Async: (hash: any, password: any, salt: any, opts: any) =>
      pbkdf2(hash).async(password, salt, opts),
    web: {
      ...web,
      sha256: webHash(web.sha256),
      sha384: webHash(web.sha384),
      sha512: webHash(web.sha512),
      hmac: Object.assign(
        (hash: any, key: any, msg: any) => web.hmac(rawHash(hash), key, msg),
        web.hmac
      ),
      hkdf: (hash: any, ikm: any, salt: any, info: any, len: any) =>
        web.hkdf(rawHash(hash), ikm, salt, info, len),
      pbkdf2: (hash: any, password: any, salt: any, opts: any) =>
        web.pbkdf2(rawHash(hash)).async(password, salt, opts),
    },
  } as Record<string, any>;
  if (platform.scrypt)
    shared.scryptAsync = (password: any, salt: any, opts: any) =>
      platform.scrypt.async(password, salt, opts);
  if (platform.argon2d)
    shared.argon2dAsync = (password: any, salt: any, opts: any) =>
      platform.argon2d.async(password, salt, opts);
  if (platform.argon2i)
    shared.argon2iAsync = (password: any, salt: any, opts: any) =>
      platform.argon2i.async(password, salt, opts);
  if (platform.argon2id)
    shared.argon2idAsync = (password: any, salt: any, opts: any) =>
      platform.argon2id.async(password, salt, opts);
  return shared;
};
export const sharePlatforms = (kind: 'ciphers' | 'hashes') => {
  const shared = ((globalThis as Record<string, unknown>)[SLOT] ||= {}) as Record<string, unknown>;
  if (kind !== 'hashes') return;
  shared[kind] = Object.fromEntries(
    Object.entries(PLATFORMS).map(([name, platform]) => [name, wrapHash(platform)])
  );
};

import { pathToFileURL } from 'node:url';
import { WP } from '../src/workers.ts';
// Custom wrappers/hacks to run after all tests. Note, this is important that those used only once per test run, so we
// need to early return if file is required
export const startTests = (importMetaUrl: string) => {
  const proc = globalThis['process'];
  if (importMetaUrl !== pathToFileURL(proc.argv[1]).href) return;
  if (process.env.CHECK_ZEROIZE) should.opts.FAST = 0;
  const stopWatch = watchMemory();
  // Quick hack to make tests exit in deno
  const isDeno = 'deno' in process.versions; // https://github.com/denoland/deno/issues/24864 etc
  if (isDeno) should('terminate workers', () => WP.stop());
  should('stop watch memory', () => stopWatch());
  should.runWhen(importMetaUrl);
};
