import { describe, should } from '@paulmillr/jsbt/test.js';
import { deepStrictEqual } from 'node:assert';
import { Definitions as CipherDefinitions } from '../src/ciphers.ts';
import { Definitions as HashDefinitions } from '../src/hashes.ts';
import * as runtime from '../src/targets/runtime/index.ts';
import * as wasm from '../src/targets/wasm/index.ts';

const tmp = new Uint8Array(256);
for (let i = 0; i < tmp.length; i++) tmp[i] = (i * 13 + 7) & 0xff;

const parts = {
  pwd: tmp.subarray(0, 32),
  salt: tmp.subarray(32, 64),
  msg: tmp.subarray(64, 160),
  split: 41,
  key16: tmp.subarray(0, 16),
  key32: tmp.subarray(0, 32),
  nonce: tmp.subarray(160),
};
const MACS = new Set(['poly1305', 'cmac', 'ghash', 'polyval']);

describe('runtime fast', () => {
  should('hashes', () => {
    for (const name in HashDefinitions) {
      if (!(name in runtime)) continue;
      const rt = (runtime as any)[name];
      const wm = (wasm as any)[name];
      if (typeof rt !== 'function') throw new Error(`missing runtime hash export: ${name}`);
      if (typeof wm !== 'function') throw new Error(`missing wasm hash export: ${name}`);
      if (name === 'scrypt') {
        deepStrictEqual(
          rt(parts.pwd, parts.salt, { N: 2, r: 8, p: 1, dkLen: 16 }),
          wm(parts.pwd, parts.salt, { N: 2, r: 8, p: 1, dkLen: 16 })
        );
        continue;
      }
      if (name.startsWith('argon2')) {
        deepStrictEqual(
          rt(parts.pwd, parts.salt, { m: 32, t: 1, p: 1, dkLen: 16 }),
          wm(parts.pwd, parts.salt, { m: 32, t: 1, p: 1, dkLen: 16 })
        );
        continue;
      }
      if (MACS.has(name)) {
        const key = name === 'ghash' || name === 'polyval' ? parts.key16 : parts.key32;
        deepStrictEqual(rt(parts.msg, key), wm(parts.msg, key));
        deepStrictEqual(
          rt.chunks([parts.msg.subarray(0, parts.split), parts.msg.subarray(parts.split)], key),
          wm.chunks([parts.msg.subarray(0, parts.split), parts.msg.subarray(parts.split)], key)
        );
        deepStrictEqual(
          rt
            .create(key)
            .update(parts.msg.subarray(0, parts.split))
            .update(parts.msg.subarray(parts.split))
            .digest(),
          wm
            .create(key)
            .update(parts.msg.subarray(0, parts.split))
            .update(parts.msg.subarray(parts.split))
            .digest()
        );
        continue;
      }
      deepStrictEqual(rt(parts.msg), wm(parts.msg));
      deepStrictEqual(
        rt.chunks([parts.msg.subarray(0, parts.split), parts.msg.subarray(parts.split)]),
        wm.chunks([parts.msg.subarray(0, parts.split), parts.msg.subarray(parts.split)])
      );
      deepStrictEqual(
        rt
          .create()
          .update(parts.msg.subarray(0, parts.split))
          .update(parts.msg.subarray(parts.split))
          .digest(),
        wm
          .create()
          .update(parts.msg.subarray(0, parts.split))
          .update(parts.msg.subarray(parts.split))
          .digest()
      );
    }
  });

  should('ciphers', () => {
    for (const name in CipherDefinitions) {
      if (!(name in runtime)) continue;
      const rt = (runtime as any)[name];
      const wm = (wasm as any)[name];
      if (typeof rt !== 'function') throw new Error(`missing runtime cipher export: ${name}`);
      if (typeof wm !== 'function') throw new Error(`missing wasm cipher export: ${name}`);
      const def =
        typeof rt.getDefinition === 'function'
          ? rt.getDefinition()
          : CipherDefinitions[name as keyof typeof CipherDefinitions];
      const nonce =
        def.nonceLength === undefined ? undefined : parts.nonce.subarray(0, def.nonceLength);
      const msg =
        name === 'aeskw' || name === 'aeskwp'
          ? parts.msg.subarray(0, 16)
          : name === 'ecb' || name === 'cbc'
            ? parts.msg.subarray(0, 32)
            : parts.msg.subarray(0, 48);
      const rtCtx = nonce === undefined ? rt(parts.key32) : rt(parts.key32, nonce);
      const wmCtx = nonce === undefined ? wm(parts.key32) : wm(parts.key32, nonce);
      const rtEnc = rtCtx.encrypt(msg);
      const wmEnc = wmCtx.encrypt(msg);
      deepStrictEqual(rtEnc, wmEnc);
      deepStrictEqual(rtCtx.decrypt(rtEnc), msg);
      deepStrictEqual(wmCtx.decrypt(wmEnc), msg);
    }
  });

  should('secretbox', () => {
    const nonce = parts.nonce.subarray(0, 24);
    const msg = parts.msg.subarray(0, 48);
    const rt = runtime.secretbox(parts.key32, nonce);
    const wm = wasm.secretbox(parts.key32, nonce);
    const sealed = rt.seal(msg);
    deepStrictEqual(sealed, wm.seal(msg));
    deepStrictEqual(rt.open(sealed), msg);
  });
});

should.runWhen(import.meta.url);
