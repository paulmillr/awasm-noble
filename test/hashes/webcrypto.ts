import { describe, should } from '@paulmillr/jsbt/test.js';
import { deepStrictEqual as eql, rejects, throws } from 'node:assert';
import { mkHashStub } from '../../src/hashes-abstract.ts';
import { hkdf } from '../../src/hkdf.ts';
import { hmac } from '../../src/hmac.ts';
import { pbkdf2 } from '../../src/kdf.ts';
import * as stubs from '../../src/targets/stub/index.ts';
import * as wasm from '../../src/targets/wasm/index.ts';
import * as webcrypto from '../../src/webcrypto.ts';

const HASHES = {
  sha1: { noble: wasm.sha1, web: webcrypto.sha1 },
  sha256: { noble: wasm.sha256, web: webcrypto.sha256 },
  sha384: { noble: wasm.sha384, web: webcrypto.sha384 },
  sha512: { noble: wasm.sha512, web: webcrypto.sha512 },
};
const EXP_HASHES = [
  { name: 'sha224', noble: wasm.sha224, web: webcrypto.sha224 },
  { name: 'sha3_256', noble: wasm.sha3_256, web: webcrypto.sha3_256 },
  { name: 'sha3_384', noble: wasm.sha3_384, web: webcrypto.sha3_384 },
  { name: 'sha3_512', noble: wasm.sha3_512, web: webcrypto.sha3_512 },
] as const;
const BUF1 = new Uint8Array([1, 2, 3]);
const BUF2 = new Uint8Array([4, 5, 6, 7]);
const BUF3 = new Uint8Array([8, 9, 10]);
const P1 = new Uint8Array([1, 2, 3, 4]);
const P2 = new Uint8Array([5, 6, 7, 8]);

describe('webcrypto hashes', () => {
  should.serial('rejects PBKDF2 iteration overflow before entering WebCrypto', async () => {
    const original = Object.getOwnPropertyDescriptor(globalThis, 'crypto');
    const subtle = {
      importKey() {
        throw new Error('backend called');
      },
    };
    Object.defineProperty(globalThis, 'crypto', { configurable: true, value: { subtle } });
    try {
      for (const c of [2 ** 31, 2 ** 32])
        await rejects(() => webcrypto.pbkdf2(webcrypto.sha256).async(BUF1, BUF2, { c }), {
          message: '"c" exceeds WebCrypto backend limit',
        });
    } finally {
      if (original) Object.defineProperty(globalThis, 'crypto', original);
      else delete (globalThis as any).crypto;
    }
  });
  should.serial('wipes owned UTF-8 inputs after success and validation failure', async () => {
    const expected = pbkdf2(wasm.sha256)('password', 'salt', { c: 1 });
    const encode = TextEncoder.prototype.encode;
    const copies: Uint8Array[] = [];
    TextEncoder.prototype.encode = function (text) {
      const out = encode.call(this, text);
      copies.push(out);
      return out;
    };
    try {
      eql(await webcrypto.pbkdf2(webcrypto.sha256).async('password', 'salt', { c: 1 }), expected);
      await rejects(() =>
        webcrypto.pbkdf2(webcrypto.sha256).async('password', null as any, { c: 1 })
      );
      eql(copies, [new Uint8Array(8), new Uint8Array(4), new Uint8Array(8)]);
    } finally {
      TextEncoder.prototype.encode = encode;
    }
  });
  for (const [name, { noble, web }] of Object.entries(HASHES)) {
    describe(name, () => {
      should.serial('digest lengths ignore inherited options', async () => {
        const digest = noble(BUF1);
        const previous = Object.getOwnPropertyDescriptor(Object.prototype, 'dkLen');
        Object.defineProperty(Object.prototype, 'dkLen', {
          configurable: true,
          writable: true,
          value: 0,
        });
        try {
          for (const [opts, expected] of [
            [undefined, digest],
            [{}, digest],
            [{ dkLen: undefined }, digest],
            [{ dkLen: 0 }, new Uint8Array()],
            [{ dkLen: 3 }, digest.subarray(0, 3)],
          ] as const)
            eql(
              [
                await web.async(BUF1, opts),
                await web.chunks.async([BUF1], opts),
                await web.parallel.async([BUF1, BUF1], opts),
              ],
              [expected, expected, [expected, expected]]
            );
        } finally {
          if (previous) Object.defineProperty(Object.prototype, 'dkLen', previous);
          else delete (Object.prototype as { dkLen?: number }).dkLen;
        }
      });
      should('basic async', async () => {
        eql(await web.async(BUF1), noble(BUF1));
        eql(web.blockLen, noble.blockLen);
        eql(web.outputLen, noble.outputLen);
      });
      should('sync & stream throw', () => {
        throws(() => web(BUF1));
        throws(() => web.chunks([BUF1, BUF2]));
        throws(() => web.parallel([BUF1, BUF2]));
        throws(() => web.create());
      });
      should('chunks/parallel async', async () => {
        eql(await web.chunks.async([BUF1, BUF2]), noble.chunks([BUF1, BUF2]));
        eql(await web.parallel.async([P1, P2]), noble.parallel([P1, P2]));
      });
    });
  }

  should('webcrypto pbkdf2 async shape', async () => {
    eql(
      await webcrypto.pbkdf2(webcrypto.sha256).async(BUF1, BUF2, { c: 1 }),
      pbkdf2(wasm.sha256)(BUF1, BUF2, { c: 1 })
    );
    eql(
      await webcrypto.pbkdf2(webcrypto.sha256).async('pwd', 'salt', { c: 11, dkLen: 1000 }),
      pbkdf2(wasm.sha256)('pwd', 'salt', { c: 11, dkLen: 1000 })
    );
  });
  should('stub installs work for all web hashes', async () => {
    const cases = [
      { stub: stubs.sha1, web: webcrypto.sha1, wasm: wasm.sha1 },
      { stub: stubs.sha256, web: webcrypto.sha256, wasm: wasm.sha256 },
      { stub: stubs.sha384, web: webcrypto.sha384, wasm: wasm.sha384 },
      { stub: stubs.sha512, web: webcrypto.sha512, wasm: wasm.sha512 },
    ];
    for (const { stub, web, wasm: w } of cases) {
      stub.install(web);
      try {
        throws(() => stub(BUF1));
        eql(await stub.async(BUF1), w(BUF1));
        eql(await stub.chunks.async([BUF1, BUF2]), w.chunks([BUF1, BUF2]));
        eql(await stub.parallel.async([P1, P2]), w.parallel([P1, P2]));
        eql(await webcrypto.hmac(stub, BUF1, BUF2), hmac(w, BUF1, BUF2));
        eql(await webcrypto.hkdf(stub, BUF1, BUF2, BUF3, 10), hkdf(w, BUF1, BUF2, BUF3, 10));
        eql(
          await webcrypto.pbkdf2(stub).async(BUF1, BUF2, { c: 1 }),
          pbkdf2(w)(BUF1, BUF2, { c: 1 })
        );
      } finally {
        stub.install(w);
      }
    }
  });
  for (const e of EXP_HASHES) {
    should(`stub install for ${e.name} follows support gate`, async () => {
      const stub = (stubs as any)[e.name];
      if (!stub) return;
      const ok = await e.web.isSupported();
      if (!ok) return;
      stub.install(e.web);
      try {
        throws(() => stub(BUF1));
        eql(await stub.async(BUF1), e.noble(BUF1));
      } finally {
        stub.install(e.noble);
      }
    });
  }

  should('webcrypto kdf/mac reject non-web platform hashes', async () => {
    await rejects(() => webcrypto.hmac(wasm.sha256, BUF1, BUF2));
    await rejects(() => webcrypto.hkdf(wasm.sha256, BUF1, BUF2, BUF3, 10));
    await rejects(() => webcrypto.pbkdf2(wasm.sha256).async(BUF1, BUF2, { c: 1 }));
  });

  should('hash wrapper isSupported methods', async () => {
    eql(await webcrypto.sha1.isSupported(), true);
    eql(await webcrypto.sha256.isSupported(), true);
  });
  should('webcrypto pbkdf2 sync path throws', () => {
    throws(() => webcrypto.pbkdf2(webcrypto.sha256)(BUF1, BUF2, { c: 1 }));
  });

  for (const e of EXP_HASHES) {
    should(`${e.name} support gate`, async () => {
      const ok = await e.web.isSupported();
      if (ok) eql(await e.web.async(BUF1), e.noble(BUF1));
      else await rejects(() => e.web.async(BUF1));
    });
  }

  should('stub async hash preserves output validation', async () => {
    stubs.sha256.install(webcrypto.sha256);
    try {
      await rejects(() => stubs.sha256.async(BUF1, { out: new Uint8Array(1) }));
      await rejects(() => stubs.sha256.chunks.async([BUF1], { out: new Uint8Array(1) }));
      await rejects(() => stubs.sha256.parallel.async([P1], { out: [new Uint8Array(1)] }));
    } finally {
      stubs.sha256.install(wasm.sha256);
    }
  });

  should('stub install does not check implementation support', () => {
    const stub = mkHashStub(wasm.sha256.getDefinition());
    const bad = webcrypto.sha256;
    stub.install(bad);
  });
});

should.runWhen(import.meta.url);
