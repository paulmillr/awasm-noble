import { describe, should } from '@paulmillr/jsbt/test.js';
import { deepStrictEqual, throws } from 'node:assert';
import { u8, concatBytes } from '../../src/utils.ts';
import * as js from '../../src/targets/js/index.ts';
import * as wasm from '../../src/targets/wasm/index.ts';
import * as stubs from '../../src/targets/stub/index.ts';
import { NOBLE } from '../noble-all.ts';

describe('Basic', () => {
  describe('stubs', () => {
    should('basic', () => {
      stubs.sha256.install(wasm.sha256);
      deepStrictEqual(stubs.sha256(new Uint8Array()), wasm.sha256(new Uint8Array()));
      // re-install
      stubs.sha256.install(js.sha256);
      deepStrictEqual(stubs.sha256(new Uint8Array()), js.sha256(new Uint8Array()));
      throws(() => stubs.sha256.install(js.sha512));
      stubs.sha3_256.install(js.sha3_256);
      throws(() => stubs.sha3_256.install(js.keccak_256));
      const maliciousHash = function () {
        throw new Error('broken!');
      };
      Object.assign(maliciousHash, {
        outputLen: js.sha256.outputLen,
        blockLen: js.sha256.blockLen,
        oid: js.sha256.oid,
        BRAND: js.sha256.BRAND,
      });
      throws(() => stubs.sha256.install(maliciousHash));
      const maliciousHash2 = function () {
        throw new Error('broken2!');
      };
      Object.assign(maliciousHash2, js.sha256);
      throws(() => stubs.sha256.install(maliciousHash2));
      stubs.sha256(new Uint8Array()); // would throw if install happened
    });
  });
});

should.runWhen(import.meta.url);
