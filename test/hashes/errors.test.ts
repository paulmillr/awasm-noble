import { describe, should } from '@paulmillr/jsbt/test.js';
import { throws } from 'node:assert';
import { PLATFORMS } from '../platforms.ts';
import { mkKDFStub } from '../../src/kdf.ts';
import { scrypt as defScrypt } from '../../src/hashes.ts';
import {
  blake2Opts,
  blake3Opts,
  hashArgs,
  shakeOpts,
  test,
} from './noble-hashes/test/errors.test.ts';

const algo = ({
  md5,
  sha1,
  ripemd160,
  sha256,
  sha512,
  sha3_256,
  shake128,
  blake256,
  blake2s,
  blake2b,
  blake3,
}) => ({
  md5: { fn: md5, args: hashArgs, ret: 'bytes' },
  sha1: { fn: sha1, args: hashArgs, ret: 'bytes' },
  ripemd160: { fn: ripemd160, args: hashArgs, ret: 'bytes' },
  sha256: { fn: sha256, args: hashArgs, ret: 'bytes' },
  sha512: { fn: sha512, args: hashArgs, ret: 'bytes' },
  sha3_256: { fn: sha3_256, args: hashArgs, ret: 'bytes' },
  shake128: { fn: shake128, args: { ...hashArgs, opts: shakeOpts }, ret: 'bytes' },
  blake256: { fn: blake256, args: { ...hashArgs, opts: { salt: 'bytes?' } }, ret: 'bytes' },
  blake2s: { fn: blake2s, args: { ...hashArgs, opts: blake2Opts }, ret: 'bytes' },
  blake2b: { fn: blake2b, args: { ...hashArgs, opts: blake2Opts }, ret: 'bytes' },
  blake3: { fn: blake3, args: { ...hashArgs, opts: blake3Opts }, ret: 'bytes' },
});

for (const k in PLATFORMS) test(k, algo(PLATFORMS[k]), { describe, should });

describe('kdf stub', () => {
  should('rejects wrong implementation definition', () => {
    const stub = mkKDFStub(defScrypt);
    throws(() => stub.install(PLATFORMS.js.argon2id as any), {
      message: 'wrong implementation definition',
    });
  });

  should('accepts matching implementation definition', () => {
    const stub = mkKDFStub(defScrypt);
    stub.install(PLATFORMS.js.scrypt);
  });
});
