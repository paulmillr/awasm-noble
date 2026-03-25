import { describe, should } from '@paulmillr/jsbt/test.js';
import { deepStrictEqual as eql } from 'node:assert';
import { pbkdf2 } from '../../src/kdf.ts';
import { test } from '../noble-hashes/test/async.test.ts';
import { PLATFORMS } from '../platforms.ts';

const wrap = ({ sha256, scrypt }) => ({
  sha256,
  scrypt,
  scryptAsync: (password, salt, opts) => scrypt.async(password, salt, opts),
  pbkdf2Async: (hash, password, salt, opts) => pbkdf2(hash).async(password, salt, opts),
});
const progress = (_variant: string, { scrypt }, { should }) => {
  should('scrypt progreessCallback', async () => {
    for (const scr of [scrypt, scrypt.async]) {
      let t = [];
      await scr('', '', { N: 2 ** 18, r: 8, p: 1, onProgress: (per) => t.push(per) });
      eql(t.length, 5045);
      eql(
        t.slice(0, 5),
        [
          0.12685394287109375, 0.2537078857421875, 0.38056182861328125, 0.5000762939453125,
          0.5001754760742188,
        ]
      );
      eql(
        t.slice(-5),
        [0.9996566772460938, 0.999755859375, 0.9998550415039062, 0.9999542236328125, 1]
      );
    }
  });
};

for (const k in PLATFORMS) test(k, wrap(PLATFORMS[k]), { describe, should }, progress);

should.runWhen(import.meta.url);
