import { should } from '@paulmillr/jsbt/test.js';
import { deepStrictEqual as eql } from 'node:assert';
import { randomBytes } from '@noble/hashes/utils.js';
import { PLATFORMS } from '../platforms.ts';

function test(name: string, { aeskwp }: { aeskwp: any }) {
  should(`AES-KWP large input (${name})`, () => {
    const key = randomBytes(16);
    const msg = randomBytes(10_000);
    const enc = aeskwp(key).encrypt(msg);
    const dec = aeskwp(key).decrypt(enc);
    eql(dec, msg);
  });
}

for (const k in PLATFORMS) test(k, PLATFORMS[k]);

should.runWhen(import.meta.url);
