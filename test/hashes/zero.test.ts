import { should } from '@paulmillr/jsbt/test.js';
import { deepStrictEqual as eql, throws } from 'node:assert';
import { Definitions as HashDefinitions } from '../../src/hashes.ts';
import * as js from '../../src/targets/js/index.ts';
import * as wasm from '../../src/targets/wasm/index.ts';
import * as wasm_threads from '../../src/targets/wasm_threads/index.ts';

const MACS = new Set(['poly1305', 'cmac', 'ghash', 'polyval']);
const SKIP = (k: string) => k === 'rc' || k === 'constants' || k.startsWith('_worker');
const tmp = new Uint8Array(256);
for (let i = 0; i < tmp.length; i++) tmp[i] = (i * 13 + 7) & 0xff;

const ranges = (mem: Uint8Array, segments: Record<string, Uint8Array | Uint32Array>) => {
  const skip: [number, number][] = [];
  for (const k in segments) {
    if (!SKIP(k)) continue;
    const s = segments[k];
    if (Array.isArray(s)) continue;
    skip.push([s.byteOffset, s.byteOffset + s.byteLength]);
  }
  skip.sort((a, b) => a[0] - b[0]);
  const out: [number, number][] = [];
  let p = 0;
  for (let i = 0; i < skip.length; i++) {
    const [s, e] = skip[i]!;
    if (p < s) out.push([p, s - p]);
    p = e;
  }
  if (p < mem.length) out.push([p, mem.length - p]);
  return out;
};

const runHash = (name: string, fn: any, check: () => void) => {
  const msg = tmp.subarray(0, 96);
  if (MACS.has(name)) {
    const key = name === 'cmac' || name === 'poly1305' ? tmp.subarray(0, 32) : tmp.subarray(0, 16);
    fn(msg, key);
    check();
    fn.chunks([msg.subarray(0, 37), msg.subarray(37)], key);
    check();
    fn.create(key).update(msg.subarray(0, 41)).update(msg.subarray(41)).digest();
    check();
    return;
  }
  fn(msg);
  check();
  fn.chunks([msg.subarray(0, 37), msg.subarray(37)]);
  check();
  fn.create().update(msg.subarray(0, 41)).update(msg.subarray(41)).digest();
  check();
};

for (const mode of ['hashes', 'XOF', 'initialization', 'initialization errors'])
  should(`${mode} memory zeroized after use`, async () => {
    const libs = process.env.NO_THREADS ? { js, wasm } : { js, wasm, wasm_threads };
    const zero = new Uint8Array(4096);
    for (const [ver, lib] of Object.entries(libs)) {
      for (const [name, def] of Object.entries(HashDefinitions)) {
        const fn = (lib as Record<string, any>)[name];
        if (typeof fn !== 'function') continue;
        if (mode === 'XOF' && !fn.canXOF) continue;
        if (mode.startsWith('initialization') && name !== 'blake2s' && name !== 'blake2b') continue;
        const mod = (await import(`../../src/targets/${ver}/${def.mod}.js`)).default();
        const check = () => {
          for (const [pos, len] of ranges(mod.memory, mod.segments))
            for (let i = pos; i < pos + len; i += zero.length) {
              const size = Math.min(zero.length, pos + len - i);
              eql(
                mod.memory.subarray(i, i + size),
                zero.subarray(0, size),
                `${name}_${ver}: offset ${i}`
              );
            }
        };
        if (mode === 'initialization') {
          const opts = { key: tmp.subarray(0, 32) };
          const expected = fn(tmp, opts);
          check();
          const stream = fn.create(opts);
          check();
          eql(stream.update(tmp).digest(), expected);
          check();
        } else if (mode === 'hashes') runHash(name, fn, check);
        else if (mode === 'XOF') {
          const sizes = [0, 1, fn.blockLen - 1, fn.blockLen + 1];
          const expected = fn(tmp, { dkLen: sizes.reduce((a, b) => a + b, 0) });
          const stream = fn.create().update(tmp);
          let pos = 0;
          for (const size of sizes) {
            eql(stream.xof(size), expected.subarray(pos, pos + size));
            pos += size;
            check();
          }
          stream.destroy();
          check();
        } else {
          const key = tmp.slice(0, 32);
          for (const opts of [
            { key, salt: new Uint8Array(1) },
            { key, personalization: new Uint8Array(1) },
          ])
            for (const run of [
              () => fn(tmp, opts),
              () => fn.chunks([tmp], opts),
              () => fn.parallel([tmp, tmp], opts),
              () => fn.create(opts),
            ]) {
              throws(run);
              check();
              eql(key, tmp.subarray(0, 32));
            }
        }
      }
    }
  });

should.runWhen(import.meta.url);
