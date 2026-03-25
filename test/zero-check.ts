/*
Watch memory in async mode and crash if there is non-zero (except round constants in sha3 and worker related stuff)
*/

import { Definitions as CipherDefinitions } from '../src/ciphers.ts';
import { MODULES } from '../src/modules/index.ts';
import * as js from '../src/targets/js/index.ts';
import * as wasm from '../src/targets/wasm/index.ts';
import * as wasm_threads from '../src/targets/wasm_threads/index.ts';

const sleep = (ms: number, sig?: AbortSignal) =>
  new Promise<void>((res) => {
    if (sig?.aborted) return res();
    const t = setTimeout(res, ms);
    sig?.addEventListener(
      'abort',
      () => {
        clearTimeout(t);
        res(); // wake immediately (no throw)
      },
      { once: true }
    );
  });

function init() {
  /*
Main issue, how the to import modules?
- raw access to modules is probably bad thing, so we don't export them.
- but they need to be instantiated with real (wp pool stuff)
- but with lazy init they are not instantiated before.
  */
  const tmp = new Uint8Array(32);
  for (const [ver, lib] of Object.entries({ js, wasm, wasm_threads })) {
    for (const k in lib) {
      const fn = lib[k];
      if (typeof fn !== 'function') continue;
      if (k.startsWith('argon')) {
        fn(tmp, tmp, { m: 32, t: 3, p: 4 });
        continue;
      }
      if (k === 'scrypt') {
        fn(tmp, tmp, { N: 2, r: 8, p: 1 });
        continue;
      }
      // secretbox is compatibility wrapper and doesn't expose getDefinition()/CipherDefinitions entry.
      if (k === 'secretbox') {
        fn(tmp, tmp.subarray(0, 24));
        continue;
      }
      if (k === 'ghash' || k === 'polyval' || k === 'cmac' || k === 'poly1305') {
        const key = k === 'poly1305' ? tmp : tmp.subarray(0, 16);
        fn(tmp, { key });
        continue;
      }
      const def =
        typeof (fn as { getDefinition?: () => { nonceLength?: number } }).getDefinition ===
        'function'
          ? (fn as { getDefinition: () => { nonceLength?: number } }).getDefinition()
          : CipherDefinitions[k];
      if (def) {
        const { nonceLength } = def;
        if (nonceLength !== undefined) {
          fn(tmp, tmp.subarray(0, nonceLength));
          continue;
        }
      }
      fn(tmp);
    }
  }
}

export function watchMemory() {
  init();
  const ac = new AbortController();
  const ready = (async () => {
    const mem = {};
    for (const mod in MODULES) {
      for (const ver of ['wasm', 'js', 'wasm_threads']) {
        const curMod = (await import(`../src/targets/${ver}/${mod}.js`)).default();
        const skip: [number, number][] = [];
        for (const k in curMod.segments) {
          // `constants` are public non-secret tables; they are expected to be non-zero.
          if (k === 'rc' || k === 'constants' || k.startsWith('_worker')) {
            const s = curMod.segments[k];
            if (Array.isArray(s)) continue;
            skip.push([s.byteOffset, s.byteOffset + s.byteLength]);
          }
        }
        skip.sort((a, b) => a[0] - b[0]);
        const ranges: [number, number][] = [];
        let p = 0;
        for (let i = 0; i < skip.length; i++) {
          const [s, e] = skip[i];
          if (p < s) ranges.push([p, s - p]); // [pos,len]
          p = e;
        }
        if (p < curMod.memory.length) ranges.push([p, curMod.memory.length - p]);
        mem[`${mod}_${ver}`] = { memory: curMod.memory, ranges };
      }
    }
    return mem;
  })();
  return async () => {
    ac.abort();
    const mem = await ready;
    if (!process.env.CHECK_ZEROIZE) return;
    for (const k in mem) {
      const { memory, ranges } = mem[k];
      for (const [pos, len] of ranges) {
        for (let i = pos, end = pos + len; i < end; i++) {
          if (memory[i] !== 0) throw new Error(`non zero memory: ${k}, ${i} value=${memory[i]}`);
        }
      }
    }
  };
}

/*
Print addresses: Object.entries(mod.segments).map(([k,v])=>[k, v.byteOffset, v.byteLength])

*/
