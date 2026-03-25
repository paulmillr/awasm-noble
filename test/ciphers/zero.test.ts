import { should } from '@paulmillr/jsbt/test.js';
import { MODULES } from '../../src/modules/index.ts';
import { Definitions as CipherDefinitions } from '../../src/ciphers.ts';
import * as js from '../../src/targets/js/index.ts';
import * as wasm from '../../src/targets/wasm/index.ts';
import * as wasm_threads from '../../src/targets/wasm_threads/index.ts';

const CIPHER_MODS = Object.keys(MODULES).filter((k) => {
  const fn = MODULES[k as keyof typeof MODULES].fn;
  return (
    fn === 'genSalsa' ||
    fn === 'genSalsaAead' ||
    fn === 'genChacha' ||
    fn === 'genChachaAead' ||
    fn.startsWith('genAes')
  );
});
const MAC_MODS = Object.keys(MODULES).filter((k) => {
  const fn = MODULES[k as keyof typeof MODULES].fn;
  return fn === 'genCmac' || fn === 'genGhash' || fn === 'genPolyval' || fn === 'genPoly1305';
});
const MACS = ['cmac', 'ghash', 'polyval', 'poly1305'] as const;

const SKIP = (k: string) => k === 'rc' || k === 'constants' || k.startsWith('_worker');
const tmp = new Uint8Array(128);
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
    const [s, e] = skip[i];
    if (p < s) out.push([p, s - p]);
    p = e;
  }
  if (p < mem.length) out.push([p, mem.length - p]);
  return out;
};

const runCipher = (name: string, fn: any) => {
  const def =
    typeof fn?.getDefinition === 'function'
      ? fn.getDefinition()
      : CipherDefinitions[name as keyof typeof CipherDefinitions];
  if (!def) return;
  const key = tmp.subarray(0, 32);
  const nonce = def.nonceLength === undefined ? undefined : tmp.subarray(0, def.nonceLength);
  const ctx = nonce === undefined ? fn(key) : fn(key, nonce);
  const msg =
    name === 'aeskw' || name === 'aeskwp'
      ? tmp.subarray(0, 16)
      : name === 'ecb' || name === 'cbc'
        ? tmp.subarray(0, 32)
        : tmp.subarray(0, 48);
  const enc = ctx.encrypt(msg);
  ctx.decrypt(enc);
  if (name === 'aeskw' || name === 'aeskwp') {
    const bad = enc.slice();
    bad[0] ^= 1;
    try {
      ctx.decrypt(bad);
    } catch {}
  }
};
const runMac = (name: (typeof MACS)[number], fn: any) => {
  const key =
    name === 'cmac'
      ? tmp.subarray(0, 32)
      : name === 'poly1305'
        ? tmp.subarray(0, 32)
        : tmp.subarray(0, 16);
  const msg = tmp.subarray(0, 64);
  fn(msg, key);
  fn.chunks([msg.subarray(0, 17), msg.subarray(17)], key);
  fn.create(key).update(msg.subarray(0, 31)).update(msg.subarray(31)).digest();
};

should('ciphers memory zeroized after use', async () => {
  const libs = { js, wasm, wasm_threads };
  for (const [ver, lib] of Object.entries(libs)) {
    for (const name in CipherDefinitions) {
      const fn = (lib as Record<string, any>)[name];
      if (typeof fn !== 'function') continue;
      try {
        runCipher(name, fn);
      } catch (e) {
        throw new Error(`cipher usage failed: ${name}_${ver}: ${(e as Error).message}`);
      }
    }
    for (const name of MACS) {
      const fn = (lib as Record<string, any>)[name];
      if (typeof fn !== 'function') continue;
      try {
        runMac(name, fn);
      } catch (e) {
        throw new Error(`mac usage failed: ${name}_${ver}: ${(e as Error).message}`);
      }
    }
  }
  const leaks: string[] = [];
  for (const mod of [...CIPHER_MODS, ...MAC_MODS]) {
    for (const ver of ['js', 'wasm', 'wasm_threads'] as const) {
      const curMod = (await import(`../../src/targets/${ver}/${mod}.js`)).default();
      const checkRanges = ranges(curMod.memory, curMod.segments);
      for (const [pos, len] of checkRanges) {
        for (let i = pos, end = pos + len; i < end; i++) {
          if (curMod.memory[i] !== 0) {
            leaks.push(`non zero memory: ${mod}_${ver}, ${i} value=${curMod.memory[i]}`);
            if (leaks.length >= 32) break;
          }
        }
        if (leaks.length >= 32) break;
      }
      if (leaks.length >= 32) break;
    }
    if (leaks.length >= 32) break;
  }
  if (leaks.length) throw new Error(leaks.join('\n'));
});

should.runWhen(import.meta.url);
