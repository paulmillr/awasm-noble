import { should } from '@paulmillr/jsbt/test.js';

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

const runHash = (name: string, fn: any) => {
  const msg = tmp.subarray(0, 96);
  if (MACS.has(name)) {
    const key = name === 'cmac' || name === 'poly1305' ? tmp.subarray(0, 32) : tmp.subarray(0, 16);
    fn(msg, key);
    fn.chunks([msg.subarray(0, 37), msg.subarray(37)], key);
    fn.create(key).update(msg.subarray(0, 41)).update(msg.subarray(41)).digest();
    return;
  }
  fn(msg);
  fn.chunks([msg.subarray(0, 37), msg.subarray(37)]);
  fn.create().update(msg.subarray(0, 41)).update(msg.subarray(41)).digest();
};

// should('hashes memory zeroized after use', async () => {
//   const libs = { js, wasm, wasm_threads };
//   for (const [, lib] of Object.entries(libs)) {
//     for (const name in HashDefinitions) {
//       const fn = (lib as Record<string, any>)[name];
//       if (typeof fn !== 'function') continue;
//       runHash(name, fn);
//     }
//   }
//   const modSet = new Set<string>();
//   for (const k in HashDefinitions)
//     modSet.add(HashDefinitions[k as keyof typeof HashDefinitions].mod);
//   const leaks: string[] = [];
//   for (const mod of modSet) {
//     if (!MODULES[mod as keyof typeof MODULES]) continue;
//     for (const ver of ['js', 'wasm', 'wasm_threads'] as const) {
//       const curMod = (await import(`../../src/targets/${ver}/${mod}.js`)).default();
//       const checkRanges = ranges(curMod.memory, curMod.segments);
//       for (const [pos, len] of checkRanges) {
//         for (let i = pos, end = pos + len; i < end; i++) {
//           if (curMod.memory[i] !== 0) {
//             leaks.push(`non zero memory: ${mod}_${ver}, ${i} value=${curMod.memory[i]}`);
//             if (leaks.length >= 32) break;
//           }
//         }
//         if (leaks.length >= 32) break;
//       }
//       if (leaks.length >= 32) break;
//     }
//     if (leaks.length >= 32) break;
//   }
//   if (leaks.length) throw new Error(leaks.join('\n'));
// });

should.runWhen(import.meta.url);
