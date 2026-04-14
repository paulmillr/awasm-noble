import * as js from '../../src/targets/js/index.ts';
// import * as js_threads from '../../src/targets/js_threads/index.ts';
import * as wasm from '../../src/targets/wasm/index.ts';
import * as wasm_threads from '../../src/targets/wasm_threads/index.ts';
import { NOBLE } from '../noble-all.ts';

export function log(value) {
  console.log(util.inspect(value, { depth: null, colors: true, maxArrayLength: Infinity }));
}
export const msg = new Uint8Array(64).fill(3);

export function seqU8(n: number): Uint8Array {
  const a = new Uint8Array(n);
  for (let i = 0; i < n; ) a[i] = ++i & 255; // 1..255,0,1.. (mod 256)
  return a;
}

export function randomBytes(len: number): Uint8Array {
  // randomBytes can output up to 65k
  const out = new Uint8Array(len);
  const CHUNK = 0xffff; // 65535
  let offset = 0;
  while (offset < len) {
    const size = Math.min(len - offset, CHUNK);
    crypto.getRandomValues(out.subarray(offset, offset + size));
    offset += size;
  }
  return out;
}

export const seq = (length: number) => Array.from({ length }, (_, i) => i);
export const SIZES = Array.from(
  new Set([
    0,
    ...seq(256),
    // 1024kb chunks
    ...seq(16).map((i) => 1024 * i),
    ...seq(16).map((i) => 1024 * i + 1),
    ...seq(16).map((i) => 1024 * i - 1),
    // 4096kb chunks
    ...seq(16).map((i) => 4096 * i),
    ...seq(16).map((i) => 4096 * i + 1),
    ...seq(16).map((i) => 4096 * i - 1),
    // 1mb
    10 * 1024 * 1024,
    // NOTE: since we have loops, failure case is now different and near 16 chunks boundaries (~1024)
    // ...seq(16).map((i) => 1024 * 1024 * i),
    // ...seq(16).map((i) => 1024 * 1024 * i - 1),
    // ...seq(16).map((i) => 1024 * 1024 * i + 1),
  ])
).map((i) => Math.max(0, i));

export const BUFS = [
  ...SIZES.map((i) => seqU8(i)),
  ...SIZES.map((i) => new Uint8Array(i).fill(0xff)),
  ...SIZES.map((i) => new Uint8Array(i).fill(0x01)),
  ...SIZES.map((i) => new Uint8Array(i).fill(0x00)),
  ...SIZES.map((i) => randomBytes(i)),
];

export const HASHES = {};
const MACS = { cmac: 32, poly1305: 32, ghash: 16, polyval: 16 } as const;
const wrapHash = (name: string, fn: any) => {
  const keyLen = MACS[name as keyof typeof MACS];
  if (!keyLen) return fn;
  // Shared hash harness is unary; close over a deterministic test key for keyed MAC surfaces.
  const key = seqU8(keyLen);
  const call = (msg: Uint8Array, opts = key) => fn(msg, opts);
  const res = Object.assign(call, fn);
  res.async = (msg: Uint8Array, opts = key) => fn.async(msg, opts);
  if (typeof fn.chunks === 'function') {
    res.chunks = Object.assign(
      (parts: Uint8Array[], opts = key) => fn.chunks(parts, opts),
      fn.chunks.async
        ? { async: (parts: Uint8Array[], opts = key) => fn.chunks.async(parts, opts) }
        : {}
    );
  }
  if (typeof fn.parallel === 'function') {
    res.parallel = Object.assign(
      (parts: Uint8Array[], opts = key) => fn.parallel(parts, opts),
      fn.parallel.async
        ? { async: (parts: Uint8Array[], opts = key) => fn.parallel.async(parts, opts) }
        : {}
    );
  }
  if (typeof fn.create === 'function') res.create = (opts = key) => fn.create(opts);
  return res;
};
const ALL = new Set([...Object.keys(js), ...Object.keys(wasm)]);
for (const k of ALL) {
  // if (!runtime[k]) continue;
  if (k === 'scrypt' || k.startsWith('argon')) continue;
  if (typeof NOBLE[k]?.create !== 'function') continue;
  const noble = wrapHash(k, NOBLE[k]);
  const versions = [js[k], wasm[k] /*js_threads[k]*/, , wasm_threads[k] /*runtime[k]*/]
    .filter((i) => !!i)
    .map((i) => wrapHash(k, i));
  HASHES[k] = {
    noble,
    versions,
  };
}
