/**
 * Reusable utils.
 * The file is not used in end-user code. Instead, it's used by awasm-compiler
 * to generate different build targets (wasm, wasm_threads, js, runtime).
 * @module
 */
import type { GetOps, Scope, Val } from '@awasm/compiler/module.js';
import { type TypeName } from '@awasm/compiler/types.js';

export function getLanes(_type: TypeName) {
  // Even for u64 it is better to use virtual u64x4 than real u64x2.
  return 4;
}

export function readMSG(f: Scope, region: any, clear = true) {
  // `BUFFER.fill(0)` is slow garbage: even BUFFER.set() is faster,
  // but requires pre-allocated array of exact size.
  // So, instead of doing `fill` to zeroize data, we zeroize on read.
  // This should be slower in theory: for 100MB we would
  // wipe buffer on every 10MB chunk, instead of just once.
  //
  // The trick why it's faster: cache / memory locality,
  // we are wiping region which we've just touched.
  const T = f.getTypeGeneric(region.type);
  const res = region.get();
  if (clear) region.set(Array.isArray(res) ? res.map((_i) => T.const(0)) : T.const(0));
  return res;
}

export const CHUNKS = 10 * 1024 * 16; // ~10MB, 160K blocks
export const MIN_PER_THREAD = 1024; // 1k blocks

// Shared u32 byteswap. Placed here so `mac.ts` doesn't need to import from AES modules
// (avoids circular deps).
export const bswap = (u32: GetOps<'u32'>, x: Val<'u32'>) =>
  u32.or(
    u32.or(u32.shl(u32.and(x, u32.const(0xff)), 24), u32.shl(u32.and(x, u32.const(0xff00)), 8)),
    u32.or(u32.shr(u32.and(x, u32.const(0xff0000)), 8), u32.shr(x, 24))
  );
