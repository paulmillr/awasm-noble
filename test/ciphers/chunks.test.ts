import { describe, should } from '@paulmillr/jsbt/test.js';
import { deepStrictEqual as eql } from 'node:assert';
import { randomBytes } from '@noble/hashes/utils.js';
import { concatBytes } from '../../src/utils.ts';

const empty = new Uint8Array(0);

const concat = (parts: Uint8Array[]) => (parts.length ? concatBytes(...parts) : empty);

const splitPoints = (len: number) => {
  if (len === 0) return [0];
  const step = Math.max(1, Math.floor(len / 7));
  const pts = new Set<number>([0, len]);
  for (let i = 0; i <= len; i += step) pts.add(i);
  return Array.from(pts).sort((a, b) => a - b);
};

const makeParts = (buf: Uint8Array, lens: number[]) => {
  const parts: Uint8Array[] = [];
  let pos = 0;
  for (const len of lens) {
    parts.push(buf.subarray(pos, pos + len));
    pos += len;
  }
  return parts;
};

const chunkPatterns = (len: number, blockLen: number, dataOffset?: number) => {
  const out: number[][] = [];
  const seen = new Set<string>();
  const add = (p: number[]) => {
    let sum = 0;
    for (const n of p) {
      if (n < 0) return;
      sum += n;
    }
    if (sum !== len) return;
    const key = p.join(',');
    if (seen.has(key)) return;
    seen.add(key);
    out.push(p);
  };
  const steps = [1, 2, 3, 7, 8, 15, 16, 17, 31, 32, 33];
  if (blockLen && !steps.includes(blockLen)) steps.push(blockLen);
  if (blockLen * 2 && !steps.includes(blockLen * 2)) steps.push(blockLen * 2);
  const addZeros = (p: number[]) => {
    const z: number[] = [0];
    for (const n of p) z.push(n, 0);
    add(z);
  };
  const bounds = (b: number) => {
    if (b > 0 && b < len) {
      add([b, len - b]);
      add([len - b, b]);
      addZeros([b, len - b]);
    }
  };
  add([len]);
  addZeros([len]);
  add([0, len]);
  add([len, 0]);
  add([0, len, 0]);
  for (const pos of splitPoints(len)) add([pos, len - pos]);
  for (const step of steps) {
    if (step <= 0 || len === 0) continue;
    let rem = len;
    const p: number[] = [];
    while (rem > 0) {
      const take = Math.min(step, rem);
      p.push(take);
      rem -= take;
    }
    add(p);
    if (p.length > 1) addZeros(p);
  }
  const bSizes = [
    blockLen - 1,
    blockLen,
    blockLen + 1,
    blockLen * 2 - 1,
    blockLen * 2,
    blockLen * 2 + 1,
    blockLen * 3 - 1,
    blockLen * 3,
    blockLen * 3 + 1,
  ];
  for (const b of bSizes) bounds(b);
  if (dataOffset) {
    const cap = blockLen - dataOffset;
    const cSizes = [cap - 1, cap, cap + 1, cap * 2 - 1, cap * 2, cap * 2 + 1];
    for (const c of cSizes) bounds(c);
  }
  if (blockLen && len > 0) {
    const p: number[] = [];
    let rem = len;
    while (rem > 0) {
      const take = Math.min(blockLen - 1, rem);
      p.push(take);
      rem -= take;
      if (rem <= 0) break;
      const take2 = Math.min(1, rem);
      p.push(take2);
      rem -= take2;
    }
    add(p);
    if (p.length > 1) addZeros(p);
  }
  let state = (len ^ (blockLen << 16)) >>> 0;
  for (let i = 0; i < 12; i++) {
    state = (state * 1664525 + 1013904223) >>> 0;
    let rem = len;
    const p: number[] = [];
    while (rem > 0) {
      state = (state * 1664525 + 1013904223) >>> 0;
      const cap = Math.min(rem, blockLen ? blockLen * 2 : rem);
      const take = (state % cap) + 1;
      p.push(take);
      rem -= take;
    }
    add(p);
  }
  return out;
};

const splitTag = (factory: any, data: Uint8Array) => {
  const def = factory.getDefinition();
  if (!def.tagLength) return { ct: data, tag: undefined };
  if (def.tagLeft) {
    const tag = data.subarray(0, def.tagLength);
    return { ct: data.subarray(def.tagLength), tag };
  }
  const tag = data.subarray(data.length - def.tagLength);
  return { ct: data.subarray(0, data.length - def.tagLength), tag };
};

const streamEncrypt = (factory: any, cipher: any, parts: Uint8Array[]) => {
  const s = cipher.encrypt.create();
  const out: Uint8Array[] = [];
  for (const p of parts) out.push(s.update(p));
  const { data, tag } = s.finish();
  if (data.length) out.push(data);
  if (tag) {
    const def = factory.getDefinition();
    if (def.tagLeft) out.unshift(tag);
    else out.push(tag);
  }
  return concat(out);
};

const streamDecrypt = (cipher: any, parts: Uint8Array[], tag?: Uint8Array) => {
  const s = cipher.decrypt.create();
  const out: Uint8Array[] = [];
  for (const p of parts) out.push(s.update(p));
  const { data } = tag ? s.finish(tag) : s.finish();
  if (data.length) out.push(data);
  return concat(out);
};

const streamFromStream = (factory: any, s: any, parts: Uint8Array[]) => {
  const out: Uint8Array[] = [];
  for (const p of parts) out.push(s.update(p));
  const { data, tag } = s.finish();
  if (data.length) out.push(data);
  const def = factory.getDefinition();
  const tagOut = tag ? (def.tagLeft ? concat([tag, ...out]) : concat([...out, tag])) : concat(out);
  return tagOut;
};

const streamFromStreamDec = (s: any, parts: Uint8Array[], tag?: Uint8Array) => {
  const out: Uint8Array[] = [];
  for (const p of parts) out.push(s.update(p));
  const { data } = tag ? s.finish(tag) : s.finish();
  if (data.length) out.push(data);
  return concat(out);
};

const statePatterns = (len: number, blockLen: number, dataOffset?: number) =>
  chunkPatterns(len, blockLen, dataOffset).slice(0, 4);

const test = (name: string, platform: any) => {
  const specs = [
    { name: 'ctr', fn: platform.ctr, keyLens: [16, 24, 32] },
    { name: 'cbc', fn: platform.cbc, keyLens: [16, 24, 32] },
    { name: 'cfb', fn: platform.cfb, keyLens: [16, 24, 32] },
    { name: 'ofb', fn: platform.ofb, keyLens: [16, 24, 32] },
    { name: 'ecb', fn: platform.ecb, keyLens: [16, 24, 32] },
    { name: 'gcm', fn: platform.gcm, keyLens: [16, 24, 32], withAAD: true },
    { name: 'gcmsiv', fn: platform.gcmsiv, keyLens: [16, 32], withAAD: true, noStream: true },
    { name: 'siv', fn: platform.siv, keyLens: [32, 64], withAAD: true, noStream: true },
    { name: 'chacha20', fn: platform.chacha20, keyLens: [32] },
    { name: 'xchacha20', fn: platform.xchacha20, keyLens: [32] },
    { name: 'salsa20', fn: platform.salsa20, keyLens: [32] },
    { name: 'xsalsa20', fn: platform.xsalsa20, keyLens: [32] },
    { name: 'chacha20poly1305', fn: platform.chacha20poly1305, keyLens: [32], withAAD: true },
    { name: 'xchacha20poly1305', fn: platform.xchacha20poly1305, keyLens: [32], withAAD: true },
    { name: 'xsalsa20poly1305', fn: platform.xsalsa20poly1305, keyLens: [32], withAAD: true },
  ];

  describe(`Cipher chunks (${name})`, () => {
    for (const spec of specs) {
      if (!spec.fn) continue;
      const def = spec.fn.getDefinition();
      if (def.noStream) {
        for (const keyLen of spec.keyLens) {
          should(`${spec.name}_${keyLen * 8}: noStream`, () => {
            const key = randomBytes(keyLen);
            const nonce = spec.fn.nonceLength ? randomBytes(spec.fn.nonceLength) : undefined;
            const aad = spec.withAAD ? randomBytes(8) : undefined;
            const args = nonce ? [nonce] : [];
            if (aad !== undefined) args.push(aad);
            const c = spec.fn(key, ...args);
            let threw = false;
            try {
              c.encrypt.create();
            } catch {
              threw = true;
            }
            if (!threw) throw new Error('expected noStream to throw');
          });
        }
        continue;
      }
      const blockLen = def.blockLen as number;
      const dataOffset = def.dataOffset as number | undefined;
      const sizeSet = new Set<number>([
        0, 1, 2, 3, 7, 8, 15, 16, 17, 31, 32, 33, 63, 64, 65, 127, 128, 129, 255, 256, 257, 1024,
        2048, 4096,
      ]);
      for (const b of [
        blockLen - 1,
        blockLen,
        blockLen + 1,
        blockLen * 2 - 1,
        blockLen * 2,
        blockLen * 2 + 1,
        blockLen * 3 - 1,
        blockLen * 3,
        blockLen * 3 + 1,
        blockLen * 4 - 1,
        blockLen * 4,
        blockLen * 4 + 1,
      ]) {
        if (b >= 0) sizeSet.add(b);
      }
      if (dataOffset) {
        const cap = blockLen - dataOffset;
        for (const c of [cap - 1, cap, cap + 1, cap * 2 - 1, cap * 2, cap * 2 + 1]) {
          if (c >= 0) sizeSet.add(c);
        }
      }
      const sizes = Array.from(sizeSet)
        .filter((s) => s >= 0)
        .sort((a, b) => a - b);
      for (const keyLen of spec.keyLens) {
        should(`${spec.name}_${keyLen * 8}: chunks`, () => {
          const key = randomBytes(keyLen);
          const aadSizes = [0, 1, 2, 3, 7, 8, 15, 16, 17, 31, 32, 33];
          const aadLarge = [1024, 4096, 16384];

          for (const size of sizes) {
            const nonce = spec.fn.nonceLength ? randomBytes(spec.fn.nonceLength) : undefined;
            const nonceB = spec.fn.nonceLength ? randomBytes(spec.fn.nonceLength) : undefined;
            const aadLen = spec.withAAD ? aadSizes[(size + keyLen) % aadSizes.length] : 0;
            const aadLenB = spec.withAAD ? aadSizes[(size + keyLen + 3) % aadSizes.length] : 0;
            const aad = spec.withAAD ? (aadLen ? randomBytes(aadLen) : empty) : undefined;
            const aadB = spec.withAAD ? (aadLenB ? randomBytes(aadLenB) : empty) : undefined;
            const args = nonce ? [nonce] : [];
            if (aad !== undefined) args.push(aad);
            const argsB = nonceB ? [nonceB] : [];
            if (aadB !== undefined) argsB.push(aadB);
            const mk = () => spec.fn(key, ...args);
            const mkB = () => spec.fn(key, ...argsB);
            const msg = randomBytes(size);
            const expEnc = mk().encrypt(msg);
            const expDec = mk().decrypt(expEnc);

            for (const lens of chunkPatterns(msg.length, blockLen, dataOffset)) {
              const encParts = makeParts(msg, lens);
              const gotEnc = streamEncrypt(spec.fn, mk(), encParts);
              eql(gotEnc, expEnc);
            }

            const { ct, tag } = splitTag(spec.fn, expEnc);
            for (const lens of chunkPatterns(ct.length, blockLen, dataOffset)) {
              const decParts = makeParts(ct, lens);
              const gotDec = streamDecrypt(mk(), decParts, tag);
              eql(gotDec, expDec);
            }
          }
          if (spec.withAAD) {
            const bigSizes = [0, 1, blockLen, blockLen + 1].filter((n) => n >= 0);
            for (const aadLen of aadLarge) {
              const aad = aadLen ? randomBytes(aadLen) : empty;
              for (const size of bigSizes) {
                const nonce = spec.fn.nonceLength ? randomBytes(spec.fn.nonceLength) : undefined;
                const args = nonce ? [nonce] : [];
                args.push(aad);
                const mk = () => spec.fn(key, ...args);
                const msg = randomBytes(size);
                const expEnc = mk().encrypt(msg);
                const expDec = mk().decrypt(expEnc);
                const lensList = chunkPatterns(msg.length, blockLen, dataOffset).slice(0, 4);
                for (const lens of lensList) {
                  const encParts = makeParts(msg, lens);
                  const gotEnc = streamEncrypt(spec.fn, mk(), encParts);
                  eql(gotEnc, expEnc);
                }
                const { ct, tag } = splitTag(spec.fn, expEnc);
                for (const lens of chunkPatterns(ct.length, blockLen, dataOffset).slice(0, 4)) {
                  const decParts = makeParts(ct, lens);
                  const gotDec = streamDecrypt(mk(), decParts, tag);
                  eql(gotDec, expDec);
                }
              }
            }
          }
          if (spec.withAAD) {
            const nonce = spec.fn.nonceLength ? randomBytes(spec.fn.nonceLength) : undefined;
            const aad = randomBytes(16);
            const args = nonce ? [nonce] : [];
            args.push(aad);
            const mk = () => spec.fn(key, ...args);
            const msg = randomBytes(32);
            const expEnc = mk().encrypt(msg);
            const { ct, tag } = splitTag(spec.fn, expEnc);
            const d0 = mk().decrypt.create();
            for (const p of makeParts(
              ct,
              chunkPatterns(ct.length, blockLen, dataOffset)[0] || [ct.length]
            ))
              d0.update(p);
            let threw = false;
            try {
              d0.finish();
            } catch {
              threw = true;
            }
            if (!threw) throw new Error('expected finish() without tag to throw');
            const badTag = tag ? randomBytes(tag.length) : randomBytes(16);
            const d1 = mk().decrypt.create();
            for (const p of makeParts(
              ct,
              chunkPatterns(ct.length, blockLen, dataOffset)[1] || [ct.length]
            ))
              d1.update(p);
            let threw2 = false;
            try {
              d1.finish(badTag);
            } catch {
              threw2 = true;
            }
            if (!threw2) throw new Error('expected finish() with wrong tag to throw');
            const e1 = mk().encrypt.create();
            e1.update(msg.subarray(0, 1));
            e1.finish();
            let threw3 = false;
            try {
              e1.update(msg.subarray(1, 2));
            } catch {
              threw3 = true;
            }
            if (!threw3) throw new Error('expected update after finish to throw');
          }

          const stateSizes = [0, 1, blockLen - 1, blockLen, blockLen + 1, blockLen * 2 + 3].filter(
            (n) => n >= 0
          );
          for (const size of stateSizes) {
            const nonce = spec.fn.nonceLength ? randomBytes(spec.fn.nonceLength) : undefined;
            const nonceB = spec.fn.nonceLength ? randomBytes(spec.fn.nonceLength) : undefined;
            const aadLen = spec.withAAD ? aadSizes[(size + keyLen) % aadSizes.length] : 0;
            const aadLenB = spec.withAAD ? aadSizes[(size + keyLen + 3) % aadSizes.length] : 0;
            const aad = spec.withAAD ? (aadLen ? randomBytes(aadLen) : empty) : undefined;
            const aadB = spec.withAAD ? (aadLenB ? randomBytes(aadLenB) : empty) : undefined;
            const args = nonce ? [nonce] : [];
            if (aad !== undefined) args.push(aad);
            const argsB = nonceB ? [nonceB] : [];
            if (aadB !== undefined) argsB.push(aadB);
            const mk = () => spec.fn(key, ...args);
            const mkB = () => spec.fn(key, ...argsB);
            const msg = randomBytes(size);
            const expEnc = mk().encrypt(msg);
            const expDec = mk().decrypt(expEnc);
            const msgB = randomBytes(size ? size + 1 : 1);
            const expEncB = mkB().encrypt(msgB);
            const expDecB = mkB().decrypt(expEncB);
            const { ct, tag } = splitTag(spec.fn, expEnc);
            const { ct: ctB, tag: tagB } = splitTag(spec.fn, expEncB);
            for (const lens of statePatterns(msg.length, blockLen, dataOffset)) {
              const parts = makeParts(msg, lens);
              const s = mk().encrypt.create();
              const out: Uint8Array[] = [];
              for (let i = 0; i < parts.length; i++) {
                const chunk = s.update(parts[i]);
                out.push(chunk);
              }
              const fin = s.finish();
              if (fin.data.length) out.push(fin.data);
              const def = spec.fn.getDefinition();
              const got = fin.tag
                ? def.tagLeft
                  ? concat([fin.tag, ...out])
                  : concat([...out, fin.tag])
                : concat(out);
              eql(got, expEnc);
              const s3 = mk().encrypt.create();
              const c1 = s3.clone();
              const out3 = streamFromStream(spec.fn, s3, parts);
              const out4 = streamFromStream(spec.fn, c1, parts);
              eql(out3, expEnc);
              eql(out4, expEnc);
              const s4 = mk().encrypt.create();
              const s5 = mk().encrypt.create();
              const out5: Uint8Array[] = [];
              const out6: Uint8Array[] = [];
              for (let i = 0; i < parts.length; i++) {
                const p = parts[i];
                if (i % 2 === 0) {
                  out5.push(s4.update(p));
                  out6.push(s5.update(p));
                } else {
                  out6.push(s5.update(p));
                  out5.push(s4.update(p));
                }
              }
              const fin5 = s4.finish();
              const fin6 = s5.finish();
              if (fin5.data.length) out5.push(fin5.data);
              if (fin6.data.length) out6.push(fin6.data);
              const got5 = fin5.tag
                ? def.tagLeft
                  ? concat([fin5.tag, ...out5])
                  : concat([...out5, fin5.tag])
                : concat(out5);
              const got6 = fin6.tag
                ? def.tagLeft
                  ? concat([fin6.tag, ...out6])
                  : concat([...out6, fin6.tag])
                : concat(out6);
              eql(got5, expEnc);
              eql(got6, expEnc);
              const partsA = makeParts(msg, lens);
              const lensB = chunkPatterns(msgB.length, blockLen, dataOffset)[1] || [msgB.length];
              const partsB = makeParts(msgB, lensB);
              const sA = mk().encrypt.create();
              const sB = mkB().encrypt.create();
              const outA: Uint8Array[] = [];
              const outB: Uint8Array[] = [];
              let iA = 0;
              let iB = 0;
              for (; iA < partsA.length || iB < partsB.length; ) {
                if (iA < partsA.length) outA.push(sA.update(partsA[iA++]));
                if (iB < partsB.length) outB.push(sB.update(partsB[iB++]));
              }
              const finA = sA.finish();
              const finB = sB.finish();
              if (finA.data.length) outA.push(finA.data);
              if (finB.data.length) outB.push(finB.data);
              const gotA = finA.tag
                ? def.tagLeft
                  ? concat([finA.tag, ...outA])
                  : concat([...outA, finA.tag])
                : concat(outA);
              const gotB = finB.tag
                ? def.tagLeft
                  ? concat([finB.tag, ...outB])
                  : concat([...outB, finB.tag])
                : concat(outB);
              eql(gotA, expEnc);
              eql(gotB, expEncB);
            }
            for (const lens of statePatterns(ct.length, blockLen, dataOffset)) {
              const partsCt = makeParts(ct, lens);
              const dec = streamFromStreamDec(mk().decrypt.create(), partsCt, tag);
              eql(dec, expDec);
              const d0 = mk().decrypt.create();
              const d1 = d0.clone();
              const outd0 = streamFromStreamDec(d0, partsCt, tag);
              const outd1 = streamFromStreamDec(d1, partsCt, tag);
              eql(outd0, expDec);
              eql(outd1, expDec);
            }
            const lensCtA = chunkPatterns(ct.length, blockLen, dataOffset)[0] || [ct.length];
            const lensCtB = chunkPatterns(ctB.length, blockLen, dataOffset)[1] || [ctB.length];
            const partsCtA = makeParts(ct, lensCtA);
            const partsCtB = makeParts(ctB, lensCtB);
            const dA = mk().decrypt.create();
            const dB = mkB().decrypt.create();
            const outDA: Uint8Array[] = [];
            const outDB: Uint8Array[] = [];
            let jA = 0;
            let jB = 0;
            for (; jA < partsCtA.length || jB < partsCtB.length; ) {
              if (jA < partsCtA.length) outDA.push(dA.update(partsCtA[jA++]));
              if (jB < partsCtB.length) outDB.push(dB.update(partsCtB[jB++]));
            }
            const finDA = tag ? dA.finish(tag) : dA.finish();
            const finDB = tagB ? dB.finish(tagB) : dB.finish();
            if (finDA.data.length) outDA.push(finDA.data);
            if (finDB.data.length) outDB.push(finDB.data);
            eql(concat(outDA), expDec);
            eql(concat(outDB), expDecB);
          }
        });
      }
    }
  });
};

import { PLATFORMS } from '../platforms.ts';
for (const k in PLATFORMS) test(k, PLATFORMS[k]);
should.runWhen(import.meta.url);
