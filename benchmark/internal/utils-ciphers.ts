export const onlyNoble = process.argv[2] === 'noble';
export function buf(n) {
  return new Uint8Array(n).fill(n % 251);
}

// Avoid deepStrictEqual on large buffers; Node can allocate heavily when formatting byte diffs.
function eql(a: Uint8Array, b: Uint8Array, msg?: string) {
  if (a.length !== b.length) throw new Error(`u8a.eql: length ${a.length}!==${b.length} (${msg})`);
  for (let i = 0; i < a.length; i++) {
    if (a[i] !== b[i]) throw new Error(`u8a.eql: a[${i}](${a[i]})!==b[${i}](${b[i]}), ${msg}`);
  }
}

export async function crossValidate(title, buffers, ciphers) {
  // Verify that things we bench actually work
  const bufs = Object.values(buffers);
  const bufMap = new Map(Object.entries(buffers).map(([k, v]) => [v, k]));
  // Verify different buffer sizes
  for (let i = 0; i < 2048; i++) bufs.push(buf(i));
  // Return encrypted values for buffers for decrypt test
  const res = {};
  for (const buf of bufs) {
    const bname = bufMap.get(buf) || `${buf.length}`;
    const b = buf.slice();
    let encrypted;
    const opts = ciphers.options;
    // Skip some buffers for block ciphers without padding
    if (opts.blockSize && b.length % opts.blockSize) continue;
    for (let [lib, fn] of Object.entries(ciphers)) {
      if (lib === 'options') continue;
      if (encrypted === undefined) {
        encrypted = await fn.encrypt(buf, opts);
      } else {
        const cur = await fn.encrypt(buf, opts);
        // When threaded backends go wrong, it is often size-dependent. Add a tiny bit of
        // diagnostic context to the error so we can reproduce without rerunning full benches.
        if (encrypted.length !== cur.length) {
          throw new Error(
            `u8a.eql: length ${encrypted.length}!==${cur.length} (${title}/${bname}: encrypt verify (${lib}))`
          );
        }
        for (let i = 0; i < encrypted.length; i++) {
          if (encrypted[i] === cur[i]) continue;
          const a0 = [encrypted[0], encrypted[1], encrypted[2], encrypted[3]];
          const b0 = [cur[0], cur[1], cur[2], cur[3]];
          throw new Error(
            `u8a.eql: a[${i}](${encrypted[i]})!==b[${i}](${cur[i]}), ${title}/${bname}: encrypt verify (${lib}); head a=${a0} b=${b0}`
          );
        }
      }
      eql(buf, b, `${title}/${bname}: encrypt mutates buffer (${lib})`);
      const res = await fn.decrypt(encrypted, opts);
      eql(res, buf, `${title}/${bname}: decrypt verify (${lib})`);
    }
    const bufName = bufMap.get(buf);
    if (bufName) res[bufName] = encrypted;
  }
  return res;
}
