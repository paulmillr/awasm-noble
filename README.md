# AWASM noble

> WASM, but paranoia-friendly

Auditable WASM implementation of cryptographic hashes & ciphers.

- 🔒 Auditable: reproducible binaries produced from JS source code
- 🔻 Tree-shakeable: unused code is excluded from your builds
- 🏎 Fast: [6-10 GB/s for BLAKE3](#speed), 6.4 GB/s for ChaCha20
- 🔍 Reliable: tests from noble packages, zeroization tests
- 4️⃣ Different backends: wasm (SIMD), threaded wasm (web workers), JS, runtime
- 🎫 Stubs: switch between backends based on app needs
- 🔗 Synchronous by default, with optional async methods
- 🦘 Includes SHA, RIPEMD, BLAKE, PBKDF, Scrypt, Argon2, Salsa, ChaCha, AES
- 🪶 Lightweight

### This library belongs to _awasm_

> **awasm** — high-security, auditable WASM packages

- **Reproducible builds:** deterministic cross-platform builds
- **Auditable compiler:** reasonably small JS-to-WASM compiler
- **Synchronous execution:** with optional async variant
- Minimal deps, PGP-signed releases and transparent NPM builds
- All libraries:
  [awasm-noble](https://github.com/paulmillr/awasm-noble),
  [awasm-compiler](https://github.com/paulmillr/awasm-compiler)
- [Check out the homepage](https://paulmillr.com/awasm/) for motivation behind the project

## Usage

> `npm install @awasm/noble`

> `deno add jsr:@awasm/noble`

```ts
import { sha224, sha256, sha384, sha512, sha512_224, sha512_256 } from '@awasm/noble';
import { md5, ripemd160, sha1 } from '@awasm/noble';
import { blake224, blake256, blake384, blake512,
         blake2b, blake2s, blake3 } from '@awasm/noble';
import { keccak_224, keccak_256, keccak_384, keccak_512,
  sha3_224, sha3_256, sha3_384, sha3_512,
  shake128, shake128_32, shake256, shake256_64 } from '@awasm/noble';
import { argon2d, argon2i, argon2id, scrypt } from '@awasm/noble';
import { pbkdf2 } from '@awasm/noble/kdf.js';
import { hmac } from '@awasm/noble/hmac.js';
import { hkdf } from '@awasm/noble/hkdf.js';
import {
  chacha20poly1305, xchacha20poly1305, xsalsa20poly1305, gcm, gcmsiv,
  aessiv, ctr, cbc, cfb, ofb, ecb, aeskw, aeskwp,
  cmac, chacha20, xchacha20, salsa20, xsalsa20, chacha8, ghash, polyval, poly1305,
} from '@awasm/noble';

blake3(new Uint8Array([0xca, 0xfe]));
```

<!-- TOC start -->

* [Usage](#usage)
  + [Interface](#interface)
  + [Backends: wasm, wasm_threads, js, webcrypto, runtime](#backends-wasm-wasm_threads-js-webcrypto-runtime)
  + [Stubs](#stubs)
  + [Threads](#threads)
  + [Streaming](#streaming)
  + [Async](#async)
  + [Zero-allocation](#zero-allocation)
* [Examples](#examples)
  + [Encrypt with XChaCha20Poly1305](#encrypt-with-xchacha20poly1305)
  + [Encrypt with AES](#encrypt-with-aes)
  + [Auto-managed nonce](#auto-managed-nonce)
  + [Async ciphers with progress](#async-ciphers-with-progress)
  + [Streaming ciphers](#streaming-ciphers)
  + [Scrypt, Argon, PBKDF](#scrypt-argon-pbkdf)
  + [MACs](#macs)
  + [WebCrypto Hashes + KDF/MAC](#webcrypto-hashes--kdfmac)
  + [WebCrypto Ciphers](#webcrypto-ciphers)
* [Internals](#internals)
  + [Why one package for hashes & ciphers?](#why-one-package-for-hashes--ciphers)
  + [Differences from noble](#differences-from-noble)
  + [Deno and Web Workers](#deno-and-web-workers)
  + [Contributing](#contributing)
* [Speed](#speed)
  + [wasm_threads](#wasm_threads)
  + [wasm (no threads)](#wasm-no-threads)
* [License](#license)

<!-- TOC end -->

### Interface

Hashes can be called in the following ways:

```js
import { blake3 } from '@awasm/noble';

const msg = new Uint8Array(64);
const msg1 = msg;
const msg2 = msg;
const opts = {};

blake3(msg);
blake3(msg, opts);
await blake3.async(msg);
blake3.chunks([msg.slice(0, 32), msg.slice(32, 64)]);
blake3.parallel([msg1, msg2]);
blake3.create().update(msg1).update(msg2).digest();
```

Ciphers have following interfaces:

```js
import { chacha20poly1305 } from '@awasm/noble';

const key = new Uint8Array(32);
const nonce = new Uint8Array(12);
const data = new Uint8Array([1, 2, 3]);
const cipher = chacha20poly1305(key, nonce /*, ...optionalArgs */);
const encrypted = cipher.encrypt(data); // sync
cipher.decrypt(encrypted);

await chacha20poly1305(key, nonce).encrypt.async(data); // async
await chacha20poly1305(key, nonce).decrypt.async(encrypted);

const enc = chacha20poly1305(key, nonce).encrypt.create();
enc.update(data);
const streamed = enc.finish(); // streaming
const dec = chacha20poly1305(key, nonce).decrypt.create();
dec.update(streamed.data);
dec.finish(streamed.tag);
```

MACs (`poly1305` / `ghash` / `polyval` / `cmac`) are hash-like, with extra `key` option:
`mac(msg, key|{ key })`, `mac.chunks(...)`, `mac.parallel(...)`, `mac.create(...)`.

KDFs are `kdf(password, salt, opts?)` and `kdf.async(...)`.

### Backends: wasm, wasm_threads, js, webcrypto, runtime

```ts
import { sha256 } from '@awasm/noble'; // wasm
import { sha256 as sha256wasm_threads } from '@awasm/noble/wasm_threads.js';
import { sha256 as sha256js } from '@awasm/noble/js.js';
import { sha256 as sha256wc } from '@awasm/noble/webcrypto.js';
import { sha256 as sha256rn } from '@awasm/noble/runtime.js';

for (const hash of [sha256, sha256wasm_threads, sha256js, sha256rn]) {
  console.log(hash(new Uint8Array([1, 2, 3])));
}
for (const hash of [sha256wc]) {
  console.log(await hash.async(new Uint8Array([1, 2, 3])));
}
```

4 backends are produced from 1 source code, by awasm-compiler:

1. **wasm:** JS files containing wasm binaries in base64 strings. Requires `wasm-unsafe-eval` CORS policy to work.
    - Check out [`examples`](./examples) for node.js & vercel example of proper headers
2. **wasm_threads:** identical to wasm, but faster due to web workers. Requires `Cross-Origin-Opener-Policy: same-origin` & `Cross-Origin-Embedder-Policy: require-corp` CORS policies to work.
    - Check out [`examples`](./examples) for node.js & vercel example of proper headers
3. **js:** JS files without WASM. Extra optimizations (like loop unrolling) are auto-applied, to make everything fast.
4. **runtime:** slowly executes source code in-place. Tiny bundle size, useful for debugging. Depends on `@awasm/compiler`

Additionally, **webcrypto** submodule wraps around built-in `WebCrypto` methods. It's async-only.


### Stubs

Stubs allow using one high-level function call, while switching the internal backend
as needed.

Imagine you have a high-level library ("awasm-react"). It's not the best idea to use
wasm methods there, because users of the library may not want wasm.

Instead, you use stub, with (default) wasm inside. User then is able to switch the env any time
to JS, WebCrypto, or other backend.

```ts
import { sha256 } from '@awasm/noble/stub.js';
function hash() {
  console.log(sha256(new Uint8Array([1, 2, 3]))); // generic
}

// Switch to WASM
import { sha256 as sha256wasm } from '@awasm/noble';
sha256.install(sha256wasm);
hash();

// Switch to JS
import { sha256 as sha256js } from '@awasm/noble/js.js';
sha256.install(sha256js);
hash();

// Switch to WebCrypto
import { sha256 as sha256Web } from '@awasm/noble/webcrypto.js';
if (await sha256Web.isSupported()) {
  sha256.install(sha256Web);
  console.log(await sha256.async(new Uint8Array([1, 2, 3]))); // generic
}
```

### Threads

```ts
import { blake3 } from '@awasm/noble/wasm_threads.js';
import { xchacha20poly1305 } from '@awasm/noble/wasm_threads.js';
import { sha256 } from '@awasm/noble/wasm_threads.js';
import { deepStrictEqual } from 'node:assert';

blake3(new Uint8Array(1024 * 1024 * 1024)); // 1gb

deepStrictEqual(sha256.parallel([new Uint8Array([1, 2, 3]), new Uint8Array([4, 5, 6])]), [
  sha256(new Uint8Array([1, 2, 3])),
  sha256(new Uint8Array([4, 5, 6])),
]);
```

```ts
// Benchmark blake3
import { blake3 } from '@awasm/noble/wasm_threads.js';
async function main() {
  function hex(bytes) {
    return Array.from(bytes).map(byte => byte.toString(16).padStart(2, '0')).join('');
  }
  // warm-up JIT
  for (let i = 0; i < 20; i++) {
    blake3.parallel([new Uint8Array(1024 * 1024)]);
    await Promise.resolve();
  }
  // benchmark
  for (let i = 0; i < 5; i++) {
    const input = new Uint8Array(1024 * 1024 * 1024).fill(i); // 1GB of 0x00, 0x01, 0x02...
    const start = Date.now();
    const res = blake3(input); // or blake3.create().update().digest()
    console.log('hashed 1gb in', Date.now() - start, 'ms, result:', hex(res));
  }
}
main();
```

Default backend (WASM) uses SIMD for parallel execution.

`wasm_threads` also use web worker based threads.
It requires `Cross-Origin-Opener-Policy: same-origin` & `Cross-Origin-Embedder-Policy: require-corp`
CORS policies to work.
Check out [`examples`](./examples) for node.js & vercel example of proper headers.

BLAKE3 & most ciphers run very fast in threaded mode. Others
(e.g. SHA256, AES-CBC) can't parallelize one large input using threads,
but they still do it for multiple inputs, using `hash.parallel(input)`.

### Streaming

```ts
import { sha256 } from '@awasm/noble';

sha256
  .create()
  .update(new Uint8Array([1, 2, 3]))
  .update(new Uint8Array([4, 5, 6]))
  .digest();

sha256.chunks([new Uint8Array([1, 2, 3]), new Uint8Array([4, 5, 6])]);
```

For best performance: use chunks for <1kb messages. Use streaming for 1kb+ messages.

### Async

```ts
import { sha256 } from '@awasm/noble';
import { deepStrictEqual } from 'node:assert';

deepStrictEqual(sha256(new Uint8Array([1, 2, 3])), await sha256.async(new Uint8Array([1, 2, 3])));
deepStrictEqual(
  sha256.parallel([new Uint8Array([1, 2, 3])]),
  await sha256.parallel.async([new Uint8Array([1, 2, 3])])
);
deepStrictEqual(
  sha256.chunks([new Uint8Array([1, 2, 3])]),
  await sha256.chunks.async([new Uint8Array([1, 2, 3])])
);
```

### Zero-allocation

```ts
import { sha256 } from '@awasm/noble';
import { deepStrictEqual } from 'node:assert';

const out = new Uint8Array(sha256.outputLen);
sha256(new Uint8Array([1, 2, 3]), { out });
deepStrictEqual(out, sha256(new Uint8Array([1, 2, 3])));
```

```ts
import { ctr } from '@awasm/noble';
import { deepStrictEqual } from 'node:assert';

const key = new Uint8Array(32).fill(1);
const nonce = new Uint8Array(16).fill(2);
const msg = new Uint8Array(64).fill(7);
const c = ctr(key, nonce);

const encOut = new Uint8Array(msg.length);
c.encrypt(msg, encOut);
const decOut = new Uint8Array(msg.length);
c.decrypt(encOut, decOut);
deepStrictEqual(decOut, msg);
```

Some ciphers (GCM, GCM-SIV) don't support zero-alloc mode.

## Examples

### Encrypt with XChaCha20Poly1305

```ts
import { xchacha20poly1305 } from '@awasm/noble';

const key = new Uint8Array(32).fill(7);
const nonce = new Uint8Array(24).fill(9);
const data = new TextEncoder().encode('hello noble');
const chacha = xchacha20poly1305(key, nonce);
const ciphertext = chacha.encrypt(data);
const data_ = chacha.decrypt(ciphertext);
```

### Encrypt with AES

```ts
import { deepStrictEqual } from 'node:assert';
import { gcm, gcmsiv, aessiv, ctr, cfb, cbc, ecb, aeskw, aeskwp } from '@awasm/noble';

const plaintext = new Uint8Array(32).fill(16);
const key = new Uint8Array(32).fill(1);
const nonce12 = new Uint8Array(12).fill(2);
const nonce16 = new Uint8Array(16).fill(3);
for (const cipher of [gcm, gcmsiv, aessiv]) {
  const ct = cipher(key, nonce12).encrypt(plaintext);
  deepStrictEqual(cipher(key, nonce12).decrypt(ct), plaintext);
}
for (const cipher of [ctr, cbc, cfb]) {
  const ct = cipher(key, nonce16).encrypt(plaintext);
  deepStrictEqual(cipher(key, nonce16).decrypt(ct), plaintext);
}
const wrapped = aeskw(key.subarray(0, 16)).encrypt(key.subarray(0, 16));
deepStrictEqual(aeskw(key.subarray(0, 16)).decrypt(wrapped), key.subarray(0, 16));
const wrappedP = aeskwp(key.subarray(0, 16)).encrypt(key.subarray(0, 16));
deepStrictEqual(aeskwp(key.subarray(0, 16)).decrypt(wrappedP), key.subarray(0, 16));
deepStrictEqual(ecb(key).decrypt(ecb(key).encrypt(plaintext)), plaintext);
```

### Auto-managed nonce

```ts
import { deepStrictEqual } from 'node:assert';
import { xchacha20poly1305 } from '@awasm/noble';
import { managedNonce } from '@awasm/noble/utils.js';

const key = new Uint8Array(32).fill(4);
const chacha = managedNonce(xchacha20poly1305)(key);
const data = new TextEncoder().encode('hello noble');
const ciphertext = chacha.encrypt(data);
deepStrictEqual(chacha.decrypt(ciphertext), data);
```

### Async ciphers with progress

```ts
import { deepStrictEqual } from 'node:assert';
import { ctr, gcm } from '@awasm/noble';

const msg = Uint8Array.from({ length: 8192 }, (_, i) => i & 0xff);
const key = new Uint8Array(32).fill(8);
const nonce16 = new Uint8Array(16).fill(9);
const nonce12 = new Uint8Array(12).fill(10);
const aad = new Uint8Array(33).fill(11);

const ctrSync = ctr(key, nonce16).encrypt(msg);
const ctrAsync = await ctr(key, nonce16).encrypt.async(msg, undefined, { asyncTick: 0 });
deepStrictEqual(ctrAsync, ctrSync);
deepStrictEqual(await ctr(key, nonce16).decrypt.async(ctrAsync, undefined, { asyncTick: 0 }), msg);

const gcmSync = gcm(key, nonce12, aad).encrypt(msg);
const gcmAsync = await gcm(key, nonce12, aad).encrypt.async(msg, undefined, { asyncTick: 0 });
deepStrictEqual(gcmAsync, gcmSync);
deepStrictEqual(await gcm(key, nonce12, aad).decrypt.async(gcmAsync, undefined, { asyncTick: 0 }), msg);
```

### Streaming ciphers

```ts
import { ctr } from '@awasm/noble';

const key = new Uint8Array(32).fill(5);
const nonce = new Uint8Array(16).fill(6);
const msg = new Uint8Array(1024).fill(7);

const enc = ctr(key, nonce).encrypt.create();
const c1 = enc.update(msg.subarray(0, 256));
const c2 = enc.update(msg.subarray(256, 1024));
const tail = enc.finish().data;

const dec = ctr(key, nonce).decrypt.create();
const p1 = dec.update(c1);
const p2 = dec.update(c2);
const end = dec.finish().data;
```

### Scrypt, Argon, PBKDF

```ts
import { scrypt } from '@awasm/noble';
const scr1 = scrypt('password', 'salt', { N: 2 ** 16, r: 8, p: 1, dkLen: 32 });
const scr2 = await scrypt.async('password', 'salt', { N: 2 ** 16, r: 8, p: 1, dkLen: 32 });

import { argon2d, argon2i, argon2id } from '@awasm/noble';
const arg1 = argon2id('password', 'saltsalt', { t: 2, m: 65536, p: 1, maxmem: 2 ** 32 - 1 });
const arg2 = argon2d('password', 'saltsalt', { t: 2, m: 65536, p: 1, maxmem: 2 ** 32 - 1 });
const arg3 = argon2i('password', 'saltsalt', { t: 2, m: 65536, p: 1, maxmem: 2 ** 32 - 1 });
const arg4 = await argon2i.async('password', 'saltsalt', {
  t: 2,
  m: 65536,
  p: 1,
  maxmem: 2 ** 32 - 1,
});

import { sha256 } from '@awasm/noble';
import { pbkdf2 } from '@awasm/noble/kdf.js';
const pbkey1 = pbkdf2(sha256)('password', 'salt', { c: 524288, dkLen: 32 });
const pbkey2 = pbkdf2(sha256).async('password', 'salt', { c: 524288, dkLen: 32 });
```

All KDFs support onProgress callback (even in sync version, which allows display progress bar in CLI scripts).
Also, we now support overriding `nextTick` function which used to return control, which means it could be replaced with
`sleep` or other implementation when desired (https://github.com/paulmillr/noble-hashes/issues/113)

```ts
import { scrypt } from '@awasm/noble';

const scr3 = await scrypt.async(Uint8Array.from([1, 2, 3]), Uint8Array.from([4, 5, 6]), {
  N: 2 ** 17,
  r: 8,
  p: 1,
  dkLen: 32,
  asyncTick: 10, // return control after this amount of ms
  onProgress(percentage) {
    console.log('progress', percentage);
  },
  nextTick: async () => {},
  maxmem: 2 ** 32 + 128 * 8 * 1, // N * r * p * 128 + (128*r*p)
});
```

### MACs

```ts
import { deepStrictEqual } from 'node:assert';
import { cmac } from '@awasm/noble';
import { poly1305 } from '@awasm/noble';
import { ghash } from '@awasm/noble';

const msg = new Uint8Array([1, 2, 3, 4]);
const key32 = new Uint8Array(32).fill(12);
const key16 = new Uint8Array(16).fill(13);

const p = poly1305(msg, key32);
const g = ghash(msg, key16);
const c = cmac(msg, key16); // note order: (message, key)
deepStrictEqual(poly1305.parallel([msg, msg], key32), [p, p]);
```

### WebCrypto Hashes + KDF/MAC

```ts
import { deepStrictEqual, throws } from 'node:assert';
import { sha256, hmac, hkdf, pbkdf2 } from '@awasm/noble/webcrypto.js';
import { sha256 as sha256wasm } from '@awasm/noble';

const msg = new Uint8Array([1, 2, 3]);
const key = new Uint8Array([7, 8, 9]);
const salt = new Uint8Array([4, 5, 6]);

if (await sha256.isSupported()) {
  deepStrictEqual(await sha256.async(msg), sha256wasm(msg));
  await hmac(sha256, key, msg);
  await hkdf(sha256, key, salt, msg, 32);
  await pbkdf2(sha256).async(key, salt, { c: 10, dkLen: 32 });
}
throws(() => pbkdf2(sha256)(key, salt, { c: 10, dkLen: 32 })); // sync is not supported
throws(() => sha256(msg)); // sync is not supported
```

### WebCrypto Ciphers

```ts
import { cbc, ctr, gcm } from '@awasm/noble/webcrypto.js';

const key = new Uint8Array(32).fill(1);
const iv16 = new Uint8Array(16).fill(2);
const iv12 = new Uint8Array(12).fill(3);
const aad = new Uint8Array(8).fill(4);
const plaintext = new Uint8Array(64).fill(5);

if (await cbc.isSupported()) await cbc(key, iv16).encrypt.async(plaintext);
if (await ctr.isSupported()) await ctr(key, iv16).encrypt.async(plaintext);
if (await gcm.isSupported()) await gcm(key, iv12, aad).encrypt.async(plaintext);
```

## Internals

To set up the repository:

```sh
git submodule update --init --recursive
npm install
npm run build
npm test
```

Contribution is easy!

### What is the build process?

1. `node scripts/build-targets.ts` script compiles `src/modules` into `src/targets`.
    - The script is using [awasm-compiler](https://github.com/paulmillr/awasm-compiler)
    - Some lines are included into generated files, check out the script for details
2. Typescript compiles `src` directory into root

### Why one package for hashes & ciphers?

- There should always be ONE worker pool, not two, for optimal performance.
  Using two packages would create two worker pools
- The important components are reused across both parts. This would increase
  bundle size and especially size of runtime backend

### Differences from noble

Async methods are named as `hash.async`, not `hashAsync`.
Some functionality is not available in awasm-noble. Use noble packages for:
keccakprg, rngAesCtr, rngChacha, kmac, cshake, turboshake, kt128, ff1.

- raw xor stream ciphers (chacha20/salsa20) use same object API as other ciphers: `cipher(key, nonce).encrypt/decrypt`.
  - in noble-ciphers they had separate xor-stream style API, while `ctr` had `encrypt/decrypt`, which was inconsistent
  - `@awasm/noble` keeps one shape for ctr/chacha/salsa to make switching modes simpler
- `ofb` is available in `@awasm/noble` (`@awasm/noble/*/aes.js`), and is not present in noble-ciphers exports.
- cmac also uses `(msg, key)` (instead of noble-ciphers `(key, msg)`) to unify with ghash/polyval/poly1305.
- ciphers do not currently expose hash-like `.parallel(...)` API.
  - instead, `wasm_threads` backend uses internal block batching/threading where mode allows it
  - sequential modes (like CBC and similar dependency-chained paths) cannot be parallelized the same way
  - many AEAD modes still get strong speedups from parallelized encryption path, even when authentication path is sequential (GCM was just one example; same idea applies to SIV / XSalsa20-Poly1305 / others)
- poly1305/ghash/polyval/cmac are separate MACs with hash-like API:
  - direct: `mac(message, key)` or `mac(message, { key })`
  - chunks: `mac.chunks([part1, part2], key)` or `mac.chunks([part1, part2], { key })`
  - parallel: `mac.parallel([msg1, msg2], key)` or `mac.parallel([msg1, msg2], { key })`
  - streaming: `mac.create(key).update(...).digest()` or `mac.create({ key }).update(...).digest()`
- `secretbox` is alias to `xsalsa20poly1305` (for libsodium / nacl-style API naming), with `seal/open` methods.

### Deno and Web Workers

While Node & Bun work properly, Deno requires manual stopping of web workers in wasm_threads
because it doesn't have `unref`:

```ts
import { sha256 } from '@awasm/noble/wasm_threads.js';

sha256(new Uint8Array([1, 2, 3]));
// will pause in Deno until this called:
import { WP } from '@awasm/noble/workers.js';
WP.stop();
```

## Speed

> `npm run bench`

Benchmarks measured on Apple M4.

Prefer `.chunks()` for multiple <1mb inputs. Prefer streaming api `.update()` for >=1mb inputs.

Online benchmark (BLAKE3 checksum calculator) is available on [the demo website hosted on Vercel](https://b3sum.vercel.app).

### wasm_threads

```
# hashes, input: 32x1mb, +threads
sha256 x 1,600 mb/sec
sha512 x 6,272 mb/sec
sha3_256 x 6,976 mb/sec
sha3_512 x 4,224 mb/sec
blake2b x 9,065 mb/sec
blake2s x 9,610 mb/sec
blake3 48x1mb x 11,058 mb/sec
blake3 1x100mb x 6,564 mb/sec
ripemd160 x 6,588 mb/sec
md5 x 9,078 mb/sec
sha1 x 11,413 mb/sec

# ciphers, input: 1gb +threads
chacha20poly1305 x 2,318 mb/sec
chacha20 x 6,530 mb/sec
aes-gcm-256 x 1,015 mb/sec
aes-gcm-siv-256 x 927 mb/sec
aes-ecb-256 x 2,185 mb/sec
aes-cbc-256 x 268 mb/sec
aes-ctr-256 x 2,105 mb/sec
```

### wasm (no threads)

```
# hashes, input: 1mb
sha256 x 553 mb/sec
sha512 x 834 mb/sec
sha3_256 x 899 mb/sec
sha3_512 x 502 mb/sec
blake2b x 1,342 mb/sec
blake2s x 812 mb/sec
blake3 x 1,940 mb/sec
ripemd160 x 503 mb/sec
md5 x 857 mb/sec
sha1 x 1,294 mb/sec
# ciphers, input: 10mb
chacha20poly1305 x 1,196 mb/sec
aes-gcm-256 x 234 mb/sec
aes-gcm-siv-256 x 236 mb/sec
chacha20 x 1,672 mb/sec
aes-ecb-256 x 277 mb/sec
aes-cbc-256 x 262 mb/sec
aes-ctr-256 x 272 mb/sec

# KDF
pbkdf2(sha256, c: 2 ** 18) x 2 ops/sec @ 351ms/op
pbkdf2(sha512, c: 2 ** 18) x 1 ops/sec @ 503ms/op
scrypt(n: 2 ** 19, r: 8, p: 1) x 1 ops/sec @ 597ms/op
argon2id(t: 1, m: 128MB, p: 1) x 14 ops/sec @ 69ms/op
```

## License

The MIT License (MIT)

Copyright (c) 2026 Paul Miller [(https://paulmillr.com)](https://paulmillr.com)

See LICENSE file.
