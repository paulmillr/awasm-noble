/**
 * Creates files in `src/targets`.
 * @module
 */
import { toJs, toWasm } from '@awasm/compiler/codegen.js';
import * as js from '@awasm/compiler/js.js';
import type { Module } from '@awasm/compiler/module.js';
import { genRuntimeTypeMod, TYPE_MOD_OPTS } from '@awasm/compiler/types.js';
import * as workers from '@awasm/compiler/workers.js';
import * as fs from 'node:fs';
import os from 'node:os';
import * as path from 'node:path';
import { isMainThread, parentPort, Worker, workerData } from 'node:worker_threads';
import { Definitions as CipherDefinitions } from '../src/ciphers.ts';
import { GenericDefinitions, Definitions as HashDefinitions } from '../src/hashes.ts';
import { GENERATORS, MODULES } from '../src/modules/index.ts';

type BuildJob = { name: string; cOpts: any; versions: string[] };
const DEF_COMPILER_OPTS = {
  reuseModule: true,
  wasmAsHex: false,
};
const LICENSE = fs.readFileSync(new URL('../LICENSE', import.meta.url), 'utf8').trimEnd();
const LICENSE_COMMENT = `/*!\n${LICENSE}\n*/\n`;
const TARGET_TYPE_IMPORTS = [
  `import type { OutputOpts, HashStream, HashDef, HashInstance } from '../../hashes-abstract.ts';`,
  `import type { TArg, TRet, Asyncify, KDFInput } from '../../utils.ts';`,
  `import type { BlakeOpts, Blake2Opts, Blake3Opts } from '../../hashes.ts';`,
  `import type { Cipher, CipherDef, CipherFactory } from '../../ciphers-abstract.ts';`,
  `import type { KDF, ScryptOpts, ArgonOpts } from '../../kdf.ts';`,
].join('\n');
const TARGET_TYPE_EXPORTS = [
  `export type { OutputOpts, HashStream, HashDef, HashInstance };`,
  `export type { TArg, TRet, Asyncify, KDFInput };`,
  `export type { BlakeOpts, Blake2Opts, Blake3Opts };`,
  `export type { Cipher, CipherDef, CipherFactory };`,
  `export type { KDF, ScryptOpts, ArgonOpts };`,
].join('\n');
// Should be avail in worker
const MODULES_REGISTRY: Record<string, Module> = {
  typeMod: genRuntimeTypeMod(),
};
for (const [k, v] of Object.entries(MODULES))
  MODULES_REGISTRY[k] = GENERATORS[v.fn](v.type, v.opts);

// Worker
if (!isMainThread) {
  const { perWorker } = workerData as { perWorker: BuildJob[] };
  parentPort!.postMessage(
    perWorker.map(({ name, cOpts, versions }) => {
      const res: Record<string, any> = {};
      const mod = MODULES_REGISTRY[name];
      const opts = { ...DEF_COMPILER_OPTS, ...cOpts };
      if (versions.includes('wasm')) res.wasm = toWasm(mod.clone(), { ...opts, useSIMD: true });
      if (versions.includes('wasm_threads'))
        res.wasm_threads = toWasm(mod.clone(), { ...opts, useThreads: true });
      if (versions.includes('js')) res.js = toJs(mod.clone(), { ...opts });
      // if (versions.includes('js_threads'))
      //   res.js_threads = toJs(mod.clone(), { ...opts, useThreads: true });
      return [name, res];
    })
  );
  process.exit(0);
}
// parallel build support
async function parallelMap(items: BuildJob[], threads = os.cpus().length): Promise<BuildJob[]> {
  const chunkSize = Math.ceil(items.length / threads);
  const jobs: Promise<BuildJob[]>[] = [];
  for (let i = 0; i < items.length; i += chunkSize) {
    const perWorker = items.slice(i, i + chunkSize);
    jobs.push(
      new Promise((resolve, reject) => {
        const w = new Worker(new URL(import.meta.url), { workerData: { perWorker } });
        w.once('message', resolve);
        w.once('error', reject);
        w.once('exit', (code) => {
          if (code !== 0) reject(new Error(`worker exit ${code}`));
        });
      })
    );
  }
  return (await Promise.all(jobs)).flat();
}

function write(file: string, data: string) {
  fs.mkdirSync(path.dirname(file), { recursive: true });
  console.log(`Writing to ${file} (${data.length})`);
  const license =
    file.startsWith('./src/targets/') && file.endsWith('/index.ts') ? LICENSE_COMMENT : '';
  fs.writeFileSync(
    file,
    `${license}// WARNING: This file is auto-generated. Any changes will be lost.
${data}`
  );
}

const DOCS: Record<string, string> = {
  aeskw: `AES-KW (key-wrap). Injects static IV into plaintext, adds counter, encrypts 6 times.
Reduces block size from 16 to 8 bytes.
For padded version, use aeskwp.
[RFC 3394](https://www.rfc-editor.org/rfc/rfc3394/),
[NIST.SP.800-38F](https://nvlpubs.nist.gov/nistpubs/SpecialPublications/NIST.SP.800-38F.pdf).`,
  aeskwp: `AES-KW, but with padding and allows random keys.
Second u32 of IV is used as counter for length.
[RFC 5649](https://www.rfc-editor.org/rfc/rfc5649)`,
  aessiv: `**SIV**: Synthetic Initialization Vector (SIV) Authenticated Encryption
Nonce is derived from the plaintext and AAD using the S2V function.
See [RFC 5297](https://datatracker.ietf.org/doc/html/rfc5297.html).`,
  argon2d: ' argon2d GPU-resistant version.',
  argon2i: ' argon2i side-channel-resistant version.',
  argon2id: ' argon2id, combining i+d, the most popular version from RFC 9106',
  blake224: ' blake1-224 hash function',
  blake256: ' blake1-256 hash function',
  blake2b: `Blake2b hash function. 64-bit. 1.5x slower than blake2s in JS.
@param msg - message that would be hashed
@param opts - dkLen output length, key for MAC mode, salt, personalization`,
  blake2s: `Blake2s hash function. Focuses on 8-bit to 32-bit platforms. 1.5x faster than blake2b in JS.
@param msg - message that would be hashed
@param opts - dkLen output length, key for MAC mode, salt, personalization`,
  blake3: `BLAKE3 hash function. Can be used as MAC and KDF.
@param msg - message that would be hashed
@param opts - \`dkLen\` for output length, \`key\` for MAC mode, \`context\` for KDF mode
@example
const data = new Uint8Array(32);
const hash = blake3(data);
const mac = blake3(data, { key: new Uint8Array(32) });
const kdf = blake3(data, { context: 'application name' });`,
  blake384: ' blake1-384 hash function',
  blake512: ' blake1-512 hash function',
  cbc: `**CBC** (Cipher Block Chaining): Each plaintext block is XORed with the
previous block of ciphertext before encryption.
Hard to use: requires proper padding and an IV. Unauthenticated: needs MAC.`,
  cfb: `CFB: Cipher Feedback Mode. The input for the block cipher is the previous cipher output.
Unauthenticated: needs MAC.`,
  chacha12: ' Reduced 12-round chacha, described in original paper.',
  chacha20: `ChaCha stream cipher. Conforms to RFC 8439 (IETF, TLS). 12-byte nonce, 4-byte counter.
With smaller nonce, it's not safe to make it random (CSPRNG), due to collision chance.`,
  chacha20orig: ' Original, non-RFC chacha20 from DJB. 8-byte nonce, 8-byte counter.',
  chacha20poly1305: `ChaCha20-Poly1305 from RFC 8439.

Unsafe to use random nonces under the same key, due to collision chance.
Prefer XChaCha instead.`,
  chacha8: ' Reduced 8-round chacha, described in original paper.',
  cmac: `AES-CMAC (Cipher-based Message Authentication Code).
Specs: [RFC 4493](https://www.rfc-editor.org/rfc/rfc4493.html).`,
  ctr: `**CTR** (Counter Mode): Turns a block cipher into a stream cipher using a counter and IV (nonce).
Efficient and parallelizable. Requires a unique nonce per encryption. Unauthenticated: needs MAC.`,
  ecb: `**ECB** (Electronic Codebook): Deterministic encryption; identical plaintext blocks yield
identical ciphertexts. Not secure due to pattern leakage.
See [AES Penguin](https://words.filippo.io/the-ecb-penguin/).`,
  gcm: `**GCM** (Galois/Counter Mode): Combines CTR mode with polynomial MAC. Efficient and widely used.
Not perfect:
a) conservative key wear-out is \`2**32\` (4B) msgs.
b) key wear-out under random nonces is even smaller: \`2**23\` (8M) messages for \`2**-50\` chance.
c) MAC can be forged: see Poly1305 documentation.`,
  gcmsiv: `**SIV** (Synthetic IV): GCM with nonce-misuse resistance.
Repeating nonces reveal only the fact plaintexts are identical.
Also suffers from GCM issues: key wear-out limits & MAC forging.
See [RFC 8452](https://www.rfc-editor.org/rfc/rfc8452).`,
  ghash: ' GHash MAC for AES-GCM.',
  keccak_224: ' keccak-224 hash function.',
  keccak_256: ' keccak-256 hash function. Different from SHA3-256.',
  keccak_384: ' keccak-384 hash function.',
  keccak_512: ' keccak-512 hash function.',
  md5: `MD5 (RFC 1321) legacy hash function. It was cryptographically broken.
MD5 architecture is similar to SHA1, with some differences:
- Reduced output length: 16 bytes (128 bit) instead of 20
- 64 rounds, instead of 80
- Little-endian: could be faster, but will require more code
- Non-linear index selection: huge speed-up for unroll
- Per round constants: more memory accesses, additional speed-up for unroll`,
  ofb: ' OFB mode for AES block cipher.',
  poly1305: ' Poly1305 MAC from RFC 8439.',
  polyval: ' Polyval MAC for AES-SIV.',
  ripemd160: `RIPEMD-160 - a legacy hash function from 1990s.
* https://homes.esat.kuleuven.be/~bosselae/ripemd160.html
* https://homes.esat.kuleuven.be/~bosselae/ripemd160/pdf/AB-9601/AB-9601.pdf`,
  salsa20: `Salsa20 from original paper. 12-byte nonce.
With smaller nonce, it's not safe to make it random (CSPRNG), due to collision chance.`,
  scrypt: ' Scrypt KDF',
  secretbox: `Alias to xsalsa20poly1305, for compatibility with libsodium / nacl.
Check out https://github.com/serenity-kit/noble-sodium for crypto_box.`,
  sha1: ' SHA1 (RFC 3174) legacy hash function. It was cryptographically broken.',
  sha224: ' SHA2-224 hash function from RFC 4634',
  sha256: `SHA2-256 hash function from RFC 4634. In JS it's the fastest: even faster than Blake3. Some info:

- Trying 2^128 hashes would get 50% chance of collision, using birthday attack.
- BTC network is doing 2^70 hashes/sec (2^95 hashes/year) as per 2025.
- Each sha256 hash is executing 2^18 bit operations.
- Good 2024 ASICs can do 200Th/sec with 3500 watts of power, corresponding to 2^36 hashes/joule.`,
  sha384: ' SHA2-384 hash function from RFC 4634.',
  sha3_224: ' SHA3-224 hash function.',
  sha3_256: ' SHA3-256 hash function. Different from keccak-256.',
  sha3_384: ' SHA3-384 hash function.',
  sha3_512: ' SHA3-512 hash function.',
  sha512: ' SHA2-512 hash function from RFC 4634.',
  sha512_224: `SHA2-512/224 "truncated" hash function, with improved resistance to length extension attacks.
See the paper on [truncated SHA512](https://eprint.iacr.org/2010/548.pdf).`,
  sha512_256: `SHA2-512/256 "truncated" hash function, with improved resistance to length extension attacks.
See the paper on [truncated SHA512](https://eprint.iacr.org/2010/548.pdf).`,
  shake128: ' SHAKE128 XOF with 128-bit security.',
  shake128_32: ' SHAKE128 XOF with 256-bit output (NIST version).',
  shake256: ' SHAKE256 XOF with 256-bit security.',
  shake256_64: ' SHAKE256 XOF with 512-bit output (NIST version).',
  xchacha20: `XChaCha eXtended-nonce ChaCha. With 24-byte nonce, it's safe to make it random (CSPRNG).
See [IRTF draft](https://datatracker.ietf.org/doc/html/draft-irtf-cfrg-xchacha).`,
  xchacha20poly1305: `XChaCha20-Poly1305 extended-nonce chacha.

Can be safely used with random nonces (CSPRNG).
See [IRTF draft](https://datatracker.ietf.org/doc/html/draft-irtf-cfrg-xchacha).`,
  xsalsa20:
    " xsalsa20 eXtended-nonce salsa. With 24-byte nonce, it's safe to make it random (CSPRNG).",
  xsalsa20poly1305: `xsalsa20-poly1305 eXtended-nonce (24 bytes) salsa.
With 24-byte nonce, it's safe to make it random (CSPRNG).
Also known as \`secretbox\` from libsodium / nacl.`,
};
const cleanDocLine = (line: string) =>
  line
    .replace(/\[([^\]]+)\]\([^)]+\)/g, '$1')
    .replace(/https?:\/\/\S+/g, '')
    .replace(/\*\*/g, '')
    .replace(/`/g, "'");
const splitDoc = (doc: string) => {
  const body: string[] = [];
  const tags: string[] = [];
  const example: string[] = [];
  let inExample = false;
  for (const raw of doc.split('\n')) {
    const line = raw.trim();
    if (!line) continue;
    if (inExample) {
      example.push(line);
      continue;
    }
    if (line.startsWith('@example')) {
      inExample = true;
      continue;
    }
    if (line.startsWith('@')) {
      tags.push(cleanDocLine(line));
      continue;
    }
    body.push(cleanDocLine(line));
  }
  return { body, tags, example };
};
const DOC_TAGS = {
  hash: [
    '@param msg - message to hash.',
    '@param opts - optional hash configuration such as output length or keyed mode parameters.',
    '@returns Hash output bytes.',
  ],
  cipher: [
    '@param key - secret key bytes.',
    '@param args - algorithm-specific extra arguments such as nonce or AAD.',
    '@returns Configured cipher instance.',
  ],
  kdf: [
    '@param password - password or key material bytes.',
    '@param salt - salt bytes.',
    '@param opts - algorithm configuration options.',
    '@returns Derived output bytes.',
  ],
} as const;
const DOC_TAGS_BY_NAME: Record<string, string[]> = {
  secretbox: [
    '@param key - secret key bytes.',
    '@param nonce - nonce bytes.',
    '@returns Configured secretbox helper.',
  ],
};
const DOC_EXAMPLES: Record<string, string[]> = {
  poly1305: [
    "import { poly1305 } from '@awasm/noble';",
    'poly1305(new Uint8Array([1, 2, 3]), { key: new Uint8Array(32) });',
  ],
  cmac: [
    "import { cmac } from '@awasm/noble';",
    'cmac(new Uint8Array([1, 2, 3]), { key: new Uint8Array(16) });',
  ],
  ghash: [
    "import { ghash } from '@awasm/noble';",
    'ghash(new Uint8Array([1, 2, 3]), { key: new Uint8Array(16) });',
  ],
  polyval: [
    "import { polyval } from '@awasm/noble';",
    'polyval(new Uint8Array([1, 2, 3]), { key: new Uint8Array(16) });',
  ],
  scrypt: [
    "import { scrypt } from '@awasm/noble';",
    "scrypt('password', 'salt', { N: 16, r: 1, p: 1, dkLen: 32 });",
  ],
  argon2d: [
    "import { argon2d } from '@awasm/noble';",
    "argon2d('password', 'saltsalt', { t: 1, m: 8, p: 1, dkLen: 32 });",
  ],
  argon2i: [
    "import { argon2i } from '@awasm/noble';",
    "argon2i('password', 'saltsalt', { t: 1, m: 8, p: 1, dkLen: 32 });",
  ],
  argon2id: [
    "import { argon2id } from '@awasm/noble';",
    "argon2id('password', 'saltsalt', { t: 1, m: 8, p: 1, dkLen: 32 });",
  ],
  ecb: ["import { ecb } from '@awasm/noble';", 'ecb(new Uint8Array(16));'],
  cbc: ["import { cbc } from '@awasm/noble';", 'cbc(new Uint8Array(16), new Uint8Array(16));'],
  cfb: ["import { cfb } from '@awasm/noble';", 'cfb(new Uint8Array(16), new Uint8Array(16));'],
  ofb: ["import { ofb } from '@awasm/noble';", 'ofb(new Uint8Array(16), new Uint8Array(16));'],
  ctr: ["import { ctr } from '@awasm/noble';", 'ctr(new Uint8Array(16), new Uint8Array(16));'],
  gcm: ["import { gcm } from '@awasm/noble';", 'gcm(new Uint8Array(16), new Uint8Array(12));'],
  gcmsiv: [
    "import { gcmsiv } from '@awasm/noble';",
    'gcmsiv(new Uint8Array(16), new Uint8Array(12));',
  ],
  aessiv: ["import { aessiv } from '@awasm/noble';", 'aessiv(new Uint8Array(32));'],
  aeskw: ["import { aeskw } from '@awasm/noble';", 'aeskw(new Uint8Array(16));'],
  aeskwp: ["import { aeskwp } from '@awasm/noble';", 'aeskwp(new Uint8Array(16));'],
  salsa20: [
    "import { salsa20 } from '@awasm/noble';",
    'salsa20(new Uint8Array(32), new Uint8Array(8));',
  ],
  xsalsa20: [
    "import { xsalsa20 } from '@awasm/noble';",
    'xsalsa20(new Uint8Array(32), new Uint8Array(24));',
  ],
  chacha8: [
    "import { chacha8 } from '@awasm/noble';",
    'chacha8(new Uint8Array(32), new Uint8Array(12));',
  ],
  chacha12: [
    "import { chacha12 } from '@awasm/noble';",
    'chacha12(new Uint8Array(32), new Uint8Array(12));',
  ],
  chacha20orig: [
    "import { chacha20orig } from '@awasm/noble';",
    'chacha20orig(new Uint8Array(32), new Uint8Array(8));',
  ],
  chacha20: [
    "import { chacha20 } from '@awasm/noble';",
    'chacha20(new Uint8Array(32), new Uint8Array(12));',
  ],
  xchacha20: [
    "import { xchacha20 } from '@awasm/noble';",
    'xchacha20(new Uint8Array(32), new Uint8Array(24));',
  ],
  chacha20poly1305: [
    "import { chacha20poly1305 } from '@awasm/noble';",
    'chacha20poly1305(new Uint8Array(32), new Uint8Array(12));',
  ],
  xchacha20poly1305: [
    "import { xchacha20poly1305 } from '@awasm/noble';",
    'xchacha20poly1305(new Uint8Array(32), new Uint8Array(24));',
  ],
  xsalsa20poly1305: [
    "import { xsalsa20poly1305 } from '@awasm/noble';",
    'xsalsa20poly1305(new Uint8Array(32), new Uint8Array(24));',
  ],
  secretbox: [
    "import { secretbox } from '@awasm/noble';",
    'secretbox(new Uint8Array(32), new Uint8Array(24));',
  ],
};
const example = (name: string, kind: keyof typeof DOC_TAGS) => {
  const byName = DOC_EXAMPLES[name];
  if (byName) return byName;
  if (kind === 'hash') {
    return [
      `import { ${name} } from '@awasm/noble';`,
      `${name}(new Uint8Array([1, 2, 3]));`,
    ];
  }
  throw new Error(`missing @example for public export: ${name}`);
};
const mkDoc = (name: string, doc: string) => {
  const parsed = splitDoc(doc);
  const kind = GenericDefinitions[name]
    ? 'kdf'
    : CipherDefinitions[name] || name === 'secretbox'
      ? 'cipher'
      : 'hash';
  const tags = parsed.tags.length ? parsed.tags : DOC_TAGS_BY_NAME[name] || DOC_TAGS[kind];
  const ex = parsed.example.length ? parsed.example : example(name, kind);
  return [
    '/**',
    ...parsed.body.map((line) => ` * ${line}`),
    ' *',
    ...tags.map((line) => ` * ${line}`),
    ' * @example',
    ' * ```ts',
    ...ex.map((line) => ` * ${line}`),
    ' * ```',
    ' */',
  ].join('\n');
};
const withDoc = (name: string, code: string) => {
  const doc = DOCS[name];
  if (!doc) throw new Error(`missing JSDoc for public export: ${name}`);
  return `${mkDoc(name, doc)}\n${code}`;
};

type Mod = ReturnType<typeof js.wrapModule> | undefined;
const targetDir = (name: string) => `./src/targets/${name}`;

function buildPool() {
  for (const [type, mod] of Object.entries(workers.buildPool())) {
    const dir = type === 'wasm' ? 'wasm_threads' : type;
    write(`${targetDir(dir)}/worker_pool.js`, mod.modFn);
    if (mod.modFnType) write(`${targetDir(dir)}/worker_pool.d.ts`, mod.modFnType);
  }
}

function buildTypeMod(mods: Record<string, any>) {
  for (const [type, mod] of Object.entries(mods)) {
    write(`${targetDir(type)}/type_mod.js`, mod.modFn);
    if (mod.modFnType) write(`${targetDir(type)}/type_mod.d.ts`, mod.modFnType);
  }
}

async function main() {
  // node build-targets.ts sha256 keccak24 sha512
  const only = process.argv.slice(2);
  if (only.length) console.log('FILTER', only);
  else console.log('ALL MODULES');

  const toBuild: BuildJob[] = [{ name: 'typeMod', cOpts: TYPE_MOD_OPTS, versions: ['wasm', 'js'] }];
  for (const k in MODULES) {
    if (only.length && !only.includes(k)) continue;
    const v = MODULES[k];
    toBuild.push({ name: k, cOpts: v.compilerOpts, versions: ['wasm', 'js', 'wasm_threads'] });
  }
  const BMODULES = Object.fromEntries(await parallelMap(toBuild));
  if (only.length) {
    for (const o of only) {
      if (!BMODULES[o])
        throw new Error(`unknown module: ${o}. expected: ${Object.keys(BMODULES).join(', ')}`);
    }
  }
  function iter(cb: (name: string, ver: string, mod: Mod) => void) {
    for (const [name, versions] of Object.entries(BMODULES)) {
      for (const [ver, mod] of Object.entries(versions)) {
        cb(name, ver, mod);
      }
    }
  }
  /*
  Structure:
  - src/targets/types.ts all per mod types
  - src/targets/<target>/modName.js - actual code
    .d.ts - types

  */
  // Write actual modules
  iter((name, ver, mod) => {
    if (!mod || name === 'typeMod') return;
    write(`${targetDir(ver)}/${name}.js`, mod.modFn);
    write(`${targetDir(ver)}/${name}.d.ts`, mod.modFnType);
    //write(`${targetDir(ver)}/${name}_top.js`, mod.modExport);
    //write(`${targetDir(ver)}/${name}_top.d.ts`, mod.modExportType);
  });

  // Collect versions
  const versions = new Set();
  iter((name, ver, mod) => versions.add(ver));
  versions.add('runtime');
  versions.add('stub');
  // Write instances
  if (!only.length) {
    for (const ver of versions) {
      const imports = new Set(); // multiple instances may use same module
      const instances: string[] = [];
      const instanceAdd = (name: string, s: string) => {
        instances.push(withDoc(name, s));
      };
      const importAdd = (name: string, s: string) => {
        imports.add(s);
      };
      for (const name in HashDefinitions) {
        const { mod } = HashDefinitions[name];
        if (!BMODULES[mod]) throw new Error(`unknown module ${mod} in ${name}`);
        if (ver === 'stub') {
          importAdd(name, `import { mkHashStub } from '../../hashes-abstract.ts';`);
        } else importAdd(name, `import { mkHash } from '../../hashes-abstract.ts';`);
        //if (!MODULES[mod][ver]) continue; // no version for this module!
        importAdd(name, `import {${name} as def_${name}} from '../../hashes.ts';`);
        if (ver.includes('threads')) {
          importAdd(name, `import {${'WP'} as pool} from '../../workers.ts';`);
        }
        if (ver === 'runtime') {
          importAdd(name, `import { ${mod} as mod_${name} } from './runtime.ts';`);
        } else if (ver === 'stub') {
          // no module for stub
        } else {
          importAdd(name, `import mod_${name} from './${mod}.js';`);
        }
        let instance = `mkHash(mod_${name}, def_${name}, '${ver}')`;
        if (ver.includes('threads')) {
          instance = `mkHash(/* @__PURE__ */ mod_${name}.bind(null, {}, pool), def_${name}, '${ver}')`;
        } else if (ver === 'stub') {
          instance = `mkHashStub(def_${name})`;
        }
        instanceAdd(name, `export const ${name} = /* @__PURE__ */ ${instance};`);
      }
      for (const name in CipherDefinitions) {
        const { mod } = CipherDefinitions[name];
        if (!BMODULES[mod]) throw new Error(`unknown module ${mod} in ${name}`);
        if (ver === 'stub') {
          importAdd(name, `import { mkCipherStub } from '../../ciphers-abstract.ts';`);
        } else importAdd(name, `import { mkCipher } from '../../ciphers-abstract.ts';`);
        //if (!MODULES[mod][ver]) continue; // no version for this module!
        importAdd(name, `import {${name} as def_${name}} from '../../ciphers.ts';`);
        if (ver.includes('threads')) {
          importAdd(name, `import {${'WP'} as pool} from '../../workers.ts';`);
        }
        if (ver === 'runtime') {
          importAdd(name, `import { ${mod} as mod_${name} } from './runtime.ts';`);
        } else if (ver === 'stub') {
          // no module for stub
        } else {
          importAdd(name, `import mod_${name} from './${mod}.js';`);
        }
        let instance = `mkCipher(mod_${name}, def_${name}, '${ver}')`;
        if (ver.includes('threads')) {
          instance = `mkCipher(/* @__PURE__ */ mod_${name}.bind(null, {}, pool), def_${name}, '${ver}')`;
        } else if (ver === 'stub') {
          instance = `mkCipherStub(def_${name})`;
        }
        instanceAdd(name, `export const ${name} = /* @__PURE__ */ ${instance};`);
      }
      for (const name in GenericDefinitions) {
        const { mod, deps, stub } = GenericDefinitions[name];
        if (!BMODULES[mod]) throw new Error(`unknown module ${mod} in ${name}`);
        //if (!MODULES[mod][ver]) continue; // no version for this module!
        importAdd(name, `import {${name} as def_${name}} from '../../hashes.ts';`);
        if (ver === 'stub') importAdd(name, `import {${stub.fn}} from '../../${stub.path}';`);
        if (ver.includes('threads'))
          importAdd(name, `import {${'WP'} as pool} from '../../workers.ts';`);
        if (ver === 'runtime') {
          importAdd(name, `import { ${mod} as mod_${name} } from './runtime.ts';`);
        } else if (ver === 'stub') {
          // no module for stub
        } else {
          importAdd(name, `import mod_${name} from './${mod}.js';`);
        }
        const depsObj = `{${deps.join(', ')}}`;
        let instance = `def_${name}(mod_${name}, ${depsObj}, '${ver}')`;
        if (ver.includes('threads'))
          instance = `def_${name}(/* @__PURE__ */ mod_${name}.bind(null, {}, pool), ${depsObj}, '${ver}')`;
        else if (ver === 'stub') instance = `${stub.fn}(def_${name});`;
        instanceAdd(name, `export const ${name} = /* @__PURE__ */ ${instance};`);
      }
      // noble-sodium compatibility helper; keep it in platform modules and re-export from salsa module.
      instances.push(
        withDoc(
          'secretbox',
          `export const secretbox = (key: TArg<Uint8Array>, nonce: TArg<Uint8Array>) => {
  const xs = xsalsa20poly1305(key, nonce);
  return { seal: xs.encrypt, open: xs.decrypt };
};`
        )
      );
      write(
        `${targetDir(ver)}/index.ts`,
        `${TARGET_TYPE_IMPORTS}
${Array.from(imports).join('\n')}
${TARGET_TYPE_EXPORTS}
${Array.from(instances).join('\n')}`
      );
    }
  }
  // Write runtime
  if (!only.length) {
    const imports = new Set();
    const runtimeFns = new Set<string>();
    const runtimeSpecs = new Set<string>();
    imports.add(`import { toRuntime } from '@awasm/compiler/runtime.js';`);
    imports.add(`import typeMod from '../js/type_mod.js';`);
    const instances: string[] = [];
    for (const name in MODULES) {
      const { fn, type } = MODULES[name];
      runtimeFns.add(fn);
      runtimeSpecs.add(`${name} as spec_${name}`);
      instances.push(
        `export const ${name} = /* @__PURE__ */ toRuntime(typeMod, /* @__PURE__ */ ${fn}('${type}', /* @__PURE__ */ (() => spec_${name}.opts)()), /* @__PURE__ */ (() => spec_${name}.compilerOpts)());`
      );
    }
    imports.add(`import { ${Array.from(runtimeFns).join(', ')} } from '../../modules/index.ts';`);
    imports.add(`import { ${Array.from(runtimeSpecs).join(', ')} } from '../../modules/index.ts';`);
    write(
      `${targetDir('runtime')}/runtime.ts`,
      `${Array.from(imports).join('\n')}
${Array.from(instances).join('\n')}`
    );
  }
  // Write per module types (mostly for hash definitions)
  if (!only.length) {
    // NOTE: we cannot rewrite all types if only one module changed, since we don't know types for others
    const types: Record<string, Set<string>> = {};
    iter((name, ver, mod) => {
      if (!mod) return;
      if (!types[name]) types[name] = new Set();
      types[name].add(mod.typeRaw);
    });
    const modTypes = Object.entries(types)
      .map(([k, v]) => {
        const arr = Array.from(v);
        const value = arr.length === 1 ? arr[0] : `(${arr.map((i) => `(${i})`).join(' | ')})`;
        return `export type ${k.toUpperCase()} = ${value};`;
      })
      .join('\n');
    write(
      './src/targets/types.ts',
      `
${modTypes}

export type ModMap = {
${Object.keys(types)
  .map((i) => `${i}: ${i.toUpperCase()};`)
  .join('\n')}
};
`
    );
    buildPool();
    buildTypeMod(BMODULES.typeMod);
  }
}

main();
