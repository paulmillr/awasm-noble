import * as fs from 'node:fs';
import { createRequire } from 'node:module';
import * as path from 'node:path';

type Pkg = '@noble/hashes' | '@noble/ciphers';
type Entry = { key: string; name: string };
type Diff = { pkg: Pkg; name: string; missing: string[]; moduleMissing: boolean };

const require = createRequire(import.meta.url);
const anchors: Record<Pkg, string> = {
  '@noble/hashes': 'sha2',
  '@noble/ciphers': 'aes',
};

const readPkgExports = (pkg: Pkg): Entry[] => {
  // Noble packages don't export package.json, so resolve a known public module and climb to package root.
  const anchorPath = require.resolve(`${pkg}/${anchors[pkg]}.js`);
  const pkgPath = path.join(path.dirname(anchorPath), 'package.json');
  const raw = fs.readFileSync(pkgPath, 'utf8');
  const json = JSON.parse(raw) as { exports?: Record<string, unknown> };
  const res: Entry[] = [];
  for (const [key] of Object.entries(json.exports || {})) {
    if (!key.startsWith('./') || !key.endsWith('.js')) continue;
    if (key === './index.js') continue;
    const name = key.slice(2, -3);
    res.push({ key, name });
  }
  res.sort((a, b) => (a.key < b.key ? -1 : 1));
  return res;
};

const modKeys = (mod: Record<string, unknown>) => Object.keys(mod).filter((k) => k !== 'default').sort();
const nobleUrl = (pkg: Pkg, name: string) => `${pkg}/${name}.js`;
const awasmUrl = (name: string) => `@awasm/noble/${name}.js`;

const diffOne = async (pkg: Pkg, name: string): Promise<Diff> => {
  const noble = (await import(nobleUrl(pkg, name))) as Record<string, unknown>;
  const nobleKeys = modKeys(noble);
  try {
    const awasm = (await import(awasmUrl(name))) as Record<string, unknown>;
    const awasmSet = new Set(modKeys(awasm));
    const missing = nobleKeys.filter((k) => !awasmSet.has(k));
    return { pkg, name, missing, moduleMissing: false };
  } catch {
    // Build script may not generate every noble export module yet, report full missing set for visibility.
    return { pkg, name, missing: nobleKeys, moduleMissing: true };
  }
};

const printPkg = (pkg: Pkg, diffs: Diff[]) => {
  const rel = diffs.filter((d) => d.pkg === pkg);
  let missCount = 0;
  let modCount = 0;
  console.log(`\n[${pkg}]`);
  for (const d of rel) {
    if (!d.missing.length) continue;
    missCount += d.missing.length;
    if (d.moduleMissing) modCount++;
    const status = d.moduleMissing ? 'module missing' : 'missing exports';
    console.log(`- ${d.name}: ${status} (${d.missing.length})`);
    for (const k of d.missing) console.log(`  - ${k}`);
  }
  if (!missCount) console.log('- no missing exports');
  else console.log(`- summary: ${missCount} missing exports across ${modCount} missing modules`);
};

const main = async () => {
  const hashes = readPkgExports('@noble/hashes');
  const ciphers = readPkgExports('@noble/ciphers');
  const work = [...hashes.map((i) => ['@noble/hashes', i.name] as const), ...ciphers.map((i) => ['@noble/ciphers', i.name] as const)];
  const diffs: Diff[] = [];
  for (const [pkg, name] of work) diffs.push(await diffOne(pkg, name));
  console.log('Comparing noble exports vs awasm package exports (@awasm/noble/<module>.js)');
  console.log(`awasm package root: ${path.resolve(path.dirname(new URL(import.meta.url).pathname), '..')}`);
  printPkg('@noble/hashes', diffs);
  printPkg('@noble/ciphers', diffs);
};

main().catch((err) => {
  console.error(err);
  process.exit(1);
});
