import { describe, should } from '@paulmillr/jsbt/test.js';
import { sharePlatforms, startTests } from '../platforms.ts';

sharePlatforms('hashes');
const { PLATFORMS } = await import('./noble-hashes/test/platform.ts');
const { getHashes } = await import('./noble-hashes/test/hashes.test.ts');
const { test } = await import('./noble-hashes/test/slow-dos.test.ts');
for (const k in PLATFORMS) test(k, PLATFORMS[k], getHashes(PLATFORMS[k]), { describe, should });

// takes ~20min
startTests(import.meta.url);
