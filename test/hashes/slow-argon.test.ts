import { describe, should } from '@paulmillr/jsbt/test.js';
import { sharePlatforms, startTests } from '../platforms.ts';

sharePlatforms('hashes');
const { PLATFORMS } = await import('./noble-hashes/test/platform.ts');
const { testArgon } = await import('./noble-hashes/test/slow-kdf.test.ts');
for (const k in PLATFORMS) testArgon(k, PLATFORMS[k], { describe, should });

startTests(import.meta.url);
