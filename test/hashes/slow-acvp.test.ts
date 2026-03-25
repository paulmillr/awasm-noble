import { describe, should } from '@paulmillr/jsbt/test.js';
import { sharePlatforms, startTests } from '../platforms.ts';

sharePlatforms('hashes');
const { PLATFORMS } = await import('./noble-hashes/test/platform.ts');
const { avcpTests } = await import('./noble-hashes/test/acvp.test.ts');
// does big tests (LDT) (some like 17gb hash), takes ~14min with parallel execution
for (const k in PLATFORMS) avcpTests(false, k, PLATFORMS[k], { describe, should });
for (const k in PLATFORMS) avcpTests(true, k, PLATFORMS[k], { describe, should });

startTests(import.meta.url);
