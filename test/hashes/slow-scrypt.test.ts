import { should } from '@paulmillr/jsbt/test.js';
import { sharePlatforms, startTests } from '../platforms.ts';

sharePlatforms('hashes');
const { PLATFORMS } = await import('./noble-hashes/test/platform.ts');
const { testScrypt } = await import('./noble-hashes/test/slow-kdf.test.ts');
for (const k in PLATFORMS) testScrypt(k, PLATFORMS[k], { should });

startTests(import.meta.url);
