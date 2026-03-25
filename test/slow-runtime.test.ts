import * as runtime from '../src/targets/runtime/index.ts';
import { PLATFORMS, startTests } from './platforms.ts';
for (const k in PLATFORMS) delete PLATFORMS[k];
PLATFORMS.runtime = runtime;

// Takes ~10h
(async () => {
  // Make sure platform installed before
  await import('./index.ts');
  startTests(import.meta.url);
})();
