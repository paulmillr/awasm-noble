import compare from '@paulmillr/jsbt/benchmark-compare.js';

import { cleanFast } from '../../src/utils.ts';

const KB = 1024;
const MB = 1024 * KB;

async function main() {
  await compare(
    'Zeroize',
    {
      buffer: {
        '1MB': new Uint8Array(1 * MB).fill(1),
        '10MB': new Uint8Array(10 * MB).fill(2),
      },
    },
    {
      fill: (buf: Uint8Array) => buf.fill(0),
      cleanFast: (buf: Uint8Array) => cleanFast(buf),
    },
    {
      libraryDimensions: ['method'],
      defaults: {},
      iterations: ({ args }) => (args[0].length <= 1 * MB ? 200 : 20),
      bytes: ({ args }) => args[0].length,
    }
  );
}

main();
