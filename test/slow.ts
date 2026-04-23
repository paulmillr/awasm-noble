import { startTests } from './platforms.ts';

import './ciphers/slow.ts';
import './hashes/slow.ts';
import './slow-exhaustive.test.ts';

startTests(import.meta.url);
