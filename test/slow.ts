import { startTests } from './platforms.ts';

import './ciphers/slow.ts';
import './hashes/slow.ts';

startTests(import.meta.url);
