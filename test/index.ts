import './ciphers/index.ts';
import './hashes/index.ts';
import { startTests } from './platforms.ts';
import './runtime-fast.test.ts';
import './utils.test.ts';
//import './examples.test.ts';

startTests(import.meta.url);
