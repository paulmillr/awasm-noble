import { describe, should } from '@paulmillr/jsbt/test.js';
import { startTests } from '../platforms.ts';
import './async.test.ts';
// New extensive tests
import './slow-basic.test.ts';
import './slow-chunks.test.ts';
import './slow-parallel.test.ts';

startTests(import.meta.url);
