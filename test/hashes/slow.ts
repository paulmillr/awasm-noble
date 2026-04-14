import { should } from '@paulmillr/jsbt/test.js';

import './slow-acvp.test.ts';
import './slow-argon.test.ts';
import './slow-basic.test.ts';
import './slow-chunks.test.ts';
import './slow-parallel.test.ts';
import './slow-big.test.ts';
import './slow-dos.test.ts';
import './slow-scrypt.test.ts';

should.runWhen(import.meta.url);
