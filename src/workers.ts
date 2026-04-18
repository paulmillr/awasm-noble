/**
 * Utilities for threaded parallel execution using Web Workers.
 * @module
 */

import modWasm from './targets/wasm_threads/worker_pool.js';

/*
Details:

- We need fast command processing, using atomics instead of messages
  - Spinlock would be too slow with messages
- Main issue with atomics is that thread cannot do anything when it is waiting
  - In node.js: even console.log would get blocked
  - Means we cannot have multiple modules waiting on different atomics inside of a pool

We need 2 modes:

- Fast: Swift atomics mode which waits globally for all modules
- Slow: Message receiving mode for code/memory, since we cannot pass memory via atomics

Installation:

- module calls `pool.install` instead of `initWorkers`
- `pool.install` creates new id, returns that to module. Internally:
  - increment pending for all workers
  - notify all workers about "pending install" CMD=1
    - if worker did not get started yet, it will still see pending and will wait for install
    - for workers which weren't started, we send "install" via callback on initWorkers
- When pool worker sees cmd=1, if pending is not zero, it will exit, then
  message handler installs new module and re-starts worker
- A worker, after registering a new module, does
  'initWorker(notifyOnly=1)' on the module to set the "online" flag

How call works:

- Module sees that it uses pool, then after doing '_worker_notify' via '_worker_notifyBridge'.
  it will call 'pool_notify' with module id.
- Pool notify sets local cmd to module id, notify pool workers as usual
- Pool worker sees local cmd, then calls 'workerProcess', which calls the
  internal per-module initWorker(doOnce=1)
*/

const sleep = (ms: number) => new Promise((resolve) => setTimeout(resolve, ms));

/**
 * Shared worker-pool controller for threaded backends.
 * @param mod - compiled worker-pool module factory.
 */
export class WorkerPool {
  //  limit: number;
  private mod: any;
  private registry: Record<number, { code: any; memory: any }>;
  private pos: number;
  constructor(mod: typeof modWasm) {
    //  this.limit = 31; // 32 bitmask + main
    // <16 reserved for internal commands:
    // 0: wait
    // 1: install
    this.pos = 16;
    this.registry = {};
    this.setModule(mod);
  }
  private setModule(mod: typeof modWasm) {
    this.mod = mod(
      {
        env: {
          // Notify workers that was started after we had install
          onWorkerInstall: (w: any, _id: number) => {
            w.postMessage({ type: 'install', registry: this.registry });
          },
        },
      },
      undefined
    );
  }
  // NOTE: re-uses code from js.ts
  // Generated worker_pool.js starts root workers in setModule().
  // This placeholder does not restart after stop().
  private async initWorkers() {}
  private workerMask() {
    let mask = 0;
    // Generated worker_pool.js assigns worker ids from 1, so bit 0 is not a worker.
    for (let i = 0; i < this.mod.workers.length; i++) mask |= 1 << (i + 1);
    return mask;
  }
  _fmtMask(mask: number) {
    return mask.toString(2).padStart(32, '0');
  }
  // "Public" API
  // Module may call those
  notify(regId: number, mask: number) {
    this.mod._worker_notify(regId, mask);
  }
  online() {
    const res = this.mod._worker_online();
    return res;
  }
  install(code: any, memory: any) {
    const id = this.pos++;
    this.registry[id] = { code, memory };
    let notified = 0;
    for (const w of this.mod.workers) {
      w.postMessage({ type: 'install', registry: { [id]: { code, memory } } });
      notified++;
    }
    this.mod.mainInstalled(id);
    return id;
  }
  //
  // User may call those
  // setLimit(limit: number) {
  //   if (limit < 0 || limit > 31) throw new Error(`wrong limit: ${limit} expected [0...31)`);
  //   this.limit = limit;
  // }
  async waitOnline() {
    for (;;) {
      const online = this.mod._worker_online();
      const mask = this.workerMask();
      // console.log(
      //   'WAIT ONLINE',
      //   this.fmtMask(online),
      //   this.fmtMask(mask),
      //   this.fmtMask(mask ^ online)
      // );
      //const x = P.array(32, P.struct({ pending: P.U32LE, installed: P.U32LE }));
      //console.log('TTT', x.decode(this.mod.segments.registry));
      if (online === mask) break;
      await sleep(100);
    }
  }
  start() {
    this.initWorkers();
  }
  stop() {
    for (const w of this.mod.workers) w.terminate();
    this.mod.mainReset();
  }
}

// Keep the default pool tree-shakeable when only WorkerPool is imported.
/** Default shared worker pool for wasm_threads targets. */
export const WP = /* @__PURE__ */ new WorkerPool(modWasm);
