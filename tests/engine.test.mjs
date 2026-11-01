/** Exercise the real browser transport without a browser or a second policy engine.
 * The worker double checks message correlation, error handling and PHP runtime URLs.
 */
import { test } from 'node:test';
import assert from 'node:assert/strict';
import { startEngine, callEngine } from '../playground/engine.js';
import { state } from '../playground/state.js';

test('worker transport preserves JSON requests, correlation and lifecycle failures', async () => {
  const original = {
    document: globalThis.document,
    location: globalThis.location,
    Worker: globalThis.Worker,
  };
  const elements = new Map();
  let worker;
  globalThis.document = {
    body: { dataset: { runtimeBase: 'runtime.php?file=/' } },
    querySelector(selector) {
      if (!elements.has(selector))
        elements.set(selector, {
          textContent: '',
          hidden: false,
          classList: { toggle() {} },
        });
      return elements.get(selector);
    },
  };
  globalThis.location = { href: 'https://example.invalid/lab/' };
  globalThis.Worker = class {
    constructor(url, options) {
      this.url = url;
      this.options = options;
      this.messages = [];
      worker = this;
    }
    postMessage(message) {
      this.messages.push(structuredClone(message));
    }
  };
  try {
    let ready = 0,
      failed = 0;
    startEngine(
      () => ready++,
      () => failed++,
    );
    assert.equal(worker.options.type, 'module');
    assert.equal(worker.url.searchParams.get('runtime'), 'runtime.php?file=/');
    assert.deepEqual(worker.messages[0], { action: 'boot' });
    worker.onmessage({ data: { type: 'ready' } });
    assert.equal(ready, 1);
    assert.equal(state.engineReady, true);

    // Out-of-order responses must resolve only their own request.
    const first = callEngine('audit');
    const firstId = worker.messages.at(-1).id;
    const second = callEngine('probe', { source: '198.51.100.9' });
    const secondId = worker.messages.at(-1).id;
    worker.onmessage({ data: { id: secondId, ok: true, verdict: 'accept' } });
    worker.onmessage({ data: { id: firstId, ok: true, findings: [] } });
    assert.equal((await second).verdict, 'accept');
    assert.deepEqual((await first).findings, []);

    // A model validation error rejects that request without killing a healthy runtime.
    const invalid = callEngine('audit');
    worker.onmessage({
      data: { id: worker.messages.at(-1).id, ok: false, error: 'invalid model' },
    });
    await assert.rejects(invalid, /invalid model/);
    assert.equal(state.engineReady, true);

    const interrupted = callEngine('audit');
    worker.onerror({ message: 'test worker stopped' });
    await assert.rejects(interrupted, /Python worker failed/);
    assert.equal(state.engineReady, false);
    assert.equal(failed, 1);
    await assert.rejects(callEngine('audit'), /still loading/);
  } finally {
    Object.assign(globalThis, original);
  }
});
