/** Verify the real module graph and UI lifecycle with a small in-memory DOM.
 * This is a unit test, not browser QA: Python semantics have separate bridge tests.
 */
import { test } from 'node:test';
import assert from 'node:assert/strict';
import { state } from '../playground/state.js';

test('standalone startup, JSON edit and reset work through the real module graph', async () => {
  const originals = {
    document: globalThis.document,
    location: globalThis.location,
    Worker: globalThis.Worker,
    fetch: globalThis.fetch,
  };
  const elements = new Map();
  const tabs = ['objects', 'experiment', 'export', 'json'].map((tab) => ({
    dataset: { tab },
    classList: { toggle() {} },
  }));
  const element = (selector) => {
    if (!elements.has(selector))
      elements.set(selector, {
        value: '',
        innerHTML: '',
        textContent: '',
        hidden: true,
        classList: { toggle() {} },
        querySelectorAll() {
          return [];
        },
      });
    return elements.get(selector);
  };
  globalThis.document = {
    body: { dataset: {} },
    querySelector: element,
    querySelectorAll(selector) {
      return selector === '[data-tab]' ? tabs : [];
    },
  };
  globalThis.location = { href: 'https://example.invalid/playground/' };
  const router = {
    name: 'demo',
    role: 'switch',
    identity: 'demo',
    platform: { hardware: 'synthetic', family: null, version: null },
    addresses: [],
    interfaces: [],
    dns: [],
    firewall_v4: { rules: [], groups: [], connection_tracking: null },
    bgp: { peers: [], policies: [] },
    ppp_servers: [],
    radius: [],
    snmp_enabled: null,
    snmp_location: null,
    diagnostics: [],
    unexported: [],
  };
  const snapshot = {
    routers: [router],
    policy: { snmp_pollers: [] },
    findings: [],
    mode: 'synthetic demo',
  };
  globalThis.fetch = async (url) => {
    assert.equal(url, './data.json');
    return { ok: true, json: async () => structuredClone(snapshot) };
  };
  globalThis.Worker = class {
    postMessage(message) {
      queueMicrotask(() =>
        this.onmessage({
          data:
            message.action === 'boot'
              ? { type: 'ready' }
              : { id: message.id, ok: true, findings: [] },
        }),
      );
    }
  };
  try {
    await import('../playground/app.js');
    await new Promise((resolve) => setImmediate(resolve));
    assert.equal(state.engineReady, true);
    assert.equal(element('#selected-name').textContent, 'demo');
    assert.match(element('#inspector-content').innerHTML, /FirewallV4/);

    tabs.find((tab) => tab.dataset.tab === 'json').onclick();
    const edited = JSON.parse(element('#model-json').value);
    edited.identity = 'edited-demo';
    element('#model-json').value = JSON.stringify(edited);
    await element('#model-form').onsubmit({ preventDefault() {} });
    assert.equal(state.routers[0].identity, 'edited-demo');
    assert.equal(state.modified.has('demo'), true);

    await element('#reset-all').onclick();
    assert.equal(state.routers[0].identity, 'demo');
    assert.equal(state.modified.size, 0);
  } finally {
    Object.assign(globalThis, originals);
  }
});
