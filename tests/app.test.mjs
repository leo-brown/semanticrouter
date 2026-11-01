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
    localStorage: globalThis.localStorage,
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
        setAttribute() {},
        append() {},
        parentElement: { querySelector: () => ({ textContent: '' }) },
        querySelectorAll() {
          return [];
        },
      });
    return elements.get(selector);
  };
  globalThis.document = {
    body: { dataset: {}, classList: { toggle() {} } },
    querySelector: element,
    createElement: () => ({ innerHTML: '' }),
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
  const saved = new Map();
  globalThis.localStorage = {
    getItem: (key) => saved.get(key),
    setItem: (key, value) => saved.set(key, value),
  };
  const definition = {
    id: 'snmp',
    name: 'Monitoring access',
    scope: {},
    enabled: true,
    severity: 'P1',
    assert: {
      type: 'packet',
      source: '198.51.100.9',
      protocol: 'udp',
      port: 161,
      decision: 'accept',
    },
  };
  const requests = [];
  const snapshot = {
    routers: [router],
    rules: [definition],
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
      requests.push(message);
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

    const { openEvidence } = await import('../playground/workbench.js');
    openEvidence({ device: 'demo', rule_id: 'snmp' });
    const updated = { ...definition, name: 'Author edited rule' };
    element('#rule-definition').value = JSON.stringify(updated);
    element('#rule-definition').oninput();
    assert.equal(
      state.rules[0].name,
      'Monitoring access',
      'drafts do not change saved tests',
    );
    await element('#ide-primary').onclick();
    assert.equal(state.rules[0].name, 'Author edited rule');
    assert.equal(
      JSON.parse(saved.get('semanticrouter-rule-files-v1'))[0].name,
      'Author edited rule',
    );
    assert.ok(
      requests.some(
        (request) =>
          request.action === 'rules_validate' &&
          request.rules[0].name === 'Author edited rule',
      ),
    );
    assert.ok(
      requests.some(
        (request) =>
          request.action === 'audit' && request.rules[0].name === 'Author edited rule',
      ),
    );
    element('#rule-definition').value = '{ invalid';
    element('#rule-definition').oninput();
    await element('#ide-primary').onclick();
    assert.equal(
      state.rules[0].name,
      'Author edited rule',
      'invalid JSON never replaces a saved rule',
    );
    assert.notEqual(element('#ide-error').textContent, '');

    await element('#reset-all').onclick();
    assert.equal(state.routers[0].identity, 'demo');
    assert.equal(state.modified.size, 0);
  } finally {
    Object.assign(globalThis, originals);
  }
});
