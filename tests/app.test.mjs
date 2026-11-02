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
  const stages = ['rules', 'source', 'model', 'tests', 'export'].map((stage) => ({
    dataset: { stage },
  }));
  const typeOptions = ['field', 'packet', 'peers', 'route', 'expression'].map(
    (testKind) => ({ dataset: { testKind } }),
  );
  const ruleFiles = [{ dataset: { ruleFile: 'snmp' } }];
  const ruleToggle = { dataset: { enableRule: 'snmp' }, checked: true };
  const element = (selector) => {
    if (!elements.has(selector))
      elements.set(selector, {
        value: '',
        innerHTML: '',
        textContent: '',
        hidden: true,
        classList: { toggle() {} },
        setAttribute() {},
        focus() {},
        contains() {
          return false;
        },
        append() {},
        parentElement: { querySelector: () => ({ textContent: '' }) },
        querySelectorAll(query) {
          if (selector === '#ide-flow' && query === '[data-stage]') return stages;
          if (selector === '#new-rule-options' && query === '[data-test-kind]')
            return typeOptions;
          if (selector === '#rule-files' && query === '[data-rule-file]')
            return ruleFiles;
          if (selector === '#rule-files' && query === '[data-enable-rule]')
            return [ruleToggle];
          return [];
        },
      });
    return elements.get(selector);
  };
  globalThis.document = {
    body: { dataset: {}, classList: { toggle() {} } },
    querySelector: element,
    addEventListener() {},
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
    rule_suites: [
      {
        id: 'optional',
        name: 'Optional example',
        rules: [{ ...definition, id: 'optional-rule', name: 'Example rule' }],
      },
    ],
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
              : {
                  id: message.id,
                  ok: true,
                  findings: [],
                  ...(message.action === 'suite_validate'
                    ? { suite: message.suite }
                    : {}),
                },
        }),
      );
    }
  };
  try {
    await import('../playground/app.js');
    await new Promise((resolve) => setImmediate(resolve));
    assert.equal(state.engineReady, true);
    assert.equal(
      element('#ide-columns').hidden,
      true,
      'saved rules do not automatically open the editor',
    );
    assert.equal(element('#ide-toolbar').hidden, true);
    ruleFiles[0].onclick();
    assert.equal(
      element('#ide-columns').hidden,
      false,
      'selecting a rule opens its editor',
    );
    const draft = JSON.parse(element('#rule-definition').value);
    draft.name = 'Unsaved draft';
    element('#rule-definition').value = JSON.stringify(draft);
    element('#rule-definition').oninput();
    element('#close-rule-editor').onclick();
    assert.equal(element('#ide-columns').hidden, true);
    ruleFiles[0].onclick();
    assert.equal(
      JSON.parse(element('#rule-definition').value).name,
      'Unsaved draft',
      'closing keeps the draft',
    );
    stages.find((button) => button.dataset.stage === 'rules').onclick();
    assert.equal(
      element('#ide-columns').hidden,
      true,
      'step 1 returns to the rule list',
    );
    element('#new-rule').onclick();
    assert.equal(
      element('#ide-columns').hidden,
      false,
      'creating a test opens the editor',
    );
    element('#close-rule-editor').onclick();

    assert.equal(
      element('#test-design').hidden,
      false,
      'rule choices belong to step 1',
    );
    stages.find((button) => button.dataset.stage === 'model').onclick();
    assert.equal(
      element('#test-design').hidden,
      true,
      'rule catalog is hidden outside test design',
    );
    stages.find((button) => button.dataset.stage === 'rules').onclick();
    assert.equal(element('#test-design').hidden, false);
    assert.equal(element('#new-rule-kind').value, 'field');
    element('#new-rule-picker').open = true;
    typeOptions.find((button) => button.dataset.testKind === 'peers').onclick();
    assert.equal(element('#new-rule-kind').value, 'peers');
    assert.equal(element('#new-rule-label').textContent, 'Required peerings');
    assert.match(element('#new-rule-icon').innerHTML, /<svg/);
    assert.equal(
      element('#new-rule-picker').open,
      false,
      'selection closes the picker',
    );
    element('#new-rule-picker').open = true;
    element('#new-rule-picker').onkeydown({ key: 'Escape', preventDefault() {} });
    assert.equal(
      element('#new-rule-picker').open,
      false,
      'Escape dismisses the picker',
    );

    assert.match(
      element('#network-map').innerHTML,
      /unvalidated/,
      'untested nodes are not shown as passing',
    );
    assert.equal(element('#selected-name').textContent, 'demo');
    assert.match(element('#inspector-content').innerHTML, /FirewallV4/);

    tabs.find((tab) => tab.dataset.tab === 'json').onclick();
    const edited = JSON.parse(element('#model-json').value);
    edited.identity = 'edited-demo';
    element('#model-json').value = JSON.stringify(edited);
    await element('#model-form').onsubmit({ preventDefault() {} });
    assert.equal(state.routers[0].identity, 'edited-demo');
    assert.equal(state.modified.has('demo'), true);

    const { openEvidence, initializeWorkbench } = await import(
      '../playground/workbench.js'
    );
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
    assert.equal(state.rules.length, 1, 'examples never activate on startup');
    element('#suite-example').value = '0';
    await element('#add-example').onclick();
    assert.equal(
      element('#ide-columns').hidden,
      true,
      'adding examples does not start editing a rule',
    );
    assert.equal(
      state.rules.length,
      2,
      'explicit example selection adds editable rules',
    );
    assert.equal(
      state.rules.find((rule) => rule.id === 'snmp').name,
      'Author edited rule',
    );
    await element('#add-example').onclick();
    assert.equal(
      state.rules.length,
      2,
      'adding again does not overwrite or duplicate rules',
    );
    openEvidence({ device: 'demo', rule_id: 'optional-rule' });
    assert.equal(JSON.parse(element('#rule-definition').value).id, 'optional-rule');
    ruleToggle.checked = false;
    await ruleToggle.onchange();
    assert.equal(state.rules.find((rule) => rule.id === 'snmp').enabled, false);
    openEvidence({ device: 'demo', rule_id: 'snmp' });
    assert.equal(
      JSON.parse(element('#rule-definition').value).enabled,
      false,
      'Run choice updates the saved editor definition',
    );
    assert.ok(
      requests
        .filter((request) => request.action === 'audit')
        .every((request) => !('include_estate' in request)),
    );
    saved.set('semanticrouter-rule-files-v1', '[]');
    initializeWorkbench(
      { ...snapshot, rules: [] },
      { runChecks: async () => {}, render: () => {}, select: () => {} },
    );
    assert.equal(state.rules.length, 0);
    assert.equal(
      element('#ide-primary').disabled,
      true,
      'an empty suite cannot save a nonexistent rule',
    );
    assert.match(element('#rule-files').innerHTML, /No tests selected yet/);
  } finally {
    Object.assign(globalThis, originals);
  }
});
