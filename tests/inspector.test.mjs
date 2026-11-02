/** Expansion is an inspector preference shared across nodes, not model data. */
import { test } from 'node:test';
import assert from 'node:assert/strict';
import { state } from '../playground/state.js';
import { configureViews, renderInspector } from '../playground/views.js';

test('semantic sections keep open/closed state across nodes, tabs and delayed toggles', () => {
  const originalDocument = globalThis.document;
  const elements = new Map();
  let sections = [];
  let html = '';
  const content = {
    get innerHTML() {
      return html;
    },
    set innerHTML(value) {
      sections.forEach((section) => (section.isConnected = false));
      html = value;
      sections = [...value.matchAll(/<details\b([^>]*)>/g)].map((match) => ({
        dataset: {
          objectSection: match[1]
            .match(/data-object-section="([^"]+)"/)?.[1]
            .replaceAll('&amp;', '&'),
        },
        open: /\sopen(?:\s|$)/.test(match[1]),
        isConnected: true,
      }));
    },
    querySelectorAll(selector) {
      return selector === '[data-object-section]' ? sections : [];
    },
  };
  globalThis.document = {
    querySelector(selector) {
      if (selector === '#inspector-content') return content;
      if (!elements.has(selector))
        elements.set(selector, {
          textContent: '',
          hidden: false,
          classList: { toggle() {} },
        });
      return elements.get(selector);
    },
    querySelectorAll() {
      return [];
    },
  };
  const router = (name) => ({
    name,
    role: 'router',
    identity: name,
    platform: {},
    firewall_v4: { rules: [], connection_tracking: null },
    bgp: { peers: [{ name: 'peer-' + name, redistribute: [] }], policies: [] },
    addresses: [],
    interfaces: [],
    ppp_servers: [],
    radius: [],
    dns: [],
    unexported: [],
    snmp_enabled: null,
  });
  const opened = () =>
    sections
      .filter((section) => section.open)
      .map((section) => section.dataset.objectSection)
      .sort();
  const section = (key) =>
    sections.find((section) => section.dataset.objectSection === key);
  try {
    configureViews({ bindModel() {} });
    state.routers = [router('node-a'), router('node-b')];
    state.selected = 'node-a';
    state.tab = 'objects';
    state.openObjectSections = new Set(['FirewallV4']);
    renderInspector();
    assert.deepEqual(opened(), ['FirewallV4']);

    section('FirewallV4').open = false;
    section('FirewallV4').ontoggle();
    section('BGP').open = true;
    section('BGP').ontoggle();
    section('Addresses').open = true;
    section('Addresses').ontoggle();
    const oldFirewall = section('FirewallV4');
    state.selected = 'node-b';
    renderInspector();
    assert.deepEqual(opened(), ['Addresses', 'BGP']);
    assert.match(
      content.innerHTML,
      /peer-node-b/,
      'the new node is rendered with the previous expansion choices',
    );

    oldFirewall.open = true;
    oldFirewall.ontoggle();
    assert.equal(
      state.openObjectSections.has('FirewallV4'),
      false,
      'detached toggle events cannot reopen FirewallV4',
    );

    state.tab = 'json';
    renderInspector();
    state.tab = 'objects';
    renderInspector();
    assert.deepEqual(
      opened(),
      ['Addresses', 'BGP'],
      'changing tabs also retains expansion',
    );

    // Switch before a native toggle callback has fired; DOM capture must still win.
    sections.forEach((item) => (item.open = false));
    state.selected = 'node-a';
    renderInspector();
    assert.deepEqual(opened(), [], 'closing every branch does not restore the default');
    state.selected = 'node-b';
    renderInspector();
    assert.deepEqual(opened(), []);
  } finally {
    globalThis.document = originalDocument;
  }
});
