/** Config-flow IDE: drafts are separate from validated models and saved rule files.
 * Python validates and evaluates every saved assertion. This module only authors
 * structured requests, renders results, and navigates between source/model/rule evidence.
 */
import { state, clone, current } from './state.js';
import { $, esc, notify, download } from './dom.js';
import { callEngine, exportModel } from './engine.js';
import { TreeDocument, mountTreeEditor } from './tree-editor.js';
import { workspaceController } from './workspaces.js';

let hooks;
const drafts = new Map(),
  newRules = new Map(),
  sourceDrafts = new Map(),
  modelDrafts = new Map();
let selectedRule = null,
  stage = 'rules',
  overview = false;
const savedRule = () =>
  state.rules.find((rule) => rule.id === selectedRule) || newRules.get(selectedRule);
const definition = () =>
  drafts.get(selectedRule) ?? JSON.stringify(savedRule(), null, 2);
// Cached documents retain tree expansion, raw JSON and undo across navigation.
const ruleDocuments = new Map();
let ruleViews = [];
function destroyRuleViews() {
  for (const view of ruleViews) view.destroy();
  ruleViews = [];
}
function ruleDocument() {
  if (!ruleDocuments.has(selectedRule)) {
    let value;
    try {
      value = JSON.parse(definition());
    } catch {
      value = savedRule();
    }
    const doc = new TreeDocument(value, (next, change) => {
      // Changing assertion kind explicitly chooses a fresh, valid template. Raw
      // JSON replacements retain exactly the structure the author provided.
      if (!change.raw && JSON.stringify(change.path) === '["assert","type"]')
        next.assert = template(next.assert.type);
      return next;
    });
    ruleDocuments.set(selectedRule, doc);
    if (drafts.has(selectedRule)) doc.editJSON([], drafts.get(selectedRule));
  }
  return ruleDocuments.get(selectedRule);
}

const testTypes = [
  [
    'field',
    'Model assertion',
    'Compare model fields and collections',
    '<rect x="4" y="3" width="16" height="18" rx="2"/><path d="M8 8h8M8 12h8M8 16h4"/>',
  ],
  [
    'packet',
    'Packet decision',
    'Check how an input packet is handled',
    '<rect x="3" y="7" width="10" height="10" rx="2"/><path d="M13 12h8m-3-3 3 3-3 3M6 10h4"/>',
  ],
  [
    'peers',
    'Required peerings',
    'Require matching BGP peer definitions',
    '<rect x="2" y="8" width="6" height="8" rx="1"/><rect x="16" y="8" width="6" height="8" rx="1"/><path d="M8 10h8m-3-3 3 3-3 3M16 14H8m3-3-3 3 3 3"/>',
  ],
  [
    'route',
    'Route decision',
    'Check a route against a filter chain',
    '<path d="M5 20V8a3 3 0 0 1 3-3h11m-4-4 4 4-4 4M5 13h9a3 3 0 0 1 3 3v4"/><circle cx="5" cy="20" r="1"/><circle cx="17" cy="20" r="1"/>',
  ],
  [
    'expression',
    'Custom logic',
    'Combine conditions and cross-router tests',
    '<path d="m8 7-5 5 5 5m8-10 5 5-5 5m-3-13-2 16"/>',
  ],
];
const testTypeIcon = (paths) =>
  `<svg viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="1.7" stroke-linecap="round" stroke-linejoin="round" aria-hidden="true" focusable="false">${paths}</svg>`;
let pickerDocument;

/** Native disclosure semantics provide keyboard opening; choices are ordinary buttons.
 * Close on selection, Escape, outside clicks, or focus leaving the picker. */
function initializeTestTypePicker() {
  const picker = $('#new-rule-picker');
  const trigger = $('#new-rule-trigger');
  const choose = (kind) => {
    const selected = testTypes.find((type) => type[0] === kind) || testTypes[0];
    $('#new-rule-kind').value = selected[0];
    $('#new-rule-label').textContent = selected[1];
    $('#new-rule-icon').innerHTML = testTypeIcon(selected[3]);
    $('#new-rule-options').innerHTML = testTypes
      .map(
        ([id, label, description, icon]) =>
          `<button type="button" data-test-kind="${id}" class="test-type-option${id === selected[0] ? ' selected' : ''}" aria-pressed="${id === selected[0]}"><span class="test-type-icon">${testTypeIcon(icon)}</span><span><strong>${label}</strong><small>${description}</small></span><span class="type-check" aria-hidden="true">${id === selected[0] ? '✓' : ''}</span></button>`,
      )
      .join('');
    $('#new-rule-options')
      .querySelectorAll('[data-test-kind]')
      .forEach((button) => {
        button.onclick = () => {
          choose(button.dataset.testKind);
          picker.open = false;
          trigger.focus();
        };
      });
  };
  choose($('#new-rule-kind').value || 'field');
  // Prefer the side with enough viewport room; keep long menus scrollable.
  picker.ontoggle = () => {
    if (!picker.open) return;
    picker.classList.toggle('opens-up', false);
    const options = $('#new-rule-options');
    options.style.maxHeight = '';
    const anchor = trigger.getBoundingClientRect();
    const below = window.innerHeight - anchor.bottom - 12;
    const above = anchor.top - 12;
    const opensUp = options.offsetHeight > below && above > below;
    picker.classList.toggle('opens-up', opensUp);
    options.style.maxHeight = Math.max(80, opensUp ? above : below) + 'px';
  };
  picker.onkeydown = (event) => {
    if (event.key === 'Escape') {
      event.preventDefault();
      picker.open = false;
      trigger.focus();
    }
  };
  picker.onfocusout = () =>
    setTimeout(() => {
      if (!picker.contains(document.activeElement)) picker.open = false;
    }, 0);
  if (pickerDocument !== document) {
    document.addEventListener('pointerdown', (event) => {
      const currentPicker = $('#new-rule-picker');
      if (currentPicker && !currentPicker.contains(event.target))
        currentPicker.open = false;
    });
    pickerDocument = document;
  }
}

/** Seed a new assertion with domain examples, not executable code. */
function template(kind) {
  const assertions = {
    packet: {
      type: 'packet',
      source: state.policy.snmp_pollers?.[0] || '198.51.100.9',
      protocol: 'udp',
      port: 161,
      decision: 'accept',
    },
    field: { type: 'field', path: 'identity', operator: 'exists' },
    expression: {
      type: 'expression',
      test: { op: 'eq', args: [{ ref: 'router.identity' }, { ref: 'router.name' }] },
    },
    peers: {
      type: 'peers',
      targets: state.policy.borders?.length ? [...state.policy.borders] : [],
      reciprocal: true,
    },
    route: {
      type: 'route',
      chain: current()?.bgp.peers.find((p) => p.export_policy)?.export_policy || 'OUT',
      prefix: '203.0.113.1/32',
      decision: 'accept',
    },
  };
  return clone(assertions[kind]);
}
function persistRules() {
  try {
    localStorage.setItem(ruleStorageKey(), JSON.stringify(state.rules));
  } catch {
    notify(
      'Rules are saved in this tab. Browser storage is unavailable; download the workspace to retain them.',
    );
  }
}
function newRule(kind = 'packet') {
  let index = 1;
  while (
    state.rules.some((r) => r.id === 'rule-' + index) ||
    newRules.has('rule-' + index)
  )
    index++;
  const rule = {
    id: 'rule-' + index,
    name: 'New ' + kind + ' assertion',
    enabled: true,
    severity: 'P1',
    scope: {},
    params: {},
    assert: template(kind),
  };
  newRules.set(rule.id, rule);
  selectedRule = rule.id;
  drafts.set(rule.id, JSON.stringify(rule, null, 2));
  stage = 'rules';
  overview = false;
  renderWorkbench();
}
function ruleLabel(id) {
  return state.rules.find((r) => r.id === id)?.name || id;
}
function totals(results) {
  return results.reduce((out, r) => ((out[r.status] = (out[r.status] || 0) + 1), out), {
    pass: 0,
    fail: 0,
    unknown: 0,
    skip: 0,
  });
}
function button(text, id, primary = false, disabled = false) {
  return `<button id="${id}" class="button ${primary ? 'primary' : ''}" ${disabled ? 'disabled' : ''}>${text}</button>`;
}

/** Preserve unfinished editors within a workspace without serializing them as saved
 * rules or sharing raw draft expressions. Maps hold document instances deliberately. */
export function pendingConfigDraftNames() {
  return new Set([...sourceDrafts.keys(), ...modelDrafts.keys()]);
}
export function discardConfigDrafts(names) {
  for (const name of names) {
    sourceDrafts.delete(name);
    modelDrafts.delete(name);
  }
}
export function captureWorkbenchDrafts() {
  return {
    drafts: new Map(drafts),
    newRules: new Map(newRules),
    ruleDocuments: new Map(ruleDocuments),
    sourceDrafts: new Map(sourceDrafts),
    modelDrafts: new Map(modelDrafts),
  };
}
export function restoreWorkbenchDrafts(session) {
  destroyRuleViews();
  for (const [key, target] of Object.entries({
    drafts,
    newRules,
    ruleDocuments,
    sourceDrafts,
    modelDrafts,
  })) {
    target.clear();
    if (session?.[key]) for (const [id, value] of session[key]) target.set(id, value);
  }
  selectedRule = null;
  resultStatus = 'all';
}
const ruleStorageKey = () =>
  !state.workspace || state.workspace.id === 'bf-network'
    ? 'semanticrouter-rule-files-v1'
    : 'semanticrouter-rule-files-v1:' + state.workspace.id;

/** Wire the IDE to application actions without importing its mutable event layer. */
export function initializeWorkbench(data, callbacks, { restoreRules = true } = {}) {
  hooks = callbacks;
  state.rules = clone(data.rules || []);
  state.ruleResults = clone(data.rule_results || []);
  state.sources = clone(data.sources || {});
  state.sourceRedacted = clone(
    data.source_redacted ||
      Object.fromEntries(
        Object.keys(state.sources).map((name) => [name, !!data.sources_redacted]),
      ),
  );
  state.nativeSources = {};
  state.sourceHashes = clone(data.source_hashes || {});
  state.sourceURL = data.source_url || null;
  state.ruleSuites = clone(data.rule_suites || []);
  try {
    const retained = JSON.parse(
      (restoreRules ? localStorage.getItem(ruleStorageKey()) : null) || 'null',
    );
    if (
      Array.isArray(retained) &&
      retained.every(
        (rule) =>
          rule &&
          typeof rule.id === 'string' &&
          typeof rule.name === 'string' &&
          rule.assert &&
          ['packet', 'field', 'peers', 'route', 'expression'].includes(
            rule.assert.type,
          ),
      )
    )
      state.rules = retained;
  } catch {
    /* A corrupt browser preference must not prevent opening source files. */
  }
  selectedRule = null;
  // Two persistent view choices make the topology discoverable from the editor.
  $('#ide-workbench').onclick = () => {
    overview = false;
    renderWorkbench();
  };
  $('#ide-overview').onclick = () => {
    overview = true;
    renderWorkbench();
  };
  initializeTestTypePicker();
  $('#new-rule').onclick = () => newRule($('#new-rule-kind').value);
  $('#close-rule-editor').onclick = () => {
    selectedRule = null;
    renderWorkbench();
  };
  $('#suite-example').innerHTML =
    '<option value="">Choose an optional starting point…</option>' +
    state.ruleSuites
      .map(
        (suite, index) =>
          `<option value="${index}">${esc(suite.name)} (${suite.rules.length} rules)</option>`,
      )
      .join('');
  $('#add-example').onclick = async () => {
    const selected = $('#suite-example').value;
    if (selected === '') return notify('Choose an example suite first.');
    try {
      await addSuite(state.ruleSuites[Number(selected)]);
    } catch (error) {
      notify(error.message, true);
    }
  };
  $('#import-suite').onclick = () => $('#suite-input').click();
  $('#suite-input').onchange = async (event) => {
    try {
      const file = event.target.files[0];
      if (!file) return;
      if (file.size > 1024 * 1024) throw new Error('Use a suite smaller than 1 MB.');
      await addSuite(JSON.parse(await file.text()));
    } catch (error) {
      notify('Suite was not added: ' + error.message, true);
    } finally {
      event.target.value = '';
    }
  };
  $('#download-suite').onclick = () =>
    download('semanticrouter-tests.json', {
      id: 'workspace',
      name: 'Workspace tests',
      rules: state.rules,
      variables: state.policy,
    });
  $('#open-workspace').onclick = () => $('#workspace-input').click();
  $('#workspace-input').onchange = async (event) => {
    try {
      const file = event.target.files[0];
      if (!file) return;
      if (file.size > 10 * 1024 * 1024)
        throw new Error('Workspace is larger than 10 MB.');
      const candidate = JSON.parse(await file.text());
      if (workspaceController()) {
        await workspaceController().importSnapshot(candidate);
        notify('Workspace imported.');
        return;
      }
      if (!Array.isArray(candidate.routers))
        throw new Error('Workspace needs a router array.');
      if (
        candidate.sources &&
        (typeof candidate.sources !== 'object' ||
          Array.isArray(candidate.sources) ||
          Object.values(candidate.sources).some((value) => typeof value !== 'string'))
      )
        throw new Error('Workspace sources must map router names to source text.');
      const result = await callEngine('audit', {
        routers: candidate.routers,
        policy: candidate.policy || state.policy,
        rules: candidate.rules || [],
      });
      state.routers = clone(candidate.routers);
      state.policy = clone(candidate.policy || state.policy);
      state.rules = clone(candidate.rules || []);
      state.sources = clone(candidate.sources || {});
      state.sourceRedacted = clone(candidate.source_redacted || {});
      state.sourceHashes = clone(candidate.source_hashes || {});
      state.nativeSources = {};
      state.findings = result.findings;
      state.ruleResults = result.rule_results || [];
      state.selected = state.routers[0]?.name || null;
      state.modified = new Set(state.routers.map((r) => r.name));
      state.revision++;
      drafts.clear();
      ruleDocuments.clear();
      newRules.clear();
      sourceDrafts.clear();
      modelDrafts.clear();
      selectedRule = null;
      persistRules();
      hooks.render();
      notify('Workspace opened: models, sources and rule files are ready.');
    } catch (error) {
      notify('Workspace was not changed: ' + error.message, true);
    } finally {
      event.target.value = '';
    }
  };
  renderWorkbench();
}

/** Merge an explicitly selected suite without overwriting existing authored definitions. */
async function addSuite(value) {
  const revision = state.revision;
  const { suite } = await callEngine('suite_validate', { suite: value });
  const existing = new Set(state.rules.map((rule) => rule.id));
  const additions = suite.rules.filter((rule) => !existing.has(rule.id));
  const rules = [...state.rules, ...clone(additions)];
  await callEngine('rules_validate', { rules });
  if (state.revision !== revision)
    throw new Error('The rule list changed while importing. Please try again.');
  state.rules = rules;
  state.policy = { ...clone(suite.variables || {}), ...state.policy };
  selectedRule = null;
  stage = 'rules';
  overview = false;
  state.revision++;
  persistRules();
  hooks.render();
  await hooks.runChecks(false);
  notify(
    `${additions.length} rules added. Existing definitions were kept. Every active rule is editable.`,
  );
}

/** Navigate problems back to the authored rule or to the cited source line. */
export function openEvidence(finding) {
  if (finding.device) state.selected = finding.device;
  if (finding.rule_id || finding.check?.startsWith('custom.')) {
    selectedRule = finding.rule_id || finding.check.slice(7);
    stage = 'rules';
  } else stage = finding.source?.line ? 'source' : 'model';
  overview = false;
  hooks.render();
  if (stage === 'source' && finding.source?.line) focusLine(finding.source.line);
}
function focusLine(line) {
  const editor = $('#source-editor');
  if (!editor) return;
  const lines = editor.value.split('\n');
  const start =
    lines.slice(0, Math.max(0, line - 1)).join('\n').length + (line > 1 ? 1 : 0);
  editor.focus();
  editor.setSelectionRange(start, start + (lines[line - 1] || '').length);
  const lineHeight = parseFloat(getComputedStyle(editor).lineHeight) || 26.25;
  editor.scrollTop = Math.max(0, (line - 5) * lineHeight);
}

/** Re-render only from retained draft state, so selection changes cannot erase edits. */
export function renderWorkbench() {
  if (!hooks) return;
  document.body.classList.toggle('network-overview', overview);
  for (const [id, active] of [
    ['ide-workbench', !overview],
    ['ide-overview', overview],
  ]) {
    $('#' + id).classList.toggle('active', active);
    $('#' + id).setAttribute('aria-pressed', String(active));
  }
  $('#config-workbench').hidden = overview;
  $('#test-design').hidden = overview || stage !== 'rules';
  if (overview || stage !== 'rules') $('#new-rule-picker').open = false;
  $('#ide-flow').innerHTML = ['rules', 'source', 'model', 'tests', 'export']
    .map(
      (name, index) =>
        `<button class="${stage === name ? 'active' : ''}" data-stage="${name}"><span>${index + 1}</span>${{ source: 'Source config', model: 'Semantic model', rules: 'Test design', tests: 'Run & inspect', export: 'Export preview' }[name]}</button>`,
    )
    .join('<i>→</i>');
  $('#ide-flow')
    .querySelectorAll('[data-stage]')
    .forEach(
      (b) =>
        (b.onclick = () => {
          stage = b.dataset.stage;
          if (stage === 'rules') selectedRule = null;
          overview = false;
          renderWorkbench();
        }),
    );
  const all = [...state.rules, ...newRules.values()];
  $('#rule-file-count').textContent =
    `${state.rules.length} saved${newRules.size ? ' · ' + newRules.size + ' drafts' : ''}`;
  $('#rule-files').innerHTML =
    all
      .map((rule) => {
        const count = totals(
          (state.ruleResults || []).filter((r) => r.rule_id === rule.id),
        );
        const dirty =
          newRules.has(rule.id) ||
          (ruleDocuments.has(rule.id) && !ruleDocuments.get(rule.id).valid) ||
          (drafts.has(rule.id) &&
            drafts.get(rule.id) !== JSON.stringify(rule, null, 2));
        return `<article class="rule-entry"><button class="rule-file ${rule.id === selectedRule && stage === 'rules' ? 'selected' : ''}" data-rule-file="${esc(rule.id)}"><span>${esc(rule.name)}${dirty ? ' •' : ''}</span><code>${esc(rule.id)}</code><small>${count.fail ? count.fail + ' fail' : count.unknown ? count.unknown + ' unknown' : count.pass ? count.pass + ' pass' : 'Not run'}</small></button><label class="rule-run"><input type="checkbox" data-enable-rule="${esc(rule.id)}" ${rule.enabled !== false ? 'checked' : ''} ${newRules.has(rule.id) ? 'disabled' : ''} aria-label="Run ${esc(rule.name)}">Run</label></article>`;
      })
      .join('') ||
    '<div class="test-empty"><strong>No tests selected yet</strong><p>Create your first assertion or add an optional example suite. A configuration without tests has not been validated.</p></div>';
  $('#rule-files')
    .querySelectorAll('[data-rule-file]')
    .forEach(
      (b) =>
        (b.onclick = () => {
          selectedRule = b.dataset.ruleFile;
          stage = 'rules';
          overview = false;
          renderWorkbench();
        }),
    );
  $('#rule-files')
    .querySelectorAll('[data-enable-rule]')
    .forEach((input) => {
      input.onchange = async () => {
        const revision = state.revision;
        const previous = state.rules.find(
          (rule) => rule.id === input.dataset.enableRule,
        );
        const rules = state.rules.map((rule) =>
          rule.id === input.dataset.enableRule
            ? { ...rule, enabled: input.checked }
            : rule,
        );
        try {
          await callEngine('rules_validate', { rules });
          if (state.revision !== revision)
            throw new Error('The rule list changed. Please try again.');
          if (
            (!ruleDocuments.has(previous.id) || ruleDocuments.get(previous.id).valid) &&
            (!drafts.has(previous.id) ||
              drafts.get(previous.id) === JSON.stringify(previous, null, 2))
          ) {
            drafts.delete(previous.id);
            ruleDocuments.delete(previous.id);
          }
          state.rules = rules;
          state.revision++;
          persistRules();
          renderWorkbench();
          await hooks.runChecks(false);
        } catch (error) {
          input.checked = !input.checked;
          notify(error.message, true);
        }
      };
    });
  $('#ide-filepath').textContent =
    stage === 'rules'
      ? selectedRule
        ? 'rules/' + selectedRule + '.json'
        : 'rules/'
      : stage === 'tests'
        ? 'tests/results'
        : (current()?.name || 'workspace') +
          (stage === 'source' ? '.cfg' : stage === 'model' ? '.model.json' : '.export');
  $('#ide-status').textContent =
    (state.engineReady ? 'Python ready' : 'Python loading') +
    ' · ' +
    (current()?.name || 'No router selected') +
    ' · ' +
    state.modified.size +
    ' changed models';
  // A suite is a list until the user explicitly creates or selects a rule.
  // Closing the editor keeps drafts in memory so reopening does not discard work.
  const showEditor = stage !== 'rules' || Boolean(savedRule());
  $('#ide-toolbar').hidden = !showEditor;
  $('#ide-columns').hidden = !showEditor;
  $('#close-rule-editor').hidden = stage !== 'rules' || !showEditor;
  destroyRuleViews();
  const content = $('#ide-editor');
  if (stage === 'source' && current()) renderSource(content);
  if (stage === 'model' && current()) renderModel(content);
  if (stage === 'rules' && showEditor) renderRule(content);
  if (stage === 'tests') renderTests(content);
  if (stage === 'export' && current()) renderExport(content);
  if (!current() && ['source', 'model', 'export'].includes(stage))
    content.innerHTML =
      '<div class="empty-state"><h2>Load your first configuration</h2><p>Use Load config to add a router to this workspace. You can design tests before loading devices.</p></div>';
  renderContext();
  $('#ide-primary').onclick = () => {
    if (stage === 'source') return parseSource();
    else if (stage === 'model') return applyModel();
    else if (stage === 'rules') return saveRule();
    else if (stage === 'tests') return hooks.runChecks();
    else $('#ide-export-form')?.requestSubmit();
  };
  $('#ide-primary').disabled =
    !state.engineReady ||
    (stage === 'rules' && !savedRule()) ||
    (!current() && ['source', 'model', 'export'].includes(stage));
  $('#ide-primary').textContent = {
    source: 'Parse → model',
    model: 'Apply → run tests',
    rules: 'Save rule → run tests',
    tests: 'Run saved tests',
    export: 'Generate preview',
  }[stage];
}

function codeEditor(id, value, language = 'JSON') {
  return `<div class="code-caption"><span>${language}</span><span>Ctrl / ⌘ + Enter to run</span></div><div class="code-wrap"><pre class="line-numbers" aria-hidden="true">${value
    .split('\n')
    .map((_, i) => i + 1)
    .join(
      '\n',
    )}</pre><textarea id="${id}" class="code-editor" spellcheck="false" aria-label="${language} editor"></textarea></div>`;
}
function wireEditor(id, value, onInput) {
  const editor = $('#' + id);
  editor.value = value;
  editor.oninput = () => {
    onInput(editor.value);
    const gutter = editor.parentElement.querySelector('.line-numbers');
    gutter.textContent = editor.value
      .split('\n')
      .map((_, i) => i + 1)
      .join('\n');
  };
  editor.onscroll = () => {
    editor.parentElement.querySelector('.line-numbers').scrollTop = editor.scrollTop;
  };
  editor.onkeydown = (event) => {
    if ((event.ctrlKey || event.metaKey) && event.key === 'Enter') {
      event.preventDefault();
      $('#ide-primary').click();
    }
    if (event.key === 'Tab') {
      event.preventDefault();
      const a = editor.selectionStart,
        b = editor.selectionEnd;
      editor.setRangeText('  ', a, b, 'end');
      editor.dispatchEvent(new Event('input'));
    }
  };
}
function renderSource(content) {
  const r = current(),
    source = sourceDrafts.get(r.name) ?? state.sources[r.name] ?? '';
  content.innerHTML = `<div class="stage-intro"><h2>Start from the configuration</h2><p>Edit a source draft, parse it into a semantic model, then test the intended behaviour. Original backups remain unchanged.</p></div><div class="source-options"><label>Exact source version <input id="source-version" placeholder="Optional, e.g. 7.19.3" value="${esc(r.platform.version || '')}"></label><span>${state.sourceRedacted[r.name] ? 'Credential-redacted review copy · complete conversion requires an original export' : source ? 'Local source draft' : 'Load or paste an export to attach source to this model'}</span></div>${codeEditor('source-editor', source, 'RouterOS config')}<div id="ide-error" class="error-text" role="status"></div>`;
  wireEditor('source-editor', source, (value) => sourceDrafts.set(r.name, value));
}
async function parseSource() {
  const r = current();
  try {
    const text = $('#source-editor').value;
    if (!text.trim()) throw new Error('Paste or load a source export first.');
    if (text.length > 5 * 1024 * 1024)
      throw new Error('Please use a source smaller than 5 MB.');
    const result = await callEngine('import', {
      name: r.name,
      text,
      version: $('#source-version').value.trim(),
      redacted: !!state.sourceRedacted[r.name],
    });
    state.routers = state.routers.map((item) =>
      item.name === r.name ? result.router : item,
    );
    state.sources[r.name] = text;
    sourceDrafts.delete(r.name);
    modelDrafts.delete(r.name);
    state.modified.add(r.name);
    state.revision++;
    stage = 'model';
    hooks.render();
    await hooks.runChecks(false);
    notify('Source parsed. Inspect the model, author a rule, then run your tests.');
  } catch (error) {
    $('#ide-error').textContent = error.message;
  }
}
function renderModel(content) {
  const r = current(),
    value = modelDrafts.get(r.name) ?? JSON.stringify(r, null, 2);
  content.innerHTML = `<div class="stage-intro"><h2>Work with the semantic model</h2><p>This is the platform-independent object your rules test. Change a draft and apply it to compare the resulting test outcomes.</p></div>${codeEditor('ide-model', value)}<div id="ide-error" class="error-text" role="status"></div>`;
  wireEditor('ide-model', value, (text) => modelDrafts.set(r.name, text));
}
async function applyModel() {
  const name = state.selected;
  try {
    const value = JSON.parse($('#ide-model').value);
    if (value.name !== name) throw new Error('Keep the inventory name unchanged.');
    const routers = state.routers.map((r) => (r.name === name ? value : r));
    await callEngine('audit', { routers });
    state.routers = routers;
    state.modified.add(name);
    modelDrafts.delete(name);
    state.revision++;
    hooks.render();
    await hooks.runChecks(false);
    notify('Model applied. Test results now reflect this configuration draft.');
  } catch (error) {
    $('#ide-error').textContent = error.message;
  }
}

function input(label, id, value, help = '') {
  return `<label class="field">${label}<input id="${id}" value="${esc(value)}">${help ? `<small>${help}</small>` : ''}</label>`;
}
/** One rule document backs all three views. Editing a subtree immediately
 * updates the definition without reconstructing fields or dropping custom data. */
function renderRule(content) {
  if (!selectedRule || !savedRule()) return;
  const id = selectedRule,
    doc = ruleDocument();
  content.innerHTML = `<div class="stage-intro"><h2>Design a reusable rule</h2><p>Browse the definition, build conditions and add parameters. Switch any panel to JSON when you need it. Save to validate and run the rule.</p></div><div class="rule-author rule-tree-author"><div id="rule-definition-panel"></div><div class="rule-tree-details"><div id="rule-logic-panel"></div><div id="rule-params-panel"></div></div></div><div class="inline-actions">${button('Duplicate', 'duplicate-rule')}${button('Delete', 'delete-rule')}${button('Download rule', 'download-rule')}</div><div id="ide-error" class="error-text" role="status"></div><div id="rule-draft-state" class="draft-state">${newRules.has(id) ? 'New draft · save to include in test runs' : 'Saved definition · edits are validated before replacing it'}</div>`;
  const choices = (path, value) => {
    let values;
    const key = JSON.stringify(path);
    if (key === '["severity"]') values = ['P1', 'P2'];
    if (key === '["assert","type"]')
      return testTypes.map(([kind, label]) => [kind, label]);
    if (key === '["assert","operator"]')
      values = ['equals', 'contains', 'includes_all', 'exists', 'count_at_least'];
    if (key === '["assert","protocol"]') values = ['udp', 'tcp', 'icmp', 'ospf'];
    if (key === '["assert","decision"]') values = ['accept', 'drop', 'reject'];
    if (!values) return null;
    if (!values.includes(String(value))) values.push(String(value));
    return values.map((item) => [item, item]);
  };
  const suggestions = (path) => {
    if (!path.length)
      return [
        'name',
        'description',
        'enabled',
        'severity',
        'scope',
        'assert',
        'params',
      ];
    if (JSON.stringify(path) === '["scope"]') return ['roles', 'names'];
    return [];
  };
  const mount = (container, viewId, path, label, expressionMode = false) =>
    mountTreeEditor({
      container: $(container),
      id: viewId,
      document: doc,
      path,
      label,
      expressionMode,
      choices,
      suggestions,
      onSave: saveRule,
    });
  ruleViews.push(
    mount('#rule-definition-panel', 'rule-definition', [], 'Rule definition'),
  );
  let detailViews = [],
    previousKind;
  function mountDetails() {
    const type = doc.at(['assert', 'type']);
    if (previousKind === type) return;
    previousKind = type;
    for (const view of detailViews) view.destroy();
    detailViews = [
      mount(
        '#rule-logic-panel',
        'rule-expression',
        type === 'expression' ? ['assert', 'test'] : ['assert'],
        type === 'expression' ? 'Logic' : 'Assertion',
        type === 'expression',
      ),
      mount('#rule-params-panel', 'rule-params', ['params'], 'Parameters'),
    ];
  }
  mountDetails();
  const unsubscribe = doc.subscribe(() => {
    drafts.set(id, doc.text());
    $('#rule-draft-state').textContent =
      'Unsaved draft · save to validate and run tests';
    mountDetails();
  });
  ruleViews.push({
    destroy() {
      unsubscribe();
      for (const view of detailViews) view.destroy();
    },
  });
  $('#duplicate-rule').onclick = () => {
    try {
      const original = doc.getValue();
      newRule(original.assert.type);
      original.id = selectedRule;
      original.name += ' (copy)';
      newRules.set(selectedRule, original);
      drafts.set(selectedRule, JSON.stringify(original, null, 2));
      ruleDocuments.delete(selectedRule);
      renderWorkbench();
    } catch (error) {
      $('#ide-error').textContent = error.message;
    }
  };
  $('#delete-rule').onclick = async () => {
    state.rules = state.rules.filter((rule) => rule.id !== id);
    newRules.delete(id);
    drafts.delete(id);
    ruleDocuments.delete(id);
    selectedRule = null;
    state.revision++;
    persistRules();
    renderWorkbench();
    await hooks.runChecks(false);
  };
  $('#download-rule').onclick = () => {
    try {
      download(id + '.rule.json', doc.getValue());
    } catch (error) {
      $('#ide-error').textContent = error.message;
    }
  };
}
async function saveRule() {
  const revision = state.revision;
  const id = selectedRule;
  try {
    const doc = ruleDocument();
    const candidate = doc.getValue();
    if (candidate.id !== id)
      throw new Error('Keep the rule id unchanged; duplicate to create another file.');
    const rules = state.rules.filter((r) => r.id !== id).concat(candidate);
    await callEngine('rules_validate', { rules });
    if (state.revision !== revision)
      throw new Error('The rule list changed while saving. Please try again.');
    if (!doc.valid || JSON.stringify(doc.getValue()) !== JSON.stringify(candidate))
      throw new Error(
        'The draft changed while validating. Save again to include your latest edits.',
      );
    state.rules = rules;
    newRules.delete(id);
    drafts.set(id, JSON.stringify(candidate, null, 2));
    persistRules();
    state.revision++;
    renderWorkbench();
    await hooks.runChecks(false);
    notify('Rule saved and evaluated against the loaded semantic models.');
  } catch (error) {
    $('#ide-error').textContent = error.message;
  }
}
/** Status totals are independent filters; clicking an active total restores All.
 * Keep original result indices so filtering never opens the wrong rule/router. */
let resultStatus = 'all';
function renderTests(content) {
  const results = state.ruleResults || [],
    counts = totals(results);
  const visible = results
    .map((result, index) => ({ result, index }))
    .filter(({ result }) => resultStatus === 'all' || result.status === resultStatus);
  content.innerHTML = `<div class="stage-intro"><h2>Test the intended configuration</h2><p>Filter by result, then open a test to inspect its definition and router context.</p></div><div class="test-totals status-filters" role="group" aria-label="Filter test results">${['all', 'pass', 'fail', 'unknown', 'skip'].map((status) => `<button type="button" data-result-status="${status}" class="test-status ${status}" aria-pressed="${resultStatus === status}">${status === 'all' ? results.length : counts[status]} ${status}</button>`).join('')}</div><p class="helper" role="status">Showing ${visible.length} of ${results.length} results${resultStatus === 'all' ? '' : ' · ' + resultStatus}</p><div class="rule-results"><table><thead><tr><th>Result</th><th>Rule / router</th><th>Observed result</th></tr></thead><tbody>${visible.map(({ result, index }) => `<tr><td><span class="test-status ${result.status}">${result.status.toUpperCase()}</span></td><td><button data-result="${index}" class="text-button">${esc(result.rule_name)}<br><small>${esc(result.device)}</small></button></td><td>${esc(result.message)}${result.observed != null ? `<pre>${esc(JSON.stringify(result.observed))}</pre>` : ''}</td></tr>`).join('') || '<tr><td colspan="3">No results match this status.</td></tr>'}</tbody></table></div>`;
  content.querySelectorAll('[data-result-status]').forEach((button) => {
    button.onclick = () => {
      resultStatus =
        resultStatus === button.dataset.resultStatus
          ? 'all'
          : button.dataset.resultStatus;
      renderTests(content);
    };
  });
  content.querySelectorAll('[data-result]').forEach((button) => {
    button.onclick = () => {
      const result = results[Number(button.dataset.result)];
      state.selected = result.device;
      selectedRule = result.rule_id;
      stage = 'rules';
      hooks.render();
    };
  });
}

function renderContext() {
  const r = current();
  if (!r) {
    $('#ide-context').innerHTML =
      '<h3>New workspace</h3><p class="helper">Create tests, then load router configs to begin.</p>';
    return;
  }
  const results = (state.ruleResults || []).filter(
      (result) => result.device === r.name && result.status !== 'skip',
    ),
    counts = totals(results);
  $('#ide-context').innerHTML =
    `<div class="eyebrow">SELECTED ROUTER</div><h3>${esc(r.name)}</h3><p class="helper">${esc(r.platform.hardware || 'Hardware not recorded')}<br>Firmware: ${esc(r.platform.version || (r.platform.family ? r.platform.family + '.x syntax family' : 'not recorded'))}</p><div class="test-totals"><span class="test-status pass">${counts.pass} pass</span><span class="test-status fail">${counts.fail} fail</span><span class="test-status unknown">${counts.unknown} unknown</span></div><h3>Next step</h3><p class="helper">${{ source: 'Parse this source draft to rebuild the intermediate model.', model: 'Apply a model change, then compare your test outcomes.', rules: 'Save the rule to test every router in its scope.', tests: 'Open a failed assertion to change its intent or inspect the affected model.', export: 'Review a supported fragment and the precise import gaps before downloading.' }[stage]}</p><h3>Model changes</h3>${
      changes(r)
        .map(
          (change) =>
            `<div class="model-change"><code>${esc(change.path)}</code><del>${esc(JSON.stringify(change.before))}</del><ins>${esc(JSON.stringify(change.after))}</ins></div>`,
        )
        .join('') || '<p class="helper">No changes from the loaded snapshot.</p>'
    }`;
}
function changes(router) {
  const baseline = state.originals.get(router.name);
  if (!baseline) return [{ path: 'router', before: 'not loaded', after: 'new model' }];
  const found = [];
  function walk(before, after, path) {
    if (found.length >= 25 || JSON.stringify(before) === JSON.stringify(after)) return;
    if (before && after && typeof before === 'object' && typeof after === 'object') {
      for (const key of new Set([...Object.keys(before), ...Object.keys(after)]))
        walk(before[key], after[key], path ? path + '.' + key : key);
    } else found.push({ path, before, after });
  }
  walk(baseline, router, '');
  return found;
}
/** Portable conversion limits are relevant only when leaving RouterOS syntax.
 * The legacy unexported list is not a native export omission counter. */
function conversionGaps(router) {
  if (!router.unexported.length) return '';
  return `<details id="ide-conversion-gaps" class="conversion-gaps" hidden><summary>${router.unexported.length} statements need target conversion mappings</summary><p class="helper">These statements cannot be translated by the portable converter. Complete RouterOS export retains their native settings.</p>${router.unexported.map((source) => `<button class="gap-line" data-gap="${source.line}">${esc(source.path.split('/').pop())}:${source.line}<code>${esc((state.sources[router.name] || '').split('\n')[source.line - 1] || 'Load the source to inspect this statement')}</code></button>`).join('')}</details>`;
}

/** Render actual export proof only after the engine has verified the output. */
function exportVerification(proof = {}) {
  if (!proof.semantic_match) return '';
  return `<div class="test-totals"><span class="test-status pass">Model round trip matched</span>${proof.native_statement_match ? '<span class="test-status pass">All RouterOS statements accounted for</span>' : ''}</div>${proof.input_statements !== undefined ? `<p class="helper">${proof.input_statements} input statements · ${proof.output_statements} generated statements</p>` : ''}`;
}

function renderExport(content) {
  const r = current();
  content.innerHTML = `<div class="stage-intro"><h2>Review the config output</h2><p>Render this model for a target platform. The output is a review artifact; it is never applied to a device.</p></div><form id="ide-export-form"><div class="field-row"><label class="field">Vendor<select id="ide-vendor"><option value="routeros">RouterOS</option><option value="cisco-ios">Cisco IOS ACL</option></select></label>${input('Target version', 'ide-version', 'source', 'source keeps the original RouterOS syntax')}</div><label id="ide-partial-option" class="toggle-row" hidden>Allow a clearly labelled conversion fragment<input id="ide-partial" type="checkbox"></label></form><div id="ide-export-result" role="status"></div>${conversionGaps(r)}<div id="ide-error" class="error-text" role="status"></div>`;
  $('#ide-vendor').onchange = () => {
    const native = $('#ide-vendor').value === 'routeros';
    $('#ide-version').value = native ? 'source' : '15.2';
    $('#ide-partial-option').hidden = native;
    if ($('#ide-conversion-gaps')) $('#ide-conversion-gaps').hidden = native;
    // A successful preview belongs to its target; clear it on target changes.
    $('#ide-export-result').innerHTML = '';
    $('#ide-error').textContent = '';
    $('#ide-partial').checked = false;
  };
  $('#ide-export-form').onsubmit = async (event) => {
    event.preventDefault();
    try {
      const vendor = $('#ide-vendor').value;
      const version = $('#ide-version').value.trim();
      const result = await exportModel({
        vendor,
        version,
        partial: $('#ide-partial').checked,
      });
      if (
        $('#ide-vendor').value !== vendor ||
        $('#ide-version').value.trim() !== version
      )
        return;
      $('#ide-export-result').innerHTML =
        exportVerification(result.verification) +
        `<p class="export-state">${result.complete ? (result.mode === 'source-aware' ? 'Complete RouterOS configuration — model and native statements verified' : 'Complete supported model conversion') : 'Partial output — review the omitted statements below'}</p><pre class="result-box">${esc(result.text)}</pre><div class="error-text">${result.diagnostics.map(esc).join('\n')}</div>${button('Download configuration', 'ide-download-export')}`;
      $('#ide-download-export').onclick = () =>
        download(r.name + (vendor === 'routeros' ? '.rsc' : '.ios'), result.text);
    } catch (error) {
      $('#ide-error').textContent = error.message;
    }
  };
  content.querySelectorAll('[data-gap]').forEach(
    (b) =>
      (b.onclick = () => {
        stage = 'source';
        renderWorkbench();
        focusLine(Number(b.dataset.gap));
      }),
  );
}

export function resetWorkbench() {
  selectedRule = null;
  drafts.clear();
  ruleDocuments.clear();
  newRules.clear();
  sourceDrafts.clear();
  modelDrafts.clear();
  state.sources = clone(state.baseline.sources || {});
  state.sourceRedacted = clone(
    state.baseline.source_redacted ||
      Object.fromEntries(
        Object.keys(state.sources).map((name) => [
          name,
          !!state.baseline.sources_redacted,
        ]),
      ),
  );
  state.sourceHashes = clone(state.baseline.source_hashes || {});
  state.sourceURL = state.baseline.source_url || null;
  state.nativeSources = {};
  state.ruleResults = [];
  renderWorkbench();
}
export function attachSource(name, text, redacted = false) {
  state.sources[name] = text;
  state.sourceRedacted[name] = redacted;
  state.nativeSources = {};
  delete state.sourceHashes[name];
  sourceDrafts.delete(name);
}
export function refreshTests() {
  renderWorkbench();
}
export function workflowSnapshot() {
  return {
    sources: state.sources,
    source_redacted: state.sourceRedacted,
    source_hashes: state.sourceHashes,
    source_url: state.sourceURL,
    rules: state.rules,
  };
}
