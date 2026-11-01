/** Config-flow IDE: drafts are separate from validated models and saved rule files.
 * Python validates and evaluates every saved assertion. This module only authors
 * structured requests, renders results, and navigates between source/model/rule evidence.
 */
import { state, clone, current } from './state.js';
import { $, esc, notify, download } from './dom.js';
import { callEngine } from './engine.js';

let hooks;
const drafts = new Map(),
  newRules = new Map(),
  sourceDrafts = new Map(),
  modelDrafts = new Map();
let selectedRule = null,
  stage = 'source',
  overview = false,
  builderDirty = false;
const metadata = (f) => f.check === 'firmware.exact-version';
const savedRule = () =>
  state.rules.find((rule) => rule.id === selectedRule) || newRules.get(selectedRule);
const definition = () =>
  drafts.get(selectedRule) ?? JSON.stringify(savedRule(), null, 2);
const fields = [
  'firewall_v4.connection_tracking',
  'radius',
  'radius[].timeout_ms',
  'bgp.peers[].redistribute',
  'ppp_servers[].mtu',
  'snmp_enabled',
  'snmp_location',
  'dns',
  'platform.family',
];

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
    field: {
      type: 'field',
      path: 'firewall_v4.connection_tracking',
      operator: 'equals',
      value: false,
    },
    peers: {
      type: 'peers',
      targets: state.policy.borders?.length
        ? [...state.policy.borders]
        : ['border-X', 'border-Y'],
      reciprocal: true,
    },
    route: {
      type: 'route',
      chain: current()?.bgp.peers.find((p) => p.export_policy)?.export_policy || 'OUT',
      prefix: '195.10.222.1/32',
      decision: 'accept',
    },
  };
  return clone(assertions[kind]);
}
function persistRules() {
  try {
    localStorage.setItem('semanticrouter-rule-files-v1', JSON.stringify(state.rules));
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

/** Wire the IDE to application actions without importing its mutable event layer. */
export function initializeWorkbench(data, callbacks) {
  hooks = callbacks;
  state.rules = clone(data.rules || []);
  state.ruleResults = clone(data.rule_results || []);
  state.sources = clone(data.sources || {});
  state.sourceRedacted = Object.fromEntries(
    Object.keys(state.sources).map((name) => [name, !!data.sources_redacted]),
  );
  state.includeEstate = true;
  try {
    const retained = JSON.parse(
      localStorage.getItem('semanticrouter-rule-files-v1') || 'null',
    );
    if (
      Array.isArray(retained) &&
      retained.every(
        (rule) =>
          rule &&
          typeof rule.id === 'string' &&
          typeof rule.name === 'string' &&
          rule.assert &&
          ['packet', 'field', 'peers', 'route'].includes(rule.assert.type),
      )
    )
      state.rules = retained;
  } catch {
    /* A corrupt browser preference must not prevent opening source files. */
  }
  selectedRule = state.rules[0]?.id || null;
  // Two persistent view choices make the topology discoverable from the editor.
  $('#ide-workbench').onclick = () => {
    overview = false;
    renderWorkbench();
  };
  $('#ide-overview').onclick = () => {
    overview = true;
    renderWorkbench();
  };
  $('#new-rule').onclick = () => newRule($('#new-rule-kind').value);
  $('#open-workspace').onclick = () => $('#workspace-input').click();
  $('#workspace-input').onchange = async (event) => {
    try {
      const file = event.target.files[0];
      if (!file) return;
      if (file.size > 10 * 1024 * 1024)
        throw new Error('Workspace is larger than 10 MB.');
      const candidate = JSON.parse(await file.text());
      if (!Array.isArray(candidate.routers) || !candidate.routers.length)
        throw new Error('Workspace needs at least one router.');
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
      state.findings = result.findings;
      state.ruleResults = result.rule_results || [];
      state.selected = state.routers[0].name;
      state.modified = new Set(state.routers.map((r) => r.name));
      state.revision++;
      drafts.clear();
      newRules.clear();
      sourceDrafts.clear();
      modelDrafts.clear();
      selectedRule = state.rules[0]?.id;
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
  editor.scrollTop = Math.max(0, (line - 5) * 21);
}

/** Re-render only from retained draft state, so selection changes cannot erase edits. */
export function renderWorkbench() {
  if (!hooks || !current()) return;
  document.body.classList.toggle('network-overview', overview);
  for (const [id, active] of [
    ['ide-workbench', !overview],
    ['ide-overview', overview],
  ]) {
    $('#' + id).classList.toggle('active', active);
    $('#' + id).setAttribute('aria-pressed', String(active));
  }
  $('#config-workbench').hidden = overview;
  $('#ide-flow').innerHTML = ['source', 'model', 'rules', 'tests', 'export']
    .map(
      (name, index) =>
        `<button class="${stage === name ? 'active' : ''}" data-stage="${name}"><span>${index + 1}</span>${{ source: 'Source config', model: 'Semantic model', rules: 'Author rules', tests: 'Run & inspect', export: 'Export preview' }[name]}</button>`,
    )
    .join('<i>→</i>');
  $('#ide-flow')
    .querySelectorAll('[data-stage]')
    .forEach(
      (b) =>
        (b.onclick = () => {
          stage = b.dataset.stage;
          overview = false;
          renderWorkbench();
        }),
    );
  const all = [...state.rules, ...newRules.values()];
  $('#rule-files').innerHTML =
    all
      .map((rule) => {
        const count = totals(
          (state.ruleResults || []).filter((r) => r.rule_id === rule.id),
        );
        const dirty =
          newRules.has(rule.id) ||
          (drafts.has(rule.id) &&
            drafts.get(rule.id) !== JSON.stringify(rule, null, 2));
        return `<button class="rule-file ${rule.id === selectedRule && stage === 'rules' ? 'selected' : ''}" data-rule-file="${esc(rule.id)}"><span>◇ ${esc(rule.id)}.json${dirty ? ' •' : ''}</span><small>${count.fail ? count.fail + ' fail' : count.unknown ? count.unknown + ' unknown' : count.pass ? count.pass + ' pass' : 'Not run'}</small></button>`;
      })
      .join('') ||
    '<p class="helper">Create a rule to define the network behaviour you expect.</p>';
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
  $('#ide-filepath').textContent =
    stage === 'rules'
      ? selectedRule
        ? 'rules/' + selectedRule + '.json'
        : 'rules/'
      : stage === 'tests'
        ? 'tests/results'
        : current().name +
          (stage === 'source' ? '.cfg' : stage === 'model' ? '.model.json' : '.export');
  $('#ide-status').textContent =
    (state.engineReady ? 'Python ready' : 'Python loading') +
    ' · ' +
    current().name +
    ' · ' +
    state.modified.size +
    ' changed models';
  const content = $('#ide-editor');
  if (stage === 'source') renderSource(content);
  if (stage === 'model') renderModel(content);
  if (stage === 'rules') renderRule(content);
  if (stage === 'tests') renderTests(content);
  if (stage === 'export') renderExport(content);
  renderContext();
  $('#ide-primary').onclick = () => {
    if (stage === 'source') return parseSource();
    else if (stage === 'model') return applyModel();
    else if (stage === 'rules') return saveRule();
    else if (stage === 'tests') return hooks.runChecks();
    else $('#ide-export-form')?.requestSubmit();
  };
  $('#ide-primary').disabled = !state.engineReady;
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
function options(values, selected) {
  return values
    .map(
      ([value, label]) =>
        `<option value="${value}" ${selected === value ? 'selected' : ''}>${label}</option>`,
    )
    .join('');
}
function renderRule(content) {
  if (!selectedRule || !savedRule()) {
    content.innerHTML =
      '<div class="empty-state"><h2>Define the network you expect</h2><p>Create a rule from the explorer. Start with “Monitoring packet” to test SNMP access across all nodes.</p></div>';
    return;
  }
  let rule;
  try {
    rule = JSON.parse(definition());
    if (
      !rule ||
      !rule.assert ||
      !['packet', 'field', 'peers', 'route'].includes(rule.assert.type)
    )
      rule = savedRule();
  } catch {
    rule = savedRule();
  }
  const a = rule.assert,
    roles = rule.scope?.roles || [];
  builderDirty = false;
  const scoped = roles.length === 1 ? roles[0] : '';
  const assertion =
    a.type === 'field'
      ? `${input('Model path', 'rule-path', a.path, 'Use [] to check every item, e.g. ppp_servers[].mtu')}<label class="field">Expectation<select id="rule-operator">${options(
          [
            ['equals', 'equals'],
            ['contains', 'contains item'],
            ['includes_all', 'includes all items'],
            ['exists', 'is explicitly present'],
            ['count_at_least', 'has at least N items'],
          ],
          a.operator,
        )}</select></label>${input('Expected JSON value', 'rule-value', JSON.stringify(a.value ?? null), 'Examples: false, 1500, ["connected", "vpn"]')}`
      : a.type === 'packet'
        ? `${input('Source IPv4', 'rule-source', a.source)}<div class="field-row"><label class="field">Protocol<select id="rule-protocol">${options(
            ['udp', 'tcp', 'icmp', 'ospf'].map((x) => [x, x]),
            a.protocol,
          )}</select></label>${input('Destination port', 'rule-port', a.port)}</div><label class="field">Must be<select id="rule-decision">${options(
            [
              ['accept', 'accepted'],
              ['drop', 'dropped'],
            ],
            a.decision,
          )}</select></label>`
        : a.type === 'peers'
          ? `${input('Required router names', 'rule-targets', (Array.isArray(a.targets) ? a.targets : []).join(', '), 'Comma-separated inventory names')}<label class="toggle-row">Require matching reverse endpoints<input id="rule-reciprocal" type="checkbox" ${a.reciprocal ? 'checked' : ''}></label>`
          : `${input('Filter chain', 'rule-chain', a.chain)}${input('Route prefix', 'rule-prefix', a.prefix)}<label class="field">Must be<select id="rule-decision">${options(
              [
                ['accept', 'accepted'],
                ['reject', 'rejected'],
              ],
              a.decision,
            )}</select></label>`;
  content.innerHTML = `<div class="stage-intro"><h2>Design a reusable rule</h2><p>Scope the assertion, define what must hold, and save to run it against your semantic routers. Edit either the form or the definition.</p></div><div class="rule-author"><form id="rule-builder"><h3>Rule builder</h3>${input('Rule name', 'rule-name', rule.name)}<label class="field">Applies to<select id="rule-scope">${options(
    [
      ['', 'All loaded routers'],
      ['bng', 'BNGs'],
      ['border', 'Borders'],
      ['edge', 'Edges'],
      ['core', 'Cores'],
      ['switch', 'Distribution switches'],
    ],
    scoped,
  )}</select></label>${input('Specific router names (optional)', 'rule-names', (Array.isArray(rule.scope?.names) ? rule.scope.names : []).join(', '), 'Comma-separated names; combined with the role scope')}<label class="field">Assertion<select id="rule-kind">${options(
    [
      ['packet', 'Packet decision'],
      ['field', 'Model field / collection'],
      ['peers', 'Required BGP peerings'],
      ['route', 'Route decision'],
    ],
    a.type,
  )}</select></label>${assertion}<div class="field-row"><label class="field">Failure priority<select id="rule-severity">${options(
    [
      ['P1', 'P1'],
      ['P2', 'P2'],
    ],
    rule.severity,
  )}</select></label><label class="toggle-row">Enabled<input id="rule-enabled" type="checkbox" ${rule.enabled ? 'checked' : ''}></label></div><p class="helper">Array paths require every resolved item to satisfy the expectation. Empty matches fail; missing evidence stays unknown.</p></form><div>${codeEditor('rule-definition', definition(), 'Rule definition JSON')}<div class="inline-actions">${button('Duplicate', 'duplicate-rule')}${button('Delete', 'delete-rule')}${button('Download rule', 'download-rule')}</div></div></div><div id="ide-error" class="error-text" role="status"></div><div id="rule-draft-state" class="draft-state">${newRules.has(rule.id) ? 'New draft · save to include in test runs' : 'Saved definition · edits are validated before replacing it'}</div>`;
  wireEditor('rule-definition', definition(), (text) => {
    drafts.set(selectedRule, text);
    builderDirty = false;
    $('#rule-draft-state').textContent = 'Unsaved JSON draft · save to test';
  });
  if ($('#rule-path')) {
    $('#rule-path').setAttribute('list', 'model-paths');
    const list = document.createElement('datalist');
    list.id = 'model-paths';
    list.innerHTML = fields
      .map((path) => `<option value="${esc(path)}"></option>`)
      .join('');
    $('#rule-builder').append(list);
  }
  $('#rule-builder').onsubmit = (event) => event.preventDefault();
  $('#rule-builder').oninput = () => {
    builderDirty = true;
    $('#rule-draft-state').textContent = 'Unsaved form changes · save to test';
    try {
      const value = ruleFromForm();
      drafts.set(selectedRule, JSON.stringify(value, null, 2));
      $('#rule-definition').value = drafts.get(selectedRule);
    } catch {
      /* Incomplete JSON expected values are allowed while typing. */
    }
  };
  $('#rule-kind').onchange = () => {
    const value = {
      ...rule,
      name: $('#rule-name').value,
      assert: template($('#rule-kind').value),
    };
    drafts.set(selectedRule, JSON.stringify(value, null, 2));
    renderWorkbench();
  };
  $('#duplicate-rule').onclick = () => {
    const original = JSON.parse($('#rule-definition').value);
    newRule(original.assert.type);
    const id = selectedRule;
    original.id = id;
    original.name += ' (copy)';
    newRules.set(id, original);
    drafts.set(id, JSON.stringify(original, null, 2));
    renderWorkbench();
  };
  $('#delete-rule').onclick = async () => {
    state.rules = state.rules.filter((r) => r.id !== selectedRule);
    newRules.delete(selectedRule);
    drafts.delete(selectedRule);
    selectedRule = state.rules[0]?.id || null;
    state.revision++;
    persistRules();
    renderWorkbench();
    await hooks.runChecks(false);
  };
  $('#download-rule').onclick = () => {
    try {
      download(selectedRule + '.rule.json', JSON.parse($('#rule-definition').value));
    } catch (error) {
      $('#ide-error').textContent = error.message;
    }
  };
}
function ruleFromForm() {
  const existing = savedRule(),
    kind = $('#rule-kind').value;
  let assertion;
  if (kind === 'field') {
    const operator = $('#rule-operator').value;
    assertion = { type: kind, path: $('#rule-path').value.trim(), operator };
    if (operator !== 'exists') assertion.value = JSON.parse($('#rule-value').value);
  }
  if (kind === 'packet')
    assertion = {
      type: kind,
      source: $('#rule-source').value.trim(),
      protocol: $('#rule-protocol').value,
      port: Number($('#rule-port').value),
      decision: $('#rule-decision').value,
    };
  if (kind === 'peers')
    assertion = {
      type: kind,
      targets: $('#rule-targets')
        .value.split(',')
        .map((s) => s.trim())
        .filter(Boolean),
      reciprocal: $('#rule-reciprocal').checked,
    };
  if (kind === 'route')
    assertion = {
      type: kind,
      chain: $('#rule-chain').value.trim(),
      prefix: $('#rule-prefix').value.trim(),
      decision: $('#rule-decision').value,
    };
  const role = $('#rule-scope').value;
  return {
    ...existing,
    name: $('#rule-name').value.trim(),
    scope: {
      ...(role ? { roles: [role] } : {}),
      ...($('#rule-names').value.trim()
        ? {
            names: $('#rule-names')
              .value.split(',')
              .map((name) => name.trim())
              .filter(Boolean),
          }
        : {}),
    },
    assert: assertion,
    severity: $('#rule-severity').value,
    enabled: $('#rule-enabled').checked,
  };
}
async function saveRule() {
  const id = selectedRule;
  try {
    const candidate = builderDirty
      ? ruleFromForm()
      : JSON.parse($('#rule-definition').value);
    if (candidate.id !== id)
      throw new Error('Keep the rule id unchanged; duplicate to create another file.');
    const rules = state.rules.filter((r) => r.id !== id).concat(candidate);
    await callEngine('rules_validate', { rules });
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
function renderTests(content) {
  const results = state.ruleResults || [],
    counts = totals(results);
  content.innerHTML = `<div class="stage-intro"><h2>Test the intended configuration</h2><p>These are the results of your saved rule files. Click a result to open its definition and router context.</p></div><div class="test-totals">${['pass', 'fail', 'unknown', 'skip'].map((status) => `<span class="test-status ${status}">${counts[status]} ${status}</span>`).join('')}</div><label class="toggle-row preset-toggle">Also run the built-in estate checks<input id="estate-checks" type="checkbox" ${state.includeEstate ? 'checked' : ''}></label><div class="rule-results"><table><thead><tr><th>Result</th><th>Rule / router</th><th>Observed evidence</th></tr></thead><tbody>${results.map((result, index) => `<tr><td><span class="test-status ${result.status}">${result.status.toUpperCase()}</span></td><td><button data-result="${index}" class="text-button">${esc(result.rule_name)}<br><small>${esc(result.device)}</small></button></td><td>${esc(result.message)}${result.observed !== null ? `<pre>${esc(JSON.stringify(result.observed))}</pre>` : ''}</td></tr>`).join('') || '<tr><td colspan="3">Create a rule and run it to see pass/fail evidence here.</td></tr>'}</tbody></table></div>`;
  $('#estate-checks').onchange = async () => {
    state.includeEstate = $('#estate-checks').checked;
    state.revision++;
    await hooks.runChecks(false);
  };
  content.querySelectorAll('[data-result]').forEach(
    (b) =>
      (b.onclick = () => {
        const r = results[Number(b.dataset.result)];
        state.selected = r.device;
        selectedRule = r.rule_id;
        stage = 'rules';
        hooks.render();
      }),
  );
}
function renderContext() {
  const r = current(),
    results = (state.ruleResults || []).filter(
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
    }<details class="metadata-details"><summary>Inventory metadata (${state.findings.filter(metadata).length})</summary><p class="helper">Missing exact versions belong to inventory, not repeated configuration failures. Record a source version before parsing when you know it.</p>${state.findings
      .filter(metadata)
      .map((f) => `<p><strong>${esc(f.device)}</strong><br>${esc(f.message)}</p>`)
      .join('')}</details>`;
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
function renderExport(content) {
  const r = current();
  content.innerHTML = `<div class="stage-intro"><h2>Review the config output</h2><p>Render this model for a target platform. The output is a review artifact; it is never applied to a device.</p></div><form id="ide-export-form"><div class="field-row"><label class="field">Vendor<select id="ide-vendor"><option value="routeros">RouterOS</option><option value="cisco-ios">Cisco IOS ACL</option></select></label>${input('Target version', 'ide-version', '7.19.3')}</div><label class="toggle-row">Allow a clearly labelled partial fragment<input id="ide-partial" type="checkbox" checked></label></form><div id="ide-export-result" role="status"></div><details class="conversion-gaps"><summary>${r.unexported.length} source statements need export mappings</summary><p class="helper">These statements block a complete conversion. Open a line to inspect the source, then load an original export or extend its vendor mapping.</p>${r.unexported.map((source) => `<button class="gap-line" data-gap="${source.line}">${esc(source.path.split('/').pop())}:${source.line}<code>${esc((state.sources[r.name] || '').split('\n')[source.line - 1] || 'Source text not attached — load the export to inspect this statement')}</code></button>`).join('')}</details><div id="ide-error" class="error-text" role="status"></div>`;
  $('#ide-vendor').onchange = () =>
    ($('#ide-version').value =
      $('#ide-vendor').value === 'routeros' ? '7.19.3' : '15.2');
  $('#ide-export-form').onsubmit = async (event) => {
    event.preventDefault();
    try {
      const vendor = $('#ide-vendor').value;
      const result = await callEngine('export', {
        vendor,
        version: $('#ide-version').value.trim(),
        partial: $('#ide-partial').checked,
      });
      $('#ide-export-result').innerHTML =
        `<p class="export-state">${result.complete ? 'Supported model coverage complete' : 'Partial output — review the omitted statements below'}</p><pre class="result-box">${esc(result.text)}</pre><div class="error-text">${result.diagnostics.map(esc).join('\n')}</div>${button('Download reviewed output', 'ide-download-export')}`;
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
  drafts.clear();
  newRules.clear();
  sourceDrafts.clear();
  modelDrafts.clear();
  state.sources = clone(state.baseline.sources || {});
  state.sourceRedacted = Object.fromEntries(
    Object.keys(state.sources).map((name) => [name, !!state.baseline.sources_redacted]),
  );
  state.ruleResults = [];
  renderWorkbench();
}
export function attachSource(name, text, redacted = false) {
  state.sources[name] = text;
  state.sourceRedacted[name] = redacted;
  sourceDrafts.delete(name);
}
export function refreshTests() {
  renderWorkbench();
}
export function workflowSnapshot() {
  return {
    sources: state.sources,
    source_redacted: state.sourceRedacted,
    rules: state.rules,
  };
}
