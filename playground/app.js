/** Application entry point and user actions for the browser playground.
 * Lifecycle: load bundled snapshot -> start Python worker -> audit typed models.
 * Every mutation increments a revision so late audit results cannot replace newer state.
 * No action writes to the source exports or connects to a router.
 */
import { state, clone, current } from './state.js';
import { $, esc, notify, download, engineStatus } from './dom.js';
import { startEngine, callEngine, exportModel } from './engine.js';
import {
  initializeWorkspaces,
  renderWorkspaceControls,
  workspaceController,
} from './workspaces.js';
import { initializeTeams } from './teams.js';
import { initializeRepository } from './repository.js';
import {
  configureViews,
  render,
  renderSidebar,
  renderMetrics,
  renderMap,
  renderInspector,
  renderFindings,
} from './views.js';
import {
  initializeWorkbench,
  renderWorkbench,
  openEvidence,
  attachSource,
  resetWorkbench,
  refreshTests,
  workflowSnapshot,
  captureWorkbenchDrafts,
  restoreWorkbenchDrafts,
  pendingConfigDraftNames,
  discardConfigDrafts,
} from './workbench.js';

/** Change inspector focus and clear stale export output; the semantic models stay untouched. */
function select(name) {
  state.selected = name;
  state.exportResult = null;
  render();
}

/** Apply an ephemeral model experiment, mark provenance as edited and re-audit the workspace. */
async function mutate(edit, message) {
  edit(current());
  state.modified.add(state.selected);
  state.revision++;
  render();
  await runChecks(false);
  notify(message || 'Model updated. Policy checks re-evaluated.');
}

/** Attach inspector-local controls after rendering. Indices refer to the current model
 * arrays only; no click handler writes to a router, original export or server-side file. */
function bindExperiments(r) {
  document.querySelectorAll('[data-quick]').forEach(
    (b) =>
      (b.onclick = async () => {
        if (b.dataset.quick === 'reset') {
          const original = state.originals.get(r.name);
          if (original) {
            state.routers = state.routers.map((item) =>
              item.name === r.name ? clone(original) : item,
            );
            state.modified.delete(r.name);
            state.revision++;
            render();
            await runChecks(false);
            notify('Router restored to its original snapshot.');
          }
          return;
        }
        if (b.dataset.quick === 'radius')
          await mutate(
            (router) =>
              router.radius
                .filter((s) => s.enabled)
                .forEach((s, i) => (s.timeout_ms = i === 0 ? 500 : 2000)),
            'RADIUS timeouts updated in this model.',
          );
        if (b.dataset.quick === 'final-drop')
          await mutate((router) => {
            const rules = router.firewall_v4.rules;
            const candidate = [...rules]
              .reverse()
              .find(
                (f) =>
                  f.chain === 'input' &&
                  ['drop', 'reject'].includes(f.action) &&
                  !f.protocol &&
                  !f.source_network &&
                  !f.source_group &&
                  !f.destination_network &&
                  !f.destination_group &&
                  !f.destination_ports &&
                  !f.source_ports &&
                  !f.ingress &&
                  !f.egress &&
                  !Object.keys(f.extra).length,
              );
            if (candidate) {
              candidate.enabled = true;
              rules.splice(rules.indexOf(candidate), 1);
              rules.push(candidate);
            } else
              rules.push({
                chain: 'input',
                action: 'drop',
                protocol: null,
                source_network: null,
                source_group: null,
                destination_network: null,
                destination_group: null,
                destination_ports: null,
                source_ports: null,
                ingress: null,
                egress: null,
                enabled: true,
                extra: {},
                source: null,
              });
          }, 'Final input drop enabled in this model.');
      }),
  );
  const track = $('#conntrack');
  if (track)
    track.onchange = () =>
      mutate(
        (router) => (router.firewall_v4.connection_tracking = JSON.parse(track.value)),
      );
  document.querySelectorAll('[data-mtu]').forEach(
    (input) =>
      (input.onchange = () => {
        if (!input.reportValidity()) return;
        mutate(
          (router) =>
            (router.ppp_servers[Number(input.dataset.mtu)].mtu = Number(input.value)),
        );
      }),
  );
  document
    .querySelectorAll('[data-peer]')
    .forEach(
      (input) =>
        (input.onchange = () =>
          mutate(
            (router) =>
              (router.bgp.peers[Number(input.dataset.peer)].enabled = input.checked),
          )),
    );
  document
    .querySelectorAll('[data-rule]')
    .forEach(
      (input) =>
        (input.onchange = () =>
          mutate(
            (router) =>
              (router.firewall_v4.rules[Number(input.dataset.rule)].enabled =
                input.checked),
          )),
    );
  $('#packet-form').onsubmit = async (event) => {
    event.preventDefault();
    await probe('packet-result', {
      kind: 'firewall',
      source: $('#probe-source').value.trim(),
      protocol: $('#probe-protocol').value,
      port: $('#probe-port').value,
    });
  };
  $('#route-form').onsubmit = async (event) => {
    event.preventDefault();
    await probe('route-result', {
      kind: 'route',
      chain: $('#probe-chain').value,
      prefix: $('#probe-prefix').value.trim(),
    });
  };
}

/** Ask the Python evaluator for a packet/route verdict and retain unknown as a distinct result. */
async function probe(target, values) {
  const box = $('#' + target);
  try {
    const result = await callEngine('probe', values);
    box.innerHTML = `<div class="result-box">Verdict: <span class="verdict ${esc(result.verdict)}">${esc(result.verdict.toUpperCase())}</span>\nConfiguration evaluation only.</div>`;
  } catch (error) {
    box.textContent = error.message;
    box.className = 'error-text';
  }
}

/** Request a target/version rendering with explicit partial-fragment consent.
 * Unsupported conversions render diagnostics; downloading is a separate user action. */
function bindExport() {
  $('#export-vendor').onchange = () => {
    const native = $('#export-vendor').value === 'routeros';
    $('#export-version').value = native ? 'source' : '15.2';
    $('#export-partial-option').hidden = native;
    $('#export-partial').checked = false;
    $('#export-result').innerHTML = '';
  };
  $('#export-form').onsubmit = async (event) => {
    event.preventDefault();
    const box = $('#export-result');
    box.textContent = 'Rendering with Python…';
    try {
      const name = current().name;
      const vendor = $('#export-vendor').value;
      const version = $('#export-version').value.trim();
      const result = await exportModel({
        vendor,
        version,
        partial: $('#export-partial').checked,
      });
      if (
        current().name !== name ||
        $('#export-vendor').value !== vendor ||
        $('#export-version').value.trim() !== version
      )
        return;
      state.exportResult = result;
      box.innerHTML = `<div class="model-note">${result.complete ? (result.mode === 'source-aware' ? 'Complete RouterOS configuration · semantic round trip and native statements verified.' : 'Complete supported model conversion.') : 'PARTIAL FRAGMENT · This is not a replacement device configuration.'}</div><pre class="result-box">${esc(result.text)}</pre>${result.diagnostics.length ? `<div class="error-text">${result.diagnostics.map(esc).join('\n')}</div>` : ''}<button id="download-export" class="button small">↓ Download ${result.complete ? 'configuration' : 'fragment'}</button>`;
      $('#download-export').onclick = () =>
        download(name + (vendor === 'routeros' ? '.rsc' : '.ios'), result.text);
    } catch (error) {
      box.innerHTML = `<div class="error-text">Export blocked:\n${esc(error.message)}</div>`;
    }
  };
}

/** Audit the captured revision without reparsing exports. Ignore a late response if a
 * newer edit already exists, and keep the run button busy until all requests settle. */
async function runChecks(showNotice = true) {
  if (!state.engineReady) {
    if (showNotice) notify('The Python engine is loading. Try again in a moment.');
    return;
  }
  const revision = state.revision;
  state.busy++;
  $('#run-checks').disabled = true;
  $('#run-checks').textContent = 'Running checks…';
  try {
    const result = await callEngine('audit');
    if (revision === state.revision) {
      state.findings = result.findings;
      state.ruleResults = result.rule_results || [];
      renderSidebar();
      renderMetrics();
      renderMap();
      renderFindings();
      refreshTests();
      if (showNotice)
        notify(
          state.ruleResults.some((result) => result.status !== 'skip')
            ? 'Saved tests evaluated against the semantic models.'
            : 'No active tests matched this inventory. Choose or create tests before validating the design.',
        );
    }
  } catch (error) {
    notify('Checks could not complete: ' + error.message, true);
  } finally {
    state.busy--;
    if (!state.busy) {
      $('#run-checks').disabled = false;
      $('#run-checks').textContent = '▶ Run tests';
    }
  }
}

/** Parse one export locally in Python, then replace/add its typed semantic snapshot.
 * Size/name checks bound accidental input; originals are retained for explicit reset. */
async function importConfig(name, text, version = '') {
  if (text.length > 5 * 1024 * 1024)
    throw new Error('Please load a config smaller than 5 MB.');
  if (!/^[a-zA-Z0-9_.-]+$/.test(name))
    throw new Error(
      'Use letters, digits, dots, underscores or hyphens in the router name.',
    );
  const result = await callEngine('import', { name, text, version });
  const index = state.routers.findIndex((r) => r.name === name);
  if (index === -1) state.routers.push(result.router);
  else state.routers[index] = result.router;
  if (!state.originals.has(name)) state.originals.set(name, clone(result.router));
  attachSource(name, text);
  state.modified.add(name);
  state.selected = name;
  state.revision++;
}

/** Load the baseline first so inspection works while Python initializes, then run
 * the same policy engine used by the CLI. A missing runtime never invents fresh results. */
async function main() {
  try {
    const response = await fetch(document.body.dataset.snapshotUrl || './data.json');
    if (!response.ok) throw new Error('Snapshot could not be loaded.');
    const data = await response.json();
    state.baseline = clone(data);
    state.routers = clone(data.routers);
    state.policy = clone(data.policy);
    state.findings = clone(data.findings);
    state.originals = new Map(state.routers.map((r) => [r.name, clone(r)]));
    state.selected =
      state.routers.find((r) => r.name === 'bng-X1')?.name ||
      state.routers[0]?.name ||
      null;
    $('#snapshot-mode').textContent = data.mode;
    const workspaceCallbacks = { runChecks, render, select };
    const controller = initializeWorkspaces(data, {
      snapshot: () => ({
        routers: clone(state.routers),
        policy: clone(state.policy),
        ...clone(workflowSnapshot()),
        rule_suites: clone(state.ruleSuites),
      }),
      validate: (snapshot) =>
        callEngine('audit', {
          routers: snapshot.routers,
          policy: snapshot.policy || {},
          rules: snapshot.rules || [],
        }),
      captureDrafts: captureWorkbenchDrafts,
      restoreDrafts: restoreWorkbenchDrafts,
      render,
      async apply(snapshot, baseline, metadata) {
        state.workspace = metadata;
        state.baseline = clone(baseline);
        state.routers = clone(snapshot.routers);
        state.policy = clone(snapshot.policy || {});
        state.findings = [];
        state.originals = new Map(
          baseline.routers.map((router) => [router.name, clone(router)]),
        );
        state.selected =
          state.routers.find((router) => router.name === snapshot.selected)?.name ||
          state.routers[0]?.name ||
          null;
        state.modified = new Set(snapshot.modified || []);
        state.policyModified = false;
        state.exportResult = null;
        state.revision++;
        initializeWorkbench(snapshot, workspaceCallbacks, { restoreRules: false });
        $('#snapshot-mode').textContent = metadata.name;
        await runChecks(false);
      },
    });
    initializeTeams(controller);
    initializeRepository(controller, {
      pendingNames: pendingConfigDraftNames,
      discardDrafts: discardConfigDrafts,
    });
    initializeWorkbench(data, workspaceCallbacks);
    render();
    startEngine(
      async () => {
        try {
          await controller.restoreActive();
        } catch (error) {
          notify('Saved workspace could not be opened: ' + error.message, true);
        }
        renderInspector();
        runChecks(false);
      },
      () => renderInspector(),
    );
  } catch (error) {
    notify('Unable to load the playground: ' + error.message, true);
    engineStatus('Snapshot unavailable');
  }
}

/** Validate the JSON candidate in Python before replacing the selected model. */
function bindModel(r) {
  $('#model-form').onsubmit = async (event) => {
    event.preventDefault();
    try {
      const value = JSON.parse($('#model-json').value);
      if (value.name !== r.name)
        throw new Error(
          'Keep the model name unchanged; use import to add a new router.',
        );
      const routers = state.routers.map((item) =>
        item.name === r.name ? value : item,
      );
      const result = await callEngine('audit', { routers });
      state.routers = routers;
      state.findings = result.findings;
      state.ruleResults = result.rule_results || [];
      state.modified.add(r.name);
      state.revision++;
      render();
      notify('Model applied. Policy checks re-evaluated in Python.');
    } catch (error) {
      $('#model-error').textContent = error.message;
    }
  };
  $('#download-model').onclick = () => download(r.name + '.json', r);
}

configureViews({
  select,
  bindExperiments,
  bindExport,
  bindModel,
  renderWorkbench,
  renderWorkspaceControls,
  openEvidence,
});

// Bind page-level controls once. Inspector controls are rebound after each render.
$('#edit-policy').onclick = () => {
  $('#policy-json').value = JSON.stringify(state.policy, null, 2);
  $('#policy-error').textContent = '';
  $('#apply-policy').disabled = !state.engineReady;
  $('#policy-dialog').showModal();
};
$('#close-policy').onclick = () => $('#policy-dialog').close();
$('#policy-form').onsubmit = async (event) => {
  event.preventDefault();
  $('#apply-policy').disabled = true;
  try {
    const policy = JSON.parse($('#policy-json').value);
    const result = await callEngine('audit', { policy });
    state.policy = policy;
    state.policyModified = true;
    state.findings = result.findings;
    state.ruleResults = result.rule_results || [];
    state.revision++;
    $('#policy-dialog').close();
    render();
    notify('Network policy updated. Deterministic checks re-evaluated.');
  } catch (error) {
    $('#policy-error').textContent = error.message;
  } finally {
    $('#apply-policy').disabled = false;
  }
};
$('#search').oninput = renderSidebar;
$('#run-checks').onclick = () => runChecks();
$('#scope-filter').onchange = renderFindings;
$('#severity-filter').onchange = renderFindings;
document.querySelectorAll('[data-tab]').forEach(
  (button) =>
    (button.onclick = () => {
      state.tab = button.dataset.tab;
      renderInspector();
    }),
);
$('#reset-all').onclick = async () => {
  state.routers = clone(state.baseline.routers);
  state.policy = clone(state.baseline.policy);
  state.findings = clone(state.baseline.findings);
  state.originals = new Map(state.routers.map((r) => [r.name, clone(r)]));
  state.modified.clear();
  state.policyModified = false;
  state.revision++;
  if (!current()) state.selected = state.routers[0]?.name || null;
  resetWorkbench();
  render();
  if (state.engineReady) await runChecks(false);
  notify('Workspace restored to the bundled snapshot.');
};
$('#download-workspace').onclick = () =>
  download(
    'semanticrouter-workspace.json',
    workspaceController()?.capture() || {
      routers: state.routers,
      policy: state.policy,
      ...workflowSnapshot(),
    },
  );
$('#download-report').onclick = () =>
  download('semanticrouter-report.json', {
    kind: 'configuration-only',
    rules: state.rules,
    rule_results: state.ruleResults,
    findings: state.findings,
    modified: [...state.modified],
  });
$('#upload-button').onclick = () => $('#import-dialog').showModal();
$('#close-import').onclick = () => $('#import-dialog').close();
$('#choose-files').onclick = () => $('#file-input').click();
$('#file-input').onchange = async (event) => {
  const files = [...event.target.files];
  if (!files.length) return;
  if (files.some((file) => file.size > 5 * 1024 * 1024)) {
    notify('Please choose config files smaller than 5 MB.', true);
    return;
  }
  if (files.length === 1) {
    $('#import-name').value = files[0].name.replace(/\.[^.]+$/, '');
    $('#import-text').value = await files[0].text();
  } else {
    try {
      for (const file of files)
        await importConfig(file.name.replace(/\.[^.]+$/, ''), await file.text());
      $('#import-dialog').close();
      render();
      await runChecks(false);
      notify('Loaded ' + files.length + ' exports locally in your browser.');
    } catch (error) {
      notify(error.message, true);
    }
  }
  event.target.value = '';
};
$('#import-form').onsubmit = async (event) => {
  event.preventDefault();
  $('#import-submit').disabled = true;
  try {
    await importConfig(
      $('#import-name').value.trim(),
      $('#import-text').value,
      $('#import-version').value.trim(),
    );
    $('#import-dialog').close();
    render();
    await runChecks(false);
    notify('Export parsed into semantic objects locally. Policy checks updated.');
  } catch (error) {
    notify(error.message, true);
  } finally {
    $('#import-submit').disabled = false;
  }
};

main();
