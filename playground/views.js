/** Read-only rendering of the workspace, plus callbacks into application actions.
 * Views do not parse configs or evaluate policy. Dynamic text is HTML-escaped.
 * The callback boundary keeps worker transport and mutations out of templates.
 */
import { state, current, countFor } from './state.js';
import { $, esc } from './dom.js';
import { relationships } from './topology.js';
let actions;
/** Install action callbacks once so rendering never imports mutation or worker modules. */
export function configureViews(callbacks) {
  actions = callbacks;
}

/** Refresh all views from the current workspace; this function performs no network evaluation. */
function render() {
  renderSidebar();
  renderMetrics();
  renderMap();
  renderInspector();
  renderFindings();
  actions.renderWorkbench?.();
}

/** Render inventory search, selection and priority badges using escaped model names. */
function renderSidebar() {
  $('#device-count').textContent = state.routers.length + ' nodes';
  const query = $('#search').value.toLowerCase();
  let last = '';
  $('#device-list').innerHTML = state.routers
    .filter((r) => r.name.toLowerCase().includes(query))
    .map((r) => {
      const label =
        {
          edge: 'EDGE & CORE',
          core: 'EDGE & CORE',
          border: 'BORDERS',
          bng: 'SUBSCRIBER GATEWAYS',
          switch: 'DISTRIBUTION',
          sw: 'DISTRIBUTION',
        }[r.role] || 'OTHER NODES';
      const heading =
        label === last ? '' : `<div class="group-label">${esc(label)}</div>`;
      last = label;
      const count = countFor(r.name);
      return (
        heading +
        `<button class="device-row ${r.name === state.selected ? 'selected' : ''}" data-device="${esc(r.name)}" aria-pressed="${r.name === state.selected}"><span class="device-symbol">${r.role === 'switch' ? '▤' : '◇'}</span>${esc(r.name)}${state.modified.has(r.name) ? '<span class="device-modified">·</span>' : ''}${count ? `<span class="device-count">${count}</span>` : ''}</button>`
      );
    })
    .join('');
  $('#device-list')
    .querySelectorAll('[data-device]')
    .forEach(
      (button) => (button.onclick = () => actions.select(button.dataset.device)),
    );
}

/** Summarize reported findings; counts are not a percentage of checks passed. */
function renderMetrics() {
  $('#metric-routers').textContent = state.routers.length;
  $('#metric-peers').textContent =
    state.routers.reduce((n, r) => n + r.bgp.peers.length, 0) +
    ' configured BGP sessions';
  for (const [id, severity] of [
    ['p1', 'P1'],
    ['p2', 'P2'],
    ['unknown', 'UNKNOWN'],
  ])
    $('#metric-' + id).textContent = state.findings.filter(
      (f) => f.severity === severity,
    ).length;
}

/** Draw configuration relationships and explicitly inferred distribution uplinks.
 * Endpoint matching lives in topology.js. Colours never claim operational connectivity. */
function renderMap() {
  const positions = new Map();
  const groups = [
    state.routers.filter((r) => !['border', 'bng', 'switch', 'sw'].includes(r.role)),
    state.routers.filter((r) => r.role === 'border'),
    state.routers.filter((r) => r.role === 'bng'),
    state.routers.filter((r) => ['switch', 'sw'].includes(r.role)),
  ];
  const ys = [14, 37, 62, 87];
  groups.forEach((routers, row) =>
    routers.forEach((r, i) =>
      positions.set(r.name, { x: ((i + 1) * 100) / (routers.length + 1), y: ys[row] }),
    ),
  );
  const edges = relationships(state.routers);
  const lines = edges
    .map((edge) => {
      const a = positions.get(edge.a),
        b = positions.get(edge.b);
      if (!a || !b) return '';
      const good = edge.status === 'reciprocal',
        warning = edge.status === 'one-sided';
      const color = good ? '#4d9a84' : warning ? '#ca925a' : '#536c78';
      const dash =
        edge.inferred || edge.status === 'inactive'
          ? ' stroke-dasharray="1.1 1.1"'
          : '';
      return `<line x1="${a.x}" y1="${a.y}" x2="${b.x}" y2="${b.y}" stroke="${color}" stroke-width=".35"${dash}/>`;
    })
    .join('');
  $('#network-map').innerHTML =
    `<svg viewBox="0 0 100 100" preserveAspectRatio="none" aria-hidden="true">${lines}</svg>` +
    state.routers
      .map((r) => {
        const p = positions.get(r.name);
        const results = state.ruleResults.filter(
          (result) => result.device === r.name && result.status !== 'skip',
        );
        const testStatus = !results.length
          ? 'unvalidated'
          : results.some((result) => result.status === 'fail')
            ? 'has-issues'
            : results.some((result) => result.status === 'unknown')
              ? 'unresolved'
              : '';
        const testLabel = !results.length
          ? 'not tested'
          : testStatus === 'has-issues'
            ? 'tests failed'
            : testStatus === 'unresolved'
              ? 'tests unresolved'
              : 'selected tests passed';
        return `<button class="map-node ${r.name === state.selected ? 'selected' : ''}" data-node="${esc(r.name)}" style="left:${p.x}%;top:${p.y}%" aria-label="Inspect ${esc(r.name)} — ${testLabel}" aria-pressed="${r.name === state.selected}"><strong><i class="node-dot ${testStatus}"></i>${esc(r.name)}</strong><small>${esc(r.role.toUpperCase())}</small></button>`;
      })
      .join('');
  $('#network-map')
    .querySelectorAll('[data-node]')
    .forEach((button) => (button.onclick = () => actions.select(button.dataset.node)));
}

/** Build an expandable feature-domain section with caller-supplied escaped content. */
function card(title, count, body) {
  return `<details class="object-card" data-object-section="${esc(title)}" ${state.openObjectSections.has(title) ? 'open' : ''}><summary>${title}<span>${count}</span></summary><div class="object-content">${body || '<span class="muted">No explicit configuration</span>'}</div></details>`;
}

/** Escape a scalar model value before displaying it in the object inspector. */
function kv(key, value) {
  return `<div class="kv"><span>${esc(key)}</span><code>${esc(value ?? 'unknown')}</code></div>`;
}

/** Expose the represented fields and import limitations, including disabled and opaque rules. */
function renderObjects(r) {
  const fw = r.firewall_v4;
  const rules = fw.rules
    .map(
      (f, i) =>
        `<div class="rule ${f.enabled ? '' : 'disabled'}"><span class="muted">${i + 1}</span><span class="tag ${['drop', 'reject'].includes(f.action) ? 'drop' : ''}">${esc(f.action)}</span><code>${esc([f.chain, f.protocol, f.source_network || f.source_group, f.destination_ports ? '→ ' + f.destination_ports : '', f.ingress ? 'on ' + f.ingress : '', !f.enabled ? '(disabled)' : '', Object.keys(f.extra).length ? '[opaque predicates]' : ''].filter(Boolean).join(' · '))}</code></div>`,
    )
    .join('');
  const peers = r.bgp.peers
    .map(
      (p) =>
        `<div class="rule ${p.enabled ? '' : 'disabled'}"><span class="tag">${esc(p.role || 'BGP')}</span><code><b>${esc(p.name)}</b> → ${esc(p.remote_address || 'unknown')}<br>Redistribute: ${esc(p.redistribute.join(', ') || 'none explicit')}<br>IN ${esc(p.import_policy || '—')} / OUT ${esc(p.export_policy || '—')}</code></div>`,
    )
    .join('');
  return (
    card(
      'FirewallV4',
      fw.rules.length + ' rules',
      kv(
        'Connection tracking',
        fw.connection_tracking === null
          ? 'unknown'
          : fw.connection_tracking
            ? 'enabled'
            : 'disabled',
      ) + rules,
    ) +
    card('BGP', r.bgp.peers.length + ' peers', peers) +
    card(
      'Addresses',
      r.addresses.length,
      r.addresses
        .map((a) => kv(a.interface, a.address + (a.enabled ? '' : ' · disabled')))
        .join(''),
    ) +
    card(
      'Interfaces',
      r.interfaces.length,
      r.interfaces
        .map((i) =>
          kv(
            i.name,
            [i.kind, i.mode, !i.enabled ? 'disabled' : ''].filter(Boolean).join(' · '),
          ),
        )
        .join(''),
    ) +
    card(
      'PPP & RADIUS',
      r.ppp_servers.length + ' / ' + r.radius.length,
      r.ppp_servers
        .map((s) => kv(s.interface, 'MTU ' + (s.mtu ?? 'unknown')))
        .join('') +
        r.radius
          .map((s) =>
            kv(
              s.address,
              (s.timeout_ms ?? '?') + 'ms · ' + (s.source_address ?? 'unknown'),
            ),
          )
          .join(''),
    ) +
    card(
      'SNMP & DNS',
      'Services',
      kv(
        'SNMP',
        r.snmp_enabled === null ? 'unknown' : r.snmp_enabled ? 'enabled' : 'disabled',
      ) +
        kv('Location', r.snmp_location || 'not set') +
        kv('DNS', r.dns.join(', ') || 'not set'),
    ) +
    card(
      'Conversion support',
      r.unexported.length + ' conversion gaps',
      '<p class="helper">Open Export in the config flow to inspect the statements that need target mappings. </p>',
    )
  );
}

/** Build edit/probe controls from semantic fields. Binding is delegated to application actions. */
function renderExperiment(r) {
  const disabled = state.engineReady ? '' : 'disabled';
  return `<p class="helper">Change the semantic model, then re-run the heuristics. Your device configuration is never changed.</p>
  <div class="experiment-block"><h3>Quick experiments</h3><div class="inline-actions"><button class="button small" data-quick="final-drop" ${disabled}>Enable final input drop</button>${r.role === 'bng' ? `<button class="button small" data-quick="radius" ${disabled}>Use 500ms / 2000ms</button>` : ''}<button class="button small" data-quick="reset" ${disabled}>Reset this router</button></div></div>
  ${r.role === 'bng' ? `<div class="experiment-block"><h3>Subscriber settings</h3><label class="field">Connection tracking<select id="conntrack" ${disabled}><option value="null" ${r.firewall_v4.connection_tracking === null ? 'selected' : ''}>Unknown</option><option value="false" ${r.firewall_v4.connection_tracking === false ? 'selected' : ''}>Disabled</option><option value="true" ${r.firewall_v4.connection_tracking === true ? 'selected' : ''}>Enabled</option></select></label>${r.ppp_servers.map((s, i) => `<label class="field">PPPoE MTU · ${esc(s.interface)}<input type="number" min="576" max="9216" value="${s.mtu ?? ''}" data-mtu="${i}" ${disabled}></label>`).join('')}</div>` : ''}
  <div class="experiment-block"><h3>BGP sessions</h3>${r.bgp.peers.length ? r.bgp.peers.map((p, i) => `<label class="toggle-row"><span>${esc(p.name)} <span class="muted">${esc(p.remote_address || '')}</span></span><input type="checkbox" data-peer="${i}" ${p.enabled ? 'checked' : ''} ${disabled}></label>`).join('') : '<p class="muted">No BGP sessions in this model.</p>'}</div>
  <div class="experiment-block"><h3>Input firewall rules</h3>${r.firewall_v4.rules.map((f, i) => (f.chain === 'input' ? `<label class="toggle-row"><code>${i + 1}. ${esc([f.action, f.protocol, f.source_group || f.source_network, f.destination_ports, f.ingress].filter(Boolean).join(' · '))}</code><input type="checkbox" data-rule="${i}" ${f.enabled ? 'checked' : ''} ${disabled}></label>` : '')).join('') || '<p class="muted">No input rules.</p>'}</div>
  <div class="experiment-block"><h3>Test a packet</h3><p class="helper">Evaluate the ordered IPv4 input rules for a source and protocol. Unknown predicates remain unknown.</p><form id="packet-form"><label class="field">Source address<input id="probe-source" value="${esc(state.policy.snmp_pollers?.[0] || '198.51.100.9')}" required></label><div class="field-row"><label class="field">Protocol<select id="probe-protocol"><option>udp</option><option>tcp</option><option>icmp</option><option>ospf</option></select></label><label class="field">Destination port<input id="probe-port" type="number" min="0" max="65535" value="161" required></label></div><button class="button small" ${disabled}>Evaluate packet</button></form><div id="packet-result" role="status"></div></div>
  <div><h3>Test a route</h3><form id="route-form"><label class="field">Applied filter chain<select id="probe-chain">${[...new Set(r.bgp.policies.map((p) => p.chain))].map((c) => `<option>${esc(c)}</option>`).join('') || '<option value="">No policies</option>'}</select></label><label class="field">Route prefix<input id="probe-prefix" value="195.10.222.1/32" required></label><button class="button small" ${disabled}>Evaluate route</button></form><div id="route-result" role="status"></div></div>`;
}

/** Explain target limitations before offering a conversion preview or optional fragment. */
function renderExport() {
  return `<p class="helper">Render a supported configuration fragment from the current semantic model. Missing feature mappings remain explicit. No output is applied to a device.</p><form id="export-form"><div class="field-row"><label class="field">Target platform<select id="export-vendor"><option value="routeros">RouterOS</option><option value="cisco-ios">Cisco IOS · ACL</option></select></label><label class="field">Target version<input id="export-version" value="7.19.3" required></label></div><label class="toggle-row"><span>Allow a clearly labelled partial fragment</span><input id="export-partial" type="checkbox" checked></label><button class="button primary small" ${state.engineReady ? '' : 'disabled'}>Preview conversion</button></form><div id="export-result" role="status"></div><p class="model-note">RouterOS export targets 7.1–7.19 syntax. IOS export produces an unattached named ACL. Interfaces, PPP, RADIUS, SNMP and other inspection-only features block full export.</p>`;
}

/** Render only the selected tab, then install its action callbacks on the new controls.
 * Direct JSON edits are validated by Python before replacing the previous valid model. */
function renderInspector() {
  const r = current();
  if (!r) return;
  const content = $('#inspector-content');
  // Read the current DOM before replacing it: native toggle events can still be
  // queued when the user immediately selects another node or inspector tab.
  const remember = (section) => {
    const key = section.dataset.objectSection;
    if (section.open) state.openObjectSections.add(key);
    else state.openObjectSections.delete(key);
  };
  content.querySelectorAll('[data-object-section]').forEach(remember);
  $('#selected-role').textContent = r.role.toUpperCase() + ' / SEMANTIC ROUTER';
  $('#selected-name').textContent = r.name;
  $('#selected-platform').textContent =
    (r.platform.hardware || 'Hardware unknown') +
    ' · RouterOS ' +
    (r.platform.version || (r.platform.family || '?') + '.x');
  $('#edited-badge').hidden = !state.modified.has(r.name);
  document
    .querySelectorAll('[data-tab]')
    .forEach((b) => b.classList.toggle('active', b.dataset.tab === state.tab));
  if (state.tab === 'objects') {
    content.innerHTML = renderObjects(r);
    content.querySelectorAll('[data-object-section]').forEach((section) => {
      section.ontoggle = () => {
        // Ignore delayed events from the previous router's detached details nodes.
        if (section.isConnected) remember(section);
      };
    });
  }
  if (state.tab === 'experiment') {
    content.innerHTML = renderExperiment(r);
    actions.bindExperiments(r);
  }
  if (state.tab === 'export') {
    content.innerHTML = renderExport();
    actions.bindExport();
  }
  if (state.tab === 'json') {
    content.innerHTML = `<p class="helper">Edit the common model directly. Apply validates its structure and reruns the same Python checks across the workspace.</p><form id="model-form"><label class="field">Common model JSON<textarea id="model-json" class="json-editor" spellcheck="false"></textarea></label><div class="inline-actions"><button class="button primary small" ${state.engineReady ? '' : 'disabled'}>Apply & run checks</button><button type="button" class="button small" id="download-model">↓ Model</button></div></form><div id="model-error" class="error-text" role="status"></div>`;
    $('#model-json').value = JSON.stringify(r, null, 2);
    actions.bindModel(r);
  }
}

/** Filter existing Python findings and show source-line evidence without rerunning policy. */
function renderFindings() {
  const scope = $('#scope-filter').value,
    severity = $('#severity-filter').value;
  const items = state.findings.filter(
    (f) =>
      (scope !== 'selected' || f.device === state.selected) &&
      (severity === 'all' || f.severity === severity),
  );
  const order = { P1: 0, P2: 1, UNKNOWN: 2 };
  items.sort((a, b) => order[a.severity] - order[b.severity]);
  $('#findings-count').textContent = items.length;
  $('#findings-body').innerHTML =
    items
      .map(
        (f) =>
          `<tr><td><span class="severity ${esc(f.severity)}">${esc(f.severity)}</span></td><td><button class="table-device" data-finding-device="${esc(f.device)}">${esc(f.device)}</button></td><td>${esc(f.check)}</td><td>${esc(f.message)}</td><td><button class="evidence-link" data-evidence="${state.findings.indexOf(f)}">${f.rule_id ? 'Open rule' : f.source ? esc(f.source.path.split('/').pop() + ':' + f.source.line) : 'Inspect model'}</button></td></tr>`,
      )
      .join('') ||
    '<tr><td colspan="5"><div class="empty-state">No findings match this view. Unknowns remain separate from passes.</div></td></tr>';
  $('#findings-body')
    .querySelectorAll('[data-finding-device]')
    .forEach((b) => (b.onclick = () => actions.select(b.dataset.findingDevice)));
  $('#findings-body')
    .querySelectorAll('[data-evidence]')
    .forEach(
      (button) =>
        (button.onclick = () =>
          actions.openEvidence?.(state.findings[Number(button.dataset.evidence)])),
    );
  $('#check-summary').textContent =
    (state.engineReady
      ? 'Same Python policy engine as the CLI'
      : 'Baseline snapshot · Python engine is loading') +
    ' · ' +
    state.routers.length +
    ' models · ' +
    state.modified.size +
    ' modified' +
    (state.policyModified ? ' · policy edited' : '') +
    ' · no connectivity probes';
}
export {
  render,
  renderSidebar,
  renderMetrics,
  renderMap,
  renderInspector,
  renderFindings,
};
