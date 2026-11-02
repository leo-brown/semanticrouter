/** Named browser workspaces. Saved models/rules are portable JSON; editor drafts
 * stay in per-workspace memory. Hosted original caches never enter a saved record.
 * Python validates snapshots before switching, including deliberately empty ones.
 */
import { state, clone } from './state.js';
import { $, esc, notify } from './dom.js';

export const WORKSPACE_KEY = 'semanticrouter-workspaces-v1';
export function workspaceName(value) {
  const name = String(value || '').trim();
  if (!name || name.length > 100)
    throw new Error('Use a workspace name between 1 and 100 characters.');
  return name;
}
export function checkSnapshot(value) {
  if (!value || !Array.isArray(value.routers) || !Array.isArray(value.rules || []))
    throw new Error('A workspace needs router and rule arrays.');
  const names = value.routers.map((router) => router?.name);
  if (
    names.some((name) => typeof name !== 'string' || !name) ||
    new Set(names).size !== names.length
  )
    throw new Error('Router names must be nonempty and unique.');
  if (
    value.sources &&
    (typeof value.sources !== 'object' ||
      Array.isArray(value.sources) ||
      Object.values(value.sources).some((text) => typeof text !== 'string'))
  )
    throw new Error('Sources must map router names to config text.');
  if (JSON.stringify(value).length > 10 * 1024 * 1024)
    throw new Error('Use a workspace smaller than 10 MB.');
  return value;
}
export const blankSnapshot = () => ({
  routers: [],
  rules: [],
  policy: {},
  sources: {},
  source_redacted: {},
  source_hashes: {},
  findings: [],
  rule_results: [],
  mode: 'New workspace',
});

/** Optimistic revisions catch saves from another tab; a failed storage write must
 * not replace in-memory work or claim success. Never silently reset corrupt data. */
export class WorkspaceStore {
  constructor(storage, key = WORKSPACE_KEY) {
    this.storage = storage;
    this.key = key;
  }
  read() {
    const value = JSON.parse(
      this.storage.getItem(this.key) || '{"version":1,"entries":[],"active":null}',
    );
    if (value.version !== 1 || !Array.isArray(value.entries))
      throw new Error(
        'Saved workspace index is invalid. Export your current work before resetting browser storage.',
      );
    return value;
  }
  list() {
    return this.read().entries.map(({ snapshot, baseline, ...entry }) => entry);
  }
  get(id) {
    return clone(this.read().entries.find((entry) => entry.id === id) || null);
  }
  save(record, expectedRevision) {
    checkSnapshot(record.snapshot);
    const data = this.read(),
      old = data.entries.find((entry) => entry.id === record.id);
    if (expectedRevision !== undefined && (old?.revision || 0) !== expectedRevision)
      throw new Error(
        'This workspace changed in another tab. Export your edits before reopening its latest saved version.',
      );
    const saved = {
      ...clone(record),
      name: workspaceName(record.name),
      revision: (old?.revision || 0) + 1,
      updated_at: new Date().toISOString(),
    };
    data.entries = data.entries.filter((entry) => entry.id !== record.id).concat(saved);
    data.active = record.id;
    this.storage.setItem(this.key, JSON.stringify(data));
    return clone(saved);
  }
  activate(id) {
    const data = this.read();
    data.active = id;
    this.storage.setItem(this.key, JSON.stringify(data));
  }
}

let hooks,
  store,
  bundled,
  sessions = new Map(),
  initialActive,
  controller,
  remoteSaver;
const id = () => 'workspace-' + crypto.randomUUID();
function metadata(record) {
  return {
    id: record.id,
    name: record.name,
    revision: record.revision,
    scope: record.scope || 'local',
    teamId: record.teamId,
    remoteId: record.remoteId,
    remoteRevision: record.remoteRevision,
  };
}
function capture() {
  return {
    ...hooks.snapshot(),
    name: state.workspace.name,
    selected: state.selected,
    modified: [...state.modified],
    git: clone(state.git || null),
  };
}
async function saveCurrent() {
  if (state.workspace.scope === 'team') {
    if (!remoteSaver) throw new Error('Sign in before saving this team workspace.');
    Object.assign(state.workspace, await remoteSaver(state.workspace));
  }
  const record = store.save(
    { ...state.workspace, snapshot: capture(), baseline: state.baseline },
    state.workspace.revision || 0,
  );
  state.workspace = metadata(record);
  renderWorkspaceControls();
  return record;
}
async function apply(record) {
  checkSnapshot(record.baseline || record.snapshot);
  const revision = state.revision,
    previousId = state.workspace.id;
  await hooks.validate(record.snapshot);
  if (revision !== state.revision || previousId !== state.workspace.id)
    throw new Error(
      'The workspace changed while opening. Try again; your current edits are intact.',
    );
  sessions.set(state.workspace.id, hooks.captureDrafts());
  hooks.restoreDrafts(null);
  await hooks.apply(
    record.snapshot,
    record.baseline || record.snapshot,
    metadata(record),
  );
  hooks.restoreDrafts(sessions.get(record.id));
  state.git = clone(record.snapshot.git || null);
  store.activate(record.id);
  renderWorkspaceControls();
  hooks.render();
}
export function renderWorkspaceControls() {
  if (!store || !state.workspace) return;
  try {
    const entries = store.list();
    if (!entries.some((entry) => entry.id === bundled.id))
      entries.unshift({ id: bundled.id, name: bundled.name });
    if (!entries.some((entry) => entry.id === state.workspace.id))
      entries.push(state.workspace);
    $('#workspace-select').innerHTML = entries
      .map(
        (entry) =>
          `<option value="${esc(entry.id)}"${entry.id === state.workspace.id ? ' selected' : ''}>${esc(entry.name)}</option>`,
      )
      .join('');
    $('#workspace-select').value = state.workspace.id;
    $('#workspace-location').textContent =
      state.workspace.scope === 'team' ? 'Team workspace' : 'Saved in this browser';
  } catch (error) {
    notify(error.message, true);
  }
}

/** Bind workspace controls once; restoring a saved active workspace waits until the
 * real Python engine is available, rather than trusting unvalidated stored JSON. */
export function initializeWorkspaces(data, callbacks) {
  hooks = callbacks;
  store = new WorkspaceStore(
    localStorage,
    WORKSPACE_KEY + ':' + (data.workspace_namespace || 'browser'),
  );
  bundled = {
    id: data.workspace_id || 'bf-network',
    name: data.workspace_name || 'BF network overview',
    snapshot: clone(data),
    baseline: clone(data),
    revision: 0,
  };
  state.workspace = metadata(bundled);
  try {
    initialActive = store.read().active;
  } catch (error) {
    notify(error.message, true);
  }
  renderWorkspaceControls();
  $('#workspace-select').onchange = async () => {
    const next = $('#workspace-select').value;
    if (next === state.workspace.id) return;
    try {
      await saveCurrent();
      const record = store.get(next) || (next === bundled.id ? bundled : null);
      if (!record) throw new Error('Workspace no longer exists.');
      await apply(record);
      notify('Opened ' + state.workspace.name + '.');
    } catch (error) {
      renderWorkspaceControls();
      notify(error.message, true);
    }
  };
  $('#save-workspace').onclick = async () => {
    try {
      await saveCurrent();
      notify('Workspace saved in this browser.');
    } catch (error) {
      notify('Workspace was not saved: ' + error.message, true);
    }
  };
  $('#new-workspace').onclick = () => {
    $('#workspace-name').value = '';
    $('#workspace-template').value = 'blank';
    $('#workspace-error').textContent = '';
    $('#workspace-dialog').showModal();
    $('#workspace-name').focus();
  };
  $('#close-workspace').onclick = () => $('#workspace-dialog').close();
  $('#workspace-create').onsubmit = async (event) => {
    event.preventDefault();
    const submit = $('#create-workspace');
    submit.disabled = true;
    try {
      const name = workspaceName($('#workspace-name').value);
      const snapshot =
        $('#workspace-template').value === 'current' ? capture() : blankSnapshot();
      await hooks.validate(snapshot);
      await saveCurrent();
      const record = store.save(
        { id: id(), name, scope: 'local', snapshot, baseline: clone(snapshot) },
        0,
      );
      await apply(record);
      $('#workspace-dialog').close();
      notify('Created ' + name + '. Add tests and load configs to begin.');
    } catch (error) {
      $('#workspace-error').textContent = error.message;
    } finally {
      submit.disabled = false;
    }
  };
  controller = {
    async restoreActive() {
      if (!initialActive) return;
      const record = store.get(initialActive);
      if (record) await apply(record);
    },
    async importSnapshot(snapshot) {
      checkSnapshot(snapshot);
      await hooks.validate(snapshot);
      await saveCurrent();
      const record = store.save(
        {
          id: id(),
          name: snapshot.name || 'Imported workspace',
          scope: 'local',
          snapshot,
          baseline: clone(snapshot),
        },
        0,
      );
      await apply(record);
    },
    async openRecord(record, { stash = true } = {}) {
      if (stash) await saveCurrent();
      const existing = store.get(record.id);
      const saved = store.save(record, existing?.revision || 0);
      await apply(saved);
    },
    async replaceSnapshot(snapshot, baseline = snapshot) {
      await apply({ ...state.workspace, snapshot, baseline });
    },
    setRemoteSaver(saver) {
      remoteSaver = saver;
    },
    save: saveCurrent,
    capture,
    apply,
    createId: id,
    get store() {
      return store;
    },
  };
  return controller;
}
export function workspaceController() {
  return controller;
}
