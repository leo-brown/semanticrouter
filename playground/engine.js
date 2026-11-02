/** JSON-only worker transport. Policy evaluation stays in Python, never in this UI layer.
 * Requests are correlated by id; raw user strings are passed as data, not executable code.
 */
import { state } from './state.js';
import { notify, engineStatus } from './dom.js';
let worker,
  requestId = 0;
const pending = new Map();

/** Start one module worker and wire request correlation before asking it to boot.
 * A server-supplied runtime base supports authenticated PHP MIME delivery; static builds
 * use the same-origin runtime directory. Worker failures reject outstanding requests. */
export function startEngine(onReady, onFailure) {
  const workerURL = new URL('./engine-worker.js', location.href);
  if (document.body.dataset.runtimeBase)
    workerURL.searchParams.set('runtime', document.body.dataset.runtimeBase);
  worker = new Worker(workerURL, { type: 'module' });
  worker.onmessage = ({ data }) => {
    if (data.type === 'ready') {
      state.engineReady = true;
      engineStatus('Python engine ready');
      onReady();
      return;
    }
    if (data.id && pending.has(data.id)) {
      const { resolve, reject } = pending.get(data.id);
      pending.delete(data.id);
      data.ok ? resolve(data) : reject(new Error(data.error));
    } else if (data.type === 'error') {
      state.engineReady = false;
      engineStatus('Engine unavailable · refresh to retry');
      notify(
        'The Python engine could not start. The snapshot is still viewable. ' +
          data.error,
        true,
      );
      onFailure();
    }
  };
  worker.onerror = (event) => {
    state.engineReady = false;
    engineStatus('Engine unavailable · refresh to retry');
    notify('Unable to start the browser Python engine. ' + event.message, true);
    for (const { reject } of pending.values())
      reject(new Error('Python worker failed'));
    pending.clear();
    onFailure();
  };
  worker.postMessage({ action: 'boot' });
}

/** Send a structured-cloned workspace snapshot to Python and return a correlated Promise.
 * Actions and payloads are data. No user input is concatenated into executable Python. */
export function callEngine(action, extra = {}) {
  if (!state.engineReady)
    return Promise.reject(
      new Error('The Python engine is still loading. Please wait.'),
    );
  const id = ++requestId;
  return new Promise((resolve, reject) => {
    pending.set(id, { resolve, reject });
    worker.postMessage({
      id,
      action,
      routers: state.routers,
      policy: state.policy,
      selected: state.selected,
      rules: state.rules || [],
      ...extra,
    });
  });
}

/** Obtain original syntax only on explicit RouterOS export, never during audits.
 * Hosted originals are authenticated and pinned to the build's source hash. Local
 * originals stay in memory; a redacted/edited review is never passed as complete. */
export async function getExportSource(name) {
  const text = state.sources[name];
  if (typeof text === 'string' && !state.sourceRedacted[name]) return text;
  if (state.sourceRedacted[name] && text !== state.baseline.sources?.[name])
    throw new Error(
      'This redacted source was edited. Load the original export before producing a complete configuration; your review edits have been kept.',
    );
  const hash = state.sourceHashes[name];
  if (!state.sourceURL || !hash)
    throw new Error(
      'Load the original configuration to produce a complete export. This workspace contains only a redacted review copy.',
    );
  const key = name + ':' + hash;
  if (state.nativeSources[key]) return state.nativeSources[key];
  const page = new URL(location.href);
  const url = new URL(state.sourceURL, page);
  if (url.origin !== page.origin)
    throw new Error('Original configs must come from this application.');
  url.searchParams.set('device', name);
  url.searchParams.set('hash', hash);
  const response = await fetch(url, { credentials: 'same-origin', cache: 'no-store' });
  if (!response.ok) throw new Error(await response.text());
  if (!response.headers.get('content-type')?.includes('text/plain'))
    throw new Error('Original source access requires the current Visualiser login.');
  const original = await response.text();
  if (original.length > 5 * 1024 * 1024)
    throw new Error('Original export exceeds 5 MB.');
  state.nativeSources[key] = original;
  return original;
}

export async function exportModel(values) {
  const revision = state.revision;
  const selected = state.selected;
  const source_text =
    values.vendor === 'routeros' ? await getExportSource(selected) : undefined;
  if (revision !== state.revision || selected !== state.selected)
    throw new Error(
      'The workspace changed while loading the original source. Run export again.',
    );
  return callEngine('export', { ...values, selected, source_text });
}
