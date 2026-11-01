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
