/** Small DOM boundary: escape untrusted model strings and download explicit user artifacts. */
export const $ = (selector) => document.querySelector(selector);
export const esc = (value) =>
  String(value ?? '').replace(
    /[&<>"']/g,
    (ch) =>
      ({ '&': '&amp;', '<': '&lt;', '>': '&gt;', '"': '&quot;', "'": '&#39;' })[ch],
  );

/** Show user-facing progress or errors as plain text; never inject exception HTML. */
export function notify(message, error = false) {
  const box = $('#notice');
  box.textContent = message;
  box.classList.toggle('error', error);
  box.hidden = !message;
}

/** Update the runtime lifecycle indicator independently of the snapshot renderer. */
export function engineStatus(text) {
  $('#engine-status').textContent = text;
}

/** Create an explicitly requested local artifact and release its temporary object URL. */
export function download(name, value) {
  const blob = new Blob(
    [typeof value === 'string' ? value : JSON.stringify(value, null, 2)],
    { type: typeof value === 'string' ? 'text/plain' : 'application/json' },
  );
  const url = URL.createObjectURL(blob);
  const link = document.createElement('a');
  link.href = url;
  link.download = name;
  link.click();
  setTimeout(() => URL.revokeObjectURL(url), 1000);
}
