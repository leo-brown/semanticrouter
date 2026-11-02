/** Same-origin team transport. Passwords/invitation tokens are sent only in explicit
 * POSTs and never persisted in browser storage. CSRF tokens remain session-local.
 */
let token = '',
  account = null;
const reads = new Set(['session', 'bootstrap', 'workspaces', 'workspace']);
export function teamAccount() {
  return account;
}
export async function teamRequest(action, values = {}) {
  const endpoint = document.body.dataset.teamApi || 'api.php';
  const url = new URL(endpoint, location.href);
  if (url.origin !== new URL(location.href).origin)
    throw new Error('Team API must use this application’s origin.');
  const read = reads.has(action);
  const options = { credentials: 'same-origin', cache: 'no-store' };
  if (read) {
    url.searchParams.set('action', action);
    for (const [key, value] of Object.entries(values)) url.searchParams.set(key, value);
  } else {
    options.method = 'POST';
    options.headers = { 'Content-Type': 'application/json', 'X-CSRF-Token': token };
    options.body = JSON.stringify({ action, ...values });
  }
  const response = await fetch(url, options);
  let data;
  try {
    data = await response.json();
  } catch {
    throw new Error('Team service is unavailable.');
  }
  if (!response.ok || !data.ok) throw new Error(data.error || 'Team request failed.');
  if (data.csrf) token = data.csrf;
  if (Object.hasOwn(data, 'user')) account = data.user;
  return data;
}
