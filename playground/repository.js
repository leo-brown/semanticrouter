/** Review-only Git sync. Parse every selected source and validate the complete
 * candidate before replacing any models. Local edits are conflicts, never silently
 * overwritten; removed upstream files require an explicit selection too.
 */
import { state, clone } from './state.js';
import { $, esc, notify } from './dom.js';
import { callEngine } from './engine.js';
import { teamRequest, teamAccount } from './team-client.js';
import { activeTeam, openTeams } from './teams.js';

const digest = async (value) =>
  [
    ...new Uint8Array(
      await crypto.subtle.digest('SHA-256', new TextEncoder().encode(value)),
    ),
  ]
    .map((byte) => byte.toString(16).padStart(2, '0'))
    .join('');
function canonical(value) {
  if (Array.isArray(value)) return value.map(canonical);
  if (value && typeof value === 'object')
    return Object.fromEntries(
      Object.keys(value)
        .sort()
        .map((key) => [key, canonical(value[key])]),
    );
  return value;
}
export const modelDigest = (model) => digest(JSON.stringify(canonical(model)));
export function sameRepository(a, b) {
  return Boolean(
    a && b && ['url', 'branch', 'directory'].every((key) => a[key] === b[key]),
  );
}

/** Source and model fingerprints detect separate forms of local drift. Repository
 * paths identify tracked files; identical device basenames from different paths
 * cannot be assumed to be the same device without review.
 */
export async function repositoryPlan(pulled, snapshot, pendingNames = new Set()) {
  const previous = sameRepository(pulled.repository, snapshot.git?.repository)
    ? snapshot.git.tracked || {}
    : {};
  const rows = [];
  const models = new Map(snapshot.routers.map((router) => [router.name, router]));
  const incoming = new Set(pulled.files.map((file) => file.path));
  for (const file of pulled.files) {
    const router = models.get(file.name),
      tracked = previous[file.path];
    const localMatches =
      tracked &&
      tracked.name === file.name &&
      !pendingNames.has(file.name) &&
      (await digest(snapshot.sources?.[file.name] || '')) === tracked.sourceHash &&
      (await modelDigest(router || null)) === tracked.modelHash;
    const status = !router
      ? 'added'
      : !localMatches
        ? 'conflict'
        : file.sha256 === tracked.sourceHash
          ? 'unchanged'
          : 'changed';
    rows.push({
      ...file,
      status,
      selected: ['added', 'changed'].includes(status),
      deleted: false,
    });
  }
  for (const [path, tracked] of Object.entries(previous)) {
    if (incoming.has(path) || !models.has(tracked.name)) continue;
    const matches =
      !pendingNames.has(tracked.name) &&
      (await digest(snapshot.sources?.[tracked.name] || '')) === tracked.sourceHash &&
      (await modelDigest(models.get(tracked.name))) === tracked.modelHash;
    rows.push({
      name: tracked.name,
      path,
      status: matches ? 'removed' : 'conflict',
      selected: false,
      deleted: true,
    });
  }
  return rows;
}
let controller,
  hooks,
  preview = null;
function stillCurrent() {
  if (
    !preview ||
    preview.workspace !== state.workspace.id ||
    preview.revision !== state.revision
  )
    throw new Error(
      'The workspace changed. Preview repository changes again before importing.',
    );
}
export function initializeRepository(workspaces, callbacks) {
  controller = workspaces;
  hooks = callbacks;
  $('#repo-sync').onclick = async () => {
    if (!document.body.dataset.teamApi || !teamAccount() || !activeTeam()) {
      await openTeams();
      return;
    }
    $('#repository-dialog').showModal();
    const repo = state.git?.repository || {};
    $('#repository-url').value = repo.url || '';
    $('#repository-branch').value = repo.branch || 'HEAD';
    $('#repository-directory').value = repo.directory ?? 'net-configs';
    $('#repository-error').textContent = '';
    $('#repository-preview').innerHTML = '';
    $('#repository-apply').hidden = true;
    preview = null;
  };
  $('#close-repository').onclick = () => $('#repository-dialog').close();
  $('#repository-form').onsubmit = async (event) => {
    event.preventDefault();
    $('#repository-fetch').disabled = true;
    $('#repository-error').textContent = '';
    $('#repository-preview').innerHTML = '';
    $('#repository-apply').hidden = true;
    const workspace = state.workspace.id,
      revision = state.revision;
    try {
      const pulled = await teamRequest('git_pull', {
        team_id: activeTeam(),
        url: $('#repository-url').value.trim(),
        branch: $('#repository-branch').value.trim() || 'HEAD',
        directory: $('#repository-directory').value.trim(),
      });
      if (workspace !== state.workspace.id || revision !== state.revision)
        throw new Error('The workspace changed. Fetch a fresh preview.');
      const rows = await repositoryPlan(
        pulled,
        controller.capture(),
        hooks.pendingNames(),
      );
      preview = { workspace, revision, pulled, rows };
      $('#repository-preview').innerHTML =
        `<p class="helper">Fetched commit <code>${esc(pulled.repository.commit.slice(0, 12))}</code>. Select configs to import. Conflicts replace local source/model edits; removals delete the device.</p><div class="repository-files">${rows.map((row, index) => `<label class="repository-file"><input type="checkbox" data-repository-file="${index}" ${row.selected ? 'checked' : ''}><span><strong>${esc(row.name)}</strong><small>${esc(row.path)}</small></span><span class="repository-status ${row.status}">${row.deleted ? 'removed · ' : ''}${row.status}</span></label>`).join('')}</div>`;
      $('#repository-preview')
        .querySelectorAll('[data-repository-file]')
        .forEach(
          (input) =>
            (input.onchange = () =>
              (rows[Number(input.dataset.repositoryFile)].selected = input.checked)),
        );
      $('#repository-apply').hidden = false;
    } catch (error) {
      $('#repository-error').textContent = error.message;
    } finally {
      $('#repository-fetch').disabled = false;
    }
  };
  $('#repository-apply').onclick = async () => {
    $('#repository-apply').disabled = true;
    try {
      stillCurrent();
      const chosen = preview.rows.filter((row) => row.selected);
      if (!chosen.length) throw new Error('Select at least one config.');
      const snapshot = controller.capture();
      const tracked = sameRepository(
        snapshot.git?.repository,
        preview.pulled.repository,
      )
        ? clone(snapshot.git.tracked || {})
        : {};
      const modified = new Set(snapshot.modified || []);
      for (const row of chosen) {
        if (row.deleted) {
          snapshot.routers = snapshot.routers.filter(
            (router) => router.name !== row.name,
          );
          delete snapshot.sources[row.name];
          delete snapshot.source_redacted[row.name];
          delete snapshot.source_hashes[row.name];
          delete tracked[row.path];
          modified.delete(row.name);
        } else {
          const { router } = await callEngine('import', {
            name: row.name,
            text: row.text,
          });
          snapshot.routers = snapshot.routers
            .filter((item) => item.name !== row.name)
            .concat(router);
          snapshot.sources[row.name] = row.text;
          snapshot.source_redacted[row.name] = false;
          delete snapshot.source_hashes[row.name];
          tracked[row.path] = {
            name: row.name,
            sourceHash: row.sha256,
            modelHash: await modelDigest(router),
          };
          modified.add(row.name);
        }
      }
      await callEngine('audit', {
        routers: snapshot.routers,
        policy: snapshot.policy,
        rules: snapshot.rules,
      });
      stillCurrent();
      snapshot.git = { repository: preview.pulled.repository, tracked };
      snapshot.modified = [...modified];
      hooks.discardDrafts(chosen.map((row) => row.name));
      await controller.replaceSnapshot(snapshot);
      $('#repository-dialog').close();
      notify(
        'Imported ' +
          chosen.length +
          ' repository changes. Tests now use the updated models. Save the workspace to retain them.',
      );
    } catch (error) {
      $('#repository-error').textContent = error.message;
    } finally {
      $('#repository-apply').disabled = false;
    }
  };
}
