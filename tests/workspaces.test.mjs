import { test } from 'node:test';
import assert from 'node:assert/strict';
import {
  WorkspaceStore,
  blankSnapshot,
  checkSnapshot,
} from '../playground/workspaces.js';
import { repositoryPlan, modelDigest } from '../playground/repository.js';

function storage() {
  const values = new Map();
  return {
    getItem: (key) => values.get(key),
    setItem: (key, value) => values.set(key, value),
  };
}
test('named workspaces retain empty projects, isolate accounts and detect stale saves', () => {
  const data = storage(),
    first = new WorkspaceStore(data, 'first'),
    other = new WorkspaceStore(data, 'second');
  const record = first.save(
    { id: 'example', name: 'Lab', snapshot: blankSnapshot() },
    0,
  );
  assert.equal(record.revision, 1);
  assert.equal(first.list()[0].name, 'Lab');
  assert.deepEqual(other.list(), []);
  const copy = first.get('example');
  copy.snapshot.rules.push({ id: 'local-change' });
  assert.equal(first.get('example').snapshot.rules.length, 0, 'callers receive a copy');
  first.save({ ...record, name: 'Renamed' }, 1);
  assert.throws(() => first.save(record, 1), /another tab/);
  assert.equal(first.get('example').name, 'Renamed');
  assert.throws(
    () => checkSnapshot({ routers: [{ name: 'same' }, { name: 'same' }] }),
    /unique/,
  );
});
test('failed browser writes never pretend a workspace was saved', () => {
  const store = new WorkspaceStore({
    getItem: () => null,
    setItem: () => {
      throw new Error('Quota exceeded');
    },
  });
  assert.throws(
    () => store.save({ id: 'test', name: 'Lab', snapshot: blankSnapshot() }, 0),
    /Quota/,
  );
});
test('Git plans preserve local edits, require explicit removals and distinguish unchanged files', async () => {
  const text = '/system identity set name=router';
  const bytes = new Uint8Array(
    await crypto.subtle.digest('SHA-256', new TextEncoder().encode(text)),
  );
  const hash = [...bytes].map((value) => value.toString(16).padStart(2, '0')).join('');
  const model = { name: 'router', role: 'nni', interfaces: [] };
  const repo = {
    url: 'ssh://git@github.com/team/configs.git',
    branch: 'main',
    directory: 'configs',
  };
  const tracked = {
    'configs/router.cfg': {
      name: 'router',
      sourceHash: hash,
      modelHash: await modelDigest(model),
    },
  };
  const snapshot = {
    routers: [model],
    sources: { router: text },
    git: { repository: repo, tracked },
  };
  const pulled = {
    repository: repo,
    files: [{ name: 'router', path: 'configs/router.cfg', text, sha256: hash }],
  };
  assert.equal((await repositoryPlan(pulled, snapshot))[0].status, 'unchanged');
  const changed = structuredClone(pulled);
  changed.files[0].sha256 = 'upstream-change';
  assert.equal((await repositoryPlan(changed, snapshot))[0].selected, true);
  assert.equal(
    (await repositoryPlan(changed, snapshot, new Set(['router'])))[0].status,
    'conflict',
  );
  const local = structuredClone(snapshot);
  local.routers[0].role = 'switch';
  const conflict = (await repositoryPlan(changed, local))[0];
  assert.equal(conflict.status, 'conflict');
  assert.equal(conflict.selected, false);
  const removed = (await repositoryPlan({ repository: repo, files: [] }, snapshot))[0];
  assert.equal(removed.status, 'removed');
  assert.equal(removed.selected, false);
  const fresh = { ...snapshot, routers: [], sources: {} };
  assert.equal((await repositoryPlan(pulled, fresh))[0].status, 'added');
});
