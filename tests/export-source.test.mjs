/** Export-only access to originals; no credentials in model JSON or review text. */
import { test } from 'node:test';
import assert from 'node:assert/strict';
import { state } from '../playground/state.js';
import { getExportSource } from '../playground/engine.js';

test('complete export uses local originals or authenticated pinned sources without altering review copies', async () => {
  const originals = { fetch: globalThis.fetch, location: globalThis.location };
  globalThis.location = { href: 'https://example.invalid/visualiser/semanticrouter/' };
  try {
    state.sources = { demo: '/system identity set name=demo' };
    state.sourceRedacted = { demo: false };
    state.baseline = { sources: structuredClone(state.sources) };
    state.sourceHashes = { demo: 'snapshot-hash' };
    state.sourceURL = 'source.php';
    state.nativeSources = {};
    globalThis.fetch = () => {
      throw new Error('must not fetch a local original');
    };
    assert.equal(await getExportSource('demo'), state.sources.demo);
    const review = '/radius add secret="[REDACTED]"';
    state.sources.demo = review;
    state.baseline.sources.demo = review;
    state.sourceRedacted.demo = true;
    let calls = 0;
    globalThis.fetch = async (url, options) => {
      calls++;
      assert.equal(url.origin, 'https://example.invalid');
      assert.equal(url.searchParams.get('device'), 'demo');
      assert.equal(url.searchParams.get('hash'), 'snapshot-hash');
      assert.equal(options.credentials, 'same-origin');
      assert.equal(options.cache, 'no-store');
      return {
        ok: true,
        headers: { get: () => 'text/plain; charset=UTF-8' },
        text: async () => '/radius add secret=SYNTHETIC-ORIGINAL',
      };
    };
    assert.match(await getExportSource('demo'), /SYNTHETIC-ORIGINAL/);
    await getExportSource('demo');
    assert.equal(calls, 1, 'the pinned original is cached only in memory');
    assert.equal(
      state.sources.demo,
      review,
      'review text is not replaced with private fields',
    );
    state.sources.demo = review + '\n# user edited this';
    await assert.rejects(getExportSource('demo'), /review edits have been kept/);
    state.sources.demo = review;
    state.nativeSources = {};
    state.sourceURL = 'https://elsewhere.invalid/source';
    await assert.rejects(getExportSource('demo'), /this application/);
    state.sourceURL = 'source.php';
    state.sourceHashes = {};
    await assert.rejects(getExportSource('demo'), /original configuration/);
    state.sourceHashes = { demo: 'snapshot-hash' };
    globalThis.fetch = async () => ({
      ok: false,
      text: async () => 'Backup changed; rebuild snapshot.',
    });
    await assert.rejects(getExportSource('demo'), /Backup changed/);
    globalThis.fetch = async () => ({
      ok: true,
      headers: { get: () => 'text/html' },
      text: async () => 'Login',
    });
    await assert.rejects(getExportSource('demo'), /Visualiser login/);
  } finally {
    Object.assign(globalThis, originals);
  }
});
