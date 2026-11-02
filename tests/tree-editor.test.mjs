/** Draft operations are independent of the browser and Python's rule validator.
 * These cases exercise edits across linked views, invalid text, and data safety.
 */
import { test } from 'node:test';
import assert from 'node:assert/strict';
import {
  TreeDocument,
  expression,
  operators,
  mountTreeEditor,
} from '../playground/tree-editor.js';

const rule = () => ({
  id: 'test',
  params: { pollers: ['198.51.100.9'] },
  assert: {
    type: 'expression',
    test: { op: 'eq', args: [{ ref: 'router.name' }, 'test'] },
  },
});

test('subtree edits, types and ordering share one definition and undo history', () => {
  const doc = new TreeDocument(rule());
  doc.add(['params'], 'enabled', false);
  doc.add(['params', 'pollers'], '', '203.0.113.9');
  doc.move(['params', 'pollers', 1], -1);
  doc.rename(['params', 'enabled'], 'required');
  doc.replace(['assert', 'test', 'args', 1], 1500);
  assert.equal(doc.getValue().params.required, false);
  assert.deepEqual(doc.getValue().params.pollers, ['203.0.113.9', '198.51.100.9']);
  assert.equal(doc.getValue().assert.test.args[1], 1500);
  doc.undo();
  assert.equal(doc.at(['assert', 'test', 'args', 1]), 'test');
  doc.undo();
  assert.equal(doc.at(['params', 'enabled']), false);
  doc.redo();
  assert.equal(doc.at(['params', 'required']), false);
  doc.remove(['params', 'pollers', 0]);
  assert.deepEqual(doc.at(['params', 'pollers']), ['198.51.100.9']);
  assert.throws(() => doc.rename(['params', 'required'], 'pollers'), /unique/);
  assert.throws(() => doc.add(['params'], 'pollers', []), /exists/);
});

test('invalid subtree JSON stays available, blocks save and cannot be overwritten by another view', () => {
  const doc = new TreeDocument(rule());
  const path = ['assert', 'test'];
  doc.editJSON(path, '{ unfinished');
  assert.equal(doc.text(path), '{ unfinished');
  assert.throws(() => doc.getValue(), /highlighted/);
  assert.throws(() => doc.replace(['params'], {}), /highlighted/);
  doc.editJSON([], JSON.stringify({ ...rule(), name: 'other edit' }));
  assert.equal(doc.valid, false);
  assert.equal(
    doc.at(['name']),
    null,
    'other JSON editor cannot silently overwrite invalid text',
  );
  doc.undo();
  assert.equal(doc.valid, true);
  assert.deepEqual(doc.getValue(), rule());
  doc.editJSON(path, JSON.stringify({ op: 'and', args: [true, false] }));
  assert.equal(doc.getValue().assert.test.op, 'and');
  doc.replace(['assert', 'test', 'args', 1], true);
  assert.equal(
    JSON.parse(doc.text(path)).args[1],
    true,
    'stale valid JSON buffers are refreshed after tree edits',
  );
});

test('all supported expression operators create correct editable shapes', () => {
  for (const [op, [, arity]] of Object.entries(operators)) {
    const node = expression(op);
    if (arity === 'binding')
      assert.deepEqual(Object.keys(node), ['op', 'items', 'as', 'test']);
    else assert.equal(node.args.length, arity ?? 1);
  }
  assert.deepEqual(expression('ref'), { ref: 'router.identity' });
  assert.deepEqual(expression('ne', { args: [1, 2] }).args, [1, 2]);
});

test('property operations preserve special JSON keys without modifying prototypes', () => {
  const doc = new TreeDocument({ params: {} });
  doc.add(['params'], '__proto__', { polluted: true });
  doc.add(['params'], 'constructor', 'value');
  doc.rename(['params', 'constructor'], 'prototype');
  assert.equal({}.polluted, undefined);
  assert.equal(Object.getPrototypeOf(doc.getValue().params), Object.prototype);
  assert.equal(doc.getValue().params.__proto__.polluted, true);
  assert.equal(doc.getValue().params.prototype, 'value');
  assert.throws(() => doc.replace(['params', 'number'], Infinity), /valid JSON/);
  let deep = false;
  for (let n = 0; n < 50; n++) deep = [deep];
  assert.throws(() => doc.replace([], deep), /limit/);
});

test('linked tree and JSON controls synchronize; invalid buffers and mode survive remount', () => {
  const previous = globalThis.document;
  const elements = new Map();
  const element = (id) => {
    if (!elements.has(id))
      elements.set(id, {
        innerHTML: '',
        value: '',
        hidden: false,
        setAttribute() {},
        contains: () => true,
      });
    return elements.get(id);
  };
  globalThis.document = { querySelector: element };
  try {
    const doc = new TreeDocument(rule());
    const full = element('#full'),
      logic = element('#logic');
    const first = mountTreeEditor({
      container: full,
      id: 'definition',
      document: doc,
      label: 'Definition',
    });
    let second = mountTreeEditor({
      container: logic,
      id: 'expression',
      document: doc,
      path: ['assert', 'test'],
      label: 'Logic',
      expressionMode: true,
    });
    assert.match(full.innerHTML, /data-tree-action="add"/);
    assert.match(logic.innerHTML, /Equals/);
    // Use the actual delegated value handler, rather than mutating the document.
    const token = logic.innerHTML.match(
      /data-tree-node="(\d+)" aria-label="Argument 2" type="text"/,
    )[1];
    logic.onchange({
      target: { dataset: { treeEdit: 'value', treeNode: token }, value: 'changed' },
    });
    assert.equal(
      JSON.parse(element('#definition').value).assert.test.args[1],
      'changed',
    );
    element('#expression').value = '{ incomplete';
    element('#expression').oninput();
    assert.equal(element('#expression').hidden, false);
    assert.equal(element('#expression-undo').disabled, false);
    assert.throws(() => doc.getValue());
    second.destroy();
    second = mountTreeEditor({
      container: logic,
      id: 'expression',
      document: doc,
      path: ['assert', 'test'],
      label: 'Logic',
      expressionMode: true,
    });
    assert.equal(element('#expression').value, '{ incomplete');
    assert.equal(element('#expression').hidden, false);
    element('#expression').value = JSON.stringify(expression('and'));
    element('#expression').oninput();
    assert.equal(doc.valid, true);
    assert.equal(JSON.parse(element('#definition').value).assert.test.op, 'and');
    first.destroy();
    second.destroy();
  } finally {
    globalThis.document = previous;
  }
});

test('a missing optional parameters object can be authored without JSON', () => {
  const doc = new TreeDocument({ id: 'example' });
  doc.add(['params'], 'pollers', ['198.51.100.9']);
  assert.deepEqual(doc.getValue().params, { pollers: ['198.51.100.9'] });
  doc.undo();
  assert.deepEqual(doc.getValue(), { id: 'example' });
});
