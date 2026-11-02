/** Reusable JSON tree authoring. A document owns the draft and undo history; views
 * only select a subtree. No tree operation changes saved rules or runs a test.
 * Invalid raw JSON stays in its editor and blocks saving until repaired.
 */
import { $, esc } from './dom.js';
const copy = (value) => JSON.parse(JSON.stringify(value));
const keyOf = (path) => JSON.stringify(path);
const own = (object, key) => Object.prototype.hasOwnProperty.call(object, key);
const kind = (value) =>
  value === null ? 'null' : Array.isArray(value) ? 'array' : typeof value;
const defaults = {
  object: {},
  array: [],
  string: '',
  number: 0,
  boolean: false,
  null: null,
};

/** Read own properties only, including user-defined keys such as __proto__. */
function read(value, path) {
  for (const key of path) {
    if (value === null || typeof value !== 'object' || !own(value, key))
      return undefined;
    value = value[key];
  }
  return value;
}
function assign(object, key, value) {
  Object.defineProperty(object, key, {
    value,
    enumerable: true,
    writable: true,
    configurable: true,
  });
}
function check(value, depth = 0, budget = { left: 10000 }) {
  if (--budget.left < 0 || depth > 45)
    throw new Error('Tree exceeds the size or nesting limit.');
  const type = kind(value);
  if (!own(defaults, type) || (type === 'number' && !Number.isFinite(value)))
    throw new Error('Use a valid JSON value.');
  if (value && typeof value === 'object')
    for (const child of Object.values(value)) check(child, depth + 1, budget);
}

export class TreeDocument {
  constructor(value, beforeChange = (next) => next) {
    check(value);
    this.value = copy(value);
    this.beforeChange = beforeChange;
    this.undoStack = [];
    this.redoStack = [];
    this.buffers = new Map();
    this.preferences = new Map();
    this.listeners = new Set();
  }
  at(path = [], fallback = null) {
    const value = read(this.value, path);
    return copy(value === undefined ? fallback : value);
  }
  subscribe(listener) {
    this.listeners.add(listener);
    return () => this.listeners.delete(listener);
  }
  emit() {
    for (const listener of [...this.listeners])
      if (this.listeners.has(listener)) listener();
  }
  get valid() {
    return ![...this.buffers.values()].some((buffer) => buffer.error);
  }
  getValue() {
    if (!this.valid)
      throw new Error('Fix the highlighted JSON or value error before saving.');
    return copy(this.value);
  }
  text(path = [], fallback = null) {
    return (
      this.buffers.get(keyOf(path))?.text ??
      JSON.stringify(this.at(path, fallback), null, 2)
    );
  }
  /** Invalid text is retained separately; it must never replace the last valid tree. */
  editJSON(path, text) {
    try {
      const value = JSON.parse(text);
      check(value);
      this.replace(path, value, true);
      this.buffers.set(keyOf(path), { text, error: '' });
    } catch (error) {
      this.buffers.set(keyOf(path), { text, error: error.message });
    }
    this.emit();
  }
  error(path, message) {
    const id = keyOf(path);
    if (message) this.buffers.set(id, { text: this.text(path), error: message });
    else this.buffers.delete(id);
    this.emit();
  }
  /** Mutations are atomic, JSON-safe and share one bounded history across views. */
  replace(path, value, raw = false) {
    if (!raw && !this.valid)
      throw new Error(
        'Fix the highlighted error, or undo it, before changing the tree.',
      );
    check(value);
    let next = copy(this.value);
    if (!path.length) next = copy(value);
    else {
      const parent = read(next, path.slice(0, -1));
      if (!parent || typeof parent !== 'object')
        throw new Error('The parent is no longer a collection.');
      assign(parent, path.at(-1), copy(value));
    }
    next = this.beforeChange(next, { path, raw });
    check(next);
    // A raw edit must not overwrite another editor's unresolved text.
    const id = keyOf(path);
    if (raw && [...this.buffers].some(([key, b]) => key !== id && b.error))
      throw new Error('Fix the error in the other editor first.');
    if (JSON.stringify(next) !== JSON.stringify(this.value)) {
      this.undoStack.push(copy(this.value));
      if (this.undoStack.length > 50) this.undoStack.shift();
      this.redoStack = [];
      this.value = next;
      this.buffers.clear();
    } else this.buffers.delete(id);
    this.emit();
  }
  add(path, key, value) {
    const parent = this.at(path, {});
    if (Array.isArray(parent)) parent.push(copy(value));
    else {
      if (!parent || typeof parent !== 'object')
        throw new Error('Choose an object or list.');
      if (!key.trim()) throw new Error('Enter a property name.');
      if (own(parent, key)) throw new Error('That property already exists.');
      assign(parent, key, copy(value));
    }
    this.replace(path, parent);
  }
  remove(path) {
    if (!path.length) throw new Error('The document root cannot be removed.');
    const parentPath = path.slice(0, -1),
      parent = this.at(parentPath),
      key = path.at(-1);
    if (Array.isArray(parent)) parent.splice(key, 1);
    else delete parent[key];
    this.replace(parentPath, parent);
  }
  rename(path, name) {
    const parentPath = path.slice(0, -1),
      parent = this.at(parentPath),
      old = path.at(-1);
    if (old === name) return;
    if (Array.isArray(parent) || !name.trim() || own(parent, name))
      throw new Error('Use a unique, nonempty property name.');
    const next = {};
    for (const key of Object.keys(parent))
      assign(next, key === old ? name : key, parent[key]);
    this.replace(parentPath, next);
  }
  move(path, direction) {
    const parentPath = path.slice(0, -1),
      parent = this.at(parentPath),
      index = path.at(-1),
      target = index + direction;
    if (!Array.isArray(parent) || target < 0 || target >= parent.length) return;
    [parent[index], parent[target]] = [parent[target], parent[index]];
    this.replace(parentPath, parent);
  }
  undo() {
    if (!this.valid) {
      this.buffers.clear();
      this.emit();
      return;
    }
    if (!this.undoStack.length) return;
    this.redoStack.push(this.value);
    this.value = this.undoStack.pop();
    this.buffers.clear();
    this.emit();
  }
  redo() {
    if (!this.valid || !this.redoStack.length) return;
    this.undoStack.push(this.value);
    this.value = this.redoStack.pop();
    this.buffers.clear();
    this.emit();
  }
}

/** These operators mirror the data-only Python DSL; Python remains authoritative
 * for arity, schema and reference validation when the rule is saved. */
export const operators = {
  and: ['All conditions', null],
  or: ['Any condition', null],
  not: ['Not', 1],
  eq: ['Equals', 2],
  ne: ['Does not equal', 2],
  in: ['Is in', 2],
  contains: ['Contains', 2],
  set_equals: ['Same set', 2],
  gt: ['Greater than', 2],
  ge: ['At least', 2],
  le: ['At most', 2],
  starts_with: ['Starts with', 2],
  within: ['Within prefix', 2],
  all: ['Every item matches', 'binding'],
  any: ['Some item matches', 'binding'],
  filter: ['Filter items', 'binding'],
  map: ['Map items', 'binding'],
  concat: ['Join lists', 2],
  get: ['Get field', 2],
  length: ['Count', 1],
  lower: ['Lowercase', 1],
  host: ['Host address', 1],
  prefix_length: ['Prefix length', 1],
  last: ['Last item', 1],
  first: ['First item', 1],
  values: ['Object values', 1],
  enumerate: ['Enumerate', 1],
  if: ['If / then / else', 3],
  unconditional: ['Unconditional rule', 1],
  port_contains: ['Port range contains', 2],
  packet: ['Packet decision', 4],
  default_only: ['Default-only policy', 2],
  route_range: ['Route range', 6],
};
export function expression(op, previous = {}) {
  if (op === 'ref') return { ref: 'router.identity' };
  const arity = operators[op]?.[1];
  if (arity === undefined) throw new Error('Unknown operator.');
  if (arity === 'binding')
    return {
      op,
      items: previous.items ?? { ref: 'routers' },
      as: previous.as ?? 'item',
      test: previous.test ?? false,
    };
  const count = arity ?? Math.max(1, previous.args?.length || 1);
  return {
    op,
    args: Array.from({ length: count }, (_, i) => previous.args?.[i] ?? false),
  };
}
const selectOptions = (values, selected) =>
  values
    .map(
      ([value, label]) =>
        `<option value="${esc(value)}"${value === selected ? ' selected' : ''}>${esc(label)}</option>`,
    )
    .join('');

/** A view owns expansion and mode only. Change events commit typed values; input
 * events in JSON mode retain unfinished text without losing the user's cursor.
 * Ordinary buttons/inputs provide keyboard access without partial ARIA-tree semantics.
 */
export function mountTreeEditor({
  container,
  id,
  document: doc,
  path = [],
  label,
  expressionMode = false,
  choices = () => null,
  suggestions = () => [],
  onSave = () => {},
}) {
  const prefs = doc.preferences.get(id) || {
    mode: 'tree',
    closed: new Set(),
    known: new Set(),
  };
  doc.preferences.set(id, prefs);
  const routes = new Map();
  let serial = 0,
    renderingRaw = false;
  const route = (p) => {
    const token = String(serial++);
    routes.set(token, p);
    return token;
  };
  const act = (action, token, title, text, disabled = false) =>
    `<button type="button" id="${token === '' ? id + '-' + (action === 'tree' ? 'mode-tree' : action) : id + '-action-' + token + '-' + action}" data-tree-action="${action}" data-tree-node="${token}" aria-label="${esc(title)}" title="${esc(title)}"${disabled ? ' disabled' : ''}>${text}</button>`;
  const scalar = (value, p, token, name) => {
    const values = choices(p, value);
    if (values)
      return `<select data-tree-edit="value" data-tree-node="${token}" aria-label="${esc(name)}">${selectOptions(values, String(value))}</select>`;
    if (typeof value === 'boolean')
      return `<select data-tree-edit="value" data-tree-node="${token}" aria-label="${esc(name)}">${selectOptions(
        [
          ['true', 'True'],
          ['false', 'False'],
        ],
        String(value),
      )}</select>`;
    if (value === null) return '<span class="tree-null">null</span>';
    return `<input data-tree-edit="value" data-tree-node="${token}" aria-label="${esc(name)}" type="${typeof value === 'number' ? 'number' : 'text'}" ${typeof value === 'number' ? 'step="any"' : ''} value="${esc(value)}"${p.length === 1 && p[0] === 'id' ? ' readonly title="Duplicate the rule to create a new id"' : ''}>`;
  };
  function node(value, p, name, depth = 0) {
    const token = route(p),
      type = kind(value),
      isContainer = value !== null && typeof value === 'object';
    const isExpr =
      expressionMode &&
      isContainer &&
      !Array.isArray(value) &&
      (own(value, 'op') || own(value, 'ref'));
    const pathKey = keyOf(p);
    if (!prefs.known.has(pathKey)) {
      prefs.known.add(pathKey);
      if (depth >= 2) prefs.closed.add(pathKey);
    }
    const collapsed = prefs.closed.has(pathKey),
      parent = p.length ? read(doc.value, p.slice(0, -1)) : null;
    const root = p.length === path.length;
    const fixedId = p.length === 1 && p[0] === 'id';
    const typeChoices = Object.keys(defaults).map((type) => [
      type,
      type === 'array' ? 'List' : type[0].toUpperCase() + type.slice(1),
    ]);
    if (expressionMode)
      typeChoices.push(
        ['ref', 'Reference'],
        ...Object.entries(operators).map(([op, [title]]) => [op, title]),
      );
    const currentType = isExpr ? (own(value, 'ref') ? 'ref' : value.op) : type;
    if (!typeChoices.some(([key]) => key === currentType))
      typeChoices.push([currentType, currentType]);
    let body = '';
    if (isContainer && !collapsed) {
      const entries = Object.entries(value).filter(
        ([key]) => !isExpr || !['op', 'ref'].includes(key),
      );
      if (isExpr && own(value, 'ref'))
        body = `<div class="tree-reference">${scalar(value.ref, [...p, 'ref'], route([...p, 'ref']), 'Model or parameter reference')}<small>e.g. router.identity · params.pollers · item.name</small></div>`;
      else if (isExpr && Array.isArray(value.args)) {
        body = value.args
          .map((child, index) =>
            node(
              child,
              [...p, 'args', index],
              ['and', 'or'].includes(value.op)
                ? `Condition ${index + 1}`
                : `Argument ${index + 1}`,
              depth + 1,
            ),
          )
          .join('');
        if (['and', 'or'].includes(value.op))
          body += act('condition', token, 'Add condition', '+ Add condition');
        // Keep malformed additional fields visible so the user can repair them.
        body += entries
          .filter(([key]) => key !== 'args')
          .map(([key, child]) => node(child, [...p, key], key, depth + 1))
          .join('');
      } else
        body = entries
          .map(([key, child]) =>
            node(
              child,
              [...p, Array.isArray(value) ? Number(key) : key],
              key === 'items'
                ? 'Collection'
                : key === 'test'
                  ? 'Condition'
                  : key === 'as'
                    ? 'Item variable'
                    : key,
              depth + 1,
            ),
          )
          .join('');
      if (!isExpr) {
        const hint = suggestions(p);
        body += `<div class="tree-add">${Array.isArray(value) ? '' : `<input id="${id}-key-${token}" aria-label="New property name" placeholder="${p.at(-1) === 'params' ? 'Parameter name' : 'Property name'}" list="${id}-keys-${token}"><datalist id="${id}-keys-${token}">${hint.map((key) => `<option value="${esc(key)}"></option>`).join('')}</datalist>`}<select id="${id}-type-${token}" aria-label="New value type">${selectOptions(typeChoices, 'string')}</select>${act('add', token, 'Add child', Array.isArray(value) ? '+ Add item' : p.at(-1) === 'params' ? '+ Add parameter' : '+ Add property')}</div>`;
      }
    }
    return `<div class="tree-node${root ? ' tree-root' : ''}"><div class="tree-row">${isContainer ? act('expand', token, `${collapsed ? 'Expand' : 'Collapse'} ${name}`, collapsed ? '▸' : '▾') : '<span class="tree-spacer"></span>'}<span class="tree-key">${esc(root ? name : Array.isArray(parent) ? name : name.replaceAll('_', ' '))}</span><select class="tree-type" data-tree-edit="type" data-tree-node="${token}" aria-label="Type of ${esc(name)}"${fixedId ? ' disabled' : ''}>${selectOptions(typeChoices, currentType)}</select>${isContainer ? `<small class="tree-count">${isExpr ? '' : Object.keys(value).length + (Array.isArray(value) ? ' items' : ' properties')}</small>` : scalar(value, p, token, name)}${!root && !fixedId ? `<span class="tree-actions">${!Array.isArray(parent) ? act('rename', token, `Rename ${name}`, '✎') : act('up', token, `Move ${name} up`, '↑', p.at(-1) === 0) + act('down', token, `Move ${name} down`, '↓', p.at(-1) === parent.length - 1)}${act('duplicate', token, `Duplicate ${name}`, '⧉')}${act('remove', token, `Remove ${name}`, '×')}</span>` : ''}</div>${isContainer && !collapsed ? `<div class="tree-children">${body}</div>` : ''}</div>`;
  }
  function render() {
    // Raw input commits notify every view; leave the active textarea intact.
    if (renderingRaw) {
      updateStatus();
      return;
    }
    routes.clear();
    serial = 0;
    const mode = prefs.mode;
    container.innerHTML = `<section class="tree-editor"><div class="tree-toolbar"><h3>${esc(label)}</h3><div class="tree-modes" role="group" aria-label="${esc(label)} editor mode">${act('tree', '', 'Tree mode', 'Tree')}${act('json', '', 'JSON mode', 'JSON')}</div>${act('undo', '', 'Undo last draft change', '↶', !doc.undoStack.length && doc.valid)}${act('redo', '', 'Redo draft change', '↷', !doc.redoStack.length || !doc.valid)}</div><div id="${id}-tree" class="tree-body"${mode === 'json' ? ' hidden' : ''}>${node(doc.at(path, {}), path, label)}</div><textarea id="${id}" class="tree-json" spellcheck="false" aria-label="${esc(label)} JSON editor"${mode === 'tree' ? ' hidden' : ''}></textarea><p id="${id}-error" class="error-text" role="status"></p></section>`;
    $('#' + id).value = doc.text(path, {});
    $('#' + id).oninput = () => {
      prefs.mode = 'json'; // also supports programmatic/legacy editor access
      renderingRaw = true;
      doc.editJSON(path, $('#' + id).value);
      renderingRaw = false;
      $('#' + id).hidden = false;
      $('#' + id + '-tree').hidden = true;
    };
    container.onclick = click;
    container.onchange = change;
    container.onkeydown = (event) => {
      if ((event.ctrlKey || event.metaKey) && event.key === 'Enter') {
        event.preventDefault();
        // Commit the focused field before running the keyboard save shortcut.
        if (event.target?.dataset?.treeEdit) change(event);
        onSave();
      }
    };
    updateStatus();
  }
  function updateStatus() {
    const errors = [...doc.buffers.values()].filter((b) => b.error).map((b) => b.error);
    $('#' + id + '-error').textContent = errors.join(' · ');
    $('#' + id + '-tree').hidden = prefs.mode !== 'tree';
    $('#' + id).hidden = prefs.mode !== 'json';
    $('#' + id + '-tree').setAttribute('aria-label', label + ' tree');
    $('#' + id + '-undo').disabled = !doc.undoStack.length && doc.valid;
    $('#' + id + '-redo').disabled = !doc.redoStack.length || !doc.valid;
    $('#' + id + '-tree')?.setAttribute('role', 'group');
    // Mode buttons have separate ids from the tree viewport.
    $('#' + id + '-mode-tree').setAttribute(
      'aria-pressed',
      String(prefs.mode === 'tree'),
    );
    $('#' + id + '-json').setAttribute('aria-pressed', String(prefs.mode === 'json'));
  }
  function handle(fn) {
    try {
      fn();
    } catch (error) {
      $('#' + id + '-error').textContent = error.message;
    }
  }
  function click(event) {
    const button = event.target.closest?.('[data-tree-action]');
    if (!button || !container.contains(button)) return;
    const action = button.dataset.treeAction,
      p = routes.get(button.dataset.treeNode);
    handle(() => {
      if (action === 'tree' || action === 'json') {
        if (action === 'tree' && !doc.valid)
          throw new Error(
            'Fix the JSON error before returning to the tree, or undo to discard the invalid text.',
          );
        prefs.mode = action;
        render();
        return;
      }
      if (action === 'undo' || action === 'redo') {
        doc[action]();
        return;
      }
      if (!p) return;
      if (action === 'expand') {
        const key = keyOf(p);
        if (prefs.closed.has(key)) prefs.closed.delete(key);
        else prefs.closed.add(key);
        render();
      }
      if (action === 'remove') doc.remove(p);
      if (action === 'up' || action === 'down') doc.move(p, action === 'up' ? -1 : 1);
      if (action === 'rename') {
        // Inline rename keeps authoring keyboard-friendly and avoids modal prompts.
        const row = button.closest('.tree-row');
        const span = row.querySelector('.tree-key');
        span.innerHTML = `<input aria-label="New property name" value="${esc(p.at(-1))}" data-tree-edit="rename" data-tree-node="${button.dataset.treeNode}">`;
        span.querySelector('input').focus();
      }
      if (action === 'duplicate') {
        const parentPath = p.slice(0, -1),
          parent = doc.at(parentPath);
        if (Array.isArray(parent)) {
          parent.splice(p.at(-1) + 1, 0, doc.at(p));
          doc.replace(parentPath, parent);
        } else {
          let key = p.at(-1) + '_copy';
          while (own(parent, key)) key += '_copy';
          doc.add(parentPath, key, doc.at(p));
        }
      }
      if (action === 'condition') {
        const args = doc.at([...p, 'args']);
        args.push(false);
        doc.replace([...p, 'args'], args);
      }
      if (action === 'add') {
        const type = $(`#${id}-type-${button.dataset.treeNode}`).value;
        const value = own(defaults, type) ? copy(defaults[type]) : expression(type);
        doc.add(p, $(`#${id}-key-${button.dataset.treeNode}`)?.value || '', value);
      }
    });
  }
  function change(event) {
    const target = event.target,
      p = routes.get(target.dataset.treeNode);
    if (!p || !target.dataset.treeEdit) return;
    handle(() => {
      if (target.dataset.treeEdit === 'rename') {
        doc.rename(p, target.value);
        return;
      }
      if (target.dataset.treeEdit === 'type') {
        doc.replace(
          p,
          own(defaults, target.value)
            ? copy(defaults[target.value])
            : expression(target.value, doc.at(p)),
        );
        return;
      }
      const previous = doc.at(p);
      let value = target.value;
      if (typeof previous === 'number') {
        if (value.trim() === '' || !Number.isFinite(Number(value))) {
          renderingRaw = true;
          doc.error(p, 'Enter a finite number.');
          renderingRaw = false;
          return;
        }
        value = Number(value);
      }
      if (typeof previous === 'boolean') value = value === 'true';
      // A corrected typed value may clear its own error; other errors still block.
      doc.buffers.delete(keyOf(p));
      doc.replace(p, value);
    });
  }
  const unsubscribe = doc.subscribe(render);
  render();
  return { destroy: unsubscribe };
}
