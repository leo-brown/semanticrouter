/** Shared, tab-local semantic workspace. No model is persisted or applied to a device. */
export const clone = (value) => structuredClone(value);
export const state = {
  routers: [],
  policy: {},
  findings: [],
  baseline: null,
  originals: new Map(),
  selected: null,
  tab: 'objects',
  // Inspector preferences apply across nodes, rather than resetting per router.
  openObjectSections: new Set(['FirewallV4']),
  modified: new Set(),
  engineReady: false,
  policyModified: false,
  busy: 0,
  revision: 0,
  exportResult: null,
  rules: [],
  ruleResults: [],
  sources: {},
  sourceRedacted: {},
  ruleSuites: [],
};

/** Find the selected semantic object in the current workspace, not in the immutable baseline. */
export function current() {
  return state.routers.find((r) => r.name === state.selected);
}

/** Count findings for sidebar badges without interpreting network policy in JavaScript. */
export function countFor(name, severity = 'P1') {
  return state.findings.filter((f) => f.device === name && f.severity === severity)
    .length;
}
