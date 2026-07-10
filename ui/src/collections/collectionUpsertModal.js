function safeMergeCollection(scaffold, input) {
  const allowed = ['name', 'type', 'schema', 'listRule', 'viewRule', 'createRule', 'updateRule', 'deleteRule'];
  const out = structuredClone(scaffold);
  for (const key of allowed) {
    if (Object.prototype.hasOwnProperty.call(input, key)) out[key] = input[key];
  }
  return out;
}
