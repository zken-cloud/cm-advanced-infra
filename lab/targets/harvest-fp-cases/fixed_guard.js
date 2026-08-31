// GENUINE FIX: inline guard. Rule must stay SILENT.
exports.merge = function merge(target, source) {
  for (const key in source) {
    if (key === '__proto__' || key === 'constructor') continue;
    target[key] = source[key];
  }
  return target;
};
