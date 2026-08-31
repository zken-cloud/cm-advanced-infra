// SAME BUG, different shape: Object.keys + forEach instead of for..in
exports.merge = function merge(target, source) {
  Object.keys(source).forEach(function (k) { target[k] = source[k]; });
  return target;
};
