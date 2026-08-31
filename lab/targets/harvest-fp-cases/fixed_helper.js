// GENUINE FIX via a HELPER. Guard keywords never appear in this function.
const isSafeKey = require('./keys').isSafeKey;
exports.merge = function merge(target, source) {
  for (const key in source) {
    if (!isSafeKey(key)) continue;
    target[key] = source[key];
  }
  return target;
};
