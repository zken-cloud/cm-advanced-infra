// SAME code-injection bug, different alias route
exports.run = (formula) => {
  const F = Object.getPrototypeOf(function(){}).constructor;
  return F('return ' + formula)();
};
