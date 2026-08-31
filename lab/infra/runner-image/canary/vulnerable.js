// CANARY FIXTURE — deliberately vulnerable, and deliberately trivial.
//
// This is not a target. It is the control that tells a verify pod whether it can
// execute and observe an exploit AT ALL, before it spends 20-40 agent-minutes
// finding out that it cannot. Its only job is to be exploitable, always, with no
// dependencies, no server, and no network.
//
// Keep it boring. If this file ever needs a package, a port or a build step, it has
// stopped being a control and become a second thing that can break.
'use strict';

// A path-traversal sanitiser with the classic doubled-prefix bug: it strips "../"
// once, non-recursively, so "....//" collapses INTO "../" instead of being removed.
function safeJoin(base, userPath) {
  const cleaned = String(userPath).replace(/\.\.\//g, '');
  return base.replace(/\/+$/, '') + '/' + cleaned;
}

module.exports = { safeJoin };
