# Harvest validation cases

Four cases every harvested ruleset must be run against before any of its rules is
allowed to block a commit. A rule that passes on snippets written to demonstrate it
proves nothing; these are the shapes that break real harvested rules.

| file | what it is | required |
|---|---|---|
| `fixed_guard.js` | genuine fix, **inline** guard | stay silent |
| `fixed_helper.js` | genuine fix, guard in a **helper** | stay silent |
| `vuln_reworded.js` | same bug, `Object.keys().forEach` instead of `for..in` | fire |
| `vuln_alias_rewritten.js` | same bug reached through a different alias | fire |

`fixed_helper.js` is the one that matters, and the one harvested rules usually
fail. A rule generated from a vulnerable/fixed pair tends to decide "is this
guarded?" with a regex over guard keywords (`__proto__`, `hasOwnProperty`,
`Object.create(null)`) across the matched region. Factor the guard into
`isSafeKey()` — the normal thing to do — and those keywords leave the function, so
the rule fires on **correctly fixed code**. The same proxy runs backwards: a
comment mentioning `__proto__` silences it on a real bug.

A rule that fails `fixed_helper.js` may still ship as **advisory**. It must not be
promoted to blocking by `stamp-rules.py`, or the first well-factored fix in the
repository is rejected by a rule claiming that fix is the vulnerability. That is
how a security control gets switched off for everyone.

`vuln_reworded.js` is the mirror image: a rule tied to one syntactic form misses
the same defect written another way, and reports clean. Over-fitting shows up as a
false negative here and a false positive above; both come from harvesting the
shape instead of the defect (D21).

> Run these against **your own** harvested rules, from your own verified findings.
> This repository ships no rules for the lab target — deriving them is Step 7.
