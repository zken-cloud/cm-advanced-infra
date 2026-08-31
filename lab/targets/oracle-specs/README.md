# Oracle specs

`pipeline/oracles.py` takes callables and URLs. A verify pod has a CWE class. This
directory is the missing middle: for each finding needing a **non-functional**
oracle — one where "it crashed" is not the proof — it says which endpoint to drive
and with what.

Specs are **target-specific and location-specific**, so this repository ships none.
You write one for the findings *you* verified, the same way you harvest your own
rules in Step 7. A spec naming a target's vulnerable functions is an answer key.

## Schema

```yaml
target: <name>

app:
  install: ["npm", "install", "--omit=dev"]
  boot:    ["node", "src/server.js"]
  env:     {PORT: "3111"}
  base:    "http://127.0.0.1:3111"
  ready:                      # any wired route that answers without a dependency.
    method: POST              # a 4xx IS ready; only connection refusal is not.
    path: "/api/v1/health"
    body: {}

# Matched most-specific first: an entry with `fp3` beats one with only `cwe_class`.
# An unmatched finding is `unproven` -- NEVER a negative (invariant 6).
oracles:
  - match:  {fp3: "<file>.js::<enclosingFunction>"}
    oracle: wall-clock-timeout-oracle
    claim: >-
      One sentence, narrow and literal, describing the property this proves.
    params:
      path: "/api/v1/..."
      benign:    {...}        # NEGATIVE CONTROL. Must be fast. If it is already
                              # slow the bound is wrong and the oracle refuses
                              # to issue a verdict rather than guessing.
      malicious: {...}
      bound_s: 0.5            # SET FROM THE BENIGN SIDE, never near the malicious one
      timeout: 30
```

## Two rules that are not style

**`claim` is written into the evidence and is what the ledger records as proven.**
An oracle proves a narrow property; whether that property *matters* is
`impact_review`, and that is a human's call (D28). Overstate here and a 30-minute
proof becomes an unearned CRITICAL.

**Set the bound from the benign control.** Measured on a real finding: a bound of
2.0s with the crafted input landing at ~2.0s made the verdict depend on which side
of the line a run happened to fall — 1.9961s then 2.0753s, one silent, one fired,
on the same unchanged bug. A bound chosen from the attacker's observed timing is a
coincidence, not a threshold. Take the benign path's time and multiply.
