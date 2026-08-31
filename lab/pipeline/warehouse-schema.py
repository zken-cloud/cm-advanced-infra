#!/usr/bin/env python3
"""Generate the BigQuery schemas for the warehouse tables from the ledger schema.

Why generated rather than hand-written: the warehouse mirrors the ledger, so a
hand-maintained BQ schema is a second copy of ledger.py's CREATE TABLE that nothing
keeps in step. That exact shape has bitten this repo three times already -- the
reconciler baking its own k8s/ (D38), the CWE map diverging from the oracle routing
table (D47), poc-normalise.py copied into an image directory (D47). One source, one
generator, and a test that fails when the artefact drifts.

Why explicit rather than `autodetect`: autodetect infers the schema from whatever
files happen to be present, so the table's shape changes silently when the exporter
changes -- and anything built on it breaks without warning. It also cannot create a
table at all over an empty prefix, which is what broke the greenfield apply
(`Schema has no fields`). A declared schema is a contract; an inferred one is a
guess that looks like a contract.

  warehouse-schema.py --out infra/terraform/warehouse-schema
  warehouse-schema.py --check infra/terraform/warehouse-schema    # drift check
"""
import os, re, sys, json, argparse, importlib.util

HERE = os.path.dirname(os.path.abspath(__file__))

# SQLite is loosely typed; BigQuery is not. Map on the declared affinity.
SQL_TO_BQ = {"TEXT": "STRING", "INTEGER": "INT64", "REAL": "FLOAT64"}

# The gate writes its own events (D35); their shape lives in gate-check.py's emit(),
# not in the ledger, so it is declared here and asserted by the test.
GATE_EVENTS = [
    ("repo", "STRING"), ("sha", "STRING"), ("action", "STRING"), ("reason", "STRING"),
    ("run_id", "STRING"), ("ts", "STRING"), ("blocking_count", "INT64"),
]


def ledger_module():
    spec = importlib.util.spec_from_file_location("ledger", os.path.join(HERE, "ledger.py"))
    m = importlib.util.module_from_spec(spec); spec.loader.exec_module(m)
    return m


def columns(schema_sql, table):
    """(name, BQ type) for one CREATE TABLE, in declaration order."""
    m = re.search(rf"CREATE TABLE IF NOT EXISTS {table}\((.*?)\n\);", schema_sql, re.S)
    if not m:
        raise SystemExit(f"no CREATE TABLE for {table} in ledger.py")
    # Strip comments FIRST, then split on commas -- not on newlines. The DDL puts
    # several columns on one line (`cwe_class TEXT, enclosing_function TEXT, ...`),
    # so a line-wise parser reads the first of each and silently drops the rest. It
    # produced an 11-column `findings` from a 17-column table, and the only reason
    # that surfaced is that the generator prints its column count.
    body = "\n".join(re.sub(r"--.*$", "", ln) for ln in m.group(1).split("\n"))
    out = []
    depth = 0
    field = ""
    for ch in body + ",":                      # trailing comma flushes the last field
        if ch == "(":
            depth += 1
        elif ch == ")":
            depth -= 1
        if ch == "," and depth == 0:
            decl, field = field.strip(), ""
            if not decl:
                continue
            parts = decl.split()
            if parts[0].upper() in ("PRIMARY", "FOREIGN", "UNIQUE", "CHECK", "CONSTRAINT"):
                continue
            name = parts[0]
            typ = parts[1].upper() if len(parts) > 1 else "TEXT"
            out.append((name, SQL_TO_BQ.get(typ, "STRING")))
        else:
            field += ch
    return out


def build():
    L = ledger_module()
    tables = {}
    # Every ledger table the warehouse mirrors. `coverage` matters most: "what
    # fraction of what is running in prod has a covering campaign" is a question
    # about thousands of rows, which is a warehouse question and not a SQLite one.
    for t in ("findings", "observations", "scans", "coverage", "risk_acceptances",
              "patch_prs"):
        cols = columns(L.SCHEMA, t)
        # Columns added after ledgers existed in the wild live in _ADDED, not in the
        # CREATE TABLE. Reading only the CREATE TABLE would silently omit them --
        # `severity` and `repo` on findings, the D45 health counters on scans.
        for tbl, col, typ in L._ADDED:
            if tbl == t and col not in {c for c, _ in cols}:
                cols.append((col, SQL_TO_BQ.get(typ.upper(), "STRING")))
        # Every export row is stamped by ledger-export.py.
        cols.append(("snapshot_ts", "STRING"))
        tables[t] = cols
    tables["gate_events"] = list(GATE_EVENTS)

    out = {}
    for t, cols in tables.items():
        # NULLABLE throughout, deliberately: a snapshot of a partly-populated ledger
        # is a normal state, and REQUIRED would reject the export rather than tell
        # anyone the column was empty.
        out[t] = [{"name": n, "type": ty, "mode": "NULLABLE"} for n, ty in cols]
        if t == "gate_events":
            out[t].append({"name": "blocking", "type": "STRING", "mode": "REPEATED"})
        # `dt` (the hive partition key) is deliberately NOT declared here.
        #
        # BigQuery is asymmetric about it: CREATE rejects a schema containing the
        # partition key --
        #     Field, dt, is present in both Table Schema and Hive-Partition key
        # -- while READ returns it appended to the schema. Declaring it makes the
        # plan converge and the create fail; omitting it makes the create work and
        # the plan never converge. The asymmetry is BigQuery's, so it is handled in
        # terraform (warehouse.tf) rather than papered over here.
        #
        # This was briefly "fixed" the wrong way. The plan went quiet because the
        # tables already existed and were never recreated -- `0 added, 1 changed,
        # 0 destroyed` -- so a converged plan was mistaken for a validated create
        # path. A plan proves what terraform intends, not what the API accepts.
    return out


def main():
    ap = argparse.ArgumentParser()
    ap.add_argument("--out"); ap.add_argument("--check")
    a = ap.parse_args()
    built = build()
    target = a.out or a.check
    if not target:
        print(json.dumps(built, indent=2)); return 0
    if a.out:
        os.makedirs(a.out, exist_ok=True)
        for t, schema in built.items():
            open(os.path.join(a.out, f"{t}.json"), "w").write(json.dumps(schema, indent=2) + "\n")
        print(f"wrote {len(built)} schema(s) to {a.out}")
        return 0
    bad = []
    for t, schema in built.items():
        p = os.path.join(a.check, f"{t}.json")
        if not os.path.exists(p):
            bad.append(f"{t}: missing"); continue
        if json.load(open(p)) != schema:
            bad.append(f"{t}: drifted from ledger.py")
    if bad:
        print("\n".join(bad)); print("regenerate: warehouse-schema.py --out " + a.check)
        return 1
    print(f"{len(built)} schema(s) match ledger.py")
    return 0


if __name__ == "__main__":
    sys.exit(main())
