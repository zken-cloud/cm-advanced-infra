#!/usr/bin/env python3
"""Consolidate + deduplicate cm-find output across a fan-out. (v2)

One row per real vulnerability, keyed so it SURVIVES the measured drift
(finding_id/title/CWE/line all vary run-to-run; CM's own fingerprint is empty).

Key = sha256( canonical_path | locus ), where locus is, in order:
  1. enclosing function resolved from the source AST via tree-sitter   (item #5)
  2. for cross-file dataflow findings (no single enclosing function), the
     sink symbol + class                                              (item #4)
  3. an overlapping-line-range cluster (module-level code)            (fallback)

Tree-sitter covers JS/TS, C/C++, Python, Go, Java; a brace-scan is the fallback
for anything else so the tool degrades instead of failing.
"""
import sqlite3, re, os, sys, hashlib
from collections import defaultdict

# fp3: CWE REMOVED from identity (D17). Measured across two fan-outs on identical
# source: (path,cwe,fn) carried 81% of fingerprints, (path,fn) carried 100%, and
# (path,fn,sink) only 83% -- sink_symbol is derived from CM's snippet text, which
# also drifts. CWE and severity are now folded ATTRIBUTES, never identity: a key
# that moves when the agent relabels a finding breaks the accumulator the whole
# design rests on, and makes the merge gate miss a verified vuln (silent pass).
FP_ALGO = "fp3"   # bump => explicit re-key (never silent). fp2 keyed on cwe_class

CWE_CLASS = {
    "CWE-94":"code-injection","CWE-95":"code-injection","CWE-96":"code-injection",
    "CWE-89":"sql-injection",
    "CWE-78":"os-command-injection","CWE-77":"os-command-injection",
    "CWE-918":"ssrf",
    "CWE-639":"idor","CWE-284":"authz","CWE-285":"authz","CWE-862":"authz","CWE-863":"authz",
    "CWE-1321":"prototype-pollution",
    "CWE-942":"cors-misconfig","CWE-346":"cors-misconfig",
    "CWE-352":"csrf","CWE-434":"file-upload","CWE-22":"path-traversal","CWE-611":"xxe",
    # memory classes (native)
    "CWE-787":"oob-write","CWE-125":"oob-read","CWE-120":"buffer-overflow","CWE-121":"buffer-overflow",
    "CWE-122":"heap-overflow","CWE-190":"integer-overflow","CWE-416":"use-after-free",
    "CWE-415":"double-free","CWE-476":"null-deref","CWE-401":"mem-leak",
    "CWE-131":"buffer-overflow","CWE-193":"oob-write","CWE-680":"integer-overflow",
    # logic / authz / race the tool emitted on ShopStack
    "CWE-915":"mass-assignment","CWE-367":"race-toctou","CWE-362":"race-toctou",
    "CWE-843":"type-confusion","CWE-799":"business-logic","CWE-840":"business-logic",
    # NON-FUNCTIONAL ORACLE CLASSES. These names are not decoration: gate.py's
    # NONFUNCTIONAL_ORACLE and CLASS_P are keyed on exactly these strings, and until
    # 2026-08-25 this map produced NONE of them. Four of the five oracle routes were
    # therefore unreachable -- the routing table looked complete and could only ever
    # fire for memory-corruption, which is why wiring it in would have changed
    # nothing. The class name is chosen by the ORACLE that proves it, not by the CWE
    # taxonomy.
    #
    # CWE-400 USED TO MAP HERE and that was wrong. It is Uncontrolled Resource
    # Consumption -- it covers a regex that backtracks AND a cache that never frees,
    # and those need opposite instruments. The live ledger has `cwe-400` on
    # `telemetry.middleware.js`, a retention bug, which this map was pointing at a
    # stopwatch. A CWE that cannot name its own oracle must not pretend to: it routes
    # to `resource-exhaustion`, which needs an oracle and names none, so only an
    # explicit fp3 entry in a target's oracle spec can prove it.
    "CWE-1333":"redos", "CWE-1050":"redos",
    "CWE-400":"resource-exhaustion",
    "CWE-330":"weak-random", "CWE-338":"weak-random", "CWE-335":"weak-random",
    "CWE-208":"timing-attack", "CWE-1254":"timing-attack",
    # CWE-401 was "mem-leak", a name nothing consumed. The RSS-growth oracle suits a
    # native malloc leak and a JS closure/GC leak alike, so both route here.
    "CWE-401":"memory-leak-gc", "CWE-772":"memory-leak-gc",
}
# families that verify the same way collapse to one class for the KEY only.
MEM_FAMILY = {"oob-write","oob-read","buffer-overflow","heap-overflow","integer-overflow"}
def cwe_class(cwe):
    c = CWE_CLASS.get((cwe or "").upper(), (cwe or "unknown").lower())
    return "memory-corruption" if c in MEM_FAMILY else c

# cm emits CRITICAL/HIGH/MEDIUM (LOW/ERROR seen occasionally). Rank drives verify
# selection (--tier/--top-n) and the gate's target-confidence tiers (gate.py).
SEV_RANK = {"critical":4, "high":3, "medium":2, "low":1, "info":0, "error":2}
def severity_rank(sev):
    """Unknown/blank severity defaults to medium (2) — never silently dropped."""
    return SEV_RANK.get((sev or "").strip().lower(), 2)

def cluster_severity(obs):
    """Most-severe wins across a cluster's observations. Returns (label, rank)."""
    best = max(obs, key=lambda o: severity_rank(o.get("severity")))
    lab = (best.get("severity") or "MEDIUM").strip().upper()
    return lab, severity_rank(best.get("severity"))

EXT_LANG = {".js":"javascript",".jsx":"javascript",".ts":"typescript",".tsx":"typescript",
            ".c":"c",".h":"c",".cc":"cpp",".cpp":"cpp",".hpp":"cpp",".py":"python",".go":"go",".java":"java"}

def relpath(p):
    """Canonical repo-relative path. Prod: exporter computes clone-root-relative;
    here basename is the canonical form (all clones are one file)."""
    return os.path.basename(p or "")

# ---------- AST enclosing-function resolution (tree-sitter, item #5) ----------
_PARSERS={}
def _parser(lang):
    if lang not in _PARSERS:
        try:
            from tree_sitter_language_pack import get_parser
            _PARSERS[lang]=get_parser(lang)
        except Exception:
            _PARSERS[lang]=None
    return _PARSERS[lang]

FUNC_NODES={"function_declaration","function_definition","method_definition",
            "method_declaration","function_item","arrow_function","function_expression"}
def _txt(n, src): return src[n.start_byte:n.end_byte].decode("utf8","ignore")

def _lhs_name(n, src):
    """Rightmost identifier of an assignment target: `exports.foo` / `a.b.foo` -> foo."""
    if n is None: return None
    if n.type in ("identifier","property_identifier","field_identifier","private_property_identifier"):
        return _txt(n, src)
    if n.type in ("member_expression","member_access_expression","subscript_expression"):
        prop = n.child_by_field_name("property")
        if prop is not None: return _txt(prop, src)
    ids=[c for c in n.children if c.type in ("identifier","property_identifier","field_identifier")]
    return _txt(ids[-1], src) if ids else None

def _assigned_name(node, src):
    """Name an anonymous arrow/function-expression from its BINDING site, never from
    a parameter. Covers the dominant JS idiom `exports.foo = (...) => {}` plus
    `const foo = () => {}`, `obj.foo = function(){}`, and `foo: () => {}`. Without
    this the resolver grabs a callback's param (chunk/doc/key) or nothing at all,
    which fragments one bug across the sink/line fallback."""
    p = node.parent
    if p is None: return None
    if p.type == "variable_declarator":
        return _lhs_name(p.child_by_field_name("name") or (p.children[0] if p.children else None), src)
    if p.type == "assignment_expression":
        return _lhs_name(p.child_by_field_name("left") or (p.children[0] if p.children else None), src)
    if p.type in ("pair","property"):
        return _lhs_name(p.child_by_field_name("key") or (p.children[0] if p.children else None), src)
    if p.type in ("public_field_definition","field_definition"):
        return _lhs_name(p.child_by_field_name("name") or (p.children[0] if p.children else None), src)
    return None

def _name_of(node, src):
    # anonymous by construction: an arrow's identifier children are PARAMS, not a name.
    if node.type == "arrow_function":
        return _assigned_name(node, src)
    if node.type == "function_expression":
        # a named function expression (`function foo(){}`) carries its own name;
        # otherwise fall back to the binding site.
        for c in node.children:
            if c.type == "identifier":
                return _txt(c, src)
        return _assigned_name(node, src)
    # named declarations / methods (JS/Python/Go/Java): direct identifier child
    for c in node.children:
        if c.type in ("identifier","field_identifier","property_identifier"):
            return _txt(c, src)
    # C/C++: name is nested under (pointer_)declarator -> function_declarator -> identifier.
    def dig(n):
        for c in n.children:
            if c.type in ("identifier","field_identifier"):
                return _txt(c, src)
            if "declarator" in c.type:
                r=dig(c)
                if r: return r
        return None
    return dig(node)

_AST_CACHE={}
def enclosing_func_ast(src_path, line):
    lang=EXT_LANG.get(os.path.splitext(src_path)[1].lower())
    p=_parser(lang) if lang else None
    if not p: return None
    key=("tree",src_path)
    if key not in _AST_CACHE:
        try: _AST_CACHE[key]=(p.parse(open(src_path,"rb").read()), open(src_path,"rb").read())
        except OSError: _AST_CACHE[key]=(None,None)
    tree,src=_AST_CACHE[key]
    if not tree: return None
    # deepest function node whose line span contains `line`
    best=None
    def walk(n):
        nonlocal best
        sl,el=n.start_point[0]+1, n.end_point[0]+1
        if sl<=line<=el:
            if n.type in FUNC_NODES:
                nm=_name_of(n,src)
                if nm: best=nm
            for c in n.children: walk(c)
    walk(tree.root_node)
    return best

# brace-scan fallback (no parser for this language)
_BRACE_CACHE={}
def enclosing_func_brace(src_path, line):
    if src_path not in _BRACE_CACHE:
        idx={}
        try: lines=open(src_path,encoding="utf8",errors="ignore").read().splitlines()
        except OSError: _BRACE_CACHE[src_path]={}; return None
        fre=re.compile(r'\b(?:async\s+)?function\s+([A-Za-z_$][\w$]*)')
        cur=None; depth=0; started=False
        for i,ln in enumerate(lines,1):
            if cur is None:
                m=fre.search(ln)
                if m: cur=m.group(1); depth=0; started=False
            if cur is not None:
                depth+=ln.count("{")-ln.count("}")
                if "{" in ln: started=True
                idx[i]=cur
                if started and depth<=0: cur=None
        _BRACE_CACHE[src_path]=idx
    return _BRACE_CACHE[src_path].get(line)

_SRC_INDEX={}
def _find_src(basename, root):
    if root not in _SRC_INDEX:
        m={}
        for r,_,fs in os.walk(root):
            for f in fs: m.setdefault(f, os.path.join(r,f))
        _SRC_INDEX[root]=m
    return _SRC_INDEX[root].get(basename)

def enclosing_func(file_path, start_line, src_root, end_line=None):
    """Resolve enclosing function. Findings often point at the comment/decorator
    ABOVE the function, so scan the finding's whole [start,end] range and take the
    first line that resolves (drift tolerance)."""
    if not src_root or not start_line: return None
    sp=_find_src(os.path.basename(file_path or ""), src_root)
    if not sp: return None
    hi=end_line or start_line
    for L in range(start_line, min(hi, start_line+8)+1):   # cap the scan
        fn=enclosing_func_ast(sp, L) or enclosing_func_brace(sp, L)
        if fn and len(fn) >= 2: return fn   # reject 1-char misparses (arrow params etc.)
    return None

# ---------- sink extraction for cross-file dataflow findings (item #4) ----------
SINK_RE=re.compile(r'\b([A-Za-z_][\w.]*(?:\.[A-Za-z_]\w*|::[A-Za-z_]\w*|#[A-Za-z_]\w*|_[a-z]+)?)\s*\(')
DANGEROUS=("exec","execSync","execFile","spawn","query","eval","system","popen","memcpy",
           "strcpy","sprintf","malloc","fetch","request","Statement","createReadStream","readFile")
def sink_symbol(snippet, analysis):
    text=(snippet or "")+"\n"+(analysis or "")
    for d in DANGEROUS:
        m=re.search(rf'\b([\w.]*{re.escape(d)})\s*\(', text)
        if m: return m.group(1)
    return None

SRC_ROOT=os.environ.get("SRC_ROOT","")

def load_db(path, pod):
    c=sqlite3.connect(f"file:{path}?mode=ro",uri=True); c.row_factory=sqlite3.Row
    return [dict(r,pod=pod) for r in c.execute(
        "select finding_id,vuln_id,vuln_type,title,file_path,start_line,end_line,snippet,analysis,severity,status from findings")]

def key(f):
    """Identity = (locus_type, canonical_path, locus). No CWE: see FP_ALGO note."""
    p=relpath(f["file_path"])
    fn=enclosing_func(f["file_path"], f["start_line"], SRC_ROOT, f.get("end_line"))
    if fn: return ("fn",p,fn)
    sk=sink_symbol(f.get("snippet"), f.get("analysis"))       # cross-file / no enclosing fn
    if sk: return ("sink",p,sk)
    return None                                               # -> line-overlap fallback

def cluster_class(obs):
    """The finding's class is a FOLD over observations, not part of its identity.
    Modal cwe_class; ties broken deterministically."""
    from collections import Counter
    c=Counter(cwe_class(o.get("vuln_id")) for o in obs)
    return sorted(c.items(), key=lambda kv:(-kv[1],kv[0]))[0][0]

def needs_triage(obs):
    """Two distinct sink symbols under one key may be two different bugs in one
    function. Do not silently merge them -- flag for human triage (ARCHITECTURE:
    same-locus/different-bug routes to triage, never to auto-suppression)."""
    return len({sink_symbol(o.get("snippet"), o.get("analysis")) for o in obs
                if sink_symbol(o.get("snippet"), o.get("analysis"))}) > 1

def consolidate(findings):
    clusters={}; ranges=defaultdict(list)
    for f in findings:
        k=key(f); lo,hi=(f["start_line"] or 0),(f["end_line"] or 0)
        if k is None:
            p=relpath(f["file_path"]); k=None
            for (rlo,rhi,rk) in ranges[p]:
                if not (hi<rlo or lo>rhi): k=rk; break
            if k is None: k=("ln",p,lo)
            ranges[p].append((lo,hi,k))
        clusters.setdefault(k,[]).append(f)
    return clusters

def fingerprint(k, cluster):
    return FP_ALGO+":"+hashlib.sha256("|".join(str(x) for x in k).encode()).hexdigest()[:16]

if __name__=="__main__":
    dbs=sys.argv[1:]
    findings=[]
    for i,db in enumerate(dbs): findings+=load_db(db,f"pod{i}")
    clusters=consolidate(findings)
    print(f"IN : {len(findings)} findings from {len(dbs)} pods")
    print(f"OUT: {len(clusters)} distinct fingerprints  (algo {FP_ALGO})\n")
    # key is (locus_type, canonical_path, locus) since fp3 -- CWE is NOT in it.
    # The class shown here is a FOLD over observations, and a "!" marks a cluster
    # whose members disagree on the sink symbol, i.e. possibly two bugs in one key.
    print(f"{'fingerprint':24}{'class':22}{'kind':6}{'path':30}{'locus':22}{'pods':6}CWEs")
    for k,obs in sorted(clusters.items(),key=lambda kv:-len(kv[1])):
        fp=fingerprint(k,obs); pods=sorted({o['pod'] for o in obs}); cwes=sorted({o['vuln_id'] for o in obs})
        kind,path,locus=k
        flag="!" if needs_triage(obs) else " "
        print(f"{fp:24}{cluster_class(obs):22}{kind:6}{path[:29]:30}{str(locus)[:21]:22}"
              f"{len(pods)}/{len(dbs):<3}{flag} {','.join(cwes)}")
    print(f"\nVERIFY QUEUE: {len(clusters)}  |  naive: {len(findings)}  |  avoided: {len(findings)-len(clusters)} ({100*(len(findings)-len(clusters))//max(1,len(findings))}%)")
