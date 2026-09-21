#!/usr/bin/env python3
"""unified_fork.py — unified dynamic fork locator (the "refactored" method).

Given the boundary function (innermost common function at the last shared
position, from fork_chain.py) this module runs BOTH versions under GDB with
decision-event recording (decision_trace.py) and compares the two *decision
traces* invocation by invocation:

  1. align invocations pairwise (i-th call of f in A <-> i-th call in B),
  2. find the LAST invocation whose decision events differ,
  3. within it, find the LAST differing decision:
       * outcomes / operand values differ  -> decision fork (the guard whose
         flip would change the path), with both sides' values,
       * a decision exists on one side only -> path-shortening / code-change
         fork at that position,
  4. if all decision events are identical in every invocation, compare the
     functions' return values per invocation: differing -> value fork,
  5. if still nothing, recurse into the callees that BOTH sides invoked the
     same number of times (nearest to the function exit first) — the fork
     lives in a callee's body.

Only decision events are compared (ordinary statements never produce events),
so statement-level drift between the two versions does not affect alignment
(decision-trace invariant).  Recursion follows observed call events, not
static guesses, and terminates at a bounded depth.

No project-specific knowledge is used.
"""

import argparse
import json
import os
import re
import sys
from pathlib import Path

sys.path.insert(0, str(Path(__file__).resolve().parent))
from decision_trace import record_decisions
from decision_trace import _locate_function_source, find_function_decisions
from decision_trace import _function_body
from decision_trace import is_function_definition
from trace_fork_offsets import extract_variables_from_statement

_SEMANTIC_SUFFIXES = ('WithLimit', 'Checked', 'Safe', 'Ex', 'NoSSE', 'Array')

# Cache of _record_side results: (binary, func_names, source_root, args) ->
# (record_decisions_result, used_func_name).  Deterministic recordings are
# replayed many times during the recursive descent; the cache avoids the
# repeated full GDB runs without changing the outcome.
_RECORD_CACHE = {}

# Static decision-density cache for _recurse_candidates: (func, source_root)
# -> decision count.  The density ranking re-reads and re-parses the same
# functions for every candidate pair.
_DECISION_DENSITY_CACHE = {}

# Error/warning REPORTING functions: their divergences are consequences of
# earlier state differences (the actual input-driven fork), not causes.
# They are excluded from recursion and from the candidate set so the search
# does not terminate on the warning/error output path.
_NOISE_FUNC_RE = re.compile(
    r'(?:TIFF(?:Error|Warning)(?:Ext)?|unix(?:Error|Warning)Handler|'
    r'(?:Error|Warning)Handler|_TIFF(?:Error|Warning)|'
    r'report|fprintf|perror|'
    # allocator / runtime helpers: a fork inside them (e.g.
    # ``_TIFFmalloc``'s ``if (s == 0)``) is never the causal statement —
    # the divergence lives in the caller that computes the arguments.
    r'_(?:TIFF)?(?:malloc|realloc|calloc|free|memcpy|memset|memmove|'
    r'memcmp|strlen|strcmp|strcpy|strncpy|printf|fread|fwrite|fseek|'
    r'ftell|fflush|exit|abort|assert|qsort|bsearch)|'
    r'malloc|calloc|realloc|free|memcpy|memset|memmove|strlen|strcmp|'
    r'fread|fwrite|exit|abort|qsort|assert)$', re.IGNORECASE)


def _is_noise_func(name):
    return bool(name and _NOISE_FUNC_RE.search(name))


def _norm(text):
    return re.sub(r'[\s{};]+', '', (text or ''))


def _name_pair(name_a, name_b, refactoring_map=None):
    """True when two callee names denote the same (aligned) function."""
    if name_a == name_b:
        return True
    if refactoring_map:
        if refactoring_map.get(name_a) == name_b:
            return True
        if name_a == refactoring_map.get(name_b):
            return True
    # Semantic pair: X vs XWithLimit — same call site, strengthened callee.
    for suf in _SEMANTIC_SUFFIXES:
        if name_b == name_a + suf or name_a == name_b + suf:
            return True
    return False


def _to_int(val):
    try:
        return int(str(val), 0)
    except Exception:
        return None


def _value_tuple(clauses):
    """(lhs, rhs) per clause, None-tolerant."""
    out = []
    for i in sorted(clauses, key=lambda k: int(k)):
        c = clauses[i]
        out.append((c.get('lhs'), c.get('rhs')))
    return out


# Values at or above this magnitude are address-sized (heap/stack pointers
# under ASLR) — real scalars (file offsets, counts, sizes) never reach it.
_PTR_LIKE_MIN = 1 << 40


def _is_ptr_like(v):
    try:
        return v is not None and abs(int(v)) >= _PTR_LIKE_MIN
    except (TypeError, ValueError):
        return False


def _value_diff_is_pointer_noise(va, vb):
    """True when the operand-value difference is ONLY in pointer-like
    operands.

    Heap addresses differ between every run (ASLR) and between the two
    versions' processes even when the behavior is identical (e.g.
    ``if (p==NULL)`` where p is a malloc result on both sides).  A 'value'
    diff that rests solely on such operands is meaningless fork evidence.
    """
    if len(va) != len(vb):
        return False
    has_diff = False
    all_ptr = True
    for (la, ra), (lb, rb) in zip(va, vb):
        la_i, lb_i = _to_int(la), _to_int(lb)
        ra_i, rb_i = _to_int(ra), _to_int(rb)
        if la_i != lb_i:
            has_diff = True
            if not (_is_ptr_like(la_i) and _is_ptr_like(lb_i)):
                all_ptr = False
        if ra_i != rb_i:
            has_diff = True
            if not (_is_ptr_like(ra_i) and _is_ptr_like(rb_i)):
                all_ptr = False
    return has_diff and all_ptr


def compare_invocations(inv_a, inv_b):
    """Compare one invocation pair; return a diff dict or None.

    Diff kinds (strong to weak):
      * 'outcome' (STRONG) — the two sides reached different outcomes at the
        same decision position: the path itself diverges here;
      * 'count'   (STRONG) — one side took extra decisions: path shortening /
        an added guard;
      * 'text'    (WEAK)   — condition text rewritten (semantic pair); path
        may still be equivalent;
      * 'value'   (WEAK)   — same outcome but different operand values
        (downstream state difference; NOT causal by itself).

    The caller must report strong diffs before recursing, and only fall back
    to weak diffs when no deeper divergence exists.
    """
    ev_a = inv_a.get('events') or []
    ev_b = inv_b.get('events') or []
    n = min(len(ev_a), len(ev_b))

    def _mk(kind, strong, k, ea, eb, da, db):
        return {'kind': kind, 'strong': strong, 'index': k,
                'a': {'line': ea.get('line'), 'text': ea.get('text', ''),
                      'clauses': ea.get('clauses', {}), 'outcome': da,
                      'exprs': ea.get('exprs', [])},
                'b': {'line': eb.get('line'), 'text': eb.get('text', ''),
                      'clauses': eb.get('clauses', {}), 'outcome': db,
                      'exprs': eb.get('exprs', [])}}

    strong = None
    weak = None
    for k in range(n):
        ea, eb = ev_a[k], ev_b[k]
        da, db = ea.get('outcome'), eb.get('outcome')
        if da != db and da is not None and db is not None:
            strong = strong or _mk('outcome', True, k, ea, eb, da, db)
            continue
        if len(ev_a) != len(ev_b) and strong is None:
            pass
        ta, tb = _norm(ea.get('text', '')), _norm(eb.get('text', ''))
        va, vb = _value_tuple(ea.get('clauses') or {}), \
            _value_tuple(eb.get('clauses') or {})
        if ta and tb and ta != tb and weak is None:
            weak = _mk('text', False, k, ea, eb, da, db)
        elif va and vb and va != vb and weak is None \
                and not _value_diff_is_pointer_noise(va, vb):
            weak = _mk('value', False, k, ea, eb, da, db)
    if strong:
        return strong
    if weak:
        return weak
    if len(ev_a) != len(ev_b):
        side = 'a' if len(ev_a) > len(ev_b) else 'b'
        return {'kind': 'count', 'strong': True, 'index': n,
                'extra_side': side,
                'a_events': len(ev_a), 'b_events': len(ev_b),
                'a': {'line': ev_a[n]['line'] if n < len(ev_a) else None,
                      'text': ev_a[n].get('text', '') if n < len(ev_a) else ''},
                'b': {'line': ev_b[n]['line'] if n < len(ev_b) else None,
                      'text': ev_b[n].get('text', '') if n < len(ev_b) else ''}}
    return None


def _ret_equal(ra, rb):
    if ra is None or rb is None:
        return True  # unreadable return values do not count as a difference
    ia, ib = _to_int(ra), _to_int(rb)
    if ia is not None and ib is not None:
        return ia == ib
    return str(ra).strip() == str(rb).strip()


def _recurse_candidates(inv_a, inv_b, refactoring_map, source_a=None,
                        source_b=None):
    """Callees invoked on BOTH sides, ranked by static decision density
    (most decision-dense first: the divergence is likeliest inside functions
    with their own guards), then by their last call position as a tiebreak.

    Invocation counts may differ (the target bails out early on a failing
    path and stops calling — e.g. TIFFOpen called 2x vs 1x): a callee is a
    candidate as soon as BOTH sides called it at least once (pairing by the
    min count; the recursive level then aligns the common invocations).
    """
    cnt_a, last_a = {}, {}
    for c in inv_a.get('calls') or []:
        for name in c.get('callees') or []:
            cnt_a[name] = cnt_a.get(name, 0) + 1
            last_a[name] = max(last_a.get(name, 0), c.get('order', 0))
    cnt_b, last_b = {}, {}
    for c in inv_b.get('calls') or []:
        for name in c.get('callees') or []:
            cnt_b[name] = cnt_b.get(name, 0) + 1
            last_b[name] = max(last_b.get(name, 0), c.get('order', 0))

    def _static_decisions(name, source_root):
        if not source_root:
            return 0
        key = (name, str(source_root))
        if key in _DECISION_DENSITY_CACHE:
            return _DECISION_DENSITY_CACHE[key]
        try:
            fsrc = _locate_function_source(name, source_root)
            n = len(find_function_decisions(fsrc, name)) if fsrc else 0
        except Exception:
            n = 0
        _DECISION_DENSITY_CACHE[key] = n
        return n

    pairs = []
    for name_a, ca in cnt_a.items():
        for name_b, cb in cnt_b.items():
            if min(ca, cb) >= 1 and _name_pair(name_a, name_b, refactoring_map):
                pos = max(last_a.get(name_a, 0), last_b.get(name_b, 0))
                nd = (_static_decisions(name_a, source_a)
                      + _static_decisions(name_b, source_b)) // 2
                pairs.append((nd, pos, name_a, name_b))
    pairs.sort(key=lambda t: (-t[0], -t[1]))
    return [(na, nb) for _, _, na, nb in pairs]


def _record_side(binary, func_names, source_root, args, timeout, source_hint=None):
    """Record decision events, trying each candidate function name.

    ``source_hint`` (a file path) narrows the source lookup to the caller's
    file first — same-name functions exist in several files (e.g. _TIFFmemcpy
    in tif_unix.c vs a fake match in tif_dir.c).

    Results are cached per (binary, function, source root, args): the same
    function is recorded many times during the recursive descent (from
    different parents / depths), and record_decisions is a full GDB run of
    the whole program — replaying it is pure waste.  The recording is
    deterministic (same binary + input + function => same decision events),
    so the cache does not change the result.
    """
    root_eff = source_root
    if source_hint:
        hint_dir = str(Path(source_hint).parent)
        try:
            if any(is_function_definition(source_hint, n) for n in func_names):
                root_eff = hint_dir
        except Exception:
            pass
    # The hint only narrows the STATIC source lookup — the authoritative
    # file comes from GDB debug info, so the recording is identical either
    # way.  Check the hint-free key first: the same callee descended from
    # different parents (different hints) previously got different cache
    # keys and re-ran the whole recording for each parent.
    base_key = (binary, tuple(func_names), source_root, tuple(args))
    if base_key in _RECORD_CACHE:
        return _RECORD_CACHE[base_key]
    key = (binary, tuple(func_names), root_eff, tuple(args))
    if key in _RECORD_CACHE:
        return _RECORD_CACHE[key]
    for fname in func_names:
        try:
            r = record_decisions(binary, fname, args, source_root=root_eff,
                                 timeout=timeout)
        except Exception as e:
            r = {'error': f'record failed: {e}'}
        if r and not r.get('error') and not r.get('bp_fail'):
            _RECORD_CACHE[key] = (r, fname)
            if key != base_key:
                _RECORD_CACHE[base_key] = (r, fname)
            return r, fname
        if r and r.get('error'):
            _RECORD_CACHE[key] = (r, None)
            if key != base_key:
                _RECORD_CACHE[base_key] = (r, None)
            return r, None
    _RECORD_CACHE[key] = (None, None)
    if key != base_key:
        _RECORD_CACHE[base_key] = (None, None)
    return None, None


def _fork_summary(res, func_a, func_b):
    """Human-readable summary line for a fork result."""
    if not res or res.get('status') not in ('decision_fork', 'value_fork'):
        return ''
    fa = res.get('function_a') or func_a
    fb = res.get('function_b') or func_b
    if res['status'] == 'decision_fork':
        d = res['diff']
        a, b = d['a'], d['b']
        return (f'decision fork in {fa}/{fb} (inv {res["invocation"]}, '
                f'decision #{d["index"]}, kind={d["kind"]}'
                f'{", weak" if res.get("weak") else ""}): '
                f'A[L{a.get("line")}] outcome={a.get("outcome")} '
                f'clauses={a.get("clauses")} '
                f'| B[L{b.get("line")}] outcome={b.get("outcome")} '
                f'clauses={b.get("clauses")}')
    return (f'value fork in {fa}/{fb} (inv {res["invocation"]}): '
            f'A return={res.get("ret_a")} | B return={res.get("ret_b")}')


def build_dynamic_result(res, boundary_func, source_root_a, source_root_b,
                         input_file=None, fork_meta=None):
    """Assemble a divergence-result dict (the shape .diverge.json consumers
    expect) from a unified dynamic locator result.

    Statements are the REAL source lines of both versions at the fork
    decision (never synthetic descriptions); variables come from the guard's
    operands, ready for value-level taint instrumentation.
    """
    out = {'dynamic_fork': res}
    if res.get('status') not in ('decision_fork', 'value_fork'):
        return out
    fa = res.get('function_a') or boundary_func
    fb = res.get('function_b') or boundary_func

    def _loc(name, root):
        try:
            return _locate_function_source(name, root)
        except Exception:
            return None

    file_a = res.get('file_a') or _loc(fa, source_root_a)
    file_b = res.get('file_b') or _loc(fb, source_root_b) or file_a
    out['divergence_function'] = boundary_func
    out['root_cause_function'] = fb
    out['root_cause_file'] = os.path.basename(file_b or '') or fa
    out['root_cause_file_a'] = file_a
    out['root_cause_file_b'] = file_b

    if res['status'] == 'decision_fork':
        d = res['diff']
        a, b = d['a'], d['b']
        out['root_cause_line'] = b.get('line')
        out['root_cause_line_a'] = a.get('line')
        out['root_cause_line_b'] = b.get('line')
        out['root_cause_statement_a'] = a.get('text', '')
        out['root_cause_statement_b'] = b.get('text', '')
        variables = []
        exprs = a.get('exprs') or b.get('exprs') or []
        ca = a.get('clauses') or {}
        cb = b.get('clauses') or {}
        for i, (lhs_e, rhs_e) in enumerate(exprs):
            key = str(i)
            va, vb = ca.get(key, {}), cb.get(key, {})
            for side, expr in (('lhs', lhs_e), ('rhs', rhs_e)):
                if not expr:
                    continue
                if re.fullmatch(r'[0-9xXa-fA-F_]+', expr):
                    continue
                if re.fullmatch(r'[A-Z_][A-Z0-9_]*', expr):
                    continue  # macro constant
                # Prefer the side whose runtime value differs between the
                # two versions (the mutation-relevant operand).
                if va.get(side) != vb.get(side) and expr not in variables:
                    variables.append(expr)
        if not exprs:
            # Extract full member-access chains (e.g.
            # ``tif->tif_fields[mb]->field_tag``) rather than splitting them
            # into individual identifiers: struct members like ``field_tag``
            # are not standalone lvalues and cannot be instrumented.
            for text in (a.get('text', ''), b.get('text', '')):
                for v in extract_variables_from_statement(text):
                    if v not in variables:
                        variables.append(v)
        out['variables'] = variables
        verdict = 'weak' if res.get('weak') else 'strong'
        if res.get('absorbed'):
            verdict += ', ABSORBED (may not be causal — reported as fallback)'
        out['description'] = (
            f"Unified dynamic fork locator ({verdict}):\n"
            f"Divergence function: {boundary_func}\n"
            f"Fork function: {fa} / {fb}\n"
            f"Invocation #{res['invocation']} (of {res['a_invocations']} vs "
            f"{res['b_invocations']}), decision #{d['index']} "
            f"(kind={d['kind']})\n"
            f"  Reference: {a.get('text', '')}  "
            f"({os.path.basename(file_a or '')}:{a.get('line')}) "
            f"outcome={a.get('outcome')} clauses={a.get('clauses')}\n"
            f"  Target:    {b.get('text', '')}  "
            f"({os.path.basename(file_b or '')}:{b.get('line')}) "
            f"outcome={b.get('outcome')} clauses={b.get('clauses')}")
    else:
        out['root_cause_line'] = None
        out['root_cause_line_a'] = None
        out['root_cause_line_b'] = None
        out['root_cause_statement_a'] = ''
        out['root_cause_statement_b'] = ''
        out['description'] = (
            f"Unified dynamic fork locator (value fork):\n"
            f"Fork function: {fa} / {fb}, invocation #{res['invocation']}\n"
            f"  Reference return: {res.get('ret_a')}\n"
            f"  Target return:    {res.get('ret_b')}")
    if input_file:
        out['input_file'] = str(input_file)
    if fork_meta:
        out['fork_chain'] = fork_meta
    return out


def _null_compare_fork(diff):
    """True when the strong fork compares a pointer/return value to NULL —
    a wrapper-level fork (e.g. ``if (in == NULL)`` after TIFFOpen)."""
    if not diff:
        return False
    a, b = diff.get('a') or {}, diff.get('b') or {}
    text = (a.get('text') or '') + ' ' + (b.get('text') or '')
    return 'NULL' in text or 'null' in text


def _is_pointer_identifier(name, file_path):
    """True when ``name`` is declared as a pointer in ``file_path``.

    Handles single- and multi-declarator lines (``TIFF *in = NULL, *out;``,
    ``char *buf;``, ``const uint32_t *p = ...``)."""
    if not name or not file_path:
        return False
    try:
        lines = Path(file_path).read_text(errors='replace').splitlines()
    except Exception:
        return False
    # An identifier directly preceded by a '*' declarator.
    pat = re.compile(
        r'\*\s*(?:const\s+)?' + re.escape(name) + r'\b')
    for line in lines:
        if ';' not in line and '=' not in line:
            continue
        if pat.search(line):
            # Exclude arithmetic uses like `*in = ...` (deref) and
            # `x * in` (multiplication) — require a type token before the '*'
            # or a declarator context.
            for m in pat.finditer(line):
                before = line[max(0, m.start() - 30):m.start()]
                if re.search(r'[\w_]\s*\*$', before) or \
                        re.search(r'(?:^|[;,{])\s*(?:const\s+)?'
                                  r'[\w_]+\s*\*$', before):
                    return True
    return False


def _operands_pointer(diff, source_root, file_path=None):
    """True when the fork's differing operand is a POINTER-typed variable.

    Pointer variables (e.g. ``in``, ``tif``) are taint-dead: their value is
    an address / NULL, not an input byte, so value-level taint analysis
    cannot localize them — the fork must descend into the producer chain
    until a scalar guard is found.  Scalar operands are taint-friendly and
    the fork is reported directly.
    """
    operands = set()
    for side in (diff.get('a') or {}, diff.get('b') or {}):
        for expr_a, expr_b in side.get('exprs') or []:
            for expr in (expr_a, expr_b):
                if not expr:
                    continue
                base = re.split(r'->|\.|\[', expr)[0].strip()
                if re.fullmatch(r'[A-Za-z_]\w*', base):
                    operands.add(base)
    if not operands:
        return False
    for name in operands:
        if _is_pointer_identifier(name, file_path):
            return True
    # Fallback: the polytracker decl resolver (may miss multi-declarator
    # lines, but covers header-declared variables).
    if source_root:
        try:
            from polytracker_offsets import _resolve_pointer_vars
            ptrs = _resolve_pointer_vars(str(source_root), sorted(operands))
            if set(ptrs or []) & operands:
                return True
        except Exception:
            pass
    return False



def _same_operands(diff):
    """True when both sides evaluated the SAME operand values at the fork.

    Same values + different outcome = a CODE-CHANGE fork (the code decides
    differently, e.g. an added guard or a rewritten branch): mutating the
    input cannot flip it.  The mutation-relevant fork is the deeper STATE
    fork that makes the operands differ — so descend.
    """
    a = (diff.get('a') or {}).get('clauses') or {}
    b = (diff.get('b') or {}).get('clauses') or {}
    return _value_tuple(a) == _value_tuple(b) and bool(a or b)

def _needs_descent(diff, source_root, file_path=None):
    """Descent is needed only when the fork's differing operands are
    taint-dead: pointer variables or NULL comparisons.  Scalar guards are
    reported directly (their operands can be tainted)."""
    return (_null_compare_fork(diff)
            or _operands_pointer(diff, source_root, file_path=file_path))


def _producer_candidates(diff, source_file_a, source_file_b,
                         cnt_a, cnt_b, refactoring_map):
    """Function names that produce the NULL-comparison operands.

    ``if (in == NULL)`` -> look for ``in = TIFFOpen(...)`` in the caller's
    source and return TIFFOpen as the function to descend into FIRST — the
    real guard lives inside the producer, not in any random callee.
    """
    operands = set()
    for side in (diff.get('a') or {}, diff.get('b') or {}):
        for expr_a, expr_b in side.get('exprs') or []:
            for expr in (expr_a, expr_b):
                if expr and re.fullmatch(r'[A-Za-z_]\w*', expr):
                    operands.add(expr)
    producers = []
    for src, cnt in ((source_file_a, cnt_a), (source_file_b, cnt_b)):
        if not src:
            continue
        try:
            text = Path(src).read_text(errors='replace')
        except Exception:
            continue
        for name in operands:
            for m in re.finditer(r'\b' + re.escape(name) + r'\s*=\s*'
                                 r'([A-Za-z_]\w*)\s*\(', text):
                prod = m.group(1)
                if prod not in producers:
                    producers.append(prod)
    # Pair with matching counts on the other side (min-count rule: the
    # target may have bailed out and stopped calling it).
    out = []
    for prod_a in producers:
        for prod_b, cb in cnt_b.items():
            if min(cnt_a.get(prod_a, 0), cb) >= 1 and _name_pair(
                    prod_a, prod_b, refactoring_map):
                out.append((prod_a, prod_b))
                break
    return out


def _is_absorbed(sub, ia, ib, refactoring_map):
    """DDA-style causality check: is the callee-level fork F absorbed?

    F (found in callee C, invocation k) is ABSORBED when the parent's own
    decisions AFTER the k-th call to C are still identical on both sides —
    i.e. the callee's divergence did not change the caller's later behavior.
    Absorbed forks are not causal: the descent must continue.
    """
    if sub.get('status') != 'decision_fork':
        return False
    fa = sub.get('function_a')
    k = sub.get('invocation') or 1

    def _call_events(inv, name):
        return [c for c in inv.get('calls') or []
                if any(_name_pair(n, name, refactoring_map)
                       for n in c.get('callees') or [])]

    ca = _call_events(ia, fa)
    cb = _call_events(ib, fa)
    if not ca and not cb:
        return False  # no call visible on either side — cannot judge
    if ca and cb:
        o = max(ca[min(k - 1, len(ca) - 1)].get('order', 0),
                cb[min(k - 1, len(cb) - 1)].get('order', 0))
    else:
        side = ca or cb
        o = side[min(k - 1, len(side) - 1)].get('order', 0)

    later_a = [ev for ev in ia.get('events') or []
               if ev.get('n', 0) > o]
    later_b = [ev for ev in ib.get('events') or []
               if ev.get('n', 0) > o]
    if not later_a and not later_b:
        return False  # no later parent decisions — treat as NOT absorbed
    if len(later_a) != len(later_b):
        return False  # path lengths differ afterwards — divergence propagates
    for ea, eb in zip(later_a, later_b):
        da, db = ea.get('outcome'), eb.get('outcome')
        if da != db and da is not None and db is not None:
            return False  # later parent decision differs — NOT absorbed
    return True
def locate_fork_dynamically(binary_a, binary_b, source_root_a, source_root_b,
                            func_a, args, refactoring_map=None, timeout=300,
                            max_depth=6, _depth=0, _visited=None,
                            _hint_a=None, _hint_b=None):
    """Unified dynamic fork locator (see module docstring).

    Returns a dict with ``status`` in
    ``{decision_fork, value_fork, no_divergence, record_failed, error}`` plus
    the evidence (per-invocation comparison, statements and values on both
    sides).  The recursion chain is stored under ``chain``.
    """
    if _visited is None:
        _visited = set()
    key = (func_a, _depth)
    if key in _visited or _depth > max_depth:
        return {'status': 'no_divergence',
                'reason': f'recursion limit reached at {func_a}'}
    _visited.add(key)

    if _is_noise_func(func_a):
        return {'status': 'no_divergence',
                'reason': f'error/warning reporting function {func_a} '
                          f'(excluded — not a causal fork)'}

    func_b = func_a
    if refactoring_map:
        func_b = refactoring_map.get(func_a, func_a)
    try_names_b = list(dict.fromkeys([func_b, func_a]))
    indent = '  ' * _depth
    print(f'{indent}[unified] level {_depth}: {func_a} '
          f'(B side tried: {try_names_b})')

    # Record both sides in parallel (two independent GDB runs; the
    # recordings are independent and deterministic, so this halves the
    # GDB time without changing the result).
    from concurrent.futures import ThreadPoolExecutor
    with ThreadPoolExecutor(max_workers=2) as _ex:
        _fa = _ex.submit(_record_side, binary_a, [func_a], source_root_a,
                         args, timeout, _hint_a)
        _fb = _ex.submit(_record_side, binary_b, try_names_b, source_root_b,
                         args, timeout, _hint_b)
        ra, used_a = _fa.result()
        rb, used_b = _fb.result()
    if ra is None:
        return {'status': 'record_failed', 'side': 'a', 'func': func_a}
    if rb is None:
        return {'status': 'record_failed', 'side': 'b', 'func': func_b}
    print(f'{indent}[unified] recorded A={len(ra.get("invocations") or [])} '
          f'inv, B={len(rb.get("invocations") or [])} inv')

    inv_a = ra.get('invocations') or []
    inv_b = rb.get('invocations') or []
    n = min(len(inv_a), len(inv_b))

    def _find_diff(strong_only=False):
        for i in range(n - 1, -1, -1):
            diff = compare_invocations(inv_a[i], inv_b[i])
            if diff and (not strong_only or diff.get('strong')):
                return i, diff
        return None, None

    def _try_candidates(null_diff=None):
        """Descend into callees; ``null_diff`` (a wrapper-level NULL fork)
        prioritizes the operand producers (e.g. TIFFOpen for ``in == NULL``).
        Returns the strongest fork found below, or None."""
        if n == 0:
            return None
        # Use the LAST ALIGNED invocation pair: when the sides' call counts
        # differ (the target bailed out), each side's last invocation is NOT
        # the same logical call (e.g. A's 2nd TIFFOpen = the OUTPUT file).
        ia_last = inv_a[n - 1]
        ib_last = inv_b[n - 1]
        cand = _recurse_candidates(ia_last, ib_last, refactoring_map,
                                   source_root_a, source_root_b)
        cnt_a = {}
        for c in ia_last.get('calls') or []:
            for name in c.get('callees') or []:
                cnt_a[name] = cnt_a.get(name, 0) + 1
        cnt_b = {}
        for c in ib_last.get('calls') or []:
            for name in c.get('callees') or []:
                cnt_b[name] = cnt_b.get(name, 0) + 1
        priority = []
        if null_diff:
            priority = _producer_candidates(null_diff, ra.get('file'),
                                            rb.get('file'), cnt_a, cnt_b,
                                            refactoring_map)
        order = priority + [c for c in cand if c not in priority]
        # Drop error/warning reporting functions from the candidates.
        order = [c for c in order if not _is_noise_func(c[0])]
        print(f'{indent}[unified] candidates: '
              + ', '.join(f'{a}|{b}' for a, b in order[:8]))
        weak_best = None
        absorbed_best = None
        last_nonabsorbed = None
        last_order = -1

        def _descend(callee_a, callee_b):
            return locate_fork_dynamically(
                binary_a, binary_b, source_root_a, source_root_b, callee_a,
                args, refactoring_map=refactoring_map, timeout=timeout,
                max_depth=max_depth, _depth=_depth + 1, _visited=_visited,
                _hint_a=ra.get('file'), _hint_b=rb.get('file'))

        # Candidate subtrees are independent GDB-heavy searches (each one
        # runs both binaries to completion under breakpoints).  Descend into
        # them in parallel down to depth 4 — the fork search's WIDE levels
        # (a caller with 5-8 candidate callees) sit at depth 4-5 (e.g.
        # TIFFReadDirectory's callees when the anchor is `main`), and the
        # global GDB semaphore in decision_trace caps the actual concurrent
        # GDB subprocesses to the machine's core/memory budget.  Deeper
        # levels run sequentially inside the workers.  Shared
        # _visited/_RECORD_CACHE are GIL-safe (set/dict writes); a rare
        # duplicate recording is benign.
        candidates = order[:8]
        subs = []
        if len(candidates) > 1:
            from concurrent.futures import ThreadPoolExecutor
            with ThreadPoolExecutor(max_workers=min(3, len(candidates))) as _ex:
                _futs = {_ex.submit(_descend, a, b): (a, b)
                         for a, b in candidates}
                for _fut in _futs:
                    _ca, _cb = _futs[_fut]
                    subs.append((_ca, _cb, _fut.result()))
        else:
            subs = [(a, b, _descend(a, b)) for a, b in candidates]

        for callee_a, callee_b, sub in subs:
            print(f'{indent}[unified]   -> {callee_a}: {sub.get("status")} '
                  f'{sub.get("reason", "")}')
            # The callee's LAST call position in the parent's execution:
            # among non-absorbed forks we want the one executed LAST on the
            # trajectory (earlier forks usually re-converge).
            callee_order = -1
            for _c in ia_last.get('calls') or []:
                if any(_name_pair(_nn, callee_a, refactoring_map)
                       for _nn in _c.get('callees') or []):
                    callee_order = max(callee_order, _c.get('order', 0))
            # A callee-level count fork is usually an ABSORBED divergence
            # (extra/removed statements that do not change the caller's
            # later behavior) — only outcome/value/text forks are decisive.
            if sub.get('status') == 'decision_fork' and not sub.get('weak') \
                    and sub.get('diff', {}).get('kind') in \
                    ('outcome', 'value', 'text'):
                if _is_absorbed(sub, ia_last, ib_last, refactoring_map):
                    print(f'{indent}[unified]     !! absorbed '
                          f'(parent decisions after the call still match) — '
                          f'continuing descent')
                    if absorbed_best is None:
                        sub['absorbed'] = True
                        absorbed_best = sub
                    continue
                if callee_order >= last_order:
                    last_order = callee_order
                    last_nonabsorbed = sub
                continue
            if sub.get('status') == 'value_fork':
                if _is_absorbed(sub, ia_last, ib_last, refactoring_map):
                    print(f'{indent}[unified]     !! absorbed value fork — '
                          f'continuing descent')
                    if absorbed_best is None:
                        sub['absorbed'] = True
                        absorbed_best = sub
                    continue
                if callee_order >= last_order:
                    last_order = callee_order
                    last_nonabsorbed = sub
                continue
            if sub.get('status') == 'decision_fork' and sub.get('weak') \
                    and weak_best is None:
                weak_best = sub
        if last_nonabsorbed:
            print(f'{indent}[unified]   -> LAST non-absorbed fork: '
                  f'{last_nonabsorbed.get("function_a", "?")}:'
                  f'{last_nonabsorbed.get("diff", {}).get("b", {}).get("line", "?")} '
                  f'(order {last_order})')
            return last_nonabsorbed
        if absorbed_best:
            print(f'{indent}[unified]   no non-absorbed fork found — '
                  f'reporting the best absorbed one')
        return weak_best or absorbed_best

    # 1) STRONG decision-level fork (outcome / count): the path itself
    #    diverges here — report immediately (closest to crash first),
    #    unless it is a wrapper-level NULL/pointer fork whose real guard
    #    lives deeper inside the pointer's producer.
    i, diff = _find_diff(strong_only=True)
    if diff:
        is_code_change = (diff.get('kind') == 'outcome'
                          and _same_operands(diff))
        if _needs_descent(diff, source_root_a, file_path=ra.get('file')):
            print(f'{indent}[unified] wrapper/pointer-level fork at '
                  f'{used_a}:{diff["a"].get("line")} (taint-dead operands) '
                  f'— descending into the producer chain')
            sub = _try_candidates(null_diff=diff)
            if sub:
                return sub
            print(f'{indent}[unified]   no deeper strong fork — '
                  f'reporting the wrapper fork itself')
        elif is_code_change:
            print(f'{indent}[unified] code-change fork at '
                  f'{used_a}:{diff["a"].get("line")} (identical operand '
                  f'values, different outcome — input mutation cannot flip '
                  f'it) — descending to find the state fork')
            sub = _try_candidates(null_diff=None)
            if sub:
                return sub
            print(f'{indent}[unified]   no deeper state fork — '
                  f'reporting the code-change fork itself')
        else:
            print(f'{indent}[unified] scalar-operand fork at '
                  f'{used_a}:{diff["a"].get("line")} — descending to find '
                  f'the LAST fork (earlier forks may re-converge)')
            sub = _try_candidates(null_diff=None)
            if sub:
                return sub
            print(f'{indent}[unified]   no deeper fork — '
                  f'reporting the fork itself')
        return {
            'status': 'decision_fork',
            'function_a': used_a, 'function_b': used_b,
            'file_a': ra.get('file'), 'file_b': rb.get('file'),
            'invocation': i + 1,
            'a_invocations': len(inv_a), 'b_invocations': len(inv_b),
            'diff': diff,
            'a_events': len(inv_a[i].get('events') or []),
            'b_events': len(inv_b[i].get('events') or []),
            'chain': _visited_copy(_visited),
        }

    # 2) No strong divergence: descend into callees first — a weak diff at
    #    this level may merely reflect deeper callee state.
    sub = _try_candidates()
    if sub:
        return sub

    # 3) Weak decision-level fork (text rewrite / operand-value difference).
    i, diff = _find_diff(strong_only=False)
    if diff and not diff.get('strong'):
        return {
            'status': 'decision_fork',
            'function_a': used_a, 'function_b': used_b,
            'file_a': ra.get('file'), 'file_b': rb.get('file'),
            'invocation': i + 1,
            'a_invocations': len(inv_a), 'b_invocations': len(inv_b),
            'diff': diff,
            'weak': True,
            'a_events': len(inv_a[i].get('events') or []),
            'b_events': len(inv_b[i].get('events') or []),
            'chain': _visited_copy(_visited),
        }

    # 4) Value-level comparison (function return values).
    for i in range(n - 1, -1, -1):
        ra_r, rb_r = inv_a[i].get('return'), inv_b[i].get('return')
        if ra_r in (None, '?') or rb_r in (None, '?'):
            continue
        if not _ret_equal(ra_r, rb_r):
            return {
                'status': 'value_fork',
                'function_a': used_a, 'function_b': used_b,
                'file_a': ra.get('file'), 'file_b': rb.get('file'),
                'invocation': i + 1,
                'ret_a': ra_r, 'ret_b': rb_r,
                'a_invocations': len(inv_a), 'b_invocations': len(inv_b),
                'chain': _visited_copy(_visited),
            }

    if len(inv_a) != len(inv_b):
        return {
            'status': 'invocation_diff',
            'function_a': used_a, 'function_b': used_b,
            'a_invocations': len(inv_a), 'b_invocations': len(inv_b),
            'chain': _visited_copy(_visited),
        }
    return {'status': 'no_divergence',
            'reason': f'no divergence in {used_a} nor its common callees'}
def _visited_copy(visited):
    return list(visited)


# --------------------------------------------------------------------------
# CLI (standalone verification)
# --------------------------------------------------------------------------

def main():
    ap = argparse.ArgumentParser(description=__doc__)
    ap.add_argument('--binary-a', required=True)
    ap.add_argument('--binary-b', required=True)
    ap.add_argument('--source-a', required=True, help='version A source root')
    ap.add_argument('--source-b', required=True, help='version B source root')
    ap.add_argument('--func', required=True, help='boundary (innermost common) function')
    ap.add_argument('--timeout', type=int, default=300)
    ap.add_argument('--depth', type=int, default=6)
    ap.add_argument('--out', help='save the locator JSON result')
    ap.add_argument('--args', nargs=argparse.REMAINDER, default=[])
    a = ap.parse_args()

    res = locate_fork_dynamically(
        a.binary_a, a.binary_b, a.source_a, a.source_b, a.func,
        a.args, timeout=a.timeout, max_depth=a.depth)
    if a.out:
        Path(a.out).write_text(json.dumps(res, indent=2, ensure_ascii=False))
    print(json.dumps(res, indent=2, ensure_ascii=False))
    print('\nSummary:', _fork_summary(res, a.func, a.func))


if __name__ == '__main__':
    main()