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
from decision_trace import is_function_definition
from trace_fork_offsets import extract_variables_from_statement

_SEMANTIC_SUFFIXES = ('WithLimit', 'Checked', 'Safe', 'Ex', 'NoSSE', 'Array')


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
    for k in range(n):
        ea, eb = ev_a[k], ev_b[k]
        da, db = ea.get('outcome'), eb.get('outcome')
        if da != db and da is not None and db is not None:
            return {'kind': 'outcome', 'strong': True, 'index': k,
                    'a': {'line': ea['line'], 'text': ea.get('text', ''),
                          'clauses': ea.get('clauses', {}), 'outcome': da},
                    'b': {'line': eb['line'], 'text': eb.get('text', ''),
                          'clauses': eb.get('clauses', {}), 'outcome': db}}
        ta, tb = _norm(ea.get('text', '')), _norm(eb.get('text', ''))
        if ta and tb and ta != tb:
            return {'kind': 'text', 'strong': False, 'index': k,
                    'a': {'line': ea['line'], 'text': ea.get('text', ''),
                          'clauses': ea.get('clauses', {}), 'outcome': da},
                    'b': {'line': eb['line'], 'text': eb.get('text', ''),
                          'clauses': eb.get('clauses', {}), 'outcome': db}}
        va, vb = _value_tuple(ea.get('clauses') or {}), \
            _value_tuple(eb.get('clauses') or {})
        if va and vb and va != vb:
            return {'kind': 'value', 'strong': False, 'index': k,
                    'a': {'line': ea['line'], 'text': ea.get('text', ''),
                          'clauses': ea.get('clauses', {}), 'outcome': da},
                    'b': {'line': eb['line'], 'text': eb.get('text', ''),
                          'clauses': eb.get('clauses', {}), 'outcome': db}}
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
    """Callees invoked the same number of times on both sides, ranked by
    static decision density (most decision-dense first: the divergence is
    likeliest inside functions with their own guards), then by their last
    call position (closest to the function exit) as a tiebreak."""
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
        try:
            fsrc = _locate_function_source(name, source_root)
            if not fsrc:
                return 0
            return len(find_function_decisions(fsrc, name))
        except Exception:
            return 0

    pairs = []
    for name_a, ca in cnt_a.items():
        for name_b, cb in cnt_b.items():
            if ca == cb and _name_pair(name_a, name_b, refactoring_map):
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
    """
    root_eff = source_root
    if source_hint:
        hint_dir = str(Path(source_hint).parent)
        try:
            if any(is_function_definition(source_hint, n) for n in func_names):
                root_eff = hint_dir
        except Exception:
            pass
    for fname in func_names:
        try:
            r = record_decisions(binary, fname, args, source_root=root_eff,
                                 timeout=timeout)
        except Exception as e:
            r = {'error': f'record failed: {e}'}
        if r and not r.get('error') and not r.get('bp_fail'):
            return r, fname
        if r and r.get('error'):
            return r, None
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
                f'A[L{a["line"]}] outcome={a["outcome"]} clauses={a["clauses"]} '
                f'| B[L{b["line"]}] outcome={b["outcome"]} clauses={b["clauses"]}')
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

    file_a = _loc(fa, source_root_a)
    file_b = _loc(fb, source_root_b) or file_a
    out['divergence_function'] = boundary_func
    out['root_cause_function'] = fb
    out['root_cause_file'] = os.path.basename(file_b or '') or fa
    out['root_cause_file_a'] = file_a
    out['root_cause_file_b'] = file_b

    if res['status'] == 'decision_fork':
        d = res['diff']
        a, b = d['a'], d['b']
        out['root_cause_line'] = b['line']
        out['root_cause_line_a'] = a['line']
        out['root_cause_line_b'] = b['line']
        out['root_cause_statement_a'] = a.get('text', '')
        out['root_cause_statement_b'] = b.get('text', '')
        variables = []
        for cl in (a.get('clauses') or {}).values():
            for side in ('lhs', 'rhs'):
                expr = cl.get(side, '')
                if expr and not re.fullmatch(r'0x[0-9a-fA-F]+|\d+', expr):
                    variables.append(expr)
        variables += extract_variables_from_statement(a.get('text', ''))
        variables += extract_variables_from_statement(b.get('text', ''))
        out['variables'] = list(dict.fromkeys(variables))
        verdict = 'weak' if res.get('weak') else 'strong'
        out['description'] = (
            f"Unified dynamic fork locator ({verdict}):\n"
            f"Divergence function: {boundary_func}\n"
            f"Fork function: {fa} / {fb}\n"
            f"Invocation #{res['invocation']} (of {res['a_invocations']} vs "
            f"{res['b_invocations']}), decision #{d['index']} "
            f"(kind={d['kind']})\n"
            f"  Reference: {a.get('text', '')}  "
            f"({os.path.basename(file_a or '')}:{a['line']}) "
            f"outcome={a.get('outcome')} clauses={a.get('clauses')}\n"
            f"  Target:    {b.get('text', '')}  "
            f"({os.path.basename(file_b or '')}:{b['line']}) "
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


def locate_fork_dynamically(binary_a, binary_b, source_root_a, source_root_b,
                            func_a, args, refactoring_map=None, timeout=300,
                            max_depth=4, _depth=0, _visited=None,
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

    func_b = func_a
    if refactoring_map:
        func_b = refactoring_map.get(func_a, func_a)
    try_names_b = list(dict.fromkeys([func_b, func_a]))
    indent = '  ' * _depth
    print(f'{indent}[unified] level {_depth}: {func_a} '
          f'(B side tried: {try_names_b})')

    ra, used_a = _record_side(binary_a, [func_a], source_root_a, args, timeout,
                              source_hint=_hint_a)
    if ra is None:
        return {'status': 'record_failed', 'side': 'a', 'func': func_a}
    rb, used_b = _record_side(binary_b, try_names_b, source_root_b, args,
                              timeout, source_hint=_hint_b)
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

    # 1) STRONG decision-level fork (outcome / count): the path itself
    #    diverges here — report immediately (closest to crash first).
    i, diff = _find_diff(strong_only=True)
    if diff:
        return {
            'status': 'decision_fork',
            'function_a': used_a, 'function_b': used_b,
            'invocation': i + 1,
            'a_invocations': len(inv_a), 'b_invocations': len(inv_b),
            'diff': diff,
            'a_events': len(inv_a[i].get('events') or []),
            'b_events': len(inv_b[i].get('events') or []),
            'chain': _visited_copy(_visited),
        }

    # 2) No strong divergence: descend into callees first — a weak diff at
    #    this level may merely reflect deeper callee state.
    if n == 0:
        return {'status': 'no_divergence',
                'reason': 'no invocations recorded at this level'}
    cand = _recurse_candidates(inv_a[-1], inv_b[-1], refactoring_map,
                               source_root_a, source_root_b)
    print(f'{indent}[unified] candidates: '
          + ', '.join(f'{a}|{b}' for a, b in cand[:6]))
    weak_best = None
    for callee_a, callee_b in cand[:6]:
        sub = locate_fork_dynamically(
            binary_a, binary_b, source_root_a, source_root_b, callee_a,
            args, refactoring_map=refactoring_map, timeout=timeout,
            max_depth=max_depth, _depth=_depth + 1, _visited=_visited,
            _hint_a=ra.get('file'), _hint_b=rb.get('file'))
        print(f'{indent}[unified]   -> {callee_a}: {sub.get("status")} '
              f'{sub.get("reason", "")}')
        if sub.get('status') == 'decision_fork' and not sub.get('weak'):
            return sub
        if sub.get('status') == 'value_fork':
            return sub
        if sub.get('status') == 'decision_fork' and weak_best is None:
            weak_best = sub
    if weak_best:
        return weak_best

    # 3) Weak decision-level fork (text rewrite / operand-value difference).
    i, diff = _find_diff(strong_only=False)
    if diff and not diff.get('strong'):
        return {
            'status': 'decision_fork',
            'function_a': used_a, 'function_b': used_b,
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
    ap.add_argument('--depth', type=int, default=4)
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