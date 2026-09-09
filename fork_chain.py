#!/usr/bin/env python3
"""Crash-anchored reverse fork-chain analysis (generic, no project heuristics).

When the *reference* version crashes on the PoC but the *target* version does
not reach the same crash, the decisive fork is the LAST point (in the
reference's execution order) where the target was still following the same
call path before the crash.  Walking the reference trace BACKWARD from the
crash and anchoring on that point is far more reliable than scoring LCS gaps
with project-specific hints (TIFFErrorExt / warning asymmetry / ...).

This module is trace-level only: it consumes the LCS decomposition output
(trace_A / trace_B / matches / gaps, as written by lcs_trace.py) plus the
reference crash point (function/file/line as detected by
divergence_analyzer._detect_crash_point), and produces:

  * the fork boundary       — the last matched A/B position right before the
                              reference leaves the shared path,
  * the innermost common function at that boundary (the divergence function),
  * the first A-only / B-only activity after the boundary,
  * the A-only chain from the boundary to the crash (the path the reference
    took that the target never followed),
  * sanity flags            — rejoin detection, crash-inside-common-block,
                              gap spans, distance from boundary to crash.

No function name, warning/error function or source keyword of any specific
project is referenced here.  Cross-version renames are handled through the
refactoring map (either direction is tolerated).
"""

import argparse
import json
import os
import sys

# --------------------------------------------------------------------------
# Small shared helpers
# --------------------------------------------------------------------------

def _name_equal(n1, n2, refactoring_map=None):
    """Name equality across versions, tolerant to the rename map's direction.

    The map may be old->new or new->old depending on the pipeline stage; both
    directions are accepted.
    """
    if n1 is None or n2 is None:
        return False
    if n1 == n2:
        return True
    if refactoring_map:
        if refactoring_map.get(n1) == n2:
            return True
        if n1 == refactoring_map.get(n2):
            return True
    return False


def _sorted_blocks(blocks):
    """Sort LCS match/gap blocks by their position in trace A."""
    return sorted(
        (b for b in blocks if b),
        key=lambda b: (b.get("a_range") or [0, 0])[0])


def _path_basename(p):
    if not p:
        return None
    b = os.path.basename(str(p))
    return b or str(p)


# --------------------------------------------------------------------------
# Core analysis
# --------------------------------------------------------------------------

def find_crash_anchor(trace_a, crash_a):
    """Return the index in trace A of the crash function's last invocation.

    The crash cuts the instrumented trace short, so the faulting function's
    LAST ``enter`` event is where the crash happened.  Falls back to the end
    of the trace when the function cannot be found (e.g. inlined).
    """
    crash_func = (crash_a or {}).get("function")
    if not crash_func:
        return None
    idx = None
    for i, nd in enumerate(trace_a):
        if nd.get("name") == crash_func and nd.get("is_enter", True):
            idx = i
    if idx is None:
        return None
    return idx


def _innermost_common_at_boundary(a_event, b_event, refactoring_map=None):
    """The deepest function still executing when the two traces split.

    ``a_event``/``b_event`` are the last matched trace nodes (one from each
    side) right before the fork gap.  The decision that sent the reference
    into its own (crashing) path and the target into its own path is taken by:

      * the event itself when it is a function *enter* (both sides are inside
        it and the next call differs), or
      * its caller (path[-2]) when the event is an *exit* (the call choice of
        the parent function diverges next).
    """
    if a_event is None or b_event is None:
        return None
    if not _name_equal(a_event.get("name"), b_event.get("name"),
                       refactoring_map):
        return None
    path = a_event.get("path") or []
    if a_event.get("is_enter", True):
        return a_event.get("name")
    if len(path) >= 2:
        return path[-2]
    return a_event.get("name")


def compute_fork_chain(trace_a, trace_b, matches, gaps, crash_a,
                       refactoring_map=None):
    """Anchor the fork analysis on the reference crash point.

    Returns a dict with the fork boundary, the first divergent activities on
    each side, the A-only chain toward the crash and diagnostics.  Pure
    trace-level computation; no GDB, no source code, no project keywords.
    """
    result = {
        "method": "crash_anchor",
        "classified": False,
        "notes": [],
    }
    trace_a = trace_a or []
    trace_b = trace_b or []
    gs = _sorted_blocks(gaps)
    ms = _sorted_blocks(matches)
    crash_a = crash_a or {}

    crash_i = find_crash_anchor(trace_a, crash_a)
    crash_func = crash_a.get("function")
    if crash_i is None:
        # Crash function not seen in the trace (name mismatch, inlining, or the
        # crash is in a frame deeper than the last enter).  Anchor at the end.
        crash_i = len(trace_a) - 1
        result["notes"].append(
            f"crash function {crash_func!r} not found in reference trace; "
            f"anchoring at trace end (index {crash_i})")
    result["crash_anchor"] = {
        "index": crash_i,
        "function": crash_func or None,
        "file": crash_a.get("file"),
        "line": crash_a.get("line"),
    }

    if crash_i < 0:
        result["notes"].append("reference trace is empty")
        return result

    # The gap whose A-side contains the crash.  If none does, the crash is
    # inside a block both versions executed together -> statement-level fork.
    gap = None
    for g in gs:
        a_range = g.get("a_range") or [0, 0]
        if a_range[0] <= crash_i < a_range[1]:
            gap = g
            break
    if gap is None:
        # No gap covers the crash: everything up to the crash matched.  The
        # target followed the reference into the crash region, so the fork is
        # a value/statement divergence inside common code (needs statement
        # or variable level analysis, not trace level).
        last_gap = gs[-1] if gs else None
        result["classified"] = False
        result["classification"] = "crash_inside_common_block"
        result["notes"].append(
            "reference crash lies inside a common (matched) block — the "
            "target executed the same functions up to the crash point; "
            "localize the fork at statement/variable level on the crash line")
        if last_gap:
            result["fork_boundary"] = _describe_boundary(
                trace_a, trace_b, last_gap, refactoring_map)
        return result

    a_start, a_stop = gap.get("a_range") or [0, 0]
    b_start, b_stop = gap.get("b_range") or [0, 0]
    result["gap"] = {
        "a_range": [a_start, a_stop],
        "b_range": [b_start, b_stop],
        "a_events": a_stop - a_start,
        "b_events": b_stop - b_start,
        "spans_to_crash": a_stop >= len(trace_a),
        "contains_crash": True,
    }

    # The fork boundary: the last common position before the split.
    a_pred = a_start - 1
    b_pred = b_start - 1
    a_event = trace_a[a_pred] if 0 <= a_pred < len(trace_a) else None
    b_event = trace_b[b_pred] if 0 <= b_pred < len(trace_b) else None
    if a_event is not None and b_event is not None and not _name_equal(
            a_event.get("name"), b_event.get("name"), refactoring_map):
        # The events just before the gap do not correspond (the gap's A-side
        # may start in the middle of an open call).  Fall back to the last
        # matched block that ends right before the gap.
        a_event = b_event = None
        for m in reversed(ms):
            m_a = m.get("a_range") or [0, 0]
            m_b = m.get("b_range") or [0, 0]
            if m_a[1] <= a_start:
                ea = trace_a[m_a[1] - 1] if m_a[1] - 1 >= 0 else None
                eb = trace_b[m_b[1] - 1] if m_b[1] - 1 >= 0 else None
                a_event, b_event = ea, eb
                a_pred, b_pred = m_a[1] - 1, m_b[1] - 1
                break

    innermost = _innermost_common_at_boundary(
        a_event, b_event, refactoring_map)
    boundary = {
        "a_index": a_pred if a_event is not None else None,
        "b_index": b_pred if b_event is not None else None,
        "a_event": (a_event or {}).get("name"),
        "b_event": (b_event or {}).get("name"),
        "innermost_common_function": innermost,
    }

    # First divergent activity on each side (first enter events inside the gap).
    first_a = first_b = None
    for i in range(a_start, min(a_stop, len(trace_a))):
        nd = trace_a[i]
        if nd.get("is_enter", True):
            first_a = {"index": i, "function": nd.get("name")}
            break
    for j in range(b_start, min(b_stop, len(trace_b))):
        nd = trace_b[j]
        if nd.get("is_enter", True):
            first_b = {"index": j, "function": nd.get("name")}
            break

    # The A-only chain: every enter event from the boundary to the crash.
    chain = []
    depth = None
    for i in range(a_start, crash_i + 1):
        nd = trace_a[i]
        if nd.get("is_enter", True):
            chain.append({
                "a_index": i,
                "function": nd.get("name"),
            })
            d = len(nd.get("path") or [])
            depth = d if depth is None else max(depth, d)
    crash_path = trace_a[crash_i].get("path") if crash_i < len(trace_a) else None

    # Rejoin detection: do A and B re-synchronize AFTER this gap?  (An
    # earlier match can only rejoin B to a part of A that B already passed,
    # so a later match with a_range[0] > a_start is a genuine second common
    # segment after the fork.)
    later_matches = [m for m in ms if (m.get("a_range") or [0, 0])[0] > a_start]
    b_after = max(0, len(trace_b) - b_stop) if b_stop else 0
    # How much of the B-side post-gap segment does the crash region overlap?
    result.update({
        "classified": True,
        "classification": "crash_after_boundary",
        "crash_region": {
            "from_a_index": a_start,
            "a_only_events_to_crash": crash_i - a_start + 1,
            "a_only_enters_to_crash": len(chain),
            "max_call_depth": depth,
            "crash_path": crash_path,
        },
        "fork_boundary": boundary,
        "first_divergent_activity": {
            "a": first_a,
            "b": first_b,
        },
        "a_only_chain": chain,
        "rejoin_detected": bool(later_matches),
        "later_matches_after_fork": len(later_matches),
        "b_events_after_fork_gap": b_after,
    })

    if later_matches:
        result["notes"].append(
            f"{len(later_matches)} matched block(s) exist after the fork gap — "
            "the two versions re-synchronized later, so earlier divergences "
            "may influence the state used after the rejoin (expect multiple "
            "decisive forks)")
    if first_a and first_b and _name_equal(first_a["function"],
                                           first_b["function"],
                                           refactoring_map):
        result["notes"].append(
            "first divergent activity is the same function on both sides — "
            "the fork is a return-value/guard difference inside common code")
    if not result["gap"]["spans_to_crash"]:
        result["notes"].append(
            "the fork gap does not span to the reference trace end — "
            "additional matched blocks follow on the A side")
    return result


def _describe_boundary(trace_a, trace_b, gap, refactoring_map):
    a_start = (gap.get("a_range") or [0, 0])[0]
    b_start = (gap.get("b_range") or [0, 0])[0]
    a_event = trace_a[a_start - 1] if a_start - 1 >= 0 else None
    b_event = trace_b[b_start - 1] if b_start - 1 >= 0 else None
    return {
        "a_index": a_start - 1 if a_event is not None else None,
        "b_index": b_start - 1 if b_event is not None else None,
        "a_event": (a_event or {}).get("name"),
        "b_event": (b_event or {}).get("name"),
        "innermost_common_function": _innermost_common_at_boundary(
            a_event, b_event, refactoring_map),
    }


# --------------------------------------------------------------------------
# Selection API (used by divergence_analyzer)
# --------------------------------------------------------------------------

def select_fork_anchor(trace_a, trace_b, matches, gaps, crash_a,
                       refactoring_map=None):
    """Select (divergence_function, a_idx, b_idx) anchored on the crash.

    Returns ``(func_name, a_idx, b_idx, meta)``.  ``func_name`` is the
    innermost common function still executing when the traces split (the
    caller whose internal behavior diverges); the indexes point at the first
    divergent activity inside the fork gap on each side.  When no gap covers
    the crash, returns ``(None, -1, -1, meta)`` so callers can keep their
    existing fallback.
    """
    meta = compute_fork_chain(trace_a, trace_b, matches, gaps, crash_a,
                              refactoring_map)
    if not meta.get("classified"):
        return None, -1, -1, meta

    boundary = meta.get("fork_boundary") or {}
    first_a = (meta.get("first_divergent_activity") or {}).get("a")
    first_b = (meta.get("first_divergent_activity") or {}).get("b")
    func = boundary.get("innermost_common_function")
    if func is None:
        func = meta["crash_anchor"].get("function")
    if func is None:
        return None, -1, -1, meta

    a_idx = first_a["index"] if first_a else (boundary.get("a_index") or 0)
    b_idx = first_b["index"] if first_b else (boundary.get("b_index") or 0)
    return func, a_idx, b_idx, meta


# --------------------------------------------------------------------------
# Report / CLI
# --------------------------------------------------------------------------

def format_chain_report(meta, verbose=False):
    """Render a crash-anchored fork chain as a human-readable text block."""
    lines = ["=" * 70, "Crash-anchored reverse fork chain", "=" * 70]
    ca = meta.get("crash_anchor") or {}
    if ca.get("function"):
        loc = f"{ca['function']} at {ca.get('file')}:{ca.get('line')}"
        lines.append(f"  Reference crash anchor: index {ca.get('index')} — {loc}")
    else:
        lines.append(f"  Reference crash anchor: index {ca.get('index')}")

    if not meta.get("classified"):
        lines.append(f"  Classification: {meta.get('classification')}")
        lines.append("  (statement/variable-level localization required; "
                     "no trace-level boundary)")
        for n in meta.get("notes", []):
            lines.append(f"  - {n}")
        return "\n".join(lines)

    fb = meta.get("fork_boundary") or {}
    gap = meta.get("gap") or {}
    fda = meta.get("first_divergent_activity") or {}
    lines.append(f"  Fork gap (A {gap.get('a_range')}, B {gap.get('b_range')}, "
                 f"B events after: {meta.get('b_events_after_fork_gap')})")
    lines.append(f"  Fork boundary: A[{fb.get('a_index')}] {fb.get('a_event')} "
                 f"<-> B[{fb.get('b_index')}] {fb.get('b_event')}")
    lines.append(f"  Divergence function (innermost common): "
                 f"{fb.get('innermost_common_function')}")
    f_a, f_b = fda.get("a"), fda.get("b")
    if f_a and f_b:
        lines.append(f"  First divergent activity: A[{f_a['index']}] "
                     f"{f_a['function']} vs B[{f_b['index']}] {f_b['function']}")
    elif f_a:
        lines.append(f"  First divergent activity: A[{f_a['index']}] "
                     f"{f_a['function']} (B stopped)")
    elif f_b:
        lines.append(f"  First divergent activity: B[{f_b['index']}] "
                     f"{f_b['function']} (A stopped)")
    cr = meta.get("crash_region") or {}
    lines.append(f"  Distance boundary->crash: "
                 f"{cr.get('a_only_events_to_crash')} events, "
                 f"{cr.get('a_only_enters_to_crash')} calls "
                 f"(max depth {cr.get('max_call_depth')})")
    if meta.get("rejoin_detected"):
        lines.append(f"  WARNING: {meta.get('later_matches_after_fork')} "
                     "matched block(s) after the fork gap (rejoin detected)")
    if verbose:
        lines.append("  A-only chain (boundary -> crash):")
        for i, c in enumerate(meta.get("a_only_chain", [])):
            lines.append(f"    [{i}] A[{c['a_index']}] {c['function']}")
    for n in meta.get("notes", []):
        lines.append(f"  - {n}")
    return "\n".join(lines)


def main():
    ap = argparse.ArgumentParser(description=__doc__)
    ap.add_argument("--result", required=True,
                    help="lcs_trace.py JSON output (trace_A/trace_B/matches/gaps)")
    ap.add_argument("--crash-func", help="reference crash function (in trace A)")
    ap.add_argument("--crash-file", help="reference crash file")
    ap.add_argument("--crash-line", type=int, help="reference crash line")
    ap.add_argument("--signal", default="ASAN", help="crash signal label")
    ap.add_argument("--verbose", "-v", action="store_true",
                    help="also print the full A-only chain")
    a = ap.parse_args()

    with open(a.result) as f:
        data = json.load(f)
    trace_a = data.get("trace_A") or []
    trace_b = data.get("trace_B") or []
    matches = data.get("matches") or []
    gaps = data.get("gaps") or []
    refactor = data.get("refactoring") or {}
    rmap = refactor.get("rename_map") if isinstance(refactor, dict) else None

    crash_a = {"function": a.crash_func, "file": a.crash_file,
               "line": a.crash_line, "signal": a.signal}
    meta = compute_fork_chain(trace_a, trace_b, matches, gaps, crash_a, rmap)
    print(format_chain_report(meta, verbose=a.verbose))

    out = os.path.splitext(a.result)[0] + ".fork_chain.json"
    with open(out, "w") as f:
        json.dump(meta, f, indent=2)
    print(f"\nsaved to: {out}")


if __name__ == "__main__":
    main()
