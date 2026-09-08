#!/usr/bin/env python3
"""
refactor_detector.py - C/C++ function refactoring detector

Inspired by RefactoringMiner's algorithms for detecting rename/move/merge/split
refactorings between two source code versions.  Designed to work without git
history -- purely source-code-based analysis using multi-feature similarity
scoring and call-graph structure comparison.

Used by lcs_trace.py to align traces across different software versions by
detecting function renames before running the LCS algorithm.

Typical workflow:
  1. Extract function features from both source directories
  2. Detect renames (same-name + cross-scored greedy matching)
  3. Detect moves (cross-file same-name with preserved call graph)
  4. Detect merge/split (anchor-based caller/callee fragment analysis)
  5. Apply mappings to trace B so that both traces share a canonical name space
"""

import os
import re
import hashlib
from collections import defaultdict
from difflib import SequenceMatcher
from dataclasses import dataclass, field
from typing import Dict, List, Tuple, Set, Optional

# ---------------------------------------------------------------------------
# Reuse feature extraction from function_aligner.py
# ---------------------------------------------------------------------------
from function_aligner import (
    extract_functions,
    function_similarity,
    function_similarity_v2,
    SourceFunction,
    build_call_graph,
    jaccard,
    edit_similarity,
    _edge_profile_sim,
    merge_functions,
    C_KEYWORDS_NOISE,
)

RENAME_THRESHOLD = 0.7
MOVE_THRESHOLD = 0.5
NAME_SIM_THRESHOLD = 0.2   # low threshold for Phase 0 name heuristic (feature similarity compensates)


# Suffixes that signal a *semantic* change, not a plain rename.  When one
# function name is the other plus one of these suffixes (e.g.
# ``TIFFReadDirEntryArrayWithLimit`` vs ``TIFFReadDirEntryArray``), the callee
# did NOT merely get renamed -- it gained/lost a guard (size/range/bounds
# check) that can itself be the fork point.  Such pairs must NOT be collapsed
# by the rename map, otherwise the LCS aligns them and hides the real fork.
SEMANTIC_ENHANCEMENT_SUFFIXES = (
    "WithLimit",
    "Checked",
    "CheckedLong",
    "CheckedLong8",
    "CheckedShort",
    "CheckedRational",
    "CheckedSrational",
    "CheckedDouble",
    "Safe",
    "Secure",
    "Validated",
    "Sanitized",
    "Bounded",
    "Limited",
    "WithSize",
    "WithCount",
)


def is_semantic_enhancement(name_a: str, name_b: str) -> bool:
    """Return True if ``name_a``/``name_b`` differ only by a semantic suffix.

    e.g. ``TIFFReadDirEntryArrayWithLimit`` vs ``TIFFReadDirEntryArray``.
    """
    if name_a == name_b:
        return False
    for suffix in SEMANTIC_ENHANCEMENT_SUFFIXES:
        if name_a.endswith(suffix) and name_a[: -len(suffix)] == name_b:
            return True
        if name_b.endswith(suffix) and name_b[: -len(suffix)] == name_a:
            return True
    return False


# ---------------------------------------------------------------------------
# Name-based similarity (Phase 0 heuristic)
# ---------------------------------------------------------------------------

def _levenshtein(a: str, b: str) -> int:
    """Compute Levenshtein edit distance between two strings."""
    if not a:
        return len(b)
    if not b:
        return len(a)
    prev = list(range(len(b) + 1))
    for i, ca in enumerate(a):
        cur = [i + 1]
        for j, cb in enumerate(b):
            cost = 0 if ca == cb else 1
            cur.append(min(prev[j + 1] + 1, cur[j] + 1, prev[j] + cost))
        prev = cur
    return prev[len(b)]


def name_similarity(name_a: str, name_b: str) -> float:
    """
    Compute name-based similarity between two function names.
    
    Handles common C/C++ rename patterns:
      - Underscore prefix addition/removal (_TIFFFoo <-> TIFFFoo)
      - CamelCase / snake_case variations
      - Common prefix/suffix trimming
      - Simple character edits
    
    Returns a value in [0, 1].
    """
    if name_a == name_b:
        return 1.0

    # Normalize: strip leading underscores (common C/C++ pattern)
    a_stripped = name_a.lstrip('_')
    b_stripped = name_b.lstrip('_')

    # If stripped names are identical, it's a simple underscore rename
    if a_stripped == b_stripped:
        return 0.95

    # Also try case-insensitive comparison
    if a_stripped.lower() == b_stripped.lower():
        return 0.90

    # Levenshtein-based similarity on the stripped names
    max_len = max(len(a_stripped), len(b_stripped))
    if max_len == 0:
        return 0.0
    lev = _levenshtein(a_stripped, b_stripped)
    lev_sim = 1.0 - lev / max_len

    # Common prefix bonus
    common_prefix = 0
    for ca, cb in zip(a_stripped, b_stripped):
        if ca == cb:
            common_prefix += 1
        else:
            break
    prefix_ratio = common_prefix / max_len if max_len else 0

    # Combined name similarity: weighted average
    # High weight on Levenshtein, bonus for shared prefix
    sim = 0.7 * lev_sim + 0.3 * prefix_ratio

    # Boost if the only difference is case of a substring
    if a_stripped.lower() != b_stripped.lower():
        # Not just case difference
        pass
    else:
        sim = max(sim, 0.85)

    return sim


# ---------------------------------------------------------------------------
# Result container
# ---------------------------------------------------------------------------

@dataclass
class RefactoringMappings:
    """Container for all detected refactoring mappings between two versions."""

    renames: Dict[str, str] = field(default_factory=dict)      # ref_name -> tgt_name
    moves: Dict[str, str] = field(default_factory=dict)        # ref_name -> tgt_name (cross-file)
    split: Dict[str, List[str]] = field(default_factory=dict)  # ref_name -> [tgt_names]
    merge: Dict[str, List[str]] = field(default_factory=dict)  # tgt_name -> [ref_names]
    # ref_name -> tgt_name pairs that differ only by a semantic suffix
    # (WithLimit/Checked/...).  These are NOT collapsed by the rename map so
    # the LCS treats them as a real fork point.
    semantic_renames: Dict[str, str] = field(default_factory=dict)

    def all_renames(self) -> Dict[str, str]:
        """Combined rename + move as a single old->new mapping.

        Semantic-enhancement pairs (``semantic_renames``) are excluded: they
        must remain distinct so the LCS exposes them as a fork, rather than
        aligning them away as if they were a plain rename.
        """
        result = dict(self.renames)
        result.update(self.moves)
        for ref_name in self.semantic_renames:
            result.pop(ref_name, None)
        return result

    def summary(self) -> str:
        parts = []
        if self.renames:
            parts.append(f"{len(self.renames)} renames")
        if self.moves:
            parts.append(f"{len(self.moves)} moves")
        if self.split:
            parts.append(f"{len(self.split)} splits")
        if self.merge:
            parts.append(f"{len(self.merge)} merges")
        return ", ".join(parts) if parts else "no refactorings detected"


# ---------------------------------------------------------------------------
# Core detector
# ---------------------------------------------------------------------------

class RefactorDetector:
    """
    C/C++ function refactoring detector.

    Detection strategy (inspired by RefactoringMiner):
      1. Rename: Phase 0 name heuristics (underscore/edit distance) +
         Phase 1 same-name identity + Phase 2 combined name+feature scoring
         (greedy one-to-one matching).
      2. Move: cross-file same-name functions whose call-graph neighbourhood
         is structurally similar.
      3. Merge/Split: anchor-based caller/callee fragment analysis -- when
         merging two fragments yields a higher similarity than either alone,
         the pair is judged to be split from a single original function (and
         vice-versa for merge).

    No git history is required -- analysis is purely source-code based.
    """

    def __init__(self, ref_dir: str, target_dir: str,
                 ref_trace_funcs: Optional[List[str]] = None,
                 tgt_trace_funcs: Optional[List[str]] = None,
                 threshold: float = RENAME_THRESHOLD,
                 verbose: bool = True):
        self.verbose = verbose
        self.threshold = threshold

        print("[refactor] extracting reference version functions ...")
        self.ref_funcs = extract_functions(ref_dir)
        print(f"[refactor]   -> {len(self.ref_funcs)} functions from {ref_dir}")

        print("[refactor] extracting target version functions ...")
        self.tgt_funcs = extract_functions(target_dir)
        print(f"[refactor]   -> {len(self.tgt_funcs)} functions from {target_dir}")

        self.ref_trace = self._collapse(ref_trace_funcs) if ref_trace_funcs else []
        self.tgt_trace = self._collapse(tgt_trace_funcs) if tgt_trace_funcs else []

        # Approximate call graph from trace adjacency
        self.ref_callers, self.ref_callees = self._graph_from_trace(self.ref_trace)
        self.tgt_callers, self.tgt_callees = self._graph_from_trace(self.tgt_trace)

        self.mappings = RefactoringMappings()
        self._sim_cache: Dict[Tuple[str, str], float] = {}

    # ------------------------------------------------------------------ #
    # Helpers
    # ------------------------------------------------------------------ #

    @staticmethod
    def _collapse(seq):
        """Remove consecutive duplicates from a sequence."""
        out = []
        for f in seq:
            if not out or out[-1] != f:
                out.append(f)
        return out

    @staticmethod
    def _graph_from_trace(seq):
        """Approximate call graph from trace adjacency (fallback when no real events)."""
        callers, callees = defaultdict(set), defaultdict(set)
        for i in range(1, len(seq)):
            callees[seq[i - 1]].add(seq[i])
            callers[seq[i]].add(seq[i - 1])
        return callers, callees

    def _sim(self, r: str, t: str) -> float:
        """Compute similarity between a ref function and a tgt function (v2 with caller context)."""
        key = (r, t)
        if key not in self._sim_cache:
            rf = self.ref_funcs.get(r)
            tf = self.tgt_funcs.get(t)
            if rf and tf:
                # Compute caller context similarity
                r_callers = self.ref_callers.get(r, set())
                t_callers = self.tgt_callers.get(t, set())
                caller_sim = jaccard(r_callers, t_callers)
                self._sim_cache[key] = function_similarity_v2(rf, tf, caller_sim)
            else:
                self._sim_cache[key] = 0.0
        return self._sim_cache[key]

    # ------------------------------------------------------------------ #
    # Phase 1: Identity mapping (same name in both versions)
    # ------------------------------------------------------------------ #

    def _detect_identity(self):
        """Map functions that have the same name in both versions."""
        ref_names = [f for f in self.ref_trace if f in self.ref_funcs]
        for n in ref_names:
            if n in self.tgt_funcs:
                self.mappings.renames[n] = n

    def _record_rename(self, r: str, t: str, ns: float, feat_s: float,
                       combined: float):
        """Store a detected rename, separating semantic-enhancement pairs.

        A pair like ``TIFFReadDirEntryArrayWithLimit`` -> ``TIFFReadDirEntryArray``
        is recorded into ``semantic_renames`` (NOT ``renames``) so that
        ``all_renames()`` leaves it out of the alignment map -- the LCS then
        sees it as a real fork instead of collapsing it.
        """
        if is_semantic_enhancement(r, t):
            self.mappings.semantic_renames[r] = t
            if self.verbose:
                print(f"  [semantic-rename] {r} -> {t}  (NOT collapsed; kept as fork)")
        else:
            self.mappings.renames[r] = t
            if self.verbose:
                print(f"  [rename] {r} -> {t}  "
                      f"(name={ns:.3f}, feat={feat_s:.3f}, "
                      f"combined={combined:.3f})")

    # ------------------------------------------------------------------ #
    # Phase 0+1: Rename detection
    # ------------------------------------------------------------------ #

    def _detect_renames(self):
        """
        Multi-phase rename detection:
          Phase 0 -- name-based heuristics (underscore patterns, edit distance,
                     common prefix/suffix).  Catches obvious renames that
                     feature-based scoring misses.
          Phase 1 -- same-name direct mapping (identity).
          Phase 2 -- cross-score remaining pairs using combined
                     (0.5*name_sim + 0.5*feature_sim), greedy one-to-one
                     matching with threshold.
        """
        ref_names = [f for f in self.ref_trace if f in self.ref_funcs]
        tgt_names = [f for f in self.tgt_trace if f in self.tgt_funcs]

        mapped_ref = set(self.mappings.renames.keys())
        mapped_tgt = set(self.mappings.renames.values()) | set(self.mappings.moves.values()) | set(self.mappings.merge.keys()) | {g for v in self.mappings.split.values() for g in v}

        # Phase 0: name-based heuristics for unmapped functions
        #          (underscore prefix, edit distance, common prefix)
        name_candidates = []
        for r in ref_names:
            if r in mapped_ref:
                continue
            for t in tgt_names:
                if t in mapped_tgt:
                    continue
                ns = name_similarity(r, t)
                if ns >= NAME_SIM_THRESHOLD:
                    name_candidates.append((ns, r, t))

        name_candidates.sort(reverse=True)
        for ns, r, t in name_candidates:
            if r in mapped_ref or t in mapped_tgt:
                continue
            # Require feature similarity as a sanity check (>= 0.3)
            feat_s = self._sim(r, t)
            if feat_s < 0.3:
                continue
            # Combined score: name dominates for obvious renames
            combined = 0.6 * ns + 0.4 * feat_s
            if combined >= 0.45:   # lower threshold for Phase 0 (name heuristics)
                self._record_rename(r, t, ns, feat_s, combined)
                mapped_ref.add(r)
                mapped_tgt.add(t)

        # Phase 2: feature-based cross-scoring for remaining unmapped functions
        feat_candidates = []
        for r in ref_names:
            if r in mapped_ref:
                continue
            for t in tgt_names:
                if t in mapped_tgt:
                    continue
                feat_s = self._sim(r, t)
                ns = name_similarity(r, t)
                # High feature similarity is a strong signal even with low name sim
                if feat_s >= 0.9:
                    # Near-identical code: accept as rename regardless of name sim
                    combined = max(0.6 * ns + 0.4 * feat_s, feat_s * 0.85)
                else:
                    combined = 0.5 * ns + 0.5 * feat_s
                if combined >= self.threshold:
                    feat_candidates.append((combined, r, t, ns, feat_s))

        feat_candidates.sort(reverse=True)
        for combined, r, t, ns, feat_s in feat_candidates:
            if r in mapped_ref or t in mapped_tgt:
                continue
            self._record_rename(r, t, ns, feat_s, combined)
            mapped_ref.add(r)
            mapped_tgt.add(t)

    # ------------------------------------------------------------------ #
    # Phase 2: Move detection
    # ------------------------------------------------------------------ #

    def _detect_moves(self):
        """
        Move detection (Move Method / Move Function):
          A function is "moved" if it has the same name in both versions but
          resides in a different file, AND the call-graph neighbourhood is
          structurally preserved (Jaccard >= MOVE_THRESHOLD on callers or
          callees).
        """
        for r_name, r_func in self.ref_funcs.items():
            if r_name in self.mappings.renames:
                continue
            if r_name not in self.tgt_funcs:
                continue

            t_func = self.tgt_funcs[r_name]
            if r_func.file == t_func.file:
                continue

            # Call-graph structure preservation check
            r_callers = self.ref_callers.get(r_name, set())
            r_callees = self.ref_callees.get(r_name, set())
            t_callers = self.tgt_callers.get(r_name, set())
            t_callees = self.tgt_callees.get(r_name, set())

            caller_sim = jaccard(r_callers, t_callers)
            callee_sim = jaccard(r_callees, t_callees)

            if caller_sim >= MOVE_THRESHOLD or callee_sim >= MOVE_THRESHOLD:
                self.mappings.moves[r_name] = r_name
                if self.verbose:
                    print(f"  [move]   {r_name}  "
                          f"{os.path.basename(r_func.file)} -> "
                          f"{os.path.basename(t_func.file)}  "
                          f"(caller_sim={caller_sim:.3f}, callee_sim={callee_sim:.3f})")

    # ------------------------------------------------------------------ #
    # Phase 3: Merge / Split detection
    # ------------------------------------------------------------------ #

    def _detect_merge_split(self):
        """
        Merge/Split detection (RefactoringMiner EXTRACT/INLINE METHOD):
          - Split: one ref function -> multiple tgt fragments whose merged
            similarity to the ref function exceeds the single-function
            similarity.
          - Merge: multiple ref functions -> one tgt function (reverse).
        """
        all_mapped_tgt = (
            set(self.mappings.renames.values())
            | set(self.mappings.moves.values())
            | {g for v in self.mappings.split.values() for g in v}
        )
        all_mapped_ref = set(self.mappings.renames.keys()) | set(self.mappings.moves.keys())

        # ---- Split: one ref -> multiple tgt ----
        unmapped_t = [f for f in self.tgt_trace
                      if f in self.tgt_funcs and f not in all_mapped_tgt]
        consumed = set()

        for t in unmapped_t:
            if t in consumed:
                continue

            # Find anchor refs (mapped neighbours)
            anchor_refs = set()
            for c in self.tgt_callers.get(t, set()):
                if c in self.mappings.renames:
                    anchor_refs.add(self.mappings.renames[c])
                elif c in self.mappings.moves:
                    anchor_refs.add(self.mappings.moves[c])
            for e in self.tgt_callees.get(t, set()):
                if e in self.mappings.renames:
                    anchor_refs.add(self.mappings.renames[e])
                elif e in self.mappings.moves:
                    anchor_refs.add(self.mappings.moves[e])
            if not anchor_refs:
                continue

            # Group unmapped target functions: by shared mapped callers OR by connectivity
            group = [t]
            t_callers = self.tgt_callers.get(t, set())
            t_callees = self.tgt_callees.get(t, set())
            for u in unmapped_t:
                if u == t or u in consumed:
                    continue
                u_callers = self.tgt_callers.get(u, set())
                u_callees = self.tgt_callees.get(u, set())
                # Shared mapped caller, or sequential connection (u calls t, or t calls u)
                if ((u_callers & t_callers & all_mapped_tgt)
                    or (u in t_callees) or (t in u_callers)):
                    group.append(u)
                    consumed.add(u)

            if len(group) < 2:
                continue

            merged_t = merge_functions(
                [self.tgt_funcs[g] for g in group if g in self.tgt_funcs]
            )

            # Find best matching ref function among call-graph neighbours of anchors
            cand_refs = set()
            for a in anchor_refs:
                cand_refs |= self.ref_callers.get(a, set())
                cand_refs |= self.ref_callees.get(a, set())

            best_r, best_merged, best_single = None, 0.0, 0.0
            for r in cand_refs:
                if (r not in self.ref_funcs
                        or r in self.mappings.split
                        or r in self.mappings.renames
                        or r in self.mappings.moves):
                    continue
                s_merged = function_similarity(self.ref_funcs[r], merged_t)
                s_single = max(
                    (function_similarity(self.ref_funcs[r], self.tgt_funcs[g])
                     for g in group if g in self.tgt_funcs),
                    default=0.0,
                )
                if s_merged > best_merged:
                    best_r, best_merged, best_single = r, s_merged, s_single

            if best_r and best_merged >= self.threshold and best_merged > best_single:
                self.mappings.split[best_r] = group
                consumed.update(group)
                if self.verbose:
                    print(f"  [split]  ref:{best_r} -> tgt:{group}  "
                          f"(merged={best_merged:.3f} > single={best_single:.3f})")

        # ---- Rename+Split: ref mapped via rename, but tgt has extra unmapped callees ----
        for r, t in list(self.mappings.renames.items()):
            if r not in self.ref_funcs or t not in self.tgt_funcs:
                continue
            s_single = function_similarity_v2(self.ref_funcs[r], self.tgt_funcs[t])
            # Collect unmapped callees of t (called by the renamed target)
            extra = []
            for c in self.tgt_callees.get(t, set()):
                if (c in self.tgt_funcs and c not in all_mapped_tgt
                        and c not in self.mappings.renames.values()):
                    extra.append(c)
            if not extra:
                continue
            merged_t = merge_functions(
                [self.tgt_funcs[t]] + [self.tgt_funcs[e] for e in extra if e in self.tgt_funcs]
            )
            # Use v1 (token-based) for merged comparison — v2 is too conservative for split detection
            s_merged = function_similarity(self.ref_funcs[r], merged_t)
            if s_merged >= self.threshold and s_merged > s_single:
                self.mappings.split[r] = [t] + extra
                all_mapped_tgt.update(extra)
                if self.verbose:
                    print(f"  [split]  ref:{r} -> tgt:{[t]+extra}  "
                          f"(merged={s_merged:.3f} > single={s_single:.3f})")

        # ---- Merge: multiple ref -> one tgt (reverse direction) ----
        unmapped_r = [f for f in self.ref_trace
                      if f in self.ref_funcs and f not in all_mapped_ref]
        consumed_r = set()

        for r in unmapped_r:
            if r in consumed_r:
                continue

            anchor_tgts = set()
            for c in self.ref_callers.get(r, set()):
                if c in self.mappings.renames:
                    anchor_tgts.add(self.mappings.renames[c])
                elif c in self.mappings.moves:
                    anchor_tgts.add(self.mappings.moves[c])
            for e in self.ref_callees.get(r, set()):
                if e in self.mappings.renames:
                    anchor_tgts.add(self.mappings.renames[e])
                elif e in self.mappings.moves:
                    anchor_tgts.add(self.mappings.moves[e])
            if not anchor_tgts:
                cand_tgts = set(self.tgt_funcs.keys()) - all_mapped_tgt
            else:
                cand_tgts = set()
                for a in anchor_tgts:
                    cand_tgts |= self.tgt_callers.get(a, set())
                    cand_tgts |= self.tgt_callees.get(a, set())
                cand_tgts = {t for t in cand_tgts if t in self.tgt_funcs
                             and t not in all_mapped_tgt}

            group = [r]
            if anchor_tgts:
                r_callers = self.ref_callers.get(r, set())
                for u in unmapped_r:
                    if u == r or u in consumed_r:
                        continue
                    if self.ref_callers.get(u, set()) & r_callers & all_mapped_ref:
                        group.append(u)
                        consumed_r.add(u)
            else:
                # Fallback: group by connectivity in call graph (BFS)
                visited = {r}
                queue = [r]
                while queue:
                    cur = queue.pop(0)
                    for neighbor in (self.ref_callers.get(cur, set())
                                     | self.ref_callees.get(cur, set())):
                        if neighbor in visited or neighbor not in unmapped_r:
                            continue
                        if neighbor in consumed_r:
                            continue
                        visited.add(neighbor)
                        group.append(neighbor)
                        consumed_r.add(neighbor)
                        queue.append(neighbor)

            if len(group) < 2:
                continue

            merged_r = merge_functions(
                [self.ref_funcs[g] for g in group if g in self.ref_funcs]
            )

            best_t, best_merged, best_single = None, 0.0, 0.0
            for t in cand_tgts:
                if (t not in self.tgt_funcs
                        or t in all_mapped_tgt
                        or t in self.mappings.merge):
                    continue
                # Use v1 (token-based) for merged comparison — v2 is too conservative for merge detection
                s_merged = function_similarity(merged_r, self.tgt_funcs[t])
                s_single = max(
                    (function_similarity(self.ref_funcs[g], self.tgt_funcs[t])
                     for g in group if g in self.ref_funcs),
                    default=0.0,
                )
                if s_merged > best_merged:
                    best_t, best_merged, best_single = t, s_merged, s_single

            if best_t and best_merged >= self.threshold and best_merged > best_single:
                self.mappings.merge[best_t] = group
                consumed_r.update(group)
                if self.verbose:
                    print(f"  [merge]  ref:{group} -> tgt:{best_t}  "
                          f"(merged={best_merged:.3f} > single={best_single:.3f})")

    # ------------------------------------------------------------------ #
    # Public API
    # ------------------------------------------------------------------ #

    def detect(self) -> RefactoringMappings:
        """Run all detection phases and return the mappings.
        Order: identity -> merge/split -> renames -> moves
        (merge/split before renames to prevent partial matches blocking group detection)
        """
        # Phase 1: same-name identity mapping (needed as anchors for merge/split)
        self._detect_identity()
        # Phase 2: merge/split detection (before renames to avoid partial matches)
        self._detect_merge_split()
        # Phase 3: rename detection for remaining unmapped functions
        self._detect_renames()
        # Phase 4: move detection
        self._detect_moves()
        if self.verbose:
            print(f"[refactor] total: {self.mappings.summary()}")
        return self.mappings


# ---------------------------------------------------------------------------
# Apply mappings to traces
# ---------------------------------------------------------------------------

class TraceRefactorMapper:
    """Apply refactoring mappings to traces so that both share a canonical name space."""

    @staticmethod
    def apply_rename_mapping(seq_b, rename_map: Dict[str, str]):
        """
        Replace function names in *seq_b* according to *rename_map*.

        For EVERY TraceNode in seq_b, ALL elements of its path tuple are
        rewritten through the rename map (ancestors included).  The node's
        own name is updated if it appears as a key.  The original name is
        preserved in ``node.original_name`` for debugging / JSON output.
        """
        from lcs_trace import TraceNode

        def _rewrite_path(path, rmap):
            """Apply rename_map to every element of a path tuple."""
            return tuple(rmap.get(p, p) for p in path)

        result = []
        for node in seq_b:
            new_path = _rewrite_path(node.path, rename_map)
            if node.name in rename_map:
                new_name = rename_map[node.name]
                new_node = TraceNode(
                    name=new_name,
                    depth=node.depth,
                    path=new_path,
                    is_enter=node.is_enter,
                    count=node.count,
                    original_name=node.name,
                )
                result.append(new_node)
            else:
                # Name unchanged, but ancestors in path may have been renamed
                if new_path != node.path:
                    new_node = TraceNode(
                        name=node.name,
                        depth=node.depth,
                        path=new_path,
                        is_enter=node.is_enter,
                        count=node.count,
                        original_name=node.original_name,
                    )
                    result.append(new_node)
                else:
                    result.append(node)
        return result

    @staticmethod
    def build_canonical_name(name, rename_map):
        """Map a name through the rename mapping (transitively, avoiding cycles)."""
        visited = set()
        while name in rename_map and name not in visited:
            visited.add(name)
            name = rename_map[name]
        return name

    @staticmethod
    def format_mapping_for_display(rename_map: Dict[str, str], max_entries: int = 20) -> str:
        """Human-readable summary of a rename mapping."""
        if not rename_map:
            return "  (none)"
        lines = []
        identity = 0
        for old, new in sorted(rename_map.items()):
            if old == new:
                identity += 1
            elif len(lines) < max_entries:
                lines.append(f"  {old} -> {new}")
        if identity:
            lines.append(f"  ... plus {identity} identity mappings (same name)")
        if len(rename_map) > max_entries + identity:
            lines.append(f"  ... and {len(rename_map) - max_entries - identity} more")
        return "\n".join(lines)
