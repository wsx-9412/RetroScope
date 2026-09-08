#!/usr/bin/env python3
"""
Cross-version function-level alignment (step 1) + statement-level alignment
(step 2, based on the lldb-trace approach)

Step 1: build a function-level "dictionary" of correspondences between the two versions.
  1. Renaming: based on control-flow features, constants, call relationships, etc.,
     Jaccard similarity + edit distance, one-to-one mapping, threshold 0.7
  2. Merging/Splitting: first build an initial one-to-one mapping from same-name +
     renames; for functions in the target version that are still unmapped, inspect
     their already-mapped callers/callees (real call graph), compute similarity of
     that unmapped function merged with candidates at the call site; if the merged
     similarity is higher than the original (single function) => judged to be split
     from the original function; and vice versa for the reverse direction.

Step 2: start statement-level alignment from the entry of the last aligned function
(near the end of the trace).
"""

import os
import re
import hashlib
from collections import defaultdict
from difflib import SequenceMatcher
from dataclasses import dataclass, field
from typing import Dict, List, Tuple, Optional

RENAME_THRESHOLD = 0.7


# ================================================================ #
# Source parsing and feature extraction
# ================================================================ #

FUNC_DEF_RE = re.compile(
    r'^[ \t]*(?:[A-Za-z_][A-Za-z0-9_ \t\*]*?[ \t\*]+)?([A-Za-z_][A-Za-z0-9_]*)'
    r'\s*\(([^;{)]*)\)\s*[A-Za-z_0-9 \t]*\{', re.MULTILINE)

CALL_RE = re.compile(r'([A-Za-z_][A-Za-z0-9_]*)\s*\(')
NUM_CONST_RE = re.compile(r'\b(0[xX][0-9a-fA-F]+|\d+)[uUlL]*\b')
STR_CONST_RE = re.compile(r'"((?:[^"\\]|\\.)*)"')
KEYWORD_TOKENS = {'if', 'else', 'for', 'while', 'do', 'switch', 'case',
                  'return', 'break', 'continue', 'goto'}
C_KEYWORDS_NOISE = {'if', 'for', 'while', 'switch', 'return', 'sizeof', 'defined'}


@dataclass
class SourceFunction:
    name: str
    file: str
    line: int
    body: str = ''
    tokens: list = field(default_factory=list)       # normalized token sequence (edit distance)
    constants: set = field(default_factory=set)      # numeric/string constants (Jaccard)
    callees: set = field(default_factory=set)        # callee name set (Jaccard)
    cfg_ngrams: set = field(default_factory=set)     # control-flow k-gram fingerprint (Jaccard)
    edge_profile: tuple = ()                         # edge type profile (seq/branch/loop/exit)
    behavioral_fp: set = field(default_factory=set)  # behavioral fingerprint (syscall/API patterns)
    stmt_patterns: tuple = ()                        # (n_assign, n_call, n_return, n_if, n_loop, n_mem)


def strip_comments_and_strings(src: str) -> str:
    src = re.sub(r'/\*.*?\*/', ' ', src, flags=re.S)
    src = re.sub(r'//[^\n]*', ' ', src)
    return src


def normalize_tokens(body: str) -> list:
    """Normalization: variable name -> V, literal -> N; keep control-flow keywords and structural punctuation"""
    toks = []
    for tok in re.findall(r'[A-Za-z_][A-Za-z0-9_]*|[{}();,&*+\-/<>=!%]', body):
        if tok in KEYWORD_TOKENS or tok in '{}();,':
            toks.append(tok)
        elif re.match(r'^[A-Za-z_]', tok):
            toks.append('V')
        else:
            toks.append(tok)
    return toks


def extract_cfg_features(body_tokens: list):
    """
    Lightweight structured control-flow features (approximation of CFG without a
    compiler frontend):
      - cfg_ngrams: control-flow k-gram fingerprint. Take 3-grams of the normalized
        token stream that contain at least one control keyword or structural
        punctuation — robust to statement reordering/insertion, characterizing the
        structural pattern of branches/loops (similar to opcode n-grams in binary diffing)
      - edge_profile: (sequential edges, branch edges, loop back edges, case edges,
        exit edges) count profile
    """
    CONTROL = {'if', 'for', 'while', 'switch', 'do'}
    STRUCT = KEYWORD_TOKENS | {'{', '}', ';'}
    grams = set()
    for i in range(len(body_tokens) - 2):
        g = tuple(body_tokens[i:i + 3])
        if any(t in STRUCT for t in g):
            grams.add(hashlib.md5(str(g).encode()).hexdigest()[:8])
    edges = {'seq': 0, 'branch': 0, 'loop': 0, 'case': 0, 'exit': 0}
    depth_case = 0
    for tok in body_tokens:
        if tok == 'if':
            edges['branch'] += 1          # one if => 2 outgoing edges (true/false), counted as 1 branch point
        elif tok in ('for', 'while', 'do'):
            edges['loop'] += 1            # loop => back edge + sequential edge
        elif tok == 'case':
            edges['case'] += 1
        elif tok == 'return':
            edges['exit'] += 1
        elif tok == ';':
            edges['seq'] += 1
    return grams, tuple(edges[k] for k in ('seq', 'branch', 'loop', 'case', 'exit'))


def _extract_behavioral_fp(body: str) -> set:
    """
    Extract behavioral fingerprint: what the function DOES, not what it calls.
    Based on RefactoringMiner's approach of matching structural patterns.
    """
    fp = set()
    body_lower = body.lower()

    # File I/O patterns
    if re.search(r'\bfopen\b|\bopen\b|\bCreateFile\b', body):
        fp.add('FILE_OPEN')
    if re.search(r'\bfclose\b|\bclose\b|\bCloseHandle\b', body):
        fp.add('FILE_CLOSE')
    if re.search(r'\bfread\b|\bread\b', body_lower):
        fp.add('FILE_READ')
    if re.search(r'\bfwrite\b|\bwrite\b', body_lower):
        fp.add('FILE_WRITE')
    if re.search(r'\bfseek\b|\bseek\b', body_lower):
        fp.add('FILE_SEEK')
    if re.search(r'\bftell\b|\btell\b', body_lower):
        fp.add('FILE_TELL')
    if re.search(r'\bfeof\b|\beof\b', body_lower):
        fp.add('FILE_EOF')

    # Memory patterns
    if re.search(r'\bmalloc\b|\bcalloc\b|\brealloc\b|\bnew\b', body_lower):
        fp.add('MEM_ALLOC')
    if re.search(r'\bfree\b|\bdelete\b', body_lower):
        fp.add('MEM_FREE')
    if re.search(r'\bmemcpy\b|\bmemmove\b|\bstrcpy\b|\bstrncpy\b', body_lower):
        fp.add('MEM_COPY')

    # String patterns
    if re.search(r'\bstrlen\b|\bstrcmp\b|\bstrncmp\b', body_lower):
        fp.add('STR_COMPARE')
    if re.search(r'\bsprintf\b|\bsnprintf\b|\bprintf\b', body_lower):
        fp.add('STR_FORMAT')

    # Numeric computation
    if re.search(r'\bmalloc\s*\(|\bcalloc\s*\(', body):
        fp.add('DYN_ALLOC')
    if re.search(r'\bsizeof\b', body):
        fp.add('SIZEOF')

    # Control flow patterns
    n_if = len(re.findall(r'\bif\s*\(', body))
    n_for = len(re.findall(r'\bfor\s*\(', body))
    n_while = len(re.findall(r'\bwhile\s*\(', body))
    n_switch = len(re.findall(r'\bswitch\s*\(', body))
    if n_if > 0: fp.add(f'HAS_IF_{min(n_if, 3)}')
    if n_for > 0: fp.add(f'HAS_FOR_{min(n_for, 3)}')
    if n_while > 0: fp.add(f'HAS_WHILE_{min(n_while, 3)}')
    if n_switch > 0: fp.add('HAS_SWITCH')

    # Return patterns
    n_return = len(re.findall(r'\breturn\b', body))
    if n_return > 0: fp.add(f'HAS_RETURN_{min(n_return, 3)}')

    # Assignment patterns
    n_assign = len(re.findall(r'[=!<>]=|[<>]=?|[+\-*/%]=', body))
    if n_assign > 0: fp.add(f'N_CMP_{min(n_assign, 5)}')

    # Array/pointer access
    if re.search(r'\[[\w]+\]', body):
        fp.add('ARRAY_ACCESS')
    if re.search(r'->', body):
        fp.add('PTR_ACCESS')

    return fp


def _extract_stmt_patterns(body: str) -> tuple:
    """
    Extract statement-level pattern counts (RefactoringMiner-style).
    Returns (n_assign, n_call, n_return, n_if, n_loop, n_mem_op).
    """
    n_assign = len(re.findall(r'\w+\s*=\s*[^=]', body))
    n_call = len(re.findall(r'\w+\s*\(', body))
    n_return = len(re.findall(r'\breturn\b', body))
    n_if = len(re.findall(r'\bif\s*\(', body))
    n_loop = len(re.findall(r'\b(for|while|do)\s*[\({]', body))
    n_mem = len(re.findall(r'\b(malloc|calloc|realloc|free|memcpy|memmove)\b', body))
    return (n_assign, n_call, n_return, n_if, n_loop, n_mem)


def extract_functions(source_dir: str, extensions=('.c', '.cc', '.cpp')) -> Dict[str, SourceFunction]:
    """Scan the source directory and extract all function definitions and their features"""
    functions: Dict[str, SourceFunction] = {}
    for root, dirs, files in os.walk(source_dir):
        dirs[:] = [d for d in dirs if not d.startswith('.') and d not in
                   ('test', 'tests', 'contrib', 'html', 'man', 'CMakeFiles',
                    'build', 'bld')]
        for fn in files:
            if not fn.endswith(extensions):
                continue
            path = os.path.join(root, fn)
            try:
                raw = open(path, encoding='utf-8', errors='ignore').read()
            except Exception:
                continue
            clean = strip_comments_and_strings(raw)
            for m in FUNC_DEF_RE.finditer(clean):
                name = m.group(1)
                if name in C_KEYWORDS_NOISE:
                    continue
                start = m.end() - 1
                depth, i = 0, start
                n = len(clean)
                while i < n:
                    if clean[i] == '{':
                        depth += 1
                    elif clean[i] == '}':
                        depth -= 1
                        if depth == 0:
                            break
                    i += 1
                if depth != 0:
                    continue
                body = clean[start:i]
                sf = SourceFunction(name=name, file=path,
                                    line=clean[:m.start()].count('\n') + 1)
                sf.body = body
                sf.tokens = normalize_tokens(body)
                sf.constants = set(NUM_CONST_RE.findall(body)) | \
                               {x[:32] for x in STR_CONST_RE.findall(raw[start:i])}
                sf.callees = {c for c in CALL_RE.findall(body)
                              if c not in C_KEYWORDS_NOISE and c != name}
                sf.cfg_ngrams, sf.edge_profile = extract_cfg_features(sf.tokens)
                sf.behavioral_fp = _extract_behavioral_fp(body)
                sf.stmt_patterns = _extract_stmt_patterns(body)
                if name in functions:
                    if len(sf.body) > len(functions[name].body):
                        functions[name] = sf
                else:
                    functions[name] = sf
    return functions


# ---------------- Similarity ----------------

def jaccard(a: set, b: set) -> float:
    union = len(a | b)
    return (len(a & b) / union) if union else 0.0


def edit_similarity(a: list, b: list) -> float:
    if not a or not b:
        return 0.0
    return SequenceMatcher(None, a, b, autojunk=False).ratio()


def _edge_profile_sim(e1: tuple, e2: tuple) -> float:
    total = max(sum(e1), sum(e2))
    if total == 0:
        return 1.0 if e1 == e2 else 0.0
    return 1.0 - sum(abs(x - y) for x, y in zip(e1, e2)) / (2.0 * total)


def function_similarity(f1: SourceFunction, f2: SourceFunction) -> float:
    """
    Combined similarity (Jaccard + edit distance):
      0.25×callee-relationship Jaccard + 0.10×constant Jaccard +
      0.30×control-flow fingerprint Jaccard + 0.05×edge profile + 0.30×normalized-sequence edit distance
    """
    s_callee = jaccard(f1.callees, f2.callees)
    s_const = jaccard(f1.constants, f2.constants)
    s_cfg = jaccard(f1.cfg_ngrams, f2.cfg_ngrams)
    s_edge = _edge_profile_sim(f1.edge_profile, f2.edge_profile)
    s_edit = edit_similarity(f1.tokens, f2.tokens)
    return 0.25 * s_callee + 0.10 * s_const + 0.30 * s_cfg + 0.05 * s_edge + 0.30 * s_edit


def function_similarity_v2(f1: SourceFunction, f2: SourceFunction,
                           caller_sim: float = 0.0) -> float:
    """
    RefactoringMiner-style similarity: robust to internal function renames.
    Uses behavioral fingerprint + statement patterns + caller context + token structure.
    Reduces callee weight since callees may be renamed.
    """
    s_behavior = jaccard(f1.behavioral_fp, f2.behavioral_fp)

    # Statement pattern similarity (Manhattan distance normalized)
    p1, p2 = f1.stmt_patterns, f2.stmt_patterns
    max_p = max(max(p1), max(p2), 1)
    s_stmt = 1.0 - sum(abs(a - b) for a, b in zip(p1, p2)) / (len(p1) * max_p)

    s_cfg = jaccard(f1.cfg_ngrams, f2.cfg_ngrams)
    s_edge = _edge_profile_sim(f1.edge_profile, f2.edge_profile)
    s_edit = edit_similarity(f1.tokens, f2.tokens)
    s_const = jaccard(f1.constants, f2.constants)

    # Weight: 0.20×behavior + 0.15×stmt + 0.20×cfg + 0.05×edge + 0.25×edit + 0.05×const + 0.10×caller
    return (0.20 * s_behavior + 0.15 * s_stmt + 0.20 * s_cfg +
            0.05 * s_edge + 0.25 * s_edit + 0.05 * s_const + 0.10 * caller_sim)


def merge_functions(funcs: List[SourceFunction], base: Optional[SourceFunction] = None) -> SourceFunction:
    """Merge multiple fragments into a virtual function at a call site"""
    parts = ([base] if base else []) + [f for f in funcs if f is not base]
    merged = SourceFunction(name=(base.name if base else 'merged'), file='', line=0)
    merged.body = '\n'.join(f.body for f in parts if f)
    merged.tokens = []
    for f in parts:
        if f:
            merged.tokens.extend(f.tokens)
    merged.constants = set().union(*[f.constants for f in parts if f])
    merged.callees = set().union(*[f.callees for f in parts if f])
    grams = set()
    for f in parts:
        if f:
            grams |= f.cfg_ngrams
    merged.cfg_ngrams = grams
    prof = [0] * 5
    for f in parts:
        if f and f.edge_profile:
            for k, v in enumerate(f.edge_profile):
                prof[k] += v
    merged.edge_profile = tuple(prof)
    # Merge behavioral fingerprints and statement patterns
    merged.behavioral_fp = set()
    for f in parts:
        if f and hasattr(f, 'behavioral_fp'):
            merged.behavioral_fp |= f.behavioral_fp
    sp = [0] * 6
    for f in parts:
        if f and hasattr(f, 'stmt_patterns') and f.stmt_patterns:
            for k, v in enumerate(f.stmt_patterns):
                sp[k] += v
    merged.stmt_patterns = tuple(sp)
    return merged


# ---------------- Real call graph (rebuilt from enter/exit paired events) ----------------

def build_call_graph(events: List[Tuple[str, str]]):
    """
    events: [('>', fname), ('<', fname), ...] (paired events from functracer)
    returns callers[name]={caller...}, callees[name]={callee...}
    stack pairing: on enter, the top of stack is the real caller
    """
    stack = []
    callers = defaultdict(set)
    callees = defaultdict(set)
    for d, name in events:
        if d == '>':
            if stack:
                callers[name].add(stack[-1])
                callees[stack[-1]].add(name)
            stack.append(name)
        else:
            if stack:
                stack.pop()
    return callers, callees


# ================================================================ #
# Function-level aligner
# ================================================================ #

class FunctionAligner:
    """
    Cross-version function-level alignment:
      step 1-1 rename: same-name direct mapping + feature similarity (>=0.7) greedy one-to-one
      step 1-2 merge/split: based on already-mapped caller/callee anchors in the real
        call graph, merge fragments at the call site and compute similarity; only judged
        when the merged similarity is higher than the single-function similarity
    """

    def __init__(self, ref_dir: str, target_dir: str,
                 ref_trace_funcs: List[str], target_trace_funcs: List[str],
                 threshold: float = RENAME_THRESHOLD, verbose: bool = True,
                 ref_graph=None, tgt_graph=None):
        """
        ref_graph/tgt_graph: the (callers, callees) tuple from build_call_graph();
            when None, fall back to trace-adjacency approximation.
        """
        self.verbose = verbose
        self.threshold = threshold
        print("Extracting reference version function features...")
        self.ref_funcs = extract_functions(ref_dir)
        print("Extracting target version function features...")
        self.tgt_funcs = extract_functions(target_dir)
        self.ref_trace_funcs = self._collapse(ref_trace_funcs)
        self.tgt_trace_funcs = self._collapse(target_trace_funcs)
        # real call graph
        if ref_graph is None:
            ref_graph = self._graph_from_adjacency(self.ref_trace_funcs)
        if tgt_graph is None:
            tgt_graph = self._graph_from_adjacency(self.tgt_trace_funcs)
        self.ref_callers, self.ref_callees = ref_graph
        self.tgt_callers, self.tgt_callees = tgt_graph

        self.rename_map: Dict[str, str] = {}
        self.split_map: Dict[str, List[str]] = {}   # ref -> [tgt...] split
        self.merge_map: Dict[str, List[str]] = {}   # tgt -> [ref...] merge
        self.scores: Dict[Tuple[str, str], float] = {}

    @staticmethod
    def _collapse(seq):
        out = []
        for f in seq:
            if not out or out[-1] != f:
                out.append(f)
        return out

    @staticmethod
    def _graph_from_adjacency(seq):
        """Fallback: without an event stream, approximate the call graph with trace adjacency"""
        callers, callees = defaultdict(set), defaultdict(set)
        for i in range(1, len(seq)):
            callees[seq[i - 1]].add(seq[i])
            callers[seq[i]].add(seq[i - 1])
        return callers, callees

    def _sim(self, r, t):
        key = (r, t)
        if key not in self.scores:
            rf, tf = self.ref_funcs.get(r), self.tgt_funcs.get(t)
            self.scores[key] = function_similarity(rf, tf) if rf and tf else 0.0
        return self.scores[key]

    def align(self) -> Dict:
        print("=" * 60)
        print("Step 1: cross-version function-level alignment")
        print("=" * 60)
        self._step1_rename()
        self._step2_merge_split()
        mapped_t = set(self.rename_map.values()) | \
                   {g for v in self.split_map.values() for g in v}
        stats = {
            "same_name": sorted(set(self.ref_funcs) & set(self.tgt_funcs)),
            "renamed": {r: t for r, t in self.rename_map.items() if r != t},
            "split_in_target": dict(self.split_map),
            "merged_in_target": dict(self.merge_map),
            "unmapped_ref_traced": [f for f in self.ref_trace_funcs
                                    if f not in self.rename_map
                                    and f not in self.split_map
                                    and f not in [g for v in self.merge_map.values() for g in v]],
            "unmapped_tgt_traced": [f for f in self.tgt_trace_funcs if f not in mapped_t],
        }
        if self.verbose:
            print(f"Same-name functions: {len(stats['same_name'])}")
            real_renames = stats['renamed']
            print(f"Renamed mappings: {len(real_renames)} pairs -> {real_renames}")
            print(f"Split (one ref => multiple tgt): {stats['split_in_target']}")
            print(f"Merged (multiple ref => one tgt): {stats['merged_in_target']}")
            print(f"Still unmapped: {len(stats['unmapped_ref_traced'])} on ref side, "
                  f"{len(stats['unmapped_tgt_traced'])} on tgt side")
        return stats

    # ---- 1-1: rename ----
    def _step1_rename(self):
        ref_names = [f for f in self.ref_trace_funcs if f in self.ref_funcs]
        tgt_names = [f for f in self.tgt_trace_funcs if f in self.tgt_funcs]

        # 1) same-name direct mapping => initial one-to-one mapping
        mapped_ref, mapped_tgt = set(), set()
        for n in ref_names:
            if n in self.tgt_funcs:
                self.rename_map[n] = n
                mapped_ref.add(n)
                mapped_tgt.add(n)

        # 2) different names but semantically similar: full cross scoring, greedy one-to-one, threshold 0.7
        cand = []
        for r in ref_names:
            if r in mapped_ref:
                continue
            for t in tgt_names:
                if t in mapped_tgt:
                    continue
                s = self._sim(r, t)
                if s >= self.threshold:
                    cand.append((s, r, t))
        cand.sort(reverse=True)
        for s, r, t in cand:
            if r in mapped_ref or t in mapped_tgt:
                continue
            self.rename_map[r] = t
            mapped_ref.add(r)
            mapped_tgt.add(t)
            if self.verbose and r != t:
                print(f"  [rename] {r} <-> {t} (similarity {s:.3f})")

    # ---- 1-2: merge/split (based on caller/callee anchors in the real call graph) ----
    def _mapped_neighbors(self, graph_callers, graph_callees, name, side):
        """The already-mapped portion among name's neighbors; returns (anchor set mapped to ref domain, neighbor name set)"""
        neighbors = set(graph_callers.get(name, set())) | \
                    set(graph_callees.get(name, set()))
        anchors = set()
        for n in neighbors:
            m = self.rename_map.get(n) if side == 'tgt' else None
            if side == 'tgt':
                if n in self.rename_map:
                    anchors.add(self.rename_map[n])
            else:
                if n in mapped_ref_set:
                    anchors.add(n)
        return anchors, neighbors

    def _step2_merge_split(self):
        global mapped_ref_set
        mapped_ref_set = set(self.rename_map.keys())
        mapped_tgt_set = set(self.rename_map.values())

        # ========== split: one ref function => multiple tgt fragments ==========
        unmapped_t = [f for f in self.tgt_trace_funcs
                      if f in self.tgt_funcs and f not in mapped_tgt_set]
        consumed = set()

        for t in unmapped_t:
            if t in consumed:
                continue
            # spec requirement: inspect the "already-mapped callers and callees" of this unmapped function
            anchor_refs = set()
            for c in self.tgt_callers.get(t, set()):
                if c in self.rename_map:
                    anchor_refs.add(self.rename_map[c])
            for e in self.tgt_callees.get(t, set()):
                if e in self.rename_map:
                    anchor_refs.add(self.rename_map[e])
            if not anchor_refs:
                continue     # cold-start blind spot: no mapped neighbors around

            # call-site siblings: unmapped target functions also called by these mapped callers
            group = [t]
            t_callers = self.tgt_callers.get(t, set())
            for u in unmapped_t:
                if u == t or u in consumed:
                    continue
                if self.tgt_callers.get(u, set()) & t_callers & mapped_tgt_set:
                    group.append(u)
                    consumed.add(u)
            merged_t = merge_functions([self.tgt_funcs[g] for g in group])

            # candidates = call-graph neighbors of the anchors on the ref side
            cand_refs = set()
            for a in anchor_refs:
                cand_refs |= self.ref_callers.get(a, set())
                cand_refs |= self.ref_callees.get(a, set())
            best_r, best_merged, best_single = None, 0.0, 0.0
            for r in cand_refs:
                if r not in self.ref_funcs or r in self.split_map \
                        or r in self.rename_map:
                    continue
                s_merged = function_similarity(self.ref_funcs[r], merged_t)
                s_single = max((function_similarity(self.ref_funcs[r],
                                                    self.tgt_funcs[g])
                                for g in group), default=0.0)
                if s_merged > best_merged:
                    best_r, best_merged, best_single = r, s_merged, s_single
            # spec: merged similarity higher than the original (single) and reaches threshold
            if best_r and best_merged >= self.threshold and best_merged > best_single:
                self.split_map[best_r] = group
                consumed.update(group)
                if self.verbose:
                    print(f"  [split] ref:{best_r} => tgt:{group} "
                          f"(merged similarity {best_merged:.3f} > single {best_single:.3f})")

        # ========== merge: multiple ref functions => one tgt function (reverse, by analogy) ==========
        unmapped_r = [f for f in self.ref_trace_funcs
                      if f in self.ref_funcs and f not in self.rename_map]
        consumed_r = set()

        for r in unmapped_r:
            if r in consumed_r:
                continue
            anchor_tgts = set()
            for c in self.ref_callers.get(r, set()):
                if c in self.rename_map:
                    anchor_tgts.add(self.rename_map[c])
            for e in self.ref_callees.get(r, set()):
                if e in self.rename_map:
                    anchor_tgts.add(self.rename_map[e])
            if not anchor_tgts:
                continue

            group = [r]
            r_callers = self.ref_callers.get(r, set())
            for u in unmapped_r:
                if u == r or u in consumed_r:
                    continue
                if self.ref_callers.get(u, set()) & r_callers & mapped_ref_set:
                    group.append(u)
                    consumed_r.add(u)
            merged_r = merge_functions([self.ref_funcs[g] for g in group])

            cand_tgts = set()
            for a in anchor_tgts:
                cand_tgts |= self.tgt_callers.get(a, set())
                cand_tgts |= self.tgt_callees.get(a, set())
            best_t, best_merged, best_single = None, 0.0, 0.0
            for t in cand_tgts:
                if t not in self.tgt_funcs or t in mapped_tgt_set \
                        or t in self.merge_map:
                    continue
                s_merged = function_similarity(merged_r, self.tgt_funcs[t])
                s_single = max((function_similarity(self.ref_funcs[g],
                                                    self.tgt_funcs[t])
                                for g in group), default=0.0)
                if s_merged > best_merged:
                    best_t, best_merged, best_single = t, s_merged, s_single
            if best_t and best_merged >= self.threshold and best_merged > best_single:
                self.merge_map[best_t] = group
                consumed_r.update(group)
                if self.verbose:
                    print(f"  [merge] ref:{group} => tgt:{best_t} "
                          f"(merged similarity {best_merged:.3f} > single {best_single:.3f})")

    def _reverse_rename(self, tgt_name):
        for r, t in self.rename_map.items():
            if t == tgt_name:
                return r
        return tgt_name

    # ---- last aligned function (near the end of the trace) ----
    def last_aligned_pair(self):
        """Find the first pair of alignable functions from the end of the two traces backwards"""
        ref_set = set(self.ref_trace_funcs)
        tgt_set = set(self.tgt_trace_funcs)

        def lookup(r):
            if r in self.rename_map:
                return self.rename_map[r]
            if r in self.split_map:
                # split group: take the fragment positioned furthest back in the target trace
                frags = [g for g in self.split_map[r] if g in tgt_set]
                return max(frags, key=lambda g: len(self.tgt_trace_funcs)
                           - 1 - self.tgt_trace_funcs[::-1].index(g)) if frags else None
            return None

        for r in reversed(self.ref_trace_funcs):
            t = lookup(r)
            if t and t in tgt_set:
                return r, t
        for t in reversed(self.tgt_trace_funcs):
            if t in self.merge_map:
                group = [g for g in self.merge_map[t] if g in ref_set]
                if group:
                    return group[-1], t
        return None
# ---------------- Step 2: statement-level alignment (lldb-trace approach) ----------------

def statement_align_with_lldb(binary: str, func_name: str, program_args: List[str],
                              max_steps: int = 300000) -> Dict:
    """
    Use lldb instruction-level single-stepping (lldb-trace method) to record the
    sequence of source line numbers executed from function entry to exit.
    Returns {"lines": [(file,line)...], "truncated": bool}
    Requires python3-lldb.
    """
    global lldb
    try:
        import lldb  # noqa
        if not hasattr(lldb, 'SBDebugger'):
            raise ImportError("lldb namespace stub")
    except ImportError:
        # On Ubuntu the real bindings live under the llvm package directory
        import glob, sys
        cands = glob.glob('/usr/lib/llvm-*/lib/python3*/dist-packages') + \
                glob.glob('/usr/lib/llvm-*/lib/python3/site-packages')
        for p in sorted(cands):
            if os.path.exists(os.path.join(p, 'lldb', '__init__.py')):
                sys.path.insert(0, p)
                break
        sys.modules.pop('lldb', None)   # clear the cached namespace stub
        import lldb  # noqa
    if not hasattr(lldb, 'SBDebugger'):
        return {"error": "python lldb bindings unavailable (please install python3-lldb)"}

    dbg = lldb.SBDebugger.Create()
    dbg.SetAsync(False)
    target = dbg.CreateTarget(binary)
    if not target or not target.IsValid():
        return {"error": f"cannot create target: {binary}"}

    import shlex, time
    listener = lldb.SBListener("stmt_trace")
    err = lldb.SBError()
    # launch and stop at entry, then run to main (by now dynamic libs like libtiff.so are all loaded)
    process = target.Launch(listener, list(program_args), None, None, None, None,
                            os.getcwd(), 1, True, err)   # stop_at_entry=1
    if not process or not err.Success():
        return {"error": f"launch failed: {err}"}
    # stop at main (all dynamic libs loaded by now), then set a breakpoint on the target function
    bp_main = target.BreakpointCreateByName("main")
    if bp_main.GetNumLocations() == 0:
        process.Kill()
        return {"error": "main not found"}
    ev = lldb.SBEvent()
    deadline = time.time() + 60
    hit_main = False
    while time.time() < deadline:
        t0 = process.GetThreadAtIndex(0)
        sr = t0.GetStopReason() if t0 else None
        if sr == lldb.eStopReasonBreakpoint and (
                t0.GetFrameAtIndex(0).GetFunctionName() or '') == 'main':
            hit_main = True
            break
        if process.GetState() in (lldb.eStateStopped, lldb.eStateRunning,
                                  lldb.eStateLaunching, lldb.eStateAttaching):
            if process.GetState() != lldb.eStateRunning:
                process.Continue()
        listener.WaitForEvent(1, ev)
    if not hit_main:
        process.Kill()
        return {"error": "could not run to main"}

    bp_before = target.GetNumBreakpoints()
    dbg.HandleCommand(f"breakpoint set -n {func_name}")
    bp = target.GetBreakpointAtIndex(target.GetNumBreakpoints() - 1) \
        if target.GetNumBreakpoints() > bp_before else None
    if bp is None or bp.GetNumLocations() == 0:
        process.Kill()
        return {"error": f"function {func_name} not found"}

    # continue running until the breakpoint is hit
    deadline = time.time() + 120
    hit = False
    while time.time() < deadline:
        if process.GetState() == lldb.eStateStopped:
            t0 = process.GetThreadAtIndex(0)
            sr = t0.GetStopReason() if t0 else None
            if sr == lldb.eStopReasonBreakpoint and func_name in (
                    t0.GetFrameAtIndex(0).GetFunctionName() or ''):
                hit = True
                break
            if sr is None:
                listener.WaitForEvent(1, ev)
                continue
            process.Continue()   # intermediate stop (launch SIGSTOP etc.), continue to the breakpoint
        listener.WaitForEvent(1, ev)
    if not hit:
        if process.GetState() == lldb.eStateExited:
            return {"error": f"target program exited before reaching function {func_name}"
                             f"(exit code={process.GetExitStatus()}), that function was not executed"}
        return {"error": "did not stop at breakpoint after launch"}

    GOOD_STOP = {lldb.eStopReasonTrace, lldb.eStopReasonPlanComplete,
                 lldb.eStopReasonBreakpoint, lldb.eStopReasonNone}
    CRASH_SIGNALS = {4, 6, 7, 8, 11}   # ILL ABRT BUS FPE SEGV
    lines = []
    truncated = False
    steps = 0
    thread = process.GetThreadAtIndex(0)

    def frame_func(thread):
        f = thread.GetFrameAtIndex(0)
        return f.GetFunctionName() or ''

    # if stopped on a breakpoint, first step into the function body
    while thread.GetStopReason() == lldb.eStopReasonBreakpoint \
            and func_name not in frame_func(thread):
        thread.StepOver()
        steps += 1

    while steps < max_steps:
        stop_reason = thread.GetStopReason()
        if stop_reason == lldb.eStopReasonSignal:
            sig = thread.GetStopReasonDataAtIndex(0)
            if sig in CRASH_SIGNALS:
                break   # crash signal: stop tracing
        elif stop_reason not in GOOD_STOP:
            break
        if func_name not in frame_func(thread):
            if lines:
                break   # left the target function => normal end
            thread.StepInstruction(True)
            steps += 1
            continue
        frame = thread.GetFrameAtIndex(0)
        le = frame.GetLineEntry()
        if le and le.GetLine() > 0:
            entry = (os.path.basename(le.GetFileSpec().GetFilename() or ''), le.GetLine())
            if not lines or lines[-1] != entry:
                lines.append(entry)
        thread.StepInstruction(True)
        steps += 1

    truncated = steps >= max_steps
    try:
        process.Kill()
    except Exception:
        pass
    lldb.SBDebugger.Destroy(dbg)
    return {"lines": lines, "truncated": truncated, "steps": steps}


def build_source_index(source_dir: str) -> Dict[str, List[str]]:
    """filename -> list of source lines (used for cross-version statement alignment by content)"""
    idx = defaultdict(list)
    for root, dirs, files in os.walk(source_dir):
        dirs[:] = [d for d in dirs if not d.startswith('.') and d not in
                   ('test', 'tests', 'contrib', 'html', 'man', 'CMakeFiles',
                    'build', 'bld')]
        for fn in files:
            if fn.endswith(('.c', '.h', '.cc', '.cpp')):
                try:
                    idx[fn] = open(os.path.join(root, fn),
                                   encoding='utf-8', errors='ignore').read().split('\n')
                except Exception:
                    pass
    return dict(idx)


def _norm_stmt(text: str) -> str:
    t = re.sub(r'/\*.*?\*/', ' ', text)
    t = re.sub(r'//[^"]*$', '', t).strip()
    t = re.sub(r'\s+', ' ', t)
    return t


def statements_to_text(traced_lines, src_index) -> List[str]:
    """(filename, line number) trace -> normalized source text sequence (align by content when line numbers differ across versions)"""
    out = []
    for fname, lineno in traced_lines:
        lines = src_index.get(fname)
        if lines and 1 <= lineno <= len(lines):
            out.append(_norm_stmt(lines[lineno - 1]) or '<empty>')
        else:
            out.append(f'{fname}:{lineno}')
    return out


def align_statements(ref_lines: List[Tuple[str, int]], tgt_lines: List[Tuple[str, int]],
                     ref_src_index: Optional[Dict] = None,
                     tgt_src_index: Optional[Dict] = None) -> Dict:
    """
    Statement-level alignment: line numbers differ across versions, so prefer LCS
    alignment using "normalized source text" as the unit, and find the first
    semantically-diverging statement. Returns the fork location and context on both sides.
    """
    if ref_src_index and tgt_src_index:
        ref_keys = statements_to_text(ref_lines, ref_src_index)
        tgt_keys = statements_to_text(tgt_lines, tgt_src_index)
        mode = "content"
    else:
        ref_keys = [f"{f}:{l}" for f, l in ref_lines]
        tgt_keys = [f"{f}:{l}" for f, l in tgt_lines]
        mode = "line-number"

    sm = SequenceMatcher(None, ref_keys, tgt_keys, autojunk=False)
    blocks = sm.get_matching_blocks()
    fork = None
    prev_ref_end, prev_tgt_end = 0, 0
    for b in blocks:
        if b.size == 0:
            break
        gap_ref = ref_lines[prev_ref_end:b.a]
        gap_tgt = tgt_lines[prev_tgt_end:b.b]
        if gap_ref or gap_tgt:
            # filter out gaps that are pure identical content (only order differs), report only truly different statements
            def texts(lines_, idx):
                if idx and idx is not None:
                    return [statements_to_text([(f, l)], idx)[0] for f, l in lines_]
                return [f"{f}:{l}" for f, l in lines_]
            rt, tt = texts(gap_ref, ref_src_index), texts(gap_tgt, tgt_src_index)
            same = set(rt) & set(tt)
            rt_only = [x for x in rt if x not in same]
            tt_only = [x for x in tt if x not in same]
            if rt_only or tt_only:
                fork = {
                    "ref_gap_statements": [
                        {"file": f, "line": l, "code": c}
                        for (f, l), c in zip(gap_ref, rt)
                        if c not in same],
                    "target_gap_statements": [
                        {"file": f, "line": l, "code": c}
                        for (f, l), c in zip(gap_tgt, tt)
                        if c not in same],
                    "aligned_before": {"ref_line": prev_ref_end, "target_line": prev_tgt_end},
                }
            break
        prev_ref_end, prev_tgt_end = b.a + b.size, b.b + b.size
    return {
        "alignment_mode": mode,
        "fork_statement": fork,
        "match_ratio": round(sm.ratio(), 4),
        "ref_total": len(ref_lines),
        "target_total": len(tgt_lines),
        "matching_blocks": [{"ref_start": b.a, "tgt_start": b.b, "size": b.size}
                             for b in blocks if b.size > 0][:50],
    }
