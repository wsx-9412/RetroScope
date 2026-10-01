#!/usr/bin/env python3
"""verify_fork_path.py - post-hoc verification of generated PoCs.

Runs AFTER the mutation stage has finished.  For every input file produced by
the mutation search (e.g. under out/<input>-<version>/), it re-runs the target
binary under GDB and certifies whether the execution actually passes through
the fork statement:

  * reached           - the fork breakpoint was hit at least once;
  * conditions        - the fork condition evaluated at every hit;
  * satisfied         - every hit evaluates to the reference-side outcome
                        (the target no longer takes the divergent branch);
  * crash             - ASan signature observed in the same run;
  * crash_after_fork  - the run hit the fork and then died with the
                        reference-compatible crash signature (ordering
                        evidence).

This is deliberately a separate tool: the mutation stage is not modified.
The fork information (target binary, arguments, fork file:line, invocation,
condition text, reference-side outcome, variables) is read from the divergence
JSON, so any accepted mutant can be audited independently.

Usage
-----
    python3 verify_fork_path.py \
        --trace-json results/CVE-2023-30775.diverge.json \
        --binary-ref tiff-versions/tiff-4.3.0/tools/.libs/tiffcrop \
        --limit 32 \
        --output results/CVE-2023-30775_fork_path_verification.json

    # explicit files instead of the auto-detected out/ directory
    python3 verify_fork_path.py --trace-json ... \
        --mutants out/CVE-2023-30775-4-0-8/0x126:-0x01:time:0 ...

    # also verify the original PoC (control: reached but not satisfied)
    python3 verify_fork_path.py --trace-json ... --include-original
"""

import argparse
import glob
import json
import os
import re
import subprocess
import sys
import tempfile
from pathlib import Path

BASE = Path(__file__).resolve().parent
sys.path.insert(0, str(BASE))

# reuse infra from the (unmodified) mutation tool
from trace_fork_offsets import (  # noqa: E402
    resolve_binary, build_run_env, extract_crash_signature,
    compare_crash_signatures, _replace_input_arg, _path_basename,
)

GDB_VERIFY_SCRIPT = r"""
import gdb, json, os
CFG = json.load(open(os.environ["FORK_VERIFY_CFG"]))
gdb.execute("set pagination off")
gdb.execute("set confirm off")
gdb.execute("set breakpoint pending on")
try:
    gdb.execute("set disable-randomization on")
except Exception:
    pass

class ForkBP(gdb.Breakpoint):
    def __init__(self, spec):
        super(ForkBP, self).__init__(spec)
        self.n = 0
        self.ignore_count = CFG.get("ignore", 0)

    def stop(self):
        self.n += 1
        rec = {"hit": self.n + CFG.get("ignore", 0)}
        try:
            rec["pc"] = int(gdb.parse_and_eval("$pc"))
        except Exception:
            pass
        if CFG.get("cond_expr"):
            try:
                rec["cond"] = bool(int(gdb.parse_and_eval(CFG["cond_expr"])))
            except Exception as e:
                rec["cond_error"] = str(e)[:120]
        vals = {}
        for e in (CFG.get("var_exprs") or []):
            try:
                vals[e] = int(gdb.parse_and_eval(e))
            except Exception:
                pass
        if vals:
            rec["vars"] = vals
        print("FORK_HIT " + json.dumps(rec))
        return False

# the fork statement usually lives in a shared library that is not mapped
# before run(); keeping the breakpoints pending lets gdb resolve them on load
bps = []
for spec in CFG.get("specs", []):
    try:
        b = ForkBP(spec)
        b.ignore_count = CFG.get("ignore", 0)
        bps.append(b)
    except Exception:
        continue
if not bps:
    print("FORK_BP_UNRESOLVED")
gdb.execute("run")
gdb.execute("quit")
"""


def load_divergence(path):
    with open(path) as f:
        raw = json.load(f)
    return raw.get("divergence", raw)


def build_hint(div, binary_target, fork_file=None, fork_line=None,
               expected_outcome=None):
    dyn = div.get("dynamic_fork") or {}
    diff = dyn.get("diff") or {}
    a = diff.get("a") or {}
    b = diff.get("b") or {}
    f_file = fork_file or div.get("root_cause_file_b") or div.get("root_cause_file")
    f_line = fork_line or div.get("root_cause_line_b") or div.get("root_cause_line")
    if not f_file or not f_line:
        return None
    spec = "%s:%d" % (f_file, int(f_line))
    stmt = b.get("text") or div.get("root_cause_statement_b") or ""
    m = re.match(r"^\s*if\s*\((.*)\)\s*$", stmt, re.S)
    cond = ("((%s))" % m.group(1).strip()) if m else None
    exp = expected_outcome
    if exp is None:
        exp = a.get("outcome")
        if not isinstance(exp, bool):
            exp = None
    return {
        "fork_spec": spec,
        "cond_expr": cond,
        "expected_outcome": exp,
        "invocation": dyn.get("invocation"),
        "var_exprs": (div.get("variables") or [])[:6],
        "binary": binary_target,
    }


def verify_one(binary, hint, mutant_path, program_args, original_input,
               timeout=60):
    real = resolve_binary(binary)
    if not real or not os.path.isfile(real) or not os.access(real, os.X_OK):
        return {"status": "binary_missing",
                "error": "target binary not found: %s" % (real or binary)}
    spec = hint.get("fork_spec") or ""
    specs = []
    if spec:
        specs.append(spec)
        if ":" in spec:
            base = os.path.basename(spec.rsplit(":", 1)[0])
            specs.append("%s:%s" % (base, spec.rsplit(":", 1)[1]))
    cfg = {
        "specs": list(dict.fromkeys(specs)),
        "cond_expr": hint.get("cond_expr"),
        "var_exprs": hint.get("var_exprs") or [],
        "ignore": max(0, int(hint.get("invocation") or 1) - 1),
    }
    run_args = program_args
    if original_input:
        run_args = [_replace_input_arg(a, mutant_path, original_input)
                    for a in program_args]
    tmpdir = tempfile.mkdtemp(prefix="fork_path_verify_")
    cfg_path = os.path.join(tmpdir, "cfg.json")
    script_path = os.path.join(tmpdir, "verify.py")
    with open(cfg_path, "w") as f:
        json.dump(cfg, f)
    with open(script_path, "w") as f:
        f.write(GDB_VERIFY_SCRIPT)
    env = build_run_env(real)
    env["ASAN_OPTIONS"] = "detect_leaks=0:abort_on_error=0"
    env["FORK_VERIFY_CFG"] = cfg_path
    try:
        proc = subprocess.run(
            ["gdb", "-batch", "-nx", "-q", "-x", script_path,
             "--args", str(real)] + [str(a) for a in run_args],
            env=env, capture_output=True, text=True, timeout=timeout)
        out = proc.stdout + proc.stderr
    except subprocess.TimeoutExpired:
        return {"status": "timeout"}
    except Exception as e:
        return {"status": "error", "error": str(e)[:160]}
    # gdb could not load/exec the target: do not report this as "not reached"
    for marker in ("No such file", "not in executable format",
                   "Cannot exec", "not found"):
        if marker in out and "FORK_HIT" not in out:
            tail = [l for l in out.strip().splitlines() if l.strip()]
            return {"status": "gdb_error",
                    "error": (tail[-1] if tail else marker)[:160]}
    hits = []
    seen = set()
    for m in re.finditer(r"FORK_HIT (\{.*\})", out):
        try:
            rec = json.loads(m.group(1))
        except Exception:
            continue
        k = (rec.get("hit"), rec.get("pc"))
        if k in seen:
            continue
        seen.add(k)
        hits.append(rec)
    sig = extract_crash_signature(out)
    crash = sig["crash_frames"][0] if (sig and sig.get("crash_frames")) else {}
    res = {
        "status": "ok",
        "reached": bool(hits),
        "hit_count": len(hits),
        "hits": hits[:8],
        "invocation": cfg["ignore"] + 1,
        "bp_unresolved": "FORK_BP_UNRESOLVED" in out,
        "_sig": sig,
        "crash": ({"type": sig["type"],
                   "function": crash.get("function"),
                   "file": _path_basename(crash.get("file")),
                   "line": crash.get("line")} if sig else None),
    }
    return res


def default_mutants_dir(input_file, version=None):
    """out/<input-basename>-<version-numeric> produced by the mutation stage.

    When the target version is known (e.g. ``tiff-4.0.7``) the exact directory
    is required: a missing directory means this target produced no PoCs, and
    falling back to another version's directory would audit the wrong files.
    """
    stem = os.path.basename(input_file)
    if version:
        m = re.search(r"(\d+\.\d+(?:\.\d+)*)", str(version))
        if m:
            exact = str(BASE / "out" / (stem + "-" + m.group(1).replace(".", "-")))
            return exact if os.path.isdir(exact) else None
    cands = sorted(glob.glob(str(BASE / "out" / (stem + "-*"))),
                   key=os.path.getmtime, reverse=True)
    return cands[0] if cands else None



def _sibling(trace_json, suffix):
    d = os.path.dirname(os.path.abspath(trace_json))
    stem = os.path.basename(trace_json)
    stem = re.sub(r"\.json$", "", stem)
    stem = re.sub(r"\.diverge$", "", stem)
    path = os.path.join(d, stem + suffix)
    return path if os.path.isfile(path) else None


def collect_analysis_summary(div, input_file, trace_json):
    """Fork statement / variables / located offsets / time-to-success."""
    stmt_b = (div.get("root_cause_statement_b")
              or div.get("fork_statement") or "")
    stmt_a = div.get("root_cause_statement_a") or ""

    _C_KEYWORDS = {
        "if", "else", "while", "for", "do", "switch", "case", "break",
        "continue", "return", "sizeof", "NULL", "true", "false", "goto",
        "int", "char", "long", "short", "unsigned", "signed", "float",
        "double", "void", "const", "static", "extern", "struct", "union",
        "enum", "typedef",
    }
    stmt_vars = list(dict.fromkeys(
        v for v in re.findall(r"[A-Za-z_]\w*", stmt_b)
        if v not in _C_KEYWORDS and not v.isdigit()))

    origin_json = _sibling(trace_json, "_origin.json")
    pt_json = _sibling(trace_json, "_polytracker_offsets.json")
    mut_dyn = _sibling(trace_json, "_origin_mutation.json")
    legacy_mut = str(BASE / "in" / "fork_trace_result.json")

    traced = []
    if origin_json:
        try:
            od = json.load(open(origin_json))
            events = od.get("events") or []
            children = {}
            for e in events:
                children.setdefault(e.get("parent"), []).append(e)

            def _has_real(eid):
                for c in children.get(eid, []):
                    if c.get("kind") not in ("unsupported", "visited"):
                        return True
                    if _has_real(c.get("id")):
                        return True
                return False

            traced = [e.get("expr") for e in events
                      if e.get("kind") == "variable" and e.get("size")
                      and _has_real(e.get("id"))]
        except Exception:
            traced = []
    if not traced and pt_json:
        try:
            pd = json.load(open(pt_json))
            traced = list((pd.get("variable_offsets") or {}).keys())
        except Exception:
            traced = []
    if not traced:
        traced = [v for v in (div.get("variables") or [])
                  if isinstance(v, str)]
    traced = list(dict.fromkeys(traced))

    located = set()
    if origin_json:
        try:
            od = json.load(open(origin_json))
            for o in od.get("offsets") or []:
                off, ln = o.get("offset"), o.get("length") or 1
                if off is None:
                    continue
                located.update(range(off, off + ln))
        except Exception:
            pass
    if not located and pt_json:
        try:
            pd = json.load(open(pt_json))
            for offs in (pd.get("variable_offsets") or {}).values():
                for h in offs or []:
                    if isinstance(h, (list, tuple)):
                        off = h[0]
                        ln = h[1] if len(h) > 1 else 1
                    elif isinstance(h, dict):
                        off = h.get("offset")
                        ln = (h.get("length") or h.get("width") or 1)
                    else:
                        continue
                    if off is None:
                        continue
                    located.update(range(off, off + max(1, int(ln))))
        except Exception:
            pass
    if not located and os.path.isfile(legacy_mut):
        try:
            ld = json.load(open(legacy_mut))
            for off in ld.get("mutation_offsets") or []:
                located.add(int(off))
        except Exception:
            pass

    t_success, t_src = None, None
    for src in (mut_dyn, legacy_mut):
        if not src or not os.path.isfile(src):
            continue
        try:
            md = json.load(open(src))
        except Exception:
            continue
        def _scan(container):
            got = []
            if not isinstance(container, dict):
                return got
            for res in container.values():
                if not isinstance(res, dict):
                    continue
                for m in (res.get("matches") or {}).values():
                    if isinstance(m, dict) \
                            and m.get("time_to_success") is not None:
                        got.append(float(m["time_to_success"]))
            return got

        vals = []
        for key in ("crash_results", "pairwise_results",
                    "ifd_region_mutation"):
            vals += _scan(md.get(key))
        # dynamic mutation JSON dumps the result map directly (offset keys)
        direct = {k: v for k, v in md.items()
                  if isinstance(k, str) and k.isdigit()}
        vals += _scan(direct)
        if vals:
            v = min(vals)
            if t_success is None or v < t_success:
                t_success, t_src = v, src

    size = os.path.getsize(input_file) if os.path.isfile(input_file) else None
    traced_stmt = [v for v in stmt_vars if v in traced]
    return {
        "fork_statement": stmt_b,
        "fork_statement_reference": stmt_a,
        "statement_operands": stmt_vars,
        "traced_variables": traced,
        "traced_statement_operands": traced_stmt,
        "located_offsets": len(located),
        "input_size": size,
        "offset_ratio": ("%d/%d" % (len(located), size)) if size else None,
        "time_to_first_success_seconds": t_success,
        "time_to_first_success_source": (os.path.basename(t_src) if t_src else None),
    }

def main():
    ap = argparse.ArgumentParser(
        description="Verify that generated PoCs pass the fork statement "
                    "(post-hoc, after the mutation stage)")
    ap.add_argument("--trace-json", required=True,
                    help="divergence JSON (binary/args/fork info)")
    ap.add_argument("--binary", help="target binary override")
    ap.add_argument("--binary-ref", help="reference binary override")
    ap.add_argument("--input", help="original PoC override")
    ap.add_argument("--args", help="argument template override")
    ap.add_argument("--mutants-dir", help="directory of generated PoCs "
                    "(default: out/<input-basename>-*)")
    ap.add_argument("--mutants", nargs="*", default=[],
                    help="explicit mutant files to check")
    ap.add_argument("--include-original", action="store_true",
                    help="also check the original PoC (control)")
    ap.add_argument("--limit", type=int, default=32,
                    help="maximum number of files to check (default 32)")
    ap.add_argument("--timeout", type=int, default=60,
                    help="per-file GDB timeout in seconds")
    ap.add_argument("--output", help="report JSON path")
    ap.add_argument("--expected-outcome", type=int, choices=[0, 1],
                    help="override the reference-side fork outcome")
    a = ap.parse_args()

    div = load_divergence(a.trace_json)
    binary = (a.binary or div.get("binary_b") or div.get("binary_a"))
    binary_ref = a.binary_ref or div.get("binary_a")
    input_file = a.input or div.get("input_file")
    if not binary or not input_file:
        ap.error("need a target binary and the original input "
                 "(from --trace-json or explicit flags)")
    if not os.path.isfile(input_file):
        ap.error("input file not found: %s" % input_file)
    if a.args:
        arg_template = a.args
    else:
        arg_template = div.get("args_b") or div.get("args_a") or []
    if isinstance(arg_template, (list, tuple)):
        program_args = [str(x) for x in arg_template]
    else:
        program_args = str(arg_template).split()

    exp = a.expected_outcome if a.expected_outcome is not None else None
    hint = build_hint(div, binary, expected_outcome=exp)
    if not hint:
        ap.error("no fork location in %s" % a.trace_json)
    expected = hint.get("expected_outcome")
    print("[*] fork spec   : %s (invocation %s)" % (hint["fork_spec"],
                                                    hint["invocation"]))
    print("[*] condition   : %s" % hint["cond_expr"])
    print("[*] expected outcome (reference side): %s" % expected)

    # reference crash signature (for crash_after_fork)
    ref_sig = None
    if binary_ref and os.path.isfile(resolve_binary(binary_ref) or ""):
        try:
            ref_args = div.get("args_a") or program_args
            ref_args = [_replace_input_arg(x, input_file, input_file)
                        for x in ([str(v) for v in ref_args]
                                  if isinstance(ref_args, (list, tuple))
                                  else str(ref_args).split())]
            env = build_run_env(resolve_binary(binary_ref))
            env["ASAN_OPTIONS"] = "detect_leaks=0:abort_on_error=0"
            proc = subprocess.run([resolve_binary(binary_ref)] + ref_args,
                                  env=env, capture_output=True, text=True,
                                  timeout=a.timeout)
            ref_sig = extract_crash_signature(proc.stdout + proc.stderr)
            if ref_sig:
                fr = ref_sig["crash_frames"][0] if ref_sig["crash_frames"] else {}
                print("[*] reference crash: %s in %s (%s:%s)" % (
                    ref_sig["type"], fr.get("function"),
                    _path_basename(fr.get("file")), fr.get("line")))
        except Exception as e:
            print("[!] could not capture reference crash: %s" % e)

    # collect mutant files
    files = list(a.mutants)
    if not files:
        mdir = a.mutants_dir or default_mutants_dir(input_file,
                                                    div.get("version_b"))
        if mdir and os.path.isdir(mdir):
            files = sorted(str(p) for p in Path(mdir).iterdir() if p.is_file())
            print("[*] mutants dir : %s (%d files)" % (mdir, len(files)))
        else:
            print("[!] no mutants directory for this target version "
                  "(expected out/%s-%s*); pass --mutants-dir/--mutants to "
                  "override" % (os.path.basename(input_file),
                                str(div.get("version_b") or "?")))
    if a.include_original:
        files = [input_file] + files
    if a.limit > 0:
        files = files[:a.limit]
    if not files:
        print("[!] nothing to verify")
        return 1

    report = {
        "trace_json": a.trace_json,
        "fork": {
            "spec": hint["fork_spec"],
            "invocation": hint["invocation"],
            "condition": hint["cond_expr"],
            "expected_outcome": expected,
        },
        "reference_crash": ({"type": ref_sig["type"]} if ref_sig else None),
        "mutants": [],
        "summary": {},
    }
    n_reached = n_sat = n_caf = n_pass = 0
    for path in files:
        v = verify_one(binary, hint, path, program_args, input_file,
                       timeout=a.timeout)
        entry = {"file": path, "status": v.get("status")}
        if v.get("status") == "ok":
            conds = [h.get("cond") for h in v["hits"] if "cond" in h]
            sat = None
            if expected is not None and conds:
                sat = all(c == expected for c in conds)
            sig = v.pop("_sig", None)
            caf = None
            cverdict = None
            if v.get("reached") and sig is not None and ref_sig is not None:
                cverdict, _ = compare_crash_signatures(ref_sig, sig)
                caf = cverdict in ("same_func", "same_site")
                if not caf and cverdict == "same_type":
                    caf = "same_type"
            elif v.get("reached"):
                caf = None
            else:
                caf = False
            if v.get("reached"):
                n_reached += 1
            if sat:
                n_sat += 1
            if caf is True:
                n_caf += 1
            if v.get("reached") and sat and caf is True:
                n_pass += 1
                verdict = "passed_fork_and_satisfied"
            elif v.get("reached") and sat:
                verdict = "passed_fork_no_crash_after"
            elif v.get("reached"):
                verdict = "passed_fork_but_unsatisfied"
            else:
                verdict = "fork_not_reached"
            entry.update({
                "reached": v["reached"],
                "hit_count": v["hit_count"],
                "conditions": conds,
                "satisfied": sat,
                "crash": v.get("crash"),
                "crash_after_fork": caf,
                "crash_verdict": cverdict,
                "verdict": verdict,
            })
            print("  %-4s %-28s reached=%s conds=%s satisfied=%s "
                  "crash_after_fork=%s" % (
                      verdict.replace("passed_fork_", "ok:"),
                      os.path.basename(path), v["reached"], conds, sat, caf))
        else:
            entry["error"] = v.get("error") or v.get("status")
            print("  error %-28s %s" % (os.path.basename(path),
                                        entry["error"]))
        report["mutants"].append(entry)

    summary = collect_analysis_summary(div, input_file, a.trace_json)
    report["analysis_summary"] = summary
    report["summary"] = {
        "checked": len(report["mutants"]),
        "reached_fork": n_reached,
        "satisfied": n_sat,
        "crash_after_fork": n_caf,
        "fully_certified": n_pass,
    }
    print("\n=== fork / tracing summary ===")
    print("  fork statement (target) : %s" % (summary["fork_statement"] or "N/A"))
    print("  fork statement (ref)    : %s"
          % (summary["fork_statement_reference"] or "N/A"))
    print("  statement operands      : %s"
          % ", ".join(summary["statement_operands"]) or "N/A")
    print("  traced variable(s)      : %s"
          % ", ".join(summary["traced_variables"]) or "N/A")
    print("  traced from statement   : %s"
          % (", ".join(summary["traced_statement_operands"]) or "N/A"))
    print("  located input offsets   : %s bytes"
          % summary["located_offsets"]
          + (" / %s bytes total (%s)" % (summary["input_size"],
                                         summary["offset_ratio"])
             if summary["input_size"] else ""))
    if summary["time_to_first_success_seconds"] is not None:
        print("  first mutation success  : %.3f s after the first mutation "
              "started (%s)"
              % (summary["time_to_first_success_seconds"],
                 summary["time_to_first_success_source"]))
    out_path = a.output or str(
        Path(a.trace_json).with_name(
            os.path.splitext(os.path.basename(a.trace_json))[0]
            + "_fork_path_verification.json"))
    with open(out_path, "w") as f:
        json.dump(report, f, indent=1, default=str)
    print("\n=== fork-path verification summary ===")
    print(json.dumps(report["summary"], indent=1))
    print("report: %s" % out_path)
    return 0


if __name__ == "__main__":
    sys.exit(main())
