#!/usr/bin/env python3
"""
trace_diff.py — compare the execution trace divergence of two different inputs
in the same version of the software

Function names are fixed within a version, so align the two traces directly by name.
Output all divergence points, each containing:
  1) the last common function name before divergence (and which call it is in each trace)
  2) the input argument variable names + values, and return value of that call (comparing the two inputs)

Usage:
  python3 trace_diff.py --binary audiofile-versions/audiofile-0.2.7/sfcommands/sfconvert \
      --input-a in/CVE-2017-6836 --input-b new-in/CVE-2017-6836-0-2-7 \
      --args '{input} out.mp3 format aiff'
"""
import argparse, bisect, json, os, shutil, subprocess, sys, tempfile, time
from collections import Counter
from pathlib import Path

BASE = Path(__file__).resolve().parent
FUNCTRACER_SO = BASE / "functracer.so"
NOISE_PREFIX = ('__', 'asan', '_ZN', '_ZSt')

# ---------------- libtool wrapper script resolution ----------------
def resolve_real_binary(binpath):
    binpath = Path(binpath).resolve()
    try:
        with open(binpath, 'rb') as f:
            head = f.read(64)
        if head.startswith(b'#!') or head.startswith(b'# '):
            real = binpath.parent / '.libs' / binpath.name
            if real.exists() and open(real,'rb').read(4) == b'\x7fELF':
                return real
    except Exception:
        pass
    return binpath

# ---------------- function trace capture ----------------
_symcache = {}
def resolve_local(binpath, offset):
    if binpath not in _symcache:
        syms = []
        try:
            r = subprocess.run(["nm", "--defined-only", "-n", str(binpath)],
                               capture_output=True, text=True)
            for l in r.stdout.split('\n'):
                ps = l.split(maxsplit=2)
                if len(ps) == 3 and all(c in '0123456789abcdef' for c in ps[0]):
                    syms.append((int(ps[0], 16), ps[2]))
        except Exception:
            pass
        _symcache[binpath] = syms
    syms = _symcache[binpath]
    if not syms:
        return None
    i = bisect.bisect_right([s[0] for s in syms], offset) - 1
    if i >= 0 and offset - syms[i][0] < 65536:
        return syms[i][1].split('(')[0]
    return None

def capture_function_trace(cmd, timeout=300):
    """return (function entry sequence, whether it crashed)"""
    out_file = tempfile.mktemp(prefix="td_", suffix=".log")
    env = os.environ.copy()
    preloads = []
    try:
        r = subprocess.run(["gcc", "-print-file-name=libasan.so"],
                           capture_output=True, text=True)
        if "libasan" in r.stdout.strip():
            preloads.append(r.stdout.strip())
    except Exception:
        pass
    preloads.append(str(FUNCTRACER_SO))
    env.update({"LD_PRELOAD": ":".join(preloads),
                "FUNC_TRACE_OUT": out_file,
                "ASAN_OPTIONS": "detect_leaks=0:abort_on_error=1"})
    try:
        subprocess.run([str(c) for c in cmd], capture_output=True,
                       text=True, timeout=timeout, env=env)
    except subprocess.TimeoutExpired:
        pass
    base_map, last_module, events = {}, None, []
    try:
        for line in open(out_file):
            parts = line.split()
            if len(parts) >= 3 and parts[0] == 'M':
                try:
                    mpath = parts[2]
                    base_map[int(parts[1], 16)] = mpath
                    last_module = mpath
                except (IndexError, ValueError):
                    pass
            elif len(parts) == 3 and parts[0] in ('>','<') and parts[1].startswith('@'):
                try:
                    events.append((parts[0], ('local',
                                    base_map.get(int(parts[1][1:],16)), int(parts[2],16))))
                except ValueError:
                    continue
            elif len(parts) == 2 and parts[0] in ('>','<'):
                tok = parts[1]
                if tok.startswith('@') and last_module:
                    try:
                        events.append((parts[0], ('local', last_module, int(tok[1:],16))))
                        continue
                    except ValueError:
                        pass
                events.append((parts[0], tok))
    finally:
        try: os.unlink(out_file)
        except Exception: pass
    seq = []
    for d, tok in events:
        if isinstance(tok, tuple):
            name = resolve_local(tok[1], tok[2])
            if not name: continue
        else:
            name = tok
        if name.startswith(NOISE_PREFIX) or 'asan' in name.lower(): continue
        if d == '>' and (not seq or seq[-1] != name):   # collapse adjacent duplicates
            seq.append(name)
    print(f"    trace length: {len(seq)}")
    return seq

# ---------------- auto rebuild when not instrumented ----------------
def ensure_instrumented(version_dir, asan=False):
    version_dir = Path(version_dir)
    marker = version_dir / ".instr_build"
    instr_dir = Path(str(version_dir) + "-instr")
    if marker.exists() and instr_dir.exists():
        return instr_dir
    print(f"[rebuild] {version_dir.name} has no instrumented build, rebuilding to {instr_dir.name} ...")
    if instr_dir.exists():
        shutil.rmtree(instr_dir)
    shutil.copytree(version_dir, instr_dir,
                    ignore=lambda d, names: [n for n in names
                        if n in ('.git','bld','build','.libs')
                        or n.endswith(('.o','.lo','.log'))])
    cflags = "-O0 -g -finstrument-functions" + (" -fsanitize=address -fno-omit-frame-pointer" if asan else "")
    env = os.environ.copy()
    env.update({"CFLAGS": cflags, "CXXFLAGS": cflags + " -fpermissive",
                "LDFLAGS": "-fsanitize=address" if asan else ""})
    nproc = str(os.cpu_count() or 2)
    ok = False
    try:
        if (instr_dir/"configure").exists() or (instr_dir/"configure.ac").exists():
            if not (instr_dir/"configure").exists():
                subprocess.run(["autoreconf","-fi"], cwd=instr_dir,
                               capture_output=True, env=env)
            if subprocess.run(["sh","./configure","--disable-shared"], cwd=instr_dir,
                              capture_output=True, text=True, env=env).returncode == 0:
                r = subprocess.run(["make","-j",nproc], cwd=instr_dir,
                                   capture_output=True, text=True, env=env)
                ok = r.returncode == 0
        elif (instr_dir/"CMakeLists.txt").exists():
            bld = instr_dir/"bld-instr"; bld.mkdir(exist_ok=True)
            if subprocess.run(["cmake","..","-DCMAKE_BUILD_TYPE=Debug",
                               f"-DCMAKE_C_FLAGS={cflags}",
                               "-DJAS_ENABLE_OPENGL=OFF","-DJAS_ENABLE_DOC=OFF"],
                              cwd=bld, capture_output=True, text=True, env=env).returncode == 0:
                r = subprocess.run(["make","-j",nproc], cwd=bld,
                                   capture_output=True, text=True, env=env)
                ok = r.returncode == 0
    except Exception as e:
        print("[rebuild] exception:", e)
    if ok:
        marker.write_text("ok")
        print(f"[rebuild] done: {instr_dir}")
        return instr_dir
    shutil.rmtree(instr_dir, ignore_errors=True)
    return version_dir

def find_version_root(binary):
    """Walk up from the binary to find the version root (with .build_ok / configure / CMakeLists markers)"""
    d = binary.parent
    for _ in range(5):
        if (d / ".build_ok").exists() or (d / "configure").exists() \
           or (d / "CMakeLists.txt").exists():
            return d
        if d.parent == d:
            break
        d = d.parent
    return binary.parent.parent.parent

def locate_instr_binary(binary, instr_dir):
    rel = binary.relative_to(find_version_root(binary))
    cand = instr_dir / rel
    if not cand.exists() and '.libs' in rel.parts:
        cand = instr_dir / Path(*[p for p in rel.parts if p != '.libs'])
    return cand if cand.exists() else binary

# ---------------- find all divergence points (simple name matching) ----------------
def find_divergence_points(a, b):
    """
    Two-pointer synchronous advance; a name mismatch is a divergence point.
    After diverging, skip the differing fragments on both sides (until the next
    name that can realign) and continue looking for subsequent divergence points.
    Returns: [(last common function before divergence, which call it is in A,
               which call it is in B, A's differing fragment, B's differing fragment)]
    """
    points = []
    i = j = 0
    cnt_a, cnt_b = Counter(), Counter()
    while i < len(a) and j < len(b):
        if a[i] == b[j]:
            cnt_a[a[i]] += 1
            cnt_b[b[j]] += 1
            i += 1; j += 1
            continue
        # ---- divergence point ----
        last_func = a[i-1] if i > 0 else "(program entry)"
        occ_a = cnt_a[last_func] if i > 0 else 0
        occ_b = cnt_b[last_func] if j > 0 else 0
        # find the rejoin point: the next occurrence of the same function name in a[i:] and b[j:]
        end_a, end_b = len(a), len(b)
        for k in range(i, len(a)):
            if a[k] in b[j:]:
                end_a, end_b = k, j + b[j:].index(a[k])
                break
        points.append({
            "after_function": last_func,
            "occurrence": {"inputA": occ_a, "inputB": occ_b},
            "gap_inputA": a[i:end_a],
            "gap_inputB": b[j:end_b],
            "trace_index": {"inputA": i-1 if i > 0 else None,
                            "inputB": j-1 if j > 0 else None},
        })
        i, j = end_a, end_b
    if i < len(a) or j < len(b):
        # one side ends first
        last_func = a[i-1] if i > 0 else (b[j-1] if j > 0 else "(program entry)")
        points.append({
            "after_function": last_func,
            "occurrence": {"inputA": cnt_a.get(last_func,0), "inputB": cnt_b.get(last_func,0)},
            "gap_inputA": a[i:],
            "gap_inputB": b[j:],
            "trace_index": {"inputA": i-1 if i > 0 else None,
                            "inputB": j-1 if j > 0 else None},
        })
    return points

# ---------------- value capture (lldb, get real variable names) ----------------
ARG_REGS = ["rdi", "rsi", "rdx", "rcx", "r8", "r9"]

def capture_values(binary, cmd_args, functions, max_events=20000):
    global lldb
    try:
        import lldb
        if not hasattr(lldb, 'SBDebugger'):
            raise ImportError
    except ImportError:
        import glob
        for p in sorted(glob.glob('/usr/lib/llvm-*/lib/python3*/dist-packages'), reverse=True):
            if os.path.exists(os.path.join(p, 'lldb', '__init__.py')):
                sys.path.insert(0, p); break
        sys.modules.pop('lldb', None)
        import lldb
    sys.stdout = sys.__stdout__   # lldb import hijacks stdout, restore it

    print("    [lldb] creating target...", flush=True)
    dbg = lldb.SBDebugger.Create(); dbg.SetAsync(False)
    target = dbg.CreateTarget(str(binary))
    if not target.IsValid():
        print("    cannot create target:", binary); return {}
    listener = lldb.SBListener("td"); err = lldb.SBError()
    process = target.Launch(listener, list(cmd_args), None, None, None, None,
                            os.getcwd(), 1, True, err)
    if not process or not err.Success():
        print("    launch failed:", err); return {}
    # run to main (dynamic libs loaded)
    target.BreakpointCreateByName("main")
    ev = lldb.SBEvent(); deadline = time.time() + 60; at_main = False
    while time.time() < deadline:
        state = process.GetState()
        t0 = process.GetThreadAtIndex(0)
        sr = t0.GetStopReason() if (state == lldb.eStateStopped and t0) else None
        fname = (t0.GetFrameAtIndex(0).GetFunctionName() or '') if sr else ''
        if sr == lldb.eStopReasonBreakpoint and 'main' in fname:
            at_main = True; break
        if state == lldb.eStateExited:
            break
        if state == lldb.eStateStopped:
            process.Continue()
        listener.WaitForEvent(1, ev)
    if not at_main:
        print("    could not stop at main"); process.Kill(); return {}
    for fn in functions:
        dbg.HandleCommand(f"breakpoint set -n {fn}")
    dbg.HandleCommand("breakpoint delete 1")   # remove main breakpoint

    records = {fn: [] for fn in functions}
    pending = {}      # return-capture breakpoint id -> function name
    events = 0
    print("    [lldb] breakpoints ready, starting to run...", flush=True)
    deadline = time.time() + 1800
    while events < max_events and time.time() < deadline:
        state = process.GetState()
        if state in (lldb.eStateExited, lldb.eStateDetached):
            break
        if state != lldb.eStateStopped:
            listener.WaitForEvent(1, ev); continue
        thread = process.GetThreadAtIndex(0)
        sr = thread.GetStopReason()
        frame = thread.GetFrameAtIndex(0)
        if sr == lldb.eStopReasonBreakpoint:
            pc_la = frame.GetPCAddress().GetLoadAddress(target)
            hit_ret = None
            for bid, fname in list(pending.items()):
                bp = target.FindBreakpointByID(bid)
                if bp and bp.GetLocationAtIndex(0):
                    la = bp.GetLocationAtIndex(0).GetAddress().GetLoadAddress(target)
                    if la == pc_la:
                        hit_ret = (bid, fname); break
            if hit_ret:
                bid, fname = hit_ret
                if records.get(fname):
                    rv = frame.FindRegister("rax")
                    records[fname][-1]["return_value(rax)"] = rv.GetValue()
                target.BreakpointDelete(bid)
                del pending[bid]
            else:
                full = frame.GetFunctionName() or ''
                short = next((f for f in functions if full.startswith(f)), None)
                if short:
                    args = {}
                    for v in frame.GetVariables(True, False, False, True):
                        args[v.GetName()] = v.GetValue()   # real variable name + value (debug info)
                    if not args:   # no debug info, fall back to registers
                        args = {f"arg{k}({r})": frame.FindRegister(r).GetValue()
                                for k, r in enumerate(ARG_REGS[:3])}
                    records[short].append({"args": args})
                    if thread.GetNumFrames() > 1:
                        ra = thread.GetFrameAtIndex(1).GetPC()
                        rb = target.BreakpointCreateBySBAddress(lldb.SBAddress(ra, target))
                        rb.SetOneShot(True)
                        pending[rb.GetID()] = short
            process.Continue(); events += 1
        elif sr == lldb.eStopReasonSignal:
            desc = thread.GetStopDescription(200) or ''
            if any(s in desc for s in ("SEGV", "ABRT", "BUS ", "ILL", "FPE")):
                break
            process.Continue(); events += 1
        elif sr == lldb.eStopReasonNone:
            listener.WaitForEvent(1, ev); time.sleep(0.01)
        else:
            process.Continue(); events += 1
    try: process.Kill()
    except Exception: pass
    lldb.SBDebugger.Destroy(dbg)
    total = sum(len(v) for v in records.values())
    print(f"    value capture: {total} records")
    return records

# ---------------- value comparison (ASLR normalization) ----------------
def _vc(v):
    try:
        n = int(v, 16)
        return ('int', n) if n < 0x100000 else ('addr',)
    except (TypeError, ValueError):
        return ('raw', v)

def _args_equal(a, b):
    ka = {k: _vc(v) for k, v in (a or {}).items()}
    kb = {k: _vc(v) for k, v in (b or {}).items()}
    return ka == kb


# ---------------- main flow ----------------

def resolve_side(user_bin, args_template):
    """Resolve the libtool wrapper, build mk/mk_lldb closures"""
    user_bin = Path(user_bin)
    real_bin = resolve_real_binary(user_bin)

    def mk(input_file):
        return [str(user_bin)] + args_template.replace(
            "{input}", str(Path(input_file).resolve())).split()

    def mk_lldb(input_file):
        libs = []
        vr = find_version_root(real_bin).resolve()
        for d in sorted(vr.rglob('.libs')):
            libs.append(str(d))
        for p in real_bin.parents:
            d = p / '.libs'
            if d.exists() and str(d) not in libs:
                libs.append(str(d))
        env_note = {"LD_LIBRARY_PATH": ":".join(libs)} if libs else {}
        return [str(real_bin)] + args_template.replace(
            "{input}", str(Path(input_file).resolve())).split(), env_note

    return real_bin, mk, mk_lldb


def capture_side(user_bin, args_template, input_file, label):
    """Capture one side's trace; return (real_bin, mk, mk_lldb, seq, work)"""
    real_bin, mk, mk_lldb = resolve_side(user_bin, args_template)
    print(f"  [{label}] capturing: {input_file}")
    seq = capture_function_trace(mk(input_file))
    work = None
    if not seq:
        instr = ensure_instrumented(find_version_root(real_bin).resolve())
        nb = locate_instr_binary(real_bin, instr)
        if nb != real_bin:
            print(f"  [{label}] using instrumented version: {nb}")
            work = nb
            seq = capture_function_trace(mk(input_file))
    return real_bin, mk, mk_lldb, seq, work


def capture_side_values(mk_lldb, work_or_real, input_file, key_funcs, label, max_events):
    """Do lldb value capture on one side's binary (with LD_LIBRARY_PATH)"""
    cmd, env_note = mk_lldb(input_file)
    old_env = os.environ.copy()
    os.environ.update(env_note)
    try:
        print(f"  [{label}] ...")
        return capture_values(work_or_real, cmd[1:], key_funcs, max_events=max_events)
    finally:
        os.environ.clear(); os.environ.update(old_env)


def main():
    ap = argparse.ArgumentParser(
        description="Execution trace divergence comparison: two inputs in the same version, or two versions with the same input")
    ap.add_argument("--binary", help="[mode 1] path of the program under test (two inputs in the same version)")
    ap.add_argument("--input-a", help="[mode 1] input file A")
    ap.add_argument("--input-b", help="[mode 1] input file B")
    ap.add_argument("--binary-a", help="[mode 2] program path of version A (same input)")
    ap.add_argument("--binary-b", help="[mode 2] program path of version B (same input)")
    ap.add_argument("--input", help="[mode 2] input file (same input, comparing two versions)")
    ap.add_argument("--args", default="{input}", help="argument template, {input} is the input placeholder")
    ap.add_argument("--max-events", type=int, default=20000)
    ap.add_argument("--skip-values", action="store_true",
                    help="only compare function call sequences, no variable value capture (no lldb needed)")
    ap.add_argument("-o", "--output", default="results/trace_diff_result.json")
    args = ap.parse_args()

    cross = bool(args.binary_a and args.binary_b)

    if cross:
        if not args.input:
            sys.exit("mode 2 requires --input to specify the input file")
        bin_a, bin_b = args.binary_a, args.binary_b
        input_a, input_b = args.input, args.input
        label_a, label_b = "version A", "version B"
    else:
        if not (args.binary and args.input_a and args.input_b):
            sys.exit("mode 1 requires --binary --input-a --input-b (or mode 2: --binary-a --binary-b --input)")
        bin_a = bin_b = args.binary
        input_a, input_b = args.input_a, args.input_b
        label_a, label_b = "input A", "input B"

    print("=" * 64)
    print("step 1: capture two function call traces")
    print("=" * 64)
    if cross:
        real_a, mk_a, mk_lldb_a, seq_a, work_a = capture_side(
            bin_a, args.args, input_a, label_a)
        real_b, mk_b, mk_lldb_b, seq_b, work_b = capture_side(
            bin_b, args.args, input_b, label_b)
    else:
        real_a, mk_a, mk_lldb_a, seq_a, work_a = capture_side(
            bin_a, args.args, input_a, label_a)
        real_b, mk_b, mk_lldb_b, seq_b, work_b = capture_side(
            bin_b, args.args, input_b, label_b)

    print()
    print("=" * 64)
    print("step 2: divergence point analysis (matching by function name)")
    print("=" * 64)
    points = find_divergence_points(seq_a, seq_b)
    if not points:
        print("  the two traces are identical, no divergence points")
        return
    print(f"  found {len(points)} divergence points\n")

    key_funcs = []
    for p in points:
        f = p["after_function"]
        if f != "(program entry)" and f not in key_funcs:
            key_funcs.append(f)

    print("=" * 64)
    print("step 3: variable value capture for the common function before divergence (lldb)")
    print("=" * 64)
    rec_a, rec_b = {}, {}
    if args.skip_values:
        print("  value capture skipped (--skip-values)")
    elif not key_funcs:
        print("  no common function before divergence, no value capture needed")
    else:
        print(f"  target functions: {key_funcs}")
        wa = work_a if work_a else real_a
        wb = work_b if work_b else real_b
        rec_a = capture_side_values(mk_lldb_a, wa, input_a, key_funcs,
                                    label_a, args.max_events)
        rec_b = capture_side_values(mk_lldb_b, wb, input_b, key_funcs,
                                    label_b, args.max_events)

    # ---- output each divergence point ----
    print()
    print("#" * 64)
    print("# key divergence point report")
    print("#" * 64)
    for n, p in enumerate(points, 1):
        f = p["after_function"]
        print(f"\n◆ divergence point #{n}: paths differ after function [{f}]")
        occ = p["occurrence"]
        if f != "(program entry)":
            ia, ib = occ.get("inputA", 0), occ.get("inputB", 0)
            print(f"  this function is the {ia} / {ib}th call in the two traces")
            ra = rec_a.get(f, [{}])[ia - 1] if ia and ia <= len(rec_a.get(f, [])) else None
            rb = rec_b.get(f, [{}])[ib - 1] if ib and ib <= len(rec_b.get(f, [])) else None
            if ra or rb:
                def fmt(rec):
                    if not rec:
                        return "(not captured)"
                    s = ", ".join(f"{k}={v}" for k, v in rec.get("args", {}).items()) or "(no args)"
                    ret = rec.get("return_value(rax)", "not captured")
                    return f"({s}) -> {ret}"
                fa, fb = fmt(ra), fmt(rb)
                same = ra and rb and _args_equal(ra.get("args"), rb.get("args"))
                print(f"  {label_a} this call: {fa}")
                print(f"  {label_b} this call: {fb}")
                if same is False:
                    diff_keys = [k for k in set((ra.get("args") or {})) | set((rb.get("args") or {}))
                                 if _vc((ra.get("args") or {}).get(k)) != _vc((rb.get("args") or {}).get(k))]
                    for k in diff_keys[:5]:
                        va = (ra.get("args") or {}).get(k, "<none>")
                        vb = (rb.get("args") or {}).get(k, "<none>")
                        mark = "" if (_vc(va) != ("addr",) and _vc(vb) != ("addr",)) \
                               else "   (address-like, only category comparable under ASLR)"
                        print(f"    variable diff: {k}: A={va}  B={vb}{mark}")
            else:
                print(f"  (failed to capture args/return value of this function)")
        ga, gb = p["gap_inputA"], p["gap_inputB"]
        show = lambda g: " -> ".join(g[:8]) + (" ..." if len(g) > 8 else "") or "(none)"
        print(f"  after {label_a}: {show(ga)}")
        print(f"  after {label_b}: {show(gb)}")

    out = Path(args.output)
    out.parent.mkdir(parents=True, exist_ok=True)
    meta = ({"binary_a": bin_a, "binary_b": bin_b, "input": args.input}
            if cross else
            {"binary": bin_a, "input_a": input_a, "input_b": input_b})
    with open(out, 'w', encoding='utf-8') as fp:
        json.dump({**meta, "trace_A": seq_a, "trace_B": seq_b,
                   "divergence_points": points}, fp,
                  indent=2, ensure_ascii=False)
    print(f"\nfull report saved: {out}")

if __name__ == "__main__":
    main()
