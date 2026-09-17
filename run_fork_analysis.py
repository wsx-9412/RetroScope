#!/usr/bin/env python3
"""Integrated fork-point analysis: compile two versions, read the execution
config, and invoke lcs_trace.py to locate the fork statement.

Usage:
    python3 run_fork_analysis.py \
        --config config_libtiff.py \
        --ref  tiff-versions/tiff-4.4.0 \
        --target tiff-versions/tiff-4.0.8 \
        --input in/CVE-2022-3598 \
        --output /tmp/foo \
        [--include-exits] [--refactor-detect] [--gdb-timeout 300]

The config module must define:
    COMPILE_COMMANDS  -> {"reference": {...}, "target": {...}}
                         each with "pre_build" (list of shell commands) and
                         "compile_flags" (env vars).
    EXECUTION_CONFIG  -> {"program_name", "exec_subdir", "command_format"}
"""

import argparse
import importlib.util
import os
import shutil
import subprocess
import sys
import tempfile
from pathlib import Path

BASE = Path(__file__).resolve().parent


def load_config(config_path):
    spec = importlib.util.spec_from_file_location("proj_config", config_path)
    mod = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(mod)
    return mod


def _pre_build_compiles(compile_cfg: dict) -> bool:
    """Heuristic: does pre_build already perform the actual compilation?"""
    for cmd in compile_cfg.get("pre_build", []):
        s = cmd.lower()
        if "make" in s and "clean" not in s:
            return True
        if "configure" in s or "cmake" in s:
            return True
    return False


def run_build(src_dir: Path, version_name: str, compile_cfg: dict) -> bool:
    """Compile one version in place using the config's compile instructions."""
    env = os.environ.copy()
    env.update(compile_cfg.get("compile_flags", {}))
    nproc = str(os.cpu_count() or 2)

    pre_build_failed = False
    for cmd in compile_cfg.get("pre_build", []):
        print(f"  [{version_name}] pre_build: {cmd}")
        r = subprocess.run(cmd, shell=True, cwd=src_dir, capture_output=True,
                           text=True, env=env)
        if r.returncode != 0:
            print(f"  [{version_name}] pre_build FAILED: {r.stderr[-400:]}")
            pre_build_failed = True

    # If pre_build already compiled (e.g. lame/audiofile), skip the generic build.
    if _pre_build_compiles(compile_cfg):
        if pre_build_failed:
            print(f"  [{version_name}] pre_build reported errors.")
        return not pre_build_failed

    # autotools
    if (src_dir / "configure").exists():
        print(f"  [{version_name}] ./configure")
        r = subprocess.run(["sh", "./configure"], cwd=src_dir,
                           capture_output=True, text=True, env=env)
        if r.returncode != 0:
            print(f"  [{version_name}] configure failed: {r.stderr[-600:]}")
            return False
        print(f"  [{version_name}] make -j{nproc}")
        r = subprocess.run(["make", "-j", nproc], cwd=src_dir,
                           capture_output=True, text=True, env=env)
        if r.returncode != 0:
            print(f"  [{version_name}] make failed: {r.stderr[-600:]}")
            return False
        return True

    # cmake
    if (src_dir / "CMakeLists.txt").exists():
        bld = src_dir / "bld"
        bld.mkdir(exist_ok=True)
        print(f"  [{version_name}] cmake ..")
        r = subprocess.run(["cmake", "..", "-DCMAKE_BUILD_TYPE=Debug"],
                           cwd=bld, capture_output=True, text=True, env=env)
        if r.returncode != 0:
            print(f"  [{version_name}] cmake failed: {r.stderr[-600:]}")
            return False
        print(f"  [{version_name}] make -j{nproc}")
        r = subprocess.run(["make", "-j", nproc], cwd=bld,
                           capture_output=True, text=True, env=env)
        if r.returncode != 0:
            print(f"  [{version_name}] make failed: {r.stderr[-600:]}")
            return False
        return True

    print(f"  [{version_name}] no build system found (configure/CMakeLists.txt)")
    return False


def find_binary(build_dir: Path, exec_config: dict) -> Path:
    program = exec_config.get("program_name", "")
    subdir = exec_config.get("exec_subdir", "").lstrip("/")
    candidates = [
        build_dir / subdir / program,               # e.g. tools/tiffcrop (wrapper)
        build_dir / subdir / ".libs" / program,     # e.g. tools/.libs/tiffcrop
        build_dir / program,
    ]
    for c in candidates:
        if c.exists() and os.access(c, os.X_OK):
            return c
    for c in build_dir.rglob(program):
        if os.access(c, os.X_OK):
            return c
    return None


def has_function_instrumentation(binpath: Path) -> bool:
    """Return True if the binary was built with -finstrument-functions.

    The LCS trace relies on the ``__cyg_profile_func_enter`` hook (provided at
    runtime by functracer.so).  A binary rebuilt without this flag (e.g. by the
    PolyTracker wllvm build) produces an empty trace, so it must be recompiled.
    """
    try:
        out = subprocess.run(
            ["nm", str(binpath)], capture_output=True, text=True, timeout=60
        )
        return "__cyg_profile_func_enter" in out.stdout
    except Exception:
        return False


def build_args_template(exec_config: dict, output_file: str) -> str:
    """Convert command_format into an lcs_trace.py --args template."""
    fmt = exec_config.get("command_format", "")
    args = (fmt.replace("{program_path}", "")
               .replace("{input_file}", "{input}")
               .replace("{output_file}", str(output_file)))
    return " ".join(args.split())


def main():
    ap = argparse.ArgumentParser(description=__doc__)
    ap.add_argument("--config", required=True)
    ap.add_argument("--ref", required=True)
    ap.add_argument("--target", required=True)
    ap.add_argument("--input", required=True)
    ap.add_argument("--output", required=True)
    ap.add_argument("--gdb-timeout", type=int, default=300)
    ap.add_argument("--include-exits", action="store_true")
    ap.add_argument("--max-trace-size", type=int, default=50000)
    ap.add_argument("--refactor-detect", action="store_true")
    ap.add_argument("--rename-threshold", type=float, default=0.7)
    ap.add_argument("--no-compile", action="store_true",
                    help="skip compilation (binaries already built)")
    ap.add_argument("--no-polytracker", action="store_true",
                    help="skip polytracker inside divergence analysis (GDB-only mode)")
    args = ap.parse_args()

    config = load_config(args.config)
    compile_cmds = getattr(config, "COMPILE_COMMANDS", {})
    exec_config = getattr(config, "EXECUTION_CONFIG", {})

    ref_dir = Path(args.ref).resolve()
    tgt_dir = Path(args.target).resolve()

    # Heuristic: if binaries already exist in the version dirs, skip
    # recompilation (avoids producing different binaries in a temp tree).
    existing_ref = find_binary(ref_dir, exec_config)
    existing_tgt = find_binary(tgt_dir, exec_config)
    skip_compile = args.no_compile or (
        existing_ref is not None and existing_tgt is not None
        and has_function_instrumentation(existing_ref)
        and has_function_instrumentation(existing_tgt)
    )
    if not skip_compile and not args.no_compile:
        missing = []
        if existing_ref is not None and not has_function_instrumentation(existing_ref):
            missing.append("reference")
        if existing_tgt is not None and not has_function_instrumentation(existing_tgt):
            missing.append("target")
        if missing:
            print(f"Rebuilding (missing -finstrument-functions in: "
                  f"{', '.join(missing)}).")

    if not skip_compile:
        # Build in a fresh temp tree so the original version dirs stay intact.
        work = Path(tempfile.mkdtemp(prefix="fork_analysis_"))
        ref_build = work / "ref"
        tgt_build = work / "target"
        print(f"Copying reference -> {ref_build}")
        shutil.copytree(ref_dir, ref_build)
        print(f"Copying target -> {tgt_build}")
        shutil.copytree(tgt_dir, tgt_build)

        print(f"Compiling reference version ...")
        if not run_build(ref_build, "reference", compile_cmds.get("reference", {})):
            sys.exit(1)
        print(f"Compiling target version ...")
        if not run_build(tgt_build, "target", compile_cmds.get("target", {})):
            sys.exit(1)

        ref_bin = find_binary(ref_build, exec_config)
        tgt_bin = find_binary(tgt_build, exec_config)
    else:
        reason = "--no-compile" if args.no_compile else "binaries already exist"
        print(f"Skipping compilation ({reason}).")
        ref_bin = existing_ref
        tgt_bin = existing_tgt

    # Start the analysis clock after compilation finishes.
    import stage_timing
    stage_timing.init()

    if ref_bin is None or tgt_bin is None:
        print(f"ERROR: cannot locate binary. ref={ref_bin}, target={tgt_bin}")
        sys.exit(1)
    print(f"Reference binary: {ref_bin}")
    print(f"Target binary:    {tgt_bin}")

    # Read the program output file from config (not from --output which is for JSON result)
    program_output = exec_config.get("output_file", getattr(config, "OUTPUT_FILE", "/tmp/foo"))
    args_template = build_args_template(exec_config, program_output)
    print(f"Arguments template: {args_template}")

    cmd = [
        sys.executable, str(BASE / "lcs_trace.py"),
        "--binary-a", str(ref_bin),
        "--binary-b", str(tgt_bin),
        "--input", args.input,
        "--args", args_template,
        "--output", args.output,
        "--trace-diverge",
        "--gdb-timeout", str(args.gdb_timeout),
        "--config", str(Path(args.config).resolve()),
        # Version display labels: the binaries may live in a temp build
        # tree (compiled in place), so their paths carry no version name.
        "--ref-label", str(Path(args.ref).resolve().name),
        "--target-label", str(Path(args.target).resolve().name),
    ]
    
    # Pass --no-polytracker to skip polytracker inside divergence_analyzer
    if args.no_polytracker:
        cmd.append("--no-polytracker")
    
    if args.include_exits:
        cmd.append("--include-exits")
    cmd += ["--max-trace-size", str(args.max_trace_size)]
    if args.refactor_detect:
        cmd += ["--refactor-detect", "--rename-threshold", str(args.rename_threshold)]

    print("Running lcs_trace.py ...")
    subprocess.run(cmd)


if __name__ == "__main__":
    main()
