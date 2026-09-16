#!/usr/bin/env python3
"""Timing utility for the fork-point analysis pipeline.

The clock starts when the compilation step finishes (stage_timing.init is
called by run_fork_analysis.py right after the build).  Every later stage
appends its cumulative elapsed time (and optional duration) to a JSON file
and prints a ``[时间]`` line.  The JSON path comes from the RETRO_TIMINGS
environment variable (exported by run_analysis.sh).
"""

import json
import os
import time
from pathlib import Path


def timings_path() -> Path:
    return Path(os.environ.get("RETRO_TIMINGS", "results/timings.json"))


def _load() -> dict:
    p = timings_path()
    if p.exists():
        try:
            return json.loads(p.read_text())
        except (json.JSONDecodeError, OSError):
            pass
    return {"t0": time.time(), "stages": []}


def _save(data: dict):
    p = timings_path()
    p.parent.mkdir(parents=True, exist_ok=True)
    p.write_text(json.dumps(data, indent=2))


def init():
    """Reset the clock. Called right after compilation completes."""
    data = {"t0": time.time(), "stages": []}
    _save(data)
    print("[时间] 编译完成，计时开始 (t0)")
    return data["t0"]


def record(stage, duration=None):
    """Append a stage entry, print it, and return the cumulative elapsed."""
    data = _load()
    t = time.time()
    elapsed = t - data["t0"]
    entry = {"stage": stage, "elapsed": round(elapsed, 3)}
    if duration is not None:
        entry["duration"] = round(duration, 3)
    data["stages"].append(entry)
    _save(data)
    dur = f" 用时 {duration:.3f}s" if duration is not None else ""
    print(f"[时间] {stage}: 编译后累计 {elapsed:.3f}s{dur}")
    return elapsed