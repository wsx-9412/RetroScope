#!/usr/bin/env python3
"""Re-verify binutils CVE affected versions from poc_run_commands.md.

Tests each PoC against every available binutils version with
allocator_may_return_null=1 so ASan OOM is not misclassified as a crash.
"""
import os
import re
import subprocess
import sys
from pathlib import Path

BASE = Path("/home/ws/Desktop/RetroScope")
ENV = dict(os.environ,
           ASAN_OPTIONS="detect_leaks=0:allocator_may_return_null=1")
TIMEOUT = 20

VERSIONS = sorted(
    [p.parent.parent.name.replace("binutils-", "")
     for p in BASE.glob("binutils-versions/binutils-*/build-asan/binutils")],
    key=lambda v: [int(x) for x in re.findall(r"\d+", v)]
)

# Parse poc_run_commands.md for binutils entries
entries = []
for line in (BASE / "poc_run_commands.md").read_text().splitlines():
    m = re.match(
        r"(CVE-\S+)\s+\*?\s*([\d.,\- ]+?)\s+"
        r"(readelf|objdump|nm-new|strip-new|size|objcopy|addr2line)\s+"
        r"(-\S+(?:\s+-\S+)?)\s+in/\1",
        line)
    if m:
        entries.append({
            "cve": m.group(1),
            "claimed": m.group(2).strip(),
            "tool": m.group(3),
            "args": m.group(4).split(),
            "input": str(BASE / "in" / m.group(1)),
        })

def test(cve_entry, version):
    tool = BASE / f"binutils-versions/binutils-{version}/build-asan/binutils" / cve_entry["tool"]
    if not tool.exists():
        return "missing"
    cmd = [str(tool)] + cve_entry["args"] + [cve_entry["input"]]
    try:
        p = subprocess.run(cmd, env=ENV, timeout=TIMEOUT,
                           stdout=subprocess.DEVNULL, stderr=subprocess.PIPE)
        err = p.stderr.decode("utf-8", "replace")
        if "ERROR: AddressSanitizer:" in err and "out of memory" not in err:
            return "crash"
        if "ERROR: AddressSanitizer:" in err:
            return "oom"  # shouldn't happen with allocator_may_return_null
        return "ok"
    except subprocess.TimeoutExpired:
        return "timeout"
    except Exception:
        return "error"

def main():
    out_path = BASE / "results" / "binutils_version_reverify.tsv"
    out_path.parent.mkdir(exist_ok=True)
    results = {}
    with open(out_path, "w") as f:
        f.write("cve\tversion\tresult\n")
        for e in entries:
            cve = e["cve"]
            results[cve] = {}
            for v in VERSIONS:
                r = test(e, v)
                results[cve][v] = r
                f.write(f"{cve}\t{v}\t{r}\n")
                f.flush()
            crashed = [v for v, r in results[cve].items() if r == "crash"]
            oom = [v for v, r in results[cve].items() if r == "oom"]
            print(f"{cve}: crash={crashed or '-'} oom={oom or '-'}", flush=True)
    # Summary: actual crash versions vs claimed
    print("\n=== SUMMARY ===", flush=True)
    for e in entries:
        cve = e["cve"]
        crashed = [v for v, r in results.get(cve, {}).items() if r == "crash"]
        print(f"{cve}\n  claimed: {e['claimed']}\n  actual:  {crashed or 'NONE'}", flush=True)

if __name__ == "__main__":
    main()
