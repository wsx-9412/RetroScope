#!/usr/bin/env python3
"""Runner for fork-point detection test cases.

Builds each synthetic test case, runs lcs_trace.py --trace-diverge, and
checks whether the reported fork statement matches the expected one.
"""
import json
import os
import subprocess
import sys
from pathlib import Path

BASE = Path(__file__).resolve().parent
OUT = "/tmp/fork_test_result"

# Each test case: (name, v1_src, v2_src, input_content, args_template,
#                  include_exits, expected_function, expected_cond_v1, expected_cond_v2)
TEST_CASES = [
    {
        "name": "tc1_if_condition",
        "v1": "tc1_v1", "v2": "tc1_v2",
        "input": "15",
        "args": "{input}",
        "include_exits": False,
        "expect_func": "main",
        "expect_v1": "x > 10",   # binary-a = v1
        "expect_v2": "x > 20",   # binary-b = v2
    },
    {
        "name": "tc2_nested_function",
        "v1": "tc2_v1", "v2": "tc2_v2",
        "input": "6",
        "args": "{input}",
        "include_exits": False,
        "expect_func": "worker",
        "expect_v1": "n > 5",
        "expect_v2": "n > 8",
    },
    {
        "name": "tc3_loop_bound",
        "v1": "tc3_v1", "v2": "tc3_v2",
        "input": "0",
        "args": "{input}",
        "include_exits": True,
        "expect_func": "main",
        "expect_v1": "i < 5",
        "expect_v2": "i < 3",
    },
    {
        "name": "tc4_else_if",
        "v1": "tc4_v1", "v2": "tc4_v2",
        "input": "2",
        "args": "{input}",
        "include_exits": False,
        "expect_func": "main",
        "expect_v1": "mode == 2",
        "expect_v2": "mode == 3",
    },
]


def build(tc):
    for ver in ("v1", "v2"):
        d = BASE / "fork_tests" / tc[ver]
        src = d / "test.c"
        binpath = d / "test"
        r = subprocess.run(
            ["gcc", "-O0", "-g", "-finstrument-functions", "-rdynamic",
             "-o", str(binpath), str(src)],
            capture_output=True, text=True)
        if r.returncode != 0:
            print(f"  [BUILD FAIL] {tc['name']} {ver}: {r.stderr.strip()[:200]}")
            return False
    return True


def run_case(tc):
    inp = BASE / "fork_tests" / f"input_{tc['name']}.txt"
    inp.write_text(tc["input"])
    cmd = [
        sys.executable, str(BASE / "lcs_trace.py"),
        "--binary-a", str(BASE / "fork_tests" / tc["v1"] / "test"),
        "--binary-b", str(BASE / "fork_tests" / tc["v2"] / "test"),
        "--input", str(inp),
        "--args", tc["args"],
        "--trace-diverge",
        "--gdb-timeout", "120",
        "-o", OUT,
    ]
    if tc["include_exits"]:
        cmd.insert(4, "--include-exits")
    subprocess.run(cmd, capture_output=True, text=True, cwd=BASE)

    div_path = OUT + ".diverge.json"
    if not os.path.exists(div_path):
        return None, "no diverge result"
    with open(div_path) as f:
        d = json.load(f)
    return d, None


def check(tc, d):
    if not d:
        return False, "no result"
    func = d.get("root_cause_function")
    stmt_a = d.get("root_cause_statement_a", "") or ""
    stmt_b = d.get("root_cause_statement_b", "") or ""

    if tc["expect_func"] and func != tc["expect_func"]:
        return False, f"function={func} (expected {tc['expect_func']})"
    if tc["expect_v1"] and tc["expect_v1"] not in stmt_a:
        return False, f"v1 stmt='{stmt_a}' (missing '{tc['expect_v1']}')"
    if tc["expect_v2"] and tc["expect_v2"] not in stmt_b:
        return False, f"v2 stmt='{stmt_b}' (missing '{tc['expect_v2']}')"
    return True, f"{stmt_b}  vs  {stmt_a}"


def main():
    print("=" * 70)
    print("Fork-point detection test results")
    print("=" * 70)
    npass = 0
    for tc in TEST_CASES:
        print(f"\n[{tc['name']}]")
        if not build(tc):
            continue
        d, err = run_case(tc)
        if err:
            print(f"  FAIL: {err}")
            continue
        ok, msg = check(tc, d)
        if ok:
            npass += 1
            print(f"  PASS  {msg}")
        else:
            print(f"  FAIL  {msg}")
    print("\n" + "=" * 70)
    print(f"{npass}/{len(TEST_CASES)} test cases passed")
    print("=" * 70)


if __name__ == "__main__":
    main()
