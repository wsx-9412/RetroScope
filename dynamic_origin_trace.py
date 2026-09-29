#!/usr/bin/env python3
"""dynamic_origin_trace.py - dynamic backward origin tracing of fork variables.

Prototype: given a fork statement (file:line) and a set of fork variables, run
the target binary under GDB with full execution recording, stop at the fork,
then walk *backwards* instruction by instruction to discover where each
variable value came from.  The walk terminates when a value's storage address
falls inside a buffer that was filled by a read()/pread64() of the input file
- that read buffer gives an exact input-file offset.  Constants and function
call boundaries (return values) are reported explicitly.

This is a true dynamic reverse trace (record/replay), not value-pattern
matching:

    fork variable -> last write (reverse-stepi + value diff)
                  -> source operands (registers / memory / immediates)
                  -> ... recurse ...
                  -> input read buffer -> (file offset, length)

Usage (standalone):
    python3 dynamic_origin_trace.py \
        --binary /path/to/target_bin \
        --input in/CVE-xxxx \
        --args "-i {input} /tmp/foo" \
        --fork-spec libtiff/tif_dirread.c:5433 \
        --variables err --variables tif \
        --output results/CVE-xxxx_origin.json

Usage (from a divergence result):
    python3 dynamic_origin_trace.py --diverge-json results/CVE-xxxx.diverge.json

Notes / limitations
-------------------
* GDB "record full" cannot replay some AVX instructions found in glibc's
  ifunc dispatchers.  The driver therefore disables AVX dispatch through
  GLIBC_TUNABLES by default (--glibc-avx-off).  rr would be preferable but
  requires kernel.perf_event_paranoid <= 1 (this is checked and reported).
* Works best on -O0 builds (the fork pipeline builds with -g/-O0).
* Hardware/software watchpoints are not used: reverse stepping + value diff
  is uniform for memory and registers and does not suffer GDB's unsupported
  "watchpoints during reverse execution" limitation.
* Function-return boundaries are followed one callee at a time (bounded by
  --max-depth); calls into uninstrumented libraries without debug info end
  the trace with an explicit boundary event.
"""

import argparse
import json
import os
import shutil
import subprocess
import sys
import tempfile
import time
from pathlib import Path

BASE = Path(__file__).resolve().parent

# --------------------------------------------------------------------------- #
# GDB-side script (executed inside gdb -x).  Reads DYNT_CFG (input JSON),
# writes DYNT_OUT (result JSON).  All the tracing logic lives here because it
# needs the live inferior.
# --------------------------------------------------------------------------- #
GDB_SCRIPT = r'''
import gdb
import json
import os
import re
import sys
import time

CFG = json.load(open(os.environ["DYNT_CFG"]))
OUT = os.environ["DYNT_OUT"]
DEADLINE = time.time() + float(CFG.get("timeout", 900))

result = {
    "status": "running",
    "error": None,
    "fork": {"spec": None, "pc": None},
    "variables": [],
    "reads": [],
    "events": [],
    "offsets": [],
    "stats": {},
}

def save():
    try:
        with open(OUT + ".tmp", "w") as f:
            json.dump(result, f, indent=1, default=str)
        os.replace(OUT + ".tmp", OUT)
    except Exception:
        pass

MASK = (1 << 64) - 1

def uval(expr):
    return int(gdb.parse_and_eval(expr)) & MASK

def sval(expr):
    v = uval(expr)
    return v - (1 << 64) if v >> 63 else v

def read_mem(addr, size):
    return bytes(gdb.selected_inferior().read_memory(addr, size))

def safe_read(addr, size):
    try:
        return read_mem(addr, size)
    except Exception:
        return None

def reg_value(name):
    try:
        return int(gdb.parse_and_eval("$" + name)) & 0xFFFFFFFFFFFFFFFF
    except Exception:
        return None

def cur_pc():
    return int(gdb.parse_and_eval("$pc"))

def disas(pc):
    try:
        frame = gdb.selected_frame()
        d = frame.architecture().disassemble(pc, count=1)
        if d:
            return d[0]
    except Exception:
        pass
    return None

def func_name(pc):
    try:
        out = gdb.execute("info symbol %d" % pc, to_string=True).strip()
        return out.split(" in section")[0].strip()
    except Exception:
        return "?"

def fd_path(fd):
    try:
        pid = gdb.selected_inferior().pid
        return os.readlink("/proc/%d/fd/%d" % (pid, fd))
    except Exception:
        return None

def fd_pos(fd):
    try:
        pid = gdb.selected_inferior().pid
        with open("/proc/%d/fdinfo/%d" % (pid, fd)) as f:
            for line in f:
                if line.startswith("pos:"):
                    return int(line.split()[1])
    except Exception:
        pass
    return None

# --------------------------------------------------------------------------- #
# read()/pread64() logging: a python breakpoint that logs and never stops.
# --------------------------------------------------------------------------- #
class ReadLogger(gdb.Breakpoint):
    def __init__(self, name, kind):
        super(ReadLogger, self).__init__(name, internal=True)
        self.kind = kind
        self.silent = True

    def stop(self):
        try:
            fd = uval("$rdi")
            buf = uval("$rsi")
            size = uval("$rdx")
            if fd < 3 or size <= 0 or size > (1 << 27):
                return False
            if self.kind == "pread64":
                off = uval("$r10")
            else:
                off = fd_pos(fd)
            result["reads"].append({
                "kind": self.kind,
                "fd": fd,
                "buf": buf,
                "size": size,
                "file_offset": off,
                "file": fd_path(fd),
                "seq": len(result["reads"]),
            })
            save()
        except Exception:
            pass
        return False

# --------------------------------------------------------------------------- #
# record full cannot record some newer syscalls (e.g. getrandom, 318).  The
# tracer forces getrandom callers to take an early return with a success code;
# the returned bytes are not observable through the traced value chain.
# --------------------------------------------------------------------------- #
class GetrandomSkipper(gdb.Breakpoint):
    def __init__(self):
        super(GetrandomSkipper, self).__init__("getrandom", internal=True)
        self.silent = True

    def stop(self):
        try:
            gdb.execute("return (long)8", to_string=True)
        except Exception:
            pass
        return False

# --------------------------------------------------------------------------- #
# Instruction parsing (Intel syntax)
# --------------------------------------------------------------------------- #
MEM_RE = re.compile(r"\[([^\]]+)\]")
REG_RE = re.compile(r"^(?:r[a-z0-9]+|e[a-z0-9]+|[abcd][lhx]|r[0-9]+d?|[sd]il?|[sb]pl?)$")
SIZE_PREFIX = {
    "byte": 1, "word": 2, "dword": 4, "qword": 8,
    "xmmword": 16, "ymmword": 32, "zmmword": 64,
}
COND_JUMPS = frozenset([
    "je", "jz", "jne", "jnz", "jg", "jnle", "jge", "jnl", "jl", "jnge",
    "jle", "jng", "ja", "jnbe", "jae", "jnb", "jb", "jnae", "jbe", "jna",
])

def split_insn(asm):
    asm = asm.strip()
    if not asm:
        return "", []
    if asm.startswith("rep "):
        parts = asm.split(None, 2)
        return "rep " + (parts[1] if len(parts) > 1 else ""), []
    if " " in asm:
        mnem, rest = asm.split(None, 1)
    else:
        return asm, []
    # split operands on commas outside brackets/braces
    ops, depth, cur = [], 0, ""
    for ch in rest:
        if ch in "[{(":
            depth += 1
        elif ch in "]})":
            depth -= 1
        if ch == "," and depth == 0:
            ops.append(cur.strip()); cur = ""
        else:
            cur += ch
    if cur.strip():
        ops.append(cur.strip())
    return mnem.lower(), ops

def mem_size(op):
    low = op.lower()
    for k, v in SIZE_PREFIX.items():
        if k in low:
            return v
    return None

def eff_addr(expr, next_pc):
    expr = expr.replace(" ", "")
    expr = expr.replace("rip", str(next_pc))
    total = 0
    for sign, term in re.findall(r"([+-]?)([^+-]+)", expr):
        if not term:
            continue
        s = -1 if sign == "-" else 1
        if "*" in term:
            base, scale = term.split("*", 1)
            v = reg_value(base)
            if v is None:
                return None
            total += s * v * int(scale, 0)
        elif re.match(r"^0x[0-9a-fA-F]+$", term) or re.match(r"^-?\d+$", term):
            total += s * int(term, 0)
        else:
            v = reg_value(term)
            if v is None:
                return None
            total += s * v
    return total & 0xFFFFFFFFFFFFFFFF

def parse_operand(op, next_pc):
    op = op.strip()
    m = MEM_RE.search(op)
    if m:
        addr = eff_addr(m.group(1), next_pc)
        if addr is None:
            return ("other", op)
        return ("mem", addr, mem_size(op) or 8)
    low = op.lower()
    if low.startswith("0x") or re.match(r"^-?\d+$", op):
        try:
            return ("imm", int(op, 0))
        except ValueError:
            return ("other", op)
    if REG_RE.match(low):
        return ("reg", low)
    return ("other", op)

# --------------------------------------------------------------------------- #
# Backward scan primitives
# --------------------------------------------------------------------------- #
MAX_STEPS = int(CFG.get("max_steps", 20000))
MAX_DEPTH = int(CFG.get("max_depth", 8))
segments = []          # path stack for readable parent links
next_id = [0]
anchor_pc = [None]
visited = set()
stats = {"reverse_steps": 0, "writes": 0, "terminals": 0}

def add_event(parent, kind, **kw):
    e = {"id": next_id[0], "parent": parent, "kind": kind}
    e.update(kw)
    result["events"].append(e)
    next_id[0] += 1
    save()
    return e["id"]

def trace_path(eid):
    path = []
    by_id = {e["id"]: e for e in result["events"]}
    while eid is not None:
        e = by_id.get(eid)
        if e is None:
            break
        path.append(e)
        eid = e.get("parent")
    return list(reversed(path))

def record_offset(offset, length, eid, via, file=None):
    result["offsets"].append({
        "offset": offset, "length": length,
        "via": via, "file": file, "event": eid,
        "path": [("%s" % e["kind"]) for e in trace_path(eid)],
    })
    stats["terminals"] += 1

def terminal_for_mem(addr, size):
    for r in reversed(result["reads"]):
        b = r.get("buf")
        if b is None or not (b <= addr < b + r["size"]):
            continue
        if r.get("file_offset") is None:
            return {"terminal": "input_unknown_offset", "read": r["seq"],
                    "via": r["kind"], "file": r.get("file")}
        off = r["file_offset"] + (addr - b)
        length = min(size, b + r["size"] - addr)
        return {"terminal": "input", "offset": off, "length": length,
                "via": r["kind"], "file": r.get("file")}
    return None

def goto_anchor():
    if anchor_pc[0] is None:
        return
    if cur_pc() == anchor_pc[0]:
        return
    try:
        gdb.execute("continue", to_string=True)
    except Exception:
        pass

def over_deadline():
    return time.time() > DEADLINE

def scan_mem(addr, size, parent, depth, delta=0):
    key = ("mem", addr, size)
    if key in visited:
        add_event(parent, "visited", addr=hex(addr))
        return
    visited.add(key)
    if depth > MAX_DEPTH:
        add_event(parent, "depth_limit", addr=hex(addr))
        return
    if over_deadline():
        add_event(parent, "timeout", addr=hex(addr))
        return
    term = terminal_for_mem(addr, size)
    if term:
        add_event(parent, "input", addr=hex(addr), size=size, **term)
        record_offset(term.get("offset"), term.get("length", size), parent,
                      term.get("via", "read"), term.get("file"))
        return
    prev = safe_read(addr, size)
    if prev is None:
        add_event(parent, "unmapped", addr=hex(addr), size=size)
        return
    steps = 0
    while steps < MAX_STEPS:
        if over_deadline():
            add_event(parent, "timeout", addr=hex(addr))
            return
        try:
            gdb.execute("reverse-stepi", to_string=True)
        except Exception as e:
            add_event(parent, "record_start", addr=hex(addr), error=str(e)[:120])
            return
        stats["reverse_steps"] += 1
        steps += 1
        cur = safe_read(addr, size)
        if cur is None:
            add_event(parent, "unmapped", addr=hex(addr), size=size,
                      note="address not mapped earlier in the recording")
            return
        if cur != prev:
            changed = [i for i in range(size) if cur[i] != prev[i]]
            handle_write(("mem", addr, size), parent, depth,
                         value_before=cur, value_after=prev, changed=changed,
                         delta=delta)
            return
        prev = cur
    add_event(parent, "scan_limit", addr=hex(addr), steps=steps)

def scan_reg(reg, parent, depth, bound_pc=None, label=None, delta=0,
             stop_pcs=None):
    # key includes the pre-state PC: the same register is legitimately
    # re-traced at different times (e.g. the old value of an RMW dest).
    key = ("reg", reg, cur_pc(), label)
    if key in visited:
        add_event(parent, "visited", reg=reg)
        return
    visited.add(key)
    if depth > MAX_DEPTH:
        add_event(parent, "depth_limit", reg=reg)
        return
    prev = reg_value(reg)
    if prev is None:
        add_event(parent, "unknown_reg", reg=reg)
        return
    steps = 0
    while steps < MAX_STEPS:
        if over_deadline():
            add_event(parent, "timeout", reg=reg)
            return
        try:
            gdb.execute("reverse-stepi", to_string=True)
        except Exception as e:
            add_event(parent, "record_start", reg=reg, error=str(e)[:120])
            return
        stats["reverse_steps"] += 1
        steps += 1
        if (bound_pc is not None and cur_pc() == bound_pc) or \
                (stop_pcs and cur_pc() in stop_pcs):
            add_event(parent, "function_entry", reg=reg,
                      note="register value comes from the caller (parameter)")
            return
        cur = reg_value(reg)
        if cur is None:
            add_event(parent, "unknown_reg", reg=reg)
            return
        if cur != prev:
            handle_write(("reg", reg), parent, depth,
                         value_before=cur, value_after=prev, changed="all",
                         delta=delta)
            return
        prev = cur
    add_event(parent, "scan_limit", reg=reg, steps=steps)

# --------------------------------------------------------------------------- #
# Writer analysis
# --------------------------------------------------------------------------- #
def classify_sources(mnem, ops, slot, next_pc, parent, depth, eid):
    parsed = [parse_operand(o, next_pc) for o in ops]
    dest = parsed[0] if parsed else None
    srcs = parsed[1:] if len(parsed) > 1 else []
    rmw = mnem in ("add", "sub", "and", "or", "xor", "inc", "dec", "shl",
                   "shr", "sar", "sal", "imul", "not", "neg")
    if mnem == "lea":
        # dest = effective address; sources are the address registers
        if dest and dest[0] == "mem":
            return [("addr", dest[1])]
        return []
    if rmw and dest is not None:
        # dest also participates as input
        srcs = [dest] + srcs
    return srcs

def handle_write(slot, parent, depth, value_before=None, value_after=None,
                 changed=None, delta=0):
    pc = cur_pc()
    insn = disas(pc)
    asm = insn["asm"].strip() if insn else "?"
    length = insn["length"] if insn else 1
    def _fmt(v):
        if v is None:
            return None
        if isinstance(v, (bytes, bytearray)):
            return v.hex()
        if isinstance(v, int):
            return hex(v & MASK)
        return str(v)[:64]
    stats["writes"] += 1
    eid = add_event(parent, "write", pc=hex(pc), insn=asm,
                    func=func_name(pc), slot=("mem@%x+%d" % (slot[1], slot[2])
                                              if slot[0] == "mem" else slot[1]),
                    changed=changed,
                    value_before=_fmt(value_before),
                    value_after=_fmt(value_after))
    mnem, ops = split_insn(asm)

    if mnem.startswith("call"):
        target = None
        m = re.search(r"<([^>]+)>", asm)
        if m:
            target = m.group(1)
        add_event(eid, "call_boundary", callee=target,
                  note="value produced by a function return; "
                       "follow_returns=%s" % CFG.get("follow_returns", True))
        if CFG.get("follow_returns", True) and slot[0] == "reg" \
                and slot[1] in ("rax", "eax", "ax", "al") and depth < MAX_DEPTH:
            descend_call(eid, target, depth, delta)
        return

    if mnem in ("rep movsb", "rep movsw", "rep movsd", "rep movsq",
                "movs", "stos", "rep movs"):
        # rsi -> rdi, count rcx
        rdi, rsi, rcx = reg_value("rdi"), reg_value("rsi"), reg_value("rcx")
        if slot[0] == "mem" and rdi is not None and rsi is not None \
                and rcx is not None and rdi <= slot[1] < rdi + rcx:
            src = rsi + (slot[1] - rdi)
            add_event(eid, "memcpy_source", src=hex(src), size=slot[2],
                      note="string move rsi->rdi, rcx=%d" % rcx)
            t = terminal_for_mem(src, slot[2])
            if t:
                add_event(eid, "input", addr=hex(src), **t)
                record_offset(t.get("offset"), t.get("length", slot[2]),
                              eid, t.get("via", "read"), t.get("file"))
            else:
                scan_mem(src, slot[2], eid, depth + 1)
        else:
            add_event(eid, "unknown_movs", operands=ops)
        return

    multiple = mnem.startswith("mul") or mnem in ("cdq", "cqo", "cdqe", "cwde")
    if multiple:
        add_event(eid, "arithmetic_implicit",
                  note="implicit register arithmetic (rdx:rax); "
                       "value is a computed combination")
        if slot[0] == "reg":
            for r in ("rax", "rdx"):
                if r != slot[1]:
                    scan_reg(r, eid, depth + 1, delta=delta)
            scan_reg(slot[1], eid, depth + 1, delta=delta)
        return

    next_pc_addr = (pc + length) & 0xFFFFFFFFFFFFFFFF
    srcs = classify_sources(mnem, ops, slot, next_pc_addr, eid, depth, eid)
    if delta and slot[0] == "reg":
        add_event(eid, "delta_note", delta=delta,
                  note="byte position inside the register/window carried "
                       "through this write")
    for s in srcs:
        if s[0] == "imm":
            add_event(eid, "constant", value=hex(s[1] & MASK))
        elif s[0] == "mem":
            addr = (s[1] + delta) & 0xFFFFFFFFFFFFFFFF
            wsize = s[2] or 8
            size = max(1, wsize - delta) if delta < wsize else 1
            t = terminal_for_mem(addr, size)
            if t:
                add_event(eid, "input", addr=hex(addr), size=size, **t)
                record_offset(t.get("offset"), t.get("length", size), eid,
                              t.get("via", "read"), t.get("file"))
            else:
                scan_mem(addr, size, eid, depth + 1)
        elif s[0] == "addr":
            # lea: address computation; trace index/base registers
            expr = MEM_RE.search(asm)
            if expr:
                for reg in re.findall(r"[a-z][a-z0-9]+", expr.group(1)):
                    if reg in ("rbp", "rsp", "rip"):
                        continue
                    if reg_value(reg) is not None:
                        scan_reg(reg, eid, depth + 1)
        elif s[0] == "reg":
            if s[1] in ("rbp", "rsp", "rip"):
                add_event(eid, "frame_register", reg=s[1])
            else:
                scan_reg(s[1], eid, depth + 1, delta=delta)
        else:
            add_event(eid, "unknown_operand", operand=s[1])

def descend_call(parent_eid, target, depth, delta=0):
    """Follow a call's return value: enter the callee, run to its return, then
    reverse-scan the return register (rax) inside the callee."""
    call_pc = cur_pc()
    try:
        gdb.execute("stepi", to_string=True)     # enter callee
        entry = cur_pc()
        gdb.execute("finish", to_string=True)    # run to return
        add_event(parent_eid, "callee_enter", callee=target, entry=hex(entry))
        scan_reg("rax", parent_eid, depth + 1, bound_pc=entry, delta=delta,
                 stop_pcs={entry, call_pc})
    except Exception as e:
        add_event(parent_eid, "call_boundary_unfollowed",
                  callee=target, error=str(e)[:200])
    finally:
        goto_anchor()

# --------------------------------------------------------------------------- #
# Setup: forward run with recording + read logging
# --------------------------------------------------------------------------- #
gdb.execute("set pagination off")
gdb.execute("set confirm off")
gdb.execute("set breakpoint pending on")
gdb.execute("set disassembly-flavor intel")
try:
    gdb.execute("set disable-randomization on")
except Exception:
    pass

try:
    gdb.execute("set args %s" % " ".join(
        '"%s"' % a.replace('"', '\\"') for a in CFG.get("args", [])))
except Exception:
    pass

try:
    gdb.execute("start")
except Exception as e:
    result["status"] = "error"
    result["error"] = "cannot start inferior: %s" % e
    save(); gdb.execute("quit"); sys.exit(0)

try:
    gdb.execute("record full")
except Exception as e:
    result["status"] = "error"
    result["error"] = ("record full unsupported: %s "
                       "(try --glibc-avx-off; rr needs perf_event_paranoid<=1)"
                       % e)
    save(); gdb.execute("quit"); sys.exit(0)

ReadLogger("read", "read")
ReadLogger("pread64", "pread64")
if CFG.get("skip_getrandom", True):
    try:
        GetrandomSkipper()
    except Exception:
        pass

fork_bp = None
for spec in CFG.get("fork_specs", []):
    try:
        fork_bp = gdb.Breakpoint(spec)
        result["fork"]["spec"] = spec
        break
    except Exception:
        continue
if fork_bp is None:
    result["status"] = "error"
    result["error"] = "no fork breakpoint could be created"
    save(); gdb.execute("quit"); sys.exit(0)

try:
    gdb.execute("continue")
except Exception as e:
    result["status"] = "error"
    result["error"] = "execution failed before the fork: %s" % e
    save(); gdb.execute("quit"); sys.exit(0)

anchor_pc[0] = cur_pc()
result["fork"]["pc"] = hex(anchor_pc[0])
save()

# capture variable slots at the fork
input_size = CFG.get("input_size")
for expr in CFG.get("variables", []):
    info = {"expr": expr, "addr": None, "size": None, "value": None,
            "type": None, "pointer": False}
    try:
        v = gdb.parse_and_eval(expr)
        t = v.type.strip_typedefs()
        info["type"] = str(t)
        info["size"] = int(t.sizeof)
        info["pointer"] = (t.code == gdb.TYPE_CODE_PTR)
        try:
            info["value"] = int(v) & MASK
        except Exception:
            pass
        if v.address is not None:
            info["addr"] = int(v.address)
        else:
            try:
                info["addr"] = int(gdb.parse_and_eval("(void*)&(%s)" % expr))
            except Exception:
                pass
    except Exception as e:
        info["error"] = str(e)[:200]
    result["variables"].append(info)
save()

# pointer-typed variables whose value already points into a read buffer
for info in result["variables"]:
    if info.get("value") is None or not info.get("pointer"):
        continue
    t = terminal_for_mem(info["value"], info.get("size") or 1)
    if t:
        eid = add_event(None, "input_pointer", expr=info["expr"],
                        value=hex(info["value"]), **t)
        record_offset(t.get("offset"), t.get("length", 1), eid,
                      t.get("via", "read"), t.get("file"))

# --------------------------------------------------------------------------- #
# Backward trace per variable
# --------------------------------------------------------------------------- #
for info in result["variables"]:
    root = add_event(None, "variable", expr=info["expr"], type=info.get("type"),
                     addr=hex(info["addr"]) if info.get("addr") else None,
                     size=info.get("size"),
                     value=hex(info["value"]) if info.get("value") is not None else None)
    if info.get("addr") is None or info.get("size") in (None, 0):
        add_event(root, "unsupported",
                  note="variable has no memory storage (register temporary?)")
        continue
    t = terminal_for_mem(info["addr"], info["size"])
    if t:
        add_event(root, "input", addr=hex(info["addr"]), size=info["size"], **t)
        record_offset(t.get("offset"), t.get("length", info["size"]), root,
                      t.get("via", "read"), t.get("file"))
        continue
    goto_anchor()
    scan_mem(info["addr"], info["size"], root, 0)
    goto_anchor()

stats["reads"] = len(result["reads"])
stats["events"] = len(result["events"])
result["stats"] = stats
result["status"] = "ok"
save()
gdb.execute("quit")
'''

# --------------------------------------------------------------------------- #
# Host side
# --------------------------------------------------------------------------- #

def load_diverge_json(path):
    with open(path) as f:
        raw = json.load(f)
    div = raw.get("divergence", raw)
    return div


def basename_candidates(div):
    """Build fork breakpoint specs from a divergence result."""
    cands = []
    pt = div.get("polytracker_offsets") or {}
    pairs = [
        (pt.get("source_file"), pt.get("source_line")),
        (div.get("root_cause_file_b"), div.get("root_cause_line_b")),
        (div.get("root_cause_file"), div.get("root_cause_line")),
        (div.get("root_cause_file_a"), div.get("root_cause_line_a")),
    ]
    for f, ln in pairs:
        if not f or not ln:
            continue
        f = str(f)
        # exact path, then path suffix, then basename
        cands.append("%s:%d" % (f, ln))
        cands.append("%s:%d" % (Path(f).name, ln))
    # dedupe preserving order
    seen, out = set(), []
    for c in cands:
        if c not in seen:
            seen.add(c)
            out.append(c)
    return out


def extract_variables(div):
    vs = div.get("variables") or []
    out = []
    for v in vs:
        if isinstance(v, str) and v and not v.startswith(("if ", "while ",
                                                          "for ", "return ")):
            out.append(v)
    if out:
        return out
    # fall back to the statement's identifiers
    import re
    stmt = (div.get("root_cause_statement_b")
            or div.get("fork_statement")
            or div.get("root_cause_statement_a") or "")
    toks = re.findall(r"[A-Za-z_][A-Za-z0-9_]*(?:\s*->\s*[A-Za-z_][A-Za-z0-9_]*)*",
                      stmt)
    black = {"if", "while", "for", "return", "sizeof", "NULL", "else"}
    return [t for t in toks if t not in black][:6]


def build_args(template, input_file):
    if isinstance(template, (list, tuple)):
        args = [str(a) for a in template]
    else:
        args = str(template).split()
    return [a.replace("{input}", str(input_file))
             .replace("{input_file}", str(input_file)) for a in args]


def main():
    ap = argparse.ArgumentParser(description=__doc__,
                                 formatter_class=argparse.RawDescriptionHelpFormatter)
    ap.add_argument("--diverge-json", help="divergence result JSON "
                    "(binary/args/fork/variables auto-filled)")
    ap.add_argument("--binary", help="target binary")
    ap.add_argument("--input", help="input file (PoC)")
    ap.add_argument("--args", default="", help="program args template, "
                    "{input} is replaced")
    ap.add_argument("--fork-spec", action="append", default=[],
                    help="fork breakpoint spec file:line (repeatable)")
    ap.add_argument("--variables", action="append", default=[],
                    help="fork variable expression (repeatable)")
    ap.add_argument("--output", default=None, help="result JSON path")
    ap.add_argument("--timeout", type=float, default=900,
                    help="overall tracing deadline (seconds)")
    ap.add_argument("--max-steps", type=int, default=20000,
                    help="max reverse instructions per slot")
    ap.add_argument("--max-depth", type=int, default=8)
    ap.add_argument("--no-follow-returns", action="store_true",
                    help="do not follow function return values")
    ap.add_argument("--glibc-avx-off", dest="avx_off", action="store_true",
                    default=True, help="disable glibc AVX dispatch so "
                    "record full can replay (default on)")
    ap.add_argument("--no-glibc-avx-off", dest="avx_off", action="store_false")
    ap.add_argument("--quiet", action="store_true")
    args = ap.parse_args()

    # merge divergence JSON
    div = {}
    if args.diverge_json:
        div = load_diverge_json(args.diverge_json)

    binary = args.binary or div.get("binary_b") or div.get("binary_a")
    input_file = args.input or div.get("input_file")
    if not binary or not input_file:
        ap.error("need --binary and --input (or --diverge-json with them)")
    if not os.path.isfile(binary):
        ap.error("binary not found: %s" % binary)
    input_file = os.path.abspath(input_file)

    arg_template = args.args or div.get("args_b") or div.get("args_a") or []
    prog_args = build_args(arg_template, input_file)

    fork_specs = list(args.fork_spec) + basename_candidates(div)
    if not fork_specs:
        ap.error("need --fork-spec (or --diverge-json with a fork location)")
    variables = list(args.variables) + extract_variables(div)
    if not variables:
        ap.error("need --variables (or --diverge-json with variables)")

    output = args.output or (input_file + ".origin.json"
                             if not args.diverge_json else
                             os.path.splitext(args.diverge_json)[0] + "_origin.json")

    # environment discipline: use the project's own libraries
    env = os.environ.copy()
    try:
        sys.path.insert(0, str(BASE))
        import trace_fork_offsets as tfo
        real_bin = str(tfo.resolve_binary(binary))
        env = tfo.build_run_env(real_bin)
    except Exception:
        real_bin = binary
    env["ASAN_OPTIONS"] = "detect_leaks=0:abort_on_error=0"
    if args.avx_off:
        prev = env.get("GLIBC_TUNABLES", "")
        env["GLIBC_TUNABLES"] = ((prev + ":") if prev else "") + \
            "glibc.cpu.hwcaps=-AVX2,-AVX,-AVX512F,-AVX512VL,-AVX_Fast_Unaligned_Load"

    cfg = {
        "binary": real_bin,
        "args": prog_args,
        "input": input_file,
        "input_size": os.path.getsize(input_file),
        "fork_specs": fork_specs,
        "variables": variables,
        "timeout": args.timeout,
        "max_steps": args.max_steps,
        "max_depth": args.max_depth,
        "follow_returns": not args.no_follow_returns,
    }

    tmpdir = tempfile.mkdtemp(prefix="dyn_origin_")
    cfg_path = os.path.join(tmpdir, "cfg.json")
    with open(cfg_path, "w") as f:
        json.dump(cfg, f, indent=1)

    script_path = os.path.join(tmpdir, "trace.py")
    with open(script_path, "w") as f:
        f.write(GDB_SCRIPT)

    gdb_out = os.path.join(tmpdir, "gdb.log")
    env["DYNT_CFG"] = cfg_path
    env["DYNT_OUT"] = output

    if not args.quiet:
        print("[*] binary    : %s" % real_bin)
        print("[*] input     : %s (%d bytes)" % (input_file, cfg["input_size"]))
        print("[*] args      : %s" % " ".join(prog_args))
        print("[*] fork specs: %s" % ", ".join(fork_specs[:4]))
        print("[*] variables : %s" % ", ".join(variables))
        print("[*] recording : gdb record full (rr unavailable: %s)" %
              ("perf_event_paranoid=%s" % read_paranoid()))

    t0 = time.time()
    try:
        with open(gdb_out, "w") as logf:
            subprocess.run(
                ["gdb", "-batch", "-nx", "-q", "-x", script_path, real_bin],
                env=env, stdout=logf, stderr=subprocess.STDOUT,
                timeout=args.timeout + 120)
    except subprocess.TimeoutExpired:
        print("[!] gdb timed out")
    elapsed = time.time() - t0

    if not os.path.isfile(output):
        print("[!] no result written; see %s" % gdb_out)
        return 2

    with open(output) as f:
        res = json.load(f)

    res["wall_seconds"] = round(elapsed, 2)
    res["_output"] = output
    with open(output, "w") as f:
        json.dump(res, f, indent=1, default=str)

    print_summary(res, gdb_out)
    return 0 if res.get("status") == "ok" else 1


def read_paranoid():
    try:
        with open("/proc/sys/kernel/perf_event_paranoid") as f:
            return f.read().strip()
    except Exception:
        return "?"


def print_summary(res, gdb_log):
    print("\n================ dynamic origin trace ================")
    print("status : %s%s" % (res.get("status"),
                             (" — " + str(res.get("error")))
                             if res.get("error") else ""))
    print("fork   : %s @ %s" % (res.get("fork", {}).get("spec"),
                               res.get("fork", {}).get("pc")))
    print("reads  : %d  events: %d  reverse-steps: %s  wall: %ss" % (
        len(res.get("reads") or []), len(res.get("events") or []),
        (res.get("stats") or {}).get("reverse_steps"), res.get("wall_seconds")))

    offsets = res.get("offsets") or []
    print("\ninput offsets (dynamic provenance):")
    if not offsets:
        print("  (none — see the event tree below)")
    for o in offsets:
        off = o.get("offset")
        print("  0x%-6s len=%-3s via=%-12s file=%s" % (
            ("%x" % off) if off is not None else "?", o.get("length"),
            o.get("via"), os.path.basename(str(o.get("file")))))

    print("\nevent tree (per variable):")
    events = res.get("events") or []
    children = {}
    for e in events:
        children.setdefault(e.get("parent"), []).append(e)
    def dump(eid, indent):
        for e in children.get(eid, []):
            kind = e.get("kind")
            extra = ""
            if kind == "write":
                extra = "%s  [%s]" % (e.get("insn"), e.get("func"))
            elif kind == "input":
                extra = "offset=0x%x len=%s via=%s" % (
                    e.get("offset") or 0, e.get("length"), e.get("via"))
            elif kind == "variable":
                extra = "%s = %s" % (e.get("expr"), e.get("value"))
            elif kind == "call_boundary":
                extra = "-> %s" % e.get("callee")
            print("  %s%s %s" % (" " * indent, kind, extra))
            dump(e.get("id"), indent + 2)
    dump(None, 2)
    print("\nfull result : %s" % res.get("_output", ""))
    print("gdb log     : %s" % gdb_log)


if __name__ == "__main__":
    sys.exit(main())
