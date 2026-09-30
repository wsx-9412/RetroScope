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
* GDB "record full" cannot replay some instructions (AVX in glibc's ifunc
  dispatchers, rdtscp, some loader instructions).  The driver disables AVX
  dispatch and the AVX_Fast_Unaligned_Load preference via GLIBC_TUNABLES and
  skips getrandom; LD_BIND_NOW avoids the lazy PLT resolver.  ASan builds bring
  in additional unsupported instructions (rdtscp in the sanitizer runtime), so
  the origin trace is best run on a dedicated tracing build:
      ./configure CFLAGS="-g -O0 -Wno-error" LDFLAGS="" && make
  (the trace does not need ASan).
* rr would be the production engine (record once, replay with reverse
  watchpoints) but requires kernel.perf_event_paranoid <= 1; the driver
  reports the current value and falls back to record full.
* Hardware/software watchpoints are not used: reverse stepping + value diff
  is uniform for memory and registers and does not suffer GDB's unsupported
  "watchpoints during reverse execution" limitation.
* Function-return boundaries are followed one callee at a time (bounded by
  --max-depth); calls into uninstrumented libraries without debug info end
  the trace with an explicit boundary event.
* Multi-byte SIMD copies are handled via the "delta" carried from the stored
  destination window to the loaded source window, which keeps byte-exact
  offsets for the common vector copy patterns.
* The read-request lookback (--trace-read-request) is a heuristic bridge for
  control-side causes (e.g. an I/O error code set on a failed read); it is
  off by default because indirect calls through function pointers are not
  reliably attributed.

Validated (2026-09-29, this machine)
------------------------------------
* Synthetic read()-based demo: fork variable y traced back to byte loads from
  the read buffer, yielding exact input offsets 0x3 and 0x4
  (json: /tmp/opencode/forkdemo.origin.json).
* libtiff CVE-2023-30775 target fork (tif_dirread.c:5433, invocation 2):
  err=0x3 traced through TIFFReadDirEntryLong8Array -> TIFFReadDirEntryArray
  -> TIFFReadDirEntryData to the constant TIFFReadDirEntryErrIo (3), i.e. the
  I/O-failure assignment (json:
  results/CVE-2023-30775_tracebuild_origin.json, tracing build without ASan).
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
ENGINE = CFG.get("engine", "record")
DEADLINE = time.time() + float(CFG.get("timeout", 900))

result = {
    "status": "running",
    "error": None,
    "engine": ENGINE,
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

# fd state is tracked ourselves (open/lseek/close + read return values)
# because under rr replay /proc/<pid>/fdinfo describes the *replay* process,
# not the recorded program.
FD_POS = {}
FD_PATH = {}

def read_cstr(addr, maxlen=4096):
    try:
        data = gdb.selected_inferior().read_memory(addr, maxlen)
        return bytes(data).split(b"\0", 1)[0].decode("utf-8", "replace")
    except Exception:
        return None

def fd_path(fd):
    if fd in FD_PATH:
        return FD_PATH.get(fd)
    try:
        pid = gdb.selected_inferior().pid
        return os.readlink("/proc/%d/fd/%d" % (pid, fd))
    except Exception:
        return None

def fd_pos(fd):
    if fd in FD_POS:
        return FD_POS.get(fd)
    try:
        pid = gdb.selected_inferior().pid
        with open("/proc/%d/fdinfo/%d" % (pid, fd)) as f:
            for line in f:
                if line.startswith("pos:"):
                    return int(line.split()[1])
    except Exception:
        pass
    return None

class ReadFinish(gdb.FinishBreakpoint):
    """Advance the tracked fd position by the number of bytes read."""
    def __init__(self, fd):
        super(ReadFinish, self).__init__(internal=True)
        self.fd = fd

    def stop(self):
        try:
            n = int(self.return_value) & MASK
            if n < (1 << 63):
                FD_POS[self.fd] = FD_POS.get(self.fd, 0) + n
        except Exception:
            pass
        return False

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
                off = FD_POS.get(fd, 0)
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
            if self.kind == "read":
                ReadFinish(fd)
        except Exception:
            pass
        return False

class OpenFinish(gdb.FinishBreakpoint):
    def __init__(self, path):
        super(OpenFinish, self).__init__(internal=True)
        self.path = path

    def stop(self):
        try:
            fd = int(self.return_value) & MASK
            if fd >> 63:
                return False
            if fd < (1 << 20):
                FD_POS[fd] = 0
                if self.path:
                    FD_PATH[fd] = self.path
        except Exception:
            pass
        return False

class OpenLogger(gdb.Breakpoint):
    """Track fd -> path and initial offset 0 on open/openat."""
    def __init__(self, name, at):
        super(OpenLogger, self).__init__(name, internal=True)
        self.at = at
        self.silent = True

    def stop(self):
        try:
            path = read_cstr(uval("$rsi" if self.at else "$rdi"))
            OpenFinish(path)
        except Exception:
            pass
        return False

class LseekFinish(gdb.FinishBreakpoint):
    def __init__(self, fd):
        super(LseekFinish, self).__init__(internal=True)
        self.fd = fd

    def stop(self):
        try:
            r = int(self.return_value) & MASK
            if r < (1 << 63):
                FD_POS[self.fd] = r
        except Exception:
            pass
        return False

class LseekLogger(gdb.Breakpoint):
    def __init__(self, name):
        super(LseekLogger, self).__init__(name, internal=True)
        self.silent = True

    def stop(self):
        try:
            LseekFinish(uval("$rdi"))
        except Exception:
            pass
        return False

class CloseLogger(gdb.Breakpoint):
    def __init__(self):
        super(CloseLogger, self).__init__("close", internal=True)
        self.silent = True

    def stop(self):
        try:
            fd = uval("$rdi")
            FD_POS.pop(fd, None)
            FD_PATH.pop(fd, None)
        except Exception:
            pass
        return False

class MmapFinish(gdb.FinishBreakpoint):
    def __init__(self, fd, length, offset):
        super(MmapFinish, self).__init__(internal=True)
        self.fd = fd
        self.length = length
        self.offset = offset

    def stop(self):
        try:
            ret = int(self.return_value) & MASK
            if ret not in (0, MASK) and ret < (1 << 63):
                result["reads"].append({
                    "kind": "mmap", "fd": self.fd, "buf": ret,
                    "size": self.length, "file_offset": self.offset,
                    "file": fd_path(self.fd),
                    "seq": len(result["reads"]),
                })
                save()
        except Exception:
            pass
        return False

class MmapLogger(gdb.Breakpoint):
    """Log file mappings (input_file -> memory) so terminal mapping also works
    when the program mmaps the input instead of read()ing it (libtiff uses
    TIFFMapFileContents -> mmap for small files)."""
    def __init__(self, name):
        super(MmapLogger, self).__init__(name, internal=True)
        self.silent = True

    def stop(self):
        try:
            fd = uval("$r8")
            length = uval("$rsi")
            offset = uval("$r9")
            if fd >= 3 and 0 < length < (1 << 31):
                MmapFinish(fd, length, offset)
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
REG_FAMILY = {}
for _fam in (("rax", "eax", "ax", "al", "ah"),
             ("rbx", "ebx", "bx", "bl", "bh"),
             ("rcx", "ecx", "cx", "cl", "ch"),
             ("rdx", "edx", "dx", "dl", "dh"),
             ("rsi", "esi", "si", "sil"), ("rdi", "edi", "di", "dil"),
             ("rbp", "ebp", "bp", "bpl"), ("rsp", "esp", "sp", "spl"),
             ("r8", "r8d", "r8w", "r8b"), ("r9", "r9d", "r9w", "r9b"),
             ("r10", "r10d", "r10w", "r10b"), ("r11", "r11d", "r11w", "r11b"),
             ("r12", "r12d", "r12w", "r12b"), ("r13", "r13d", "r13w", "r13b"),
             ("r14", "r14d", "r14w", "r14b"), ("r15", "r15d", "r15w", "r15b")):
    for _r in _fam:
        REG_FAMILY[_r] = _fam[0]

def reg_family(name):
    return REG_FAMILY.get(name.lower(), name.lower())

def is_simd_reg(name):
    n = name.lower()
    return n.startswith(("xmm", "ymm", "zmm"))

def simd_bytes(name):
    """Read a vector register as raw bytes (for value-change detection)."""
    try:
        v = gdb.newest_frame().read_register(name)
    except Exception:
        return None
    for accessor in ("tobytes",):
        try:
            return bytes(getattr(v, accessor)())
        except Exception:
            pass
    try:
        parts = []
        for sub in ("v2_int64", "v2_double"):
            try:
                val = v[sub]
                for i in range(2):
                    parts.append(int(val[i]) & MASK)
                break
            except Exception:
                continue
        if parts:
            return b"".join(x.to_bytes(8, "little") for x in parts)
    except Exception:
        pass
    try:
        return bytes(int(v) & 0xFF for _ in range(0))
    except Exception:
        return None

def _reg_write(dest, slot_reg):
    if dest[0] != "reg":
        return False
    if is_simd_reg(slot_reg) or is_simd_reg(dest[1]):
        return dest[1].lower() == slot_reg.lower()
    return reg_family(dest[1]) == reg_family(slot_reg)

def _mem_overlaps(dest, addr, size):
    if dest[0] != "mem":
        return False
    d, ds = dest[1], (dest[2] or 8)
    return d < (addr + size) and addr < (d + ds)
REG_RE = re.compile(r"^(?:r[a-z0-9]+|e[a-z0-9]+|[abcd][lhx]|r[0-9]+d?|[sd]il?|[sb]pl?|[xyz]mm[0-9]+)$")
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
    m = re.match(r"\s*(byte|word|dword|qword|xmmword|ymmword|zmmword)\s+ptr",
                 op.lower())
    if m:
        return SIZE_PREFIX[m.group(1)]
    low = op.lower()
    for k in ("xmmword", "ymmword", "zmmword"):
        if k in low:
            return SIZE_PREFIX[k]
    for k in ("dword", "qword", "word", "byte"):
        if re.search(r"\b%s\b" % k, low):
            return SIZE_PREFIX[k]
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
MAX_STEPS = int(CFG.get("max_steps", 400000))
MAX_DEPTH = int(CFG.get("max_depth", 30))
segments = []          # path stack for readable parent links
next_id = [0]
anchor_pc = [None]
ANCHOR_INSN = [None]
visited = set()
stats = {"reverse_steps": 0, "writes": 0, "terminals": 0}

HALT = {"flag": False}
MAX_EVENTS = int(CFG.get("max_events", 600))

def add_event(parent, kind, **kw):
    if HALT["flag"] or len(result["events"]) >= MAX_EVENTS:
        if not HALT["flag"]:
            HALT["flag"] = True
            result["events"].append({"id": next_id[0], "parent": parent,
                                     "kind": "event_limit",
                                     "note": "max_events=%d reached — tracing "
                                             "stopped early" % MAX_EVENTS})
            next_id[0] += 1
            save()
        return parent
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
    input_real = CFG.get("input_real")
    for r in reversed(result["reads"]):
        if input_real and r.get("file"):
            try:
                if os.path.realpath(r["file"]) != input_real:
                    continue
            except Exception:
                pass
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

def goto_pc_exact(pc):
    """After an rr seek (which restores an approximate time point), replay
    forward to the exact saved PC with a temporary breakpoint."""
    try:
        if cur_pc() == pc:
            return True
        gdb.execute("tbreak *0x%x" % pc, to_string=True)
        gdb.execute("continue", to_string=True)
        return cur_pc() == pc
    except Exception:
        return False

def goto_anchor():
    if ANCHOR_INSN[0] is not None and goto_insn(ANCHOR_INSN[0]):
        if anchor_pc[0] is None or cur_pc() == anchor_pc[0] \
                or goto_pc_exact(anchor_pc[0]):
            return
    if anchor_pc[0] is None:
        return
    if cur_pc() == anchor_pc[0]:
        return
    try:
        globals().get("fork_bp").enabled = True
    except Exception:
        pass
    try:
        gdb.execute("continue", to_string=True)
    except Exception:
        pass
    try:
        globals().get("fork_bp").enabled = False
    except Exception:
        pass

def over_deadline():
    return time.time() > DEADLINE

def enter_replay():
    """record-full reports the current instruction number only in replay mode;
    a one-step reverse/forward pair switches to it without moving in time."""
    try:
        gdb.execute("reverse-stepi 1", to_string=True)
        gdb.execute("stepi 1", to_string=True)
    except Exception:
        pass

def cur_insn():
    if ENGINE == "rr":
        # rr's gdb extension: "when" prints the last completely replayed
        # event number; that is our time checkpoint
        try:
            out = gdb.execute("when", to_string=True)
            m = re.search(r"(\d+)", out)
            return int(m.group(1)) if m else None
        except Exception:
            return None
    try:
        out = gdb.execute("info record", to_string=True)
        m = re.search(r"Current instruction number is (\d+)", out)
        return int(m.group(1)) if m else None
    except Exception:
        return None

def goto_insn(n):
    if n is None:
        return False
    if cur_insn() == n:
        return True
    if ENGINE == "rr":
        try:
            gdb.execute("seek %d" % n, to_string=True)
            return True
        except Exception:
            return False
    try:
        gdb.execute("record goto %d" % n, to_string=True)
        return True
    except Exception:
        return False

BATCH = int(CFG.get("batch_steps", 128))

def _slot_value(slot):
    if slot[0] == "mem":
        return safe_read(slot[1], slot[2])
    if is_simd_reg(slot[1]):
        return simd_bytes(slot[1])
    return reg_value(slot[1])

def _slot_label(slot):
    if slot[0] == "mem":
        return "mem@%x+%d" % (slot[1], slot[2])
    return slot[1]

def _nav_reverse(n):
    """Move back exactly n instructions, or return the largest sub-count that
    succeeded (0 = no movement).  With all breakpoints disabled during the
    scan, a counted reverse-stepi only stops early at the start of recorded
    execution; on a partial move we re-sync forward and retry with halved
    counts, so the caller always learns the true number of steps taken."""
    if n <= 0:
        return 0
    before = cur_pc()

    def _resync():
        for _ in range(n + 8):
            if cur_pc() == before:
                return True
            try:
                gdb.execute("stepi", to_string=True)
            except Exception:
                return False
        return cur_pc() == before

    try:
        gdb.execute("reverse-stepi %d" % n, to_string=True)
        return n
    except Exception:
        pass
    if not _resync():
        return 0
    m = n // 2
    while m >= 1:
        try:
            gdb.execute("reverse-stepi %d" % m, to_string=True)
            return m
        except Exception:
            if not _resync():
                return 0
            m //= 2
    return 0

def _nav_forward(n):
    if n <= 0:
        return 0
    try:
        gdb.execute("stepi %d" % n, to_string=True)
        return n
    except Exception:
        return 0

WRITE_MNEMONICS = frozenset([
    "mov", "movzx", "movsx", "movsxd", "lea", "add", "sub", "and", "or",
    "xor", "inc", "dec", "shl", "sal", "shr", "sar", "rol", "ror", "neg",
    "not", "xchg", "cmpxchg", "imul", "mul", "div", "idiv", "adc", "sbb",
    "movd", "movq", "movups", "movaps", "movdqu", "movdqa", "movss",
    "vmovups", "vmovaps", "vmovdqu", "vmovdqa", "vmovss", "vmovsd",
    "stosb", "stosw", "stosd", "stosq", "movsb", "movsw", "movsd", "movsq",
    "bswap", "pmovmskb", "pinsrb", "pinsrw", "pinsrd", "pinsrq",
    "pextrb", "pextrw", "pextrd", "pextrq", "punpcklbw", "punpcklwd",
    "punpckldq", "punpcklqdq", "packuswb", "por", "pand", "pxor",
    "psllw", "pslld", "psllq", "psrlw", "psrld", "psrlq",
])

def _mnem_writes_dest(mnem):
    base = mnem.split()[0]
    if base in ("cmp", "test", "push", "pop", "jmp", "nop", "prefetch",
                "prefetchnta", "prefetcht0", "prefetcht1", "prefetcht2",
                "bt", "bts", "btr", "btc", "ucomiss", "ucomisd", "comiss",
                "comisd", "wrmsr", "rdmsr", "cpuid", "syscall", "sysenter",
                "leave", "endbr64", "pause"):
        return False
    if base in WRITE_MNEMONICS:
        return True
    if base.startswith(("set", "cmov", "vmov", "psll", "psrl", "pack",
                        "punpck", "pinsr", "pextr", "pand", "por", "pxor",
                        "movs", "stos")):
        return True
    return False

def _instr_writes_slot(asm, slot, next_pc):
    """Return True if the instruction writes the tracked slot (register or a
    memory range overlapping the slot).  Only instructions whose first operand
    is a true destination count (cmp/test/call are reads/branches)."""
    mnem, ops = split_insn(asm)
    if not mnem:
        return False
    if mnem in ("rep movsb", "rep movsw", "rep movsd", "rep movsq"):
        if slot[0] == "reg":
            return reg_family(slot[1]) in ("rsi", "rdi", "rcx")
        rdi, rcx = reg_value("rdi"), reg_value("rcx")
        if rdi is None or rcx is None:
            return False
        return rdi < (slot[1] + slot[2]) and slot[1] < (rdi + rcx)
    if not _mnem_writes_dest(mnem):
        return False
    if slot[0] == "reg":
        if not ops:
            return False
        return _reg_write(parse_operand(ops[0], next_pc), slot[1])
    # memory slot
    if not ops:
        return False
    dest = parse_operand(ops[0], next_pc)
    return _mem_overlaps(dest, slot[1], slot[2])

def _locate_last_change(slot, base_value, window):
    """Walk the detected window (<= BATCH instructions) forward and find the
    LAST instruction that writes the slot, inspecting destination operands
    rather than value changes: this catches idempotent writes (store of the
    same value), which are invisible to value differencing.  Leaves the
    inferior at that instruction's pre-state and returns (before, after)."""
    stats["reverse_steps"] += window
    ladder = []
    seen = []
    for i in range(window):
        pc = cur_pc()
        insn = disas(pc)
        if insn is None:
            break
        asm = insn["asm"]
        if _is_rr_stub(pc):
            if _nav_forward(1) == 0:
                break
            continue
        if CFG.get("debug_changes"):
            mnem, ops = split_insn(asm)
            dest = parse_operand(ops[0], pc + insn["length"]) if ops else None
            seen.append((i, hex(pc), asm, str(dest)[:40],
                         _mnem_writes_dest(mnem)))
        if _instr_writes_slot(asm, slot, pc + insn["length"]):
            ladder.append((i, pc, asm))
        if _nav_forward(1) == 0:
            break
    if not ladder:
        if CFG.get("debug_changes"):
            add_event(None, "dbg_window", slot=_slot_label(slot),
                      window=window, walked=len(seen), insns=seen)
        return None
    last_idx, writer_pc, writer_asm = ladder[-1]
    back = window - last_idx
    _nav_reverse(back)
    before = _slot_value(slot)
    _nav_forward(1)
    after = _slot_value(slot)
    _nav_reverse(1)
    return before, after

def scan_slot(slot, parent, depth, bound_pc=None, stop_pcs=None, delta=0,
              label=None):
    key = ("slot",) + tuple(slot) + (cur_pc(), label)
    if key in visited:
        add_event(parent, "visited", slot=_slot_label(slot))
        return
    visited.add(key)
    if depth > MAX_DEPTH:
        add_event(parent, "depth_limit", slot=_slot_label(slot))
        return
    if over_deadline():
        add_event(parent, "timeout", slot=_slot_label(slot))
        return
    if slot[0] == "mem":
        term = terminal_for_mem(slot[1], slot[2])
        if term:
            add_event(parent, "input", addr=hex(slot[1]), size=slot[2], **term)
            record_offset(term.get("offset"), term.get("length", slot[2]),
                          parent, term.get("via", "read"), term.get("file"))
            return
        if _structural_addr(slot[1]):
            add_event(parent, "structural_skipped", slot=_slot_label(slot),
                      note="address is in the binary/library static mapping; "
                           "not input-derived state")
            return
    base = _slot_value(slot)
    if base is None:
        add_event(parent, "unmapped" if slot[0] == "mem" else "unknown_reg",
                  slot=_slot_label(slot))
        return

    if slot[0] == "reg":
        # registers: step back first, then inspect the instruction we moved
        # over (the last executed one); the instruction AT the current
        # position is the consumer, not the producer.
        total = 0
        while total < MAX_STEPS:
            if over_deadline():
                add_event(parent, "timeout", slot=_slot_label(slot))
                return
            if _nav_reverse(1) == 0:
                add_event(parent, "record_start", slot=_slot_label(slot))
                return
            total += 1
            pc = cur_pc()
            if (bound_pc is not None and pc == bound_pc) or \
                    (stop_pcs and pc in stop_pcs):
                add_event(parent, "function_entry", slot=_slot_label(slot),
                          note="value comes from the caller (parameter)")
                return
            if _is_rr_stub(pc):
                continue
            insn = disas(pc)
            if insn is not None and _instr_writes_slot(insn["asm"], slot,
                                                       pc + insn["length"]):
                before = _slot_value(slot)
                _nav_forward(1)
                after = _slot_value(slot)
                _nav_reverse(1)
                handle_write(slot, parent, depth, value_before=before,
                             value_after=after, changed="all", delta=delta)
                return
        add_event(parent, "scan_limit", slot=_slot_label(slot), steps=total)
        return

    # memory: batched approach scan, then exact window inspection
    batch = BATCH
    total = 0
    while total < MAX_STEPS:
        if over_deadline():
            add_event(parent, "timeout", slot=_slot_label(slot))
            return
        n = min(batch, MAX_STEPS - total)
        moved = _nav_reverse(n)
        if moved == 0:
            add_event(parent, "record_start", slot=_slot_label(slot),
                      steps=total,
                      note="reached the start of the recorded execution before "
                           "any value change was observed")
            return
        total += moved
        v = _slot_value(slot)
        if v is None:
            add_event(parent, "unmapped", slot=_slot_label(slot))
            return
        if v != base:
            located = _locate_last_change(slot, base, moved)
            if located is None:
                add_event(parent, "implicit_or_unknown_write",
                          slot=_slot_label(slot),
                          note="value changed without a visible store in the "
                               "window")
                return
            before, after = located
            if isinstance(before, (bytes, bytearray)) and \
                    isinstance(after, (bytes, bytearray)):
                changed = [i for i in range(len(before)) if before[i] != after[i]]
            else:
                changed = "all"
            handle_write(slot, parent, depth, value_before=before,
                         value_after=after, changed=changed, delta=delta)
            return
    add_event(parent, "scan_limit", slot=_slot_label(slot), steps=total)

def scan_mem(addr, size, parent, depth, delta=0):
    scan_slot(("mem", addr, size), parent, depth, delta=delta)

def scan_reg(reg, parent, depth, bound_pc=None, label=None, delta=0,
             stop_pcs=None):
    scan_slot(("reg", reg), parent, depth, bound_pc=bound_pc, stop_pcs=stop_pcs,
              delta=delta, label=label)

def trace_read_request(parent, max_lookback=300):
    """At an error-constant terminal, look back a bounded window for the file
    read that set the failure status: report the nearest call(s) to a
    read/pread function with their argument registers.  This bridges the
    data-origin chain to the I/O request, which is what an analyst can map
    back to the input structure (the actionable offset may live in the
    control dependency, not the value's bytes)."""
    steps = 0
    while steps < max_lookback:
        if over_deadline():
            return
        pc = cur_pc()
        insn = disas(pc)
        asm = insn["asm"] if insn else ""
        mnem, ops = split_insn(asm)
        if mnem.startswith("call"):
            target = None
            m = re.search(r"<([^>]+)>", asm)
            if m:
                target = m.group(1)
            rec = {
                "pc": hex(pc),
                "callee": target,
                "fd": reg_value("rdi"),
                "buf": hex(reg_value("rsi")) if reg_value("rsi") is not None else None,
                "count": reg_value("rdx"),
                "offset": reg_value("r10"),
            }
            if target and any(k in target for k in ("read", "pread")):
                add_event(parent, "read_request", **rec)
                return
            if target is None:
                # indirect call (through a function pointer, e.g. the TIFF
                # read proc): the nearest layered read boundary
                add_event(parent, "indirect_call", insn=asm, **rec)
                return
            # a named non-read call: keep looking a little further back
            steps += 1
            if steps >= 60:
                add_event(parent, "nearest_call", **rec)
                return
        try:
            gdb.execute("reverse-stepi", to_string=True)
        except Exception:
            break
        steps += 1
    add_event(parent, "no_read_request",
              note="no read/pread call found within %d instructions back"
                   % max_lookback)

REGIONS = []          # [(start, end, name_or_None)] from /proc/pid/maps
INPUT_REGIONS = []    # (start, end) of input read/mmap buffers

def refresh_regions():
    """Capture the process memory map so operands living in the binary's or a
    library's static mapping (structural state such as tif->tif_flags) can be
    pruned without scanning them."""
    del REGIONS[:]
    try:
        out = gdb.execute("info proc mappings", to_string=True)
    except Exception as e:
        result["regions_info"] = {"count": 0, "error": str(e)[:200]}
        return
    for line in out.splitlines():
        parts = line.split()
        if len(parts) < 2:
            continue
        try:
            start = int(parts[0], 16)
            end = int(parts[1], 16)
        except ValueError:
            continue
        name = None
        for tok in parts[2:]:
            if tok.startswith("/") or tok.startswith("["):
                name = tok
                break
        REGIONS.append((start, end, name))
    del INPUT_REGIONS[:]
    for r in result["reads"]:
        b, n = r.get("buf"), r.get("size")
        if b is not None and n:
            INPUT_REGIONS.append((b, b + n))
    result["regions_info"] = {
        "count": len(REGIONS), "input": len(INPUT_REGIONS),
        "sample": [list(r) for r in REGIONS[:6]],
    }

def _region_of(addr):
    for (s0, e0, name) in REGIONS:
        if s0 <= addr < e0:
            return name
    return None

def _in_input_region_addr(addr):
    for (s0, e0) in INPUT_REGIONS:
        if s0 <= addr < e0:
            return True
    return False

def _structural_addr(addr):
    """True for addresses in a file-backed mapping that is not the input file
    (binary text/data/bss, shared libraries): pure structural state."""
    if _in_input_region_addr(addr):
        return False
    name = _region_of(addr)
    if name is None:
        return False
    if name.startswith("["):          # [heap], [stack], [vvar], ...
        return False
    try:
        if CFG.get("input_real") and os.path.realpath(name) == CFG["input_real"]:
            return False
    except Exception:
        pass
    return True

RR_STUB_RE = re.compile(
    r"(librrpreload|librrpage|librraudit|rr-shared|rr_page|/rr/)", re.I)

def _is_rr_stub(pc):
    """True for instructions inside rr's own instrumentation/pages: under
    rr.soft the recorded process executes injected counter stubs
    (commit_raw_syscall, __do_software_count, ...) which clobber registers and
    must not be mistaken for value producers."""
    name = _region_of(pc)
    if name:
        return bool(RR_STUB_RE.search(name))
    try:
        fn = func_name(pc)
    except Exception:
        return False
    return bool(fn and re.search(r"(commit_raw_syscall|__do_software_count|"
                                  r"software_count|rrcall|rr_page)",
                                  fn, re.I))

def _addresslike(v):
    return v is not None and v > (1 << 40)

def _in_input_region(v):
    return v is not None and terminal_for_mem(v, 1) is not None

def trace_operand(parent, parsed, depth):
    if parsed[0] == "imm":
        add_event(parent, "constant", value=hex(parsed[1] & MASK))
    elif parsed[0] == "mem":
        if _structural_addr(parsed[1]):
            add_event(parent, "structural_skipped", addr=hex(parsed[1]),
                      note="structural mapping")
        else:
            scan_mem(parsed[1], parsed[2] or 8, parent, depth)
    elif parsed[0] == "reg":
        if parsed[1] in ("rbp", "rsp", "rip"):
            add_event(parent, "frame_register", reg=parsed[1])
            return
        v = reg_value(parsed[1])
        if _addresslike(v) and not _in_input_region(v):
            add_event(parent, "pointer_skipped", reg=parsed[1], value=hex(v),
                      note="operand is a pointer into non-input memory "
                           "(structural state); not an input offset carrier")
            return
        scan_reg(parsed[1], parent, depth)
    else:
        add_event(parent, "unknown_operand", operand=parsed[1])

def trace_control(parent, depth, lookback=None, test_lookback=60):
    """Slice the control dependency of a terminal write: find the nearest
    executed conditional branch, record its outcome, then trace the operands
    of the compare/test that guards it.  This is what links a constant error
    code (e.g. TIFFReadDirEntryErrIo) back to the check that failed, and from
    there to the input-derived values (sizes, offsets, tags)."""
    if HALT["flag"] or over_deadline() or depth > MAX_DEPTH:
        return
    lookback = lookback or int(CFG.get("control_lookback", 400))
    steps = 0
    branch = None
    while steps < lookback:
        pc = cur_pc()
        insn = disas(pc)
        if insn is None:
            break
        if _is_rr_stub(pc):
            if _nav_reverse(1) == 0:
                break
            steps += 1
            continue
        mnem, ops = split_insn(insn["asm"])
        if mnem in COND_JUMPS:
            branch = (pc, insn)
            break
        if mnem.startswith("call") or mnem.startswith("ret"):
            add_event(parent, "control_boundary", pc=hex(pc), insn=insn["asm"])
            return
        if _nav_reverse(1) == 0:
            add_event(parent, "control_boundary", note="record start")
            return
        steps += 1
    if branch is None:
        add_event(parent, "no_control",
                  note="no conditional branch within %d instructions" % lookback)
        return
    pc, insn = branch
    fallthrough = pc + insn["length"]
    ok = _nav_forward(1)
    taken = bool(ok) and cur_pc() != fallthrough
    _nav_reverse(1)
    ev = add_event(parent, "control_branch", pc=hex(pc), insn=insn["asm"],
                   taken=taken)
    steps = 0
    while steps < test_lookback:
        # step over the branch (or the previous instruction) first: we want
        # the instruction that produced the branch's operands, not the branch
        if _nav_reverse(1) == 0:
            break
        steps += 1
        pc2 = cur_pc()
        if _is_rr_stub(pc2):
            continue
        insn2 = disas(pc2)
        if insn2 is None:
            break
        mnem2, ops2 = split_insn(insn2["asm"])
        if mnem2 in ("cmp", "test"):
            add_event(ev, "control_test", pc=hex(pc2), insn=insn2["asm"])
            nextp = pc2 + insn2["length"]
            for o in ops2:
                trace_operand(ev, parse_operand(o, nextp), depth + 1)
            return
        if mnem2 in COND_JUMPS or mnem2.startswith("call"):
            add_event(ev, "control_test_boundary", pc=hex(pc2),
                      insn=insn2["asm"])
            return
    add_event(ev, "control_test_unknown")

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
        if target and any(k in target for k in ("read", "pread")):
            # the value is the return status of a file-read call: report the
            # request arguments (fd, buf, count, pread offset) instead of
            # trying to descend into libc
            add_event(eid, "read_call", callee=target,
                      fd=reg_value("rdi"), buf=hex(reg_value("rsi"))
                      if reg_value("rsi") is not None else None,
                      count=reg_value("rdx"), offset=reg_value("r10"),
                      note="value is the return of a read/pread call")
        add_event(eid, "call_boundary", callee=target,
                  note="value produced by a function return; "
                       "follow_returns=%s" % CFG.get("follow_returns", True))
        if CFG.get("trace_args", True) and depth < int(CFG.get("trace_args_depth", 3)):
            for _r in ("rdi", "rsi", "rdx", "rcx", "r8", "r9"):
                _v = reg_value(_r)
                if _v is None:
                    continue
                if _v > (1 << 40) and not terminal_for_mem(_v, 1):
                    continue  # address-like (tif/pointers/dest buffers)
                if slot[0] == "reg" and slot[1] == _r:
                    continue
                scan_reg(_r, eid, depth + 1, label="arg@%x" % pc)
        follow = CFG.get("follow_returns", True)
        if target and any(k in target for k in ("read", "pread")):
            follow = False
        if follow and slot[0] == "reg" \
                and slot[1] in ("rax", "eax", "ax", "al") and depth < MAX_DEPTH:
            descend_call(eid, target, depth, delta)
        return

    COPY_CALLEES = ("memcpy", "memmove", "mempcpy", "_TIFFmemcpy",
                    "bcopy", "TIFFmemcpy")
    if mnem.startswith("call") and slot[0] == "mem" and any(
            k.lower() in (asm.lower()) for k in COPY_CALLEES):
        # call memcpy(dst=rdi, src=rsi, n=rdx): the bytes of our slot were
        # copied from rsi + (slot_addr - rdi)
        rdi, rsi = reg_value("rdi"), reg_value("rsi")
        if rdi is not None and rsi is not None and rdi <= slot[1] < rdi + slot[2]:
            src = rsi + (slot[1] - rdi)
            add_event(eid, "copy_source", src=hex(src), size=slot[2],
                      callee=asm.strip())
            scan_mem(src, slot[2], eid, depth + 1)
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
    _cp = (cur_insn(), cur_pc())
    if delta and slot[0] == "reg":
        add_event(eid, "delta_note", delta=delta,
                  note="byte position inside the register/window carried "
                       "through this write")
    for _si, s in enumerate(srcs):
        if _si > 0 and _cp is not None:
            goto_insn(_cp[0])
            if cur_pc() != _cp[1]:
                goto_pc_exact(_cp[1])
        if s[0] == "imm":
            add_event(eid, "constant", value=hex(s[1] & MASK))
            if CFG.get("trace_control", True):
                trace_control(eid, depth)
            if CFG.get("trace_read_request", False):
                trace_read_request(eid)
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
                continue
            _rv = reg_value(s[1])
            if _addresslike(_rv) and not _in_input_region(_rv):
                add_event(eid, "pointer_skipped", reg=s[1], value=hex(_rv),
                          note="pointer into non-input memory")
                continue
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

if ENGINE == "rr":
    # Under rr replay the inferior is already at the recording start and the
    # program arguments come from the recording.  Do NOT use start/run: it
    # restarts the replay and desynchronizes rr.soft's software-counter
    # instrumentation (verified: without start the fork breakpoint hits
    # normally, with start the replay runs off the rails).
    try:
        gdb.execute("set sysroot /")
    except Exception:
        pass
else:
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
                           "(try --glibc-avx-off; rr needs "
                           "perf_event_paranoid<=1)" % e)
        save(); gdb.execute("quit"); sys.exit(0)

LOGGERS = []
LOGGERS.append(ReadLogger("read", "read"))
LOGGERS.append(ReadLogger("pread64", "pread64"))
for _on, _at in (("open", False), ("open64", False),
                 ("openat", True), ("openat64", True)):
    try:
        LOGGERS.append(OpenLogger(_on, _at))
    except Exception:
        pass
for _ln in ("lseek", "lseek64"):
    try:
        LOGGERS.append(LseekLogger(_ln))
    except Exception:
        pass
try:
    LOGGERS.append(CloseLogger())
except Exception:
    pass
for _mm in ("mmap", "mmap64"):
    try:
        LOGGERS.append(MmapLogger(_mm))
    except Exception:
        pass
if CFG.get("skip_getrandom", True):
    try:
        LOGGERS.append(GetrandomSkipper())
    except Exception:
        pass

fork_bp = None
_pending = None
for spec in CFG.get("fork_specs", []):
    try:
        bp = gdb.Breakpoint(spec)
    except Exception:
        continue
    # an absolute source path from the pipeline build never resolves in a
    # trace build loaded from another tree; skip unresolved specs in favour
    # of the basename spec that does resolve
    try:
        if getattr(bp, "pending", False):
            if _pending is None:
                _pending = (spec, bp)
            else:
                bp.delete()
            continue
    except Exception:
        pass
    fork_bp = bp
    result["fork"]["spec"] = spec
    break
if fork_bp is None and _pending is not None:
    result["fork"]["spec"] = _pending[0]
    fork_bp = _pending[1]
if fork_bp is None:
    result["status"] = "error"
    result["error"] = "no fork breakpoint could be created"
    save(); gdb.execute("quit"); sys.exit(0)

IGNORE = int(CFG.get("fork_ignore", 0))
if IGNORE:
    fork_bp.ignore_count = IGNORE
    result["fork"]["ignore"] = IGNORE

try:
    gdb.execute("continue")
except Exception as e:
    result["status"] = "error"
    result["error"] = "execution failed before the fork: %s" % e
    save(); gdb.execute("quit"); sys.exit(0)

if fork_bp.hit_count < IGNORE + 1:
    result["status"] = "error"
    result["error"] = ("did not reach the fork breakpoint (%s); the stop was "
                       "at %s — likely a record-full limitation (see gdb log)"
                       % (result["fork"]["spec"], func_name(cur_pc())))
    save(); gdb.execute("quit"); sys.exit(0)

refresh_regions()
anchor_pc[0] = cur_pc()
enter_replay()
ANCHOR_INSN = [cur_insn()]
result["fork"]["pc"] = hex(anchor_pc[0])
result["fork"]["insn"] = ANCHOR_INSN[0]
for _b in LOGGERS:
    try:
        _b.enabled = False
    except Exception:
        pass
# the fork breakpoint would intercept forward verification steps during the
# backward scan; goto_anchor uses the recorded instruction checkpoint instead
try:
    fork_bp.enabled = False
except Exception:
    pass
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
    """Fork variables, preferring the ones that appear in the fork statement
    (e.g. `err` in `if (err != TIFFReadDirEntryErrOk)`).  Pointer-typed
    context variables from the divergence result are kept as a fallback."""
    import re
    stmt = (div.get("root_cause_statement_b")
            or div.get("fork_statement")
            or div.get("root_cause_statement_a") or "")
    black = {"if", "while", "for", "return", "sizeof", "NULL", "else", "goto"}
    toks = re.findall(
        r"[A-Za-z_][A-Za-z0-9_]*(?:\s*->\s*[A-Za-z_][A-Za-z0-9_]*)*", stmt)
    stmt_vars = [t for t in toks if t not in black]
    out, seen = [], set()
    for v in stmt_vars + [v for v in (div.get("variables") or [])
                          if isinstance(v, str)]:
        v = v.strip()
        if not v or v.startswith(("if ", "while ", "for ", "return ")):
            continue
        if v not in seen:
            seen.add(v)
            out.append(v)
    return out[:8]


def sanitize_compile_cfg(cfg):
    """Strip sanitizer/instrumentation flags so record-full can replay."""
    import re
    TOKENS = ("-fsanitize=address", "-fsanitize=undefined", "-fsanitize=leak",
              "-fsanitize=thread", "-finstrument-functions",
              "-fno-omit-frame-pointer")

    def strip(t):
        for tok in TOKENS:
            t = t.replace(tok, " ")
        return re.sub(r"\s+", " ", t).strip()

    out = {}
    for k, v in (cfg or {}).items():
        if k == "pre_build":
            out[k] = [strip(c) for c in (v or [])]
        elif k == "compile_flags":
            out[k] = {kk: strip(vv) for kk, vv in (v or {}).items()}
        else:
            out[k] = v
    return out


def _trace_build_key(source_dir, config_path):
    import hashlib
    h = hashlib.sha1()
    h.update(str(Path(source_dir).resolve()).encode())
    h.update(b"|")
    if config_path and os.path.isfile(config_path):
        with open(config_path, "rb") as f:
            h.update(f.read())
    return h.hexdigest()[:12]


def build_trace_build(source_dir, config_mod, config_path=None,
                      cache_root=None, refresh=False):
    """Build (or reuse from cache) a -g -O0, no-ASan copy of source_dir for
    record-full replay.

    ASan is only needed as the crash oracle, not for origin tracing; the ASan
    runtime executes instructions (e.g. rdtscp) that record-full cannot
    replay.  The build is cached by (source dir, config bytes) so repeated
    pipeline runs do not pay the compile time again."""
    import shutil
    import tempfile as _tf
    import run_fork_analysis as rfa

    compile_cmds = getattr(config_mod, "COMPILE_COMMANDS", {})
    exec_cfg = getattr(config_mod, "EXECUTION_CONFIG", {})
    cfg = sanitize_compile_cfg(compile_cmds.get("target")
                               or compile_cmds.get("reference") or {})
    if not cfg:
        print("[!] config has no COMPILE_COMMANDS for a trace build")
        return None

    src = None
    if cache_root:
        base = Path(cache_root) / _trace_build_key(source_dir, config_path)
        src = base / "src"
    if src is not None and src.is_dir() and not refresh:
        binp = rfa.find_binary(src, exec_cfg)
        if binp is not None:
            try:
                import trace_fork_offsets as _tfo
                binp = Path(_tfo.resolve_binary(str(binp)))
            except Exception:
                pass
            if os.access(str(binp), os.X_OK):
                print("[*] reusing cached trace build: %s" % binp)
                return str(binp)
    if src is None:
        work = Path(_tf.mkdtemp(prefix="dyn_trace_build_"))
        src = work / "src"
    else:
        if src.exists() and refresh:
            shutil.rmtree(str(src.parent))
        src.parent.mkdir(parents=True, exist_ok=True)

    print("[*] building a no-ASan trace build in %s ..." % src)
    if not src.is_dir():
        shutil.copytree(str(source_dir), str(src))
    if not rfa.run_build(src, "trace", cfg):
        print("[!] trace build failed")
        return None
    binp = rfa.find_binary(src, exec_cfg)
    if binp is None:
        print("[!] trace binary not found under %s" % src)
        return None
    try:
        import trace_fork_offsets as _tfo
        binp = Path(_tfo.resolve_binary(str(binp)))
    except Exception:
        pass
    print("[*] trace binary: %s" % binp)
    return str(binp)


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
    ap.add_argument("--config", help="project config (for a no-ASan trace "
                    "build when the pipeline binary is ASan-instrumented)")
    ap.add_argument("--source-dir", help="target version source tree "
                    "(for the trace build)")
    ap.add_argument("--no-trace-build", action="store_true",
                    help="never build a no-ASan trace build")
    ap.add_argument("--trace-build-cache", default=None,
                    help="cache dir for no-ASan trace builds "
                    "(default: out/.dyn_trace_build)")
    ap.add_argument("--no-trace-build-cache", action="store_true",
                    help="disable trace-build caching (always rebuild)")
    ap.add_argument("--refresh-trace-build", action="store_true",
                    help="force a rebuild of the cached trace build")
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
    ap.add_argument("--max-steps", type=int, default=400000,
                    help="max reverse instructions per slot")
    ap.add_argument("--max-depth", type=int, default=30)
    ap.add_argument("--batch-steps", type=int, default=128,
                    help="reverse-stepping batch size for the approach scan "
                    "(clamped to 64)")
    ap.add_argument("--fork-ignore", type=int, default=None,
                    help="skip this many earlier hits of the fork breakpoint "
                    "(select a specific invocation; default: from diverge JSON)")
    ap.add_argument("--no-control", dest="trace_control", action="store_false",
                    default=True, help="do not slice the control dependency at "
                    "constant terminals (default: on)")
    ap.add_argument("--no-trace-args", dest="trace_args", action="store_false",
                    default=True, help="do not trace call argument registers "
                    "at call boundaries (default: on)")
    ap.add_argument("--trace-read-request", action="store_true",
                    help="at constant/error terminals, look back for the nearest "
                    "read/pread call and report its request arguments (heuristic)")
    ap.add_argument("--no-follow-returns", action="store_true",
                    help="do not follow function return values")
    ap.add_argument("--glibc-avx-off", dest="avx_off", action="store_true",
                    default=True, help="disable glibc AVX dispatch so "
                    "record full can replay (default on)")
    ap.add_argument("--no-glibc-avx-off", dest="avx_off", action="store_false")
    ap.add_argument("--debug-changes", action="store_true",
                    help="record per-window change diagnostics in the events")
    ap.add_argument("--engine", choices=["auto", "record", "rr"], default="auto",
                    help="reverse-execution engine: 'record' = gdb record full; "
                    "'rr' = rr/rr.soft record+replay (needs "
                    "perf_event_paranoid<=1); 'auto' prefers rr when available")
    ap.add_argument("--rr-bin", default=None,
                    help="path to the rr (or rr.soft) executable")
    ap.add_argument("--quiet", action="store_true")
    args = ap.parse_args()

    # merge divergence JSON
    div = {}
    if args.diverge_json:
        div = load_diverge_json(args.diverge_json)

    config_mod = None
    if args.config:
        import importlib.util as _ilu
        _spec = _ilu.spec_from_file_location("dyn_config", args.config)
        config_mod = _ilu.module_from_spec(_spec)
        try:
            _spec.loader.exec_module(config_mod)
        except Exception as e:
            print("[!] cannot load config %s: %s" % (args.config, e))
            config_mod = None
    source_dir = args.source_dir
    if source_dir and not os.path.isdir(source_dir):
        print("[!] --source-dir not found: %s" % source_dir)
        source_dir = None

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

    # ---- engine selection (record full vs rr / rr.soft) ----
    def _find_rr():
        cands = []
        if args.rr_bin:
            cands.append(args.rr_bin)
        else:
            cands.append(str(Path.home() / "tools" / "rr-soft-built" / "bin" / "rr"))
            w = shutil.which("rr")
            if w:
                cands.append(w)
        for c in cands:
            if c and os.path.isfile(c) and os.access(c, os.X_OK):
                return c
        return None

    rr_bin = _find_rr()
    engine = args.engine
    if engine == "auto":
        engine = "rr" if rr_bin else "record"
    if engine == "rr":
        _p = read_paranoid()
        if not rr_bin:
            print("[!] rr executable not found; using gdb record full")
            engine = "record"
        elif _p not in ("0", "1"):
            print("[!] rr needs kernel.perf_event_paranoid<=1 (currently %s);"
                  " using gdb record full" % _p)
            engine = "record"

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
    # ld.so's lazy PLT resolver uses XSAVE instructions that record-full
    # cannot replay; resolve everything before main instead.
    env.setdefault("LD_BIND_NOW", "1")
    if args.avx_off:
        prev = env.get("GLIBC_TUNABLES", "")
        env["GLIBC_TUNABLES"] = ((prev + ":") if prev else "") + \
            "glibc.cpu.hwcaps=-AVX2,-AVX,-AVX512F,-AVX512VL,-AVX_Fast_Unaligned_Load"

    fork_ignore = args.fork_ignore
    if fork_ignore is None:
        dyn = div.get("dynamic_fork") or {}
        inv = dyn.get("invocation")
        if isinstance(inv, int) and inv > 0:
            fork_ignore = inv - 1
            if not args.quiet:
                print("[*] fork invocation: %d (ignoring %d earlier hit(s))"
                      % (inv, fork_ignore))
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
        "trace_read_request": bool(args.trace_read_request),
        "trace_control": bool(args.trace_control),
        "trace_args": bool(args.trace_args),
        "input_real": os.path.realpath(input_file),
        "batch_steps": min(512, max(2, args.batch_steps)),
        "debug_changes": bool(args.debug_changes),
        "fork_ignore": fork_ignore or 0,
        "engine": engine,
    }

    def _env_for(binary_path):
        run_env = dict(env)
        try:
            import trace_fork_offsets as _tfo
            run_env = _tfo.build_run_env(str(binary_path))
            run_env["ASAN_OPTIONS"] = env.get("ASAN_OPTIONS",
                                              "detect_leaks=0:abort_on_error=0")
            if env.get("GLIBC_TUNABLES"):
                run_env["GLIBC_TUNABLES"] = env["GLIBC_TUNABLES"]
            run_env.setdefault("LD_BIND_NOW", "1")
        except Exception:
            pass
        return run_env

    def _write_run_files(tmpdir, binary_path, engine_name):
        cfg_path = os.path.join(tmpdir, "cfg.json")
        run_cfg = dict(cfg)
        run_cfg["binary"] = str(binary_path)
        run_cfg["engine"] = engine_name
        with open(cfg_path, "w") as f:
            json.dump(run_cfg, f, indent=1)
        script_path = os.path.join(tmpdir, "trace.py")
        with open(script_path, "w") as f:
            f.write(GDB_SCRIPT)
        return cfg_path, script_path

    def _parse_result(binary_path, elapsed):
        if not os.path.isfile(output):
            return None
        with open(output) as f:
            res = json.load(f)
        res["wall_seconds"] = round(elapsed, 2)
        res["_output"] = output
        res["binary"] = str(binary_path)
        with open(output, "w") as f:
            json.dump(res, f, indent=1, default=str)
        return res

    def _clear_output():
        try:
            if os.path.isfile(output):
                os.remove(output)
        except Exception:
            pass

    def run_gdb(binary_path):
        """gdb record-full engine."""
        _clear_output()
        tmpdir = tempfile.mkdtemp(prefix="dyn_origin_")
        cfg_path, script_path = _write_run_files(tmpdir, binary_path, "record")
        gdb_log = os.path.join(tmpdir, "gdb.log")
        run_env = _env_for(binary_path)
        run_env["DYNT_CFG"] = cfg_path
        run_env["DYNT_OUT"] = output
        t0 = time.time()
        try:
            with open(gdb_log, "w") as logf:
                subprocess.run(
                    ["gdb", "-batch", "-nx", "-q", "-x", script_path,
                     str(binary_path)],
                    env=run_env, stdout=logf, stderr=subprocess.STDOUT,
                    timeout=args.timeout + 120)
        except subprocess.TimeoutExpired:
            print("[!] gdb timed out")
        elapsed = time.time() - t0
        return _parse_result(binary_path, elapsed), gdb_log, elapsed

    def run_rr(binary_path):
        """rr / rr.soft engine: record once, then replay under gdb via the
        remote debug server.  The debugger command line is built explicitly
        (sysroot + copied binary) because our gdb script must run *after* the
        remote connection is established."""
        import glob as _glob
        import socket as _socket
        _clear_output()
        tmpdir = tempfile.mkdtemp(prefix="dyn_rr_")
        trace_dir = os.path.join(tmpdir, "trace")
        cfg_path, script_path = _write_run_files(tmpdir, binary_path, "rr")
        gdb_log = os.path.join(tmpdir, "gdb.log")
        rec_log = os.path.join(tmpdir, "rr_record.log")
        run_env = _env_for(binary_path)

        t0 = time.time()
        try:
            with open(rec_log, "w") as logf:
                subprocess.run(
                    [rr_bin, "record", "-W", "-o", trace_dir,
                     os.path.abspath(str(binary_path))]
                    + [str(a) for a in prog_args],
                    env=run_env, stdout=logf, stderr=subprocess.STDOUT,
                    timeout=args.timeout + 120)
        except subprocess.TimeoutExpired:
            print("[!] rr record timed out")

        copied = _glob.glob(os.path.join(
            trace_dir, "mmap_copy_*_" + os.path.basename(str(binary_path))))
        if not copied:
            with open(gdb_log, "w") as logf:
                logf.write("no copied binary in %s (rr record failed?)\n"
                           % trace_dir)
            print("[!] rr record produced no trace in %s" % trace_dir)
            try:
                _tail = open(rec_log).read().splitlines()[-15:]
                print("--- %s ---" % rec_log)
                print("\n".join(_tail))
            except Exception:
                pass
            return _parse_result(binary_path, time.time() - t0), gdb_log, \
                time.time() - t0

        # pick a free port
        srv = _socket.socket()
        srv.bind(("127.0.0.1", 0))
        port = srv.getsockname()[1]
        srv.close()

        run_env["DYNT_CFG"] = cfg_path
        run_env["DYNT_OUT"] = output
        rr_proc = subprocess.Popen(
            [rr_bin, "replay", "-W", "-s", str(port), "-k", trace_dir],
            env=run_env, stdout=open(rec_log, "a"),
            stderr=subprocess.STDOUT)
        try:
            for _ in range(120):
                try:
                    c = _socket.create_connection(("127.0.0.1", port), 0.2)
                    c.close()
                    break
                except OSError:
                    time.sleep(0.25)
            try:
                with open(gdb_log, "w") as logf:
                    subprocess.run(
                        ["gdb", "-batch", "-nx", "-q", copied[0],
                         "-ex", "set sysroot /",
                         "-ex", "target extended-remote 127.0.0.1:%d" % port,
                         "-x", script_path],
                        env=run_env, stdout=logf, stderr=subprocess.STDOUT,
                        timeout=args.timeout + 120)
            except subprocess.TimeoutExpired:
                print("[!] gdb (rr replay) timed out")
        finally:
            try:
                rr_proc.terminate()
                rr_proc.wait(timeout=10)
            except Exception:
                try:
                    rr_proc.kill()
                except Exception:
                    pass
        elapsed = time.time() - t0
        res = _parse_result(binary_path, elapsed)
        if res is None or res.get("status") != "ok":
            print("[!] rr engine failed (logs in %s)" % tmpdir)
            for _f in (rec_log, gdb_log):
                try:
                    _tail = open(_f).read().splitlines()[-10:]
                    print("--- %s ---" % _f)
                    print("\n".join(_tail))
                except Exception:
                    pass
        return res, gdb_log, elapsed

    def run_engine(binary_path):
        if engine == "rr":
            return run_rr(binary_path)
        return run_gdb(binary_path)

    if not args.quiet:
        print("[*] binary    : %s" % real_bin)
        print("[*] input     : %s (%d bytes)" % (input_file, cfg["input_size"]))
        print("[*] args      : %s" % " ".join(prog_args))
        print("[*] fork specs: %s" % ", ".join(fork_specs[:4]))
        print("[*] variables : %s" % ", ".join(variables))
        if engine == "rr":
            print("[*] engine    : rr (rr.soft -W software counters) "
                  "[%s, perf_event_paranoid=%s]" % (rr_bin, read_paranoid()))
        else:
            print("[*] engine    : gdb record full [perf_event_paranoid=%s]"
                  % read_paranoid())

    res, gdb_out, elapsed = run_engine(real_bin)
    if engine == "rr" and (res is None or res.get("status") != "ok"):
        print("[*] rr engine failed; falling back to gdb record full")
        res, gdb_out, elapsed = run_gdb(real_bin)
    if res is None:
        print("[!] no result written; see %s" % gdb_out)
        return 2

    # If the engine failed on the pipeline binary (e.g. ASan runtime
    # instructions for record full), build a no-ASan trace build and retry.
    if res.get("status") != "ok" and source_dir and config_mod and \
            not args.no_trace_build:
        print("[*] engine failed on the pipeline binary; trying a no-ASan "
              "trace build (origin tracing does not need ASan)")
        cache_root = None
        if not args.no_trace_build_cache:
            cache_root = args.trace_build_cache or str(
                BASE / "out" / ".dyn_trace_build")
        trace_bin = build_trace_build(
            source_dir, config_mod, config_path=args.config,
            cache_root=cache_root, refresh=args.refresh_trace_build)
        if trace_bin:
            res2, gdb_out2, elapsed2 = run_engine(trace_bin)
            if res2 is not None:
                res, gdb_out, elapsed = res2, gdb_out2, elapsed2

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
            elif kind == "read_request":
                extra = "%s(fd=%s, count=%s, offset=%s) buf=%s" % (
                    e.get("callee"), e.get("fd"), e.get("count"),
                    e.get("offset"), e.get("buf"))
            elif kind in ("indirect_call", "nearest_call"):
                extra = "%s  [%s]" % (e.get("insn"), e.get("pc"))
            print("  %s%s %s" % (" " * indent, kind, extra))
            dump(e.get("id"), indent + 2)
    dump(None, 2)
    print("\nfull result : %s" % res.get("_output", ""))
    print("gdb log     : %s" % gdb_log)


if __name__ == "__main__":
    sys.exit(main())
