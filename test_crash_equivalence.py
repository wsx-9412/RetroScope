#!/usr/bin/env python3
"""Unit tests for the same-vulnerability judgment criterion.

Criterion (as fixed):
  1. crash type — equal, or the SEGV umbrella (exactly one side is coarse
     'SEGV' and the other is a concrete family member);
  2. crash point — innermost USER frame of the FAULT stack (sanitizer
     interceptors filtered); compare the crash-point FUNCTION (line numbers
     differ across versions); if the function matches, require the
     statements at both crash points to be similar (best effort — skipped
     when a source line is unresolvable).

Rejected outcomes must NOT count as matches: 'same_type' alone, and the
removed Case-C rule ("same type at any site != target baseline") no longer
exists anywhere.
"""
import os
import sys
import tempfile

sys.path.insert(0, os.path.dirname(os.path.abspath(__file__)))

from trace_fork_offsets import (  # noqa: E402
    compare_crash_signatures,
    extract_crash_signature,
    _attach_crash_statement,
    _statements_similar,
    _resolve_source_file,
)

PASS = []
FAIL = []


def check(name, cond, detail=""):
    (PASS if cond else FAIL).append(name)
    print(f"  [{'PASS' if cond else 'FAIL'}] {name}"
          + (f"  -- {detail}" if detail and not cond else ""))


def mk(type_, func, file_, line, stmt=None, frames=None):
    f = {"function": func, "file": file_, "line": line}
    if stmt is not None:
        f["statement"] = stmt
    return {"type": type_, "frames": frames or [],
            "crash_frames": [f], "summary": None}


HBO = "heap-buffer-overflow"

# ---------------------------------------------------------------- criterion 1
print("\n[criterion 1] crash type")
v, d = compare_crash_signatures(mk(HBO, "f", "a.c", 1), mk(HBO, "f", "a.c", 1))
check("equal types pass", v == "same_site", d)

v, d = compare_crash_signatures(mk(HBO, "f", "a.c", 1),
                                mk("SEGV on unknown address", "f", "a.c", 1))
check("SEGV umbrella passes", v is not None and v.startswith("same"), d)

v, d = compare_crash_signatures(
    mk(HBO, "f", "a.c", 1), mk("stack-buffer-overflow", "g", "b.c", 2))
check("two distinct concrete types -> None", v is None, d)

v, d = compare_crash_signatures(
    mk("heap-use-after-free", "f", "a.c", 1),
    mk(HBO, "f", "a.c", 1))
check("UAF vs heap-overflow -> None (both concrete)", v is None, d)

# ---------------------------------------------------------------- criterion 2
print("\n[criterion 2] crash point: function first, then statement")

# Reported false positive: binutils mutant crashed in the ELF byte-getter
# while the reference crash is in the DWARF line-dump reader.  Same ASan
# type must NOT count as a match.
ref = mk(HBO, "get_line_filename_and_dirname", "../../binutils/dwarf.c",
         4001, stmt="_bfd_safe_read_leb128 (abfd, false, &length, &uvalue)")
tgt = mk(HBO, "byte_get_little_endian", "../../binutils/elfcomm.c",
         148, stmt="switch (sizeof (bfd_vma)) {")
v, d = compare_crash_signatures(ref, tgt)
check("elfcomm mutant rejected (0xcd50 case)", v == "same_type", f"{v}: {d}")

# giflib line-drift: same function, same statement, different line numbers.
ref = mk(HBO, "display_gif_line", "/tmp/x/gif2rgb.c", 298,
         stmt="*BufferP++ = ColorMapEntry->Red;")
tgt = mk(HBO, "display_gif_line", "/tmp/x/gif2rgb.c", 296,
         stmt="*BufferP++ = ColorMapEntry->Red;")
v, d = compare_crash_signatures(ref, tgt)
check("line drift, identical statement -> same_func", v == "same_func",
      f"{v}: {d}")

# Version drift on the crash line itself (a guard added by the fix):
# still the same failure point.
ref = mk(HBO, "read_record", "dwarf.c", 4001,
         stmt="while (*data != 0)")
tgt = mk(HBO, "read_record", "dwarf.c", 3980,
         stmt="while (data < data_end && *data != 0)")
v, d = compare_crash_signatures(ref, tgt)
check("guard-added drift -> same_func", v == "same_func", f"{v}: {d}")

# Same function but unrelated statements = different crash points.
ref = mk(HBO, "display_debug_section", "dwarf.c", 100,
         stmt='fprintf (stderr, "error: %s\\n", msg);')
tgt = mk(HBO, "display_debug_section", "dwarf.c", 420,
         stmt="for (i = 0; i < sec->sh_size; i++) {")
v, d = compare_crash_signatures(ref, tgt)
check("same function, unrelated statements -> same_type", v == "same_type",
      f"{v}: {d}")

# Statement unavailable on one side: fail open to the function match.
ref = mk(HBO, "f", "a.c", 10, stmt="x = *p;")
tgt = mk(HBO, "f", "a.c", 12)
v, d = compare_crash_signatures(ref, tgt)
check("missing statement fails open -> same_func", v == "same_func",
      f"{v}: {d}")

# Identical file+line but statements differ (coincidental line numbers
# across versions): statement check still applies.
ref = mk(HBO, "big_function", "parser.c", 500, stmt="a = b + c;")
tgt = mk(HBO, "big_function", "parser.c", 500,
         stmt="free_everything_and_return (ctx);")
v, d = compare_crash_signatures(ref, tgt)
check("same_site name but dissimilar statements -> same_type",
      v == "same_type", f"{v}: {d}")

# Genuine same_site.
ref = mk(HBO, "f", "a.c", 7, stmt="*dst = *src;")
tgt = mk(HBO, "f", "a.c", 7, stmt="*dst = *src;")
v, d = compare_crash_signatures(ref, tgt)
check("identical site -> same_site", v == "same_site", f"{v}: {d}")

# ---------------------------------------------------------------- sanitizer filter
print("\n[criterion 2] sanitizer/interceptor frames are not the crash point")
UAF_OUT = """\
==123==ERROR: AddressSanitizer: heap-use-after-free on address 0x602000000050
READ of size 4 at 0x602000000050 thread T0
    #0 0x4c3211 in __interceptor_strcmp /src/llvm/compiler-rt/lib/asan/asan_interceptors.cc:501:5
    #1 0x5d4aaa in bfd_hash_lookup /src/binutils/bfd/hash.c:200:5
    #2 0x6e5bbb in program_name_lookup /src/binutils/readelf.c:900:7
    #3 0x7f6ccc in main /src/binutils/readelf.c:1200:3
SUMMARY: AddressSanitizer: heap-use-after-free /src/binutils/bfd/hash.c:200:5 in bfd_hash_lookup
freed by thread T0 here:
    #0 0x4a1111 in __interceptor_free /src/llvm/compiler-rt/lib/asan/asan_malloc_linux.cc:101:3
    #1 0x111aaa in load_image /src/binutils/readelf.c:50:3
"""
sig_ref = extract_crash_signature(UAF_OUT)
sig_tgt = extract_crash_signature(UAF_OUT)
check("interceptor filtered from crash_frames",
      sig_ref and sig_ref["crash_frames"][0]["function"] == "bfd_hash_lookup",
      str(sig_ref["crash_frames"][:1] if sig_ref else None))
v, d = compare_crash_signatures(sig_ref, sig_tgt)
check("UAF interceptor case -> same_func", v == "same_func", f"{v}: {d}")

# ---------------------------------------------------------------- helpers
print("\n[helpers] statement resolution + similarity")


def test_resolver():
    with tempfile.TemporaryDirectory() as tdir:
        os.makedirs(os.path.join(tdir, "build-asan", "binutils"))
        binary = os.path.join(tdir, "build-asan", "binutils", "readelf")
        open(binary, "w").close()
        os.makedirs(os.path.join(tdir, "binutils"))
        src = os.path.join(tdir, "binutils", "dwarf.c")
        with open(src, "w") as f:
            f.write("int a;\nint b;\n    *dst = *src;   // crash line\nint d;\n")
        got = _resolve_source_file("../../binutils/dwarf.c", binary)
        check("relative frame path resolves via binary walk-up", got == src,
              f"{got} != {src}")

        sig = mk(HBO, "f", "../../binutils/dwarf.c", 3)
        _attach_crash_statement(sig, binary)
        check("statement attached from source line",
              sig["crash_frames"][0].get("statement") == "*dst = *src;   // crash line",
              str(sig["crash_frames"][0]))

        sig = mk(HBO, "f", "../../binutils/dwarf.c", 9999)
        _attach_crash_statement(sig, binary)
        check("out-of-range line attaches nothing",
              "statement" not in sig["crash_frames"][0])

        sig = mk(HBO, "f", "/nonexistent/dir/x.c", 1)
        _attach_crash_statement(sig, binary)
        check("unresolvable source attaches nothing",
              "statement" not in sig["crash_frames"][0])

        check("none-signature tolerated", _attach_crash_statement(None,
                                                                  binary) is None)


test_resolver()

check("identical statements similar", _statements_similar("a->b = c;", "a->b = c;"))
check("whitespace-only difference similar",
      _statements_similar("if (a && b) {", "if(a&&b){"))
check("guard addition similar",
      _statements_similar("while (*p)", "while (p < end && *p)"))
check("unrelated statements not similar",
      not _statements_similar('fprintf (stderr, "error: %s\\n", msg);',
                              "for (i = 0; i < sec->sh_size; i++) {"))
check("missing statement similar (fail open)",
      _statements_similar(None, "x = *p;"))

print(f"\n{'='*60}")
print(f"passed: {len(PASS)}  failed: {len(FAIL)}")
if FAIL:
    print("FAILED: " + ", ".join(FAIL))
    sys.exit(1)
print("all tests passed")
