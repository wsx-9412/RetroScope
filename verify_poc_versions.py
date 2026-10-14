#!/usr/bin/env python3
"""Cross-version same-vulnerability verification for the downloaded PoCs.

For every PoC catalogued in poc_run_commands.md (giflib / libxml2 /
binutils / freetype), run the trigger command against every built version
of that project and classify each run with the SAME criterion the pipeline
uses (trace_fork_offsets.extract_crash_signature +
compare_crash_signatures):

  same_site / same_func  -> SAME vulnerability as the reference crash
  same_type              -> same ASan type but different crash point
                            (counted as DIFFERENT vulnerability)
  None (different type)  -> different crash
  no ASan report:
    signal               -> died by signal without an ASan report (recorded)
    no_crash             -> exited without crashing
    timeout              -> killed by the run timeout

The reference crash is the crash produced on the documented vulnerable
version (`ref` in the catalog).  The observed reference crash function is
also compared against the CVE's reported crash function (`reported`) from
the sourceware Bugzilla / advisory.

Results: results/poc_samevuln/results.json + a markdown summary printed
to stdout (appended to poc_run_commands.md).
"""

import json
import os
import re
import signal
import subprocess
import sys
import time
from concurrent.futures import ThreadPoolExecutor, as_completed

sys.path.insert(0, os.path.dirname(os.path.abspath(__file__)))
from trace_fork_offsets import (  # noqa: E402
    extract_crash_signature, compare_crash_signatures)

REPO = os.path.dirname(os.path.abspath(__file__))
OUT_DIR = os.path.join(REPO, 'results', 'poc_samevuln')
TIMEOUT = int(os.environ.get('POC_SWEEP_TIMEOUT', '15'))
WORKERS = int(os.environ.get('POC_SWEEP_WORKERS', '3'))
ENV = dict(os.environ, ASAN_OPTIONS='detect_leaks=0')

HUGE_OBJDUMP_ARGS = [
    '-S', '-D', '-x', '-s', '-Z', '-g', '-e', '-G', '-T', '-t', '-L', '-R',
    '--disassemble-zeroes', '--insn-width=32', '--disassembler-color=extended',
]

LD_ARGS = {
    'CVE-2025-5244': ['--no-undefined', '--orphan-handling', 'discard',
                      '--gc-sections', '--no-print-gc-sections', '-w', '-r',
                      '-d'],
    'CVE-2025-11412': ['--gc-sections', '--no-print-gc-sections', '-w'],
    'CVE-2025-11413': ['--gc-sections', '--no-print-gc-sections', '-w'],
    'CVE-2025-11414': ['--gc-sections', '--no-print-gc-sections', '-w'],
    'CVE-2025-11082': ['--gc-sections', '--no-print-gc-sections', '-w'],
    'CVE-2025-11495': ['--gc-sections', '--no-print-gc-sections', '-w'],
    'CVE-2025-11083': ['--version-exports-section', 'symbol', '--shared'],
    'CVE-2025-11840': ['--version-exports-section', 'symbol', '--shared'],
    'CVE-2025-11494': ['--version-exports-section', 'symbol', '--shared'],
    'CVE-2026-6846': ['-o', '/dev/null'],
    'CVE-2026-15003': ['--gc-sections', '-o', '/dev/null'],
    'CVE-2026-90801': ['--gc-sections', '-w'],
    'CVE-2026-90802': ['-o', '/dev/null'],
    'CVE-2026-90803': ['-o', '/dev/null'],
    'CVE-2026-90828': ['-r', '-o', '/dev/null'],
    'CVE-2026-90829': ['-r', '-o', '/dev/null'],
    'CVE-2026-90830': ['--shared', '-z', 'now', '-o', '/dev/null'],
    'CVE-2026-90831': ['--version-exports-section', 'symbol', '--shared',
                       '-o', '/dev/null'],
    'CVE-2026-91779': ['-r', '-o', '/dev/null'],
    'CVE-2026-91780': ['-o', '/dev/null'],
    'CVE-2026-91781': ['-r', '-o', '/dev/null'],
    'CVE-2026-91782': ['-r', '-o', '/dev/null'],
}
LD_REF = {
    'CVE-2025-5244': '2.44',
    'CVE-2025-11412': '2.45', 'CVE-2025-11413': '2.45',
    'CVE-2025-11414': '2.45', 'CVE-2025-11082': '2.45',
    'CVE-2025-11495': '2.45', 'CVE-2025-11083': '2.45',
    'CVE-2025-11840': '2.45', 'CVE-2025-11494': '2.45',
    'CVE-2026-6846': '2.45', 'CVE-2026-15003': '2.45',
    'CVE-2026-90801': '2.47', 'CVE-2026-90802': '2.47',
    'CVE-2026-90803': '2.47', 'CVE-2026-90828': '2.47',
    'CVE-2026-90829': '2.47', 'CVE-2026-90830': '2.47',
    'CVE-2026-90831': '2.47', 'CVE-2026-91779': '2.47',
    'CVE-2026-91780': '2.47', 'CVE-2026-91781': '2.47',
    'CVE-2026-91782': '2.44',
}

# (cve, tool, args, ref_version, reported_crash_function)
BINUTILS_CLI = [
    ('CVE-2017-6965', 'readelf', ['-w'], '2.28', 'byte_put_little_endian'),
    ('CVE-2017-8392', 'objdump', ['-S'], '2.28', 'bfd_getl32'),
    ('CVE-2017-8396', 'objdump', ['-g'], '2.28', 'bfd_getl64'),
    ('CVE-2017-12448', 'objdump', ['-x'], '2.29', 'bfd_cache_close'),
    ('CVE-2017-12449', 'objdump', ['-x'], '2.29',
     '_bfd_vms_save_sized_string'),
    ('CVE-2017-12450', 'objdump', ['-x'], '2.29', 'alpha_vms_object_p'),
    ('CVE-2017-12451', 'objdump', ['-x'], '2.29', '_bfd_xcoff_read_ar_hdr'),
    ('CVE-2017-12452', 'objdump', ['-x'], '2.29',
     'bfd_mach_o_i386_canonicalize_one_reloc'),
    ('CVE-2017-12453', 'objdump', ['-x'], '2.29', '_bfd_vms_slurp_eeom'),
    ('CVE-2017-12454', 'objdump', ['-x'], '2.29', '_bfd_vms_slurp_egsd'),
    ('CVE-2017-12455', 'objdump', ['-x'], '2.29', 'evax_bfd_print_emh'),
    ('CVE-2017-12456', 'objdump', ['-x', '-g'], '2.29',
     'read_symbol_stabs_debugging_info'),
    ('CVE-2017-12457', 'objdump', ['-x'], '2.29',
     'bfd_make_section_with_flags'),
    ('CVE-2017-12458', 'objdump', ['-x'], '2.29',
     'nlm_swap_auxiliary_headers_in'),
    ('CVE-2017-12459', 'objdump', ['-x'], '2.29',
     'bfd_mach_o_read_symtab_strtab'),
    ('CVE-2017-14130', 'objdump', ['-x'], '2.29', 'display_object_bfd'),
    ('CVE-2017-14529', 'objdump', ['-x'], '2.29', 'dump_bfd_private_header'),
    ('CVE-2017-14729', 'objdump', ['-x'], '2.29', 'dump_bfd_private_header'),
    ('CVE-2017-15225', 'readelf', ['-w'], '2.29',
     'get_line_filename_and_dirname'),
    ('CVE-2017-15996', 'readelf', ['-w'], '2.29', None),
    ('CVE-2017-16826', 'objdump', ['-r'], '2.29', 'dump_relocs_in_section'),
    ('CVE-2017-16832', 'objdump', ['-x'], '2.29', 'display_object_bfd'),
    ('CVE-2017-17080', 'objdump', ['-x'], '2.29', 'display_object_bfd'),
    ('CVE-2017-17121', 'objdump', ['-g'], '2.29', 'perform_reloc'),
    ('CVE-2017-17122', 'objdump', ['-r'], '2.29', 'dump_relocs_in_section'),
    ('CVE-2017-17123', 'objdump', ['-g'], '2.29',
     'load_specific_debug_section'),
    ('CVE-2018-6323', 'objdump', ['-x'], '2.31.1', 'elf_object_p'),
    ('CVE-2018-1000876', 'objdump', ['-d'], '2.34',
     'bfd_get_dynamic_reloc_upper_bound'),
    ('CVE-2018-10372', 'readelf', ['-w'], '2.30', 'process_cu_tu_index'),
    ('CVE-2019-9077', 'readelf', ['-a'], '2.32', 'process_mips_specific'),
    ('CVE-2021-20284', 'objdump', ['-D'], '2.35.1',
     '_bfd_elf_slurp_secondary_reloc_section'),
    ('CVE-2021-20294', 'readelf', ['--dyn-syms'], '2.35.1',
     'get_num_dynamic_syms'),
    ('CVE-2021-45078', 'objdump', ['-g'], '2.36', 'finish_stab'),
    ('CVE-2022-44840', 'readelf', ['-w'], '2.38', 'find_section_in_set'),
    ('CVE-2022-47695', 'objdump', ['-d'], '2.38', 'compare_symbols'),
    ('CVE-2022-47696', 'objdump', ['-d'], '2.38', 'bfd_get_flavour'),
    ('CVE-2023-1579', 'objdump', ['-S'], '2.35.1', 'coff_slurp_reloc_table'),
    ('CVE-2018-18605', 'readelf', ['-w'], '2.29', 'byte_get_little_endian'),
    ('CVE-2018-18606', 'readelf', ['-w'], '2.29', None),
    ('CVE-2018-18607', 'readelf', ['-w'], '2.29', None),
    ('CVE-2018-19931', 'objdump', ['-x'], '2.31.1', None),
    ('CVE-2018-20002', 'objdump', ['-s'], '2.32', None),
    ('CVE-2019-9073', 'objdump', ['-x'], '2.32', None),
    ('CVE-2019-9074', 'objdump', ['-x'], '2.32', None),
    ('CVE-2019-9075', 'objdump', ['-x'], '2.32', None),
    ('CVE-2019-9076', 'objdump', ['-x'], '2.34', None),
    ('CVE-2019-17450', 'objdump', ['-g'], '2.34', None),
    ('CVE-2019-17451', 'objdump', ['-g'], '2.34', None),
    ('CVE-2020-16592', 'objdump', ['-x'], '2.34', None),
    ('CVE-2020-16599', 'objdump', ['-s'], '2.32', None),
    ('CVE-2020-35448', 'objdump', ['-d'], '2.35.1', None),
    ('CVE-2021-46174', 'objdump', ['-g'], '2.36', None),
    ('CVE-2022-48063', 'objdump', ['-g'], '2.38', None),
    ('CVE-2022-48064', 'objdump', ['-s'], '2.32', None),
    ('CVE-2023-1972', 'objdump', ['-x'], '2.32', None),
    ('CVE-2023-25588', 'objdump', ['-d'], '2.38', None),
    ('CVE-2025-0840', 'objdump', ['--insn-width', '64', '-d'], '2.43', None),
    ('CVE-2025-11081', 'objdump', HUGE_OBJDUMP_ARGS, '2.45', None),
    ('CVE-2025-11839', 'objdump', HUGE_OBJDUMP_ARGS, '2.45', None),
    ('CVE-2025-69645', 'objdump', ['--source-comment'], '2.45', None),
    ('CVE-2025-69652', 'readelf', ['-w', 'abbrev'], '2.42', None),
]

LIBXML2_CLI = [
    ('CVE-2017-9047', ['--valid'], '2.9.4', 'xmlSnprintfElementContent'),
    ('CVE-2017-9049', ['--memory', '--oldxml10'], '2.9.4',
     'xmlDictComputeFastKey'),
    ('CVE-2016-3627', ['--valid', '--recover'], '2.9.2', None),
    ('CVE-2017-7376', ['--xinclude'], '2.9.4', None),  # + redirect server
    ('CVE-2024-34459', ['--htmlout'], '2.11.5', None),
    ('CVE-2025-27113', ['--walker', '--pattern', '/child::info/.'],
     '2.11.5', None),
]

GIFLIB_CLI = [
    ('CVE-2022-28506', 'gif2rgb', [], '5.2.1', 'DumpScreen2RGB'),
    ('CVE-2015-7555', 'giffix', [], '5.1.1', None),
    ('CVE-2024-45993', 'gif2rgb', ['-o', '/tmp/poc_sweep_o'], '5.2.1', None),
    ('CVE-2026-26740', 'giftool', ['-d', '1'], '5.2.1', None),
]


def _sorted_versions(prefix, root):
    out = []
    for name in os.listdir(root):
        if name.startswith(prefix):
            out.append(name[len(prefix):])
    def _key(v):
        return [int(x) if x.isdigit() else x for x in re.split(r'[.\-]', v)]
    return sorted(out, key=_key)


def binutils_versions():
    return _sorted_versions('binutils-',
                            os.path.join(REPO, 'binutils-versions'))


def binutils_tool(ver, tool):
    p = os.path.join(REPO, 'binutils-versions', f'binutils-{ver}',
                     'build-asan', 'binutils', tool)
    return p if os.path.isfile(p) and os.access(p, os.X_OK) else None


def binutils_ld(ver):
    p = os.path.join(REPO, 'binutils-versions', f'binutils-{ver}',
                     'build-asan-ld', 'ld', 'ld-new')
    return p if os.path.isfile(p) and os.access(p, os.X_OK) else None


def libxml2_versions():
    return _sorted_versions('libxml2-',
                            os.path.join(REPO, 'libxml2-versions'))


def libxml2_xmllint(ver):
    base = os.path.join(REPO, 'libxml2-versions', f'libxml2-{ver}')
    for p in (os.path.join(base, 'xmllint'), os.path.join(base, 'build',
                                                          'xmllint')):
        if os.path.isfile(p) and os.access(p, os.X_OK):
            return p
    return None


def giflib_versions():
    return _sorted_versions('giflib-',
                            os.path.join(REPO, 'giflib-versions'))


def giflib_tool(ver, tool):
    base = os.path.join(REPO, 'giflib-versions', f'giflib-{ver}')
    cands = [os.path.join(base, tool), os.path.join(base, 'util', tool)]
    for p in cands:
        if os.path.isfile(p) and os.access(p, os.X_OK):
            return p
    return None


def _norm_func(f):
    if not f:
        return None
    f = re.sub(r'\s*\(.*\)$', '', f.strip())
    return f or None


def run_one(binary, args, stdin_file=None, timeout=TIMEOUT):
    """Run one trigger command; return rc / signal / ASan signature."""
    t0 = time.time()
    try:
        fin = open(stdin_file, 'rb') if stdin_file else subprocess.DEVNULL
        try:
            proc = subprocess.run(
                [binary] + args, stdin=fin,
                capture_output=True, text=True, errors='replace',
                timeout=timeout, env=ENV, cwd=REPO)
            out = proc.stdout + proc.stderr
            rc = proc.returncode
        finally:
            if stdin_file:
                fin.close()
        timed_out = False
    except subprocess.TimeoutExpired as e:
        out = ((e.stdout or b'') + (e.stderr or b'')) \
            if isinstance(e.stdout, bytes) else ((e.stdout or '') +
                                                 (e.stderr or ''))
        if isinstance(out, bytes):
            out = out.decode('utf-8', 'replace')
        rc = None
        timed_out = True
    sig = extract_crash_signature(out) if out else None
    signame = None
    if rc is not None and rc < 0:
        try:
            signame = signal.Signals(-rc).name
        except ValueError:
            signame = f'signal{-rc}'
    elif rc == 134:
        signame = 'SIGABRT'
    elif rc == 139:
        signame = 'SIGSEGV'
    return {
        'rc': rc,
        'signal': signame,
        'timed_out': timed_out,
        'asan': sig is not None,
        'asan_type': sig['type'] if sig else None,
        'crash_func': _norm_func(
            (sig['crash_frames'][0].get('function') if sig and
             sig.get('crash_frames') else None)),
        'crash_file': (sig['crash_frames'][0].get('file')
                       if sig and sig.get('crash_frames') else None),
        'crash_line': (sig['crash_frames'][0].get('line')
                       if sig and sig.get('crash_frames') else None),
        'seconds': round(time.time() - t0, 2),
        '_sig': sig,
    }


def classify(ref_run, run):
    if run['timed_out']:
        return 'timeout'
    if run['asan']:
        if ref_run and ref_run['asan']:
            v, _ = compare_crash_signatures(ref_run['_sig'], run['_sig'])
            return {'same_site': 'same_site',
                    'same_func': 'same_func',
                    'same_type': 'same_type'}.get(v, 'different')
        return 'crash_uncompared'
    if run['signal']:
        return f"signal:{run['signal']}"
    return 'no_crash'


def build_catalog():
    """Expand every CVE into concrete (label, binary, args, stdin) runs."""
    cat = []

    for cve, tool, args, ref, reported in BINUTILS_CLI:
        runs = []
        for ver in binutils_versions():
            b = binutils_tool(ver, tool)
            if b:
                runs.append((ver, b, args + [f'in/{cve}'], None))
        cat.append({'id': cve, 'project': 'binutils', 'kind': 'cli',
                    'ref': ref, 'reported': reported, 'runs': runs})

    for cve, args in LD_ARGS.items():
        runs = []
        for ver in ('2.44', '2.45', '2.47'):
            b = binutils_ld(ver)
            if b:
                runs.append((ver, b, args, None))
        cat.append({'id': cve, 'project': 'binutils-ld', 'kind': 'cli',
                    'ref': LD_REF[cve], 'reported': None, 'runs': runs})

    for cve, args, ref, reported in LIBXML2_CLI:
        runs = []
        for ver in libxml2_versions():
            b = libxml2_xmllint(ver)
            if not b:
                continue
            _args = list(args)
            if cve == 'CVE-2024-56171':
                sch = os.path.join(REPO, 'libxml2-versions',
                                   f'libxml2-{ver}', 'test', 'schemas',
                                   'bug322411_1.xsd')
                if not os.path.isfile(sch):
                    continue
                _args = ['--noout', '--schema', sch]
            runs.append((ver, b, _args + [f'in/{cve}'], None))
        cat.append({'id': cve, 'project': 'libxml2', 'kind': 'cli',
                    'ref': ref, 'reported': reported, 'runs': runs})

    # libxml2 harness-based CVEs (prebuilt per-version binaries)
    cat.append({
        'id': 'CVE-2015-8710', 'project': 'libxml2', 'kind': 'harness',
        'ref': '2.9.1', 'reported': 'htmlCurrentChar',
        'runs': [(v, os.path.join(REPO, 'build', f'h8710_{v}'),
                  [f'in/CVE-2015-8710'], None)
                 for v in ('2.9.0', '2.9.1', '2.9.2', '2.9.4')
                 if os.path.isfile(os.path.join(REPO, 'build',
                                                f'h8710_{v}'))]})
    cat.append({
        'id': 'CVE-2024-25062', 'project': 'libxml2', 'kind': 'harness',
        'ref': '2.11.5', 'reported': 'xmlValidatePopElement',
        'runs': [(v, os.path.join(REPO, 'build', f'f25062_{v}'),
                  [f'in/CVE-2024-25062'], None)
                 for v in ('2.11.5', '2.12.10')
                 if os.path.isfile(os.path.join(REPO, 'build',
                                                f'f25062_{v}'))]})
    cat.append({
        'id': 'CVE-2025-49794', 'project': 'libxml2', 'kind': 'harness',
        'ref': '2.11.5', 'reported': 'xmlSchematronFormatReport',
        'runs': [(v, os.path.join(REPO, 'build', f't_{v}'), [], None)
                 for v in ('2.9.14', '2.11.5', '2.13.6')
                 if os.path.isfile(os.path.join(REPO, 'build', f't_{v}'))]})
    for cve, reported in (('CVE-2025-49795', 'xmlSchematronFormatReport'),
                          ('CVE-2025-49796', None)):
        runs = []
        for v in ('2.9.14', '2.11.5', '2.13.6'):
            b = os.path.join(REPO, 'build', f'{cve.replace("-", "_")}_{v}')
            if os.path.isfile(b):
                runs.append((v, b, [], None))
        cat.append({'id': cve, 'project': 'libxml2', 'kind': 'harness',
                    'ref': '2.11.5', 'reported': reported, 'runs': runs})

    for cve, tool, args, ref, reported in GIFLIB_CLI:
        runs = []
        for ver in giflib_versions():
            b = giflib_tool(ver, tool)
            if b:
                stdin = f'in/{cve}' if cve == 'CVE-2026-26740' else None
                _args = list(args) if stdin is None else args
                if stdin is None:
                    _args = args + [f'in/{cve}']
                runs.append((ver, b, _args, stdin))
        cat.append({'id': cve, 'project': 'giflib', 'kind': 'cli',
                    'ref': ref, 'reported': reported, 'runs': runs})

    # freetype harness-based CVEs
    cat.append({
        'id': 'CVE-2020-15999', 'project': 'freetype', 'kind': 'harness',
        'ref': '2.9.1', 'reported': 'Load_SBit_Png',
        'runs': [(v, os.path.join(REPO, 'build', f'tf_{v}'),
                  [f'in/CVE-2020-15999'], None)
                 for v in ('2.5.5', '2.6.5', '2.7.1', '2.8.1', '2.9.1')
                 if os.path.isfile(os.path.join(REPO, 'build', f'tf_{v}'))]})
    cat.append({
        'id': 'CVE-2022-27404', 'project': 'freetype', 'kind': 'harness',
        'ref': '2.11.1', 'reported': 'sfnt_init_face',
        'runs': [('2.11.1', os.path.join(REPO, 'build',
                                         'test_face_idx_ft2111'),
                  [f'in/CVE-2022-27404'], None)]})
    cat.append({
        'id': 'CVE-2026-23865', 'project': 'freetype', 'kind': 'harness',
        'ref': '2.14.1', 'reported': 'tt_var_get_item_delta',
        'runs': [(v, os.path.join(REPO, 'build', f'tvar_{v}'),
                  [f'in/CVE-2026-23865'], None)
                 for v in ('2.13.1', '2.13.2', '2.13.3', '2.14.0', '2.14.1')
                 if os.path.isfile(os.path.join(REPO, 'build', f'tvar_{v}'))]})
    cat.append({
        'id': 'CVE-2026-50811', 'project': 'freetype', 'kind': 'harness',
        'ref': '2.14.1', 'reported': 'TT_Get_Var_Design',
        'runs': [(v, os.path.join(REPO, 'build', f't50811_{v}'),
                  [f'in/CVE-2026-50811', '64'], None)
                 for v in ('2.13.3', '2.14.0', '2.14.1')
                 if os.path.isfile(os.path.join(REPO, 'build', f't50811_{v}'))]})
    cat.append({
        'id': 'CVE-2026-95512', 'project': 'freetype', 'kind': 'harness',
        'ref': '2.14.1', 'reported': None, 'note': 'resource-exhaustion',
        'runs': [('2.14.1', os.path.join(REPO, 'build', 't95512'),
                  [f'in/CVE-2026-95512'], None)]})

    return cat


def compile_4979x():
    """Compile the CVE-2025-49795/49796 C PoCs against each libxml2."""
    specs = {
        'CVE-2025-49795': 'in/CVE-2025-49795.c',
        'CVE-2025-49796': 'in/CVE-2025-49796.c',
    }
    libs = {
        '2.9.14': ('libxml2-versions/libxml2-2.9.14/include',
                   'libxml2-versions/libxml2-2.9.14/.libs/libxml2.a'),
        '2.11.5': ('libxml2-versions/libxml2-2.11.5/include',
                   'libxml2-versions/libxml2-2.11.5/build/libxml2.a'),
        '2.13.6': ('libxml2-versions/libxml2-2.13.6/include',
                   'libxml2-versions/libxml2-2.13.6/.libs/libxml2.a'),
    }
    for cve, src in specs.items():
        for ver, (inc, lib) in libs.items():
            out = os.path.join(REPO, 'build',
                               f'{cve.replace("-", "_")}_{ver}')
            if os.path.isfile(out):
                continue
            if not (os.path.isfile(os.path.join(REPO, lib)) and
                    os.path.isdir(os.path.join(REPO, inc))):
                print(f'  [!] {cve} {ver}: missing lib/include, skip')
                continue
            cmd = ['gcc', '-O1', '-g', '-fsanitize=address',
                   f'-I{inc}', os.path.join(REPO, src),
                   os.path.join(REPO, lib), '-lz', '-lm',
                   '-fsanitize=address', '-o', out]
            r = subprocess.run(cmd, capture_output=True, text=True)
            if r.returncode != 0:
                print(f'  [!] compile {cve} {ver} failed: '
                      f'{r.stderr[-300:]}')
            else:
                print(f'  [+] compiled {cve} {ver}')


def start_redir_server():
    p = subprocess.Popen(['python3', 'build/redir_server.py'], cwd=REPO,
                         stdout=subprocess.DEVNULL, stderr=subprocess.DEVNULL)
    time.sleep(0.5)
    return p


def main():
    os.makedirs(OUT_DIR, exist_ok=True)
    print('[*] compiling harness PoCs (49795/49796) if needed...')
    compile_4979x()
    redir = start_redir_server()
    try:
        cat = build_catalog()
        results = {}
        jobs = []  # (cve, label, binary, args, stdin)

        # Phase 1: reference runs (serial per CVE for a stable baseline)
        print('[*] phase 1: reference crashes...')
        for entry in cat:
            ref_label = entry['ref']
            ref_run = None
            for label, b, args, stdin in entry['runs']:
                if label == ref_label:
                    print(f"  {entry['id']} ref={label} "
                          f"{os.path.basename(b)} {' '.join(args)}")
                    ref_run = run_one(b, args, stdin)
                    ref_run.pop('_sig', None)
                    break
            results[entry['id']] = {
                'project': entry['project'],
                'kind': entry['kind'],
                'ref_version': ref_label,
                'reported_func': entry.get('reported'),
                'note': entry.get('note'),
                'ref_run': {k: v for k, v in ref_run.items()}
                if ref_run else None,
                'versions': {},
            }
            # keep the ref signature in memory for comparison
            entry['_ref_run'] = ref_run

        # re-run refs keeping _sig for comparison (run_one stores sig in _sig;
        # we popped it above for JSON — recompute lazily in phase 2 by
        # re-adding: simplest is to keep a parallel dict)
        ref_sigs = {}
        for entry in cat:
            rr = entry.get('_ref_run')
            if rr and rr.get('_sig') is None and rr.get('asan'):
                # re-extract by re-running is wasteful; instead we should not
                # have popped.  Fix: re-run only the ref with sig kept.
                for label, b, args, stdin in entry['runs']:
                    if label == entry['ref']:
                        full = run_one(b, args, stdin)
                        ref_sigs[entry['id']] = full
                        entry['_ref_run'] = full
                        # refresh JSON copy
                        results[entry['id']]['ref_run'] = {
                            k: v for k, v in full.items()
                            if k != '_sig'}
                        break
            elif rr:
                ref_sigs[entry['id']] = rr

        # Phase 2: all other versions
        print('[*] phase 2: sweeping all versions '
              f'({WORKERS} workers, timeout {TIMEOUT}s)...')
        for entry in cat:
            for label, b, args, stdin in entry['runs']:
                if label == entry['ref']:
                    continue
                jobs.append((entry, label, b, args, stdin))

        done = 0
        total = len(jobs)
        with ThreadPoolExecutor(max_workers=WORKERS) as ex:
            futs = {ex.submit(run_one, b, args, stdin): (entry, label)
                    for entry, label, b, args, stdin in jobs}
            for fut in as_completed(futs):
                entry, label = futs[fut]
                try:
                    run = fut.result()
                except Exception as e:
                    run = {'rc': None, 'signal': None, 'timed_out': False,
                           'asan': False, 'asan_type': None,
                           'crash_func': None, 'seconds': 0,
                           'error': str(e), '_sig': None}
                ref_full = ref_sigs.get(entry['id'])
                verdict = classify(ref_full, run)
                results[entry['id']]['versions'][label] = {
                    'verdict': verdict,
                    'rc': run.get('rc'),
                    'signal': run.get('signal'),
                    'asan_type': run.get('asan_type'),
                    'crash_func': run.get('crash_func'),
                    'seconds': run.get('seconds'),
                }
                done += 1
                if done % 50 == 0 or done == total:
                    print(f'  [{done}/{total}] last: {entry["id"]} '
                          f'{label} -> {verdict}')

        # Summarize
        for cve, res in results.items():
            buckets = {'same_site': [], 'same_func': [], 'same_type': [],
                       'different': [], 'no_crash': [], 'timeout': [],
                       'crash_uncompared': []}
            signals = {}
            for ver, r in res['versions'].items():
                v = r['verdict']
                if v.startswith('signal:'):
                    signals.setdefault(v, []).append(ver)
                else:
                    buckets.setdefault(v, []).append(ver)
            res['summary'] = {
                'same': sorted(buckets['same_site'] + buckets['same_func'],
                               key=lambda s: [int(x) if x.isdigit() else x
                                              for x in re.split(r'[.\-]', s)]),
                'same_type_diff_site': buckets['same_type'],
                'different': buckets['different'],
                'no_crash': buckets['no_crash'],
                'timeout': buckets['timeout'],
                'signals': signals,
            }
            rr = res.get('ref_run') or {}
            res['reported_match'] = (
                None if not res.get('reported_func') or not rr.get(
                    'crash_func')
                else (_norm_func(rr['crash_func']) ==
                      _norm_func(res['reported_func'])))

        with open(os.path.join(OUT_DIR, 'results.json'), 'w') as f:
            json.dump(results, f, indent=2, default=str)
        print(f'[*] results: {os.path.join(OUT_DIR, "results.json")}')
        print_markdown(results)
    finally:
        redir.terminate()


def _vsort(vers):
    return sorted(vers, key=lambda s: [int(x) if x.isdigit() else x
                                       for x in re.split(r'[.\-]', s)])


def print_markdown(results):
    lines = []
    lines.append('')
    lines.append('## 同漏洞跨版本验证 (2026-10-14)')
    lines.append('')
    lines.append('判定标准与代码一致 (`trace_fork_offsets.py::'
                 'compare_crash_signatures`): **同漏洞** = ASan 崩溃类型'
                 '一致 + 最内层用户帧函数一致 (same_site/same_func); '
                 'same_type (类型同、函数/语句不同) 判为**不同漏洞**; '
                 '无 ASan 报告的信号崩溃单独按信号记录。')
    lines.append('每个 CVE 以文档记录的受影响版本为参考基准 (ref), '
                 '其余版本逐一运行同命令并对比崩溃签名。')
    lines.append('')
    proj_order = ['binutils', 'binutils-ld', 'libxml2', 'giflib',
                  'freetype']
    titles = {'binutils': 'binutils (objdump/readelf)',
              'binutils-ld': 'binutils ld-new',
              'libxml2': 'libxml2', 'giflib': 'giflib',
              'freetype': 'freetype'}
    for proj in proj_order:
        entries = [(c, r) for c, r in results.items()
                   if r['project'] == proj]
        if not entries:
            continue
        lines.append(f'### {titles[proj]}')
        lines.append('')
        lines.append('```')
        for cve, res in sorted(entries):
            rr = res.get('ref_run') or {}
            ref_crash = (f"{rr.get('asan_type')} {rr.get('crash_func')}"
                         if rr.get('asan') else
                         (f"no-ASAN {rr.get('signal')}"
                          if rr.get('signal') else 'no crash'))
            rm = res.get('reported_match')
            rm_s = ('' if rm is None else
                    (' [报告函数一致]' if rm else ' [报告函数不一致!]'))
            rep = res.get('reported_func') or '?'
            s = res['summary']
            lines.append(f"{cve}  ref={res['ref_version']}  "
                         f"ref_crash={ref_crash}  reported={rep}{rm_s}")
            lines.append(f"    同漏洞: "
                         f"{', '.join(_vsort(s['same'])) or '-'}")
            if s['same_type_diff_site']:
                lines.append(f"    同类型异点(不同漏洞): "
                             f"{', '.join(_vsort(s['same_type_diff_site']))}")
            if s['different']:
                lines.append(f"    异类型崩溃: "
                             f"{', '.join(_vsort(s['different']))}")
            for sig, vs in sorted((s.get('signals') or {}).items()):
                lines.append(f"    {sig} (无ASAN报告): "
                             f"{', '.join(_vsort(vs))}")
            if s['no_crash']:
                lines.append(f"    不触发: "
                             f"{', '.join(_vsort(s['no_crash']))}")
            if s['timeout']:
                lines.append(f"    超时: "
                             f"{', '.join(_vsort(s['timeout']))}")
        lines.append('```')
        lines.append('')
    md = '\n'.join(lines)
    with open(os.path.join(OUT_DIR, 'summary.md'), 'w') as f:
        f.write(md + '\n')
    print(md)


if __name__ == '__main__':
    main()
