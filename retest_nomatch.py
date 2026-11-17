#!/usr/bin/env python3
"""No-match CVE retest driver (fork-flip + field-stage pipeline).

Loads every NO_MATCH (CVE, target-version) pair recorded in
results/allver_mut/_summary_*.json, resolves the reference/target source
trees, generates a per-pair config, and runs ./run_analysis.sh with
RETRO_REF/RETRO_TGT overrides — strictly sequentially, low priority, single
mutation worker (the host is shared with fuzzers).

Idempotent: pairs whose log + result json already exist are skipped, so the
batch can be restarted.  Results land in results/nomatch_retest/.
"""

import json
import os
import re
import subprocess
import sys
import time
from pathlib import Path

BASE = Path(__file__).resolve().parent
SUMMARY_FILES = [
    BASE / 'results/allver_mut/_summary_cat1.json',
    BASE / 'results/allver_mut/_summary_cat2-3-4-5.json',
]
ALLVER_DIR = BASE / 'results/allver_mut'
RETEST_DIR = BASE / 'results/nomatch_retest'
CFG_DIR = BASE / 'results/nomatch_cfgs'
LOG_DIR = RETEST_DIR / 'logs'

# project -> (config template, version-dir prefix under <proj>-versions/)
PROJECTS = {
    'binutils':   ('config_binutils.py',  'binutils-versions', 'binutils-'),
    'exiv2':      ('config_exiv2.py',     'exiv2-versions',    'exiv2-'),
    'freetype':   ('config_freetype.py',  'freetype-versions', 'freetype-'),
    'giflib':     ('config_giflib.py',    'giflib-versions',   'giflib-'),
    'jasper':     ('config_jasper.py',    'jasper-versions',   'jasper-version-'),
    'lame':       ('config_lame.py',      'lame-versions',     'lame-'),
    'libarchive': ('config_libarchive.py', 'libarchive-versions', 'v'),
    'libredwg':   ('config_libredwg.py',  'libredwg-versions', 'libredwg-'),
    'pcre2':      ('config_pcre2.py',     'pcre2-versions',    'pcre2-pcre2-'),
    'tiff':       ('config_libtiff.py',   'tiff-versions',     'tiff-'),
}

PAIR_TIMEOUT_S = int(os.environ.get('RETRO_PAIR_TIMEOUT', '3600'))

# per-project, per-CVE harness source under build/ (repo root)
HARNESS_MAP = {
    'freetype': {
        'CVE-2026-23865': 'test_var.c',
        'CVE-2026-50811': 'ft_get_design_dump.c',
        'CVE-2022-27404': 'test_face_idx.c',
        'CVE-2020-15999': 'test_face.c',
    },
}


def load_pairs():
    pairs = {}
    for sf in SUMMARY_FILES:
        if not sf.is_file():
            continue
        d = json.load(open(sf))
        for r in d.get('results', []):
            if r.get('status') != 'NO_MATCH':
                continue
            key = (r['cve'], r['ver'])
            pairs[key] = r
    # Enrich with the per-pair detail json (proj/ref/input/args).
    for cve, ver in list(pairs.keys()):
        found = None
        for cand in ALLVER_DIR.glob(f'{cve}__*.json'):
            try:
                j = json.load(open(cand))
            except Exception:
                continue
            if j.get('cve') == cve and j.get('ver') == ver:
                found = j
                break
        if found:
            pairs[(cve, ver)] = found
    return pairs


def resolve_version_dir(proj, ver):
    _, vroot, prefix = PROJECTS[proj]
    root = BASE / vroot
    if not root.is_dir():
        return None
    target_name = prefix + ver
    exact = root / target_name
    if exact.is_dir():
        return str(exact)
    # exact suffix match among entries (avoid prefix collisions like 2.0/2.0.1)
    best = None
    for d in sorted(root.iterdir()):
        if d.is_dir() and d.name.endswith(ver):
            best = str(d)
    return best


def make_config(pair, ref_dir, tgt_dir, cfg_path):
    proj = pair.get('proj')
    if not proj:
        return False, 'pair has no proj'
    base_cfg = PROJECTS.get(proj)
    if not base_cfg:
        return False, f'no config mapping for {proj}'
    cfg_tpl = BASE / base_cfg[0]
    if not cfg_tpl.is_file():
        return False, f'config template missing: {cfg_tpl}'
    args = pair.get('args') or []
    parts = []
    for a in args:
        parts.append('{input_file}' if a == 'INPUT' else a)
    # if the command carries no output argument, append the pipeline output
    if not any(a in ('-o', '-out', '--output') for a in args):
        parts.append('{output_file}')
    cmd_fmt = '{program_path} ' + ' '.join(parts)
    input_file = pair.get('input')
    if not input_file or not os.path.isfile(input_file):
        return False, f'input missing: {input_file}'
    cve = pair['cve']
    cve_id = cve
    extra = f"""
# ---- per-pair overrides (retest_nomatch) ----
CVE_ID = {cve_id!r}
INPUT_FILE = {os.path.abspath(input_file)!r}
OUTPUT_FILE = "/dev/null"
COMMAND_FORMAT = {cmd_fmt!r}
"""
    # harness selection: the template config lives in the repo root, but the
    # generated per-pair config is copied into results/nomatch_cfgs/<tag>/,
    # so the template's dirname(__file__)-based HARNESS_SRC would point at a
    # non-existent build/ dir.  Rewrite the HARNESS_SRC definition IN PLACE:
    # the pre_build f-strings bake the value in at module load time, so an
    # appended override would come too late.
    text = cfg_tpl.read_text()
    harness = HARNESS_MAP.get(proj, {}).get(cve)
    if harness:
        hpath = str(BASE / 'build' / harness)
        lines = text.splitlines(keepends=True)
        i = next((k for k, l in enumerate(lines)
                  if l.startswith('HARNESS_SRC')), None)
        if i is None:
            return False, f'HARNESS_SRC not found in {cfg_tpl.name}'
        # statement may span multiple lines; it ends at the first line whose
        # stripped content ends with ')'
        j = i
        while j < len(lines) and not lines[j].rstrip().endswith(')'):
            j += 1
        if j >= len(lines):
            return False, f'unterminated HARNESS_SRC in {cfg_tpl.name}'
        lines[i:j + 1] = [f'HARNESS_SRC = {hpath!r}\n']
        text = ''.join(lines)
    text += extra
    cfg_path.parent.mkdir(parents=True, exist_ok=True)
    cfg_path.write_text(text + extra)
    return True, ''


def _owned(path, started):
    """True if `path` was written during this pair's run window.

    fork_trace_result.json lives next to the input and is shared by every
    pair that uses the same input dir, so a failed run would otherwise read
    a stale match from a previous pair (false NOW_MATCH).
    """
    if started is None:
        return True
    try:
        return os.stat(path).st_mtime >= started - 1.0
    except OSError:
        return False


def parse_outcome(pair, log_text, input_file, started=None):
    """(status, detail) after a pair run."""
    cve, ver = pair['cve'], pair['ver']
    base_out = input_file.replace('.', '_') if input_file else cve
    trace_json = os.path.join(os.path.dirname(os.path.abspath(input_file)),
                              'fork_trace_result.json')
    if os.path.isfile(trace_json) and _owned(trace_json, started):
        try:
            d = json.load(open(trace_json))
            if d.get('mutation_any_match'):
                stage = None
                if (d.get('field_combo_results') or {}).get('matches'):
                    stage = 'Step6g'
                if (d.get('format_field_results') or {}).get('matches'):
                    stage = 'Step6h'
                cr = d.get('crash_results') or {}
                if not stage and any(isinstance(i, dict) and i.get('matches')
                                     for i in cr.values()):
                    stage = 'Step6'
                pr = d.get('pairwise_results') or {}
                if not stage and any(isinstance(i, dict) and i.get('matches')
                                     for i in pr.values()):
                    stage = 'Step6b'
                sc = d.get('static_crash_results') or {}
                if not stage and any(isinstance(i, dict) and i.get('matches')
                                     for i in sc.values()):
                    stage = 'Step6c'
                sp = d.get('static_pairwise_results') or {}
                if not stage and any(isinstance(i, dict) and i.get('matches')
                                     for i in sp.values()):
                    stage = 'Step6d'
                em = d.get('extended_mutation_results') or {}
                if not stage and em.get('matches'):
                    stage = 'Step6f'
                return 'NOW_MATCH', f'{stage or "?"} (in-round)'
        except Exception:
            pass
    chain = BASE / 'results' / f'{cve}_fork_flip_chain.json'
    if chain.is_file() and _owned(str(chain), started):
        try:
            d = json.load(open(chain))
            if d.get('status') == 'success':
                return 'NOW_MATCH', 'fork-flip iteration'
        except Exception:
            pass
    # no-match markers under out/
    out_root = BASE / 'out'
    markers = []
    if out_root.is_dir():
        markers = [p for p in out_root.rglob('NO_CRASH_MATCH.txt')
                   if cve.replace('_', '') in p.parent.name.replace('_', '')]
    # log heuristics — a GDB/fork failure is only fatal when the mutation
    # pipeline did NOT get far enough to produce results.  Non-fatal
    # "Call-site trace failed: fork_not_reached" after Step 6 / origin
    # success means the pair completed without a match.
    mutation_ran = (
        'Step 6' in log_text
        or 'fork flips recorded' in log_text
        or 'dynamic-offset mutation' in log_text
        or 'pairwise   (Step 6b)' in log_text
        or 'field-combo (Step 6g' in log_text
    )
    hard_needles = ('COMPILE_FAIL', 'Fork-point analysis failed',
                    'Error: unknown project', 'cannot locate binary')
    for needle in hard_needles:
        if needle in log_text:
            return 'ERROR', needle.split(':')[0]
    gdb_failed = 'GDB trace failed' in log_text
    fork_nr = 'fork_not_reached' in log_text
    if (gdb_failed or fork_nr) and not mutation_ran:
        return 'ERROR', ('fork_not_reached' if fork_nr else 'GDB trace failed')
    return 'STILL_NO_MATCH', 'no match'


def run_pair(pair, ref_dir, tgt_dir, idx, total):
    cve, ver = pair['cve'], pair['ver']
    tag = f'{cve}__{ver}'.replace('/', '_')
    log_path = LOG_DIR / f'{tag}.log'
    # name the generated config after the TEMPLATE file: run_analysis.sh
    # derives PROJECT_NAME from the config filename (config_libtiff.py ->
    # libtiff); naming it config_tiff.py made all 62 tiff pairs fail with
    # "Error: unknown project 'tiff'".
    cfg_path = CFG_DIR / tag / PROJECTS[pair['proj']][0]
    result_path = RETEST_DIR / f'{tag}.json'
    if result_path.is_file() and log_path.is_file():
        try:
            prev = json.load(open(result_path))
            return prev.get('status'), f"{prev.get('detail')} (cached)"
        except Exception:
            pass

    ok, err = make_config(pair, ref_dir, tgt_dir, cfg_path)
    if not ok:
        return 'SKIP', err

    cmd = (f'nice -n 15 env RETRO_REF={ref_dir} RETRO_TGT={tgt_dir} '
           f'RETROSCOPE_MUTATION_WORKERS=1 '
           f'timeout {PAIR_TIMEOUT_S} ./run_analysis.sh {cfg_path}')
    print(f'[{idx}/{total}] {tag}  ref={os.path.basename(ref_dir)} '
          f'tgt={os.path.basename(tgt_dir)}', flush=True)
    t0 = time.time()
    try:
        proc = subprocess.run(cmd, shell=True, cwd=str(BASE),
                              capture_output=True, text=True,
                              errors='replace', timeout=PAIR_TIMEOUT_S + 600)
        log_text = (proc.stdout or '') + '\n' + (proc.stderr or '')
    except subprocess.TimeoutExpired as e:
        log_text = (e.stdout or '') + '\n' + (e.stderr or '') + \
            '\n[driver] pair timed out'
    elapsed = time.time() - t0
    log_path.parent.mkdir(parents=True, exist_ok=True)
    log_path.write_text(log_text)
    status, detail = parse_outcome(pair, log_text, pair.get('input'),
                                   started=t0)
    result_path.parent.mkdir(parents=True, exist_ok=True)
    json.dump({'cve': cve, 'ver': ver, 'proj': pair.get('proj'),
               'ref': os.path.basename(ref_dir),
               'tgt': os.path.basename(tgt_dir),
               'status': status, 'detail': detail,
               'elapsed': round(elapsed, 1), 'log': str(log_path)},
              open(result_path, 'w'), indent=2)
    print(f'  -> {status} ({detail})  [{elapsed:.0f}s]', flush=True)
    return status, detail


def main():
    pairs = load_pairs()
    print(f'NO_MATCH pairs loaded: {len(pairs)}')
    queue = []
    for (cve, ver), pair in sorted(pairs.items()):
        proj = pair.get('proj')
        if not proj or proj not in PROJECTS:
            queue.append((pair, None, None, 'no project mapping'))
            continue
        ref_dir = resolve_version_dir(proj, pair.get('ref', ''))
        tgt_dir = resolve_version_dir(proj, ver)
        if not ref_dir or not tgt_dir:
            queue.append((pair, ref_dir, tgt_dir,
                          f'missing version dir (ref={pair.get("ref")}, '
                          f'tgt={ver})'))
            continue
        if not pair.get('input') or not os.path.isfile(pair.get('input')):
            queue.append((pair, ref_dir, tgt_dir, 'input missing'))
            continue
        queue.append((pair, ref_dir, tgt_dir, None))
    # cost order: cheap projects first
    order = ['giflib', 'exiv2', 'pcre2', 'libarchive', 'freetype', 'lame',
             'libredwg', 'jasper', 'tiff', 'binutils']
    rank = {p: i for i, p in enumerate(order)}
    queue.sort(key=lambda q: (rank.get(q[0].get('proj'), 99),
                              q[0]['cve'], q[0]['ver']))

    summary = {'generated': time.strftime('%Y-%m-%d %H:%M:%S'),
               'pairs': [], 'counts': {}}
    for idx, (pair, ref_dir, tgt_dir, why) in enumerate(queue, 1):
        if why:
            print(f'[{idx}/{len(queue)}] {pair["cve"]}__{pair["ver"]}: '
                  f'SKIP ({why})', flush=True)
            summary['pairs'].append(
                {'cve': pair['cve'], 'ver': pair['ver'],
                 'status': 'SKIP', 'detail': why})
            continue
        status, detail = run_pair(pair, ref_dir, tgt_dir, idx, len(queue))
        summary['pairs'].append(
            {'cve': pair['cve'], 'ver': pair['ver'],
             'proj': pair.get('proj'),
             'ref': os.path.basename(ref_dir),
             'tgt': os.path.basename(tgt_dir),
             'status': status, 'detail': detail})
        summary['counts'][status] = summary['counts'].get(status, 0) + 1
        json.dump(summary, open(RETEST_DIR / '_summary.json', 'w'),
                  indent=2)
        time.sleep(20)  # breathing room for the fuzzers

    print('\nDone.', flush=True)
    print(json.dumps(summary['counts'], indent=2), flush=True)


if __name__ == '__main__':
    main()
